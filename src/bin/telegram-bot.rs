use std::{
    collections::{HashMap, HashSet},
    net,
    num::ParseIntError,
    str::FromStr,
};

use anyhow::Context;
use clap::{Parser, builder::ValueParser};
use futures::channel::mpsc;
use futures_util::FutureExt;
use teloxide::{Bot, types::UserId};
use tokio::{signal, task::JoinSet};
use tokio_util::sync::CancellationToken;

use talos_unlockr::{ClusterNodes, sync, telegram};
use uuid::Uuid;

fn parse_colon_separated(arg: &str) -> anyhow::Result<(String, net::IpAddr, Uuid)> {
    let [cluster_name, raw_ip, raw_uuid] = arg
        .splitn(3, "/")
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| anyhow::anyhow!("couldn't split on slash"))?;
    Ok((
        cluster_name.to_owned(),
        net::IpAddr::from_str(raw_ip).context("invalid IP")?,
        Uuid::from_str(raw_uuid).context("invalid UUID")?,
    ))
}

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long, value_parser = parse_colon_separated)]
    allowed_ips: Vec<(String, net::IpAddr, Uuid)>,
    #[arg(long, value_parser = ValueParser::new(|s: &str| Result::<_, ParseIntError>::Ok(UserId(u64::from_str(s)?))))]
    user_id: UserId,
    #[arg(long)]
    socket: std::path::PathBuf,
}

struct Run {
    allowed_ips: ClusterNodes,
    user_id: UserId,
    socket: std::path::PathBuf,
}

fn handle_args(args: Cli) -> Result<Run, anyhow::Error> {
    let allowed_ips = args
        .allowed_ips
        .iter()
        .fold(
            HashMap::new(),
            |mut map: HashMap<_, HashSet<(net::IpAddr, Uuid)>>, (name, ip, uuid)| {
                map.entry(name.to_owned()).or_default().insert((*ip, *uuid));
                map
            },
        )
        .into();

    Ok(Run {
        allowed_ips,
        user_id: args.user_id,
        socket: args.socket,
    })
}

async fn run(
    Run {
        allowed_ips,
        user_id,
        socket,
    }: Run,
) -> Result<(), anyhow::Error> {
    let cancelled = CancellationToken::new();

    let (send_allowed, receive_allowed) = mpsc::channel(1);

    let (stream, sink) = tokio::net::UnixStream::connect(socket).await?.into_split();

    let bot = Bot::from_env();

    let mut join_set = JoinSet::new();

    join_set.spawn(
        cancelled
            .clone()
            .run_until_cancelled_owned(sync::sink_allowed(sink, receive_allowed))
            .map(|r| r.unwrap_or(Ok(()))),
    );

    join_set.spawn(
        telegram::telegram_loop(
            cancelled.clone(),
            bot.clone(),
            user_id,
            allowed_ips.clone(),
            send_allowed,
        )
        .map(Ok),
    );

    let (send_attempts, receive_attempts) = mpsc::channel(1);

    join_set.spawn(
        cancelled
            .clone()
            .run_until_cancelled_owned(telegram::handle_attempts(
                bot,
                user_id,
                allowed_ips,
                receive_attempts,
            ))
            .map(|r| r.unwrap_or(()))
            .map(Ok),
    );

    join_set.spawn(
        cancelled
            .clone()
            .run_until_cancelled_owned(sync::stream_attempts(stream, send_attempts))
            .map(|r| r.unwrap_or(Ok(()))),
    );

    let ctrl_c_cancelled = cancelled.clone();
    join_set.spawn(
        cancelled
            .clone()
            .run_until_cancelled_owned(signal::ctrl_c().map(move |res| {
                res.expect("ctrl-c signal should work");
                ctrl_c_cancelled.cancel();
                log::info!("caught ctrl-c")
            }))
            .map(|r| r.unwrap_or(()))
            .map(Ok),
    );

    join_set
        .join_all()
        .await
        .into_iter()
        .collect::<Result<_, _>>()
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Cli::parse();
    log::debug!(args:?; "starting telegram bot");

    let run_args = handle_args(args)?;
    run(run_args).await?;

    log::info!("finished");
    Ok(())
}
