use std::{
    collections::{HashMap, HashSet},
    num::ParseIntError,
    str::FromStr,
    time,
};

use anyhow::Context;
use clap::{Parser, builder::ValueParser};
use futures_util::FutureExt as _;
use teloxide::{Bot, types::UserId};
use tokio::{signal, sync::mpsc, task::JoinSet};
use tokio_util::{future::FutureExt as _, sync::CancellationToken};

use talos_unlockr::{ClusterNodes, sync, telegram, unix};
use uuid::Uuid;

#[derive(Debug, Clone)]
struct AllowedNode {
    cluster_name: String,
    uuid: Uuid,
}

impl FromStr for AllowedNode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let [cluster_name, raw_uuid] = s
            .splitn(2, ",")
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| anyhow::anyhow!("couldn't split on slash"))?;
        Ok(AllowedNode {
            cluster_name: cluster_name.to_owned(),
            uuid: Uuid::from_str(raw_uuid).context("invalid UUID")?,
        })
    }
}

fn parse_duration(arg: &str) -> Result<std::time::Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(std::time::Duration::from_secs(seconds))
}

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long, value_parser = parse_duration)]
    timeout_secs: Option<time::Duration>,
    #[arg(long)]
    allowed_nodes: Vec<AllowedNode>,
    #[arg(long, value_parser = ValueParser::new(|s: &str| Result::<_, ParseIntError>::Ok(UserId(u64::from_str(s)?))))]
    user_id: UserId,
    #[arg(long)]
    socket: std::path::PathBuf,
}

struct Run {
    timeout_secs: Option<time::Duration>,
    allowed_nodes: ClusterNodes,
    user_id: UserId,
    socket: std::path::PathBuf,
}

fn handle_args(
    Cli {
        timeout_secs,
        allowed_nodes,
        user_id,
        socket,
    }: Cli,
) -> Result<Run, anyhow::Error> {
    let allowed_nodes = ClusterNodes(allowed_nodes.into_iter().fold(
        HashMap::new(),
        |mut map: HashMap<_, HashSet<Uuid>>, AllowedNode { cluster_name, uuid }| {
            map.entry(cluster_name).or_default().insert(uuid);
            map
        },
    ));

    Ok(Run {
        timeout_secs,
        allowed_nodes,
        user_id,
        socket,
    })
}

impl Run {
    async fn run(self) -> Result<(), anyhow::Error> {
        let Run {
            timeout_secs,
            allowed_nodes,
            user_id,
            socket,
        } = self;
        let cancelled = CancellationToken::new();

        let (send_allowed, receive_allowed) = mpsc::channel(20);

        let abstract_namespace_path = unix::to_abstract_namespace(&socket);
        let path = abstract_namespace_path.as_ref().unwrap_or(&socket);
        let (stream, sink) = tokio::net::UnixStream::connect(path).await?.into_split();

        let bot = Bot::from_env();

        let mut join_set = JoinSet::new();

        join_set.spawn(
            sync::sink_allowed(sink, receive_allowed)
                .with_cancellation_token_owned(cancelled.clone())
                .map(|r| r.unwrap_or(Ok(()))),
        );

        join_set.spawn(
            telegram::telegram_loop(
                cancelled.clone(),
                timeout_secs,
                bot.clone(),
                user_id,
                allowed_nodes.clone(),
                send_allowed,
            )
            .map(Ok),
        );

        let (send_attempts, receive_attempts) = mpsc::channel(20);

        join_set.spawn(
            telegram::handle_attempts(bot, user_id, allowed_nodes, receive_attempts)
                .with_cancellation_token_owned(cancelled.clone())
                .map(|r| {
                    let _: () = r.unwrap_or(());
                    Ok(())
                }),
        );

        join_set.spawn(
            sync::stream_attempts(stream, send_attempts)
                .with_cancellation_token_owned(cancelled.clone())
                .map(|r| r.unwrap_or(Ok(()))),
        );

        join_set.spawn(
            signal::ctrl_c()
                .map({
                    let ctrl_c_cancelled = cancelled.clone();
                    move |res| {
                        res.expect("ctrl-c signal should work");
                        ctrl_c_cancelled.cancel();
                        log::info!("caught ctrl-c")
                    }
                })
                .with_cancellation_token_owned(cancelled)
                .map(|r| {
                    let _: () = r.unwrap_or(());
                    Ok(())
                }),
        );

        join_set
            .join_all()
            .await
            .into_iter()
            .collect::<Result<_, _>>()
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Cli::parse();
    log::info!(args:?; "starting telegram bot");

    handle_args(args)?.run().await?;

    log::info!("finished");
    Ok(())
}
