use std::{
    io::{stdin, Read}, net, str::FromStr, time
};

use anyhow::Context;
use chacha20poly1305::Key;
use clap::{Args, Parser};
use futures_util::FutureExt;
use tokio::{signal, task::JoinSet, time as tokio_time};
use tokio_util::sync::CancellationToken;
use tonic::transport::{Identity, Server, ServerTlsConfig};

use talos_unlockr::{KeySource, Unlocker};
use uuid::Uuid;

#[derive(Debug, Args)]
struct TlsCli {
    #[arg(long, required = false)]
    tls_key: std::path::PathBuf,
    #[arg(long, required = false)]
    tls_cert: std::path::PathBuf,
}

fn parse_duration(arg: &str) -> Result<std::time::Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(std::time::Duration::from_secs(seconds))
}

fn parse_colon_separated(arg: &str) -> anyhow::Result<(net::IpAddr, Uuid)> {
    let (raw_ip, raw_uuid) = arg.rsplit_once(":").context("couldn't split on colon")?;
    Ok((net::IpAddr::from_str(raw_ip).context("invalid IP")?, Uuid::from_str(raw_uuid).context("invalid UUID")?))
}

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long, value_parser = parse_duration)]
    timeout_secs: Option<time::Duration>,
    #[arg(long)]
    interface: Option<String>,
    #[arg(long)]
    port: u16,
    #[arg(long, value_parser = parse_colon_separated)]
    allowed_ips: Vec<(net::IpAddr, Uuid)>,
    #[arg(long)]
    key_file: Option<std::path::PathBuf>,
    #[command(flatten)]
    tls: Option<TlsCli>,
}

struct Run {
    timeout_secs: Option<time::Duration>,
    addrs: Vec<net::IpAddr>,
    port: u16,
    allowed_ips: Vec<(net::IpAddr, Uuid)>,
    key_source: KeySource,
    tls_identity: Option<Identity>,
}

fn handle_args(args: Cli) -> Result<Run, anyhow::Error> {
    let key_source = {
        match args.key_file {
            Some(ref filename) => {
                let mut key = Key::default();
                let mut file = std::fs::File::open(filename).map_err(|err| {
                    anyhow::Error::new(err).context(format!(
                        "couldn't open key file {}",
                        filename.to_string_lossy()
                    ))
                })?;
                let file_len = file.metadata().map(|metadata| metadata.len())?;

                if file_len == key.len() as u64 {
                    file.read_exact(&mut key)?;
                    Ok(KeySource::Key(key))
                } else {
                    Err(anyhow::Error::msg(format!(
                        "invalid key in file, expected length: {}, actual length: {}",
                        key.len(),
                        file_len,
                    )))
                }
            }
            None => Ok({
                let mut passphrase = String::new();
                println!("Using KDF with node UUID as salt...");
                println!(">>> Enter passphrase:");
                stdin().read_line(&mut passphrase)?;
                KeySource::Kdf(passphrase.trim_end().to_owned().into_bytes())
            }),
        }
    }?;

    let addrs = match args.interface {
        None => vec![net::Ipv6Addr::UNSPECIFIED.into()],
        Some(interface) => {
            let mut addrs: Vec<net::IpAddr> = Vec::new();
            for ifaddr in nix::ifaddrs::getifaddrs().unwrap() {
                if ifaddr.interface_name != interface {
                    continue;
                }
                match ifaddr.address {
                    Some(addr) => {
                        let ip_addr = match (addr.as_sockaddr_in(), addr.as_sockaddr_in6()) {
                            (Some(addr), _) => net::IpAddr::V4(addr.ip()),
                            (_, Some(addr)) => net::IpAddr::V6(addr.ip()),
                            _ => continue,
                        };
                        addrs.push(ip_addr);
                    }
                    None => continue,
                }
            }
            addrs
        }
    };

    let tls_identity = if let Some(tls) = args.tls {
        let cert = std::fs::read_to_string(tls.tls_cert)?;
        let key = std::fs::read_to_string(tls.tls_key)?;
        Some(Identity::from_pem(cert, key))
    } else {
        None
    };

    Ok(Run {
        timeout_secs: args.timeout_secs,
        addrs,
        port: args.port,
        allowed_ips: args.allowed_ips,
        key_source,
        tls_identity,
    })
}

async fn run(
    Run {
        timeout_secs,
        addrs,
        port,
        allowed_ips,
        key_source,
        tls_identity,
    }: Run,
) -> Result<(), anyhow::Error> {
    let cancelled = CancellationToken::new();

    let mut join_set: JoinSet<_> = addrs
        .into_iter()
        .map(|ip_addr| {
            let socket_addr = net::SocketAddr::new(ip_addr, port);
            log::info!(socket_addr:?; "listening");

            let unlocker = Unlocker::new(
                allowed_ips.clone().into_iter().collect(),
                key_source.clone(),
            );

            let mut builder = Server::builder();
            if let Some(identity) = &tls_identity {
                builder = builder
                    .tls_config(ServerTlsConfig::new().identity(identity.clone()))
                    .unwrap()
            }

            let cancelled = cancelled.clone();
            builder
                .add_service(unlocker)
                .serve_with_shutdown(socket_addr, async move {
                    cancelled.cancelled_owned().await;
                    log::info!(socket_addr:?; "shutting down");
                })
                .map(move |err| err.context(socket_addr))
        })
        .collect();

    let ctrl_c_cancelled = cancelled.clone();
    join_set.spawn(
        cancelled
            .clone()
            .run_until_cancelled_owned(signal::ctrl_c().map(move |res| {
                res.expect("ctrl-c signal should work");
                ctrl_c_cancelled.cancel();
                log::info!("caught ctrl-c")
            }))
            .map(|_| Ok(())),
    );

    if let Some(timeout_secs) = timeout_secs {
        let cancelled = cancelled.clone();
        join_set.spawn(
            cancelled
                .clone()
                .run_until_cancelled_owned(tokio_time::sleep(timeout_secs).map(move |_| {
                    log::info!("timed out, exiting");
                    cancelled.cancel();
                }))
                .map(|_| Ok(())),
        );
    }

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
    log::debug!(args:?; "starting");

    let run_args = handle_args(args)?;
    run(run_args).await?;

    log::info!("finished");
    Ok(())
}
