use std::{
    io::{stdin, Read},
    net, time,
};

use chacha20poly1305::Key;
use clap::{Args, Parser};
use futures::future::Either;
use futures_util::{stream::FuturesUnordered, FutureExt, StreamExt};
use tokio::{signal, time as tokio_time};
use tonic::transport::{Identity, Server, ServerTlsConfig};

use talos_unlockr::{KeySource, Unlocker};

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

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long, value_parser = parse_duration)]
    timeout_secs: Option<time::Duration>,
    #[arg(long)]
    interface: Option<String>,
    #[arg(long)]
    port: u16,
    #[arg(long)]
    allowed_ips: Vec<net::IpAddr>,
    #[arg(long)]
    key_file: Option<std::path::PathBuf>,
    #[command(flatten)]
    tls: Option<TlsCli>,
}

struct Run {
    timeout_secs: Option<time::Duration>,
    addrs: Vec<net::IpAddr>,
    port: u16,
    allowed_ips: Vec<net::IpAddr>,
    key_source: KeySource,
    tls_identity: Option<Identity>,
}

fn handle_args(args: Cli) -> Result<Run, anyhow::Error> {
    let key_source = {
        match args.key_file {
            Some(ref filename) => {
                let mut key = Key::default();
                let mut file = std::fs::File::open(filename).map_err(|err| {
                    anyhow::Error::new(err).context(format!("couldn't open key file {}", filename.to_string_lossy()))
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

enum RunFuture {
    ListenerClose,
    Timeout,
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
    let mut servers = addrs
        .into_iter()
        .map(|ip_addr| {
            let socket_addr = net::SocketAddr::new(ip_addr, port);
            log::info!(socket_addr:?; "listening");

            let shutdown = signal::ctrl_c().map(move |res| match res {
                Ok(()) => {
                    log::info!(socket_addr:?; "caught ctrl-c")
                }
                Err(err) => {
                    log::error!(err:err, socket_addr:?; "error waiting on ctrl-c")
                }
            });

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

            Either::Right(
                builder
                    .add_service(unlocker)
                    .serve_with_shutdown(socket_addr, shutdown)
                    .map(move |res| match res {
                        Err(err) => Err(anyhow::Error::new(err).context(socket_addr)),
                        Ok(()) => Ok(RunFuture::ListenerClose),
                    }),
            )
        })
        .collect::<FuturesUnordered<_>>();

    if let Some(timeout_secs) = timeout_secs {
        servers.push(Either::Left(
            tokio_time::sleep(timeout_secs).map(|_| Ok(RunFuture::Timeout)),
        ));
    }

    while let Some(res) = servers.next().await {
        match res {
            Ok(RunFuture::ListenerClose) => continue,
            Ok(RunFuture::Timeout) => {
                log::info!("timed out, exiting");
                return Ok(());
            }
            Err(err) => log::error!(err:?; "server encountered error"),
        }
    }
    Ok(())
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
