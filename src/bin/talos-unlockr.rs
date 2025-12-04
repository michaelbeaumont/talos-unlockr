use std::{
    collections::HashSet,
    fs::set_permissions,
    io::{Read, stdin},
    net,
    os::{
        fd::{FromRawFd, IntoRawFd},
        unix::fs::PermissionsExt,
    },
    str::FromStr,
    time,
};

use anyhow::Context;
use chacha20poly1305::Key;
use clap::{Args, Parser};
use futures::future::{Either, join};
use futures_util::FutureExt;
use libsystemd::activation::IsType;
use std::sync::Arc;
use tokio::{
    signal,
    sync::{broadcast, watch, Notify},
    task::JoinSet,
};
use tokio_util::{
    future::FutureExt as _, sync::CancellationToken, task::task_tracker::TaskTracker,
};
use tonic::transport::{Identity, Server, ServerTlsConfig, server::TcpIncoming};

use talos_unlockr::{KeySource, Unlocker, sync, unix};
use uuid::Uuid;

fn parse_duration(arg: &str) -> Result<std::time::Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(std::time::Duration::from_secs(seconds))
}

fn parse_colon_separated(arg: &str) -> anyhow::Result<(net::IpAddr, Uuid)> {
    let (raw_ip, raw_uuid) = arg.split_once("/").context("couldn't split on slash")?;
    Ok((
        net::IpAddr::from_str(raw_ip).context("invalid IP")?,
        Uuid::from_str(raw_uuid).context("invalid UUID")?,
    ))
}

#[derive(Debug, Args)]
struct TlsCli {
    #[arg(long, required = false)]
    tls_key: std::path::PathBuf,
    #[arg(long, required = false)]
    tls_cert: std::path::PathBuf,
}

#[derive(Debug, Args)]
struct ListenCli {
    #[arg(long, required = false)]
    interface: Option<String>,
    #[arg(long, required = false)]
    port: u16,
}

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long, value_parser = parse_duration)]
    timeout_secs: Option<time::Duration>,
    #[command(flatten)]
    listen: Option<ListenCli>,
    #[arg(long, conflicts_with_all = ["interface", "port"])]
    named_sockets: bool,
    #[arg(long)]
    key_file: Option<std::path::PathBuf>,
    #[command(flatten)]
    tls: Option<TlsCli>,
    #[arg(long)]
    socket: Option<std::path::PathBuf>,
    #[arg(long, value_parser = parse_colon_separated)]
    allowed_ips: Vec<(net::IpAddr, Uuid)>,
}

struct Timeout {
    duration: time::Duration,
    activity_notify: Arc<Notify>,
}

struct Run {
    timeout: Option<Timeout>,
    listen: Either<(Vec<net::IpAddr>, u16), net::TcpListener>,
    key_source: KeySource,
    tls_identity: Option<Identity>,
    socket: Option<std::path::PathBuf>,
    allowed_ips: HashSet<(net::IpAddr, Uuid)>,
}

fn handle_args(args: Cli) -> Result<Run, anyhow::Error> {
    let key_source = {
        match args.key_file {
            Some(ref filename) => {
                let mut key = Key::default();
                let mut file = std::fs::File::open(filename).with_context(|| {
                    format!("couldn't open key file {}", filename.to_string_lossy())
                })?;
                let file_len = file
                    .metadata()
                    .map(|metadata| metadata.len())
                    .context("failed to get file metadata")?;

                if file_len == key.len() as u64 {
                    file.read_exact(&mut key)
                        .context("failed to read key from command line")?;
                    Ok(KeySource::Key(key))
                } else {
                    Err(anyhow::anyhow!(
                        "invalid key in file, expected length: {}, actual length: {}",
                        key.len(),
                        file_len,
                    ))
                }
            }
            None => Ok({
                let mut passphrase = String::new();
                println!("Using KDF with node UUID as salt...");
                println!(">>> Enter passphrase:");
                stdin()
                    .read_line(&mut passphrase)
                    .context("failed to read passphrase from stdin")?;
                KeySource::Kdf(passphrase.trim_end().to_owned().into_bytes())
            }),
        }
    }?;

    let listen = match (args.listen, args.named_sockets) {
        (_, true) => {
            let descriptors = libsystemd::activation::receive_descriptors_with_names(true)
                .context("failed to receive named sockets")?;
            let (fd, _) = descriptors
                .into_iter()
                .find(|(fd, name)| name == "grpc" && fd.is_inet())
                .expect("failed to find named inet socket");
            // SAFETY: systemd guarantees this is a valid socket file descriptor.
            Either::Right(unsafe { net::TcpListener::from_raw_fd(fd.into_raw_fd()) })
        }
        (
            Some(ListenCli {
                interface: None,
                port,
            }),
            _,
        ) => Either::Left((vec![net::Ipv6Addr::UNSPECIFIED.into()], port)),
        (
            Some(ListenCli {
                interface: Some(interface),
                port,
            }),
            _,
        ) => {
            let mut addrs: Vec<net::IpAddr> = Vec::new();
            for ifaddr in nix::ifaddrs::getifaddrs().expect("failed to get ifaddrs") {
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
            if addrs.is_empty() {
                anyhow::bail!("No addresses found for interface: {}", interface);
            }
            Either::Left((addrs, port))
        }
        (None, false) => {
            anyhow::bail!(
                "You must use either --named-sockets or --port (optionally with --interface)"
            );
        }
    };

    let tls_identity = if let Some(tls) = args.tls {
        let cert = std::fs::read_to_string(tls.tls_cert).context("failed to read TLS cert file")?;
        let key = std::fs::read_to_string(tls.tls_key).context("failed to read TLS key file")?;
        Some(Identity::from_pem(cert, key))
    } else {
        None
    };

    Ok(Run {
        timeout: args.timeout_secs.map(|duration| Timeout {
            duration,
            activity_notify: Arc::new(Notify::new()),
        }),
        listen,
        key_source,
        tls_identity,
        allowed_ips: args.allowed_ips.into_iter().collect(),
        socket: args.socket,
    })
}

impl Run {
    async fn run(self) -> Result<(), anyhow::Error> {
        let Run {
            timeout,
            listen,
            key_source,
            tls_identity,
            allowed_ips,
            socket,
        } = self;
        let cancelled = CancellationToken::new();

        const TCP_NODELAY: bool = true;
        let incoming = match listen {
            Either::Right(listener) => {
                let socket_addr = listener
                    .local_addr()
                    .context("failed to get local address")?;

                listener.set_nonblocking(true)?;
                let listener = tokio::net::TcpListener::from_std(listener)
                    .context("failed to convert from std listener")?;

                vec![(socket_addr, TcpIncoming::from(listener))]
            }
            Either::Left((addrs, port)) => addrs
                .into_iter()
                .flat_map(|ip| {
                    let socket_addr = net::SocketAddr::new(ip, port);
                    match TcpIncoming::bind(socket_addr) {
                        Ok(incoming) => Some((socket_addr, incoming)),
                        Err(err) => {
                            log::warn!(err:?, socket_addr:?; "failed to bind");
                            None
                        }
                    }
                })
                .collect::<Vec<_>>(),
        };

        let (update_allowed, allowed) = watch::channel(allowed_ips);
        let send_attempts = broadcast::Sender::new(10);
        let activity_notify = timeout.as_ref().map(|t| &t.activity_notify);

        let mut join_set: JoinSet<_> = incoming
            .into_iter()
            .map(|(socket_addr, incoming)| {
                log::info!(socket_addr:?; "listening");
                let unlocker =
                    Unlocker::new(key_source.clone(), allowed.clone(), send_attempts.clone(), activity_notify.cloned());

                let mut builder = Server::builder();
                if let Some(identity) = &tls_identity {
                    builder = builder
                        .tls_config(ServerTlsConfig::new().identity(identity.clone()))
                        .unwrap()
                }

                let cancelled = cancelled.clone();
                builder
                    .add_service(unlocker)
                    .serve_with_incoming_shutdown(
                        incoming.with_nodelay(Some(TCP_NODELAY)),
                        async move {
                            cancelled.cancelled_owned().await;
                            log::info!(socket_addr:?; "shutting down");
                        },
                    )
                    .map(move |err| err.context(socket_addr))
            })
            .collect();

        if let Some(raw_path) = &socket {
            let abstract_namespace_path = unix::to_abstract_namespace(raw_path);
            let path = abstract_namespace_path.as_ref().unwrap_or(raw_path);
            let listener =
                tokio::net::UnixListener::bind(path).context("failed to open unix socket")?;

            if abstract_namespace_path.is_none() {
                set_permissions(path, PermissionsExt::from_mode(0o777))
                    .context("failed to chmod unix socket")?;
            }

            let tasks = TaskTracker::new();
            let shutdown_tasks = tasks.clone();
            let cancelled_conn = cancelled.clone();

            let handle_conns = async move {
                loop {
                    let send_attempts = send_attempts.subscribe();
                    let (stream, sink) = listener
                        .accept()
                        .await
                        .expect("should accept")
                        .0
                        .into_split();

                    tasks.spawn(
                        join(
                            sync::sink_attempts(sink, send_attempts),
                            sync::stream_allowed(stream, update_allowed.clone()),
                        )
                        .with_cancellation_token_owned(cancelled_conn.clone()),
                    );
                }
            };

            join_set.spawn(
                handle_conns
                    .with_cancellation_token_owned(cancelled.clone())
                    .then(async move |_| {
                        log::info!("waiting for connections to shutdown");
                        shutdown_tasks.close();
                        shutdown_tasks.wait().await;
                    })
                    .map(Ok),
            );
        }

        let ctrl_c_cancelled = cancelled.clone();
        join_set.spawn(
            signal::ctrl_c()
                .map(move |res| {
                    res.expect("ctrl-c signal should work");
                    log::info!("caught ctrl-c");
                    ctrl_c_cancelled.cancel();
                    anyhow::Ok(())
                })
                .with_cancellation_token_owned(cancelled.clone())
                .map(move |_| {
                    if let Some(socket) = socket {
                        let _ = std::fs::remove_file(socket);
                    }
                    Ok(())
                }),
        );

        if let Some(Timeout { duration, activity_notify }) = timeout {
            let cancel_timeout = cancelled.clone();
            join_set.spawn(
                async move {
                    loop {
                        tokio::select! {
                            _ = tokio::time::sleep(duration) => {
                                log::info!("timed out after no activity, exiting");
                                cancel_timeout.cancel();
                                break;
                            }
                            _ = activity_notify.notified() => {
                                log::debug!("activity detected, resetting timeout");
                            }
                        }
                    }
                }
                .with_cancellation_token_owned(cancelled)
                .map(|_| Ok(())),
            );
        }

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
    log::info!(args:?; "starting unlockr");

    handle_args(args)?.run().await?;

    log::info!("finished");
    Ok(())
}
