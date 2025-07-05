use core::net;
use std::collections::HashSet;

use futures::{SinkExt, StreamExt};
use log::debug;
use tokio::{
    net::unix,
    sync::{broadcast, mpsc, watch},
};
use tokio_util::codec::{FramedRead, FramedWrite, LinesCodec};

use crate::types::{Attempt, Toggle, ToggleKind};

pub async fn stream_attempts(
    stream: unix::OwnedReadHalf,
    updates: mpsc::Sender<Attempt>,
) -> anyhow::Result<()> {
    let codec = LinesCodec::new();
    let mut lines = FramedRead::new(stream, codec);
    while let Some(line) = lines.next().await.transpose().expect("failed to read line") {
        let attempt: Attempt = serde_json::from_str(&line).expect("invalid attempt");
        updates.send(attempt).await.expect("failed to send update");
    }
    Ok(())
}

pub async fn sink_attempts(
    sink: unix::OwnedWriteHalf,
    mut updates: broadcast::Receiver<Attempt>,
) -> () {
    let codec = LinesCodec::new();
    let mut lines = FramedWrite::new(sink, codec);
    while let Ok(attempt) = updates.recv().await {
        let attempt = serde_json::to_string(&attempt).expect("invalid attempt");
        lines.send(attempt).await.expect("failed to send update");
    }
}

pub async fn stream_allowed(
    stream: unix::OwnedReadHalf,
    updates: watch::Sender<HashSet<(net::IpAddr, uuid::Uuid)>>,
) -> () {
    let codec = LinesCodec::new();
    let mut lines = FramedRead::new(stream, codec);
    while let Some(line) = lines.next().await.transpose().expect("failed to read line") {
        let allow: Toggle = serde_json::from_str(&line).expect("invalid allow");
        debug!(allow:?; "received allow update");
        updates.send_modify(|set| match allow.kind {
            ToggleKind::Allow => {
                set.insert((allow.ip, allow.uuid));
            }
            ToggleKind::Block => {
                set.remove(&(allow.ip, allow.uuid));
            }
        });
    }
}

pub async fn sink_allowed(
    sink: unix::OwnedWriteHalf,
    mut updates: mpsc::Receiver<Toggle>,
) -> anyhow::Result<()> {
    let codec = LinesCodec::new();
    let mut lines = FramedWrite::new(sink, codec);
    while let Some(allow) = updates.recv().await {
        let allow = serde_json::to_string(&allow).expect("invalid allow");
        debug!(allow:?; "sent allow update");
        lines.send(allow).await.expect("failed to send update");
    }
    Ok(())
}
