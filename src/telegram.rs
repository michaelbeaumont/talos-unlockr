use std::time::Duration;

use anyhow::Context;
use futures::{FutureExt, future::join};
use serde::{Deserialize, Serialize};
use teloxide::{
    dispatching::dialogue::{self, InMemStorage},
    prelude::*,
    sugar::bot::BotMessagesExt,
    types::{InlineKeyboardButton, InlineKeyboardMarkup, ParseMode},
};
use tokio::{sync::mpsc, time};
use tokio_util::sync::CancellationToken;

use crate::types::{Attempt, AttemptResponse, ClusterNodes, Toggle, ToggleKind};

#[derive(Clone, Default)]
struct State {}

pub async fn handle_attempts(
    bot: Bot,
    user_id: UserId,
    nodes: ClusterNodes,
    mut attempts: mpsc::Receiver<Attempt>,
) {
    while let Some(attempt) = attempts.recv().await {
        let Attempt {
            kind,
            addr,
            node,
            resp,
        } = attempt;
        let message = match resp {
            AttemptResponse::Block => {
                bot.send_message(
                    user_id,
                    format!(
                        "{kind:?} attempt by \n<strong>{node}</strong> from {addr}\n<strong>denied</strong>",
                    ),
                )
                .parse_mode(ParseMode::Html)
                .reply_markup(nodes.to_clusters_keyboard(
                    "Allow actions for your cluster",
                    |cluster| CallbackToggle::Allow { cluster },
                ))
                .await
            }
            AttemptResponse::Allow => {
                bot.send_message(
                    user_id,
                    format!(
                        "{kind:?} attempt by \n<strong>{node}</strong> from {addr}\n<strong>granted</strong>",
                    ),
                )
                .parse_mode(ParseMode::Html)
                .await
            }
        };
        if let Err(err) = message {
            log::error!(err:%; "failed to send message");
        }
    }
}

pub async fn telegram_loop(
    cancelled: CancellationToken,
    bot: Bot,
    user_id: UserId,
    nodes: ClusterNodes,
    allowed_nodes: mpsc::Sender<Toggle>,
) {
    let message_handler = Update::filter_message()
        .filter(move |msg: Message| msg.from.expect("has sender").id == user_id);

    let callback_handler = Update::filter_callback_query().endpoint(button_callback_handler);

    let mut dispatcher = Dispatcher::builder(
        bot.clone(),
        dialogue::enter::<Update, InMemStorage<State>, State, _>()
            .branch(message_handler)
            .branch(callback_handler),
    )
    .dependencies(dptree::deps![
        InMemStorage::<State>::new(),
        nodes,
        allowed_nodes,
        cancelled.clone()
    ])
    .build();

    let token = dispatcher.shutdown_token();
    join(
        cancelled
            .cancelled()
            .then(async move |()| token.shutdown().expect("not idle").await),
        dispatcher.dispatch(),
    )
    .await;
}

#[derive(Deserialize, Serialize)]
enum CallbackToggle {
    Allow { cluster: String },
    Block { cluster: String },
}

impl ClusterNodes {
    fn to_clusters_keyboard<F>(&self, msg: &str, mk: F) -> InlineKeyboardMarkup
    where
        F: Fn(String) -> CallbackToggle,
    {
        let mut keyboard: Vec<Vec<InlineKeyboardButton>> = vec![];

        for clusters in self.0.keys().collect::<Vec<_>>().chunks(3) {
            let row = clusters
                .iter()
                .cloned()
                .map(|cluster| {
                    let cluster = cluster.to_owned();
                    let data = mk(cluster.clone());
                    InlineKeyboardButton::callback(
                        msg,
                        serde_json::to_string(&data).expect("can't fail"),
                    )
                })
                .collect();

            keyboard.push(row);
        }

        InlineKeyboardMarkup::new(keyboard)
    }
}

const TIMEOUT: Duration = Duration::from_secs(30);

async fn button_callback_handler(
    cancelled: CancellationToken,
    bot: Bot,
    query: CallbackQuery,
    nodes: ClusterNodes,
    allowed_nodes: mpsc::Sender<Toggle>,
) -> anyhow::Result<()> {
    match query
        .data
        .as_ref()
        .ok_or(anyhow::anyhow!("no data present"))
        .and_then(|s| serde_json::from_str::<CallbackToggle>(s).context("failed to parse"))?
    {
        CallbackToggle::Allow { cluster } => {
            bot.answer_callback_query(query.id.clone()).await?;

            tokio::spawn(cancelled.clone().run_until_cancelled_owned({
                let timeout_nodes = nodes.clone();
                let allowed_nodes = allowed_nodes.clone();
                let cluster_name = cluster.clone();
                async move {
                    let Some(cluster) = timeout_nodes.0.get(&cluster_name) else {
                        return;
                    };
                    let permits = allowed_nodes
                        .reserve_many(cluster.len())
                        .await
                        .expect("no receiver");
                    for (permit, uuid) in permits.zip(cluster) {
                        let allow = Toggle {
                            kind: ToggleKind::Allow,
                            uuid: *uuid,
                        };
                        permit.send(allow);
                    }

                    log::info!(cluster=cluster_name; "nodes can now unseal!");
                    time::sleep(TIMEOUT).await;
                    log::info!(cluster=cluster_name; "timed out on unseal permission");

                    let permits = allowed_nodes
                        .reserve_many(cluster.len())
                        .await
                        .expect("no receiver");
                    for (permit, uuid) in permits.zip(cluster) {
                        let block = Toggle {
                            kind: ToggleKind::Block,
                            uuid: *uuid,
                        };
                        permit.send(block);
                    }
                }
            }));

            let text = format!("{cluster} nodes can now send requests!");
            if let Some(message) = query.regular_message() {
                bot.edit_text(message, text)
                    .await
                    .context("edit text after unseal")?;
                bot.edit_reply_markup(message)
                    .reply_markup(nodes.to_clusters_keyboard("Disallow actions", |cluster| {
                        CallbackToggle::Block { cluster }
                    }))
                    .await
                    .context("edit reply after unseal")?;
            } else if let Some(id) = query.inline_message_id {
                bot.edit_message_text_inline(id, text).await?;
            }
        }
        CallbackToggle::Block { cluster } => {
            bot.answer_callback_query(query.id.clone()).await?;

            let Some(cluster_nodes) = nodes.0.get(&cluster) else {
                let text = format!("Ignoring block for {cluster}!");
                if let Some(message) = query.regular_message() {
                    bot.edit_text(message, text).await?;
                } else if let Some(id) = query.inline_message_id {
                    bot.edit_message_text_inline(id, text).await?;
                }
                return Ok(());
            };

            let permits = allowed_nodes
                .reserve_many(cluster.len())
                .await
                .expect("no receiver");
            for (permit, uuid) in permits.zip(cluster_nodes) {
                permit.send(Toggle {
                    kind: ToggleKind::Block,
                    uuid: *uuid,
                });
            }

            let text = format!("{cluster} nodes can no longer seal or unseal!");
            if let Some(message) = query.regular_message() {
                bot.edit_text(message, text).await?;
            } else if let Some(id) = query.inline_message_id {
                bot.edit_message_text_inline(id, text).await?;
            }

            log::info!("{cluster} nodes can no longer seal or unseal!");
        }
    }

    Ok(())
}
