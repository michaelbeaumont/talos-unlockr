use std::time::Duration;

use anyhow::Context;
use futures::{FutureExt, SinkExt, StreamExt, channel::mpsc, future::join};
use serde::{Deserialize, Serialize};
use teloxide::{
    dispatching::dialogue::{self, InMemStorage},
    prelude::*,
    sugar::bot::BotMessagesExt,
    types::{InlineKeyboardButton, InlineKeyboardMarkup, ParseMode},
    utils::command::BotCommands,
};
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::types::{Attempt, AttemptResponse, ClusterNodes, Toggle, ToggleKind};

#[derive(BotCommands, Clone)]
#[command(
    rename_rule = "lowercase",
    description = "These commands are supported:"
)]
enum Command {
    #[command(description = "Permit UUIDs registered to this cluster to unseal")]
    Unseal,
}

#[derive(Clone, Default)]
struct State {}

type MyDialogue = Dialogue<State, InMemStorage<State>>;

pub async fn handle_attempts(
    bot: Bot,
    user_id: UserId,
    nodes: ClusterNodes,
    mut attempts: mpsc::Receiver<Attempt>,
) {
    while let Some(attempt) = attempts.next().await {
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
    let command_handler = teloxide::filter_command::<Command, _>().endpoint(unseal_command);

    let message_handler = Update::filter_message()
        .filter(move |msg: Message| msg.from.expect("has sender").id == user_id)
        .branch(command_handler);

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

        for clusters in self.keys().collect::<Vec<_>>().chunks(3) {
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

async fn unseal_command(bot: Bot, nodes: ClusterNodes, dialogue: MyDialogue) -> anyhow::Result<()> {
    log::info!(nodes:?; "Offering clusters to allow action for");
    bot.send_message(dialogue.chat_id(), "Allow one of your clusters:")
        .reply_markup(
            nodes
                .to_clusters_keyboard("Allow actions", |cluster| CallbackToggle::Allow { cluster }),
        )
        .await?;
    Ok(())
}

const TIMEOUT: Duration = Duration::from_secs(5);

async fn button_callback_handler(
    cancelled: CancellationToken,
    bot: Bot,
    query: CallbackQuery,
    nodes: ClusterNodes,
    mut allowed_nodes: mpsc::Sender<Toggle>,
) -> anyhow::Result<()> {
    match query
        .data
        .as_ref()
        .ok_or(anyhow::anyhow!("no data present"))
        .and_then(|s| serde_json::from_str::<CallbackToggle>(s).context("failed to parse"))?
    {
        CallbackToggle::Allow { cluster } => {
            let text = format!("{cluster} nodes can now send requests!");

            bot.answer_callback_query(query.id.clone()).await?;

            let timeout_nodes = nodes.clone();
            let allowed_nodes = allowed_nodes.clone();
            let cluster_name = cluster.clone();
            tokio::spawn(cancelled.clone().run_until_cancelled_owned(async move {
                let mut allowed_nodes = allowed_nodes;
                time::sleep(TIMEOUT).await;

                log::info!(cluster=cluster_name; "timed out on allowing {cluster_name}");
                for (ip, uuid) in timeout_nodes.iter().flat_map(|(_, nodes)| nodes.iter()) {
                    let _ = allowed_nodes
                        .send(Toggle {
                            kind: ToggleKind::Allow,
                            ip: *ip,
                            uuid: *uuid,
                        })
                        .await;

                    let block = Toggle {
                        kind: ToggleKind::Block,
                        ip: *ip,
                        uuid: *uuid,
                    };
                    let _ = allowed_nodes.send(block).await;
                }
            }));

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

            log::info!("{cluster} nodes can now unseal!");
        }
        CallbackToggle::Block { cluster } => {
            let text = format!("{cluster} nodes can no longer seal or unseal!");

            bot.answer_callback_query(query.id.clone()).await?;

            for (ip, uuid) in nodes.iter().flat_map(|(_, nodes)| nodes.iter()) {
                allowed_nodes
                    .send(Toggle {
                        kind: ToggleKind::Block,
                        ip: *ip,
                        uuid: *uuid,
                    })
                    .await?;
            }

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
