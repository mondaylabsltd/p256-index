//! Operator alert delivery over Telegram — the only eyes on this unattended, fund-spending queue.
//!
//! Ported from the retired service's `sendTelegram`: bounded by a short timeout so a hung Telegram
//! API can never stall a caller, and — critically — it **warns instead of failing silently** on a
//! bad token / wrong chat id / network error, so a misconfigured alert channel is discoverable
//! rather than every alert vanishing without a trace.

use std::time::Duration;

use reqwest::Client;
use serde_json::json;

use crate::config::Config;

const TELEGRAM_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct Telegram {
    bot_token: String,
    chat_id: String,
    http: Client,
}

impl Telegram {
    /// Build a client only when both the bot token and chat id are non-empty; returns `None`
    /// otherwise so callers can log the "alerts will not be delivered" warning exactly once.
    pub fn new(bot_token: String, chat_id: String) -> Option<Self> {
        if bot_token.is_empty() || chat_id.is_empty() {
            return None;
        }
        let http = Client::builder().timeout(TELEGRAM_TIMEOUT).build().ok()?;
        Some(Self {
            bot_token,
            chat_id,
            http,
        })
    }

    pub fn from_config(config: &Config) -> Option<Self> {
        Self::new(
            config.telegram_bot_token.clone()?,
            config.telegram_chat_id.clone()?,
        )
    }

    /// Best-effort delivery: never returns an error to the caller, but a non-2xx response or a
    /// transport error is surfaced as a structured `warn` (the bot token is never logged).
    pub async fn send(&self, message: &str) {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);
        let request = self
            .http
            .post(url)
            .json(&json!({ "chat_id": self.chat_id, "text": message }))
            .send()
            .await;
        match request {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => {
                tracing::warn!(
                    dependency = "telegram",
                    operation = "sendMessage",
                    outcome = "failed",
                    http_status = response.status().as_u16(),
                    "telegram alert delivery failed"
                );
            }
            Err(_) => {
                tracing::warn!(
                    dependency = "telegram",
                    operation = "sendMessage",
                    outcome = "error",
                    "telegram alert delivery error"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::Telegram;
    use crate::config::Config;

    fn config_with(token: Option<&str>, chat: Option<&str>) -> Config {
        Config {
            listen_addr: "127.0.0.1:0".parse().expect("addr"),
            private_key: None,
            commit_private_key: None,
            alchemy_api_key: None,
            iggy_url: "iggy+tcp://unused".into(),
            iggy_consumer_url: "iggy+tcp://unused".into(),
            iggy_provisioner_url: "iggy+tcp://unused".into(),
            redis_url: "redis://unused".into(),
            queue_worker_enabled: false,
            telegram_bot_token: token.map(str::to_owned),
            telegram_chat_id: chat.map(str::to_owned),
            global_write_limit: 40,
            iggy_enqueue_timeout: Duration::from_secs(5),
            iggy_consumer_group: "test".into(),
        }
    }

    #[test]
    fn requires_both_token_and_chat_id() {
        assert!(Telegram::from_config(&config_with(Some("token"), Some("chat"))).is_some());
        assert!(Telegram::from_config(&config_with(Some("token"), None)).is_none());
        assert!(Telegram::from_config(&config_with(None, Some("chat"))).is_none());
        assert!(Telegram::from_config(&config_with(Some(""), Some("chat"))).is_none());
    }
}
