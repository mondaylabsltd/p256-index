//! Operator alert delivery over Telegram, on `fetch`: bounded by a short
//! abort timeout so a hung Telegram API can never stall the maintenance
//! pass, and it warns to the log instead of failing silently on a bad
//! token / wrong chat id / network error.

use std::time::Duration;

use futures_util::future::{Either, select};
use serde_json::json;
use worker::{AbortController, Delay, Fetch, Headers, Method, Request, RequestInit};

const TELEGRAM_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct Telegram {
    bot_token: String,
    chat_id: String,
}

impl Telegram {
    /// Build a client only when both the bot token and chat id are
    /// non-empty, so callers can log "alerts will not be delivered" once.
    pub fn new(bot_token: Option<String>, chat_id: Option<String>) -> Option<Self> {
        match (bot_token, chat_id) {
            (Some(bot_token), Some(chat_id)) if !bot_token.is_empty() && !chat_id.is_empty() => {
                Some(Self { bot_token, chat_id })
            }
            _ => None,
        }
    }

    /// Best-effort delivery: never returns an error, but a non-2xx response
    /// or a transport error is surfaced in the log (the token is never
    /// logged).
    pub async fn send(&self, message: &str) {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);
        let payload = json!({ "chat_id": self.chat_id, "text": message }).to_string();

        let attempt = async {
            let headers = Headers::new();
            headers.set("content-type", "application/json").ok()?;
            let mut init = RequestInit::new();
            init.with_method(Method::Post)
                .with_headers(headers)
                .with_body(Some(payload.into()));
            let request = Request::new_with_init(&url, &init).ok()?;
            let controller = AbortController::default();
            let signal = controller.signal();
            let fetch = Fetch::Request(request);
            let fetched = Box::pin(fetch.send_with_signal(&signal));
            let timer = Box::pin(Delay::from(TELEGRAM_TIMEOUT));
            match select(fetched, timer).await {
                Either::Left((Ok(response), _)) if response.status_code() < 300 => Some(()),
                Either::Left((_, _)) => None,
                Either::Right(((), _)) => {
                    controller.abort();
                    None
                }
            }
        };
        if attempt.await.is_none() {
            worker::console_warn!("telegram alert delivery failed");
        }
    }
}
