use std::{env, net::SocketAddr, time::Duration};

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

pub const DEFAULT_PORT: u16 = 11256;

#[derive(Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub private_key: Option<String>,
    pub commit_private_key: Option<String>,
    pub alchemy_api_key: Option<String>,
    pub iggy_url: String,
    pub iggy_consumer_url: String,
    pub iggy_provisioner_url: String,
    pub redis_url: String,
    pub queue_worker_enabled: bool,
    pub telegram_bot_token: Option<String>,
    pub telegram_chat_id: Option<String>,
    pub global_write_limit: u64,
    pub iggy_enqueue_timeout: Duration,
    pub iggy_consumer_group: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        match dotenvy::dotenv() {
            Ok(_) | Err(dotenvy::Error::Io(_)) => {}
            Err(error) => return Err(error.into()),
        }

        let port = optional("PORT")
            .map(|value| value.parse::<u16>())
            .transpose()?
            .unwrap_or(DEFAULT_PORT);
        let private_key = optional("PRIVATE_KEY");
        if let Some(key) = private_key.as_deref() {
            validate_private_key(key)?;
        }
        let commit_private_key = private_key.as_deref().map(derive_commit_key);

        let iggy_url = required("P256_INDEX_IGGY_URL")?;
        let redis_url = required("P256_INDEX_REDIS_URL")?;
        let iggy_consumer_url =
            optional("P256_INDEX_IGGY_CONSUMER_URL").unwrap_or_else(|| iggy_url.clone());
        let iggy_provisioner_url =
            optional("P256_INDEX_IGGY_PROVISIONER_URL").unwrap_or_else(|| iggy_url.clone());
        let global_write_limit = optional("GLOBAL_WRITE_LIMIT")
            .map(|value| value.parse::<u64>())
            .transpose()?
            .unwrap_or(40);
        if global_write_limit == 0 {
            bail!("GLOBAL_WRITE_LIMIT must be greater than zero");
        }

        Ok(Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], port)),
            private_key,
            commit_private_key,
            alchemy_api_key: optional("ALCHEMY_API_KEY"),
            iggy_url,
            iggy_consumer_url,
            iggy_provisioner_url,
            redis_url,
            queue_worker_enabled: optional("QUEUE_WORKER").as_deref() != Some("0"),
            telegram_bot_token: optional("TELEGRAM_BOT_TOKEN"),
            telegram_chat_id: optional("TELEGRAM_CHAT_ID"),
            global_write_limit,
            iggy_enqueue_timeout: Duration::from_secs(
                optional("P256_INDEX_IGGY_ENQUEUE_TIMEOUT_SECS")
                    .map(|value| value.parse::<u64>())
                    .transpose()?
                    .unwrap_or(5),
            ),
            iggy_consumer_group: optional("P256_INDEX_IGGY_CONSUMER_GROUP")
                .unwrap_or_else(|| "p256-index-server-v1".into()),
        })
    }
}

fn required(name: &str) -> Result<String> {
    required_value(name, optional(name))
}

fn required_value(name: &str, value: Option<String>) -> Result<String> {
    value.ok_or_else(|| anyhow::anyhow!("missing required environment variable: {name}"))
}

fn optional(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

fn validate_private_key(value: &str) -> Result<()> {
    let Some(value) = value.strip_prefix("0x") else {
        bail!("PRIVATE_KEY must be a 0x-prefixed 32-byte (64 hex character) private key");
    };
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("PRIVATE_KEY must be a 0x-prefixed 32-byte (64 hex character) private key");
    }
    Ok(())
}

fn derive_commit_key(private_key: &str) -> String {
    let bytes = hex::decode(private_key.strip_prefix("0x").unwrap_or(private_key))
        .expect("validated private key is hex");
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::{derive_commit_key, required_value};

    #[test]
    fn derives_a_distinct_commit_key_without_exposing_the_source() {
        let private_key = "0x0000000000000000000000000000000000000000000000000000000000000001";
        assert_eq!(
            derive_commit_key(private_key),
            "0xec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5"
        );
    }

    #[test]
    fn returns_the_connection_variable_when_present() {
        assert_eq!(
            required_value("P256_INDEX_IGGY_URL", Some("iggy+tcp://relay".into())).unwrap(),
            "iggy+tcp://relay"
        );
    }

    #[test]
    fn fails_when_a_required_connection_variable_is_missing() {
        let error = required_value("P256_INDEX_REDIS_URL", None).unwrap_err();
        assert!(error.to_string().contains("P256_INDEX_REDIS_URL"));
    }
}
