use std::{env, net::SocketAddr, time::Duration};

use anyhow::{Result, bail};

use crate::queue::{DEFAULT_STREAM_NAME, DEFAULT_TOPIC_NAME};

pub const DEFAULT_PORT: u16 = 11256;

#[derive(Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub private_key: Option<String>,
    pub alchemy_api_key: Option<String>,
    pub iggy_url: String,
    pub iggy_consumer_url: String,
    pub iggy_provisioner_url: String,
    pub redis_url: String,
    pub queue_worker_enabled: bool,
    pub telegram_bot_token: Option<String>,
    pub telegram_chat_id: Option<String>,
    pub global_write_limit: u64,
    /// Absolute ceiling on `max_fee_per_gas`, in wei. A write priced above
    /// this is never signed; the batch returns to the queue instead.
    pub max_gas_price_wei: u128,
    pub iggy_enqueue_timeout: Duration,
    pub iggy_consumer_group: String,
    /// Iggy stream this deployment owns. Multiple applications sharing one
    /// Iggy server are isolated by stream name, not by connection URL.
    pub iggy_stream: String,
    pub iggy_topic: String,
    /// The deployed registry address (P256_INDEX_CONTRACT_ADDRESS). Always
    /// required — the service is meaningless without a registry to read.
    pub contract_address: String,
    /// The frozen signature-domain address (P256_INDEX_DOMAIN_REGISTRY),
    /// defaulting to `contract_address`. From registry VERSION 12 the
    /// challenge domain is baked in at deployment, so a migration
    /// deployment is read and written at `contract_address` while every
    /// challenge keeps binding the ORIGINAL registry's address — the two
    /// only differ after a migration, and must match the deployed
    /// contract's DOMAIN_REGISTRY.
    pub domain_registry: String,
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
        let max_gas_price_wei = optional("P256_INDEX_MAX_GAS_PRICE_WEI")
            .map(|value| value.parse::<u128>())
            .transpose()?
            .unwrap_or(p256_registrar::gas::DEFAULT_MAX_FEE_WEI);
        if max_gas_price_wei == 0 {
            bail!("P256_INDEX_MAX_GAS_PRICE_WEI must be greater than zero");
        }
        let contract_address = required("P256_INDEX_CONTRACT_ADDRESS")?;
        let domain_registry =
            optional("P256_INDEX_DOMAIN_REGISTRY").unwrap_or_else(|| contract_address.clone());

        Ok(Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], port)),
            private_key,
            alchemy_api_key: optional("ALCHEMY_API_KEY"),
            iggy_url,
            iggy_consumer_url,
            iggy_provisioner_url,
            redis_url,
            queue_worker_enabled: optional("QUEUE_WORKER").as_deref() != Some("0"),
            telegram_bot_token: optional("TELEGRAM_BOT_TOKEN"),
            telegram_chat_id: optional("TELEGRAM_CHAT_ID"),
            global_write_limit,
            max_gas_price_wei,
            contract_address,
            domain_registry,
            iggy_enqueue_timeout: Duration::from_secs(
                optional("P256_INDEX_IGGY_ENQUEUE_TIMEOUT_SECS")
                    .map(|value| value.parse::<u64>())
                    .transpose()?
                    .unwrap_or(5),
            ),
            iggy_consumer_group: optional("P256_INDEX_IGGY_CONSUMER_GROUP")
                .unwrap_or_else(|| "p256-index-server-v1".into()),
            iggy_stream: optional("P256_INDEX_IGGY_STREAM")
                .unwrap_or_else(|| DEFAULT_STREAM_NAME.into()),
            iggy_topic: optional("P256_INDEX_IGGY_TOPIC")
                .unwrap_or_else(|| DEFAULT_TOPIC_NAME.into()),
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

#[cfg(test)]
mod tests {
    use super::required_value;

    #[test]
    fn the_shipped_gas_cap_leaves_room_above_the_live_gnosis_base_fee() {
        // The default must never be tight enough to throttle normal traffic:
        // a cap below the market silently stalls every registration instead of
        // failing loudly. Observed Gnosis base fee is ~9_000 wei.
        const { assert!(p256_registrar::gas::DEFAULT_MAX_FEE_WEI > 9_960 * 100) };
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
