//! Deployment configuration, read from Worker vars and secrets. The same
//! vocabulary as the docker shell's `Config`, minus Redis/Iggy (their roles
//! are played by the Durable Object) and the listen address (the platform
//! owns transport).

use worker::Env;

pub const FALLBACK_RPCS: &[&str] = &[
    "https://rpc.gnosischain.com",
    "https://gnosis-rpc.publicnode.com",
];
pub const WRITE_RPCS: &[&str] = &[
    "https://rpc.gnosischain.com",
    "https://gnosis-rpc.publicnode.com",
];

#[derive(Clone)]
pub struct CfConfig {
    /// The deployed registry address. Always required.
    pub contract_address: String,
    /// The frozen signature-domain address, defaulting to `contract_address`
    /// (they differ only after a registry migration).
    pub domain_registry: String,
    /// Secret. Optional: without it the API is read-only and the Durable
    /// Object's submission alarm stays idle, exactly like the docker shell
    /// with an unset PRIVATE_KEY.
    pub private_key: Option<String>,
    pub global_write_limit: u64,
    /// Absolute ceiling on `max_fee_per_gas`, in wei.
    pub max_gas_price_wei: u128,
    pub read_rpcs: Vec<String>,
    pub write_rpcs: Vec<String>,
    /// Secrets; both must be set for operator alerts to be delivered.
    pub telegram_bot_token: Option<String>,
    pub telegram_chat_id: Option<String>,
    /// Optional build tag echoed by the daily heartbeat.
    pub release: Option<String>,
}

impl CfConfig {
    pub fn from_env(env: &Env) -> worker::Result<Self> {
        let contract_address = required(env, "P256_INDEX_CONTRACT_ADDRESS")?;
        let domain_registry =
            optional(env, "P256_INDEX_DOMAIN_REGISTRY").unwrap_or_else(|| contract_address.clone());
        let private_key = secret(env, "PRIVATE_KEY");
        let global_write_limit = optional(env, "GLOBAL_WRITE_LIMIT")
            .and_then(|value| value.parse().ok())
            .unwrap_or(40);
        let max_gas_price_wei = optional(env, "P256_INDEX_MAX_GAS_PRICE_WEI")
            .and_then(|value| value.parse().ok())
            .unwrap_or(p256_registrar::gas::DEFAULT_MAX_FEE_WEI);

        let read_rpcs = list(env, "P256_INDEX_READ_RPCS")
            .unwrap_or_else(|| FALLBACK_RPCS.iter().map(|url| (*url).to_owned()).collect());
        let mut write_rpcs = list(env, "P256_INDEX_WRITE_RPCS")
            .unwrap_or_else(|| WRITE_RPCS.iter().map(|url| (*url).to_owned()).collect());
        if let Some(key) = secret(env, "ALCHEMY_API_KEY") {
            write_rpcs.insert(0, format!("https://gnosis-mainnet.g.alchemy.com/v2/{key}"));
        }

        Ok(Self {
            contract_address,
            domain_registry,
            private_key,
            global_write_limit,
            max_gas_price_wei,
            read_rpcs,
            write_rpcs,
            telegram_bot_token: secret(env, "TELEGRAM_BOT_TOKEN"),
            telegram_chat_id: secret(env, "TELEGRAM_CHAT_ID"),
            release: optional(env, "RELEASE"),
        })
    }
}

fn required(env: &Env, name: &str) -> worker::Result<String> {
    optional(env, name)
        .ok_or_else(|| worker::Error::RustError(format!("missing required variable: {name}")))
}

fn optional(env: &Env, name: &str) -> Option<String> {
    // A value may arrive as a var or (for local `.dev.vars` workflows) a
    // secret; accept either.
    env.var(name)
        .map(|value| value.to_string())
        .ok()
        .or_else(|| secret(env, name))
        .filter(|value| !value.is_empty())
}

fn secret(env: &Env, name: &str) -> Option<String> {
    env.secret(name)
        .map(|value| value.to_string())
        .ok()
        .filter(|value| !value.is_empty())
}

fn list(env: &Env, name: &str) -> Option<Vec<String>> {
    let raw = optional(env, name)?;
    let urls: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_owned)
        .collect();
    (!urls.is_empty()).then_some(urls)
}
