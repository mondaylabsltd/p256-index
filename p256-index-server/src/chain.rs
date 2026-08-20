use std::{
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use alloy::{
    consensus::{SignableTransaction, TxEip1559, TxEnvelope},
    eips::{eip2718::Encodable2718, eip2930::AccessList},
    network::TxSignerSync,
    primitives::{Address, B256, Bytes, TxKind, U256},
    signers::local::PrivateKeySigner,
};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use k256::SecretKey;
use reqwest::Client;
use serde_json::{Value, json};

use p256_registrar::{
    gas::{self, FeePlan, FeeVerdict},
    lookup::{Entry, Page, SiteItem},
    protocol::{
        CHAIN_ID, UNIT_REGISTERED_TOPIC, decode_bool, decode_entries_page, decode_entry,
        decode_has_entries, decode_rp_ids, decode_total, entries_by_key_calldata,
        entries_by_rp_id_calldata, get_entry_calldata, has_entries_calldata,
        is_content_registered_calldata, is_nonce_used_calldata, is_revert, register_calldata,
        rp_ids_calldata, total_entries_calldata, total_rp_ids_calldata, total_units_calldata,
    },
    roster::{Lane, Roster},
    task::RegisterTask,
};

// Chain's error vocabulary and its classification rules live in the registrar
// (`p256_registrar::protocol`); re-export the error type so `chain::ChainError`
// stays a valid path for the rest of the shell.
pub use p256_registrar::protocol::ChainError;

use crate::config::Config;

const FALLBACK_RPCS: &[&str] = &[
    "https://rpc.gnosischain.com",
    "https://gnosis-rpc.publicnode.com",
];
const WRITE_RPCS: &[&str] = &[
    "https://rpc.gnosischain.com",
    "https://gnosis-rpc.publicnode.com",
];

#[derive(Clone)]
pub struct Chain {
    rpc: RpcPool,
    registry_address: Address,
    signer_key: Option<SecretKey>,
    /// Absolute ceiling on `max_fee_per_gas`; see [`Config::max_gas_price_wei`].
    max_gas_price_wei: U256,
}

/// Transport wrapper around the registrar's [`Roster`]: selection, cooldown
/// and the circuit verdict are decisions and live there; HTTP, error
/// translation and the retry loop stay here.
#[derive(Clone)]
struct RpcPool {
    http: Client,
    roster: Arc<Mutex<Roster>>,
}

/// The service runs a single funded wallet (there is no commit wallet — the
/// registry has no commit-reveal). The enum survives as the broadcast
/// ledger's role vocabulary.
#[derive(Clone, Copy)]
pub enum WalletRole {
    Register,
}

impl WalletRole {
    pub fn ledger_name(self) -> &'static str {
        match self {
            Self::Register => "register",
        }
    }
}

struct Transaction {
    to: Address,
    data: Bytes,
    value: U256,
    nonce: u64,
    gas_limit: u64,
    fees: FeePlan,
}

/// A transaction that reached the network, plus the ceiling it was signed at.
/// The fee travels with the hash so the broadcast ledger can record it and the
/// unstick sweep can price a replacement against it rather than the market.
#[derive(Clone, Debug)]
pub struct Broadcast {
    pub hash: String,
    /// `(max_fee_per_gas, max_priority_fee_per_gas)` as signed. Both are needed
    /// because a same-nonce replacement must outbid the old transaction on each
    /// axis independently.
    pub fees_wei: Option<(u128, u128)>,
}

/// A definite receipt verdict. On success the receipt's UnitRegistered log
/// yields the unit's first entry id (absent for non-register transactions).
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum ReceiptOutcome {
    Success { first_entry_id: Option<u64> },
    Reverted,
}

/// Read-only chain surface used by the HTTP API. Keeping this boundary
/// explicit makes the public endpoint contract testable without a live RPC
/// endpoint or a signing key.
#[async_trait]
pub trait ReadChain: Send + Sync {
    fn rpc_circuit_state(&self) -> &'static str;
    /// The configured registry address, EIP-55 checksummed.
    fn registry_address(&self) -> String;
    async fn entry(&self, entry_id: u64) -> Result<Option<Entry>, ChainError>;
    async fn entries_by_key(
        &self,
        public_key: &str,
        page: u64,
        page_size: u64,
        descending: bool,
    ) -> Result<Page<Entry>, ChainError>;
    async fn entries_by_rp_id(
        &self,
        rp_id: &str,
        page: u64,
        page_size: u64,
        descending: bool,
    ) -> Result<Page<Entry>, ChainError>;
    async fn rp_ids(
        &self,
        page: u64,
        page_size: u64,
        descending: bool,
    ) -> Result<Page<SiteItem>, ChainError>;
    /// (total entries, total units, total rpIds)
    async fn totals(&self) -> Result<(u64, u64, u64), ChainError>;
    async fn is_nonce_used(&self, public_key: Vec<u8>, unit_nonce: B256) -> Result<bool, ChainError>;
    async fn is_content_registered(&self, content_hash: B256) -> Result<bool, ChainError>;
}

impl Chain {
    pub fn new(config: &Config) -> Result<Self> {
        let signer_key = config
            .private_key
            .as_deref()
            .map(parse_secret_key)
            .transpose()?;
        let mut writes = WRITE_RPCS
            .iter()
            .map(|url| (*url).to_owned())
            .collect::<Vec<_>>();
        if let Some(key) = config.alchemy_api_key.as_deref() {
            writes.insert(0, format!("https://gnosis-mainnet.g.alchemy.com/v2/{key}"));
        }
        Ok(Self {
            rpc: RpcPool::new(
                FALLBACK_RPCS.iter().map(|url| (*url).to_owned()).collect(),
                writes,
            )?,
            registry_address: Address::from_str(&config.contract_address)
                .map_err(|_| anyhow!("P256_INDEX_CONTRACT_ADDRESS is not a valid address"))?,
            signer_key,
            max_gas_price_wei: U256::from(config.max_gas_price_wei),
        })
    }

    pub fn rpc_circuit_state(&self) -> &'static str {
        if self.rpc.read_available() {
            "closed"
        } else {
            "open"
        }
    }

    pub fn has_signer(&self) -> bool {
        self.signer_key.is_some()
    }

    pub fn chain_id(&self) -> u64 {
        CHAIN_ID
    }

    // ── Reads ──────────────────────────────────────────────────────────────

    pub async fn entry(&self, entry_id: u64) -> Result<Option<Entry>, ChainError> {
        match self
            .call_contract(self.registry_address, get_entry_calldata(entry_id))
            .await
        {
            Ok(bytes) => decode_entry(&bytes)
                .map(Some)
                .map_err(|_| ChainError::InvalidResponse),
            Err(ChainError::Reverted(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn entries_by_key(
        &self,
        public_key: &str,
        page: u64,
        page_size: u64,
        descending: bool,
    ) -> Result<Page<Entry>, ChainError> {
        let key = hex::decode(public_key.strip_prefix("0x").unwrap_or(public_key))
            .map_err(|_| ChainError::InvalidResponse)?;
        let offset = page.saturating_sub(1).saturating_mul(page_size);
        let bytes = self
            .call_contract(
                self.registry_address,
                entries_by_key_calldata(key, offset, page_size, descending),
            )
            .await?;
        let (total, items) =
            decode_entries_page(&bytes).map_err(|_| ChainError::InvalidResponse)?;
        Ok(Page {
            total,
            page,
            page_size,
            items,
        })
    }

    pub async fn entries_by_rp_id(
        &self,
        rp_id: &str,
        page: u64,
        page_size: u64,
        descending: bool,
    ) -> Result<Page<Entry>, ChainError> {
        let offset = page.saturating_sub(1).saturating_mul(page_size);
        let bytes = self
            .call_contract(
                self.registry_address,
                entries_by_rp_id_calldata(rp_id.to_owned(), offset, page_size, descending),
            )
            .await?;
        let (total, items) =
            decode_entries_page(&bytes).map_err(|_| ChainError::InvalidResponse)?;
        Ok(Page {
            total,
            page,
            page_size,
            items,
        })
    }

    pub async fn rp_ids(
        &self,
        page: u64,
        page_size: u64,
        descending: bool,
    ) -> Result<Page<SiteItem>, ChainError> {
        let offset = page.saturating_sub(1).saturating_mul(page_size);
        let bytes = self
            .call_contract(
                self.registry_address,
                rp_ids_calldata(offset, page_size, descending),
            )
            .await?;
        let (total, items) = decode_rp_ids(&bytes).map_err(|_| ChainError::InvalidResponse)?;
        Ok(Page {
            total,
            page,
            page_size,
            items: items
                .into_iter()
                .map(|(rp_id, entry_count, created_at)| SiteItem {
                    rp_id,
                    entry_count,
                    created_at,
                })
                .collect(),
        })
    }

    pub async fn totals(&self) -> Result<(u64, u64, u64), ChainError> {
        let entries = self
            .call_contract(self.registry_address, total_entries_calldata())
            .await
            .and_then(|bytes| decode_total(&bytes).map_err(|_| ChainError::InvalidResponse))?;
        let units = self
            .call_contract(self.registry_address, total_units_calldata())
            .await
            .and_then(|bytes| decode_total(&bytes).map_err(|_| ChainError::InvalidResponse))?;
        let rp_ids = self
            .call_contract(self.registry_address, total_rp_ids_calldata())
            .await
            .and_then(|bytes| decode_total(&bytes).map_err(|_| ChainError::InvalidResponse))?;
        Ok((entries, units, rp_ids))
    }

    pub async fn has_entries(&self, public_key: &str) -> Result<bool, ChainError> {
        let key = hex::decode(public_key.strip_prefix("0x").unwrap_or(public_key))
            .map_err(|_| ChainError::InvalidResponse)?;
        let bytes = self
            .call_contract(self.registry_address, has_entries_calldata(key))
            .await?;
        decode_has_entries(&bytes).map_err(|_| ChainError::InvalidResponse)
    }

    pub async fn is_nonce_used(
        &self,
        public_key: Vec<u8>,
        unit_nonce: B256,
    ) -> Result<bool, ChainError> {
        let bytes = self
            .call_contract(
                self.registry_address,
                is_nonce_used_calldata(public_key, unit_nonce),
            )
            .await?;
        decode_bool(&bytes).map_err(|_| ChainError::InvalidResponse)
    }

    pub async fn is_content_registered(&self, content_hash: B256) -> Result<bool, ChainError> {
        let bytes = self
            .call_contract(
                self.registry_address,
                is_content_registered_calldata(content_hash),
            )
            .await?;
        decode_bool(&bytes).map_err(|_| ChainError::InvalidResponse)
    }

    pub async fn gas_price(&self) -> Result<U256, ChainError> {
        let value = self.rpc.call("eth_gasPrice", json!([])).await?;
        parse_u256_value(&value)
    }

    pub async fn current_block(&self) -> Result<u64, ChainError> {
        let value = self.rpc.call("eth_blockNumber", json!([])).await?;
        parse_quantity_value(&value)
    }

    pub async fn pending_nonce(&self, role: WalletRole) -> Result<u64, ChainError> {
        let address = self.wallet_address(role)?;
        let value = self
            .rpc
            .call(
                "eth_getTransactionCount",
                json!([address.to_string(), "pending"]),
            )
            .await?;
        parse_quantity_value(&value)
    }

    pub async fn confirmed_nonce(&self, role: WalletRole) -> Result<u64, ChainError> {
        let address = self.wallet_address(role)?;
        let value = self
            .rpc
            .call(
                "eth_getTransactionCount",
                json!([address.to_string(), "latest"]),
            )
            .await?;
        parse_quantity_value(&value)
    }

    pub async fn balance(&self, role: WalletRole) -> Result<U256, ChainError> {
        let address = self.wallet_address(role)?;
        let value = self
            .rpc
            .call("eth_getBalance", json!([address.to_string(), "latest"]))
            .await?;
        parse_u256_value(&value)
    }

    // ── Writes ─────────────────────────────────────────────────────────────

    /// One register() transaction for one task.
    pub async fn register(&self, task: &RegisterTask, nonce: u64) -> Result<Broadcast, ChainError> {
        let data = register_calldata(task)
            .map_err(|_| ChainError::Rejected("could not encode a register call".into()))?;
        self.send_contract_transaction(WalletRole::Register, self.registry_address, data, nonce)
            .await
    }

    /// Wait for a definite receipt. On success, parse the UnitRegistered log
    /// for the unit's first entry id.
    pub async fn wait_for_receipt(
        &self,
        hash: &str,
        timeout: Duration,
    ) -> Result<ReceiptOutcome, ChainError> {
        let started = Instant::now();
        while started.elapsed() < timeout {
            let value = self
                .rpc
                .call("eth_getTransactionReceipt", json!([hash]))
                .await?;
            if value.is_null() {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            let status = value
                .get("status")
                .and_then(Value::as_str)
                .ok_or(ChainError::InvalidResponse)?;
            return match status {
                "0x1" | "0x01" => Ok(ReceiptOutcome::Success {
                    first_entry_id: parse_first_entry_id(&value),
                }),
                _ => Ok(ReceiptOutcome::Reverted),
            };
        }
        Err(ChainError::Unavailable)
    }

    /// Replace a stuck nonce with a zero-value self-transfer. `fees` comes from
    /// [`p256_registrar::gas::plan_replacement`], which prices against the
    /// stuck transaction's own fee so the replacement always clears the node's
    /// 110% admission rule.
    pub async fn cancel_stuck_nonce(
        &self,
        role: WalletRole,
        nonce: u64,
        fees: FeePlan,
    ) -> Result<String, ChainError> {
        let address = self.wallet_address(role)?;
        self.send_transaction(
            role,
            Transaction {
                to: address,
                data: Bytes::new(),
                value: U256::ZERO,
                nonce,
                gas_limit: 21_000,
                fees,
            },
        )
        .await
    }

    async fn call_contract(&self, to: Address, data: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let result = self
            .rpc
            .call("eth_call", json!([{ "to": to.to_string(), "data": format!("0x{}", hex::encode(data)) }, "latest"]))
            .await?;
        let value = result.as_str().ok_or(ChainError::InvalidResponse)?;
        decode_rpc_bytes(value)
    }

    async fn send_contract_transaction(
        &self,
        role: WalletRole,
        to: Address,
        data: Vec<u8>,
        nonce: u64,
    ) -> Result<Broadcast, ChainError> {
        let key = self.wallet_key(role)?;
        let from = signer_address(key);
        let url = self.rpc.select_write().ok_or(ChainError::Unavailable)?;
        let estimate = self.estimate_gas_on(&url, from, to, &data).await?;
        let gas_limit = estimate.saturating_mul(120).saturating_div(100);
        if !gas::gas_limit_within_bounds(gas_limit) {
            return Err(ChainError::Rejected(format!(
                "gas limit {gas_limit} exceeds the {} cap",
                gas::MAX_GAS_LIMIT
            )));
        }

        // Price against the base fee, not against `eth_gasPrice`: the latter
        // is base fee + ~1 wei on Gnosis and leaves a broadcast includable in
        // only the block it was quoted against.
        let base_fee = self.base_fee_on(&url).await?;
        let fees = match self.fee_plan_from(base_fee) {
            FeeVerdict::Send(fees) => fees,
            FeeVerdict::TooExpensive { required, cap } => {
                return Err(ChainError::Rejected(gas::too_expensive_reason(
                    required, cap,
                )));
            }
        };

        // Refuse to broadcast a transaction the wallet cannot fund: a failed
        // send that still consumes the nonce is the expensive failure mode.
        let required = gas::required_balance(gas_limit, fees.max_fee_per_gas);
        let balance = self.balance_on(&url, from).await?;
        if balance < required {
            return Err(ChainError::Rejected(format!(
                "wallet {from} holds {balance} wei, below the {required} wei this write may cost"
            )));
        }

        let hash = self
            .send_transaction_on(
                &url,
                key,
                Transaction {
                    to,
                    data: Bytes::from(data),
                    value: U256::ZERO,
                    nonce,
                    gas_limit,
                    fees,
                },
            )
            .await?;
        Ok(Broadcast {
            hash,
            fees_wei: u128::try_from(fees.max_fee_per_gas)
                .ok()
                .zip(u128::try_from(fees.max_priority_fee_per_gas).ok()),
        })
    }

    /// The current fee verdict for a fresh write, used by the queue worker as a
    /// pre-flight gate: when the answer is [`FeeVerdict::TooExpensive`] the
    /// batch is returned to the queue unspent rather than failed.
    pub async fn fee_plan(&self) -> Result<FeeVerdict, ChainError> {
        Ok(self.fee_plan_from(self.base_fee().await?))
    }

    fn fee_plan_from(&self, base_fee: U256) -> FeeVerdict {
        gas::plan_fees(
            base_fee,
            U256::from(gas::DEFAULT_TIP_WEI),
            self.max_gas_price_wei,
        )
    }

    pub fn max_gas_price_wei(&self) -> U256 {
        self.max_gas_price_wei
    }

    async fn send_transaction(
        &self,
        role: WalletRole,
        transaction: Transaction,
    ) -> Result<String, ChainError> {
        let key = self.wallet_key(role)?;
        let url = self.rpc.select_write().ok_or(ChainError::Unavailable)?;
        self.send_transaction_on(&url, key, transaction).await
    }

    async fn send_transaction_on(
        &self,
        url: &str,
        key: &SecretKey,
        transaction: Transaction,
    ) -> Result<String, ChainError> {
        let signed = sign_eip1559(
            key,
            transaction.nonce,
            transaction.gas_limit,
            transaction.fees,
            transaction.to,
            transaction.value,
            transaction.data,
        )?;
        let result = self
            .rpc
            .call_on(
                url,
                "eth_sendRawTransaction",
                json!([format!("0x{}", hex::encode(signed))]),
            )
            .await?;
        result
            .as_str()
            .map(str::to_owned)
            .ok_or(ChainError::InvalidResponse)
    }

    async fn estimate_gas_on(
        &self,
        url: &str,
        from: Address,
        to: Address,
        data: &[u8],
    ) -> Result<u64, ChainError> {
        let value = self
            .rpc
            .call_on(
                url,
                "eth_estimateGas",
                json!([{ "from": from.to_string(), "to": to.to_string(), "data": format!("0x{}", hex::encode(data)) }]),
            )
            .await?;
        parse_quantity_value(&value)
    }

    async fn gas_price_on(&self, url: &str) -> Result<U256, ChainError> {
        let value = self.rpc.call_on(url, "eth_gasPrice", json!([])).await?;
        parse_u256_value(&value)
    }

    /// The pending block's base fee — the number every EIP-1559 price must be
    /// built on. Falls back to `eth_gasPrice` only on a pre-1559 answer.
    pub async fn base_fee(&self) -> Result<U256, ChainError> {
        let url = self.rpc.select_write().ok_or(ChainError::Unavailable)?;
        self.base_fee_on(&url).await
    }

    async fn base_fee_on(&self, url: &str) -> Result<U256, ChainError> {
        let value = self
            .rpc
            .call_on(url, "eth_getBlockByNumber", json!(["latest", false]))
            .await?;
        match value.get("baseFeePerGas") {
            Some(base_fee) => parse_u256_value(base_fee),
            None => self.gas_price_on(url).await,
        }
    }

    async fn balance_on(&self, url: &str, address: Address) -> Result<U256, ChainError> {
        let value = self
            .rpc
            .call("eth_getBalance", json!([address.to_string(), "latest"]))
            .await?;
        let _ = url;
        parse_u256_value(&value)
    }

    fn wallet_key(&self, role: WalletRole) -> Result<&SecretKey, ChainError> {
        let WalletRole::Register = role;
        self.signer_key.as_ref().ok_or(ChainError::MissingSigner)
    }

    pub fn wallet_address(&self, role: WalletRole) -> Result<Address, ChainError> {
        Ok(signer_address(self.wallet_key(role)?))
    }
}

/// Extract the unit's first entry id from a register receipt's
/// UnitRegistered(uint256 indexed unitId, bytes32 indexed rpIdHash,
/// uint256 firstEntryId, uint256 memberCount) log.
fn parse_first_entry_id(receipt: &Value) -> Option<u64> {
    let logs = receipt.get("logs")?.as_array()?;
    for log in logs {
        let topics = log.get("topics")?.as_array()?;
        if topics.first()?.as_str()? != UNIT_REGISTERED_TOPIC {
            continue;
        }
        let data = log.get("data")?.as_str()?;
        let raw = data.strip_prefix("0x").unwrap_or(data);
        if raw.len() < 64 {
            return None;
        }
        return u64::from_str_radix(raw[..64].trim_start_matches('0'), 16)
            .ok()
            .or(Some(0));
    }
    None
}

#[async_trait]
impl ReadChain for Chain {
    fn rpc_circuit_state(&self) -> &'static str {
        Chain::rpc_circuit_state(self)
    }

    fn registry_address(&self) -> String {
        self.registry_address.to_checksum(None)
    }

    async fn entry(&self, entry_id: u64) -> Result<Option<Entry>, ChainError> {
        Chain::entry(self, entry_id).await
    }

    async fn entries_by_key(
        &self,
        public_key: &str,
        page: u64,
        page_size: u64,
        descending: bool,
    ) -> Result<Page<Entry>, ChainError> {
        Chain::entries_by_key(self, public_key, page, page_size, descending).await
    }

    async fn entries_by_rp_id(
        &self,
        rp_id: &str,
        page: u64,
        page_size: u64,
        descending: bool,
    ) -> Result<Page<Entry>, ChainError> {
        Chain::entries_by_rp_id(self, rp_id, page, page_size, descending).await
    }

    async fn rp_ids(
        &self,
        page: u64,
        page_size: u64,
        descending: bool,
    ) -> Result<Page<SiteItem>, ChainError> {
        Chain::rp_ids(self, page, page_size, descending).await
    }

    async fn totals(&self) -> Result<(u64, u64, u64), ChainError> {
        Chain::totals(self).await
    }

    async fn is_nonce_used(&self, public_key: Vec<u8>, unit_nonce: B256) -> Result<bool, ChainError> {
        Chain::is_nonce_used(self, public_key, unit_nonce).await
    }

    async fn is_content_registered(&self, content_hash: B256) -> Result<bool, ChainError> {
        Chain::is_content_registered(self, content_hash).await
    }
}

impl RpcPool {
    fn new(reads: Vec<String>, writes: Vec<String>) -> Result<Self> {
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            http,
            roster: Arc::new(Mutex::new(Roster::new(reads, writes))),
        })
    }

    fn read_available(&self) -> bool {
        self.roster().circuit_state(monotonic_ms()) == "closed"
    }

    fn select_write(&self) -> Option<String> {
        self.roster().select(Lane::Write, monotonic_ms())
    }

    fn roster(&self) -> std::sync::MutexGuard<'_, Roster> {
        self.roster.lock().expect("rpc roster lock")
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, ChainError> {
        let attempts = self.roster().read_attempts();
        for _ in 0..attempts {
            let Some(url) = self.roster().select(Lane::Read, monotonic_ms()) else {
                break;
            };
            match self.call_on(&url, method, params.clone()).await {
                Ok(value) => return Ok(value),
                Err(ChainError::Reverted(error)) => return Err(ChainError::Reverted(error)),
                Err(_) => self.roster().mark_failed(&url, monotonic_ms()),
            }
        }
        Err(ChainError::Unavailable)
    }

    async fn call_on(&self, url: &str, method: &str, params: Value) -> Result<Value, ChainError> {
        let response = self
            .http
            .post(url)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            }))
            .send()
            .await
            .map_err(|_| ChainError::Unavailable)?;
        let body = response
            .error_for_status()
            .map_err(|_| ChainError::Unavailable)?
            .json::<Value>()
            .await
            .map_err(|_| ChainError::InvalidResponse)?;
        if let Some(error) = body.get("error") {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("RPC rejected request");
            let detail = error.get("data").map(Value::to_string).unwrap_or_default();
            let text = format!("{message} {detail}");
            if is_revert(&text) {
                return Err(ChainError::Reverted(text));
            }
            return Err(ChainError::Rejected(text));
        }
        let result = body
            .get("result")
            .cloned()
            .ok_or(ChainError::InvalidResponse)?;
        self.roster().mark_healthy(url);
        Ok(result)
    }
}

/// Process-monotonic milliseconds for the roster's cooldown arithmetic; the
/// roster only ever compares these to each other.
fn monotonic_ms() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

fn parse_secret_key(value: &str) -> Result<SecretKey> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))?;
    SecretKey::from_slice(&bytes).map_err(|_| anyhow!("PRIVATE_KEY is not a valid secp256k1 key"))
}

fn signer_address(key: &SecretKey) -> Address {
    let signer = PrivateKeySigner::from(key.clone());
    signer.address()
}

fn sign_eip1559(
    key: &SecretKey,
    nonce: u64,
    gas_limit: u64,
    fees: FeePlan,
    to: Address,
    value: U256,
    input: Bytes,
) -> Result<Vec<u8>, ChainError> {
    // These two are deliberately distinct. `max_fee_per_gas` is a ceiling, not
    // a price — the chain charges `min(max_fee, base_fee + priority)` — so the
    // headroom in it is free and is what keeps the transaction includable as
    // the base fee climbs.
    let max_fee_per_gas = u128::try_from(fees.max_fee_per_gas)
        .map_err(|_| ChainError::Rejected("gas price exceeds u128".into()))?;
    let max_priority_fee_per_gas = u128::try_from(fees.max_priority_fee_per_gas)
        .map_err(|_| ChainError::Rejected("priority fee exceeds u128".into()))?;
    let signer = PrivateKeySigner::from(key.clone());
    let mut transaction = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce,
        gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        to: TxKind::Call(to),
        value,
        access_list: AccessList::default(),
        input,
    };
    let signature = signer
        .sign_transaction_sync(&mut transaction)
        .map_err(|_| ChainError::Rejected("could not sign transaction".into()))?;
    let envelope: TxEnvelope = transaction.into_signed(signature).into();
    Ok(envelope.encoded_2718())
}

fn parse_quantity_value(value: &Value) -> Result<u64, ChainError> {
    let value = parse_u256_value(value)?;
    u64::try_from(value).map_err(|_| ChainError::InvalidResponse)
}

fn parse_u256_value(value: &Value) -> Result<U256, ChainError> {
    let value = value.as_str().ok_or(ChainError::InvalidResponse)?;
    U256::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16)
        .map_err(|_| ChainError::InvalidResponse)
}

fn decode_rpc_bytes(value: &str) -> Result<Vec<u8>, ChainError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(value).map_err(|_| ChainError::InvalidResponse)
}

#[cfg(test)]
mod tests {
    use alloy::primitives::U256;
    use serde_json::json;

    use super::{parse_first_entry_id, parse_quantity_value, parse_u256_value};

    #[test]
    fn parses_json_rpc_hex_quantities_without_precision_loss() {
        assert_eq!(parse_quantity_value(&json!("0x64")).unwrap(), 100);
        assert_eq!(
            parse_u256_value(&json!("0xffffffffffffffff")).unwrap(),
            U256::from(u64::MAX)
        );
    }

    #[test]
    fn extracts_the_first_entry_id_from_a_register_receipt() {
        let receipt = json!({
            "logs": [
                { "topics": ["0xdead"], "data": "0x" },
                {
                    "topics": [p256_registrar::protocol::UNIT_REGISTERED_TOPIC, "0x01", "0x02"],
                    // firstEntryId = 0x2a, memberCount = 3
                    "data": format!("0x{:064x}{:064x}", 0x2a, 3),
                },
            ]
        });
        assert_eq!(parse_first_entry_id(&receipt), Some(42));
        // firstEntryId zero decodes as zero, not None.
        let zero = json!({
            "logs": [{
                "topics": [p256_registrar::protocol::UNIT_REGISTERED_TOPIC],
                "data": format!("0x{:064x}{:064x}", 0, 1),
            }]
        });
        assert_eq!(parse_first_entry_id(&zero), Some(0));
        assert_eq!(parse_first_entry_id(&json!({"logs": []})), None);
    }

    use std::time::Duration;

    use crate::config::Config;

    fn offline_config(private_key: Option<&str>) -> Config {
        Config {
            listen_addr: "127.0.0.1:0".parse().expect("test address"),
            private_key: private_key.map(str::to_owned),
            alchemy_api_key: None,
            iggy_url: "iggy+tcp://unused".into(),
            iggy_consumer_url: "iggy+tcp://unused".into(),
            iggy_provisioner_url: "iggy+tcp://unused".into(),
            redis_url: "redis://unused".into(),
            queue_worker_enabled: false,
            telegram_bot_token: None,
            telegram_chat_id: None,
            max_gas_price_wei: p256_registrar::gas::DEFAULT_MAX_FEE_WEI,
            global_write_limit: 10_000,
            iggy_enqueue_timeout: Duration::from_secs(1),
            iggy_consumer_group: "test".into(),
            contract_address: "0x1111111111111111111111111111111111111111".into(),
        }
    }

    #[test]
    fn registry_address_renders_eip55_checksummed() {
        use super::ReadChain as _;
        let chain = super::Chain::new(&offline_config(None)).expect("read-only chain");
        assert_eq!(
            chain.registry_address(),
            "0x1111111111111111111111111111111111111111"
        );
        let mut mixed = offline_config(None);
        mixed.contract_address = "0xDD93420bd49baabdff4a363ddd300622ae87e9c3".into();
        let chain = super::Chain::new(&mixed).expect("read-only chain");
        // Re-checksummed, not echoed.
        assert_eq!(
            chain.registry_address(),
            "0xdd93420BD49baaBdFF4A363DdD300622Ae87E9c3"
        );
    }
}
