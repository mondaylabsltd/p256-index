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
    lookup::{Page, Record, SiteItem},
    protocol::{
        BATCH_HELPER_ADDRESS, CHAIN_ID, CONTRACT_ADDRESS, V2_CONTRACT_ADDRESS,
        batch_commit_calldata, batch_create_calldata, build_commitment, decode_commit_block,
        decode_has_record, decode_keys, decode_record, decode_record_by_wallet_ref, decode_sites,
        decode_total, decode_total_wallets, index_get_commit_block_calldata,
        index_get_record_by_wallet_ref_calldata, index_get_record_calldata,
        index_has_record_calldata, index_keys_calldata, index_sites_calldata, index_total_calldata,
        index_total_wallets_calldata, is_revert, wallet_create_calldata,
    },
    roster::{Lane, Roster},
    task::CreateTask,
    wallet::default_metadata,
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
    /// The frozen V2 index, probed directly for cross-version wallet conflicts.
    v2_address: Address,
    rpc: RpcPool,
    index_address: Address,
    batch_helper_address: Address,
    create_key: Option<SecretKey>,
    commit_key: Option<SecretKey>,
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

#[derive(Clone, Copy)]
pub enum WalletRole {
    Create,
    Commit,
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
    /// because a same-nonce replacement must outbid this transaction on each
    /// axis independently.
    pub fees_wei: Option<(u128, u128)>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ReceiptStatus {
    Success,
    Reverted,
}

/// Read-only chain surface used by the HTTP API. Keeping this boundary explicit makes the
/// public endpoint contract testable without a live RPC endpoint or a signing key.
#[async_trait]
pub trait ReadChain: Send + Sync {
    fn rpc_circuit_state(&self) -> &'static str;
    /// The RESOLVED active index address (env override applied), so operator
    /// surfaces like /api/health report what is actually being called.
    fn index_address(&self) -> String;
    async fn get_record(
        &self,
        rp_id: &str,
        credential_id: &str,
    ) -> Result<Option<Record>, ChainError>;
    async fn get_record_by_wallet_ref(
        &self,
        wallet_ref: B256,
    ) -> Result<Option<Record>, ChainError>;
    /// Direct read against the frozen V2 index (cross-version conflict probe).
    async fn get_v2_record_by_wallet_ref(
        &self,
        wallet_ref: B256,
    ) -> Result<Option<Record>, ChainError>;
    async fn total_credentials(&self) -> Result<u64, ChainError>;
    /// None when the active contract predates getTotalWallets (still on V2).
    async fn total_wallets(&self) -> Result<Option<u64>, ChainError>;
    async fn list_sites(
        &self,
        page: u64,
        page_size: u64,
        descending: bool,
    ) -> Result<Page<SiteItem>, ChainError>;
    async fn list_keys(
        &self,
        rp_id: &str,
        page: u64,
        page_size: u64,
        descending: bool,
    ) -> Result<Page<Record>, ChainError>;
}

impl Chain {
    pub fn new(config: &Config) -> Result<Self> {
        let create_key = config
            .private_key
            .as_deref()
            .map(parse_secret_key)
            .transpose()?;
        let commit_key = config
            .commit_private_key
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
            index_address: Address::from_str(
                config
                    .contract_address
                    .as_deref()
                    .unwrap_or(CONTRACT_ADDRESS),
            )?,
            v2_address: Address::from_str(V2_CONTRACT_ADDRESS)?,
            batch_helper_address: Address::from_str(BATCH_HELPER_ADDRESS)?,
            create_key,
            commit_key,
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

    pub fn has_signers(&self) -> bool {
        self.create_key.is_some() && self.commit_key.is_some()
    }

    pub async fn get_record(
        &self,
        rp_id: &str,
        credential_id: &str,
    ) -> Result<Option<Record>, ChainError> {
        let data = index_get_record_calldata(rp_id.to_owned(), credential_id.to_owned());
        match self.call_contract(self.index_address, data).await {
            Ok(bytes) => decode_record(&bytes)
                .map(Some)
                .map_err(|_| ChainError::InvalidResponse),
            Err(ChainError::Reverted(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn get_record_by_wallet_ref(
        &self,
        wallet_ref: B256,
    ) -> Result<Option<Record>, ChainError> {
        match self
            .call_contract(
                self.index_address,
                index_get_record_by_wallet_ref_calldata(wallet_ref),
            )
            .await
        {
            Ok(bytes) => decode_record_by_wallet_ref(&bytes)
                .map(Some)
                .map_err(|_| ChainError::InvalidResponse),
            Err(ChainError::Reverted(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Probe the frozen V2 index directly. Metadata is normalized to the V3
    /// packed convention (prefix word || pubkey), mirroring what the V3
    /// contract's own read fallback returns, so cached copies stay uniform.
    pub async fn get_v2_record_by_wallet_ref(
        &self,
        wallet_ref: B256,
    ) -> Result<Option<Record>, ChainError> {
        match self
            .call_contract(
                self.v2_address,
                index_get_record_by_wallet_ref_calldata(wallet_ref),
            )
            .await
        {
            Ok(bytes) => {
                let mut record =
                    decode_record_by_wallet_ref(&bytes).map_err(|_| ChainError::InvalidResponse)?;
                record.metadata = default_metadata(&record.public_key)
                    .map_err(|_| ChainError::InvalidResponse)?
                    .trim_start_matches("0x")
                    .to_owned();
                Ok(Some(record))
            }
            Err(ChainError::Reverted(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn has_record(&self, rp_id: &str, credential_id: &str) -> Result<bool, ChainError> {
        let bytes = self
            .call_contract(
                self.index_address,
                index_has_record_calldata(rp_id.to_owned(), credential_id.to_owned()),
            )
            .await?;
        decode_has_record(&bytes).map_err(|_| ChainError::InvalidResponse)
    }

    pub async fn get_commit_block(&self, commitment: B256) -> Result<u64, ChainError> {
        let bytes = self
            .call_contract(
                self.index_address,
                index_get_commit_block_calldata(commitment),
            )
            .await?;
        decode_commit_block(&bytes).map_err(|_| ChainError::InvalidResponse)
    }

    pub async fn total_credentials(&self) -> Result<u64, ChainError> {
        let bytes = self
            .call_contract(self.index_address, index_total_calldata())
            .await?;
        decode_total(&bytes).map_err(|_| ChainError::InvalidResponse)
    }

    /// V3-only view; a V2 target has no such function, so a revert maps to
    /// None and the stats payload simply omits the wallet count.
    pub async fn total_wallets(&self) -> Result<Option<u64>, ChainError> {
        match self
            .call_contract(self.index_address, index_total_wallets_calldata())
            .await
        {
            Ok(bytes) => decode_total_wallets(&bytes)
                .map(Some)
                .map_err(|_| ChainError::InvalidResponse),
            Err(ChainError::Reverted(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn list_sites(
        &self,
        page: u64,
        page_size: u64,
        descending: bool,
    ) -> Result<Page<SiteItem>, ChainError> {
        let offset = page.saturating_sub(1).saturating_mul(page_size);
        let bytes = self
            .call_contract(
                self.index_address,
                index_sites_calldata(offset, page_size, descending),
            )
            .await?;
        let (total, items) =
            decode_sites(&bytes, page, page_size).map_err(|_| ChainError::InvalidResponse)?;
        Ok(Page {
            total,
            page,
            page_size,
            items: items
                .into_iter()
                .map(|(rp_id, public_key_count, created_at)| SiteItem {
                    rp_id,
                    public_key_count,
                    created_at,
                })
                .collect(),
        })
    }

    pub async fn list_keys(
        &self,
        rp_id: &str,
        page: u64,
        page_size: u64,
        descending: bool,
    ) -> Result<Page<Record>, ChainError> {
        let offset = page.saturating_sub(1).saturating_mul(page_size);
        let bytes = self
            .call_contract(
                self.index_address,
                index_keys_calldata(rp_id.to_owned(), offset, page_size, descending),
            )
            .await?;
        let (total, items) = decode_keys(&bytes).map_err(|_| ChainError::InvalidResponse)?;
        Ok(Page {
            total,
            page,
            page_size,
            items,
        })
    }

    pub async fn current_block(&self) -> Result<u64, ChainError> {
        let value = self.rpc.call("eth_blockNumber", json!([])).await?;
        parse_quantity_value(&value)
    }

    pub async fn gas_price(&self) -> Result<U256, ChainError> {
        let value = self.rpc.call("eth_gasPrice", json!([])).await?;
        parse_u256_value(&value)
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

    pub async fn commit(&self, tasks: &[CreateTask], nonce: u64) -> Result<Broadcast, ChainError> {
        let commitments = tasks
            .iter()
            .map(build_commitment)
            .collect::<Result<Vec<_>>>()
            .map_err(|_| ChainError::Rejected("could not encode a commit".into()))?;
        let data = batch_commit_calldata(self.index_address, commitments);
        self.send_contract_transaction(WalletRole::Commit, self.batch_helper_address, data, nonce)
            .await
    }

    pub async fn create(&self, tasks: &[CreateTask], nonce: u64) -> Result<Broadcast, ChainError> {
        // A wallet task reveals alone as one atomic createWallet on the index
        // itself; single-key tasks batch through the helper contract.
        let (to, data) = if tasks.len() == 1 && tasks[0].is_wallet() {
            (
                self.index_address,
                wallet_create_calldata(&tasks[0])
                    .map_err(|_| ChainError::Rejected("could not encode a createWallet".into()))?,
            )
        } else {
            (
                self.batch_helper_address,
                batch_create_calldata(self.index_address, tasks)
                    .map_err(|_| ChainError::Rejected("could not encode a create batch".into()))?,
            )
        };
        self.send_contract_transaction(WalletRole::Create, to, data, nonce)
            .await
    }

    pub async fn wait_for_receipt(
        &self,
        hash: &str,
        timeout: Duration,
    ) -> Result<ReceiptStatus, ChainError> {
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
                "0x1" | "0x01" => Ok(ReceiptStatus::Success),
                _ => Ok(ReceiptStatus::Reverted),
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
            // A batch this large cannot be scheduled reliably against a
            // 17M-gas block; broadcasting it would burn the fee for nothing.
            return Err(ChainError::Rejected(format!(
                "gas limit {gas_limit} exceeds the {} cap; split the batch",
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
            .call_on(
                url,
                "eth_getBalance",
                json!([address.to_string(), "latest"]),
            )
            .await?;
        parse_u256_value(&value)
    }

    fn wallet_key(&self, role: WalletRole) -> Result<&SecretKey, ChainError> {
        match role {
            WalletRole::Create => self.create_key.as_ref(),
            WalletRole::Commit => self.commit_key.as_ref(),
        }
        .ok_or(ChainError::MissingSigner)
    }

    pub fn wallet_address(&self, role: WalletRole) -> Result<Address, ChainError> {
        Ok(signer_address(self.wallet_key(role)?))
    }
}

#[async_trait]
impl ReadChain for Chain {
    fn rpc_circuit_state(&self) -> &'static str {
        Chain::rpc_circuit_state(self)
    }

    fn index_address(&self) -> String {
        format!("{:#x}", self.index_address)
    }

    async fn get_record(
        &self,
        rp_id: &str,
        credential_id: &str,
    ) -> Result<Option<Record>, ChainError> {
        Chain::get_record(self, rp_id, credential_id).await
    }

    async fn get_record_by_wallet_ref(
        &self,
        wallet_ref: B256,
    ) -> Result<Option<Record>, ChainError> {
        Chain::get_record_by_wallet_ref(self, wallet_ref).await
    }

    async fn get_v2_record_by_wallet_ref(
        &self,
        wallet_ref: B256,
    ) -> Result<Option<Record>, ChainError> {
        Chain::get_v2_record_by_wallet_ref(self, wallet_ref).await
    }

    async fn total_credentials(&self) -> Result<u64, ChainError> {
        Chain::total_credentials(self).await
    }

    async fn total_wallets(&self) -> Result<Option<u64>, ChainError> {
        Chain::total_wallets(self).await
    }

    async fn list_sites(
        &self,
        page: u64,
        page_size: u64,
        descending: bool,
    ) -> Result<Page<SiteItem>, ChainError> {
        Chain::list_sites(self, page, page_size, descending).await
    }

    async fn list_keys(
        &self,
        rp_id: &str,
        page: u64,
        page_size: u64,
        descending: bool,
    ) -> Result<Page<Record>, ChainError> {
        Chain::list_keys(self, rp_id, page, page_size, descending).await
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
    // the base fee climbs. Setting both to the same quoted number (the
    // original behaviour) removed that headroom entirely.
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

    use super::{parse_quantity_value, parse_u256_value};

    #[test]
    fn parses_json_rpc_hex_quantities_without_precision_loss() {
        assert_eq!(parse_quantity_value(&json!("0x64")).unwrap(), 100);
        assert_eq!(
            parse_u256_value(&json!("0xffffffffffffffff")).unwrap(),
            U256::from(u64::MAX)
        );
    }
}
