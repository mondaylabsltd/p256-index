use std::{
    collections::HashMap,
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
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

use crate::{
    config::Config,
    contract::{
        batch_commit_calldata, batch_create_calldata, decode_commit_block, decode_has_record,
        decode_keys, decode_record, decode_record_by_wallet_ref, decode_sites, decode_total,
        index_get_commit_block_calldata, index_get_record_by_wallet_ref_calldata,
        index_get_record_calldata, index_has_record_calldata, index_keys_calldata,
        index_sites_calldata, index_total_calldata,
    },
    types::{BATCH_HELPER_ADDRESS, CHAIN_ID, CONTRACT_ADDRESS, CreateTask, Page, Record, SiteItem},
};

const FALLBACK_RPCS: &[&str] = &[
    "https://rpc.gnosischain.com",
    "https://gnosis-rpc.publicnode.com",
    "https://gnosis.drpc.org",
    "https://1rpc.io/gnosis",
];
const WRITE_RPCS: &[&str] = &[
    "https://rpc.gnosischain.com",
    "https://gnosis-rpc.publicnode.com",
    "https://gnosis.drpc.org",
];
const RPC_COOLDOWN: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct Chain {
    rpc: RpcPool,
    index_address: Address,
    batch_helper_address: Address,
    create_key: Option<SecretKey>,
    commit_key: Option<SecretKey>,
}

#[derive(Clone)]
struct RpcPool {
    http: Client,
    reads: Arc<Vec<String>>,
    writes: Arc<Vec<String>>,
    read_index: Arc<AtomicUsize>,
    write_index: Arc<AtomicUsize>,
    failed: Arc<Mutex<HashMap<String, Instant>>>,
}

#[derive(Debug)]
pub enum ChainError {
    Unavailable,
    Reverted(String),
    InvalidResponse,
    MissingSigner,
    Rejected(String),
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("chain RPC temporarily unavailable"),
            Self::Reverted(_) => formatter.write_str("EVM execution reverted"),
            Self::InvalidResponse => formatter.write_str("chain RPC returned an invalid response"),
            Self::MissingSigner => formatter.write_str("PRIVATE_KEY is required for chain writes"),
            Self::Rejected(_) => formatter.write_str("chain RPC rejected the request"),
        }
    }
}

impl std::error::Error for ChainError {}

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
    gas_price: U256,
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
    async fn get_record(
        &self,
        rp_id: &str,
        credential_id: &str,
    ) -> Result<Option<Record>, ChainError>;
    async fn get_record_by_wallet_ref(
        &self,
        wallet_ref: B256,
    ) -> Result<Option<Record>, ChainError>;
    async fn total_credentials(&self) -> Result<u64, ChainError>;
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
            index_address: Address::from_str(CONTRACT_ADDRESS)?,
            batch_helper_address: Address::from_str(BATCH_HELPER_ADDRESS)?,
            create_key,
            commit_key,
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

    pub async fn commit(&self, tasks: &[CreateTask], nonce: u64) -> Result<String, ChainError> {
        let commitments = tasks
            .iter()
            .map(crate::contract::build_commitment)
            .collect::<Result<Vec<_>>>()
            .map_err(|_| ChainError::Rejected("could not encode a commit".into()))?;
        let data = batch_commit_calldata(self.index_address, commitments);
        self.send_contract_transaction(WalletRole::Commit, self.batch_helper_address, data, nonce)
            .await
    }

    pub async fn create(&self, tasks: &[CreateTask], nonce: u64) -> Result<String, ChainError> {
        let data = batch_create_calldata(self.index_address, tasks)
            .map_err(|_| ChainError::Rejected("could not encode a create batch".into()))?;
        self.send_contract_transaction(WalletRole::Create, self.batch_helper_address, data, nonce)
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

    pub async fn cancel_stuck_nonce(
        &self,
        role: WalletRole,
        nonce: u64,
        gas_price: U256,
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
                gas_price,
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
    ) -> Result<String, ChainError> {
        let key = self.wallet_key(role)?;
        let from = signer_address(key);
        let url = self.rpc.select_write().ok_or(ChainError::Unavailable)?;
        let estimate = self.estimate_gas_on(&url, from, to, &data).await?;
        let gas_limit = estimate.saturating_mul(120).saturating_div(100);
        let gas_price = self.gas_price_on(&url).await?;
        self.send_transaction_on(
            &url,
            key,
            Transaction {
                to,
                data: Bytes::from(data),
                value: U256::ZERO,
                nonce,
                gas_limit,
                gas_price,
            },
        )
        .await
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
            transaction.gas_price,
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

    async fn total_credentials(&self) -> Result<u64, ChainError> {
        Chain::total_credentials(self).await
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
            reads: Arc::new(reads),
            writes: Arc::new(writes),
            read_index: Arc::new(AtomicUsize::new(0)),
            write_index: Arc::new(AtomicUsize::new(0)),
            failed: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn read_available(&self) -> bool {
        self.reads.iter().any(|url| self.available(url))
    }

    fn select_write(&self) -> Option<String> {
        self.select(&self.writes, &self.write_index)
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, ChainError> {
        let attempts = self.reads.len().min(3);
        for _ in 0..attempts {
            let Some(url) = self.select(&self.reads, &self.read_index) else {
                break;
            };
            match self.call_on(&url, method, params.clone()).await {
                Ok(value) => return Ok(value),
                Err(ChainError::Reverted(error)) => return Err(ChainError::Reverted(error)),
                Err(_) => self.mark_failed(&url),
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
        self.mark_healthy(url);
        Ok(result)
    }

    fn select(&self, urls: &[String], index: &AtomicUsize) -> Option<String> {
        for _ in 0..urls.len() {
            let current = index.fetch_add(1, Ordering::Relaxed) % urls.len();
            let url = &urls[current];
            if self.available(url) {
                return Some(url.clone());
            }
        }
        urls.get(index.fetch_add(1, Ordering::Relaxed) % urls.len())
            .cloned()
    }

    fn available(&self, url: &str) -> bool {
        let mut failed = self.failed.lock().expect("rpc failure state lock");
        match failed.get(url).copied() {
            Some(at) if at.elapsed() < RPC_COOLDOWN => false,
            Some(_) => {
                failed.remove(url);
                true
            }
            None => true,
        }
    }

    fn mark_failed(&self, url: &str) {
        self.failed
            .lock()
            .expect("rpc failure state lock")
            .insert(url.to_owned(), Instant::now());
    }

    fn mark_healthy(&self, url: &str) {
        self.failed
            .lock()
            .expect("rpc failure state lock")
            .remove(url);
    }
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
    max_fee_per_gas: U256,
    to: Address,
    value: U256,
    input: Bytes,
) -> Result<Vec<u8>, ChainError> {
    let gas_price = u128::try_from(max_fee_per_gas)
        .map_err(|_| ChainError::Rejected("gas price exceeds u128".into()))?;
    let signer = PrivateKeySigner::from(key.clone());
    let mut transaction = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce,
        gas_limit,
        max_fee_per_gas: gas_price,
        max_priority_fee_per_gas: gas_price,
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

fn is_revert(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("execution reverted")
        || value.contains("revert")
        || value.contains("0x46a08bc5")
        || value.contains("0xc9af4506")
}

pub fn is_record_exists_error(error: &ChainError) -> bool {
    matches!(error, ChainError::Reverted(value) | ChainError::Rejected(value)
        if value.contains("RecordAlreadyExists") || value.contains("0x46a08bc5"))
}

pub fn is_wallet_conflict_error(error: &ChainError) -> bool {
    matches!(error, ChainError::Reverted(value) | ChainError::Rejected(value)
        if value.contains("WalletRefAlreadyExists") || value.contains("0xc9af4506"))
}

pub fn is_transient(error: &ChainError) -> bool {
    matches!(error, ChainError::Unavailable | ChainError::InvalidResponse)
        || matches!(error, ChainError::Rejected(value)
            if !value.contains("RecordAlreadyExists") && !value.contains("WalletRefAlreadyExists")
                && !value.contains("execution reverted") && !value.contains("revert"))
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
