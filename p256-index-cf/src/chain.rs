//! Chain access over the Workers `fetch` API: a line-for-line port of the
//! docker shell's `chain.rs`, with reqwest/tokio swapped for `worker::Fetch`
//! and `worker::Delay`. Every decision (roster selection, error
//! classification, fee policy, calldata) still comes from `p256_registrar`.

use std::{cell::RefCell, rc::Rc, str::FromStr, time::Duration};

use alloy::{
    consensus::{SignableTransaction, TxEip1559, TxEnvelope},
    eips::{eip2718::Encodable2718, eip2930::AccessList},
    network::TxSignerSync,
    primitives::{Address, B256, Bytes, TxKind, U256},
    signers::local::PrivateKeySigner,
};
use futures_util::future::{Either, select};
use k256::SecretKey;
use serde_json::{Value, json};
use worker::{
    AbortController, Date, Delay, Fetch, Headers, Method, Request, RequestInit,
    Result as WorkerResult,
};

use p256_registrar::{
    gas::{self, FeePlan, FeeVerdict},
    lookup::{Entry, Page, SiteItem, Unit},
    protocol::{
        CHAIN_ID, GROUP_CREATED_TOPIC, REFERENCE_CREATED_TOPIC, decode_bool, decode_entry,
        decode_entry_by_key, decode_group_members, decode_id_page, decode_rp_ids, decode_total,
        decode_unit, decode_unit_by_group_key, get_entry_by_key_calldata, get_entry_calldata,
        get_group_members_calldata, get_unit_by_group_key_calldata, get_unit_calldata,
        groups_by_rp_id_calldata, groups_of_key_calldata, is_content_registered_calldata,
        is_referenced_calldata, is_revert, references_of_key_calldata,
        references_to_group_calldata, rp_ids_calldata, total_entries_calldata,
        total_references_calldata, total_rp_ids_calldata, total_units_calldata, write_calldata,
    },
    roster::{Lane, Roster},
    task::RegisterTask,
};

pub use p256_registrar::protocol::ChainError;

use crate::config::CfConfig;

const RPC_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct Chain {
    rpc: RpcPool,
    registry_address: Address,
    domain_registry_address: Address,
    signer_key: Option<SecretKey>,
    max_gas_price_wei: U256,
}

/// Transport wrapper around the registrar's [`Roster`]. The Worker isolate
/// is single-threaded, so a `RefCell` plays the docker shell's mutex.
#[derive(Clone)]
struct RpcPool {
    roster: Rc<RefCell<Roster>>,
}

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

#[derive(Clone, Debug)]
pub struct Broadcast {
    pub hash: String,
    pub fees_wei: Option<(u128, u128)>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Totals {
    pub entries: u64,
    pub units: u64,
    pub references: u64,
    pub rp_ids: u64,
}

#[derive(Clone, Debug)]
pub struct KeyProfile {
    pub entry: Entry,
    pub group_total: u64,
    pub group_ids: Vec<u64>,
    pub reference_total: u64,
    pub reference_ids: Vec<u64>,
}

#[derive(Clone, Debug)]
pub struct GroupDetail {
    pub unit: Unit,
    pub member_total: u64,
    pub members: Vec<Entry>,
    pub reference_total: u64,
    pub reference_ids: Vec<u64>,
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum ReceiptOutcome {
    Success { on_chain_id: Option<u64> },
    Reverted,
}

impl Chain {
    pub fn new(config: &CfConfig) -> WorkerResult<Self> {
        let signer_key = config
            .private_key
            .as_deref()
            .map(parse_secret_key)
            .transpose()?;
        Ok(Self {
            rpc: RpcPool::new(config.read_rpcs.clone(), config.write_rpcs.clone()),
            registry_address: Address::from_str(&config.contract_address).map_err(|_| {
                worker::Error::RustError("P256_INDEX_CONTRACT_ADDRESS is not a valid address".into())
            })?,
            domain_registry_address: Address::from_str(&config.domain_registry).map_err(|_| {
                worker::Error::RustError("P256_INDEX_DOMAIN_REGISTRY is not a valid address".into())
            })?,
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

    #[allow(dead_code)]
    pub fn chain_id(&self) -> u64 {
        CHAIN_ID
    }

    pub fn registry_address(&self) -> String {
        self.registry_address.to_checksum(None)
    }

    pub fn domain_registry_address(&self) -> String {
        self.domain_registry_address.to_checksum(None)
    }

    // ── Reads ──────────────────────────────────────────────────────────────

    pub async fn entry(&self, entry_id: u64) -> Result<Option<Entry>, ChainError> {
        match self
            .call_contract(self.registry_address, get_entry_calldata(entry_id))
            .await
        {
            Ok(bytes) => decode_entry(entry_id, &bytes)
                .map(Some)
                .map_err(|_| ChainError::InvalidResponse),
            Err(ChainError::Reverted(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn unit(&self, unit_id: u64) -> Result<Option<Unit>, ChainError> {
        match self
            .call_contract(self.registry_address, get_unit_calldata(unit_id))
            .await
        {
            Ok(bytes) => decode_unit(unit_id, &bytes)
                .map(Some)
                .map_err(|_| ChainError::InvalidResponse),
            Err(ChainError::Reverted(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn key_profile(
        &self,
        public_key: &str,
        page: u64,
        page_size: u64,
        descending: bool,
    ) -> Result<Option<KeyProfile>, ChainError> {
        let key = hex::decode(public_key.strip_prefix("0x").unwrap_or(public_key))
            .map_err(|_| ChainError::InvalidResponse)?;
        let bytes = self
            .call_contract(
                self.registry_address,
                get_entry_by_key_calldata(key.clone()),
            )
            .await?;
        let Some(entry) = decode_entry_by_key(&bytes).map_err(|_| ChainError::InvalidResponse)?
        else {
            return Ok(None);
        };

        let offset = page.saturating_sub(1).saturating_mul(page_size);
        let bytes = self
            .call_contract(
                self.registry_address,
                groups_of_key_calldata(key.clone(), offset, page_size, descending),
            )
            .await?;
        let (group_total, group_ids) =
            decode_id_page(&bytes).map_err(|_| ChainError::InvalidResponse)?;
        let bytes = self
            .call_contract(
                self.registry_address,
                references_of_key_calldata(key, offset, page_size, descending),
            )
            .await?;
        let (reference_total, reference_ids) =
            decode_id_page(&bytes).map_err(|_| ChainError::InvalidResponse)?;
        Ok(Some(KeyProfile {
            entry,
            group_total,
            group_ids,
            reference_total,
            reference_ids,
        }))
    }

    pub async fn groups_by_rp_id(
        &self,
        rp_id: &str,
        page: u64,
        page_size: u64,
        descending: bool,
    ) -> Result<Page<Unit>, ChainError> {
        let offset = page.saturating_sub(1).saturating_mul(page_size);
        let bytes = self
            .call_contract(
                self.registry_address,
                groups_by_rp_id_calldata(rp_id.to_owned(), offset, page_size, descending),
            )
            .await?;
        let (total, ids) = decode_id_page(&bytes).map_err(|_| ChainError::InvalidResponse)?;
        let mut items = Vec::with_capacity(ids.len());
        for unit_id in ids {
            let bytes = self
                .call_contract(self.registry_address, get_unit_calldata(unit_id))
                .await?;
            items.push(decode_unit(unit_id, &bytes).map_err(|_| ChainError::InvalidResponse)?);
        }
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

    pub async fn unit_by_group_key(&self, public_key: Vec<u8>) -> Result<Option<Unit>, ChainError> {
        let bytes = self
            .call_contract(
                self.registry_address,
                get_unit_by_group_key_calldata(public_key),
            )
            .await?;
        decode_unit_by_group_key(&bytes).map_err(|_| ChainError::InvalidResponse)
    }

    pub async fn group_detail_by_key(
        &self,
        public_key: Vec<u8>,
        page: u64,
        page_size: u64,
        descending: bool,
    ) -> Result<Option<GroupDetail>, ChainError> {
        let Some(unit) = self.unit_by_group_key(public_key.clone()).await? else {
            return Ok(None);
        };
        self.group_detail_for(unit, public_key, page, page_size, descending)
            .await
            .map(Some)
    }

    pub async fn group_detail_by_id(
        &self,
        unit_id: u64,
        page: u64,
        page_size: u64,
        descending: bool,
    ) -> Result<Option<GroupDetail>, ChainError> {
        let Some(unit) = self.unit(unit_id).await? else {
            return Ok(None);
        };
        let group_key =
            hex::decode(&unit.group_public_key).map_err(|_| ChainError::InvalidResponse)?;
        self.group_detail_for(unit, group_key, page, page_size, descending)
            .await
            .map(Some)
    }

    async fn group_detail_for(
        &self,
        unit: Unit,
        group_key: Vec<u8>,
        page: u64,
        page_size: u64,
        descending: bool,
    ) -> Result<GroupDetail, ChainError> {
        let offset = page.saturating_sub(1).saturating_mul(page_size);
        let bytes = self
            .call_contract(
                self.registry_address,
                get_group_members_calldata(unit.unit_id, offset, page_size, descending),
            )
            .await?;
        let (member_total, members) =
            decode_group_members(&bytes).map_err(|_| ChainError::InvalidResponse)?;
        let bytes = self
            .call_contract(
                self.registry_address,
                references_to_group_calldata(group_key, offset, page_size, descending),
            )
            .await?;
        let (reference_total, reference_ids) =
            decode_id_page(&bytes).map_err(|_| ChainError::InvalidResponse)?;
        Ok(GroupDetail {
            unit,
            member_total,
            members,
            reference_total,
            reference_ids,
        })
    }

    pub async fn is_referenced(
        &self,
        group_public_key: Vec<u8>,
        member_public_key: Vec<u8>,
    ) -> Result<bool, ChainError> {
        let bytes = self
            .call_contract(
                self.registry_address,
                is_referenced_calldata(group_public_key, member_public_key),
            )
            .await?;
        decode_bool(&bytes).map_err(|_| ChainError::InvalidResponse)
    }

    pub async fn totals(&self) -> Result<Totals, ChainError> {
        let read = async |calldata: Vec<u8>| {
            self.call_contract(self.registry_address, calldata)
                .await
                .and_then(|bytes| decode_total(&bytes).map_err(|_| ChainError::InvalidResponse))
        };
        Ok(Totals {
            entries: read(total_entries_calldata()).await?,
            units: read(total_units_calldata()).await?,
            references: read(total_references_calldata()).await?,
            rp_ids: read(total_rp_ids_calldata()).await?,
        })
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

    pub async fn gas_price(&self) -> Result<U256, ChainError> {
        let value = self.rpc.call("eth_gasPrice", json!([])).await?;
        parse_u256_value(&value)
    }

    /// The pending block's base fee via the write lane (the lane a rescue
    /// broadcast would use).
    pub async fn base_fee(&self) -> Result<U256, ChainError> {
        let url = self.rpc.select_write().ok_or(ChainError::Unavailable)?;
        self.base_fee_on(&url).await
    }

    pub fn max_gas_price_wei(&self) -> U256 {
        self.max_gas_price_wei
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

    pub async fn register(&self, task: &RegisterTask, nonce: u64) -> Result<Broadcast, ChainError> {
        let data = write_calldata(task)
            .map_err(|_| ChainError::Rejected("could not encode a register call".into()))?;
        self.send_contract_transaction(WalletRole::Register, self.registry_address, data, nonce)
            .await
    }

    pub async fn wait_for_receipt(
        &self,
        hash: &str,
        timeout: Duration,
    ) -> Result<ReceiptOutcome, ChainError> {
        let deadline = Date::now().as_millis() + timeout.as_millis() as u64;
        while Date::now().as_millis() < deadline {
            let value = self
                .rpc
                .call("eth_getTransactionReceipt", json!([hash]))
                .await?;
            if value.is_null() {
                Delay::from(Duration::from_secs(2)).await;
                continue;
            }
            let status = value
                .get("status")
                .and_then(Value::as_str)
                .ok_or(ChainError::InvalidResponse)?;
            return match status {
                "0x1" | "0x01" => Ok(ReceiptOutcome::Success {
                    on_chain_id: parse_on_chain_id(&value),
                }),
                _ => Ok(ReceiptOutcome::Reverted),
            };
        }
        Err(ChainError::Unavailable)
    }

    /// Replace a stuck nonce with a zero-value self-transfer. `fees` comes
    /// from [`gas::plan_replacement`], which prices against the stuck
    /// transaction's own fee so the replacement always clears the node's
    /// 110% admission rule.
    pub async fn cancel_stuck_nonce(
        &self,
        role: WalletRole,
        nonce: u64,
        fees: FeePlan,
    ) -> Result<String, ChainError> {
        let key = self.wallet_key(role)?;
        let address = signer_address(key);
        let url = self.rpc.select_write().ok_or(ChainError::Unavailable)?;
        self.send_transaction_on(
            &url,
            key,
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
        let balance = self.balance_on(from).await?;
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

    pub async fn fee_plan(&self) -> Result<FeeVerdict, ChainError> {
        let url = self.rpc.select_write().ok_or(ChainError::Unavailable)?;
        Ok(self.fee_plan_from(self.base_fee_on(&url).await?))
    }

    fn fee_plan_from(&self, base_fee: U256) -> FeeVerdict {
        gas::plan_fees(
            base_fee,
            U256::from(gas::DEFAULT_TIP_WEI),
            self.max_gas_price_wei,
        )
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

    /// The pending block's base fee; falls back to `eth_gasPrice` only on a
    /// pre-1559 answer.
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

    async fn balance_on(&self, address: Address) -> Result<U256, ChainError> {
        let value = self
            .rpc
            .call("eth_getBalance", json!([address.to_string(), "latest"]))
            .await?;
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

/// Extract the confirmed write's on-chain id from the receipt: the unitId
/// from a GroupCreated log, or the referenceId from a ReferenceCreated log.
fn parse_on_chain_id(receipt: &Value) -> Option<u64> {
    let logs = receipt.get("logs")?.as_array()?;
    for log in logs {
        let topics = log.get("topics")?.as_array()?;
        let event = topics.first()?.as_str()?;
        if event != GROUP_CREATED_TOPIC && event != REFERENCE_CREATED_TOPIC {
            continue;
        }
        let id = topics.get(1)?.as_str()?;
        let raw = id.strip_prefix("0x").unwrap_or(id);
        return u64::from_str_radix(raw.trim_start_matches('0'), 16)
            .ok()
            .or(Some(0));
    }
    None
}

impl RpcPool {
    fn new(reads: Vec<String>, writes: Vec<String>) -> Self {
        Self {
            roster: Rc::new(RefCell::new(Roster::new(reads, writes))),
        }
    }

    fn read_available(&self) -> bool {
        self.roster.borrow_mut().circuit_state(wall_ms()) == "closed"
    }

    fn select_write(&self) -> Option<String> {
        self.roster.borrow_mut().select(Lane::Write, wall_ms())
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, ChainError> {
        let attempts = self.roster.borrow().read_attempts();
        for _ in 0..attempts {
            let Some(url) = self.roster.borrow_mut().select(Lane::Read, wall_ms()) else {
                break;
            };
            match self.call_on(&url, method, params.clone()).await {
                Ok(value) => return Ok(value),
                Err(ChainError::Reverted(error)) => return Err(ChainError::Reverted(error)),
                Err(_) => self.roster.borrow_mut().mark_failed(&url, wall_ms()),
            }
        }
        Err(ChainError::Unavailable)
    }

    async fn call_on(&self, url: &str, method: &str, params: Value) -> Result<Value, ChainError> {
        let body = post_json(
            url,
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            }),
        )
        .await?;
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
        self.roster.borrow_mut().mark_healthy(url);
        Ok(result)
    }
}

/// One JSON POST with an abort-on-timeout, the fetch-flavored equivalent of
/// reqwest's request timeout.
async fn post_json(url: &str, payload: &Value) -> Result<Value, ChainError> {
    let headers = Headers::new();
    headers
        .set("content-type", "application/json")
        .map_err(|_| ChainError::Unavailable)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(payload.to_string().into()));
    let request = Request::new_with_init(url, &init).map_err(|_| ChainError::Unavailable)?;

    let controller = AbortController::default();
    let signal = controller.signal();
    let fetch = Fetch::Request(request);
    let fetched = Box::pin(fetch.send_with_signal(&signal));
    let timer = Box::pin(Delay::from(RPC_TIMEOUT));
    let mut response = match select(fetched, timer).await {
        Either::Left((result, _)) => result.map_err(|_| ChainError::Unavailable)?,
        Either::Right(((), _)) => {
            controller.abort();
            return Err(ChainError::Unavailable);
        }
    };
    if response.status_code() >= 400 {
        return Err(ChainError::Unavailable);
    }
    response
        .json::<Value>()
        .await
        .map_err(|_| ChainError::InvalidResponse)
}

/// Wall-clock milliseconds for the roster's cooldown arithmetic (it only
/// compares these to each other; `std::time::Instant` is unavailable on
/// wasm).
fn wall_ms() -> u64 {
    Date::now().as_millis()
}

fn parse_secret_key(value: &str) -> WorkerResult<SecretKey> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|_| worker::Error::RustError("PRIVATE_KEY is not valid hex".into()))?;
    SecretKey::from_slice(&bytes)
        .map_err(|_| worker::Error::RustError("PRIVATE_KEY is not a valid secp256k1 key".into()))
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
