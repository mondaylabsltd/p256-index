//! Export register/refer calldata from one WebAuthnP256PublicKeyRegistry
//! deployment and replay it verbatim into another.
//!
//! The registry's signatures cover a FROZEN domain (VERSION >= 12), so the
//! archived calldata verifies unchanged on any deployment constructed with
//! the same domain pair — this tool never touches, re-encodes or re-signs a
//! payload; it only moves the original bytes. Replay is order-independent
//! except for one natural edge: a `refer` needs its target group present, so
//! registers go first and a `GroupNotFound` refer is simply retried after
//! the rest of its round.
//!
//!   p256-replay export --rpc URL --registry ADDR --out FILE [--from-block N] [--to-block N]
//!   p256-replay replay --rpc URL --registry ADDR --archive FILE [--private-key HEX | --from ADDR] [--shuffle SEED]
//!   p256-replay verify --rpc URL --registry ADDR --archive FILE
//!
//! `replay` signs raw EIP-1559 transactions when given `--private-key`, and
//! falls back to `eth_sendTransaction` from `--from` against an unlocked
//! node (anvil) otherwise. `verify` proves presence without any getter: it
//! `eth_call`s every archived payload and expects the duplicate revert
//! (`GroupKeyAlreadyUsed` / `AlreadyReferenced`) — a payload that would
//! still WRITE is a missing record.

use std::{collections::BTreeMap, time::Duration};

use alloy::{
    consensus::{SignableTransaction, TxEip1559},
    eips::eip2718::Encodable2718,
    network::TxSignerSync,
    primitives::{Address, Bytes, TxKind, U256, keccak256},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const RECEIPT_TIMEOUT: Duration = Duration::from_secs(120);
const RECEIPT_POLL: Duration = Duration::from_millis(500);
/// Starting `eth_getLogs` span; halved on provider errors, floored at 500.
const LOG_CHUNK: u64 = 100_000;

fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes())[..4].try_into().expect("4")
}

fn register_selector() -> [u8; 4] {
    selector(
        "register(string,bytes,bytes,(bytes,string,uint256,uint256,uint256,uint256),(bytes,bytes,bytes,bytes,bytes,(bytes,string,uint256,uint256,uint256,uint256))[])",
    )
}

fn refer_selector() -> [u8; 4] {
    selector(
        "refer(bytes,bytes,(bytes,bytes,bytes,bytes,bytes,(bytes,string,uint256,uint256,uint256,uint256)))",
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Register,
    Refer,
}

/// One archived write: the original transaction's raw input, untouched.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Row {
    tx_hash: String,
    block: u64,
    tx_index: u64,
    kind: Kind,
    input: String,
}

// ── JSON-RPC plumbing ──────────────────────────────────────────────────────

struct Rpc {
    client: reqwest::Client,
    url: String,
}

/// An `eth_call` outcome, with the revert selector when one is decodable.
enum CallOutcome {
    Ok,
    Reverted {
        error_selector: Option<[u8; 4]>,
        raw: String,
    },
}

impl Rpc {
    fn new(url: &str) -> Self {
        // A local node (anvil, a rehearsal fork) must never be reached
        // through the ambient http_proxy/all_proxy that a developer shell
        // commonly carries — the proxy resets loopback connections. Remote
        // RPCs keep the proxy: reaching them may be exactly what it is for.
        let loopback = ["//127.0.0.1", "//localhost", "//[::1]"]
            .iter()
            .any(|host| url.contains(host));
        let client = if loopback {
            reqwest::Client::builder()
                .no_proxy()
                .build()
                .expect("client")
        } else {
            reqwest::Client::new()
        };
        Self {
            client,
            url: url.to_owned(),
        }
    }

    async fn request(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let response: Value = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("{method} transport"))?
            .json()
            .await
            .with_context(|| format!("{method} body"))?;
        if let Some(error) = response.get("error") {
            bail!("{method} error: {error}");
        }
        response
            .get("result")
            .cloned()
            .ok_or_else(|| anyhow!("{method}: no result"))
    }

    async fn quantity(&self, method: &str, params: Value) -> Result<u64> {
        let result = self.request(method, params).await?;
        parse_quantity(&result)
    }

    /// `eth_call` that keeps revert data instead of erroring: providers
    /// surface reverts as JSON-RPC errors whose `data` carries the raw
    /// return bytes (sometimes nested one level).
    async fn call(&self, from: Option<Address>, to: Address, data: &str) -> Result<CallOutcome> {
        let mut tx = json!({"to": to.to_string(), "data": data});
        if let Some(from) = from {
            tx["from"] = json!(from.to_string());
        }
        let body =
            json!({"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [tx, "latest"]});
        let response: Value = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .context("eth_call transport")?
            .json()
            .await
            .context("eth_call body")?;
        if response.get("result").is_some_and(|r| !r.is_null()) {
            return Ok(CallOutcome::Ok);
        }
        let error = response
            .get("error")
            .cloned()
            .ok_or_else(|| anyhow!("eth_call: neither result nor error"))?;
        Ok(CallOutcome::Reverted {
            error_selector: revert_selector(&error),
            raw: error.to_string(),
        })
    }
}

fn parse_quantity(value: &Value) -> Result<u64> {
    let text = value
        .as_str()
        .ok_or_else(|| anyhow!("quantity not a string: {value}"))?;
    u64::from_str_radix(text.trim_start_matches("0x"), 16).context("quantity parse")
}

/// Dig the 4-byte custom-error selector out of a JSON-RPC error object.
fn revert_selector(error: &Value) -> Option<[u8; 4]> {
    fn from_hex_str(text: &str) -> Option<[u8; 4]> {
        let bytes = hex::decode(text.trim_start_matches("0x")).ok()?;
        bytes.get(..4)?.try_into().ok()
    }
    let data = error.get("data")?;
    if let Some(text) = data.as_str() {
        return from_hex_str(text);
    }
    // Some providers nest: {"data": {"data": "0x…"}} or keyed by tx hash.
    if let Some(text) = data.get("data").and_then(Value::as_str) {
        return from_hex_str(text);
    }
    data.as_object()?.values().find_map(|inner| {
        inner
            .get("return")
            .or(inner.get("data"))
            .and_then(Value::as_str)
            .and_then(from_hex_str)
    })
}

// ── export ─────────────────────────────────────────────────────────────────

/// Earliest block at which the registry has code, by binary search — so an
/// export never scans the chain's whole history for a young contract.
async fn find_deploy_block(rpc: &Rpc, registry: Address, latest: u64) -> Result<u64> {
    let has_code = |block: u64| async move {
        let code = rpc
            .request(
                "eth_getCode",
                json!([registry.to_string(), format!("0x{block:x}")]),
            )
            .await?;
        Ok::<bool, anyhow::Error>(code.as_str().map(|c| c.len() > 2).unwrap_or(false))
    };
    if !has_code(latest).await? {
        bail!("registry {registry} has no code at block {latest}");
    }
    let (mut lo, mut hi) = (1u64, latest);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if has_code(mid).await? {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    Ok(lo)
}

async fn export(
    rpc: &Rpc,
    registry: Address,
    from_block: Option<u64>,
    to_block: Option<u64>,
    out: &str,
) -> Result<()> {
    let latest = rpc.quantity("eth_blockNumber", json!([])).await?;
    let to_block = to_block.unwrap_or(latest);
    let from_block = match from_block {
        Some(block) => block,
        None => {
            let deploy = find_deploy_block(rpc, registry, to_block).await?;
            eprintln!("deploy block found: {deploy}");
            deploy
        }
    };

    // Every event the registry ever emitted names a write tx; the calldata
    // is fetched per unique tx. Ordered by (block, txIndex) so the archive
    // stays chronological — replay does not need the order, humans do.
    let mut txs: BTreeMap<(u64, u64), String> = BTreeMap::new();
    let mut start = from_block;
    let mut chunk = LOG_CHUNK;
    while start <= to_block {
        let end = to_block.min(start + chunk - 1);
        let filter = json!([{
            "address": registry.to_string(),
            "fromBlock": format!("0x{start:x}"),
            "toBlock": format!("0x{end:x}"),
        }]);
        match rpc.request("eth_getLogs", filter).await {
            Ok(Value::Array(logs)) => {
                for log in &logs {
                    let block = parse_quantity(log.get("blockNumber").unwrap_or(&Value::Null))?;
                    let index =
                        parse_quantity(log.get("transactionIndex").unwrap_or(&Value::Null))?;
                    let hash = log
                        .get("transactionHash")
                        .and_then(Value::as_str)
                        .ok_or_else(|| anyhow!("log without transactionHash"))?;
                    txs.insert((block, index), hash.to_owned());
                }
                eprintln!(
                    "blocks {start}..={end}: {} logs, {} txs total",
                    logs.len(),
                    txs.len()
                );
                start = end + 1;
            }
            Ok(other) => bail!("eth_getLogs: unexpected result {other}"),
            Err(error) if chunk > 500 => {
                chunk /= 2;
                eprintln!(
                    "eth_getLogs failed over {start}..={end} ({error}); retrying with chunk {chunk}"
                );
            }
            Err(error) => return Err(error.context("eth_getLogs at minimum chunk")),
        }
    }

    let (register, refer) = (register_selector(), refer_selector());
    let mut rows = Vec::new();
    let mut skipped = 0usize;
    for ((block, tx_index), tx_hash) in txs {
        let tx = rpc
            .request("eth_getTransactionByHash", json!([tx_hash]))
            .await?;
        let input = tx
            .get("input")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("tx {tx_hash}: no input"))?;
        let to = tx.get("to").and_then(Value::as_str).unwrap_or_default();
        let head = hex::decode(input.trim_start_matches("0x").get(..8).unwrap_or_default())
            .unwrap_or_default();
        let kind = match head.as_slice() {
            head if head == register => Kind::Register,
            head if head == refer => Kind::Refer,
            _ => {
                // A wrapper call (multicall, contract wallet) does not carry
                // the write as its own calldata; it cannot be replayed
                // verbatim and must be reconstructed by hand.
                eprintln!(
                    "WARN tx {tx_hash} (to {to}): input is not a direct register/refer call; skipped"
                );
                skipped += 1;
                continue;
            }
        };
        rows.push(Row {
            tx_hash,
            block,
            tx_index,
            kind,
            input: input.to_owned(),
        });
    }

    let mut body = String::new();
    for row in &rows {
        body.push_str(&serde_json::to_string(row)?);
        body.push('\n');
    }
    std::fs::write(out, body).with_context(|| format!("write {out}"))?;
    let registers = rows.iter().filter(|row| row.kind == Kind::Register).count();
    println!(
        "exported {} writes ({} register, {} refer, {} skipped) from blocks {from_block}..={to_block} to {out}",
        rows.len(),
        registers,
        rows.len() - registers,
        skipped
    );
    Ok(())
}

// ── replay ─────────────────────────────────────────────────────────────────

enum Sender {
    /// Raw EIP-1559 signing — the real-chain path.
    Key(Box<PrivateKeySigner>),
    /// `eth_sendTransaction` from an unlocked account — the anvil path.
    Unlocked(Address),
}

impl Sender {
    /// The account the replay txs (and their preflight calls) come from.
    fn sending_address(&self) -> Address {
        match self {
            Sender::Key(signer) => signer.address(),
            Sender::Unlocked(address) => *address,
        }
    }
}

async fn send_write(rpc: &Rpc, sender: &Sender, to: Address, input: &str) -> Result<String> {
    let tx_hash = match sender {
        Sender::Unlocked(from) => rpc
            .request(
                "eth_sendTransaction",
                json!([{"from": from.to_string(), "to": to.to_string(), "data": input}]),
            )
            .await?
            .as_str()
            .ok_or_else(|| anyhow!("eth_sendTransaction: non-string hash"))?
            .to_owned(),
        Sender::Key(signer) => {
            let chain_id = rpc.quantity("eth_chainId", json!([])).await?;
            let nonce = rpc
                .quantity(
                    "eth_getTransactionCount",
                    json!([signer.address().to_string(), "pending"]),
                )
                .await?;
            let gas = rpc
                .quantity(
                    "eth_estimateGas",
                    json!([{"from": signer.address().to_string(), "to": to.to_string(), "data": input}]),
                )
                .await?;
            let gas_price = rpc.quantity("eth_gasPrice", json!([])).await?;
            // The tip follows the network's quoted price instead of a
            // hardcoded gwei figure: on a chain idling at single-digit-wei
            // gas (Gnosis does) a fixed 1-gwei tip overpays by five orders
            // of magnitude, and on a busy chain the quote already carries
            // the going tip. The ceiling must still clear the tip or the
            // transaction is invalid (maxFee < maxPriorityFee).
            let tip = ((gas_price as u128) / 2).max(1);
            let mut tx = TxEip1559 {
                chain_id,
                nonce,
                gas_limit: gas + gas / 5,
                max_fee_per_gas: ((gas_price as u128) * 2).max(tip * 2),
                max_priority_fee_per_gas: tip,
                to: TxKind::Call(to),
                value: U256::ZERO,
                input: Bytes::from(hex::decode(input.trim_start_matches("0x"))?),
                ..Default::default()
            };
            let signature = signer.sign_transaction_sync(&mut tx)?;
            let encoded = tx.into_signed(signature).encoded_2718();
            rpc.request(
                "eth_sendRawTransaction",
                json!([format!("0x{}", hex::encode(encoded))]),
            )
            .await?
            .as_str()
            .ok_or_else(|| anyhow!("eth_sendRawTransaction: non-string hash"))?
            .to_owned()
        }
    };

    let deadline = std::time::Instant::now() + RECEIPT_TIMEOUT;
    loop {
        let receipt = rpc
            .request("eth_getTransactionReceipt", json!([tx_hash]))
            .await?;
        if !receipt.is_null() {
            let status = receipt.get("status").and_then(Value::as_str).unwrap_or("");
            if status != "0x1" {
                bail!("tx {tx_hash} reverted on-chain");
            }
            return Ok(tx_hash);
        }
        if std::time::Instant::now() > deadline {
            bail!("tx {tx_hash}: no receipt within {RECEIPT_TIMEOUT:?}");
        }
        tokio::time::sleep(RECEIPT_POLL).await;
    }
}

/// Deterministic Fisher–Yates over a xorshift stream: `--shuffle SEED`
/// exists to prove order-independence, so runs must be reproducible.
fn shuffle<T>(items: &mut [T], seed: u64) {
    let mut state = seed | 1;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for i in (1..items.len()).rev() {
        items.swap(i, (next() as usize) % (i + 1));
    }
}

async fn replay(
    rpc: &Rpc,
    registry: Address,
    archive: &str,
    sender: &Sender,
    shuffle_seed: Option<u64>,
) -> Result<()> {
    let rows = read_archive(archive)?;
    let mut registers: Vec<&Row> = rows
        .iter()
        .filter(|row| row.kind == Kind::Register)
        .collect();
    let mut refers: Vec<&Row> = rows.iter().filter(|row| row.kind == Kind::Refer).collect();
    if let Some(seed) = shuffle_seed {
        shuffle(&mut registers, seed);
        shuffle(&mut refers, seed.wrapping_add(1));
        eprintln!("shuffled with seed {seed}");
    }

    let already_used = selector("GroupKeyAlreadyUsed(bytes32)");
    let already_referenced = selector("AlreadyReferenced(uint256)");
    let group_not_found = selector("GroupNotFound(bytes32)");

    let (mut sent, mut present, mut failed) = (0usize, 0usize, Vec::<String>::new());
    // Registers first (refers need their group), then refers with a retry
    // round for GroupNotFound — enough for any submission order within the
    // two phases, shuffled or not.
    let mut queue: Vec<(&Row, [u8; 4])> = registers
        .iter()
        .map(|row| (*row, already_used))
        .chain(refers.iter().map(|row| (*row, already_referenced)))
        .collect();
    while !queue.is_empty() {
        let mut retry = Vec::new();
        let round = queue.len();
        for (row, duplicate) in queue {
            match rpc
                .call(Some(sender.sending_address()), registry, &row.input)
                .await?
            {
                CallOutcome::Ok => {
                    let tx_hash = send_write(rpc, sender, registry, &row.input).await?;
                    eprintln!("replayed {:?} {} -> {tx_hash}", row.kind, row.tx_hash);
                    sent += 1;
                }
                CallOutcome::Reverted {
                    error_selector: Some(found),
                    ..
                } if found == duplicate => {
                    present += 1;
                }
                CallOutcome::Reverted {
                    error_selector: Some(found),
                    ..
                } if found == group_not_found && row.kind == Kind::Refer => {
                    retry.push((row, duplicate));
                }
                CallOutcome::Reverted { raw, .. } => {
                    eprintln!("FAILED {:?} {}: {raw}", row.kind, row.tx_hash);
                    failed.push(row.tx_hash.clone());
                }
            }
        }
        if retry.len() == round {
            for (row, _) in &retry {
                eprintln!("FAILED refer {}: target group never appeared", row.tx_hash);
                failed.push(row.tx_hash.clone());
            }
            break;
        }
        queue = retry;
    }

    println!(
        "replay done: {sent} written, {present} already present, {} failed",
        failed.len()
    );
    if !failed.is_empty() {
        bail!("{} writes failed: {failed:?}", failed.len());
    }
    Ok(())
}

// ── verify ─────────────────────────────────────────────────────────────────

async fn verify(rpc: &Rpc, registry: Address, archive: &str) -> Result<()> {
    let rows = read_archive(archive)?;
    let already_used = selector("GroupKeyAlreadyUsed(bytes32)");
    let already_referenced = selector("AlreadyReferenced(uint256)");

    let (mut ok, mut missing, mut anomalies) = (0usize, Vec::<String>::new(), Vec::<String>::new());
    for row in &rows {
        let duplicate = match row.kind {
            Kind::Register => already_used,
            Kind::Refer => already_referenced,
        };
        match rpc.call(None, registry, &row.input).await? {
            // The payload would still write: its record is not there.
            CallOutcome::Ok => missing.push(row.tx_hash.clone()),
            CallOutcome::Reverted {
                error_selector: Some(found),
                ..
            } if found == duplicate => ok += 1,
            CallOutcome::Reverted { raw, .. } => {
                eprintln!("ANOMALY {:?} {}: {raw}", row.kind, row.tx_hash);
                anomalies.push(row.tx_hash.clone());
            }
        }
    }

    for (label, signature) in [
        ("entries", "getTotalEntries()"),
        ("units", "getTotalUnits()"),
        ("references", "getTotalReferences()"),
    ] {
        let data = format!("0x{}", hex::encode(selector(signature)));
        let total = rpc
            .request(
                "eth_call",
                json!([{"to": registry.to_string(), "data": data}, "latest"]),
            )
            .await?;
        println!(
            "target {label}: {}",
            u128::from_str_radix(total.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16)
                .unwrap_or(0)
        );
    }
    println!(
        "verify: {ok}/{} archived writes present, {} missing, {} anomalies",
        rows.len(),
        missing.len(),
        anomalies.len()
    );
    if !missing.is_empty() || !anomalies.is_empty() {
        bail!("missing: {missing:?}, anomalies: {anomalies:?}");
    }
    Ok(())
}

// ── CLI ────────────────────────────────────────────────────────────────────

fn read_archive(path: &str) -> Result<Vec<Row>> {
    std::fs::read_to_string(path)
        .with_context(|| format!("read {path}"))?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).with_context(|| format!("archive row: {line}")))
        .collect()
}

struct Args(BTreeMap<String, String>);

impl Args {
    fn parse(raw: &[String]) -> Result<Self> {
        let mut map = BTreeMap::new();
        let mut pending = raw.iter();
        while let Some(flag) = pending.next() {
            let name = flag
                .strip_prefix("--")
                .ok_or_else(|| anyhow!("expected --flag, got {flag}"))?;
            let value = pending
                .next()
                .ok_or_else(|| anyhow!("--{name} needs a value"))?;
            map.insert(name.to_owned(), value.clone());
        }
        Ok(Self(map))
    }

    fn required(&self, name: &str) -> Result<&str> {
        self.0
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| anyhow!("--{name} is required"))
    }

    fn address(&self, name: &str) -> Result<Address> {
        self.required(name)?
            .parse()
            .with_context(|| format!("--{name}"))
    }

    fn number(&self, name: &str) -> Result<Option<u64>> {
        self.0
            .get(name)
            .map(|value| value.parse().with_context(|| format!("--{name}")))
            .transpose()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = raw.split_first() else {
        bail!("usage: p256-replay <export|replay|verify> --rpc URL --registry ADDR …");
    };
    let args = Args::parse(rest)?;
    let rpc = Rpc::new(args.required("rpc")?);
    let registry = args.address("registry")?;

    match command.as_str() {
        "export" => {
            export(
                &rpc,
                registry,
                args.number("from-block")?,
                args.number("to-block")?,
                args.required("out")?,
            )
            .await
        }
        "replay" => {
            let sender = match self::key_or_from(&args)? {
                Some(sender) => sender,
                None => bail!("replay needs --private-key HEX or --from ADDR (unlocked node)"),
            };
            replay(
                &rpc,
                registry,
                args.required("archive")?,
                &sender,
                args.number("shuffle")?,
            )
            .await
        }
        "verify" => verify(&rpc, registry, args.required("archive")?).await,
        other => bail!("unknown command {other}; expected export, replay or verify"),
    }
}

fn key_or_from(args: &Args) -> Result<Option<Sender>> {
    if let Some(key) = args.0.get("private-key") {
        return Ok(Some(Sender::Key(Box::new(
            key.parse().context("--private-key")?,
        ))));
    }
    if args.0.contains_key("from") {
        return Ok(Some(Sender::Unlocked(args.address("from")?)));
    }
    Ok(None)
}
