/**
 * Durable Object for queue processing (CF Worker version).
 * Replaces Deno's setInterval-based worker with DO alarm.
 * Reuses shared logic from queue-shared.ts and contract-shared.ts.
 */
import { createPublicClient, http } from "viem";
import { gnosis } from "viem/chains";
import { getWriteRpc } from "../shared/rpc.ts";
import {
  CONTRACT_ADDRESS,
  CONTRACT_ABI,
  BATCH_HELPER_ADDRESS,
  BATCH_ABI,
} from "../shared/contract.ts";
import {
  type QueueItem,
  type AppConfig,
  MAX_RETRIES,
  QUERY_BATCH_SIZE,
  TX_BATCH_SIZE,
  MAX_GAS_PRICE_GWEI,
  GAS_BALANCE_THRESHOLD,
  FUND_THRESHOLD,
  FUND_AMOUNT,
  DONE_RETENTION,
  CREATE_SUB_BATCH,
  buildCommitment,
  getCreateWallet,
  getCommitWallet,
  sendTelegram,
} from "../shared/queue.ts";
import { acquireNonce } from "./nonce.ts";
import { buildConfig } from "./config.ts";
import type { Env } from "./types.ts";

const ALARM_INTERVAL = 10_000; // 10s
const ALERT_INTERVAL = 5 * 60_000;
const QUEUE_BACKLOG_THRESHOLD = 100;
const FAILURE_ALERT_BATCH = 10;

export class QueueProcessor implements DurableObject {
  private state: DurableObjectState;
  private env: Env;
  private lastAlertAt = 0;
  private lastFailedCount = 0;
  private failuresSinceLastAlert = 0;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/start") {
      const existing = await this.state.storage.getAlarm();
      if (!existing) {
        await this.state.storage.setAlarm(Date.now() + ALARM_INTERVAL);
      }
      return new Response("started");
    }
    return new Response("ok");
  }

  async alarm(): Promise<void> {
    try {
      await this.processQueue();
    } catch (err) {
      console.error("[queue-processor] Error:", err);
    }
    // Re-schedule
    await this.state.storage.setAlarm(Date.now() + ALARM_INTERVAL);
  }

  private get db(): D1Database {
    return this.env.DB;
  }

  private async getConfig(): Promise<AppConfig> {
    return await buildConfig(this.env);
  }

  private async processQueue(): Promise<void> {
    const config = await this.getConfig();
    if (!config.privateKey) {
      console.warn("[queue-processor] No PRIVATE_KEY configured, skipping");
      return;
    }

    // Check gas price
    try {
      const writeClient = createPublicClient({ chain: gnosis, transport: http(getWriteRpc(), { timeout: 10_000 }) });
      const gasPrice = await writeClient.getGasPrice();
      const gasPriceGwei = Number(gasPrice) / 1e9;
      if (gasPriceGwei > MAX_GAS_PRICE_GWEI) {
        console.warn(`[queue-processor] Gas price too high: ${gasPriceGwei.toFixed(4)} Gwei, pausing`);
        await this.checkAlerts(config);
        return;
      }
    } catch (err) {
      console.warn(`[queue-processor] Gas price check failed:`, err instanceof Error ? err.message : err);
      return;
    }

    await this.processCreating(config);
    await this.processCommitted(config);
    await this.processPending(config);
    await this.cleanupDoneRecords();
    await this.checkAlerts(config);
  }

  private async processCreating(_config: AppConfig): Promise<void> {
    const { results } = await this.db.prepare(
      "SELECT * FROM create_queue WHERE status = 'creating' ORDER BY createdAt ASC LIMIT ?"
    ).bind(QUERY_BATCH_SIZE).all<QueueItem>();

    if (results.length === 0) return;

    const client = createPublicClient({ chain: gnosis, transport: http(getWriteRpc(), { timeout: 10_000 }) });

    const calls = results.map((item) => ({
      address: CONTRACT_ADDRESS as `0x${string}`,
      abi: CONTRACT_ABI,
      functionName: "hasRecord" as const,
      args: [item.rpId, item.credentialId] as const,
    }));

    try {
      const multicallResults = await client.multicall({ contracts: calls });
      let doneCount = 0;
      for (let i = 0; i < results.length; i++) {
        const r = multicallResults[i];
        if (r.status === "success" && r.result) {
          await this.db.prepare("UPDATE create_queue SET status = 'done', error = '', updatedAt = ? WHERE id = ?")
            .bind(Date.now(), results[i].id).run();
          doneCount++;
        } else if (r.status === "success" && !r.result) {
          const CREATING_TIMEOUT = 2 * 60_000;
          if (Date.now() - results[i].updatedAt > CREATING_TIMEOUT) {
            await this.handleFailure(results[i], "createRecord tx not confirmed after 2min", "committed");
          }
        }
      }
      if (doneCount > 0) console.log(`[queue-processor] ${doneCount} items confirmed on-chain`);
    } catch (err) {
      console.warn(`[queue-processor] processCreating multicall failed:`, err instanceof Error ? err.message : err);
    }
  }

  private async processCommitted(config: AppConfig): Promise<void> {
    const { results: items } = await this.db.prepare(
      "SELECT * FROM create_queue WHERE status = 'committed' AND retryAfter <= ? ORDER BY createdAt ASC LIMIT ?"
    ).bind(Date.now(), TX_BATCH_SIZE).all<QueueItem>();

    if (items.length === 0) return;

    const client = createPublicClient({ chain: gnosis, transport: http(getWriteRpc(), { timeout: 10_000 }) });
    const currentBlock = await client.getBlockNumber();

    const commitments = items.map((item) => buildCommitment(item).commitment);
    const calls = commitments.map((commitment) => ({
      address: CONTRACT_ADDRESS as `0x${string}`,
      abi: CONTRACT_ABI,
      functionName: "getCommitBlock" as const,
      args: [commitment] as const,
    }));

    let results: { status: "success" | "failure"; result?: unknown; error?: unknown }[];
    try {
      results = await client.multicall({ contracts: calls }) as typeof results;
    } catch (err) {
      console.warn(`[queue-processor] processCommitted multicall failed:`, err instanceof Error ? err.message : err);
      return;
    }

    const ready: QueueItem[] = [];
    const needsHasRecordCheck: QueueItem[] = [];

    for (let i = 0; i < items.length; i++) {
      const result = results[i];
      if (result.status !== "success") continue;
      const commitBlock = result.result as bigint;
      if (commitBlock > 0n && currentBlock >= commitBlock + 1n) {
        ready.push(items[i]);
      } else if (commitBlock === 0n) {
        needsHasRecordCheck.push(items[i]);
      }
    }

    if (needsHasRecordCheck.length > 0) {
      const hasRecordCalls = needsHasRecordCheck.map((item) => ({
        address: CONTRACT_ADDRESS as `0x${string}`,
        abi: CONTRACT_ABI,
        functionName: "hasRecord" as const,
        args: [item.rpId, item.credentialId] as const,
      }));
      try {
        const hasRecordResults = await client.multicall({ contracts: hasRecordCalls });
        for (let i = 0; i < needsHasRecordCheck.length; i++) {
          const item = needsHasRecordCheck[i];
          const r = hasRecordResults[i];
          if (r.status === "success" && r.result) {
            await this.db.prepare("UPDATE create_queue SET status = 'done', error = '', updatedAt = ? WHERE id = ?")
              .bind(Date.now(), item.id).run();
          } else {
            const COMMIT_COOLDOWN = 2 * 60_000;
            if (Date.now() - item.updatedAt >= COMMIT_COOLDOWN) {
              await this.db.prepare("UPDATE create_queue SET status = 'pending', updatedAt = ? WHERE id = ?")
                .bind(Date.now(), item.id).run();
              console.warn(`[queue-processor] Item ${item.id} commitment missing, resetting to pending`);
            }
          }
        }
      } catch (err) { console.warn(`[queue-processor] hasRecord multicall failed:`, err instanceof Error ? err.message : err); }
    }

    if (ready.length === 0) return;

    const { wallet, client: walletClient } = getCreateWallet(config);

    for (let offset = 0; offset < ready.length; offset += CREATE_SUB_BATCH) {
      const batch = ready.slice(offset, offset + CREATE_SUB_BATCH);
      const params = batch.map((item) => {
        const { walletRefHex, publicKeyHex, metadataHex } = buildCommitment(item);
        return {
          rpId: item.rpId,
          credentialId: item.credentialId,
          walletRef: walletRefHex,
          publicKey: publicKeyHex,
          name: item.name,
          initialCredentialId: item.initialCredentialId,
          metadata: metadataHex,
        };
      });

      const handle = await acquireNonce("create", config);
      try {
        const gasEstimate = await walletClient.estimateContractGas({
          address: BATCH_HELPER_ADDRESS,
          abi: BATCH_ABI,
          functionName: "batchCreateRecord",
          args: [CONTRACT_ADDRESS, params],
          account: wallet.account,
        });

        const hash = await wallet.writeContract({
          address: BATCH_HELPER_ADDRESS,
          abi: BATCH_ABI,
          functionName: "batchCreateRecord",
          args: [CONTRACT_ADDRESS, params],
          nonce: handle.nonce,
          gas: gasEstimate * 120n / 100n,
        });

        // Wait for receipt and verify success before marking done
        const createReceipt = await walletClient.waitForTransactionReceipt({ hash, timeout: 60_000 });
        if (createReceipt.status === "reverted") {
          throw new Error(`batchCreateRecord tx reverted: ${hash}`);
        }
        const now = Date.now();
        const stmts = batch.map((item) =>
          this.db.prepare("UPDATE create_queue SET status = 'done', txHash = ?, error = '', updatedAt = ? WHERE id = ?")
            .bind(hash, now, item.id)
        );
        await this.db.batch(stmts);
        console.log(`[queue-processor] batchCreateRecord: ${batch.length} items confirmed, done`);
      } catch (err) {
        handle.release();
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(`[queue-processor] batchCreateRecord failed: ${msg.slice(0, 200)}`);
        break;
      }
    }
  }

  private async processPending(config: AppConfig): Promise<void> {
    const { results: items } = await this.db.prepare(
      "SELECT * FROM create_queue WHERE status = 'pending' AND retryAfter <= ? ORDER BY createdAt ASC LIMIT ?"
    ).bind(Date.now(), TX_BATCH_SIZE).all<QueueItem>();

    if (items.length === 0) return;

    const commitments = items.map((item) => buildCommitment(item).commitment);

    const { wallet, client: commitClient } = getCommitWallet(config);
    const handle = await acquireNonce("commit", config);
    try {
      const gasEstimate = await commitClient.estimateContractGas({
        address: BATCH_HELPER_ADDRESS,
        abi: BATCH_ABI,
        functionName: "batchCommit",
        args: [CONTRACT_ADDRESS, commitments],
        account: wallet.account,
      });
      const hash = await wallet.writeContract({
        address: BATCH_HELPER_ADDRESS,
        abi: BATCH_ABI,
        functionName: "batchCommit",
        args: [CONTRACT_ADDRESS, commitments],
        nonce: handle.nonce,
        gas: gasEstimate * 120n / 100n,
      });

      // Wait for receipt and verify success
      const commitReceipt = await commitClient.waitForTransactionReceipt({ hash, timeout: 60_000 });
      if (commitReceipt.status === "reverted") {
        throw new Error(`batchCommit tx reverted: ${hash}`);
      }

      const now = Date.now();
      const stmts = items.map((item) =>
        this.db.prepare("UPDATE create_queue SET status = 'committed', updatedAt = ? WHERE id = ?")
          .bind(now, item.id)
      );
      await this.db.batch(stmts);
      console.log(`[queue-processor] batchCommit: ${items.length} items confirmed in 1 tx`);
    } catch (err) {
      handle.release();
      console.warn(`[queue-processor] batchCommit failed: ${err instanceof Error ? err.message : err}`);
    }
  }

  private async cleanupDoneRecords(): Promise<void> {
    const cutoff = Date.now() - DONE_RETENTION;
    const result = await this.db.prepare("DELETE FROM create_queue WHERE status = 'done' AND updatedAt < ?")
      .bind(cutoff).run();
    if (result.meta.changes && result.meta.changes > 0) {
      console.log(`[queue-processor] Cleaned up ${result.meta.changes} done records`);
    }
  }

  private async handleFailure(item: QueueItem, error: string, retryStatus: "pending" | "committed" = "pending"): Promise<void> {
    const retries = item.retries + 1;
    if (retries >= MAX_RETRIES) {
      await this.db.prepare("UPDATE create_queue SET status = 'failed', error = ?, retries = ?, updatedAt = ? WHERE id = ?")
        .bind(error, retries, Date.now(), item.id).run();
      console.error(`[queue-processor] Item ${item.id} permanently failed after ${retries} attempts: ${error}`);
    } else {
      const delay = Math.min(5000 * Math.pow(3, retries - 1), 12 * 60 * 60_000);
      const retryAfter = Date.now() + delay;
      await this.db.prepare("UPDATE create_queue SET status = ?, error = ?, retries = ?, retryAfter = ?, updatedAt = ? WHERE id = ?")
        .bind(retryStatus, error, retries, retryAfter, Date.now(), item.id).run();
      console.warn(`[queue-processor] Item ${item.id} retry ${retries}/${MAX_RETRIES}, next in ${delay / 1000}s`);
    }

    this.failuresSinceLastAlert++;
    if (this.failuresSinceLastAlert >= FAILURE_ALERT_BATCH) {
      const config = await this.getConfig();
      const failed = await this.db.prepare("SELECT COUNT(*) as count FROM create_queue WHERE status = 'failed'")
        .first<{ count: number }>();
      await sendTelegram(config, `🔴 [webauthnp256-publickey-index] [CF Worker] [Gnosis]\n${this.failuresSinceLastAlert} tx failures\nTotal failed: ${failed?.count ?? 0}\nLatest: ${error}`);
      this.failuresSinceLastAlert = 0;
    }
  }

  private async checkAlerts(config: AppConfig): Promise<void> {
    const now = Date.now();
    if (now - this.lastAlertAt < ALERT_INTERVAL) return;
    this.lastAlertAt = now;

    const alerts: string[] = [];

    const pending = await this.db.prepare(
      "SELECT COUNT(*) as count FROM create_queue WHERE status IN ('pending', 'committed', 'creating')"
    ).first<{ count: number }>();
    if (pending && pending.count >= QUEUE_BACKLOG_THRESHOLD) {
      alerts.push(`⚠️ Queue backlog: ${pending.count} items pending`);
    }

    const failed = await this.db.prepare(
      "SELECT COUNT(*) as count FROM create_queue WHERE status = 'failed'"
    ).first<{ count: number }>();
    if (failed && failed.count > 0 && failed.count !== this.lastFailedCount) {
      alerts.push(`🔴 ${failed.count} items permanently failed`);
    }
    this.lastFailedCount = failed?.count ?? 0;

    try {
      const { wallet: createWallet, client } = getCreateWallet(config);
      const balance = await client.getBalance({ address: createWallet.account.address });
      const balanceXdai = Number(balance) / 1e18;
      if (balanceXdai < GAS_BALANCE_THRESHOLD) {
        alerts.push(`🪫 Create wallet balance low: ${balanceXdai.toFixed(6)} xDAI (${createWallet.account.address})`);
      }

      // Auto-fund commit wallet
      const { wallet: commitWallet } = getCommitWallet(config);
      if (commitWallet.account.address !== createWallet.account.address) {
        const commitBalance = await client.getBalance({ address: commitWallet.account.address });
        const commitBalanceXdai = Number(commitBalance) / 1e18;
        if (commitBalanceXdai < FUND_THRESHOLD) {
          await this.ensureCommitWalletFunded(config);
        }
      }
    } catch (err) { console.warn(`[queue-processor] checkAlerts gas/balance check failed:`, err instanceof Error ? err.message : err); }

    if (alerts.length > 0) {
      await sendTelegram(config, `[webauthnp256-publickey-index] [CF Worker] [Gnosis]\n${alerts.join("\n")}`);
    }
  }

  private async ensureCommitWalletFunded(config: AppConfig): Promise<void> {
    try {
      const { wallet: createWallet, client } = getCreateWallet(config);
      const { wallet: commitWallet } = getCommitWallet(config);
      if (commitWallet.account.address === createWallet.account.address) return;

      const commitBalance = await client.getBalance({ address: commitWallet.account.address });
      if (Number(commitBalance) / 1e18 >= FUND_THRESHOLD) return;

      const mainBalance = await client.getBalance({ address: createWallet.account.address });
      if (Number(mainBalance) / 1e18 < FUND_AMOUNT + GAS_BALANCE_THRESHOLD) return;

      const hash = await createWallet.sendTransaction({
        to: commitWallet.account.address,
        value: BigInt(Math.floor(FUND_AMOUNT * 1e18)),
      });
      const fundReceipt = await client.waitForTransactionReceipt({ hash, timeout: 30_000 });
      if (fundReceipt.status === "reverted") {
        throw new Error(`Fund tx reverted: ${hash}`);
      }
      console.log(`[queue-processor] Commit wallet funded: ${hash}`);
    } catch (err) {
      console.warn(`[queue-processor] Auto-fund failed:`, err instanceof Error ? err.message : err);
    }
  }
}
