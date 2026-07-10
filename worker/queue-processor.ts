/**
 * Durable Object for queue processing (CF Worker version).
 *
 * The queue state machine itself lives in shared/queue-engine.ts (single
 * implementation for both runtimes — previously a hand-synced fork of
 * deno/queue.ts that produced several production bugs). This class provides
 * only the CF-specific pieces: the DO alarm loop, the D1 QueueStore, config,
 * alerting, and commit-wallet auto-funding.
 */
import { setAlchemyRpc } from "../shared/rpc.ts";
import {
  type QueueItem,
  type AppConfig,
  MAX_GAS_PRICE_GWEI,
  GAS_BALANCE_THRESHOLD,
  FUND_THRESHOLD,
  FUND_AMOUNT,
  getCreateWallet,
  getCommitWallet,
  sendTelegram,
} from "../shared/queue.ts";
import { runQueueCycle, type QueueStore, type AlertReason, type ItemFailureInfo } from "../shared/queue-engine.ts";
import { createViemChainOps } from "../shared/chain-viem.ts";
import { createNonceManager } from "../shared/nonce.ts";
import { buildConfig } from "./config.ts";
import { initQueue, withD1Retry } from "./queue.ts";
import { log, redactSecrets } from "../shared/log.ts";
import type { Env } from "./types.ts";

function shortMsg(err: unknown): string {
  // Redact embedded RPC credentials before storing in the 'error' column / logs.
  return redactSecrets(err instanceof Error ? err.message : String(err)).slice(0, 200);
}

const ALARM_INTERVAL = 10_000; // 10s
const ALERT_INTERVAL = 5 * 60_000;
const QUEUE_BACKLOG_THRESHOLD = 100;
const FAILURE_ALERT_BATCH = 10;

// Per-isolate nonce pools (one DO instance — matches the prior module-level pools).
const nonceManager = createNonceManager();

export class QueueProcessor implements DurableObject {
  private state: DurableObjectState;
  private env: Env;
  private lastAlertAt = 0;
  private lastFailedCount = 0;
  private failuresSinceLastAlert = 0;
  private lastTerminalAlertAt = 0;
  private terminalSinceLastAlert = 0;
  private lastTerminalError = "";
  private consecutiveGasFails = 0;
  private lastRpcUnreachableAlertAt = 0;
  private consecutiveAlarmErrors = 0;
  private lastAlarmErrorAlertAt = 0;
  private lastStuckAlertAt = 0;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
    // The DO runs in its own isolate and never goes through the fetch entry's
    // initRpc path — wire the priority write RPC here or every write tx
    // (commit/createRecord/nonce/gas) silently falls back to public endpoints.
    if (env.ALCHEMY_API_KEY) setAlchemyRpc(env.ALCHEMY_API_KEY);
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
    const start = Date.now();
    try {
      await this.processQueue();
      this.consecutiveAlarmErrors = 0;
      log.info("queue alarm cycle done", { operation: "processQueue", latency_ms: Date.now() - start, outcome: "success" });
    } catch (err) {
      log.error("queue alarm cycle error", { operation: "processQueue", latency_ms: Date.now() - start, error: shortMsg(err) });
      // A throwing cycle (bug / broken migration / D1 down) never reaches
      // checkAlerts — page after several consecutive so a halted queue always
      // reaches Telegram.
      this.consecutiveAlarmErrors++;
      if (this.consecutiveAlarmErrors >= 3 && Date.now() - this.lastAlarmErrorAlertAt >= 5 * 60_000) {
        this.lastAlarmErrorAlertAt = Date.now();
        try {
          const config = await this.getConfig();
          await sendTelegram(config, `🛑 [webauthnp256-publickey-index] [CF Worker] [Gnosis]\nDO alarm cycle FAILING (${this.consecutiveAlarmErrors} consecutive) — creates NOT processed.\nLatest: ${shortMsg(err)}`);
        } catch { /* config/telegram unavailable — nothing more we can do here */ }
      }
    }
    // Always re-schedule — a failed/slow cycle must never leave the alarm unset
    // (that would silently stop all queue processing).
    await this.state.storage.setAlarm(Date.now() + ALARM_INTERVAL);
  }

  private get db(): D1Database {
    return this.env.DB;
  }

  private async getConfig(): Promise<AppConfig> {
    return await buildConfig(this.env);
  }

  private migrated = false;
  private async ensureMigrated(): Promise<void> {
    if (!this.migrated) {
      await initQueue(this.db);
      this.migrated = true;
    }
  }

  private async processQueue(): Promise<void> {
    const config = await this.getConfig();
    if (!config.privateKey) {
      console.warn("[queue-processor] No PRIVATE_KEY configured, skipping");
      // Accepting creates we can never process is a dev-intervention condition:
      // page if anything is actually queued (throttled via checkAlerts).
      try {
        await this.ensureMigrated();
        const active = await this.db.prepare(
          "SELECT COUNT(*) as c FROM create_queue WHERE status IN ('pending','committed','creating')"
        ).first<{ c: number }>();
        if (active && active.c > 0 && Date.now() - this.lastAlarmErrorAlertAt >= 5 * 60_000) {
          this.lastAlarmErrorAlertAt = Date.now();
          await sendTelegram(config, `🔑 [webauthnp256-publickey-index] [CF Worker] [Gnosis]\nNO SIGNER (PRIVATE_KEY) configured but ${active.c} create(s) are queued — they will NEVER complete. Set the secret and redeploy.`);
        }
      } catch { /* best-effort */ }
      return;
    }

    // The DO runs in its OWN isolate: after a fresh deploy the cron→alarm path
    // can fire BEFORE any fetch isolate has run initQueue, so a new migration's
    // table (e.g. pending_txs) would not exist yet and the cycle's ledger
    // writes would fail. Cheap when current (2 statements), once per instance.
    await this.ensureMigrated();

    await runQueueCycle({
      store: this.makeStore(),
      chain: createViemChainOps(() => config),
      nonces: {
        acquire: (role) => {
          const pk = role === "commit" ? config.commitPrivateKey : config.privateKey;
          if (!pk) throw new Error(`Missing key for role: ${role}`);
          return nonceManager.acquire(role, pk);
        },
      },
      hooks: {
        onItemFailure: (error, info) => this.onItemFailure(error, info),
        checkAlerts: (gasPriceGwei, reason) => this.onCheckAlerts(config, gasPriceGwei, reason),
        onStuckTx: async (role, nonce, attempts, ageMs) => {
          if (Date.now() - this.lastStuckAlertAt < 5 * 60_000) return;
          this.lastStuckAlertAt = Date.now();
          await sendTelegram(config, `🧵 [webauthnp256-publickey-index] [CF Worker] [Gnosis]\nWallet nonce STUCK: role=${role} nonce=${nonce} not clearing after ${attempts} attempts (${Math.round(ageMs / 60_000)}min). Creates behind it are blocked — check RPC acceptance / MAX_GAS_PRICE_GWEI.`);
        },
      },
      label: "[queue-processor]",
    });
  }

  /** D1 implementation of the engine's QueueStore (SQL transcribed from the pre-refactor DO). */
  private makeStore(): QueueStore {
    const db = this.db;
    return {
      async countActive(): Promise<number> {
        const row = await db.prepare(
          "SELECT COUNT(*) as count FROM create_queue WHERE status IN ('pending', 'committed', 'creating')"
        ).first<{ count: number }>();
        return row?.count ?? 0;
      },
      async listCreating(limit: number): Promise<QueueItem[]> {
        const { results } = await db.prepare(
          "SELECT * FROM create_queue WHERE status = 'creating' ORDER BY createdAt ASC LIMIT ?"
        ).bind(limit).all<QueueItem>();
        return results;
      },
      async listCommittedReady(now: number, limit: number): Promise<QueueItem[]> {
        const { results } = await db.prepare(
          "SELECT * FROM create_queue WHERE status = 'committed' AND retryAfter <= ? ORDER BY createdAt ASC LIMIT ?"
        ).bind(now, limit).all<QueueItem>();
        return results;
      },
      async listPendingReady(now: number, limit: number): Promise<QueueItem[]> {
        const { results } = await db.prepare(
          "SELECT * FROM create_queue WHERE status = 'pending' AND retryAfter <= ? ORDER BY createdAt ASC LIMIT ?"
        ).bind(now, limit).all<QueueItem>();
        return results;
      },
      async markManyDone(ids: string[], now: number, txHash?: string): Promise<void> {
        if (ids.length === 0) return;
        const stmts = ids.map((id) =>
          txHash !== undefined
            ? db.prepare("UPDATE create_queue SET status = 'done', txHash = ?, error = '', updatedAt = ? WHERE id = ?").bind(txHash, now, id)
            : db.prepare("UPDATE create_queue SET status = 'done', error = '', updatedAt = ? WHERE id = ?").bind(now, id)
        );
        await db.batch(stmts);
      },
      async markManyCommitted(ids: string[], now: number): Promise<void> {
        if (ids.length === 0) return;
        await db.batch(ids.map((id) =>
          db.prepare("UPDATE create_queue SET status = 'committed', updatedAt = ? WHERE id = ?").bind(now, id)
        ));
      },
      async applyFailure(id, fields): Promise<void> {
        if (fields.retryAfter !== undefined) {
          await db.prepare("UPDATE create_queue SET status = ?, error = ?, retries = ?, retryAfter = ?, updatedAt = ? WHERE id = ?")
            .bind(fields.status, fields.error, fields.retries, fields.retryAfter, fields.updatedAt, id).run();
        } else {
          await db.prepare("UPDATE create_queue SET status = ?, error = ?, retries = ?, updatedAt = ? WHERE id = ?")
            .bind(fields.status, fields.error, fields.retries, fields.updatedAt, id).run();
        }
      },
      async cleanupExpired(doneBefore: number, failedBefore: number): Promise<{ doneDeleted: number }> {
        // Bound the DLQ ('failed') alongside 'done' cleanup so neither grows forever.
        await db.prepare("DELETE FROM create_queue WHERE status = 'failed' AND updatedAt < ?").bind(failedBefore).run();
        const result = await db.prepare("DELETE FROM create_queue WHERE status = 'done' AND updatedAt < ?").bind(doneBefore).run();
        return { doneDeleted: result.meta.changes ?? 0 };
      },
      async recordPendingTx(role, nonce, hash, sentAt, attempts = 0): Promise<void> {
        await withD1Retry(() => db.prepare("INSERT OR REPLACE INTO pending_txs (role, nonce, hash, sentAt, attempts) VALUES (?, ?, ?, ?, ?)")
          .bind(role, nonce, hash, sentAt, attempts).run());
      },
      async deletePendingTx(role, nonce): Promise<void> {
        await db.prepare("DELETE FROM pending_txs WHERE role = ? AND nonce = ?").bind(role, nonce).run();
      },
      async listPendingTxs(sentBefore) {
        const { results } = await withD1Retry(() => db.prepare(
          "SELECT role, nonce, hash, sentAt, attempts FROM pending_txs WHERE sentAt < ? ORDER BY nonce ASC"
        ).bind(sentBefore).all<{ role: "create" | "commit"; nonce: number; hash: `0x${string}`; sentAt: number; attempts: number }>());
        return results;
      },
    };
  }

  /**
   * Engine hook. Terminal (DLQ) quarantines mean a user's create will NOT
   * complete without a developer (POISON = code/data bug, EXHAUSTED = outage
   * outlived retries) — they page IMMEDIATELY (one aggregate message per
   * minute). Non-terminal failures use the batched counter as before.
   */
  private async onItemFailure(error: string, info: ItemFailureInfo): Promise<void> {
    if (info.conflict) {
      // USER-INPUT conflict (same passkey already registered under another
      // credential). Terminal + DLQ/status-visible, but a page means "code bug
      // or funding" — this is neither. Log only (mirrors the Deno runtime).
      console.warn(`[queue-processor] user-conflict quarantine (no page): job ${info.jobId}: ${error}`);
      return;
    }
    if (info.terminal) {
      this.terminalSinceLastAlert++;
      this.lastTerminalError = `${info.poison ? "POISON" : "EXHAUSTED"} (job ${info.jobId}): ${error}`;
      const now = Date.now();
      if (now - this.lastTerminalAlertAt >= 60_000) {
        this.lastTerminalAlertAt = now;
        const n = this.terminalSinceLastAlert;
        this.terminalSinceLastAlert = 0;
        const config = await this.getConfig();
        const kind = info.poison ? "code/data bug" : "outage exhausted retries";
        await sendTelegram(config, `🚨 [webauthnp256-publickey-index] [CF Worker] [Gnosis]\n${n} create request(s) QUARANTINED to DLQ — developer intervention required (${kind}).\nLatest: ${this.lastTerminalError}\nReplay after fixing: see 06-operations-runbook.md`);
      }
      return;
    }
    this.failuresSinceLastAlert++;
    if (this.failuresSinceLastAlert >= FAILURE_ALERT_BATCH) {
      const config = await this.getConfig();
      const failed = await this.db.prepare("SELECT COUNT(*) as count FROM create_queue WHERE status = 'failed'")
        .first<{ count: number }>();
      await sendTelegram(config, `🔴 [webauthnp256-publickey-index] [CF Worker] [Gnosis]\n${this.failuresSinceLastAlert} tx failures\nTotal in DLQ (failed): ${failed?.count ?? 0}\nLatest: ${error}`);
      this.failuresSinceLastAlert = 0;
    }
  }

  /**
   * Consecutive gas-check failures = write RPC face unreachable = creates NOT
   * progressing. Page explicitly after 3 cycles (throttled 5 min), then run
   * the regular alert sweep.
   */
  private async flushTerminalAlerts(config: AppConfig): Promise<void> {
    if (this.terminalSinceLastAlert > 0 && Date.now() - this.lastTerminalAlertAt >= 60_000) {
      this.lastTerminalAlertAt = Date.now();
      const n = this.terminalSinceLastAlert;
      this.terminalSinceLastAlert = 0;
      await sendTelegram(config, `🚨 [webauthnp256-publickey-index] [CF Worker] [Gnosis]\n${n} create request(s) QUARANTINED to DLQ — developer intervention required.\nLatest: ${this.lastTerminalError}\nReplay after fixing: see 06-operations-runbook.md`);
    }
  }

  private async onCheckAlerts(config: AppConfig, gasPriceGwei: number | undefined, reason: AlertReason): Promise<void> {
    await this.flushTerminalAlerts(config);
    if (reason === "gas-fail") {
      this.consecutiveGasFails++;
      if (this.consecutiveGasFails >= 3 && Date.now() - this.lastRpcUnreachableAlertAt >= 5 * 60_000) {
        this.lastRpcUnreachableAlertAt = Date.now();
        const pending = await this.db.prepare(
          "SELECT COUNT(*) as count FROM create_queue WHERE status IN ('pending', 'committed', 'creating')"
        ).first<{ count: number }>();
        await sendTelegram(config, `🔌 [webauthnp256-publickey-index] [CF Worker] [Gnosis]\nWrite RPC unreachable for ${this.consecutiveGasFails} consecutive cycles — creates are NOT being processed (${pending?.count ?? "?"} queued). Endpoints rotate automatically; if this persists check RPC providers / ALCHEMY_API_KEY.`);
      }
    } else {
      this.consecutiveGasFails = 0;
    }
    await this.checkAlerts(config, gasPriceGwei);
  }

  private async checkAlerts(config: AppConfig, gasPriceGwei?: number): Promise<void> {
    const now = Date.now();
    if (now - this.lastAlertAt < ALERT_INTERVAL) return;
    this.lastAlertAt = now;

    const alerts: string[] = [];

    // Gas-price pause alert — parity with the Deno runtime, which alerts when a
    // sustained high-gas regime silently pauses all writes.
    if (gasPriceGwei !== undefined && gasPriceGwei > MAX_GAS_PRICE_GWEI) {
      alerts.push(`⛽ Gas price too high: ${gasPriceGwei.toFixed(4)} Gwei (max: ${MAX_GAS_PRICE_GWEI}), queue paused`);
    }

    const pending = await this.db.prepare(
      "SELECT COUNT(*) as count FROM create_queue WHERE status IN ('pending', 'committed', 'creating')"
    ).first<{ count: number }>();
    if (pending && pending.count >= QUEUE_BACKLOG_THRESHOLD) {
      alerts.push(`⚠️ Queue backlog: ${pending.count} items pending`);
    }

    // CONFLICT: rows are user-input conflicts — terminal but NOT dev-actionable,
    // so they are excluded from this page (still visible in DLQ/status).
    const failed = await this.db.prepare(
      "SELECT COUNT(*) as count FROM create_queue WHERE status = 'failed' AND error NOT LIKE 'CONFLICT:%'"
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
          const fundingIssue = await this.ensureCommitWalletFunded(config);
          if (fundingIssue) alerts.push(fundingIssue);
        }
      }
    } catch (err) { console.warn(`[queue-processor] checkAlerts gas/balance check failed:`, shortMsg(err)); }

    if (alerts.length > 0) {
      await sendTelegram(config, `[webauthnp256-publickey-index] [CF Worker] [Gnosis]\n${alerts.join("\n")}`);
    }
  }

  /**
   * Top up the commit wallet from the create wallet when low. Returns an
   * operator-actionable alert string when developer intervention is required
   * (top-up needed / funding failing) — "needs money" must never be console-only.
   */
  private async ensureCommitWalletFunded(config: AppConfig): Promise<string | null> {
    try {
      const { wallet: createWallet, client } = getCreateWallet(config);
      const { wallet: commitWallet } = getCommitWallet(config);
      if (commitWallet.account.address === createWallet.account.address) return null;

      const commitBalance = await client.getBalance({ address: commitWallet.account.address });
      if (Number(commitBalance) / 1e18 >= FUND_THRESHOLD) return null;

      const mainBalance = await client.getBalance({ address: createWallet.account.address });
      const mainBalanceXdai = Number(mainBalance) / 1e18;
      if (mainBalanceXdai < FUND_AMOUNT + GAS_BALANCE_THRESHOLD) {
        console.warn(`[queue-processor] Cannot fund commit wallet: main balance too low (${mainBalanceXdai.toFixed(6)} xDAI)`);
        return `🪫 TOP-UP REQUIRED: cannot auto-fund commit wallet — create wallet ${createWallet.account.address} has only ${mainBalanceXdai.toFixed(6)} xDAI (needs ≥ ${(FUND_AMOUNT + GAS_BALANCE_THRESHOLD).toFixed(3)}). Creates will stall when it runs out.`;
      }

      const hash = await createWallet.sendTransaction({
        to: commitWallet.account.address,
        value: BigInt(Math.floor(FUND_AMOUNT * 1e18)),
      });
      const fundReceipt = await client.waitForTransactionReceipt({ hash, timeout: 30_000 });
      if (fundReceipt.status === "reverted") {
        throw new Error(`Fund tx reverted: ${hash}`);
      }
      console.log(`[queue-processor] Commit wallet funded: ${hash}`);
      return null;
    } catch (err) {
      console.warn(`[queue-processor] Auto-fund failed:`, shortMsg(err));
      return `⚠️ Commit wallet auto-fund FAILED: ${shortMsg(err)} — check wallet balances / RPC.`;
    }
  }
}
