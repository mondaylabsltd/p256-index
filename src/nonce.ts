/**
 * Local nonce manager.
 *
 * Supports multiple independent nonce pools (one per EOA wallet).
 * Each pool: fetches on-chain nonce once, then increments locally.
 * On failure, resyncs from the chain.
 */

import { createPublicClient, http } from "viem";
import { gnosis } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { getWriteRpc } from "./rpc.ts";
import { getConfig } from "./config.ts";

interface NonceState {
  current: number | null;
  mutex: Promise<void>;
}

// Separate nonce pools: "create" for createRecord, "commit" for commit
const pools = new Map<string, NonceState>();

function getPool(role: string): NonceState {
  let pool = pools.get(role);
  if (!pool) {
    pool = { current: null, mutex: Promise.resolve() };
    pools.set(role, pool);
  }
  return pool;
}

function getAccountForRole(role: string) {
  const cfg = getConfig();
  const pk = role === "commit" ? cfg.commitPrivateKey : cfg.privateKey;
  if (!pk) throw new Error(`Missing env: ${role === "commit" ? "COMMIT_PRIVATE_KEY/PRIVATE_KEY" : "PRIVATE_KEY"}`);
  return privateKeyToAccount(pk as `0x${string}`);
}

async function fetchOnChainNonce(role: string): Promise<number> {
  const client = createPublicClient({
    chain: gnosis,
    transport: http(getWriteRpc()),
  });
  const nonce = await client.getTransactionCount({
    address: getAccountForRole(role).address,
    blockTag: "pending",
  });
  return nonce;
}

/**
 * Acquire the next nonce for a role. Serialized per role.
 * First call (or after reset) fetches from the chain; subsequent calls increment locally.
 */
export function acquireNonce(role: "create" | "commit" = "create"): Promise<number> {
  const pool = getPool(role);
  return new Promise<number>((resolve, reject) => {
    pool.mutex = pool.mutex.then(async () => {
      try {
        if (pool.current === null) {
          pool.current = await fetchOnChainNonce(role);
          console.log(`[nonce:${role}] Synced from chain: ${pool.current}`);
        }
        const nonce = pool.current;
        pool.current++;
        resolve(nonce);
      } catch (err) {
        reject(err);
      }
    });
  });
}

/**
 * Reset nonce state for a role. Next acquireNonce() will re-fetch from chain.
 */
export function resetNonce(role: "create" | "commit" = "create"): void {
  const pool = getPool(role);
  pool.current = null;
  console.log(`[nonce:${role}] Reset — will resync from chain on next acquire`);
}

/**
 * Check if an error is a nonce-related error.
 */
export function isNonceError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /nonce too low|nonce.*already|replacement transaction underpriced|already known/i.test(msg);
}
