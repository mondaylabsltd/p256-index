/**
 * Local nonce manager for fire-and-forget tx pattern.
 *
 * Supports multiple independent nonce pools (one per EOA wallet).
 * Each pool: syncs from chain, increments locally, handles failures.
 *
 * Key design: acquireNonce returns a nonce and a release function.
 * On success (tx sent to RPC): do nothing — nonce is consumed.
 * On failure (tx NOT sent): call release() to return the nonce to the pool.
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

export interface NonceHandle {
  nonce: number;
  /** Call on send failure to return the nonce to the pool (prevents gaps). */
  release: () => void;
}

/**
 * Acquire the next nonce for a role. Returns { nonce, release }.
 * If the tx fails to send, call release() to avoid nonce gaps.
 * If the tx is sent successfully, do nothing (nonce is consumed).
 */
export function acquireNonce(role: "create" | "commit" = "create"): Promise<NonceHandle> {
  const pool = getPool(role);
  return new Promise<NonceHandle>((resolve, reject) => {
    pool.mutex = pool.mutex.then(async () => {
      try {
        if (pool.current === null) {
          pool.current = await fetchOnChainNonce(role);
          console.log(`[nonce:${role}] Synced from chain: ${pool.current}`);
        }
        const nonce = pool.current;
        pool.current++;
        resolve({
          nonce,
          release: () => {
            // Return nonce to pool — force resync on next acquire
            // (can't just decrement because other nonces may have been issued)
            pool.current = null;
            console.log(`[nonce:${role}] Released nonce ${nonce}, will resync`);
          },
        });
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
