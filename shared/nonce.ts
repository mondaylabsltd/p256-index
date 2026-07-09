/**
 * Local nonce manager for the fire-and-forget tx pattern — SHARED by both
 * runtimes (previously two hand-synced copies in deno/nonce.ts and
 * worker/nonce.ts).
 *
 * Supports multiple independent nonce pools (one per EOA wallet role).
 * Each pool: syncs from chain, increments locally, handles failures.
 *
 * Key design: acquire returns a nonce and a release function.
 * On success (tx sent to RPC): do nothing — nonce is consumed.
 * On failure (tx NOT sent): call release() to return the nonce to the pool
 * (forces a resync from chain on the next acquire — we can't just decrement
 * because other nonces may have been issued from the pool meanwhile).
 */

import { createPublicClient, http } from "viem";
import { gnosis } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { getWriteRpc } from "./rpc.ts";

export type NonceRole = "create" | "commit";

export interface NonceHandle {
  nonce: number;
  /** Call on send failure to return the nonce to the pool (prevents gaps). */
  release: () => void;
}

export interface NonceManager {
  /**
   * Acquire the next nonce for a role. `privateKey` identifies the EOA whose
   * on-chain nonce is fetched on a cold pool (must be the same key for a given
   * role for the lifetime of the process — matching both prior runtimes).
   */
  acquire(role: NonceRole, privateKey: string): Promise<NonceHandle>;
  /** Reset a role's pool — next acquire re-fetches the nonce from chain. */
  reset(role: NonceRole): void;
}

interface NonceState {
  current: number | null;
  mutex: Promise<void>;
}

export function createNonceManager(): NonceManager {
  const pools = new Map<string, NonceState>();

  function getPool(role: string): NonceState {
    let pool = pools.get(role);
    if (!pool) {
      pool = { current: null, mutex: Promise.resolve() };
      pools.set(role, pool);
    }
    return pool;
  }

  async function fetchOnChainNonce(role: NonceRole, privateKey: string): Promise<number> {
    if (!privateKey) throw new Error(`Missing key for role: ${role}`);
    const account = privateKeyToAccount(privateKey as `0x${string}`);
    const client = createPublicClient({
      chain: gnosis,
      // Bounded budget: this runs inside the per-role nonce mutex, so a slow node
      // here serializes/stalls every tx send for the role. 5s × 1 retry, not 40s.
      transport: http(getWriteRpc(), { timeout: 5_000, retryCount: 1 }),
    });
    return await client.getTransactionCount({
      address: account.address,
      blockTag: "pending",
    });
  }

  return {
    acquire(role: NonceRole, privateKey: string): Promise<NonceHandle> {
      const pool = getPool(role);
      return new Promise<NonceHandle>((resolve, reject) => {
        pool.mutex = pool.mutex.then(async () => {
          try {
            if (pool.current === null) {
              pool.current = await fetchOnChainNonce(role, privateKey);
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
    },

    reset(role: NonceRole): void {
      const pool = getPool(role);
      pool.current = null;
      console.log(`[nonce:${role}] Reset — will resync from chain on next acquire`);
    },
  };
}
