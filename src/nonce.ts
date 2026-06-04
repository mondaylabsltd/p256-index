/**
 * Local nonce manager.
 *
 * Prevents nonce collisions when sending multiple transactions in parallel.
 * Fetches the on-chain nonce once, then increments locally. On failure
 * (e.g. nonce already used), resyncs from the chain.
 */

import { createPublicClient, http } from "viem";
import { gnosis } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { getWriteRpc } from "./rpc.ts";
import { getConfig } from "./config.ts";

let currentNonce: number | null = null;
let mutex: Promise<void> = Promise.resolve();

function getAccount() {
  const pk = getConfig().privateKey;
  if (!pk) throw new Error("Missing env: PRIVATE_KEY");
  return privateKeyToAccount(pk as `0x${string}`);
}

async function fetchOnChainNonce(): Promise<number> {
  const client = createPublicClient({
    chain: gnosis,
    transport: http(getWriteRpc()),
  });
  const nonce = await client.getTransactionCount({
    address: getAccount().address,
    blockTag: "pending",
  });
  return nonce;
}

/**
 * Acquire the next nonce. Serialized — only one caller gets a nonce at a time.
 * First call (or after reset) fetches from the chain; subsequent calls increment locally.
 */
export function acquireNonce(): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    mutex = mutex.then(async () => {
      try {
        if (currentNonce === null) {
          currentNonce = await fetchOnChainNonce();
          console.log(`[nonce] Synced from chain: ${currentNonce}`);
        }
        const nonce = currentNonce;
        currentNonce++;
        resolve(nonce);
      } catch (err) {
        reject(err);
      }
    });
  });
}

/**
 * Reset local nonce state. Called when a transaction fails with a nonce error
 * so the next acquireNonce() re-fetches from the chain.
 */
export function resetNonce(): void {
  currentNonce = null;
  console.log("[nonce] Reset — will resync from chain on next acquire");
}

/**
 * Check if an error is a nonce-related error.
 */
export function isNonceError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /nonce too low|nonce.*already|replacement transaction underpriced|already known/i.test(msg);
}
