/**
 * Deno-side nonce API — thin wrapper over the SHARED nonce manager
 * (shared/nonce.ts). Kept as a module so callers/tests keep the historical
 * signature (role-only, config resolved internally) and error messages.
 */

import { getConfig } from "./config.ts";
import { createNonceManager, type NonceHandle, type NonceRole } from "../shared/nonce.ts";

export type { NonceHandle };

const manager = createNonceManager();

/**
 * Acquire the next nonce for a role. Returns { nonce, release }.
 * If the tx fails to send, call release() to avoid nonce gaps.
 * If the tx is sent successfully, do nothing (nonce is consumed).
 */
export function acquireNonce(role: NonceRole = "create"): Promise<NonceHandle> {
  const cfg = getConfig();
  const pk = role === "commit" ? cfg.commitPrivateKey : cfg.privateKey;
  if (!pk) throw new Error(`Missing env: ${role === "commit" ? "COMMIT_PRIVATE_KEY/PRIVATE_KEY" : "PRIVATE_KEY"}`);
  return manager.acquire(role, pk);
}

/**
 * Reset nonce state for a role. Next acquireNonce() will re-fetch from chain.
 */
export function resetNonce(role: NonceRole = "create"): void {
  manager.reset(role);
}
