import { createPublicClient, http } from "viem";
import { gnosis } from "viem/chains";
import { getCurrentRpc, markFailed, markHealthy, getReadCircuitState, readCircuitRetryAfterMs, tryReadProbe } from "./rpc.ts";
import {
  CONTRACT_ABI,
  CONTRACT_ADDRESS,
  MAX_RPC_RETRIES,
  formatRecord,
  isContractRevert,
} from "./contract.ts";
import {
  withRetry,
  withDeadline,
  classifyError,
  DependencyError,
  type RetryAttemptInfo,
} from "./reliability.ts";
import { log } from "./log.ts";

export { CONTRACT_ADDRESS, CONTRACT_ABI } from "./contract.ts";
export { DependencyError } from "./reliability.ts";

const RPC_TIMEOUT = 10_000; // 10s per single RPC request (viem transport timeout)
// Total budget for a logical read across all RPC-rotation retries. Caps the
// worst case so a synchronous request can never hang for minutes: previously
// MAX_RPC_RETRIES(3) × viem's own retryCount(3) × 10s ≈ 90s with no ceiling.
const READ_DEADLINE = 12_000;

export function getClient() {
  const rpcUrl = getCurrentRpc();
  const client = createPublicClient({
    chain: gnosis,
    // retryCount: 0 — OUR layer owns retries (with RPC rotation + backoff +
    // classification). Letting viem also retry on the same endpoint multiplied
    // attempts (request amplification) and ignored our deadline.
    transport: http(rpcUrl, { timeout: RPC_TIMEOUT, retryCount: 0 }),
  });
  return { client, rpcUrl };
}

/**
 * Read a contract view function with bounded, deadline-capped retries that
 * rotate RPC endpoints between attempts.
 *
 * - A contract revert (e.g. RecordNotFound) is a *business outcome*: rethrown
 *   immediately, never retried, never marks the RPC bad.
 * - A transient RPC fault marks that endpoint bad (cooldown) and retries the
 *   next endpoint, under a single total time budget.
 * - If every attempt fails transiently, throws DependencyError("rpc") so the
 *   caller can return 503 + Retry-After instead of a misleading 404/500.
 */
// deno-lint-ignore no-explicit-any
async function readWithRetry(params: any): Promise<any> {
  const operation = params.functionName as string;

  // Circuit breaker: if every read endpoint is currently in cooldown, don't burn
  // the 12s retry deadline hammering known-dead nodes — fail fast with a stable,
  // retryable signal so the caller returns 503 in milliseconds and the server's
  // own connections/CPU aren't tied up while the upstream is fully down.
  // Half-open: still let ONE probe through every few seconds so recovery is
  // detected promptly (a successful probe calls markHealthy → circuit closes).
  if (getReadCircuitState() === "open" && !tryReadProbe()) {
    log.warn("rpc read circuit open, fast-failing", { dependency: "rpc", operation, circuit_state: "open", outcome: "shed" });
    throw new DependencyError(
      "rpc",
      { category: "transient", retryable: true, reason: "all rpc endpoints in cooldown", retryAfterMs: readCircuitRetryAfterMs() || 5_000 },
      new Error("rpc circuit open"),
    );
  }

  const deadlineStart = Date.now();
  try {
    return await withRetry(
      async () => {
        const { client, rpcUrl } = getClient();
        const start = performance.now();
        try {
          // In-flight budget enforcement: withRetry checks the deadline only
          // BETWEEN attempts, so an attempt started at t=11.9s could still run
          // its full 10s transport timeout (worst case ~22s). Racing each
          // attempt against the REMAINING budget makes READ_DEADLINE a real
          // ceiling for the synchronous request path.
          const remaining = Math.max(1, READ_DEADLINE - (Date.now() - deadlineStart));
          const result = await withDeadline(
            client.readContract({ address: CONTRACT_ADDRESS, abi: CONTRACT_ABI, ...params }),
            remaining,
            operation,
          );
          markHealthy(rpcUrl); // a working read clears any prior cooldown → fast circuit recovery
          log.debug("rpc read ok", {
            dependency: "rpc", operation, outcome: "success",
            latency_ms: Math.round(performance.now() - start), rpc: rpcUrl,
          });
          return result;
        } catch (err) {
          // A contract revert is NOT an RPC fault — surface it so the caller
          // (and withRetry) treat it as a permanent business outcome.
          if (!isContractRevert(err)) markFailed(rpcUrl);
          throw err;
        }
      },
      {
        attempts: MAX_RPC_RETRIES,
        context: "rpc-read",
        dependency: "rpc",
        operation,
        deadlineMs: READ_DEADLINE,
        baseDelayMs: 150,
        maxDelayMs: 2_000,
        onAttempt: (i: RetryAttemptInfo) => {
          log.warn("rpc read attempt failed", {
            dependency: "rpc", operation, attempt: i.attempt,
            error_category: i.classified.category, retryable: i.classified.retryable,
            latency_ms: Math.round(i.elapsedMs), willRetry: i.willRetry,
          });
        },
      },
    );
  } catch (err) {
    // A permanent (revert) error: rethrow as-is so getPublicKey can detect
    // "not found". A transient exhaustion: wrap as DependencyError.
    const classified = classifyError(err, "rpc-read");
    if (classified.category === "permanent" || isContractRevert(err)) throw err;
    throw new DependencyError("rpc", classified, err);
  }
}

// --- Query ---

/**
 * Returns the record, or null if it is genuinely not on-chain (contract revert
 * / RecordNotFound). Throws DependencyError if the chain could not be reached —
 * callers MUST NOT treat that as "not found".
 */
export async function getPublicKey(rpId: string, credentialId: string) {
  try {
    const record = await readWithRetry({ functionName: "getRecord", args: [rpId, credentialId] });
    return formatRecord(record);
  } catch (err) {
    if (err instanceof DependencyError) throw err;
    if (isContractRevert(err)) {
      log.debug("getRecord: no record yet", { dependency: "rpc", operation: "getRecord", rpId, credentialId });
      return null;
    }
    // Defensive: anything else unexpected is treated as a dependency failure
    // rather than silently becoming a false "not found".
    throw new DependencyError("rpc", classifyError(err, "rpc-read"), err);
  }
}

export async function getPublicKeyByWalletRef(walletRef: `0x${string}`) {
  try {
    const record = await readWithRetry({ functionName: "getRecordByWalletRef", args: [walletRef] });
    return formatRecord(record);
  } catch (err) {
    if (err instanceof DependencyError) throw err;
    if (isContractRevert(err)) {
      log.debug("getRecordByWalletRef: no record yet", { dependency: "rpc", operation: "getRecordByWalletRef", walletRef });
      return null;
    }
    throw new DependencyError("rpc", classifyError(err, "rpc-read"), err);
  }
}

// --- Stats ---

export async function getTotalCredentials(): Promise<number> {
  const total = await readWithRetry({ functionName: "getTotalCredentials" });
  return Number(total);
}

export async function listRpIds(page: number, pageSize: number, order: "asc" | "desc" = "desc") {
  const offset = (page - 1) * pageSize;

  const [total, rpIds, counts, createdAts] = await readWithRetry({
    functionName: "getRpIds",
    args: [BigInt(offset), BigInt(pageSize), order === "desc"],
  });

  const items = (rpIds as string[]).map((rpId: string, i: number) => ({
    rpId,
    publicKeyCount: Number(counts[i]),
    createdAt: Number(createdAts[i]) * 1000,
  }));

  return { total: Number(total), page, pageSize, items };
}

export async function listPublicKeysByRpId(rpId: string, page: number, pageSize: number, order: "asc" | "desc" = "desc") {
  const offset = (page - 1) * pageSize;

  const [total, records] = await readWithRetry({
    functionName: "getKeysByRpId",
    args: [rpId, BigInt(offset), BigInt(pageSize), order === "desc"],
  });

  const items = (records as Array<{ rpId: string; credentialId: string; walletRef: string; publicKey: string; name: string; initialCredentialId: string; metadata: string; createdAt: bigint }>).map((r) => formatRecord(r));

  return { total: Number(total), page, pageSize, items };
}
