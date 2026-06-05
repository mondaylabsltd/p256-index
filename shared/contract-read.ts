import { createPublicClient, http } from "viem";
import { gnosis } from "viem/chains";
import { getCurrentRpc, markFailed } from "./rpc.ts";
import {
  CONTRACT_ABI,
  CONTRACT_ADDRESS,
  MAX_RPC_RETRIES,
  formatRecord,
  isContractRevert,
} from "./contract.ts";

export { CONTRACT_ADDRESS, CONTRACT_ABI } from "./contract.ts";

const RPC_TIMEOUT = 10_000; // 10s per RPC request

export function getClient() {
  const rpcUrl = getCurrentRpc();
  const client = createPublicClient({
    chain: gnosis,
    transport: http(rpcUrl, { timeout: RPC_TIMEOUT }),
  });
  return { client, rpcUrl };
}

/**
 * Read contract with automatic RPC retry.
 * On RPC failure, marks the RPC as failed and retries with the next one.
 * On contract revert, throws immediately (no retry).
 */
// deno-lint-ignore no-explicit-any
async function readWithRetry(params: any): Promise<any> {
  let lastErr: unknown;
  for (let i = 0; i < MAX_RPC_RETRIES; i++) {
    const { client, rpcUrl } = getClient();
    const start = performance.now();
    try {
      const result = await client.readContract({ address: CONTRACT_ADDRESS, abi: CONTRACT_ABI, ...params });
      console.log(`[contract-read] ${params.functionName} via ${rpcUrl} — ${(performance.now() - start).toFixed(0)}ms`);
      return result;
    } catch (err) {
      const ms = (performance.now() - start).toFixed(0);
      if (isContractRevert(err)) {
        console.warn(`[contract-read] ${params.functionName} reverted via ${rpcUrl} — ${ms}ms`);
        throw err;
      }
      console.warn(`[contract-read] ${params.functionName} failed via ${rpcUrl} — ${ms}ms:`, err instanceof Error ? err.message : err);
      markFailed(rpcUrl);
      lastErr = err;
    }
  }
  throw lastErr;
}

// --- Query ---

export async function getPublicKey(rpId: string, credentialId: string) {
  try {
    const record = await readWithRetry({
      functionName: "getRecord",
      args: [rpId, credentialId],
    });
    return formatRecord(record);
  } catch (err) {
    console.warn(`[contract-read] getRecord(${rpId}, ${credentialId}) failed:`, err instanceof Error ? err.message : err);
    return null;
  }
}

export async function getPublicKeyByWalletRef(walletRef: `0x${string}`) {
  try {
    const record = await readWithRetry({
      functionName: "getRecordByWalletRef",
      args: [walletRef],
    });
    return formatRecord(record);
  } catch (err) {
    console.warn(`[contract-read] getRecordByWalletRef(${walletRef}) failed:`, err instanceof Error ? err.message : err);
    return null;
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
