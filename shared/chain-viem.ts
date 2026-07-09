/**
 * Real ChainOps implementation over viem — shared by both runtimes.
 *
 * All chain-facing details live here: RPC endpoint selection (getWriteRpc),
 * transport timeouts, wallet clients, and — for the cycle-opening gas check —
 * write-endpoint cooldown marking (markFailed/markHealthy) so a dead or
 * rate-limited endpoint (incl. a pinned Alchemy URL) is rotated away on the
 * next cycle instead of stalling the pipeline forever.
 *
 * Transport budgets (transcribed from the prior implementations):
 * - read-style calls (gas price, block number, multicalls): 10s, fresh client
 * - wallet clients (estimate/send/receipt/hasRecord-single): WRITE_TRANSPORT
 *   (8s × 1 retry) via getCreateWallet/getCommitWallet
 */

import { createPublicClient, http } from "viem";
import { gnosis } from "viem/chains";
import { getWriteRpc, markFailed, markHealthy } from "./rpc.ts";
import { CONTRACT_ADDRESS, CONTRACT_ABI, BATCH_HELPER_ADDRESS, BATCH_ABI } from "./contract.ts";
import {
  type AppConfig,
  type CallResult,
  getCreateWallet,
  getCommitWallet,
} from "./queue.ts";
import type { BatchCreateParam, ChainOps } from "./queue-engine.ts";
import type { NonceRole } from "./nonce.ts";
import { log, redactSecrets } from "./log.ts";

const READ_STYLE_TIMEOUT = 10_000;

export function createViemChainOps(getCfg: () => AppConfig): ChainOps {
  // ENDPOINT AFFINITY (pre-refactor parity): the old code resolved getWriteRpc()
  // once per PHASE and reused that client for every operation in the phase, so a
  // tx was estimated, broadcast, and receipt-polled against the SAME endpoint.
  // Re-resolving per call would let the round-robin advance mid-flow (send on A,
  // poll receipt on B → spurious 60s timeouts → duplicate sends / wasted gas).
  // The engine calls beginPhase() at each phase boundary; within a phase the
  // read client and each wallet pair are memoized on first use.
  let phaseRead: ReturnType<typeof createPublicClient> | null = null;
  const phaseWallets: Partial<Record<NonceRole, ReturnType<typeof getCreateWallet>>> = {};

  function beginPhase(): void {
    phaseRead = null;
    delete phaseWallets.create;
    delete phaseWallets.commit;
  }
  function readClient() {
    phaseRead ??= createPublicClient({ chain: gnosis, transport: http(getWriteRpc(), { timeout: READ_STYLE_TIMEOUT }) });
    return phaseRead;
  }
  function walletFor(role: NonceRole) {
    phaseWallets[role] ??= role === "commit" ? getCommitWallet(getCfg()) : getCreateWallet(getCfg());
    return phaseWallets[role]!;
  }

  return {
    beginPhase,
    async getGasPrice(): Promise<bigint> {
      const gasRpc = getWriteRpc();
      try {
        const client = createPublicClient({ chain: gnosis, transport: http(gasRpc, { timeout: READ_STYLE_TIMEOUT }) });
        const price = await client.getGasPrice();
        markHealthy(gasRpc); // a working call clears any cooldown → fast recovery
        return price;
      } catch (err) {
        // Cool down the endpoint that just failed (incl. a pinned Alchemy URL)
        // so the NEXT cycle's getWriteRpc rotates to a healthy one instead of
        // pinning the dead one forever.
        markFailed(gasRpc);
        log.warn("write RPC gas-price probe failed, cooling down endpoint", {
          dependency: "rpc", operation: "getGasPrice", error_category: "transient",
          error: redactSecrets(err instanceof Error ? err.message : String(err)).slice(0, 200),
        });
        throw err;
      }
    },

    getBlockNumber(): Promise<bigint> {
      return readClient().getBlockNumber();
    },

    async hasRecordMulticall(items, via = "read"): Promise<CallResult[]> {
      const calls = items.map((item) => ({
        address: CONTRACT_ADDRESS as `0x${string}`,
        abi: CONTRACT_ABI,
        functionName: "hasRecord" as const,
        args: [item.rpId, item.credentialId] as const,
      }));
      // "wallet" (reconcileReady): the create-wallet's client — same endpoint
      // as the subsequent send, tighter WRITE_TRANSPORT budget (pre-refactor parity).
      const client = via === "wallet" ? walletFor("create").client : readClient();
      return await client.multicall({ contracts: calls }) as CallResult[];
    },

    async getCommitBlockMulticall(commitments): Promise<CallResult[]> {
      const calls = commitments.map((commitment) => ({
        address: CONTRACT_ADDRESS as `0x${string}`,
        abi: CONTRACT_ABI,
        functionName: "getCommitBlock" as const,
        args: [commitment] as const,
      }));
      return await readClient().multicall({ contracts: calls }) as CallResult[];
    },

    async hasRecord(rpId, credentialId): Promise<boolean> {
      const { client } = walletFor("create");
      return await client.readContract({
        address: CONTRACT_ADDRESS, abi: CONTRACT_ABI, functionName: "hasRecord", args: [rpId, credentialId],
      }) as boolean;
    },

    async estimateBatchCreate(params: BatchCreateParam[]): Promise<bigint> {
      const { wallet, client } = walletFor("create");
      return await client.estimateContractGas({
        address: BATCH_HELPER_ADDRESS,
        abi: BATCH_ABI,
        functionName: "batchCreateRecord",
        args: [CONTRACT_ADDRESS, params],
        account: wallet.account,
      });
    },

    async sendBatchCreate(params: BatchCreateParam[], nonce: number, gas: bigint): Promise<`0x${string}`> {
      const { wallet } = walletFor("create");
      return await wallet.writeContract({
        address: BATCH_HELPER_ADDRESS,
        abi: BATCH_ABI,
        functionName: "batchCreateRecord",
        args: [CONTRACT_ADDRESS, params],
        nonce,
        gas,
      });
    },

    async estimateBatchCommit(commitments): Promise<bigint> {
      const { wallet, client } = walletFor("commit");
      return await client.estimateContractGas({
        address: BATCH_HELPER_ADDRESS,
        abi: BATCH_ABI,
        functionName: "batchCommit",
        args: [CONTRACT_ADDRESS, commitments],
        account: wallet.account,
      });
    },

    async sendBatchCommit(commitments, nonce: number, gas: bigint): Promise<`0x${string}`> {
      const { wallet } = walletFor("commit");
      return await wallet.writeContract({
        address: BATCH_HELPER_ADDRESS,
        abi: BATCH_ABI,
        functionName: "batchCommit",
        args: [CONTRACT_ADDRESS, commitments],
        nonce,
        gas,
      });
    },

    async waitReceipt(hash, timeoutMs, role): Promise<{ status: "success" | "reverted" }> {
      const { client } = walletFor(role);
      const receipt = await client.waitForTransactionReceipt({ hash, timeout: timeoutMs });
      return { status: receipt.status === "reverted" ? "reverted" : "success" };
    },
  };
}
