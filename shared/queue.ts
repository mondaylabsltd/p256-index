/**
 * Shared queue types, constants, and pure logic.
 * Used by both Deno (node:sqlite) and CF Worker (D1) queue implementations.
 */
import { createWalletClient, createPublicClient, http, keccak256, encodeAbiParameters } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { gnosis } from "viem/chains";
import { getWriteRpc } from "./rpc.ts";

// --- Types ---

export type QueueStatus = "pending" | "committing" | "committed" | "creating" | "done" | "failed";

export interface QueueItem {
  id: string;
  status: QueueStatus;
  rpId: string;
  credentialId: string;
  walletRef: string;
  publicKey: string;
  name: string;
  initialCredentialId: string;
  metadata: string;
  txHash: string;
  error: string;
  retries: number;
  retryAfter: number;
  ip: string;
  createdAt: number;
  updatedAt: number;
}

// --- Constants ---

export const MAX_RETRIES = 10;
export const WORKER_INTERVAL = 60_000;
export const QUERY_BATCH_SIZE = 100;
export const TX_BATCH_SIZE = 50;
export const RATE_WINDOW = 60_000;
export const DEFAULT_RATE_LIMIT = 5;
export const MAX_GAS_PRICE_GWEI = 0.1;
export const GAS_BALANCE_THRESHOLD = 0.01;
export const FUND_THRESHOLD = 0.005;
export const FUND_AMOUNT = 0.05;
export const DONE_RETENTION = 7 * 24 * 60 * 60_000;
export const CREATE_SUB_BATCH = 10;

// --- Table DDL ---

export const CREATE_QUEUE_DDL = `
  CREATE TABLE IF NOT EXISTS create_queue (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'pending',
    rpId TEXT NOT NULL,
    credentialId TEXT NOT NULL,
    walletRef TEXT NOT NULL DEFAULT '',
    publicKey TEXT NOT NULL,
    name TEXT NOT NULL,
    initialCredentialId TEXT NOT NULL,
    metadata TEXT NOT NULL,
    txHash TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    retries INTEGER NOT NULL DEFAULT 0,
    retryAfter INTEGER NOT NULL DEFAULT 0,
    ip TEXT NOT NULL DEFAULT '',
    createdAt INTEGER NOT NULL,
    updatedAt INTEGER NOT NULL
  )
`;

// --- Pure helpers ---

export async function hashIp(ip: string): Promise<string> {
  const data = new TextEncoder().encode(ip);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
}

export function buildCommitment(item: QueueItem) {
  const walletRefHex = item.walletRef as `0x${string}`;
  const publicKeyHex = (item.publicKey.startsWith("0x") ? item.publicKey : `0x${item.publicKey}`) as `0x${string}`;
  const metadataHex = (item.metadata.startsWith("0x") ? item.metadata : `0x${item.metadata}`) as `0x${string}`;

  return {
    commitment: keccak256(
      encodeAbiParameters(
        [{ type: "string" }, { type: "string" }, { type: "bytes32" }, { type: "bytes" }, { type: "string" }, { type: "string" }, { type: "bytes" }],
        [item.rpId, item.credentialId, walletRefHex, publicKeyHex, item.name, item.initialCredentialId, metadataHex],
      ),
    ),
    walletRefHex,
    publicKeyHex,
    metadataHex,
  };
}

// --- Wallet helpers ---

export interface AppConfig {
  privateKey: string;
  commitPrivateKey: string;
  telegramBotToken: string;
  telegramChatId: string;
}

export function getCreateWallet(config: AppConfig) {
  const pk = config.privateKey;
  if (!pk) throw new Error("Missing env: PRIVATE_KEY");
  const rpcUrl = getWriteRpc();
  return {
    wallet: createWalletClient({
      account: privateKeyToAccount(pk as `0x${string}`),
      chain: gnosis,
      transport: http(rpcUrl),
    }),
    client: createPublicClient({ chain: gnosis, transport: http(rpcUrl) }),
  };
}

export function getCommitWallet(config: AppConfig) {
  const pk = config.commitPrivateKey;
  if (!pk) throw new Error("Missing env: COMMIT_PRIVATE_KEY or PRIVATE_KEY");
  const rpcUrl = getWriteRpc();
  return {
    wallet: createWalletClient({
      account: privateKeyToAccount(pk as `0x${string}`),
      chain: gnosis,
      transport: http(rpcUrl),
    }),
    client: createPublicClient({ chain: gnosis, transport: http(rpcUrl) }),
  };
}

// --- Telegram ---

export async function sendTelegram(config: AppConfig, message: string): Promise<void> {
  const { telegramBotToken: botToken, telegramChatId: chatId } = config;
  if (!botToken || !chatId) return;
  try {
    await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text: message }),
    });
  } catch { /* ignore send failures */ }
}
