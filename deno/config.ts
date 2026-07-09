/**
 * Global config from environment variables.
 * Deployed via .env file written by `deno task deploy`.
 */

import { createHash } from "node:crypto";

export interface AppConfig {
  port: number;
  privateKey: string;
  commitPrivateKey: string; // derived from PRIVATE_KEY via SHA-256 for commit txs
  alchemyApiKey: string;
  queueDbPath: string;
  telegramBotToken: string;
  telegramChatId: string;
}

let config: AppConfig;

export function initConfig(): AppConfig {
  const privateKey = Deno.env.get("PRIVATE_KEY") || "";
  // Fail fast on a malformed key. Without this, deriveCommitKey throws an opaque
  // TypeError on '0x'/odd-length, or — worse — silently derives a WRONG commit
  // wallet when a non-hex char makes parseInt→NaN→0. An empty key is allowed (the
  // service still serves read-only; the worker is a no-op without a signer).
  if (privateKey && !isValidPrivateKey(privateKey)) {
    throw new Error("Invalid PRIVATE_KEY: must be a 0x-prefixed 32-byte (64 hex char) private key");
  }
  config = {
    port: parseInt(Deno.env.get("PORT") || "11256"),
    privateKey,
    commitPrivateKey: privateKey ? deriveCommitKey(privateKey) : "",
    queueDbPath: Deno.env.get("QUEUE_DB_PATH") || "queue.db",
    alchemyApiKey: Deno.env.get("ALCHEMY_API_KEY") || "",
    telegramBotToken: Deno.env.get("TELEGRAM_BOT_TOKEN") || "",
    telegramChatId: Deno.env.get("TELEGRAM_CHAT_ID") || "",
  };
  return config;
}

/** True only for a well-formed 0x-prefixed 32-byte hex private key. */
export function isValidPrivateKey(pk: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(pk);
}

/** Derive commit wallet private key: SHA-256(PRIVATE_KEY bytes) → 0x... */
function deriveCommitKey(privateKey: string): string {
  const hex = privateKey.startsWith("0x") ? privateKey.slice(2) : privateKey;
  const bytes = new Uint8Array(hex.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
  const hash = createHash("sha256").update(bytes).digest();
  return "0x" + Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function getConfig(): AppConfig {
  if (!config) throw new Error("Config not initialized. Call initConfig() first.");
  return config;
}
