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
