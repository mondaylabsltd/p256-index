/**
 * Config builder for CF Worker.
 * Uses crypto.subtle instead of node:crypto for key derivation.
 */
import type { Env } from "./types.ts";
import type { AppConfig } from "../shared/queue.ts";

/** True only for a well-formed 0x-prefixed 32-byte hex private key. */
export function isValidPrivateKey(pk: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(pk);
}

async function deriveCommitKey(privateKey: string): Promise<string> {
  const hex = privateKey.startsWith("0x") ? privateKey.slice(2) : privateKey;
  const bytes = new Uint8Array(hex.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return "0x" + Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function buildConfig(env: Env): Promise<AppConfig> {
  const privateKey = env.PRIVATE_KEY || "";
  // Fail fast on a malformed secret instead of deriving a silently-wrong commit
  // wallet (non-hex → parseInt NaN → 0) or throwing an opaque TypeError.
  if (privateKey && !isValidPrivateKey(privateKey)) {
    throw new Error("Invalid PRIVATE_KEY: must be a 0x-prefixed 32-byte (64 hex char) private key");
  }
  return {
    privateKey,
    commitPrivateKey: privateKey ? await deriveCommitKey(privateKey) : "",
    telegramBotToken: env.TELEGRAM_BOT_TOKEN || "",
    telegramChatId: env.TELEGRAM_CHAT_ID || "",
  };
}
