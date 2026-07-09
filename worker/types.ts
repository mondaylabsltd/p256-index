export interface Env {
  DB: D1Database;
  PRIVATE_KEY: string;
  TELEGRAM_BOT_TOKEN: string;
  TELEGRAM_CHAT_ID: string;
  /** Optional priority write RPC (mirrors the Deno runtime's ALCHEMY_API_KEY support). */
  ALCHEMY_API_KEY?: string;
  QUEUE_PROCESSOR: DurableObjectNamespace;
}
