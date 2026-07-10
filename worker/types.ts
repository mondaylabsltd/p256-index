export interface Env {
  DB: D1Database;
  PRIVATE_KEY: string;
  TELEGRAM_BOT_TOKEN: string;
  TELEGRAM_CHAT_ID: string;
  /** Optional priority write RPC (mirrors the Deno runtime's ALCHEMY_API_KEY support). */
  ALCHEMY_API_KEY?: string;
  /** Optional cache budget in MB (default 8 on Workers' 128MB isolates). */
  CACHE_MAX_MB?: string;
  /** Optional global create cap per minute (default 40). */
  GLOBAL_WRITE_LIMIT?: string;
  /** Optional minimum log level: debug|info|warn|error (default debug). */
  LOG_LEVEL?: string;
  /** Optional override for the external-liveness watchdog's probe target. */
  WATCHDOG_TARGET_URL?: string;
  QUEUE_PROCESSOR: DurableObjectNamespace;
}
