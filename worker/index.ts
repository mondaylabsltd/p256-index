/**
 * Cloudflare Worker entry point.
 * Shares rpc.ts, contract.ts, validation.ts, wallet-ref.ts, cache.ts,
 * challenge.ts, stats.ts routes with Deno version.
 * Only queue (D1 vs SQLite) and config (env bindings vs Deno.env) differ.
 */
import { initRpc, setAlchemyRpc, getReadCircuitState } from "../shared/rpc.ts";
import { CONTRACT_ADDRESS } from "../shared/contract.ts";
import { handleChallenge } from "../shared/routes/challenge.ts";
import { handleListRpIds, handleListPublicKeys, handleTotalCredentials } from "../shared/routes/stats.ts";
import { handleQuery } from "./routes/query.ts";
import { handleCreate, handleCreateStatus } from "./routes/create.ts";
import { initQueue, getQueueStats, setGlobalWriteLimit } from "./queue.ts";
import { setIpHashSalt, deriveIpSalt } from "../shared/queue.ts";
import { configureCache } from "../shared/cache.ts";
import { buildHealthBody } from "../shared/routes/health.ts";
import { withCors } from "../shared/cors.ts";
import { log, newRequestId, setLogLevel } from "../shared/log.ts";
import { runWatchdog } from "./watchdog.ts";
import type { Env } from "./types.ts";

export { QueueProcessor } from "./queue-processor.ts";

const HOME_HTML = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>WebAuthn P256 Public Key Index</title></head>
<body><h1>WebAuthn P256 Public Key Index</h1><p>API running on Cloudflare Workers.</p>
<p>See <a href="/api/health">/api/health</a> for status.</p></body></html>`;


let rpcInitialized = false;
let queueInitPromise: Promise<void> | null = null;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Initialize RPC list (lazy, once per isolate lifetime)
    if (!rpcInitialized) {
      await initRpc();
      if (env.ALCHEMY_API_KEY) setAlchemyRpc(env.ALCHEMY_API_KEY);
      // Salt IP hashing with a DERIVED secret (never the raw signing key) so
      // stored hashes can't be brute-forced back to raw IPs if D1 leaks.
      setIpHashSalt(await deriveIpSalt(env.PRIVATE_KEY || "webauthnp256-index"));
      if (env.LOG_LEVEL) setLogLevel(env.LOG_LEVEL);
      // Workers isolates have a 128MB budget — cap the cache well below it
      // (overridable via the CACHE_MAX_MB var; GLOBAL_WRITE_LIMIT likewise).
      const cacheMaxMb = Number(env.CACHE_MAX_MB ?? "8");
      configureCache({ maxBytes: (Number.isFinite(cacheMaxMb) && cacheMaxMb > 0 ? cacheMaxMb : 8) * 1024 * 1024 });
      const gwl = Number(env.GLOBAL_WRITE_LIMIT);
      if (Number.isFinite(gwl) && gwl > 0) setGlobalWriteLimit(gwl);
      rpcInitialized = true;
    }

    // OPTIONS preflight is answered BEFORE any DB init — a browser preflight
    // must never depend on / be blocked by a D1 outage.
    if (request.method === "OPTIONS") {
      return withCors(new Response(null, { status: 204 }), request);
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const requestId = newRequestId();
    const start = Date.now();

    let response: Response;

    try {
      // Initialize D1 queue tables (lazy, memoized per isolate). A single shared
      // promise means concurrent first requests await ONE migration run instead
      // of racing it. A failed run clears the memo so the next request retries.
      // Migrations are idempotent + INSERT OR IGNORE, so a cross-ISOLATE race is
      // also safe. Inside the try so a D1 init failure yields a CORS'd JSON 500
      // with an X-Request-Id (not a raw exception page).
      if (!queueInitPromise) {
        queueInitPromise = initQueue(env.DB).catch((err) => {
          queueInitPromise = null;
          throw err;
        });
      }
      await queueInitPromise;

      if (path === "/" && request.method === "GET") {
        response = new Response(HOME_HTML, {
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      } else if (path === "/api/health" && request.method === "GET") {
        const base = {
          service: "webauthn-p256-publickey-index",
          version: "1.0.0",
          runtime: "cloudflare-workers",
          chainId: 100,
          contract: CONTRACT_ADDRESS,
          rpcCircuit: getReadCircuitState(),
          telegramConfigured: !!(env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID),
        };
        let stats = null;
        try { stats = await getQueueStats(env.DB); } catch { /* DB hiccup → degraded */ }
        response = Response.json(buildHealthBody(base, stats));
      } else if (path === "/api/challenge" && request.method === "GET") {
        response = handleChallenge();
      } else if (path === "/api/query" && request.method === "GET") {
        response = await handleQuery(request, env.DB);
      } else if (path === "/api/create" && request.method === "POST") {
        response = await handleCreate(request, env.DB, requestId);
      } else if (path.startsWith("/api/create/") && request.method === "GET") {
        response = await handleCreateStatus(request, env.DB);
      } else if (path === "/api/stats/total" && request.method === "GET") {
        response = await handleTotalCredentials(request);
      } else if (path === "/api/stats/sites" && request.method === "GET") {
        response = await handleListRpIds(request);
      } else if (path === "/api/stats/keys" && request.method === "GET") {
        response = await handleListPublicKeys(request);
      } else {
        response = Response.json({ error: "not found" }, { status: 404 });
      }
    } catch (error) {
      log.error("http unhandled error", { request_id: requestId, method: request.method, path, error: String(error) });
      response = Response.json({ error: "internal server error", request_id: requestId }, { status: 500 });
    }

    // Only log non-trivial outcomes (errors / degraded) to keep edge logs lean;
    // CF already records every invocation. A request_id correlates the two.
    if (response.status >= 400 || response.headers.get("X-Served-Stale")) {
      log.info("http response", { request_id: requestId, method: request.method, path, status: response.status, latency_ms: Date.now() - start });
    }
    response.headers.set("X-Request-Id", requestId);

    // Ensure the queue processor DO is running — but only when this request
    // actually created queue work. Pinging on EVERY request was a subrequest
    // per hit (cost/latency amplification); the every-minute cron already
    // guarantees liveness for everything else.
    if (path === "/api/create" && request.method === "POST") {
      ctx.waitUntil((async () => {
        try {
          const doId = env.QUEUE_PROCESSOR.idFromName("main");
          const doStub = env.QUEUE_PROCESSOR.get(doId);
          await doStub.fetch(new Request("https://do/start"));
        } catch { /* ignore */ }
      })());
    }

    return withCors(response, request);
  },

  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    // Backup: ensure DO alarm is running via cron trigger
    ctx.waitUntil((async () => {
      try {
        const doId = env.QUEUE_PROCESSOR.idFromName("main");
        const doStub = env.QUEUE_PROCESSOR.get(doId);
        await doStub.fetch(new Request("https://do/start"));
      } catch { /* ignore */ }
    })());
    // External-liveness watchdog: probe the VPS runtime's /api/health from CF's
    // independent infrastructure and page Telegram when it is hard-down — the
    // one failure class the VPS's own in-process alerting can never report.
    ctx.waitUntil(runWatchdog(env));
  },
};
