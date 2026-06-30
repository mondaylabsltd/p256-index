/**
 * Cloudflare Worker entry point.
 * Shares rpc.ts, contract.ts, validation.ts, wallet-ref.ts, cache.ts,
 * challenge.ts, stats.ts routes with Deno version.
 * Only queue (D1 vs SQLite) and config (env bindings vs Deno.env) differ.
 */
import { initRpc, getReadCircuitState } from "../shared/rpc.ts";
import { CONTRACT_ADDRESS } from "../shared/contract.ts";
import { handleChallenge } from "../shared/routes/challenge.ts";
import { handleListRpIds, handleListPublicKeys, handleTotalCredentials } from "../shared/routes/stats.ts";
import { handleQuery } from "./routes/query.ts";
import { handleCreate, handleCreateStatus } from "./routes/create.ts";
import { initQueue, getQueueStats } from "./queue.ts";
import { setIpHashSalt } from "../shared/queue.ts";
import { buildHealthBody } from "../shared/routes/health.ts";
import { withCors } from "../shared/cors.ts";
import { log, newRequestId } from "../shared/log.ts";
import type { Env } from "./types.ts";

export { QueueProcessor } from "./queue-processor.ts";

const HOME_HTML = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>WebAuthn P256 Public Key Index</title></head>
<body><h1>WebAuthn P256 Public Key Index</h1><p>API running on Cloudflare Workers.</p>
<p>See <a href="/api/health">/api/health</a> for status.</p></body></html>`;


let rpcInitialized = false;
let queueInitialized = false;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Initialize RPC list (lazy, once per isolate lifetime)
    if (!rpcInitialized) {
      await initRpc();
      // Salt IP hashing with a server secret so stored hashes can't be brute-
      // forced back to raw IPs if D1 leaks.
      setIpHashSalt(env.PRIVATE_KEY || "webauthnp256-index");
      rpcInitialized = true;
    }

    // Initialize D1 queue tables (lazy)
    if (!queueInitialized) {
      await initQueue(env.DB);
      queueInitialized = true;
    }

    if (request.method === "OPTIONS") {
      return withCors(new Response(null, { status: 204 }), request);
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const requestId = newRequestId();
    const start = Date.now();

    let response: Response;

    try {
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
        };
        let stats = null;
        try { stats = await getQueueStats(env.DB); } catch { /* DB hiccup → degraded */ }
        response = Response.json(buildHealthBody(base, stats));
      } else if (path === "/api/challenge" && request.method === "GET") {
        response = handleChallenge();
      } else if (path === "/api/query" && request.method === "GET") {
        response = await handleQuery(request, env.DB);
      } else if (path === "/api/create" && request.method === "POST") {
        response = await handleCreate(request, env.DB);
      } else if (path.startsWith("/api/create/") && request.method === "GET") {
        response = await handleCreateStatus(request, env.DB);
      } else if (path === "/api/stats/total" && request.method === "GET") {
        response = await handleTotalCredentials();
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

    // Ensure queue processor DO is running
    ctx.waitUntil((async () => {
      try {
        const doId = env.QUEUE_PROCESSOR.idFromName("main");
        const doStub = env.QUEUE_PROCESSOR.get(doId);
        await doStub.fetch(new Request("https://do/start"));
      } catch { /* ignore */ }
    })());

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
  },
};
