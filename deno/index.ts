import { initConfig } from "./config.ts";
import { initRpc, setAlchemyRpc, getReadCircuitState } from "../shared/rpc.ts";
import { CONTRACT_ADDRESS } from "../shared/contract-read.ts";
import { handleQuery } from "./routes/query.ts";
import { handleChallenge } from "../shared/routes/challenge.ts";
import { handleCreate, handleCreateStatus } from "./routes/create.ts";
import { handleListRpIds, handleListPublicKeys, handleTotalCredentials } from "../shared/routes/stats.ts";
import { initQueue, startQueueWorker, getQueueStats } from "./queue.ts";
import { setIpHashSalt } from "../shared/queue.ts";
import { buildHealthBody } from "../shared/routes/health.ts";
import { withCors } from "../shared/cors.ts";
import { log, newRequestId } from "../shared/log.ts";

const HOME_HTML = await Deno.readTextFile(new URL("./index.html", import.meta.url));

const config = initConfig();
if (config.alchemyApiKey) setAlchemyRpc(config.alchemyApiKey);
// Salt IP hashing with a server secret so stored hashes can't be brute-forced
// back to raw IPs if the DB leaks. PRIVATE_KEY is the always-present secret.
setIpHashSalt(config.privateKey || "webauthnp256-index");
await initRpc();
initQueue(config.queueDbPath);

const server = Deno.serve({ port: config.port }, async (req) => {
  if (req.method === "OPTIONS") {
    return withCors(new Response(null, { status: 204 }), req);
  }

  const url = new URL(req.url);
  const path = url.pathname;
  const requestId = newRequestId();
  const start = performance.now();
  log.info("http request", { request_id: requestId, method: req.method, path, query: url.search || undefined });

  let response: Response;

  try {
    if (path === "/" && req.method === "GET") {
      response = new Response(HOME_HTML, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    } else if (path === "/api/health" && req.method === "GET") {
      const base = {
        service: "webauthn-p256-publickey-index",
        version: "1.0.0",
        chainId: 100,
        contract: CONTRACT_ADDRESS,
        rpcCircuit: getReadCircuitState(),
      };
      let stats = null;
      try { stats = getQueueStats(); } catch { /* DB hiccup → degraded */ }
      response = Response.json(buildHealthBody(base, stats));
    } else if (path === "/api/challenge" && req.method === "GET") {
      response = handleChallenge();
    } else if (path === "/api/query" && req.method === "GET") {
      response = await handleQuery(req);
    } else if (path === "/api/create" && req.method === "POST") {
      response = await handleCreate(req);
    } else if (path.startsWith("/api/create/") && req.method === "GET") {
      response = handleCreateStatus(req);
    } else if (path === "/api/stats/total" && req.method === "GET") {
      response = await handleTotalCredentials();
    } else if (path === "/api/stats/sites" && req.method === "GET") {
      response = await handleListRpIds(req);
    } else if (path === "/api/stats/keys" && req.method === "GET") {
      response = await handleListPublicKeys(req);
    } else {
      response = Response.json({ error: "not found" }, { status: 404 });
    }
  } catch (error) {
    log.error("http unhandled error", { request_id: requestId, method: req.method, path, error: String(error) });
    response = Response.json({ error: "internal server error", request_id: requestId }, { status: 500 });
  }

  const ms = Math.round(performance.now() - start);
  log.info("http response", { request_id: requestId, method: req.method, path, status: response.status, latency_ms: ms });
  response.headers.set("X-Request-Id", requestId);
  return withCors(response, req);
});

console.log(`Server running at http://localhost:${config.port}`);
startQueueWorker();

export { server };
