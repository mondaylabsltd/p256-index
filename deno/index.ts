import { initConfig } from "./config.ts";
import { initRpc, setAlchemyRpc } from "../shared/rpc.ts";
import { CONTRACT_ADDRESS } from "../shared/contract-read.ts";
import { handleQuery } from "./routes/query.ts";
import { handleChallenge } from "../shared/routes/challenge.ts";
import { handleCreate, handleCreateStatus } from "./routes/create.ts";
import { handleListRpIds, handleListPublicKeys, handleTotalCredentials } from "../shared/routes/stats.ts";
import { initQueue, startQueueWorker } from "./queue.ts";

const HOME_HTML = await Deno.readTextFile(new URL("./index.html", import.meta.url));

const config = initConfig();
if (config.alchemyApiKey) setAlchemyRpc(config.alchemyApiKey);
await initRpc();
initQueue(config.queueDbPath);

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function withCors(response: Response): Response {
  for (const [key, value] of Object.entries(CORS_HEADERS)) {
    response.headers.set(key, value);
  }
  return response;
}

const server = Deno.serve({ port: config.port }, async (req) => {
  if (req.method === "OPTIONS") {
    return withCors(new Response(null, { status: 204 }));
  }

  const url = new URL(req.url);
  const path = url.pathname;
  const start = performance.now();
  console.log(`[http] → ${req.method} ${path}${url.search}`);

  let response: Response;

  try {
    if (path === "/" && req.method === "GET") {
      response = new Response(HOME_HTML, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    } else if (path === "/api/health" && req.method === "GET") {
      response = Response.json({
        service: "webauthn-p256-publickey-index",
        version: "1.0.0",
        chainId: 100,
        contract: CONTRACT_ADDRESS,
        status: "ok",
      });
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
    console.error("Unhandled error:", error);
    response = Response.json({ error: "internal server error" }, { status: 500 });
  }

  const ms = (performance.now() - start).toFixed(0);
  console.log(`[http] ← ${req.method} ${path} ${response.status} ${ms}ms`);
  return withCors(response);
});

console.log(`Server running at http://localhost:${config.port}`);
startQueueWorker();

export { server };
