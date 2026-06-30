import { assertEquals, assert } from "@std/assert/";
import { withCors, CORS_HEADERS } from "../../shared/cors.ts";

Deno.test("withCors: any origin + the methods we expose", () => {
  const r = withCors(Response.json({}));
  assertEquals(r.headers.get("Access-Control-Allow-Origin"), "*");
  assert(r.headers.get("Access-Control-Allow-Methods")!.includes("POST"));
  assert(r.headers.get("Access-Control-Allow-Methods")!.includes("GET"));
});

Deno.test("withCors: allow-headers is wildcard when nothing specific is requested", () => {
  const r = withCors(Response.json({}));
  assertEquals(r.headers.get("Access-Control-Allow-Headers"), "*");
});

// REGRESSION: the production CORS block was 'Request header field idempotency-key
// is not allowed by Access-Control-Allow-Headers'. A preflight asking for custom
// headers (incl. authorization, which '*' alone does NOT cover) must get them all
// back in Allow-Headers, or the browser blocks the request.
Deno.test("withCors: echoes every requested preflight header (idempotency-key, authorization)", () => {
  const preflight = new Request("http://x/api/create", {
    method: "OPTIONS",
    headers: { "Access-Control-Request-Headers": "content-type, idempotency-key, authorization" },
  });
  const r = withCors(new Response(null, { status: 204 }), preflight);
  const allow = (r.headers.get("Access-Control-Allow-Headers") || "").toLowerCase();
  for (const h of ["content-type", "idempotency-key", "authorization"]) {
    assert(allow === "*" || allow.includes(h), `preflight must allow "${h}", got "${allow}"`);
  }
});

Deno.test("withCors: caches the preflight (Max-Age) to cut repeat OPTIONS", () => {
  assert(Number(CORS_HEADERS["Access-Control-Max-Age"]) > 0);
});

Deno.test("withCors: applies to a normal (non-preflight) response too", () => {
  const r = withCors(new Response("ok", { status: 200 }));
  assertEquals(r.headers.get("Access-Control-Allow-Origin"), "*");
});
