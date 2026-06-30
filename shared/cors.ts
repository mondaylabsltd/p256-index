/**
 * CORS for this PUBLIC, credential-less API — shared by both runtimes so they
 * can never drift. Any origin, any method we expose, and ANY request header.
 *
 * History: the frontend sends an `idempotency-key` header on POST /api/create;
 * when Allow-Headers was hardcoded to "Content-Type" the browser blocked the
 * preflight ("Request header field idempotency-key is not allowed ...") and the
 * call surfaced as a CORS error. cors.test.ts locks this behaviour in.
 */

export const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "*",
  "Access-Control-Max-Age": "86400",
};

/**
 * Apply permissive CORS headers to a response. Pass the inbound `req` on the
 * preflight (and ideally every response) so we can echo the browser's
 * `Access-Control-Request-Headers` — this also permits `Authorization`, which
 * the `*` wildcard does NOT match per the Fetch spec.
 */
export function withCors(response: Response, req?: Request): Response {
  for (const [key, value] of Object.entries(CORS_HEADERS)) {
    response.headers.set(key, value);
  }
  const requested = req?.headers.get("Access-Control-Request-Headers");
  if (requested) response.headers.set("Access-Control-Allow-Headers", requested);
  return response;
}
