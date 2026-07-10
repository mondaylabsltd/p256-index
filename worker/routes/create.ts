import { getPublicKey, getPublicKeyByWalletRef } from "../../shared/contract-read.ts";
import { enqueue, findDuplicate, findDuplicateByWalletRef, getQueueItem, checkRateLimit, getActiveQueueDepth, globalWriteLimitExceeded } from "../queue.ts";
import { encodeAbiParameters } from "viem";
import { buildWalletRef } from "../../shared/wallet-ref.ts";
import { cacheGet, cacheSet, cacheKey as cacheKey_, NOT_FOUND } from "../../shared/cache.ts";
import { validateStringLength } from "../../shared/validation.ts";
import { readBodyLimited } from "../../shared/body.ts";
import { isDependencyError } from "../../shared/routes/errors.ts";
import { MAX_ACTIVE_QUEUE_DEPTH } from "../../shared/routes/health.ts";
import { log } from "../../shared/log.ts";

const MAX_BODY_SIZE = 32 * 1024;

export async function handleCreate(req: Request, db: D1Database, requestId?: string): Promise<Response> {
  const contentLength = req.headers.get("content-length");
  const contentLengthNum = Number(contentLength);
  if (contentLength && (Number.isNaN(contentLengthNum) || contentLengthNum > MAX_BODY_SIZE)) {
    return Response.json({ error: "request body too large" }, { status: 413 });
  }

  let body: {
    rpId?: string;
    credentialId?: string;
    walletRef?: string;
    publicKey?: string;
    name?: string;
    initialCredentialId?: string;
    metadata?: string;
  };

  // Stream-limited read: memory use is bounded by MAX_BODY_SIZE even for
  // chunked / no-Content-Length requests (req.text() would buffer everything
  // BEFORE any length check — a memory-DoS vector on the single-process host).
  let text: string | null;
  try {
    text = await readBodyLimited(req, MAX_BODY_SIZE);
  } catch {
    return Response.json({ error: "invalid request body" }, { status: 400 });
  }
  if (text === null) {
    return Response.json({ error: "request body too large" }, { status: 413 });
  }
  try {
    body = JSON.parse(text);
  } catch {
    return Response.json({ error: "invalid JSON body" }, { status: 400 });
  }

  const name = body.name;
  const { rpId, credentialId, publicKey } = body;

  if (!rpId || !credentialId || !publicKey || !name) {
    return Response.json(
      { error: "rpId, credentialId, publicKey, and name are required" },
      { status: 400 },
    );
  }

  const lengthError = validateStringLength({
    rpId, credentialId, publicKey, name,
    walletRef: body.walletRef,
    initialCredentialId: body.initialCredentialId,
    metadata: body.metadata,
  });
  if (lengthError) {
    return Response.json({ error: lengthError }, { status: 400 });
  }

  // Rate limit by IP (CF provides cf-connecting-ip)
  const ip = req.headers.get("cf-connecting-ip")
    || req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || req.headers.get("x-real-ip")
    || "unknown";
  if (!await checkRateLimit(db, ip)) {
    return Response.json({ error: "rate limit exceeded, max 5 requests per minute" }, { status: 429 });
  }

  const initialCredentialId = body.initialCredentialId || credentialId;
  const publicKeyHex = (publicKey.startsWith("0x") ? publicKey : `0x${publicKey}`) as `0x${string}`;
  // walletRef is BOUND to the publicKey (must be the derived Safe address) — a
  // client can never claim an arbitrary/victim address (identity forgery).
  const walletRef = buildWalletRef(publicKey);
  if (body.walletRef && body.walletRef.toLowerCase() !== walletRef.toLowerCase()) {
    return Response.json({ error: "walletRef does not match publicKey" }, { status: 400 });
  }
  const metadata = body.metadata || encodeAbiParameters(
    [{ type: "string" }, { type: "bytes" }],
    ["VelaWalletV1", publicKeyHex],
  );

  // Already exists on-chain (idempotent). MUST exclude the negative-cache
  // sentinel — a cached "not found" is NOT a record; spreading it into a 201
  // "done" body would silently DROP the user's create.
  const cacheKey = cacheKey_("query", rpId, credentialId);
  const cached = cacheGet<object>(cacheKey);
  if (cached && cached !== NOT_FOUND) {
    return Response.json({ ...cached, status: "done" }, { status: 201 });
  }
  // Precheck is a fast-path only; a transient chain outage must not fail create.
  // We fall through to enqueue and let the worker's hasRecord reconciliation
  // converge safely (idempotent — marks done if the record is already on-chain).
  let existing = null;
  try {
    existing = await getPublicKey(rpId, credentialId);
  } catch (err) {
    if (!isDependencyError(err)) throw err;
    log.warn("create precheck skipped: chain unreachable, enqueueing anyway", {
      request_id: requestId, dependency: "rpc", operation: "getRecord", rpId, error_category: err.classified.category,
    });
  }
  if (existing) {
    cacheSet(cacheKey, existing);
    return Response.json({ ...existing, status: "done" }, { status: 201 });
  }

  // Check if already in queue
  const queued = await findDuplicate(db, rpId, credentialId);
  if (queued && queued.status !== "failed") {
    return Response.json({ id: queued.id, status: queued.status }, { status: 202 });
  }

  // walletRef conflict precheck: the SAME P256 key registered under a DIFFERENT
  // credential deterministically reverts on-chain (WalletRefAlreadyExists) —
  // after burning commit gas and quarantining to the DLQ (the exact production
  // failure of 2026-07-03). Reject up-front with an actionable 409. Two layers,
  // both fail-open (a check hiccup must never block a legitimate create — the
  // engine's CONFLICT quarantine is the backstop):
  // 1. an ACTIVE queue item already claims this walletRef;
  try {
    const refQueued = await findDuplicateByWalletRef(db, walletRef);
    if (refQueued && refQueued.status !== "failed" && !(refQueued.rpId === rpId && refQueued.credentialId === credentialId)) {
      return Response.json(
        { error: "this publicKey is already being registered under a different credential (walletRef conflict)", walletRef },
        { status: 409 },
      );
    }
  } catch { /* fail-open */ }
  // 2. the walletRef is already on-chain (cache-first; shared with query-by-walletRef).
  try {
    const refCacheKey = cacheKey_("query", "walletRef", walletRef);
    const refCached = cacheGet<{ rpId?: string; credentialId?: string }>(refCacheKey);
    let refHolder = refCached && refCached !== NOT_FOUND ? refCached : null;
    if (!refHolder && refCached !== NOT_FOUND) {
      refHolder = await getPublicKeyByWalletRef(walletRef);
      if (refHolder) cacheSet(refCacheKey, refHolder);
    }
    if (refHolder) {
      if (refHolder.rpId === rpId && refHolder.credentialId === credentialId) {
        // Same record — it IS on-chain (the earlier getRecord precheck was
        // skipped or lagging). Idempotent success, like the fast path above.
        cacheSet(cacheKey, refHolder);
        return Response.json({ ...refHolder, status: "done" }, { status: 201 });
      }
      return Response.json(
        { error: "this publicKey is already registered under a different credential (walletRef conflict)", walletRef },
        { status: 409 },
      );
    }
  } catch (err) {
    if (!isDependencyError(err)) throw err;
    log.warn("walletRef conflict precheck skipped: chain unreachable", {
      request_id: requestId, dependency: "rpc", operation: "getRecordByWalletRef", rpId, error_category: err.classified.category,
    });
  }

  // Backpressure + global write cap (bounds gas spend even if per-IP is evaded).
  // DECISION (availability-first, operator requirement): these gates FAIL OPEN
  // on a D1 error — a storage hiccup must NEVER reject a legitimate user's
  // account creation. The residual abuse window is bounded (Gnosis gas is tiny,
  // commit-reveal costs the attacker time) and the skip is logged for
  // visibility instead of failing closed.
  try {
    if (await getActiveQueueDepth(db) >= MAX_ACTIVE_QUEUE_DEPTH || await globalWriteLimitExceeded(db)) {
      log.warn("create shed: backpressure / global write cap", { request_id: requestId, operation: "create", outcome: "shed" });
      return Response.json(
        { error: "service busy, please retry shortly", retryable: true },
        { status: 503, headers: { "Retry-After": "30" } },
      );
    }
  } catch (err) {
    log.warn("write gates skipped: D1 unavailable (fail-open by design)", {
      request_id: requestId, operation: "create", outcome: "gate-skipped", dependency: "d1",
      error: err instanceof Error ? err.message : String(err),
    });
  }

  // Enqueue
  const id = await enqueue(db, { rpId, credentialId, walletRef, publicKey, name, initialCredentialId, metadata, ip });
  return Response.json({ id, status: "pending" }, { status: 202 });
}

export async function handleCreateStatus(req: Request, db: D1Database): Promise<Response> {
  const url = new URL(req.url);
  const id = url.pathname.split("/").pop();
  if (!id) {
    return Response.json({ error: "id is required" }, { status: 400 });
  }

  const item = await getQueueItem(db, id);
  if (!item) {
    return Response.json({ error: "not found" }, { status: 404 });
  }

  if (item.status === "done") {
    return Response.json({
      id: item.id,
      status: item.status,
      rpId: item.rpId,
      credentialId: item.credentialId,
      walletRef: item.walletRef,
      publicKey: item.publicKey,
      name: item.name,
      txHash: item.txHash,
      createdAt: item.createdAt,
    });
  }

  return Response.json({
    id: item.id,
    status: item.status,
    rpId: item.rpId,
    publicKey: item.publicKey,
    name: item.name,
    error: item.error || undefined,
    createdAt: item.createdAt,
  });
}
