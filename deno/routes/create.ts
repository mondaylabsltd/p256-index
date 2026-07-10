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

const MAX_BODY_SIZE = 32 * 1024; // 32KB

export async function handleCreate(req: Request, requestId?: string): Promise<Response> {
  // Reject oversized bodies before parsing
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

  // Rate limit by IP (hashed for GDPR). Prefer cf-connecting-ip (set by
  // Cloudflare, not client-spoofable) when fronted by CF; x-forwarded-for[0] is
  // client-controlled and only a best-effort fairness signal. The global write
  // cap below is the real, spoof-proof bound on gas spend.
  const ip = req.headers.get("cf-connecting-ip")
    || req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || req.headers.get("x-real-ip")
    || "unknown";
  if (!await checkRateLimit(ip)) {
    return Response.json({ error: "rate limit exceeded, max 5 requests per minute" }, { status: 429 });
  }

  const initialCredentialId = body.initialCredentialId || credentialId;
  const publicKeyHex = (publicKey.startsWith("0x") ? publicKey : `0x${publicKey}`) as `0x${string}`;
  // walletRef is BOUND to the publicKey: it must be the deterministically-derived
  // Safe address. A client may omit it (we derive) or send it (must match) — it
  // can never claim an arbitrary/victim address (identity forgery / squatting),
  // since query-by-walletRef returns this record's publicKey.
  const walletRef = buildWalletRef(publicKey);
  if (body.walletRef && body.walletRef.toLowerCase() !== walletRef.toLowerCase()) {
    return Response.json({ error: "walletRef does not match publicKey" }, { status: 400 });
  }
  const metadata = body.metadata || encodeAbiParameters(
    [{ type: "string" }, { type: "bytes" }],
    ["VelaWalletV1", publicKeyHex],
  );

  // Already exists on-chain — return success (idempotent). MUST exclude the
  // negative-cache sentinel: a cached "not found" is NOT a record, and
  // spreading it into a 201 "done" body would silently DROP the user's create
  // (they'd think the account exists when nothing was ever enqueued).
  const cacheKey = cacheKey_("query", rpId, credentialId);
  const cached = cacheGet<object>(cacheKey);
  if (cached && cached !== NOT_FOUND) {
    return Response.json({ ...cached, status: "done" }, { status: 201 });
  }
  // The on-chain precheck is only a fast-path optimization (return 201 if the
  // record already exists). If the chain is transiently unreachable we MUST NOT
  // fail the create — we fall through to enqueue, and the background worker's
  // hasRecord reconciliation safely converges (marks done if already on-chain).
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
  const queued = findDuplicate(rpId, credentialId);
  if (queued && queued.status !== "failed") {
    return Response.json({ id: queued.id, status: queued.status }, { status: 202 });
  }

  // walletRef conflict precheck: the SAME P256 key registered under a DIFFERENT
  // credential deterministically reverts on-chain (WalletRefAlreadyExists) —
  // after burning commit gas and quarantining to the DLQ. Reject it up-front
  // with an actionable 409 instead. Two layers, both fail-open (a check hiccup
  // must never block a legitimate create — the engine's CONFLICT quarantine is
  // the backstop):
  // 1. an ACTIVE queue item already claims this walletRef;
  try {
    const refQueued = findDuplicateByWalletRef(walletRef);
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

  // Backpressure + global write cap: shed genuinely-new work when the active
  // queue is dangerously deep OR the global create rate (across ALL clients) is
  // at the cap. The latter bounds worst-case gas spend even if the per-IP limit
  // is evaded. Fail-open on a stats hiccup (never block a create on a count error).
  try {
    if (getActiveQueueDepth() >= MAX_ACTIVE_QUEUE_DEPTH || globalWriteLimitExceeded()) {
      log.warn("create shed: backpressure / global write cap", { request_id: requestId, operation: "create", outcome: "shed" });
      return Response.json(
        { error: "service busy, please retry shortly", retryable: true },
        { status: 503, headers: { "Retry-After": "30" } },
      );
    }
  } catch { /* stats unavailable — allow the create */ }

  // Enqueue
  const id = await enqueue({ rpId, credentialId, walletRef, publicKey, name, initialCredentialId, metadata, ip });
  return Response.json({ id, status: "pending" }, { status: 202 });
}

export function handleCreateStatus(req: Request): Response {
  const url = new URL(req.url);
  const id = url.pathname.split("/").pop();
  if (!id) {
    return Response.json({ error: "id is required" }, { status: 400 });
  }

  const item = getQueueItem(id);
  if (!item) {
    return Response.json({ error: "not found" }, { status: 404 });
  }

  // Only expose full data after on-chain (done/failed), redact during commit-reveal to prevent front-running
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
