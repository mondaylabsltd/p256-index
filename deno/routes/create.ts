import { getPublicKey } from "../../shared/contract-read.ts";
import { enqueue, findDuplicate, getQueueItem, checkRateLimit } from "../queue.ts";
import { encodeAbiParameters } from "viem";
import { buildWalletRef } from "../../shared/wallet-ref.ts";
import { cacheGet, cacheSet } from "../../shared/cache.ts";
import { validateStringLength } from "../../shared/validation.ts";

const MAX_BODY_SIZE = 32 * 1024; // 32KB

export async function handleCreate(req: Request): Promise<Response> {
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

  try {
    const text = await req.text();
    if (text.length > MAX_BODY_SIZE) {
      return Response.json({ error: "request body too large" }, { status: 413 });
    }
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

  // Rate limit by IP (hashed for GDPR)
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || req.headers.get("x-real-ip")
    || "unknown";
  if (!await checkRateLimit(ip)) {
    return Response.json({ error: "rate limit exceeded, max 5 requests per minute" }, { status: 429 });
  }

  const initialCredentialId = body.initialCredentialId || credentialId;
  const publicKeyHex = (publicKey.startsWith("0x") ? publicKey : `0x${publicKey}`) as `0x${string}`;
  // walletRef: optional, default to Safe address derived from publicKey
  const walletRef = body.walletRef || buildWalletRef(publicKey);
  const metadata = body.metadata || encodeAbiParameters(
    [{ type: "string" }, { type: "bytes" }],
    ["VelaWalletV1", publicKeyHex],
  );

  // Already exists on-chain — return success (idempotent)
  const cacheKey = `query:${rpId}:${credentialId}`;
  const cached = cacheGet<object>(cacheKey);
  if (cached) {
    return Response.json({ ...cached, status: "done" }, { status: 201 });
  }
  const existing = await getPublicKey(rpId, credentialId);
  if (existing) {
    cacheSet(cacheKey, existing);
    return Response.json({ ...existing, status: "done" }, { status: 201 });
  }

  // Check if already in queue
  const queued = findDuplicate(rpId, credentialId);
  if (queued && queued.status !== "failed") {
    return Response.json({ id: queued.id, status: queued.status }, { status: 202 });
  }

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
