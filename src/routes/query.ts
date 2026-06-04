import { getPublicKey, getPublicKeyByWalletRef } from "../contract.ts";
import { cacheGet, cacheSet } from "../cache.ts";
import { findDuplicate } from "../queue.ts";
import { validateStringLength } from "../validation.ts";

const CACHE_HEADERS = { "Cache-Control": "public, max-age=3600" };

export async function handleQuery(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const rpId = url.searchParams.get("rpId");
  const credentialId = url.searchParams.get("credentialId");
  const walletRef = url.searchParams.get("walletRef");

  const lengthError = validateStringLength({ rpId: rpId ?? undefined, credentialId: credentialId ?? undefined, walletRef: walletRef ?? undefined });
  if (lengthError) {
    return Response.json({ error: lengthError }, { status: 400 });
  }

  // Query by walletRef
  if (walletRef) {
    const cacheKey = `query:walletRef:${walletRef}`;
    const cached = cacheGet<object>(cacheKey);
    if (cached) {
      return Response.json(cached, { headers: CACHE_HEADERS });
    }

    const result = await getPublicKeyByWalletRef(walletRef as `0x${string}`);
    if (result) {
      cacheSet(cacheKey, result);
      return Response.json(result, { headers: CACHE_HEADERS });
    }
    return Response.json({ error: "not found" }, { status: 404 });
  }

  // Query by rpId + credentialId (backward compatible)
  if (!rpId || !credentialId) {
    return Response.json({ error: "rpId and credentialId are required (or walletRef)" }, { status: 400 });
  }

  const cacheKey = `query:${rpId}:${credentialId}`;
  const cached = cacheGet<object>(cacheKey);
  if (cached) {
    return Response.json(cached, { headers: CACHE_HEADERS });
  }

  // Try on-chain first
  const result = await getPublicKey(rpId, credentialId);
  if (result) {
    cacheSet(cacheKey, result);
    return Response.json(result, { headers: CACHE_HEADERS });
  }

  // Fallback: check queue for pending/in-progress records
  const queued = findDuplicate(rpId, credentialId);
  if (queued) {
    // Redact credentialId/walletRef/initialCredentialId to prevent front-running
    // Always return publicKey (client needs it)
    return Response.json({
      rpId: queued.rpId,
      publicKey: queued.publicKey,
      name: queued.name,
      metadata: queued.metadata,
      createdAt: queued.createdAt,
      _queue: { id: queued.id, status: queued.status },
    });
  }

  return Response.json({ error: "not found" }, { status: 404 });
}
