import { listRpIds, listPublicKeysByRpId, getTotalCredentials } from "../contract-read.ts";
import { cacheGet, cacheSet } from "../cache.ts";
import { validateStringLength } from "../validation.ts";

const CACHE_HEADERS = { "Cache-Control": "public, max-age=3600" };

function parsePagination(url: URL) {
  const page = Math.max(1, parseInt(url.searchParams.get("page") || "1", 10) || 1);
  const pageSize = Math.min(100, Math.max(1, parseInt(url.searchParams.get("pageSize") || "20", 10) || 20));
  const order = url.searchParams.get("order") === "asc" ? "asc" as const : "desc" as const;
  return { page, pageSize, order };
}

export async function handleListRpIds(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const { page, pageSize, order } = parsePagination(url);

  const cacheKey = `stats:rpIds:${page}:${pageSize}:${order}`;
  const cached = cacheGet<object>(cacheKey);
  if (cached) {
    return Response.json(cached, { headers: CACHE_HEADERS });
  }

  const result = await listRpIds(page, pageSize, order);
  if (result.items.length > 0) {
    cacheSet(cacheKey, result);
  }
  return Response.json(result, { headers: result.items.length > 0 ? CACHE_HEADERS : undefined });
}

export async function handleTotalCredentials(): Promise<Response> {
  const cacheKey = "stats:totalCredentials";
  const cached = cacheGet<object>(cacheKey);
  if (cached) {
    return Response.json(cached, { headers: CACHE_HEADERS });
  }

  const total = await getTotalCredentials();
  const result = { totalCredentials: total };
  cacheSet(cacheKey, result);
  return Response.json(result, { headers: CACHE_HEADERS });
}

export async function handleListPublicKeys(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const rpId = url.searchParams.get("rpId");

  if (!rpId) {
    return Response.json({ error: "rpId is required" }, { status: 400 });
  }
  const lengthError = validateStringLength({ rpId });
  if (lengthError) {
    return Response.json({ error: lengthError }, { status: 400 });
  }

  const { page, pageSize, order } = parsePagination(url);

  const cacheKey = `stats:keys:${rpId}:${page}:${pageSize}:${order}`;
  const cached = cacheGet<object>(cacheKey);
  if (cached) {
    return Response.json(cached, { headers: CACHE_HEADERS });
  }

  const result = await listPublicKeysByRpId(rpId, page, pageSize, order);
  if (result.items.length > 0) {
    cacheSet(cacheKey, result);
  }
  return Response.json(result, { headers: result.items.length > 0 ? CACHE_HEADERS : undefined });
}
