import { assertEquals } from "@std/assert/";
import { cacheClear } from "../../shared/cache.ts";
import { initQueue } from "../queue.ts";
import { handleCreate, handleCreateStatus } from "../routes/create.ts";

async function setup() {
  cacheClear();
  await initQueue(":memory:");
}

function makeCreateRequest(body: Record<string, unknown>): Request {
  return new Request("http://localhost/api/create", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

const VALID_BODY = {
  rpId: "example.com",
  credentialId: "cred123",
  // A REAL P-256 point (the curve generator G) — validation now rejects
  // format-valid-but-off-curve keys at the trust boundary.
  publicKey: "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
  name: "Test Key",
};

// --- Missing required fields ---

Deno.test("handleCreate returns 400 when body is not JSON", async () => {
  await setup();
  const req = new Request("http://localhost/api/create", {
    method: "POST",
    body: "not json",
  });
  const res = await handleCreate(req);
  assertEquals(res.status, 400);
});

Deno.test("handleCreate returns 400 when rpId is missing", async () => {
  await setup();
  const res = await handleCreate(makeCreateRequest({ ...VALID_BODY, rpId: undefined }));
  assertEquals(res.status, 400);
});

Deno.test("handleCreate returns 400 when credentialId is missing", async () => {
  await setup();
  const res = await handleCreate(makeCreateRequest({ ...VALID_BODY, credentialId: undefined }));
  assertEquals(res.status, 400);
});

Deno.test("handleCreate returns 400 when publicKey is missing", async () => {
  await setup();
  const res = await handleCreate(makeCreateRequest({ ...VALID_BODY, publicKey: undefined }));
  assertEquals(res.status, 400);
});

Deno.test("handleCreate returns 400 when name is missing", async () => {
  await setup();
  const res = await handleCreate(makeCreateRequest({ ...VALID_BODY, name: undefined }));
  assertEquals(res.status, 400);
});

// --- Input length validation ---

Deno.test("handleCreate returns 400 when rpId exceeds max length", async () => {
  await setup();
  const res = await handleCreate(makeCreateRequest({ ...VALID_BODY, rpId: "a".repeat(254) }));
  assertEquals(res.status, 400);
  const body = await res.json();
  assertEquals(body.error.includes("rpId"), true);
});

Deno.test("handleCreate returns 400 when name exceeds max length", async () => {
  await setup();
  const res = await handleCreate(makeCreateRequest({ ...VALID_BODY, name: "n".repeat(257) }));
  assertEquals(res.status, 400);
  const body = await res.json();
  assertEquals(body.error.includes("name"), true);
});

Deno.test("handleCreate returns 400 when publicKey exceeds max length", async () => {
  await setup();
  const res = await handleCreate(makeCreateRequest({ ...VALID_BODY, publicKey: "0".repeat(131) }));
  assertEquals(res.status, 400);
  const body = await res.json();
  assertEquals(body.error.includes("publicKey"), true);
});

// --- Security: walletRef binding (identity-forgery guard) ---

Deno.test("handleCreate rejects a walletRef that does not match the publicKey", async () => {
  await setup();
  const res = await handleCreate(makeCreateRequest({
    ...VALID_BODY,
    credentialId: "wr-bind-test",
    // valid 32-byte hex, but NOT the address derived from publicKey → forgery attempt
    walletRef: "0x" + "11".repeat(32),
  }));
  assertEquals(res.status, 400);
  const body = await res.json();
  assertEquals(body.error.includes("walletRef"), true);
});

// --- handleCreateStatus ---

Deno.test("handleCreateStatus returns 404 for unknown id", async () => {
  await setup();
  const req = new Request("http://localhost/api/create/nonexistent-id");
  const res = handleCreateStatus(req);
  assertEquals(res.status, 404);
});

Deno.test("handleCreateStatus returns 400 when id is empty", async () => {
  await setup();
  const req = new Request("http://localhost/api/create/");
  const res = handleCreateStatus(req);
  // path.split("/").pop() returns "" → treated as missing
  assertEquals(res.status, 400);
});

// --- P0 regression: negative-cache sentinel must NEVER be served as a record ---
import { cacheSet as _cset, cacheKey as _ckey, NOT_FOUND as _NF, NEGATIVE_TTL_MS as _NTTL } from "../../shared/cache.ts";

Deno.test("handleCreate: a cached NOT_FOUND does NOT short-circuit to 201 — the create is still enqueued", async () => {
  await setup();
  const rpId = "sentinel.test", credentialId = "cred-sentinel";
  // Simulate a prior /api/query that negatively-cached this exact key.
  _cset(_ckey("query", rpId, credentialId), _NF, _NTTL);
  const res = await handleCreate(makeCreateRequest({ ...VALID_BODY, rpId, credentialId }));
  // Must NOT be 201 "done" (that would silently drop the user's account) —
  // either 202 (enqueued) or a 503 if the chain precheck was skipped/busy,
  // but never a fabricated success.
  assertEquals(res.status === 201, false, "sentinel must not be treated as an existing record");
  const body = await res.json();
  assertEquals(body.status === "done", false);
});

// --- walletRef conflict prechecks (the 2026-07-03 production failure class) ---
import { buildWalletRef as _bwr } from "../../shared/wallet-ref.ts";

// Each conflict test uses its own client IP so the per-IP rate limiter (5/min,
// in-memory, shared across tests in this process) never interferes.
let ipSeq = 0;
function makeCreateRequestFromIp(body: Record<string, unknown>): Request {
  ipSeq++;
  return new Request("http://localhost/api/create", {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-real-ip": `10.9.${Math.floor(ipSeq / 250)}.${ipSeq % 250}` },
    body: JSON.stringify(body),
  });
}

// A second REAL P-256 point (2G), distinct from VALID_BODY's generator G.
const SECOND_VALID_KEY = "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1";

Deno.test("handleCreate: same publicKey already ACTIVE in queue under another credential → 409", async () => {
  await setup();
  // First create enqueues (chain prechecks fail-open offline → 202).
  const first = await handleCreate(makeCreateRequestFromIp({ ...VALID_BODY, rpId: "conflict.test", credentialId: "cred-A" }));
  assertEquals(first.status, 202);
  // Same key, different credential → the queue-layer conflict check rejects.
  const second = await handleCreate(makeCreateRequestFromIp({ ...VALID_BODY, rpId: "conflict.test", credentialId: "cred-B" }));
  assertEquals(second.status, 409);
  const body = await second.json();
  assertEquals(typeof body.error, "string");
  assertEquals(body.walletRef, _bwr(VALID_BODY.publicKey));
});

Deno.test("handleCreate: exact duplicate (same rpId+credentialId) still returns 202 idempotently, not 409", async () => {
  await setup();
  const first = await handleCreate(makeCreateRequestFromIp({ ...VALID_BODY, rpId: "dup.test", credentialId: "cred-same" }));
  assertEquals(first.status, 202);
  const again = await handleCreate(makeCreateRequestFromIp({ ...VALID_BODY, rpId: "dup.test", credentialId: "cred-same" }));
  assertEquals(again.status, 202, "identical retry is idempotent, not a conflict");
});

Deno.test("handleCreate: walletRef already on-chain under another credential (cached) → 409", async () => {
  await setup();
  const ref = _bwr(SECOND_VALID_KEY);
  // Simulate a prior query that cached the on-chain holder of this walletRef.
  _cset(_ckey("query", "walletRef", ref), { rpId: "other.example", credentialId: "cred-other" });
  const res = await handleCreate(makeCreateRequestFromIp({ ...VALID_BODY, publicKey: SECOND_VALID_KEY, rpId: "chain-conflict.test", credentialId: "cred-new" }));
  assertEquals(res.status, 409);
});

Deno.test("handleCreate: cached walletRef holder matching THIS record → 201 done (idempotent)", async () => {
  await setup();
  const ref = _bwr(SECOND_VALID_KEY);
  const record = { rpId: "same.example", credentialId: "cred-same", publicKey: SECOND_VALID_KEY, name: "n" };
  _cset(_ckey("query", "walletRef", ref), record);
  const res = await handleCreate(makeCreateRequestFromIp({ ...VALID_BODY, publicKey: SECOND_VALID_KEY, rpId: "same.example", credentialId: "cred-same" }));
  assertEquals(res.status, 201);
  const body = await res.json();
  assertEquals(body.status, "done");
});

Deno.test("handleCreate: cached NOT_FOUND for the walletRef → precheck passes, create enqueued (202)", async () => {
  await setup();
  const ref = _bwr(SECOND_VALID_KEY);
  _cset(_ckey("query", "walletRef", ref), _NF, _NTTL);
  const res = await handleCreate(makeCreateRequestFromIp({ ...VALID_BODY, publicKey: SECOND_VALID_KEY, rpId: "negcache.test", credentialId: "cred-neg" }));
  assertEquals(res.status, 202, "negative cache must not block (and must not 409) a legitimate create");
});
