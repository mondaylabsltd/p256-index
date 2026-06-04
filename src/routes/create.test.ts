import { assertEquals } from "@std/assert/";
import { cacheClear } from "../cache.ts";
import { initQueue } from "../queue.ts";
import { handleCreate, handleCreateStatus } from "./create.ts";

function setup() {
  cacheClear();
  initQueue(":memory:");
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
  publicKey: "04" + "aa".repeat(64),
  name: "Test Key",
};

// --- Missing required fields ---

Deno.test("handleCreate returns 400 when body is not JSON", async () => {
  setup();
  const req = new Request("http://localhost/api/create", {
    method: "POST",
    body: "not json",
  });
  const res = await handleCreate(req);
  assertEquals(res.status, 400);
});

Deno.test("handleCreate returns 400 when rpId is missing", async () => {
  setup();
  const res = await handleCreate(makeCreateRequest({ ...VALID_BODY, rpId: undefined }));
  assertEquals(res.status, 400);
});

Deno.test("handleCreate returns 400 when credentialId is missing", async () => {
  setup();
  const res = await handleCreate(makeCreateRequest({ ...VALID_BODY, credentialId: undefined }));
  assertEquals(res.status, 400);
});

Deno.test("handleCreate returns 400 when publicKey is missing", async () => {
  setup();
  const res = await handleCreate(makeCreateRequest({ ...VALID_BODY, publicKey: undefined }));
  assertEquals(res.status, 400);
});

Deno.test("handleCreate returns 400 when name is missing", async () => {
  setup();
  const res = await handleCreate(makeCreateRequest({ ...VALID_BODY, name: undefined }));
  assertEquals(res.status, 400);
});

// --- Input length validation ---

Deno.test("handleCreate returns 400 when rpId exceeds max length", async () => {
  setup();
  const res = await handleCreate(makeCreateRequest({ ...VALID_BODY, rpId: "a".repeat(254) }));
  assertEquals(res.status, 400);
  const body = await res.json();
  assertEquals(body.error.includes("rpId"), true);
});

Deno.test("handleCreate returns 400 when name exceeds max length", async () => {
  setup();
  const res = await handleCreate(makeCreateRequest({ ...VALID_BODY, name: "n".repeat(257) }));
  assertEquals(res.status, 400);
  const body = await res.json();
  assertEquals(body.error.includes("name"), true);
});

Deno.test("handleCreate returns 400 when publicKey exceeds max length", async () => {
  setup();
  const res = await handleCreate(makeCreateRequest({ ...VALID_BODY, publicKey: "0".repeat(131) }));
  assertEquals(res.status, 400);
  const body = await res.json();
  assertEquals(body.error.includes("publicKey"), true);
});

// --- handleCreateStatus ---

Deno.test("handleCreateStatus returns 404 for unknown id", () => {
  setup();
  const req = new Request("http://localhost/api/create/nonexistent-id");
  const res = handleCreateStatus(req);
  assertEquals(res.status, 404);
});

Deno.test("handleCreateStatus returns 400 when id is empty", () => {
  setup();
  const req = new Request("http://localhost/api/create/");
  const res = handleCreateStatus(req);
  // path.split("/").pop() returns "" → treated as missing
  assertEquals(res.status, 400);
});
