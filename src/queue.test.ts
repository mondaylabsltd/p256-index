import { assertEquals, assert } from "@std/assert/";
import { initQueue, enqueue, getQueueItem, findDuplicate, checkRateLimit } from "./queue.ts";

function setup() {
  initQueue(":memory:");
}

// --- Enqueue + retrieve ---

Deno.test("enqueue creates item and getQueueItem retrieves it", async () => {
  setup();
  const id = await enqueue({
    rpId: "example.com",
    credentialId: "cred1",
    walletRef: "0x" + "ab".repeat(32),
    publicKey: "04" + "aa".repeat(64),
    name: "Test Key",
    initialCredentialId: "cred1",
    metadata: "0x00",
    ip: "127.0.0.1",
  });
  const item = getQueueItem(id);
  assert(item !== null);
  assertEquals(item!.rpId, "example.com");
  assertEquals(item!.credentialId, "cred1");
  assertEquals(item!.status, "pending");
  assertEquals(item!.name, "Test Key");
  assert(item!.createdAt > 0);
});

Deno.test("getQueueItem returns null for unknown id", () => {
  setup();
  assertEquals(getQueueItem("nonexistent"), null);
});

// --- findDuplicate ---

Deno.test("findDuplicate finds existing item", async () => {
  setup();
  await enqueue({
    rpId: "site.com", credentialId: "c1", walletRef: "0x00", publicKey: "04aa",
    name: "k", initialCredentialId: "c1", metadata: "0x", ip: "1.2.3.4",
  });
  const dup = findDuplicate("site.com", "c1");
  assert(dup !== null);
  assertEquals(dup!.rpId, "site.com");
});

Deno.test("findDuplicate returns null when not found", () => {
  setup();
  assertEquals(findDuplicate("nosite.com", "c999"), null);
});

// --- IP hashing in enqueue ---

Deno.test("enqueue stores hashed IP, not raw", async () => {
  setup();
  const id = await enqueue({
    rpId: "x.com", credentialId: "c", walletRef: "0x", publicKey: "04",
    name: "k", initialCredentialId: "c", metadata: "0x", ip: "192.168.1.1",
  });
  const item = getQueueItem(id);
  assert(item !== null);
  // IP should be a hex hash prefix, not the raw IP
  assertNotEquals(item!.ip, "192.168.1.1");
  assert(item!.ip.length === 16); // SHA-256 hash truncated to 16 hex chars
});

// --- Rate limiting ---

Deno.test("checkRateLimit allows up to 5 requests per IP", async () => {
  setup();
  const ip = "10.0.0.1";
  for (let i = 0; i < 5; i++) {
    assertEquals(await checkRateLimit(ip), true, `request ${i + 1} should pass`);
  }
  assertEquals(await checkRateLimit(ip), false, "6th request should be blocked");
});

Deno.test("checkRateLimit tracks different IPs independently", async () => {
  setup();
  // Fill up ip-a
  for (let i = 0; i < 5; i++) await checkRateLimit("ip-a");
  assertEquals(await checkRateLimit("ip-a"), false);
  // ip-b should still be allowed
  assertEquals(await checkRateLimit("ip-b"), true);
});

// --- Import not-equals separately ---
import { assertNotEquals } from "@std/assert/";
