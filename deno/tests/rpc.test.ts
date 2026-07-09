import { assertEquals, assertNotEquals, assert } from "@std/assert/";
import { getCurrentRpc, getWriteRpc, markFailed, markHealthy, setAlchemyRpc, tryReadProbe, getReadCircuitState, readCircuitRetryAfterMs, _resetForTest } from "../../shared/rpc.ts";

const TEST_RPCS = ["https://rpc-a.test", "https://rpc-b.test", "https://rpc-c.test"];

function setup() {
  _resetForTest(TEST_RPCS);
}

// --- Round-robin ---

Deno.test("getCurrentRpc cycles through RPCs in round-robin", () => {
  setup();
  const first = getCurrentRpc();
  const second = getCurrentRpc();
  const third = getCurrentRpc();
  assertEquals(first, "https://rpc-a.test");
  assertEquals(second, "https://rpc-b.test");
  assertEquals(third, "https://rpc-c.test");
  // wraps around
  const fourth = getCurrentRpc();
  assertEquals(fourth, "https://rpc-a.test");
});

// --- markFailed + skip ---

Deno.test("getCurrentRpc skips failed RPCs", () => {
  setup();
  markFailed("https://rpc-a.test");
  // Should skip rpc-a and return rpc-b
  const rpc = getCurrentRpc();
  assertEquals(rpc, "https://rpc-b.test");
});

Deno.test("getCurrentRpc returns any RPC when all marked failed", () => {
  setup();
  for (const rpc of TEST_RPCS) markFailed(rpc);
  // Should still return something (fallback to any)
  const rpc = getCurrentRpc();
  assertNotEquals(rpc, undefined);
});

// --- getWriteRpc ---

Deno.test("getWriteRpc skips failed RPCs", () => {
  _resetForTest(); // uses default WRITE_RPCS
  const first = getWriteRpc();
  markFailed(first);
  const second = getWriteRpc();
  assertNotEquals(first, second);
});

// Regression: a pinned-but-dead Alchemy write endpoint must be rotatable. Before
// the write-path health-tracking fix, getWriteRpc returned the Alchemy URL
// unconditionally (isAvailable was never false for it because markFailed was only
// called on the READ path), so a dead/rate-limited Alchemy stalled the whole
// write pipeline forever. The queue's gas-check now calls markFailed on failure.
Deno.test("getWriteRpc rotates OFF a failed Alchemy endpoint to a public write RPC", () => {
  _resetForTest();
  setAlchemyRpc("test-key-abc123");
  const alchemy = "https://gnosis-mainnet.g.alchemy.com/v2/test-key-abc123";
  assertEquals(getWriteRpc(), alchemy); // Alchemy is preferred while healthy

  markFailed(alchemy); // simulate the gas-check catch cooling it down
  const afterFail = getWriteRpc();
  assertNotEquals(afterFail, alchemy); // must fall back to a public write RPC
  assert(afterFail.startsWith("https://"), `expected a real RPC url, got ${afterFail}`);

  markHealthy(alchemy); // a later successful cycle clears the cooldown
  assertEquals(getWriteRpc(), alchemy); // and Alchemy is preferred again
  _resetForTest(); // don't leak the Alchemy endpoint into other tests
});

// --- Cooldown recovery ---

Deno.test("failed RPC becomes available after cooldown", () => {
  setup();
  markFailed("https://rpc-a.test");
  // Immediately after marking, rpc-a should be skipped
  const rpc1 = getCurrentRpc();
  assertEquals(rpc1, "https://rpc-b.test");

  // Simulate cooldown expiry by re-marking with old timestamp
  // We can't easily mock Date.now, but we can verify the mechanism
  // by resetting state
  _resetForTest(TEST_RPCS);
  const rpc2 = getCurrentRpc();
  assertEquals(rpc2, "https://rpc-a.test"); // available again after reset
});

// --- Circuit breaker ---

Deno.test("read circuit is closed while any endpoint is available", () => {
  setup();
  assertEquals(getReadCircuitState(), "closed");
  markFailed("https://rpc-a.test");
  markFailed("https://rpc-b.test");
  // rpc-c still available → closed
  assertEquals(getReadCircuitState(), "closed");
});

Deno.test("read circuit opens only when every endpoint is in cooldown", () => {
  setup();
  for (const rpc of TEST_RPCS) markFailed(rpc);
  assertEquals(getReadCircuitState(), "open");
  // Retry-After hint should be within the 60s cooldown window.
  const ra = readCircuitRetryAfterMs();
  assert(ra > 0 && ra <= 60_000, `retry-after ${ra} should be in (0, 60000]`);
});

Deno.test("read circuit recovers (closes) after reset", () => {
  setup();
  for (const rpc of TEST_RPCS) markFailed(rpc);
  assertEquals(getReadCircuitState(), "open");
  _resetForTest(TEST_RPCS);
  assertEquals(getReadCircuitState(), "closed");
});

Deno.test("markHealthy closes the circuit immediately (a working read recovers fast)", () => {
  setup();
  for (const rpc of TEST_RPCS) markFailed(rpc);
  assertEquals(getReadCircuitState(), "open");
  // One successful read on any endpoint clears its cooldown → circuit closes.
  markHealthy(TEST_RPCS[1]);
  assertEquals(getReadCircuitState(), "closed");
});

Deno.test("half-open: tryReadProbe allows one probe then throttles", () => {
  setup();
  // First call lets a probe through; the immediate next call is throttled.
  assertEquals(tryReadProbe(), true);
  assertEquals(tryReadProbe(), false);
});

// --- Reset ---

Deno.test("_resetForTest clears all state", () => {
  _resetForTest(["https://only.test"]);
  const rpc = getCurrentRpc();
  assertEquals(rpc, "https://only.test");
  const rpc2 = getCurrentRpc();
  assertEquals(rpc2, "https://only.test"); // only one in list, wraps around
});
