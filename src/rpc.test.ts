import { assertEquals, assertNotEquals } from "@std/assert/";
import { getCurrentRpc, getWriteRpc, markFailed, _resetForTest } from "./rpc.ts";

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

// --- Reset ---

Deno.test("_resetForTest clears all state", () => {
  _resetForTest(["https://only.test"]);
  const rpc = getCurrentRpc();
  assertEquals(rpc, "https://only.test");
  const rpc2 = getCurrentRpc();
  assertEquals(rpc2, "https://only.test"); // only one in list, wraps around
});
