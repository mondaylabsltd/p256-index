import { assertEquals, assert } from "@std/assert/";
import { acquireNonce, resetNonce, isNonceError } from "./nonce.ts";

// --- isNonceError ---

Deno.test("isNonceError matches 'nonce too low'", () => {
  assertEquals(isNonceError(new Error("nonce too low")), true);
});

Deno.test("isNonceError matches 'nonce has already been used'", () => {
  assertEquals(isNonceError(new Error("nonce has already been used")), true);
});

Deno.test("isNonceError matches 'replacement transaction underpriced'", () => {
  assertEquals(isNonceError(new Error("replacement transaction underpriced")), true);
});

Deno.test("isNonceError matches 'already known'", () => {
  assertEquals(isNonceError(new Error("already known")), true);
});

Deno.test("isNonceError returns false for unrelated error", () => {
  assertEquals(isNonceError(new Error("out of gas")), false);
});

Deno.test("isNonceError handles non-Error input", () => {
  assertEquals(isNonceError("nonce too low"), true);
  assertEquals(isNonceError(42), false);
  assertEquals(isNonceError(null), false);
});

// --- resetNonce ---

Deno.test("resetNonce does not throw", () => {
  resetNonce();
  resetNonce(); // double reset is safe
});

// --- acquireNonce serialization ---
// Note: acquireNonce depends on a live RPC to fetch on-chain nonce.
// We test serialization by calling resetNonce + multiple acquireNonce calls
// to verify they return sequential values (requires PRIVATE_KEY to be set).
// When PRIVATE_KEY is not set, acquireNonce will throw — we test that case.

Deno.test("acquireNonce throws when PRIVATE_KEY is not set", async () => {
  resetNonce();
  try {
    await acquireNonce();
    assert(false, "should have thrown");
  } catch (err) {
    assert(err instanceof Error);
    assert(err.message.includes("PRIVATE_KEY") || err.message.includes("Config not initialized"));
  }
});
