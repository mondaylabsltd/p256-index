import { assertEquals, assertThrows, assert } from "@std/assert/";
import { initConfig, isValidPrivateKey } from "../config.ts";

// Regression: initConfig() fails fast on a malformed PRIVATE_KEY instead of
// letting deriveCommitKey throw an opaque TypeError (on '0x' / odd length) or —
// worse — silently derive a WRONG commit wallet when a non-hex char makes
// parseInt() return NaN (coerced to 0 in the Uint8Array).

Deno.test("isValidPrivateKey accepts a well-formed 0x 32-byte key", () => {
  assertEquals(isValidPrivateKey("0x" + "a".repeat(64)), true);
  assertEquals(isValidPrivateKey("0x" + "0123456789abcdef".repeat(4)), true);
  assertEquals(isValidPrivateKey("0x" + "ABCDEF".padEnd(64, "0")), true);
});

Deno.test("isValidPrivateKey rejects malformed keys that would corrupt the commit wallet", () => {
  assertEquals(isValidPrivateKey("0x"), false);                       // empty → TypeError in derive
  assertEquals(isValidPrivateKey("0x" + "a".repeat(63)), false);      // odd length → dropped nibble
  assertEquals(isValidPrivateKey("0x" + "a".repeat(65)), false);      // too long
  assertEquals(isValidPrivateKey("0x" + "z".repeat(64)), false);      // non-hex → NaN → 0 silently
  assertEquals(isValidPrivateKey("a".repeat(64)), false);             // missing 0x prefix
  assertEquals(isValidPrivateKey("0xZZ" + "a".repeat(60)), false);    // partial non-hex
});

// Pin the ACTUAL fail-fast behavior (not just the predicate): initConfig must
// THROW on a malformed key rather than crash later in deriveCommitKey or silently
// derive a wrong commit wallet. Restores PRIVATE_KEY in a finally so it never
// leaks into the PRIVATE_KEY-gated e2e/stress suites.
Deno.test("initConfig throws fast on a malformed PRIVATE_KEY", () => {
  const prev = Deno.env.get("PRIVATE_KEY");
  try {
    Deno.env.set("PRIVATE_KEY", "0x" + "z".repeat(64)); // non-hex → would silently become 0-bytes
    assertThrows(() => initConfig(), Error, "Invalid PRIVATE_KEY");
    Deno.env.set("PRIVATE_KEY", "0x1234"); // too short
    assertThrows(() => initConfig(), Error, "Invalid PRIVATE_KEY");
  } finally {
    if (prev === undefined) Deno.env.delete("PRIVATE_KEY");
    else Deno.env.set("PRIVATE_KEY", prev);
  }
});

Deno.test("initConfig accepts a valid key and derives a well-formed commit wallet", () => {
  const prev = Deno.env.get("PRIVATE_KEY");
  try {
    Deno.env.set("PRIVATE_KEY", "0x" + "11".repeat(32));
    const cfg = initConfig();
    assert(/^0x[0-9a-f]{64}$/.test(cfg.commitPrivateKey), "commit key must be a valid derived 0x 32-byte key");
    assertEquals(cfg.commitPrivateKey === cfg.privateKey, false, "commit wallet must differ from create wallet");
  } finally {
    if (prev === undefined) Deno.env.delete("PRIVATE_KEY");
    else Deno.env.set("PRIVATE_KEY", prev);
  }
});
