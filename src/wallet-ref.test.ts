import { assertEquals, assert } from "@std/assert/";
import { buildWalletRef } from "./wallet-ref.ts";

/** Generate a real P256 uncompressed public key (04 + x + y, 65 bytes = 130 hex chars). */
async function generateP256PublicKeyHex(): Promise<string> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  return Array.from(raw).map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.test("buildWalletRef returns valid bytes32 hex", async () => {
  const publicKey = await generateP256PublicKeyHex();
  const walletRef = buildWalletRef(publicKey);

  // Must be 0x + 64 hex chars (32 bytes)
  assert(walletRef.startsWith("0x"), "should start with 0x");
  assertEquals(walletRef.length, 66, "bytes32 = 66 chars including 0x prefix");
  assert(/^0x[0-9a-f]{64}$/.test(walletRef), "should be valid lowercase hex");
});

Deno.test("buildWalletRef is deterministic for same key", async () => {
  const publicKey = await generateP256PublicKeyHex();
  const ref1 = buildWalletRef(publicKey);
  const ref2 = buildWalletRef(publicKey);
  assertEquals(ref1, ref2);
});

Deno.test("buildWalletRef produces different refs for different keys", async () => {
  const pk1 = await generateP256PublicKeyHex();
  const pk2 = await generateP256PublicKeyHex();
  const ref1 = buildWalletRef(pk1);
  const ref2 = buildWalletRef(pk2);
  assert(ref1 !== ref2, "different keys should produce different walletRefs");
});

Deno.test("buildWalletRef handles 0x prefix", async () => {
  const publicKey = await generateP256PublicKeyHex();
  const withPrefix = buildWalletRef("0x" + publicKey);
  const without = buildWalletRef(publicKey);
  assertEquals(withPrefix, without, "0x prefix should not change result");
});

Deno.test("buildWalletRef embeds an address in last 20 bytes", async () => {
  const publicKey = await generateP256PublicKeyHex();
  const walletRef = buildWalletRef(publicKey);
  // bytes32(uint256(uint160(address))) — first 12 bytes should be zero-padded
  const hex = walletRef.slice(2);
  assertEquals(hex.slice(0, 24), "0".repeat(24), "first 12 bytes should be zero (left-padded address)");
  // Last 20 bytes (40 hex chars) should be non-zero (an address)
  const addressPart = hex.slice(24);
  assert(addressPart !== "0".repeat(40), "address part should be non-zero");
});
