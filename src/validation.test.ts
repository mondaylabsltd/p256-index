import { assertEquals } from "@std/assert/";
import { validateStringLength } from "./validation.ts";

Deno.test("validateStringLength passes valid inputs", () => {
  assertEquals(validateStringLength({
    rpId: "example.com",
    credentialId: "abc123",
    publicKey: "04" + "aa".repeat(64),
    name: "My Key",
  }), null);
});

Deno.test("validateStringLength passes when fields are undefined", () => {
  assertEquals(validateStringLength({
    rpId: "example.com",
    walletRef: undefined,
    metadata: undefined,
  }), null);
});

Deno.test("validateStringLength rejects oversized rpId", () => {
  const result = validateStringLength({ rpId: "a".repeat(254) });
  assertEquals(typeof result, "string");
  assertEquals(result!.includes("rpId"), true);
});

Deno.test("validateStringLength rejects oversized credentialId", () => {
  const result = validateStringLength({ credentialId: "x".repeat(1025) });
  assertEquals(typeof result, "string");
  assertEquals(result!.includes("credentialId"), true);
});

Deno.test("validateStringLength rejects oversized publicKey", () => {
  const result = validateStringLength({ publicKey: "0".repeat(131) });
  assertEquals(typeof result, "string");
  assertEquals(result!.includes("publicKey"), true);
});

Deno.test("validateStringLength rejects oversized name", () => {
  const result = validateStringLength({ name: "n".repeat(257) });
  assertEquals(typeof result, "string");
  assertEquals(result!.includes("name"), true);
});

Deno.test("validateStringLength rejects oversized walletRef", () => {
  const result = validateStringLength({ walletRef: "0x" + "f".repeat(65) });
  assertEquals(typeof result, "string");
  assertEquals(result!.includes("walletRef"), true);
});

Deno.test("validateStringLength rejects oversized metadata", () => {
  const result = validateStringLength({ metadata: "0x" + "ff".repeat(2048) });
  assertEquals(typeof result, "string");
  assertEquals(result!.includes("metadata"), true);
});

Deno.test("validateStringLength accepts values at exact limit", () => {
  assertEquals(validateStringLength({ rpId: "a".repeat(253) }), null);
  assertEquals(validateStringLength({ name: "n".repeat(256) }), null);
});
