import { assert } from "@std/assert/";
import { acquireNonce, resetNonce } from "./nonce.ts";

// --- resetNonce ---

Deno.test("resetNonce does not throw", () => {
  resetNonce();
  resetNonce(); // double reset is safe
});

// --- acquireNonce ---

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
