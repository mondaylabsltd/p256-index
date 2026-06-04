import { assertEquals, assert } from "@std/assert/";
import { cacheGet, cacheSet, cacheClear, cacheSize, cacheMemoryUsage, _configureForTest, _resetConfigForTest } from "./cache.ts";

function setup() {
  cacheClear();
  _resetConfigForTest();
}

Deno.test("cacheGet returns undefined for missing key", () => {
  setup();
  assertEquals(cacheGet("missing"), undefined);
});

Deno.test("cacheSet and cacheGet round-trip", () => {
  setup();
  cacheSet("key1", { data: "hello" });
  assertEquals(cacheGet("key1"), { data: "hello" });
});

Deno.test("cacheClear removes all entries", () => {
  setup();
  cacheSet("a", 1);
  cacheSet("b", 2);
  cacheClear();
  assertEquals(cacheSize(), 0);
});

Deno.test("cacheSize returns correct count", () => {
  setup();
  assertEquals(cacheSize(), 0);
  cacheSet("a", 1);
  cacheSet("b", 2);
  assertEquals(cacheSize(), 2);
});

// --- Memory usage & eviction ---

Deno.test("cacheMemoryUsage tracks size", () => {
  setup();
  assertEquals(cacheMemoryUsage(), 0);
  cacheSet("k1", { data: "hello" });
  assert(cacheMemoryUsage() > 0);
});

Deno.test("cacheMemoryUsage resets after cacheClear", () => {
  setup();
  cacheSet("k1", { data: "hello" });
  cacheClear();
  assertEquals(cacheMemoryUsage(), 0);
});

Deno.test("cacheSet overwrites existing key and updates size", () => {
  setup();
  cacheSet("k1", "short");
  const size1 = cacheMemoryUsage();
  cacheSet("k1", "a much longer string value here");
  const size2 = cacheMemoryUsage();
  assert(size2 > size1);
  assertEquals(cacheSize(), 1);
});

// --- TTL expiry ---

Deno.test("cacheGet returns undefined after TTL expires", async () => {
  setup();
  _configureForTest({ ttl: 50 }); // 50ms TTL
  cacheSet("ttl-key", "value");
  assertEquals(cacheGet("ttl-key"), "value"); // still valid
  await new Promise((r) => setTimeout(r, 60));
  assertEquals(cacheGet("ttl-key"), undefined); // expired
});

Deno.test("expired entry is removed from store on access", async () => {
  setup();
  _configureForTest({ ttl: 50 });
  cacheSet("exp", "data");
  assertEquals(cacheSize(), 1);
  await new Promise((r) => setTimeout(r, 60));
  cacheGet("exp"); // triggers cleanup
  assertEquals(cacheSize(), 0);
  assertEquals(cacheMemoryUsage(), 0);
});

// --- Memory eviction ---

Deno.test("eviction removes oldest entries when memory limit exceeded", () => {
  setup();
  _configureForTest({ maxBytes: 100 }); // very low limit
  // Insert entries until we exceed the limit
  for (let i = 0; i < 20; i++) {
    cacheSet(`evict-${i}`, { data: "x".repeat(10) });
  }
  // Oldest entries should have been evicted
  assert(cacheMemoryUsage() <= 100);
  // Some entries exist but not all 20
  assert(cacheSize() < 20);
  assert(cacheSize() > 0);
});

Deno.test("eviction preserves most recent entries", () => {
  setup();
  _configureForTest({ maxBytes: 200 });
  for (let i = 0; i < 10; i++) {
    cacheSet(`key-${i}`, { n: i });
  }
  // The last entry should still exist
  const last = cacheGet<{ n: number }>("key-9");
  assert(last !== undefined);
  assertEquals(last!.n, 9);
});
