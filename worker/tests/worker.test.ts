import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import worker from "../index.ts";
import { QueueProcessor } from "../queue-processor.ts";
import { getWriteRpc, _resetForTest } from "../../shared/rpc.ts";
import type { Env } from "../types.ts";
import {
  initQueue, enqueue, getQueueItem, findDuplicate, checkRateLimit,
  getQueueStats, withD1Retry, isTransientD1Error,
} from "../queue.ts";

// Helpers
function makeRequest(path: string, opts?: RequestInit) {
  return new Request(`https://test.workers.dev${path}`, opts);
}

async function fetchWorker(path: string, opts?: RequestInit) {
  const req = makeRequest(path, opts);
  const ctx = createExecutionContext();
  const res = await worker.fetch(req, env, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

// --- API Route Tests ---

describe("API routes", () => {
  it("GET / returns HTML", async () => {
    const res = await fetchWorker("/");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
  });

  it("GET /api/health returns ok", async () => {
    const res = await fetchWorker("/api/health");
    const body = await res.json() as { status: string; runtime: string };
    expect(res.status).toBe(200);
    expect(body.status).toBe("ok");
    expect(body.runtime).toBe("cloudflare-workers");
  });

  it("GET /api/challenge returns base64url challenge", async () => {
    const res = await fetchWorker("/api/challenge");
    const body = await res.json() as { challenge: string };
    expect(res.status).toBe(200);
    expect(body.challenge).toBeDefined();
    expect(body.challenge.length).toBeGreaterThan(0);
    // base64url: no +, /, or =
    expect(body.challenge).not.toMatch(/[+/=]/);
  });

  it("OPTIONS returns CORS headers", async () => {
    const res = await fetchWorker("/", { method: "OPTIONS" });
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(res.headers.get("Access-Control-Allow-Methods")).toContain("POST");
  });

  it("preflight allows custom request headers (e.g. idempotency-key)", async () => {
    const res = await fetchWorker("/api/create", {
      method: "OPTIONS",
      headers: {
        "Origin": "http://localhost:8081",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type, idempotency-key, authorization",
      },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    // The browser requires every requested header to appear in allow-headers.
    const allow = (res.headers.get("Access-Control-Allow-Headers") || "").toLowerCase();
    for (const h of ["content-type", "idempotency-key", "authorization"]) {
      expect(allow === "*" || allow.includes(h)).toBe(true);
    }
  });

  it("a non-OPTIONS response also carries permissive CORS", async () => {
    const res = await fetchWorker("/api/health");
    const allow = res.headers.get("Access-Control-Allow-Headers");
    expect(allow === "*" || (allow || "").toLowerCase().includes("content-type")).toBe(true);
  });

  it("unknown route returns 404", async () => {
    const res = await fetchWorker("/api/nonexistent");
    expect(res.status).toBe(404);
  });

  it("wrong HTTP method returns 404", async () => {
    const res = await fetchWorker("/api/challenge", { method: "POST" });
    expect(res.status).toBe(404);
  });

  it("GET /api/query without params returns 400", async () => {
    const res = await fetchWorker("/api/query");
    expect(res.status).toBe(400);
  });

  it("GET /api/stats/keys without rpId returns 400", async () => {
    const res = await fetchWorker("/api/stats/keys");
    expect(res.status).toBe(400);
  });

  it("POST /api/create with missing fields returns 400", async () => {
    const res = await fetchWorker("/api/create", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rpId: "test.com" }),
    });
    expect(res.status).toBe(400);
  });

  it("POST /api/create with invalid JSON returns 400", async () => {
    const res = await fetchWorker("/api/create", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not json",
    });
    expect(res.status).toBe(400);
  });

  it("GET /api/create/:id with unknown id returns 404", async () => {
    const res = await fetchWorker("/api/create/unknown-id-123");
    expect(res.status).toBe(404);
  });

  it("CORS headers are present on all responses", async () => {
    const res = await fetchWorker("/api/health");
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });
});

// --- D1 Queue Tests ---

describe("D1 Queue", () => {
  beforeAll(async () => {
    await initQueue(env.DB);
  });

  it("enqueue + getQueueItem round-trip", async () => {
    const id = await enqueue(env.DB, {
      rpId: "test.example.com",
      credentialId: "cred-123",
      walletRef: "0x" + "ab".repeat(32),
      publicKey: "04" + "aa".repeat(64),
      name: "Test Key",
      initialCredentialId: "cred-123",
      metadata: "0x1234",
      ip: "127.0.0.1",
    });

    const item = await getQueueItem(env.DB, id);
    expect(item).not.toBeNull();
    expect(item!.rpId).toBe("test.example.com");
    expect(item!.credentialId).toBe("cred-123");
    expect(item!.status).toBe("pending");
    expect(item!.name).toBe("Test Key");
  });

  it("getQueueItem returns null for unknown id", async () => {
    const item = await getQueueItem(env.DB, "nonexistent-id");
    expect(item).toBeNull();
  });

  it("findDuplicate finds existing item", async () => {
    await enqueue(env.DB, {
      rpId: "dup.example.com",
      credentialId: "dup-cred",
      walletRef: "0x" + "cc".repeat(32),
      publicKey: "04" + "bb".repeat(64),
      name: "Dup Key",
      initialCredentialId: "dup-cred",
      metadata: "0x5678",
      ip: "192.168.1.1",
    });

    const dup = await findDuplicate(env.DB, "dup.example.com", "dup-cred");
    expect(dup).not.toBeNull();
    expect(dup!.rpId).toBe("dup.example.com");
  });

  it("findDuplicate returns null for unknown pair", async () => {
    const dup = await findDuplicate(env.DB, "unknown.com", "unknown-cred");
    expect(dup).toBeNull();
  });

  it("enqueue stores hashed IP, not raw", async () => {
    const id = await enqueue(env.DB, {
      rpId: "ip-test.com",
      credentialId: "ip-cred",
      walletRef: "0x" + "dd".repeat(32),
      publicKey: "04" + "cc".repeat(64),
      name: "IP Key",
      initialCredentialId: "ip-cred",
      metadata: "0x",
      ip: "10.0.0.1",
    });

    const item = await getQueueItem(env.DB, id);
    expect(item).not.toBeNull();
    expect(item!.ip).not.toBe("10.0.0.1");
    expect(item!.ip.length).toBe(16); // first 16 hex chars of SHA-256
  });

  it("checkRateLimit allows up to 5 requests", async () => {
    const testIp = `rate-limit-${Date.now()}`;
    for (let i = 0; i < 5; i++) {
      expect(await checkRateLimit(env.DB, testIp)).toBe(true);
    }
    expect(await checkRateLimit(env.DB, testIp)).toBe(false);
  });

  it("checkRateLimit tracks different IPs independently", async () => {
    const ip1 = `rl-ip1-${Date.now()}`;
    const ip2 = `rl-ip2-${Date.now()}`;
    for (let i = 0; i < 5; i++) {
      await checkRateLimit(env.DB, ip1);
    }
    // ip1 exhausted, ip2 should still work
    expect(await checkRateLimit(env.DB, ip2)).toBe(true);
  });

  it("enqueue is idempotent under concurrent identical creates", async () => {
    const params = {
      rpId: "idem.example.com", credentialId: `c-${Date.now()}`,
      walletRef: "0x" + "ab".repeat(32), publicKey: "04" + "aa".repeat(64),
      name: "k", initialCredentialId: "x", metadata: "0x", ip: "127.0.0.1",
    };
    params.initialCredentialId = params.credentialId;
    const [id1, id2] = await Promise.all([enqueue(env.DB, params), enqueue(env.DB, params)]);
    expect(id1).toBe(id2);
    const { results } = await env.DB.prepare(
      "SELECT id FROM create_queue WHERE rpId = ? AND credentialId = ? AND status != 'failed'",
    ).bind(params.rpId, params.credentialId).all();
    expect(results.length).toBe(1);
  });

  it("getQueueStats reports active depth and dlq count", async () => {
    const stats = await getQueueStats(env.DB);
    expect(typeof stats.queueDepth).toBe("number");
    expect(typeof stats.dlqCount).toBe("number");
    expect(stats.queueDepth).toBeGreaterThanOrEqual(0);
  });
});

// --- D1 transient-retry ---

describe("withD1Retry", () => {
  it("classifies D1 transient patterns", () => {
    expect(isTransientD1Error(new Error("D1_ERROR: storage operation exceeded timeout which caused object to be reset"))).toBe(true);
    expect(isTransientD1Error(new Error("network connection lost"))).toBe(true);
    expect(isTransientD1Error(new Error("UNIQUE constraint failed"))).toBe(false);
    expect(isTransientD1Error(new Error("syntax error"))).toBe(false);
  });

  it("retries a transient failure then succeeds", async () => {
    let calls = 0;
    const result = await withD1Retry(async () => {
      calls++;
      if (calls < 2) throw new Error("D1_ERROR: storage operation exceeded timeout");
      return "ok";
    });
    expect(result).toBe("ok");
    expect(calls).toBe(2);
  });

  it("does NOT retry a non-transient error (e.g. unique constraint)", async () => {
    let calls = 0;
    await expect(withD1Retry(async () => {
      calls++;
      throw new Error("UNIQUE constraint failed: create_queue.rpId, create_queue.credentialId");
    })).rejects.toThrow(/UNIQUE constraint/);
    expect(calls).toBe(1);
  });
});

// --- QueueProcessor RPC wiring ---
//
// The Durable Object runs in its own isolate and never passes through the fetch
// entry's initRpc path. Its constructor must wire ALCHEMY_API_KEY itself, or
// every write tx (commit/createRecord/nonce/gas) silently falls back to public
// endpoints. This pins the wiring so it can't regress.
describe("QueueProcessor Alchemy wiring", () => {
  it("constructor registers ALCHEMY_API_KEY as the priority write RPC", () => {
    _resetForTest();
    const fakeEnv = { ...env, ALCHEMY_API_KEY: "test-alchemy-key-123456" } as Env;
    new QueueProcessor({} as DurableObjectState, fakeEnv);
    expect(getWriteRpc()).toBe("https://gnosis-mainnet.g.alchemy.com/v2/test-alchemy-key-123456");
    _resetForTest(); // don't leak the priority endpoint into other tests
  });

  it("without ALCHEMY_API_KEY the write RPC stays on public endpoints", () => {
    _resetForTest();
    new QueueProcessor({} as DurableObjectState, { ...env, ALCHEMY_API_KEY: undefined } as Env);
    expect(getWriteRpc()).toMatch(/^https:\/\/(rpc\.gnosischain\.com|gnosis-rpc\.publicnode\.com|gnosis\.drpc\.org)/);
  });
});

// --- External-liveness watchdog (worker/watchdog.ts wiring) ---
// Decision logic is pinned in deno/tests/watchdog.test.ts; this covers the CF
// wiring end-to-end: probe → decide → Telegram → state persisted in D1.
import { fetchMock } from "cloudflare:test";
import { runWatchdog } from "../watchdog.ts";

describe("watchdog wiring", () => {
  const TARGET_ORIGIN = "https://vps.watchdog-test.example";
  const wdEnv: Env = {
    ...env,
    TELEGRAM_BOT_TOKEN: "TESTTOKEN",
    TELEGRAM_CHAT_ID: "42",
    WATCHDOG_TARGET_URL: `${TARGET_ORIGIN}/api/health`,
  };

  it("full sequence: summary on first tick, page after 3 fails, recovery — exactly 3 telegram messages", async () => {
    fetchMock.activate();
    fetchMock.disableNetConnect();
    const tg = fetchMock.get("https://api.telegram.org");
    const vps = fetchMock.get(TARGET_ORIGIN);

    // Tick 1: healthy probe; first tick → daily summary (lastSummaryAt=0).
    vps.intercept({ method: "GET", path: "/api/health" })
      .reply(200, JSON.stringify({ status: "ok", telegramConfigured: true }), { headers: { "content-type": "application/json" } });
    tg.intercept({ method: "POST", path: "/botTESTTOKEN/sendMessage" }).reply(200, JSON.stringify({ ok: true }));
    await runWatchdog(wdEnv);

    let row = await wdEnv.DB.prepare("SELECT v FROM watchdog_state WHERE k = 'state'").first<{ v: string }>();
    expect(row).toBeTruthy();
    let state = JSON.parse(row!.v);
    expect(state.consecutiveFails).toBe(0);
    expect(state.paged).toBe(false);
    expect(state.lastSummaryAt).toBeGreaterThan(0);

    // Ticks 2-4: probe fails 3× → exactly ONE down page (on the 3rd).
    for (let i = 0; i < 3; i++) {
      vps.intercept({ method: "GET", path: "/api/health" }).reply(503, "unavailable");
    }
    tg.intercept({ method: "POST", path: "/botTESTTOKEN/sendMessage" }).reply(200, JSON.stringify({ ok: true }));
    await runWatchdog(wdEnv);
    await runWatchdog(wdEnv);
    await runWatchdog(wdEnv);

    row = await wdEnv.DB.prepare("SELECT v FROM watchdog_state WHERE k = 'state'").first<{ v: string }>();
    state = JSON.parse(row!.v);
    expect(state.consecutiveFails).toBe(3);
    expect(state.paged).toBe(true);

    // Tick 5: probe healthy again → recovery message.
    vps.intercept({ method: "GET", path: "/api/health" })
      .reply(200, JSON.stringify({ status: "ok", telegramConfigured: true }), { headers: { "content-type": "application/json" } });
    tg.intercept({ method: "POST", path: "/botTESTTOKEN/sendMessage" }).reply(200, JSON.stringify({ ok: true }));
    await runWatchdog(wdEnv);

    row = await wdEnv.DB.prepare("SELECT v FROM watchdog_state WHERE k = 'state'").first<{ v: string }>();
    state = JSON.parse(row!.v);
    expect(state.paged).toBe(false);
    expect(state.consecutiveFails).toBe(0);

    // Every scripted intercept consumed = exactly 5 probes + 3 telegram sends.
    fetchMock.assertNoPendingInterceptors();
    fetchMock.deactivate();
  });

  it("watchdog never throws — even with an unreachable probe target and no telegram config", async () => {
    fetchMock.activate();
    fetchMock.disableNetConnect(); // no intercepts at all → fetch rejects
    const bare: Env = { ...env, WATCHDOG_TARGET_URL: `${TARGET_ORIGIN}/api/health` };
    await expect(runWatchdog(bare)).resolves.toBeUndefined();
    fetchMock.deactivate();
  });
});
