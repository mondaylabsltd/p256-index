import { assert } from "@std/assert/";
import { sendTelegram, type AppConfig } from "../../shared/queue.ts";

// Regression for the "Telegram is fail-silent" fix: a misconfigured or unreachable
// alert channel must no longer vanish without a trace. We stub fetch + capture
// console.warn (log.warn writes there) and assert a structured warn is emitted.

const configured: AppConfig = {
  privateKey: "",
  commitPrivateKey: "",
  telegramBotToken: "test-token",
  telegramChatId: "123456",
};

async function captureWarn(fn: () => Promise<void>): Promise<string[]> {
  const origWarn = console.warn;
  const lines: string[] = [];
  console.warn = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
  try {
    await fn();
  } finally {
    console.warn = origWarn;
  }
  return lines;
}

Deno.test("sendTelegram warns (not silent) on a non-2xx response — a bad token/chat id is discoverable", async () => {
  const origFetch = globalThis.fetch;
  globalThis.fetch = () => Promise.resolve(new Response("Bad Request", { status: 400 }));
  try {
    const lines = await captureWarn(() => sendTelegram(configured, "hello"));
    assert(
      lines.some((l) => l.includes("telegram alert delivery failed")),
      `expected a delivery-failed warn, got: ${lines.join(" | ")}`,
    );
  } finally {
    globalThis.fetch = origFetch;
  }
});

Deno.test("sendTelegram warns (not silent) on a fetch/network error", async () => {
  const origFetch = globalThis.fetch;
  globalThis.fetch = () => Promise.reject(new Error("network boom"));
  try {
    const lines = await captureWarn(() => sendTelegram(configured, "hello"));
    assert(
      lines.some((l) => l.includes("telegram alert delivery error")),
      `expected a delivery-error warn, got: ${lines.join(" | ")}`,
    );
  } finally {
    globalThis.fetch = origFetch;
  }
});

Deno.test("sendTelegram stays a silent no-op when unconfigured (no token/chat)", async () => {
  const origFetch = globalThis.fetch;
  let called = false;
  globalThis.fetch = () => { called = true; return Promise.resolve(new Response("")); };
  try {
    await sendTelegram({ privateKey: "", commitPrivateKey: "", telegramBotToken: "", telegramChatId: "" }, "x");
  } finally {
    globalThis.fetch = origFetch;
  }
  assert(!called, "must not call fetch when Telegram is not configured");
});
