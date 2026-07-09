/**
 * Gnosis RPC provider with auto-failover.
 * Fetches RPC list from ethereum-data.awesometools.dev, then cycles
 * through endpoints on failure.
 */

import { redactSecrets } from "./log.ts";

const CHAIN_DATA_URL = "https://ethereum-data.awesometools.dev/chains/eip155-100.json";
const REFRESH_INTERVAL = 15 * 60_000; // refresh RPC list every 15 minutes
const HEALTH_CHECK_TIMEOUT = 5000; // 5s

// Fallback RPCs in case the remote list is unreachable
const FALLBACK_RPCS = [
  "https://rpc.gnosischain.com",
  "https://gnosis-rpc.publicnode.com",
  "https://gnosis.drpc.org",
  "https://1rpc.io/gnosis",
];

// RPCs known to support write operations (sendRawTransaction, pending nonce)
const WRITE_RPCS = [
  "https://rpc.gnosischain.com",
  "https://gnosis-rpc.publicnode.com",
  "https://gnosis.drpc.org",
];
let writeIndex = 0;

// Allowlist of reputable Gnosis RPC HOSTS. The RPC list is fetched at runtime
// from a third-party URL (CHAIN_DATA_URL); if that source were compromised it
// could inject an attacker-controlled "RPC" that forges on-chain reads (record
// substitution / false not-found). We only adopt fetched endpoints whose host
// is on this list, so a poisoned source can at worst reorder known-good hosts.
const ALLOWED_RPC_HOSTS = new Set<string>([
  "rpc.gnosischain.com",
  "gnosis-rpc.publicnode.com",
  "gnosis.drpc.org",
  "1rpc.io",
  "gnosis-mainnet.public.blastapi.io",
  "gnosis.api.onfinality.io",
  "rpc.gnosis.gateway.fm",
  "gnosis-pokt.nodies.app",
  "gnosis.blockpi.network",
  "rpc.ankr.com",
  "gnosischain-rpc.gateway.pokt.network",
]);

function isAllowedRpcHost(url: string): boolean {
  try {
    return ALLOWED_RPC_HOSTS.has(new URL(url).hostname);
  } catch {
    return false;
  }
}

let rpcList: string[] = [...FALLBACK_RPCS];
let currentIndex = 0;
let lastRefresh = 0;

// Track failed RPCs: url -> timestamp when it failed (cooldown before retry)
const BAD_RPC_COOLDOWN = 60_000; // 1 minute cooldown for failed RPCs
const failedRpcs = new Map<string, number>();

async function fetchRpcList(): Promise<string[]> {
  try {
    const res = await fetch(CHAIN_DATA_URL, { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) return [];
    const data = await res.json();
    const rpcs: string[] = [];
    // Extract HTTP(S) RPC URLs from the chain data
    for (const provider of data.rpc ?? []) {
      const url = typeof provider === "string" ? provider : provider?.url;
      // Only adopt https endpoints on the reputable-host allowlist — a poisoned
      // chain-data source must not be able to inject a data-forging RPC.
      if (typeof url === "string" && url.startsWith("https://") && !url.includes("${") && isAllowedRpcHost(url)) {
        rpcs.push(url);
      }
    }
    return rpcs;
  } catch {
    return [];
  }
}

async function refreshIfNeeded(): Promise<void> {
  const now = Date.now();
  if (now - lastRefresh < REFRESH_INTERVAL) return;
  lastRefresh = now;

  const fetched = await fetchRpcList();
  if (fetched.length > 0) {
    rpcList = fetched;
    currentIndex = 0;
    console.log(`[rpc] Refreshed RPC list: ${rpcList.length} endpoints`);
  }
}

function isAvailable(url: string): boolean {
  const failedAt = failedRpcs.get(url);
  if (!failedAt) return true;
  // Allow retry after cooldown
  if (Date.now() - failedAt > BAD_RPC_COOLDOWN) {
    failedRpcs.delete(url);
    return true;
  }
  return false;
}

export function getCurrentRpc(): string {
  // Round-robin, skipping known-bad RPCs
  for (let i = 0; i < rpcList.length; i++) {
    const rpc = rpcList[currentIndex % rpcList.length];
    currentIndex = (currentIndex + 1) % rpcList.length;
    if (isAvailable(rpc)) return rpc;
  }
  // All marked bad — return any (cooldowns will expire)
  const rpc = rpcList[currentIndex % rpcList.length];
  currentIndex = (currentIndex + 1) % rpcList.length;
  return rpc;
}

let alchemyRpc: string | null = null;

/** Set Alchemy RPC URL. Called once from initRpc if ALCHEMY_API_KEY is configured. */
export function setAlchemyRpc(apiKey: string): void {
  alchemyRpc = `https://gnosis-mainnet.g.alchemy.com/v2/${apiKey}`;
  console.log(`[rpc] Alchemy RPC configured (priority write endpoint)`);
}

export function getWriteRpc(): string {
  // Alchemy first if configured and available
  if (alchemyRpc && isAvailable(alchemyRpc)) return alchemyRpc;

  // Fallback: round-robin over known-good write RPCs
  for (let i = 0; i < WRITE_RPCS.length; i++) {
    const rpc = WRITE_RPCS[writeIndex % WRITE_RPCS.length];
    writeIndex = (writeIndex + 1) % WRITE_RPCS.length;
    if (isAvailable(rpc)) return rpc;
  }
  const rpc = WRITE_RPCS[writeIndex % WRITE_RPCS.length];
  writeIndex = (writeIndex + 1) % WRITE_RPCS.length;
  return rpc;
}

export function markFailed(url: string): void {
  failedRpcs.set(url, Date.now());
  console.warn(`[rpc] Marked as failed (1min cooldown): ${redactSecrets(url)}`);
}

/**
 * Clear an endpoint's failed mark — call on a SUCCESSFUL use so the circuit
 * recovers the instant any endpoint works again, instead of waiting out the
 * full 60s cooldown.
 */
export function markHealthy(url: string): void {
  if (failedRpcs.delete(url)) {
    console.log(`[rpc] Recovered: ${redactSecrets(url)}`);
  }
}

// Half-open: while the read circuit is open, let ONE probe request through every
// PROBE_INTERVAL so recovery is detected in seconds, not a fixed 60s, without
// hammering known-dead nodes with the full request volume.
const PROBE_INTERVAL = 5_000;
let lastProbeAt = 0;

/** Returns true at most once per PROBE_INTERVAL — the caller may probe-through. */
export function tryReadProbe(): boolean {
  const now = Date.now();
  if (now - lastProbeAt < PROBE_INTERVAL) return false;
  lastProbeAt = now;
  return true;
}

/**
 * Read-path circuit state. "open" means EVERY known read endpoint is currently
 * in cooldown (all marked bad) — so a read should fast-fail with 503 instead of
 * burning the whole retry deadline hammering known-dead nodes. As soon as any
 * cooldown expires this returns "closed" again (the next request probes it),
 * giving free half-open behaviour. `isAvailable` also prunes expired entries.
 */
export function getReadCircuitState(): "open" | "closed" {
  if (rpcList.length === 0) return "open";
  for (const url of rpcList) {
    if (isAvailable(url)) return "closed";
  }
  return "open";
}

/** How many ms until the soonest read endpoint leaves cooldown (for Retry-After). */
export function readCircuitRetryAfterMs(): number {
  let soonest = BAD_RPC_COOLDOWN;
  const now = Date.now();
  for (const url of rpcList) {
    const failedAt = failedRpcs.get(url);
    if (failedAt === undefined) return 0; // something is available now
    soonest = Math.min(soonest, Math.max(0, BAD_RPC_COOLDOWN - (now - failedAt)));
  }
  return soonest;
}

export function failover(): string {
  const next = getCurrentRpc();
  console.warn(`[rpc] Failover to: ${redactSecrets(next)}`);
  return next;
}

export async function initRpc(): Promise<void> {
  const fetched = await fetchRpcList();
  if (fetched.length > 0) {
    rpcList = fetched;
    console.log(`[rpc] Loaded ${rpcList.length} RPC endpoints`);
  } else {
    console.log(`[rpc] Using ${FALLBACK_RPCS.length} fallback RPC endpoints`);
  }
  lastRefresh = Date.now();

  // Periodic refresh (only in long-lived runtimes like Deno, not CF Workers)
  if (typeof Deno !== "undefined") {
    setInterval(() => {
      refreshIfNeeded().catch(() => {});
    }, REFRESH_INTERVAL);
  }
}

/**
 * Get a working RPC URL. Tries current, on failure cycles through the list.
 */
export async function getHealthyRpc(): Promise<string> {
  await refreshIfNeeded();

  // Try current first
  const current = getCurrentRpc();
  if (await isHealthy(current)) return current;

  // Cycle through others
  for (let i = 1; i < rpcList.length; i++) {
    const url = failover();
    if (await isHealthy(url)) return url;
  }

  // All failed, return current anyway and let caller handle error
  return getCurrentRpc();
}

/** Reset internal state (for testing only). */
export function _resetForTest(rpcs?: string[]): void {
  rpcList = rpcs ?? [...FALLBACK_RPCS];
  currentIndex = 0;
  writeIndex = 0;
  failedRpcs.clear();
  lastRefresh = Date.now();
  lastProbeAt = 0;
  alchemyRpc = null;
}

async function isHealthy(url: string): Promise<boolean> {
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", method: "eth_blockNumber", params: [], id: 1 }),
      signal: AbortSignal.timeout(HEALTH_CHECK_TIMEOUT),
    });
    if (!res.ok) return false;
    const data = await res.json();
    return !!data.result;
  } catch {
    return false;
  }
}
