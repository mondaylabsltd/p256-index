/**
 * Gnosis RPC provider with auto-failover.
 * Fetches RPC list from ethereum-data.awesometools.dev, then cycles
 * through endpoints on failure.
 */

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
      if (typeof url === "string" && url.startsWith("https://") && !url.includes("${")) {
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
  console.warn(`[rpc] Marked as failed (1min cooldown): ${url}`);
}

export function failover(): string {
  const next = getCurrentRpc();
  console.warn(`[rpc] Failover to: ${next}`);
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

  // Periodic refresh
  setInterval(() => {
    refreshIfNeeded().catch(() => {});
  }, REFRESH_INTERVAL);
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
