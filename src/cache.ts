const DEFAULT_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const DEFAULT_MAX_MEMORY_BYTES = 100 * 1024 * 1024; // 100MB

let CACHE_TTL = DEFAULT_CACHE_TTL;
let MAX_MEMORY_BYTES = DEFAULT_MAX_MEMORY_BYTES;

interface CacheEntry {
  value: unknown;
  size: number;
  expiresAt: number;
}

// Map preserves insertion order — oldest entries are first
const store = new Map<string, CacheEntry>();
let totalSize = 0;

const encoder = new TextEncoder();

function estimateSize(value: unknown): number {
  return encoder.encode(JSON.stringify(value)).byteLength;
}

function evictOldest(): void {
  for (const [key, entry] of store) {
    if (totalSize <= MAX_MEMORY_BYTES) break;
    totalSize -= entry.size;
    store.delete(key);
  }
}

export function cacheGet<T>(key: string): T | undefined {
  const entry = store.get(key);
  if (!entry) return undefined;
  if (Date.now() > entry.expiresAt) {
    totalSize -= entry.size;
    store.delete(key);
    return undefined;
  }
  return entry.value as T;
}

export function cacheSet<T>(key: string, value: T): void {
  const existing = store.get(key);
  if (existing) {
    totalSize -= existing.size;
    store.delete(key);
  }

  const size = estimateSize(value);
  totalSize += size;
  store.set(key, { value, size, expiresAt: Date.now() + CACHE_TTL });

  if (totalSize > MAX_MEMORY_BYTES) {
    evictOldest();
  }
}

export function cacheClear(): void {
  store.clear();
  totalSize = 0;
}

export function cacheSize(): number {
  return store.size;
}

export function cacheMemoryUsage(): number {
  return totalSize;
}

/** Override TTL and memory limit (for testing only). */
export function _configureForTest(opts: { ttl?: number; maxBytes?: number }): void {
  if (opts.ttl !== undefined) CACHE_TTL = opts.ttl;
  if (opts.maxBytes !== undefined) MAX_MEMORY_BYTES = opts.maxBytes;
}

/** Reset configuration to defaults (for testing only). */
export function _resetConfigForTest(): void {
  CACHE_TTL = DEFAULT_CACHE_TTL;
  MAX_MEMORY_BYTES = DEFAULT_MAX_MEMORY_BYTES;
}
