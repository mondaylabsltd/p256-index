/**
 * Input validation for API routes.
 * Prevents oversized inputs from consuming memory or polluting cache.
 */

// Max lengths for string fields (bytes)
const LIMITS = {
  rpId: 253,            // max DNS hostname length
  credentialId: 1024,   // WebAuthn spec allows variable length, 1KB is generous
  publicKey: 130,       // uncompressed P256: "04" + 64 hex bytes = 130 chars
  name: 256,            // display name
  walletRef: 66,        // "0x" + 32 bytes hex = 66 chars
  initialCredentialId: 1024,
  metadata: 4096,       // abi-encoded metadata
} as const;

export type FieldName = keyof typeof LIMITS;

export function validateStringLength(
  fields: Partial<Record<FieldName, string | undefined | null>>,
): string | null {
  for (const [name, value] of Object.entries(fields)) {
    if (value == null) continue;
    const limit = LIMITS[name as FieldName];
    if (limit && value.length > limit) {
      return `${name} exceeds max length (${limit})`;
    }
  }
  return null;
}
