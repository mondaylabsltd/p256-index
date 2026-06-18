import { type Abi } from "viem";

export const CONTRACT_ABI = [
  {
    type: "function",
    name: "getRecord",
    inputs: [
      { name: "rpId", type: "string" },
      { name: "credentialId", type: "string" },
    ],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "rpId", type: "string" },
          { name: "credentialId", type: "string" },
          { name: "walletRef", type: "bytes32" },
          { name: "publicKey", type: "bytes" },
          { name: "name", type: "string" },
          { name: "initialCredentialId", type: "string" },
          { name: "metadata", type: "bytes" },
          { name: "createdAt", type: "uint256" },
        ],
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getRecordByWalletRef",
    inputs: [{ name: "walletRef", type: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "rpId", type: "string" },
          { name: "credentialId", type: "string" },
          { name: "walletRef", type: "bytes32" },
          { name: "publicKey", type: "bytes" },
          { name: "name", type: "string" },
          { name: "initialCredentialId", type: "string" },
          { name: "metadata", type: "bytes" },
          { name: "createdAt", type: "uint256" },
        ],
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "hasRecord",
    inputs: [
      { name: "rpId", type: "string" },
      { name: "credentialId", type: "string" },
    ],
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getCommitBlock",
    inputs: [{ name: "commitment", type: "bytes32" }],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getTotalCredentials",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getRpIds",
    inputs: [
      { name: "offset", type: "uint256" },
      { name: "limit", type: "uint256" },
      { name: "desc", type: "bool" },
    ],
    outputs: [
      { name: "total", type: "uint256" },
      { name: "rpIds", type: "string[]" },
      { name: "counts", type: "uint256[]" },
      { name: "createdAts", type: "uint256[]" },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getKeysByRpId",
    inputs: [
      { name: "rpId", type: "string" },
      { name: "offset", type: "uint256" },
      { name: "limit", type: "uint256" },
      { name: "desc", type: "bool" },
    ],
    outputs: [
      { name: "total", type: "uint256" },
      {
        name: "records",
        type: "tuple[]",
        components: [
          { name: "rpId", type: "string" },
          { name: "credentialId", type: "string" },
          { name: "walletRef", type: "bytes32" },
          { name: "publicKey", type: "bytes" },
          { name: "name", type: "string" },
          { name: "initialCredentialId", type: "string" },
          { name: "metadata", type: "bytes" },
          { name: "createdAt", type: "uint256" },
        ],
      },
    ],
    stateMutability: "view",
  },
  // Custom errors — included so viem decodes reverts by name (e.g. RecordNotFound,
  // selector 0x85da2f88, which is the normal "not registered yet" case) instead of
  // logging a raw, undecodable selector. Purely additive; does not affect calls.
  { type: "error", name: "EmptyRpId", inputs: [] },
  { type: "error", name: "EmptyCredentialId", inputs: [] },
  { type: "error", name: "InvalidPublicKeyLength", inputs: [{ name: "length", type: "uint256" }] },
  { type: "error", name: "RpIdTooLong", inputs: [{ name: "length", type: "uint256" }] },
  { type: "error", name: "CredentialIdTooLong", inputs: [{ name: "length", type: "uint256" }] },
  { type: "error", name: "NameTooLong", inputs: [{ name: "length", type: "uint256" }] },
  { type: "error", name: "RecordAlreadyExists", inputs: [{ name: "rpId", type: "string" }, { name: "credentialId", type: "string" }] },
  { type: "error", name: "RecordNotFound", inputs: [{ name: "rpId", type: "string" }, { name: "credentialId", type: "string" }] },
  { type: "error", name: "InvalidPublicKeyPrefix", inputs: [{ name: "prefix", type: "bytes1" }] },
  { type: "error", name: "InitialCredentialIdTooLong", inputs: [{ name: "length", type: "uint256" }] },
  { type: "error", name: "MetadataTooLong", inputs: [{ name: "length", type: "uint256" }] },
  { type: "error", name: "InitialRecordNotFound", inputs: [{ name: "rpId", type: "string" }, { name: "initialCredentialId", type: "string" }] },
  { type: "error", name: "InitialRecordNotRoot", inputs: [{ name: "rpId", type: "string" }, { name: "initialCredentialId", type: "string" }] },
  { type: "error", name: "NotCommitted", inputs: [] },
  { type: "error", name: "RevealTooEarly", inputs: [] },
  { type: "error", name: "EmptyWalletRef", inputs: [] },
  { type: "error", name: "WalletRefNotFound", inputs: [{ name: "walletRef", type: "bytes32" }] },
  { type: "error", name: "WalletRefAlreadyExists", inputs: [{ name: "walletRef", type: "bytes32" }] },
  { type: "error", name: "InvalidPublicKeyCoordinate", inputs: [] },
  { type: "error", name: "InvalidPublicKeyPoint", inputs: [] },
] as const satisfies Abi;

export const CONTRACT_ADDRESS = "0xdd93420BD49baaBdFF4A363DdD300622Ae87E9c3" as const;

export const BATCH_HELPER_ADDRESS = "0xc7b0db5d4974aba3ea25780f40bf369cc013a16e" as const;

export const BATCH_ABI = [
  {
    type: "function",
    name: "batchCommit",
    inputs: [
      { name: "index", type: "address" },
      { name: "commitments", type: "bytes32[]" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "batchCreateRecord",
    inputs: [
      { name: "index", type: "address" },
      {
        name: "params",
        type: "tuple[]",
        components: [
          { name: "rpId", type: "string" },
          { name: "credentialId", type: "string" },
          { name: "walletRef", type: "bytes32" },
          { name: "publicKey", type: "bytes" },
          { name: "name", type: "string" },
          { name: "initialCredentialId", type: "string" },
          { name: "metadata", type: "bytes" },
        ],
      },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
] as const;

export const MAX_RPC_RETRIES = 3;

export function stripHexPrefix(hex: string): string {
  return hex.startsWith("0x") ? hex.slice(2) : hex;
}

export function formatRecord(record: {
  rpId: string;
  credentialId: string;
  walletRef: string;
  publicKey: string;
  name: string;
  initialCredentialId: string;
  metadata: string;
  createdAt: bigint;
}) {
  return {
    rpId: record.rpId,
    credentialId: record.credentialId,
    walletRef: record.walletRef,
    publicKey: stripHexPrefix(record.publicKey),
    name: record.name,
    initialCredentialId: record.initialCredentialId,
    metadata: stripHexPrefix(record.metadata),
    createdAt: Number(record.createdAt) * 1000,
  };
}

export function isContractRevert(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return msg.includes("reverted") || msg.includes("revert");
}
