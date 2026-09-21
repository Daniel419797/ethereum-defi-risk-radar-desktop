import { createHash } from "node:crypto";
import type { BytecodeAttestation } from "./model.js";

const HEX_RE = /^0x(?:[a-fA-F0-9]{2})*$/;

function normalizeHex(value: string | undefined) {
  if (!value) return undefined;
  const normalized = value.toLowerCase();
  if (!HEX_RE.test(normalized)) throw new Error("Bytecode must be canonical 0x-prefixed even-length hex.");
  return normalized;
}

function bytes(value: string | undefined) {
  return value ? Math.max(0, (value.length - 2) / 2) : 0;
}

function sha256Bytecode(value: string | undefined) {
  if (!value) return undefined;
  return createHash("sha256").update(Buffer.from(value.slice(2), "hex")).digest("hex");
}

/**
 * Solidity appends CBOR metadata followed by a two-byte big-endian metadata length.
 * Removing only that well-formed trailer lets us distinguish exact runtime equality
 * from metadata-only compiler/build differences without pretending arbitrary prefixes match.
 */
export function stripSolidityMetadata(runtimeBytecode: string) {
  const code = normalizeHex(runtimeBytecode)!;
  const raw = code.slice(2);
  if (raw.length < 4) return code;
  const metadataBytes = Number.parseInt(raw.slice(-4), 16);
  if (!Number.isInteger(metadataBytes) || metadataBytes <= 0) return code;
  const trailerHexChars = metadataBytes * 2 + 4;
  if (trailerHexChars >= raw.length) return code;
  return "0x" + raw.slice(0, raw.length - trailerHexChars);
}

export function attestRuntimeBytecode(input: {
  contractRefId: string;
  sourceRole?: "DIRECT" | "PROXY" | "IMPLEMENTATION";
  observedRuntime?: string;
  expectedRuntime?: string;
  explorerVerified: boolean;
  compilerVersion?: string;
  sourceSha256?: string;
  blockNumber: number;
  blockHash: string;
  observedAt?: string;
}): BytecodeAttestation {
  const observed = normalizeHex(input.observedRuntime);
  const expected = normalizeHex(input.expectedRuntime);
  const observedAt = input.observedAt ?? new Date().toISOString();

  if (!observed) {
    return {
      contractRefId: input.contractRefId,
      sourceRole: input.sourceRole,
      status: "UNAVAILABLE",
      observedAt,
      blockNumber: input.blockNumber,
      blockHash: input.blockHash,
      observedRuntimeBytes: 0,
      expectedRuntimeBytes: expected ? bytes(expected) : undefined,
      expectedCodeSha256: sha256Bytecode(expected),
      compilerVersion: input.compilerVersion,
      sourceSha256: input.sourceSha256,
      explorerVerified: input.explorerVerified,
      locallyCompiled: Boolean(expected),
      metadataStrippedMatch: false,
      limitations: ["No independently observed deployed runtime bytecode was available for attestation."]
    };
  }

  if (observed === "0x") {
    return {
      contractRefId: input.contractRefId,
      sourceRole: input.sourceRole,
      status: "NO_CODE",
      observedAt,
      blockNumber: input.blockNumber,
      blockHash: input.blockHash,
      observedCodeSha256: sha256Bytecode(observed),
      expectedCodeSha256: sha256Bytecode(expected),
      observedRuntimeBytes: 0,
      expectedRuntimeBytes: expected ? bytes(expected) : undefined,
      compilerVersion: input.compilerVersion,
      sourceSha256: input.sourceSha256,
      explorerVerified: input.explorerVerified,
      locallyCompiled: Boolean(expected),
      metadataStrippedMatch: false,
      limitations: ["The pinned block returned no runtime code for this contract target."]
    };
  }

  if (expected) {
    const exact = observed === expected;
    const metadataStrippedMatch =
      !exact && stripSolidityMetadata(observed) === stripSolidityMetadata(expected);

    return {
      contractRefId: input.contractRefId,
      sourceRole: input.sourceRole,
      status: exact ? "EXACT" : metadataStrippedMatch ? "METADATA_ONLY_DIFFERENCE" : "MISMATCH",
      observedAt,
      blockNumber: input.blockNumber,
      blockHash: input.blockHash,
      observedCodeSha256: sha256Bytecode(observed),
      expectedCodeSha256: sha256Bytecode(expected),
      observedRuntimeBytes: bytes(observed),
      expectedRuntimeBytes: bytes(expected),
      compilerVersion: input.compilerVersion,
      sourceSha256: input.sourceSha256,
      explorerVerified: input.explorerVerified,
      locallyCompiled: true,
      metadataStrippedMatch,
      limitations: exact
        ? []
        : metadataStrippedMatch
          ? ["Executable runtime matched after removing a valid Solidity metadata trailer; metadata/build provenance still differs."]
          : ["Locally supplied expected runtime does not match the deployed runtime at the pinned block."]
    };
  }

  return {
    contractRefId: input.contractRefId,
    sourceRole: input.sourceRole,
    status: input.explorerVerified ? "EXPLORER_VERIFIED_RUNTIME_OBSERVED" : "UNAVAILABLE",
    observedAt,
    blockNumber: input.blockNumber,
    blockHash: input.blockHash,
    observedCodeSha256: sha256Bytecode(observed),
    observedRuntimeBytes: bytes(observed),
    compilerVersion: input.compilerVersion,
    sourceSha256: input.sourceSha256,
    explorerVerified: input.explorerVerified,
    locallyCompiled: false,
    metadataStrippedMatch: false,
    limitations: input.explorerVerified
      ? [
          "Etherscan verified-source status and an independent pinned-block runtime observation agree that deployed code exists, but no locally recompiled expected runtime was supplied. This is provenance corroboration, not an exact local compile match."
        ]
      : ["No locally compiled expected runtime and no explorer verification were available."]
  };
}

export function sourceDigest(source: string | undefined) {
  return source ? createHash("sha256").update(source).digest("hex") : undefined;
}
