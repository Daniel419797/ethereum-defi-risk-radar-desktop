import { createHash } from "node:crypto";
import type { BytecodeAttestation } from "./model.js";

const HEX = /^0x(?:[a-fA-F0-9]{2})*$/;

function normalizeHex(value: string) {
  const normalized = value.trim().toLowerCase();
  if (!HEX.test(normalized)) throw new Error("Runtime bytecode must be canonical 0x-prefixed even-length hex.");
  return normalized;
}

export function bytecodeHash(bytecode: string) {
  const normalized = normalizeHex(bytecode);
  return "sha256:" + createHash("sha256").update(Buffer.from(normalized.slice(2), "hex")).digest("hex");
}

export function bytecodeSize(bytecode: string) {
  return Math.max(0, (normalizeHex(bytecode).length - 2) / 2);
}

/**
 * Solidity appends CBOR metadata to runtime bytecode. This removes only a structurally valid
 * trailer whose final two bytes declare the CBOR payload length. It deliberately does not
 * rewrite library placeholders or immutables.
 */
export function stripSolidityMetadata(bytecode: string) {
  const normalized = normalizeHex(bytecode);
  const body = normalized.slice(2);
  if (body.length < 4) return normalized;
  const metadataBytes = Number.parseInt(body.slice(-4), 16);
  if (!Number.isFinite(metadataBytes) || metadataBytes <= 0) return normalized;
  const trailerHex = (metadataBytes + 2) * 2;
  if (trailerHex >= body.length) return normalized;
  const prefix = body.slice(0, body.length - trailerHex);
  return "0x" + prefix;
}

export function attestRuntimeBytecode(opts: {
  observedRuntimeBytecode?: string | null;
  compiledRuntimeBytecode?: string | null;
  compilerVersion?: string;
  unavailableReason?: string;
}): BytecodeAttestation {
  const comparedAt = new Date().toISOString();
  const limitations: string[] = [];

  if (!opts.observedRuntimeBytecode) {
    return {
      version: 1,
      status: opts.unavailableReason ? "UNAVAILABLE" : "NO_RUNTIME_CODE",
      observedRuntimeBytes: 0,
      compilerVersion: opts.compilerVersion,
      metadataStripped: false,
      comparedAt,
      limitations: [opts.unavailableReason || "No deployed runtime bytecode was available for comparison."]
    };
  }

  const observed = normalizeHex(opts.observedRuntimeBytecode);
  if (observed === "0x") {
    return {
      version: 1,
      status: "NO_RUNTIME_CODE",
      observedRuntimeHash: bytecodeHash(observed),
      observedRuntimeBytes: 0,
      compilerVersion: opts.compilerVersion,
      metadataStripped: false,
      comparedAt,
      limitations: ["The pinned address had no runtime bytecode at the observed block."]
    };
  }

  if (!opts.compiledRuntimeBytecode) {
    return {
      version: 1,
      status: "DEPLOYED_BYTECODE_OBSERVED",
      observedRuntimeHash: bytecodeHash(observed),
      observedRuntimeBytes: bytecodeSize(observed),
      compilerVersion: opts.compilerVersion,
      metadataStripped: false,
      comparedAt,
      limitations: [
        opts.unavailableReason || "Verified source was not recompiled with an exact matching compiler, so source-to-bytecode equivalence is not claimed."
      ]
    };
  }

  const compiled = normalizeHex(opts.compiledRuntimeBytecode);
  const observedHash = bytecodeHash(observed);
  const compiledHash = bytecodeHash(compiled);
  if (observed === compiled) {
    return {
      version: 1,
      status: "SOURCE_RECOMPILED_EXACT",
      observedRuntimeHash: observedHash,
      observedRuntimeBytes: bytecodeSize(observed),
      compiledRuntimeHash: compiledHash,
      compiledRuntimeBytes: bytecodeSize(compiled),
      compilerVersion: opts.compilerVersion,
      metadataStripped: false,
      comparedAt,
      limitations
    };
  }

  const observedStripped = stripSolidityMetadata(observed);
  const compiledStripped = stripSolidityMetadata(compiled);
  if (observedStripped !== "0x" && observedStripped === compiledStripped) {
    limitations.push("The executable runtime prefix matched after stripping structurally valid Solidity CBOR metadata trailers.");
    return {
      version: 1,
      status: "SOURCE_RECOMPILED_METADATA_EQUIVALENT",
      observedRuntimeHash: observedHash,
      observedRuntimeBytes: bytecodeSize(observed),
      compiledRuntimeHash: compiledHash,
      compiledRuntimeBytes: bytecodeSize(compiled),
      compilerVersion: opts.compilerVersion,
      metadataStripped: true,
      comparedAt,
      limitations
    };
  }

  limitations.push("Recompiled runtime bytecode did not match deployed runtime bytecode; the verified-source/compiler reconstruction must be reviewed.");
  return {
    version: 1,
    status: "RECOMPILE_MISMATCH",
    observedRuntimeHash: observedHash,
    observedRuntimeBytes: bytecodeSize(observed),
    compiledRuntimeHash: compiledHash,
    compiledRuntimeBytes: bytecodeSize(compiled),
    compilerVersion: opts.compilerVersion,
    metadataStripped: false,
    comparedAt,
    limitations
  };
}
