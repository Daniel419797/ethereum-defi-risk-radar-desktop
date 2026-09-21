import {
  eventTopic,
  functionSelector
} from "../analysis/bytecode/keccak.js";
import {
  ETH_ADDRESS_RE,
  ETH_HEX_RE
} from "./rpc.js";

function body(value: string) {
  if (!ETH_HEX_RE.test(value)) {
    throw new Error("ABI value must be canonical hex.");
  }
  return value.slice(2).toLowerCase();
}

export function encodeAddressWord(address: string) {
  if (!ETH_ADDRESS_RE.test(address)) {
    throw new Error("Invalid ABI address.");
  }
  return address
    .slice(2)
    .toLowerCase()
    .padStart(64, "0");
}

export function encodeUintWord(value: bigint | number) {
  const numeric =
    typeof value === "number"
      ? BigInt(value)
      : value;
  if (numeric < 0n) {
    throw new Error("ABI uint cannot be negative.");
  }
  return numeric
    .toString(16)
    .padStart(64, "0");
}

export function encodeBytes32Word(value: string) {
  const normalized = body(value);
  if (normalized.length !== 64) {
    throw new Error("ABI bytes32 must be 32 bytes.");
  }
  return normalized;
}

export function encodeCall(
  signature: string,
  words: string[] = []
) {
  for (const word of words) {
    if (!/^[a-f0-9]{64}$/i.test(word)) {
      throw new Error(
        "ABI call word must be exactly 32 bytes."
      );
    }
  }
  return (
    functionSelector(signature) +
    words.join("")
  );
}

export function decodeUintWord(
  data: string,
  wordIndex = 0
) {
  const normalized = body(data);
  const start = wordIndex * 64;
  if (normalized.length < start + 64) {
    throw new Error(
      "ABI uint word is out of bounds."
    );
  }
  return BigInt(
    "0x" +
      normalized.slice(start, start + 64)
  );
}

export function decodeAddressWord(
  data: string,
  wordIndex = 0
) {
  const normalized = body(data);
  const start = wordIndex * 64;
  if (normalized.length < start + 64) {
    throw new Error(
      "ABI address word is out of bounds."
    );
  }
  return (
    "0x" +
    normalized
      .slice(start + 24, start + 64)
      .toLowerCase()
  );
}

export function decodeDynamicAddressArray(
  data: string
) {
  const normalized = body(data);
  if (normalized.length < 64) return [];
  const offset =
    Number(
      decodeUintWord("0x" + normalized, 0)
    ) * 2;
  if (
    !Number.isSafeInteger(offset) ||
    offset < 0 ||
    normalized.length < offset + 64
  ) {
    throw new Error(
      "ABI address-array offset is invalid."
    );
  }
  const length = Number(
    BigInt(
      "0x" +
        normalized.slice(
          offset,
          offset + 64
        )
    )
  );
  if (
    !Number.isSafeInteger(length) ||
    length < 0 ||
    length > 10_000
  ) {
    throw new Error(
      "ABI address-array length is invalid."
    );
  }
  const out: string[] = [];
  for (let index = 0; index < length; index += 1) {
    const start =
      offset + 64 + index * 64;
    if (
      normalized.length <
      start + 64
    ) {
      throw new Error(
        "ABI address-array payload is truncated."
      );
    }
    out.push(
      "0x" +
        normalized
          .slice(start + 24, start + 64)
          .toLowerCase()
    );
  }
  return out;
}

export function decodeDynamicBytes4Array(
  data: string
) {
  const normalized = body(data);
  if (normalized.length < 64) return [];
  const offset =
    Number(
      decodeUintWord("0x" + normalized, 0)
    ) * 2;
  if (
    !Number.isSafeInteger(offset) ||
    normalized.length < offset + 64
  ) {
    throw new Error(
      "ABI bytes4-array offset is invalid."
    );
  }
  const length = Number(
    BigInt(
      "0x" +
        normalized.slice(
          offset,
          offset + 64
        )
    )
  );
  if (
    !Number.isSafeInteger(length) ||
    length > 50_000
  ) {
    throw new Error(
      "ABI bytes4-array length is invalid."
    );
  }
  const out: string[] = [];
  for (let index = 0; index < length; index += 1) {
    const start =
      offset + 64 + index * 64;
    if (
      normalized.length <
      start + 64
    ) {
      throw new Error(
        "ABI bytes4-array payload is truncated."
      );
    }
    out.push(
      "0x" +
        normalized.slice(
          start,
          start + 8
        )
    );
  }
  return out;
}

export function topicAddress(topic: string) {
  const normalized = body(topic);
  if (normalized.length !== 64) {
    throw new Error(
      "Indexed address topic must be 32 bytes."
    );
  }
  return (
    "0x" +
    normalized.slice(-40)
  );
}

export function topicUint(topic: string) {
  const normalized = body(topic);
  if (normalized.length !== 64) {
    throw new Error(
      "Indexed uint topic must be 32 bytes."
    );
  }
  return BigInt("0x" + normalized);
}

export function signatureTopic(signature: string) {
  return eventTopic(signature);
}
