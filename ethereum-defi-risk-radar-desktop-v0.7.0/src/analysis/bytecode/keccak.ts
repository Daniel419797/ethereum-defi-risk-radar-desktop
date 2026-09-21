const MASK_64 = (1n << 64n) - 1n;

const ROTATION = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14
] as const;

const ROUND_CONSTANTS = [
  0x0000000000000001n, 0x0000000000008082n,
  0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n,
  0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n,
  0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn,
  0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n,
  0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n,
  0x0000000080000001n, 0x8000000080008008n
] as const;

function rotl64(value: bigint, shift: number) {
  if (shift === 0) return value & MASK_64;
  const s = BigInt(shift);
  return ((value << s) | (value >> (64n - s))) & MASK_64;
}

function laneFromBytes(bytes: Uint8Array, offset: number) {
  let value = 0n;
  for (let i = 0; i < 8; i += 1) {
    value |= BigInt(bytes[offset + i] ?? 0) << BigInt(i * 8);
  }
  return value;
}

function laneToBytes(value: bigint, output: Uint8Array, offset: number) {
  for (let i = 0; i < 8; i += 1) {
    output[offset + i] = Number((value >> BigInt(i * 8)) & 0xffn);
  }
}

function keccakF(state: bigint[]) {
  const b = Array<bigint>(25).fill(0n);
  const c = Array<bigint>(5).fill(0n);
  const d = Array<bigint>(5).fill(0n);

  for (const rc of ROUND_CONSTANTS) {
    for (let x = 0; x < 5; x += 1) {
      c[x] =
        state[x] ^
        state[x + 5] ^
        state[x + 10] ^
        state[x + 15] ^
        state[x + 20];
    }

    for (let x = 0; x < 5; x += 1) {
      d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
    }

    for (let y = 0; y < 5; y += 1) {
      for (let x = 0; x < 5; x += 1) {
        const index = x + 5 * y;
        state[index] = (state[index] ^ d[x]) & MASK_64;
      }
    }

    b.fill(0n);
    for (let y = 0; y < 5; y += 1) {
      for (let x = 0; x < 5; x += 1) {
        const index = x + 5 * y;
        const nextX = y;
        const nextY = (2 * x + 3 * y) % 5;
        b[nextX + 5 * nextY] = rotl64(state[index], ROTATION[index]);
      }
    }

    for (let y = 0; y < 5; y += 1) {
      for (let x = 0; x < 5; x += 1) {
        const index = x + 5 * y;
        state[index] =
          b[index] ^
          ((~b[((x + 1) % 5) + 5 * y] & MASK_64) &
            b[((x + 2) % 5) + 5 * y]);
      }
    }

    state[0] ^= rc;
  }
}

export function keccak256Bytes(input: Uint8Array) {
  const rate = 136;
  const paddedLength = Math.ceil((input.length + 1) / rate) * rate;
  const padded = new Uint8Array(paddedLength);
  padded.set(input);
  padded[input.length] = 0x01;
  padded[padded.length - 1] |= 0x80;

  const state = Array<bigint>(25).fill(0n);
  for (let offset = 0; offset < padded.length; offset += rate) {
    for (let lane = 0; lane < rate / 8; lane += 1) {
      state[lane] ^=
        laneFromBytes(padded, offset + lane * 8);
    }
    keccakF(state);
  }

  const output = new Uint8Array(32);
  for (let lane = 0; lane < 4; lane += 1) {
    laneToBytes(state[lane], output, lane * 8);
  }
  return output;
}

export function bytesToHex(bytes: Uint8Array) {
  return (
    "0x" +
    [...bytes]
      .map(value => value.toString(16).padStart(2, "0"))
      .join("")
  );
}

export function keccak256Utf8(value: string) {
  return bytesToHex(
    keccak256Bytes(new TextEncoder().encode(value))
  );
}

export function functionSelector(signature: string) {
  return keccak256Utf8(signature).slice(0, 10);
}

export function eventTopic(signature: string) {
  return keccak256Utf8(signature);
}
