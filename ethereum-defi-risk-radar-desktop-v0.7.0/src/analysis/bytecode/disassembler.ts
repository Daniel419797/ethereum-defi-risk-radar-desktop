export type EvmInstruction = {
  pc: number;
  opcode: number;
  name: string;
  immediate?: string;
  size: number;
};

export type EvmBasicBlock = {
  id: string;
  startPc: number;
  endPc: number;
  instructions: EvmInstruction[];
  successors: number[];
  terminal: boolean;
};

const NAMES = new Map<number, string>([
  [0x00, "STOP"], [0x01, "ADD"], [0x02, "MUL"], [0x03, "SUB"],
  [0x04, "DIV"], [0x05, "SDIV"], [0x06, "MOD"], [0x07, "SMOD"],
  [0x08, "ADDMOD"], [0x09, "MULMOD"], [0x0a, "EXP"], [0x0b, "SIGNEXTEND"],
  [0x10, "LT"], [0x11, "GT"], [0x12, "SLT"], [0x13, "SGT"],
  [0x14, "EQ"], [0x15, "ISZERO"], [0x16, "AND"], [0x17, "OR"],
  [0x18, "XOR"], [0x19, "NOT"], [0x1a, "BYTE"], [0x1b, "SHL"],
  [0x1c, "SHR"], [0x1d, "SAR"], [0x20, "KECCAK256"],
  [0x30, "ADDRESS"], [0x31, "BALANCE"], [0x32, "ORIGIN"], [0x33, "CALLER"],
  [0x34, "CALLVALUE"], [0x35, "CALLDATALOAD"], [0x36, "CALLDATASIZE"],
  [0x37, "CALLDATACOPY"], [0x38, "CODESIZE"], [0x39, "CODECOPY"],
  [0x3a, "GASPRICE"], [0x3b, "EXTCODESIZE"], [0x3c, "EXTCODECOPY"],
  [0x3d, "RETURNDATASIZE"], [0x3e, "RETURNDATACOPY"], [0x3f, "EXTCODEHASH"],
  [0x40, "BLOCKHASH"], [0x41, "COINBASE"], [0x42, "TIMESTAMP"], [0x43, "NUMBER"],
  [0x44, "PREVRANDAO"], [0x45, "GASLIMIT"], [0x46, "CHAINID"], [0x47, "SELFBALANCE"],
  [0x48, "BASEFEE"], [0x49, "BLOBHASH"], [0x4a, "BLOBBASEFEE"],
  [0x50, "POP"], [0x51, "MLOAD"], [0x52, "MSTORE"], [0x53, "MSTORE8"],
  [0x54, "SLOAD"], [0x55, "SSTORE"], [0x56, "JUMP"], [0x57, "JUMPI"],
  [0x58, "PC"], [0x59, "MSIZE"], [0x5a, "GAS"], [0x5b, "JUMPDEST"],
  [0x5c, "TLOAD"], [0x5d, "TSTORE"], [0x5e, "MCOPY"], [0x5f, "PUSH0"],
  [0xa0, "LOG0"], [0xa1, "LOG1"], [0xa2, "LOG2"], [0xa3, "LOG3"], [0xa4, "LOG4"],
  [0xf0, "CREATE"], [0xf1, "CALL"], [0xf2, "CALLCODE"], [0xf3, "RETURN"],
  [0xf4, "DELEGATECALL"], [0xf5, "CREATE2"], [0xfa, "STATICCALL"],
  [0xfd, "REVERT"], [0xfe, "INVALID"], [0xff, "SELFDESTRUCT"]
]);

for (let opcode = 0x60; opcode <= 0x7f; opcode += 1) {
  NAMES.set(opcode, "PUSH" + (opcode - 0x5f));
}
for (let opcode = 0x80; opcode <= 0x8f; opcode += 1) {
  NAMES.set(opcode, "DUP" + (opcode - 0x7f));
}
for (let opcode = 0x90; opcode <= 0x9f; opcode += 1) {
  NAMES.set(opcode, "SWAP" + (opcode - 0x8f));
}

function hexToBytes(runtimeBytecode: string) {
  const body = runtimeBytecode.toLowerCase().replace(/^0x/, "");
  if (!body.length || body.length % 2 !== 0 || !/^[a-f0-9]+$/.test(body)) {
    throw new Error("Runtime bytecode must be non-empty canonical hex.");
  }
  return Uint8Array.from(
    body.match(/.{2}/g)!.map(value => Number.parseInt(value, 16))
  );
}

export function disassembleRuntimeBytecode(runtimeBytecode: string) {
  const bytes = hexToBytes(runtimeBytecode);
  const instructions: EvmInstruction[] = [];
  for (let pc = 0; pc < bytes.length;) {
    const opcode = bytes[pc];
    const pushBytes =
      opcode >= 0x60 && opcode <= 0x7f
        ? opcode - 0x5f
        : 0;
    const available =
      Math.min(pushBytes, bytes.length - pc - 1);
    const immediate =
      pushBytes > 0
        ? "0x" +
          [...bytes.slice(pc + 1, pc + 1 + available)]
            .map(value => value.toString(16).padStart(2, "0"))
            .join("")
        : undefined;
    instructions.push({
      pc,
      opcode,
      name: NAMES.get(opcode) || "OP_" + opcode.toString(16).padStart(2, "0"),
      immediate,
      size: 1 + available
    });
    pc += 1 + available;
  }
  return instructions;
}

function staticJumpTarget(
  instructions: EvmInstruction[],
  index: number
) {
  for (
    let cursor = index - 1;
    cursor >= 0 && cursor >= index - 4;
    cursor -= 1
  ) {
    const previous = instructions[cursor];
    if (previous.name.startsWith("PUSH") && previous.immediate) {
      return Number.parseInt(previous.immediate.slice(2) || "0", 16);
    }
    if (
      previous.name === "JUMPDEST" ||
      previous.name === "JUMP" ||
      previous.name === "JUMPI"
    ) {
      break;
    }
  }
  return undefined;
}

const TERMINALS = new Set([
  "STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT"
]);

export function buildBytecodeCfg(
  instructions: EvmInstruction[]
): EvmBasicBlock[] {
  if (!instructions.length) return [];
  const leaders = new Set<number>([instructions[0].pc]);

  for (let index = 0; index < instructions.length; index += 1) {
    const instruction = instructions[index];
    if (instruction.name === "JUMPDEST") leaders.add(instruction.pc);
    if (
      instruction.name === "JUMP" ||
      instruction.name === "JUMPI" ||
      TERMINALS.has(instruction.name)
    ) {
      const next = instructions[index + 1];
      if (next) leaders.add(next.pc);
    }
    if (instruction.name === "JUMP" || instruction.name === "JUMPI") {
      const target = staticJumpTarget(instructions, index);
      if (target !== undefined) leaders.add(target);
    }
  }

  const sortedLeaders = [...leaders].sort((a, b) => a - b);
  const blocks: EvmBasicBlock[] = [];
  for (let index = 0; index < sortedLeaders.length; index += 1) {
    const startPc = sortedLeaders[index];
    const nextStart = sortedLeaders[index + 1] ?? Number.MAX_SAFE_INTEGER;
    const rows = instructions.filter(
      instruction =>
        instruction.pc >= startPc &&
        instruction.pc < nextStart
    );
    if (!rows.length) continue;
    const last = rows[rows.length - 1];
    blocks.push({
      id: "bb:" + startPc,
      startPc,
      endPc: last.pc,
      instructions: rows,
      successors: [],
      terminal: TERMINALS.has(last.name)
    });
  }

  const byPc = new Map(blocks.map(block => [block.startPc, block]));
  for (let index = 0; index < blocks.length; index += 1) {
    const block = blocks[index];
    const lastIndex = instructions.findIndex(
      instruction => instruction.pc === block.endPc
    );
    const last = instructions[lastIndex];
    if (last.name === "JUMP" || last.name === "JUMPI") {
      const target = staticJumpTarget(instructions, lastIndex);
      if (target !== undefined && byPc.has(target)) {
        block.successors.push(target);
      }
    }
    if (
      last.name !== "JUMP" &&
      !TERMINALS.has(last.name)
    ) {
      const next = blocks[index + 1];
      if (next) block.successors.push(next.startPc);
    }
    block.successors = [...new Set(block.successors)];
  }

  return blocks;
}

export function recoverFunctionSelectors(
  instructions: EvmInstruction[]
) {
  const selectors = new Set<string>();
  for (let index = 0; index < instructions.length; index += 1) {
    const current = instructions[index];
    if (
      current.name === "PUSH4" &&
      /^0x[a-f0-9]{8}$/.test(current.immediate || "")
    ) {
      const window = instructions.slice(index + 1, index + 5);
      if (
        window.some(item => item.name === "EQ") &&
        window.some(item => item.name === "JUMPI")
      ) {
        selectors.add(current.immediate!);
      }
    }
  }
  return [...selectors].sort();
}
