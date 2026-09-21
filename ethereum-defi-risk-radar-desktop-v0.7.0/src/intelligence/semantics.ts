import {
  functionSelector
} from "../analysis/bytecode/keccak.js";
import type {
  BytecodeAnalysisReport
} from "../analysis/bytecode/analyzer.js";

export type EvmSemanticStandard =
  | "ERC4626"
  | "EIP2612_PERMIT"
  | "EIP712"
  | "ERC1271"
  | "MULTICALL"
  | "ERC2535_DIAMOND"
  | "EIP7702_DELEGATION"
  | "EIP1153_TRANSIENT_STORAGE"
  | "CREATE2_FACTORY"
  | "BLOB_AWARE";

export type ModernEvmSemantics = {
  standards: Array<{
    standard: EvmSemanticStandard;
    confidence: "MEDIUM" | "HIGH";
    evidence: string[];
  }>;
  securityNotes: string[];
};

function selectorSet(
  signatures: string[]
) {
  return new Set(
    signatures.map(functionSelector)
  );
}

function matchesAtLeast(
  observed: Set<string>,
  signatures: string[],
  minimum: number
) {
  const expected =
    selectorSet(signatures);
  return [...expected].filter(value =>
    observed.has(value)
  ).length >= minimum;
}

export function profileModernEvmSemantics(
  report: BytecodeAnalysisReport
): ModernEvmSemantics {
  const observed = new Set(
    report.selectors
  );
  const standards: ModernEvmSemantics["standards"] =
    [];
  const securityNotes: string[] = [];

  const erc4626 = [
    "totalAssets()",
    "convertToShares(uint256)",
    "convertToAssets(uint256)",
    "deposit(uint256,address)",
    "mint(uint256,address)",
    "withdraw(uint256,address,address)",
    "redeem(uint256,address,address)",
    "previewDeposit(uint256)",
    "previewMint(uint256)",
    "previewWithdraw(uint256)",
    "previewRedeem(uint256)"
  ];
  if (
    matchesAtLeast(
      observed,
      erc4626,
      5
    )
  ) {
    standards.push({
      standard: "ERC4626",
      confidence: "HIGH",
      evidence: erc4626
        .filter(signature =>
          observed.has(
            functionSelector(signature)
          )
        )
        .map(
          signature =>
            "selector:" + signature
        )
    });
    securityNotes.push(
      "ERC-4626 semantics make share/asset rounding, donation and first-depositor properties applicable."
    );
  }

  const permit = [
    "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    "nonces(address)",
    "DOMAIN_SEPARATOR()"
  ];
  if (
    matchesAtLeast(
      observed,
      permit,
      2
    )
  ) {
    standards.push({
      standard: "EIP2612_PERMIT",
      confidence: "HIGH",
      evidence: permit
        .filter(signature =>
          observed.has(
            functionSelector(signature)
          )
        )
        .map(
          signature =>
            "selector:" + signature
        )
    });
    securityNotes.push(
      "Permit/signature replay and domain-separation properties are applicable."
    );
  } else if (
    observed.has(
      functionSelector(
        "DOMAIN_SEPARATOR()"
      )
    )
  ) {
    standards.push({
      standard: "EIP712",
      confidence: "MEDIUM",
      evidence: [
        "selector:DOMAIN_SEPARATOR()"
      ]
    });
  }

  if (
    observed.has(
      functionSelector(
        "isValidSignature(bytes32,bytes)"
      )
    )
  ) {
    standards.push({
      standard: "ERC1271",
      confidence: "HIGH",
      evidence: [
        "selector:isValidSignature(bytes32,bytes)"
      ]
    });
  }

  if (
    observed.has(
      functionSelector(
        "multicall(bytes[])"
      )
    )
  ) {
    standards.push({
      standard: "MULTICALL",
      confidence: "HIGH",
      evidence: [
        "selector:multicall(bytes[])"
      ]
    });
    securityNotes.push(
      "Authorization and msg.value accounting should be reviewed under composed/multicall execution."
    );
  }

  if (
    report.proxyKind ===
    "ERC2535_DIAMOND"
  ) {
    standards.push({
      standard: "ERC2535_DIAMOND",
      confidence: "HIGH",
      evidence: report.proxySignals
    });
  }

  if (
    report.semantics
      .eip7702Delegation
  ) {
    standards.push({
      standard: "EIP7702_DELEGATION",
      confidence: "HIGH",
      evidence: [
        "delegation:" +
          report.semantics
            .eip7702Delegation
      ]
    });
    securityNotes.push(
      "Do not assume an EOA has empty behavior; authorization must reason about delegated code."
    );
  }

  if (
    report.semantics
      .usesTransientStorage
  ) {
    standards.push({
      standard:
        "EIP1153_TRANSIENT_STORAGE",
      confidence: "HIGH",
      evidence: [
        "opcode:TLOAD/TSTORE"
      ]
    });
    securityNotes.push(
      "Transient storage is transaction-scoped; cross-call locks/accounting must be interpreted separately from persistent SSTORE state."
    );
  }

  if (
    report.semantics.usesCreate2
  ) {
    standards.push({
      standard: "CREATE2_FACTORY",
      confidence: "HIGH",
      evidence: ["opcode:CREATE2"]
    });
  }

  if (
    report.semantics.usesBlobOpcodes
  ) {
    standards.push({
      standard: "BLOB_AWARE",
      confidence: "HIGH",
      evidence: [
        "opcode:BLOBHASH/BLOBBASEFEE"
      ]
    });
  }

  return {
    standards,
    securityNotes
  };
}
