import {
  createHash
} from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import type {
  AnalysisFinding
} from "../analysis/model.js";
import type {
  Candidate
} from "../types.js";
import type {
  ProtocolIntelligenceBundle,
  PinnedStateSnapshot
} from "./model.js";

export type ReproductionPackageOptions = {
  outputDir: string;
  packageName: string;
  candidate: Candidate;
  finding: AnalysisFinding;
  intelligence?: ProtocolIntelligenceBundle;
  snapshot?: PinnedStateSnapshot;
  includeDeploymentAddresses: boolean;
  forkReplaySpec?: unknown;
  formalArtifacts?: Array<{
    name: string;
    content: string;
  }>;
};

export type ReproductionPackageManifest = {
  version: 1;
  createdAt: string;
  protocolId: string;
  findingId: string;
  evidenceStrength: string;
  evidenceClass?: string;
  evidenceScope?: string;
  pinnedBlock?: number;
  pinnedBlockHash?: string;
  files: Array<{
    path: string;
    sha256: string;
    bytes: number;
  }>;
  commands: string[];
  limitations: string[];
};

const ADDRESS_RE =
  /0x[a-fA-F0-9]{40}/g;

function safeSegment(value: string) {
  const cleaned = value
    .replace(
      /[^A-Za-z0-9._-]+/g,
      "-"
    )
    .replace(/^-+|-+$/g, "")
    .slice(0, 100);
  return cleaned || "artifact";
}

function redactAddresses(
  value: string
) {
  return value.replace(
    ADDRESS_RE,
    "[contract-address]"
  );
}

function safeJson(
  value: unknown,
  includeDeploymentAddresses: boolean
) {
  const raw = JSON.stringify(
    value,
    null,
    2
  );
  return includeDeploymentAddresses
    ? raw
    : redactAddresses(raw);
}

async function writeFileWithHash(
  root: string,
  relative: string,
  content: string
) {
  const target = path.resolve(
    root,
    relative
  );
  if (
    target !== root &&
    !target.startsWith(
      root + path.sep
    )
  ) {
    throw new Error(
      "Reproduction artifact escaped package directory."
    );
  }
  await fs.mkdir(
    path.dirname(target),
    {
      recursive: true
    }
  );
  await fs.writeFile(
    target,
    content,
    {
      encoding: "utf8",
      mode: 0o600
    }
  );
  const bytes =
    Buffer.byteLength(content);
  const sha256 =
    createHash("sha256")
      .update(content)
      .digest("hex");
  return {
    path: relative.replaceAll(
      "\\",
      "/"
    ),
    sha256:
      "sha256:" + sha256,
    bytes
  };
}

function findingRunbook(
  opts: ReproductionPackageOptions
) {
  const finding = opts.finding;
  const snapshot =
    opts.snapshot ||
    opts.candidate.ethereum
      .pinnedStateSnapshot;
  const commands: string[] = [];
  if (opts.forkReplaySpec) {
    commands.push(
      "risk-radar replay-fork ./replay-spec.json --confirm-fork"
    );
  }
  commands.push(
    "risk-radar doctor"
  );

  const lines = [
    "# Risk Radar reproduction package",
    "",
    "Protocol: " +
      opts.candidate.label,
    "Finding: " + finding.title,
    "Finding ID: " + finding.id,
    "Severity: " +
      finding.severity,
    "Evidence: " +
      finding.evidenceStrength +
      (finding.evidenceClass
        ? " / " +
          finding.evidenceClass
        : ""),
    "Exploitability: " +
      (finding.exploitabilityVerdict ||
        "UNKNOWN"),
    "",
    "## Evidence boundary",
    "",
    "This package reproduces only the evidence captured for this finding. It is not a protocol-wide safety or exploitability claim.",
    "",
    snapshot
      ? "Pinned Ethereum block: " +
        snapshot.blockNumber +
        " (" +
        snapshot.blockHash +
        ")"
      : "Pinned Ethereum block: not included",
    "",
    "## Finding",
    "",
    finding.description,
    "",
    "## Limitations",
    "",
    ...finding.limitations.map(
      value => "- " + value
    ),
    "",
    "## Commands",
    "",
    ...commands.map(
      value => "    " + value
    ),
    ""
  ];
  return {
    markdown: lines.join("\n"),
    commands
  };
}

export async function writeReproductionPackage(
  opts: ReproductionPackageOptions
) {
  const packageRoot = path.resolve(
    opts.outputDir,
    safeSegment(opts.packageName)
  );
  await fs.mkdir(packageRoot, {
    recursive: true,
    mode: 0o700
  });

  const intelligence =
    opts.intelligence ||
    opts.candidate.ethereum
      .intelligence;
  const snapshot =
    opts.snapshot ||
    opts.candidate.ethereum
      .pinnedStateSnapshot;
  const files: ReproductionPackageManifest["files"] =
    [];
  const write = async (
    relative: string,
    content: string
  ) => {
    files.push(
      await writeFileWithHash(
        packageRoot,
        relative,
        content
      )
    );
  };

  await write(
    "finding.json",
    safeJson(
      opts.finding,
      opts.includeDeploymentAddresses
    )
  );
  await write(
    "candidate.json",
    safeJson(
      opts.candidate,
      opts.includeDeploymentAddresses
    )
  );
  if (intelligence) {
    await write(
      "protocol-intelligence.json",
      safeJson(
        intelligence,
        opts.includeDeploymentAddresses
      )
    );
  }
  if (snapshot) {
    await write(
      "pinned-state.json",
      safeJson(
        snapshot,
        opts.includeDeploymentAddresses
      )
    );
  }
  if (opts.forkReplaySpec) {
    await write(
      "replay-spec.json",
      safeJson(
        opts.forkReplaySpec,
        opts.includeDeploymentAddresses
      )
    );
  }
  for (const artifact of
    opts.formalArtifacts || []) {
    await write(
      path.join(
        "formal",
        safeSegment(artifact.name)
      ),
      artifact.content
    );
  }

  const runbook =
    findingRunbook(opts);
  await write(
    "README.md",
    runbook.markdown
  );

  const manifestWithoutFiles = {
    version: 1 as const,
    createdAt:
      new Date().toISOString(),
    protocolId:
      opts.candidate.id,
    findingId:
      opts.finding.id,
    evidenceStrength:
      opts.finding
        .evidenceStrength,
    evidenceClass:
      opts.finding.evidenceClass,
    evidenceScope:
      opts.finding.evidenceScope,
    pinnedBlock:
      snapshot?.blockNumber,
    pinnedBlockHash:
      snapshot?.blockHash,
    commands:
      runbook.commands,
    limitations: [
      "Every file checksum is calculated after address-redaction policy is applied.",
      opts.includeDeploymentAddresses
        ? "Deployment addresses are included because package creation explicitly requested them."
        : "Deployment addresses are redacted from package JSON by default.",
      "Execution commands target local tooling/pinned forks only; the package does not contain a live-network broadcast workflow."
    ]
  };
  const manifest: ReproductionPackageManifest =
    {
      ...manifestWithoutFiles,
      files: [...files]
    };
  await write(
    "manifest.json",
    JSON.stringify(
      manifest,
      null,
      2
    )
  );

  const finalManifest: ReproductionPackageManifest =
    {
      ...manifestWithoutFiles,
      files
    };
  return {
    root: packageRoot,
    manifest: finalManifest
  };
}
