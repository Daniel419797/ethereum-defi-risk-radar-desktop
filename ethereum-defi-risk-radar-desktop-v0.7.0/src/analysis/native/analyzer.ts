import { createHash } from "node:crypto";
import { finalizeFinding, stepSeverity } from "../evidence.js";
import type {
  AnalysisFinding, AnalysisGraph, CrossContractCall, DataDependency, GraphEdge, GraphNode,
  Mitigation, MitigationKind, NativeAnalysisReport, SourceLocation, StorageSurface,
  TruncationRecord, WitnessStep
} from "../model.js";

export type SoliditySourceFile = { name: string; content: string };

type FunctionRange = {
  name: string; start: number; open: number; end: number; signature: string; body: string;
  externallyCallable: boolean; parameters: string[];
};

type ReviewRule = {
  id: string; kind: AnalysisFinding["kind"]; severity: AnalysisFinding["severity"];
  title: string; description: string; pattern: RegExp; remediation: string;
  mitigation?: MitigationKind;
};

const FUNCTION_RE = /\b(function|constructor|fallback|receive)\s*([A-Za-z_$][\w$]*)?\s*\(([^)]*)\)[^{;]*\{/g;
const DECLARATION_RE = /^\s*(mapping\s*\([^;]+\)|(?:u?int(?:8|16|32|64|128|256)?|address|bool|bytes\d*|string|[A-Z][A-Za-z0-9_]*(?:\[\])?)(?:\s*\[\s*\])?)\s+(?:(public|private|internal|external|constant|immutable)\s+)*([A-Za-z_$][\w$]*)\s*(?:=|;)/gm;
const ASSIGNMENT_RE = /\b([A-Za-z_$][\w$]*(?:\[[^\]]+\])?)\s*(?:=|\+=|-=|\*=|\/=)\s*([^;]+);/g;
const IDENTIFIER_RE = /\b[A-Za-z_$][\w$]*\b/g;
const CALL_RE = /([A-Za-z_$][\w$]*(?:\[[^\]]+\])?(?:\.[A-Za-z_$][\w$]*)*)\.(delegatecall|staticcall|call|send|transfer)\s*(\{[^}]*\})?\s*\(/g;
const SOURCE_RE = /\b(msg\.sender|msg\.value|msg\.data|tx\.origin|block\.timestamp|block\.number|calldata|_?amount|_?value|_?price|_?recipient|_?target)\b/i;
const SINK_RE = /\.delegatecall\b|\.call\b|\.transfer\b|\.send\b|\bselfdestruct\b|\bsstore\b|\b(owner|admin|implementation|oracle|price|balance|allowance)\s*(?:=|\[)/i;
const RULE_LIMIT = 3;

const REVIEW_RULES: ReviewRule[] = [
  { id: "tx-origin-auth", kind: "authorization", severity: "HIGH", title: "tx.origin authorization surface", description: "Transaction origin participates in authorization logic.", pattern: /\btx\.origin\b/g, remediation: "Authenticate explicit callers and use role-based authorization.", mitigation: "access_control" },
  { id: "external-call", kind: "reentrancy", severity: "MEDIUM", title: "External interaction requires reentrancy ordering review", description: "A low-level call transfers control to another contract.", pattern: /\.call\s*(?:\{|\()/g, remediation: "Use checks-effects-interactions, scoped guards, and pull settlement.", mitigation: "reentrancy_guard" },
  { id: "stale-oracle", kind: "oracle_risk", severity: "HIGH", title: "Oracle freshness validation not evident", description: "A latestRoundData read lacks a complete dominating freshness validation.", pattern: /\blatestRoundData\s*\(/g, remediation: "Validate answer, updatedAt, answeredInRound, decimals, and heartbeat.", mitigation: "staleness_check" },
  { id: "spot-reserve-price", kind: "oracle_risk", severity: "HIGH", title: "AMM reserve/spot-price dependency", description: "Reserve or spot-price data may be manipulable in a short window.", pattern: /\bgetReserves\s*\(|\bslot0\s*\(/g, remediation: "Use a manipulation-resistant TWAP, liquidity floors, and circuit breakers." },
  { id: "raw-ecrecover", kind: "signature_replay", severity: "MEDIUM", title: "Raw signature recovery surface", description: "Raw recovery requires domain, nonce, expiry, signer, and malleability checks.", pattern: /\becrecover\s*\(/g, remediation: "Use audited EIP-712/ECDSA helpers with nonce and expiry enforcement." },
  { id: "division-order", kind: "arithmetic_precision", severity: "MEDIUM", title: "Division-before-multiplication precision surface", description: "Integer division can truncate before multiplication.", pattern: /\b[A-Za-z_$][\w$]*\s*\/\s*[^;]+\s*\*/g, remediation: "Define rounding direction and reorder arithmetic where safe." },
  { id: "unbounded-loop", kind: "denial_of_service", severity: "MEDIUM", title: "Potentially user/state-bounded loop", description: "The loop bound may grow with input or state.", pattern: /\b(?:for|while)\s*\([^)]*(?:\.length|[A-Za-z_$][\w$]*)[^)]*\)/g, remediation: "Bound work per transaction or paginate." },
  { id: "delegatecall-upgrade", kind: "upgradeability", severity: "HIGH", title: "Delegatecall upgrade boundary", description: "Delegatecall couples authorization, target trust, initialization, and storage layout.", pattern: /\.delegatecall\s*\(/g, remediation: "Use standardized proxy slots, guarded upgrades, locks, and layout diffs.", mitigation: "access_control" },
  { id: "deadline-missing", kind: "mev_ordering", severity: "MEDIUM", title: "Swap/order execution surface", description: "Swap execution needs an explicit deadline and slippage bound.", pattern: /\b(?:swap|amountOutMin|minAmountOut)\b/g, remediation: "Require a user-defined deadline and minimum output.", mitigation: "deadline_check" },
  { id: "governance-execute", kind: "governance_risk", severity: "MEDIUM", title: "Governance execution surface", description: "Governance execution changes protocol trust boundaries.", pattern: /\b(?:propose|castVote|quorum|executeProposal|timelock)\b/g, remediation: "Test snapshots, timelock, cancellation, replay protection, and emergency powers." },
  { id: "bridge-message", kind: "bridge_messaging", severity: "HIGH", title: "Cross-domain message surface", description: "Cross-chain messages require origin, sender, nonce, finality, and replay validation.", pattern: /\b(?:sendMessage|processMessage|xDomainMessageSender|messageNonce|bridge)\b/g, remediation: "Bind source chain, sender, nonce, payload, and finality." },
  { id: "unsafe-token-call", kind: "token_integration", severity: "MEDIUM", title: "ERC-20 return-value compatibility surface", description: "Direct token calls may mishandle false or missing return values.", pattern: /\b(?:IERC20|ERC20)\s*\([^)]*\)\.(?:transfer|transferFrom|approve)\s*\(/g, remediation: "Use safe wrappers and account for non-standard token behavior.", mitigation: "return_value_check" }
];

function lineAt(content: string, index: number) { return content.slice(0, index).split("\n").length; }
function location(file: SoliditySourceFile, index: number): SourceLocation {
  const lastNewline = file.content.lastIndexOf("\n", index);
  return { file: file.name, line: lineAt(file.content, index), column: index - lastNewline };
}
function stableId(...parts: string[]) { return createHash("sha256").update(parts.join("\0")).digest("hex").slice(0, 16); }
function identifiers(value: string) {
  const ignored = new Set(["true", "false", "address", "uint", "uint256", "int", "int256", "this", "msg", "block", "tx"]);
  return [...new Set(value.match(IDENTIFIER_RE) ?? [])].filter(value => !ignored.has(value));
}
function matchingBrace(content: string, opening: number) {
  let depth = 0; let quote = "";
  for (let i = opening; i < content.length; i += 1) {
    const char = content[i];
    if (quote) { if (char === quote && content[i - 1] !== "\\") quote = ""; continue; }
    if (char === '"' || char === "'") { quote = char; continue; }
    if (char === "{") depth += 1;
    if (char === "}" && --depth === 0) return i;
  }
  return content.length - 1;
}

function functionRanges(file: SoliditySourceFile): FunctionRange[] {
  return [...file.content.matchAll(FUNCTION_RE)].map(match => {
    const start = match.index ?? 0; const open = file.content.indexOf("{", start); const end = matchingBrace(file.content, open);
    const signature = file.content.slice(start, open); const kind = match[1];
    const name = kind === "function" ? (match[2] || "anonymous") : kind;
    const parameters = String(match[3] ?? "").split(",").map(value => value.trim().split(/\s+/).at(-1) ?? "").filter(Boolean);
    return { name, start, open, end, signature, body: file.content.slice(open + 1, end), externallyCallable: kind !== "function" || /\b(public|external)\b/.test(signature), parameters };
  });
}

function externallyReachableFunctions(ranges: FunctionRange[]) {
  const reachable = new Set(ranges.filter(fn => fn.externallyCallable).map(fn => fn.name));
  let changed = true;
  while (changed) {
    changed = false;
    for (const caller of ranges.filter(fn => reachable.has(fn.name))) for (const callee of ranges) {
      if (!reachable.has(callee.name) && new RegExp(`\\b${callee.name}\\s*\\(`).test(caller.body)) { reachable.add(callee.name); changed = true; }
    }
  }
  return reachable;
}

function dominators(nodes: GraphNode[], edges: GraphEdge[], entryId: string) {
  const ids = nodes.map(node => node.id); const all = new Set(ids);
  const sets = new Map<string, Set<string>>(ids.map(id => [id, id === entryId ? new Set([id]) : new Set(all)]));
  let changed = true;
  while (changed) {
    changed = false;
    for (const id of ids.filter(value => value !== entryId)) {
      const predecessors = edges.filter(edge => edge.to === id).map(edge => sets.get(edge.from)!).filter(Boolean);
      const next = predecessors.length ? new Set([...predecessors[0]].filter(value => predecessors.every(set => set.has(value)))) : new Set<string>();
      next.add(id); const current = sets.get(id)!;
      if (next.size !== current.size || [...next].some(value => !current.has(value))) { sets.set(id, next); changed = true; }
    }
  }
  const immediate: Record<string, string | null> = { [entryId]: null };
  for (const id of ids.filter(value => value !== entryId)) {
    const candidates = [...sets.get(id)!].filter(value => value !== id);
    immediate[id] = candidates.sort((a, b) => sets.get(b)!.size - sets.get(a)!.size)[0] ?? null;
  }
  return immediate;
}

function buildGraph(file: SoliditySourceFile, fn: FunctionRange, externallyReachable: boolean): AnalysisGraph {
  const entryId = `${fn.name}:entry`; const exitId = `${fn.name}:exit`;
  const nodes: GraphNode[] = [{ id: entryId, kind: "entry", label: `${fn.name} entry`, location: location(file, fn.start), reachable: externallyReachable }];
  const edges: GraphEdge[] = []; let previous = entryId; let counter = 0;
  const controls = [...fn.body.matchAll(/\b(if|require|assert|for|while|revert|return)\b|\.(delegatecall|staticcall|call|send|transfer)\s*(?:\{|\()/g)];
  for (const control of controls) {
    const absolute = fn.open + 1 + (control.index ?? 0); const keyword = control[1] || control[2] || "statement";
    const base = `${fn.name}:${++counter}`;
    if (["if", "require", "assert"].includes(keyword)) {
      const branch: GraphNode = { id: base, kind: "branch", label: keyword, location: location(file, absolute), reachable: true };
      const yes: GraphNode = { id: `${base}:true`, kind: "statement", label: `${keyword} true`, reachable: !/\b(?:if|require|assert)\s*\(\s*false\s*\)/.test(fn.body.slice(control.index ?? 0)) };
      const join: GraphNode = { id: `${base}:join`, kind: "join", label: `${keyword} join`, reachable: true };
      nodes.push(branch, yes, join); edges.push({ from: previous, to: base, kind: "next" }, { from: base, to: yes.id, kind: "true" }, { from: base, to: join.id, kind: "false" }, { from: yes.id, to: join.id, kind: "next" }); previous = join.id;
    } else if (["for", "while"].includes(keyword)) {
      const loop: GraphNode = { id: base, kind: "loop", label: keyword, location: location(file, absolute), reachable: true };
      const body: GraphNode = { id: `${base}:body`, kind: "statement", label: `${keyword} body`, reachable: true };
      const out: GraphNode = { id: `${base}:exit`, kind: "loop_exit", label: `${keyword} exit`, reachable: true };
      nodes.push(loop, body, out); edges.push({ from: previous, to: base, kind: "next" }, { from: base, to: body.id, kind: "true" }, { from: body.id, to: base, kind: "back_edge" }, { from: base, to: out.id, kind: "loop_exit" }); previous = out.id;
    } else {
      const abrupt = keyword === "return" || keyword === "revert";
      const kind: GraphNode["kind"] = keyword === "return" ? "return" : keyword === "revert" ? "revert" : control[2] ? "call" : "statement";
      nodes.push({ id: base, kind, label: keyword, location: location(file, absolute), reachable: true });
      edges.push({ from: previous, to: base, kind: control[2] === "delegatecall" ? "delegate_call" : control[2] ? "external_call" : "next" });
      previous = base; if (abrupt) previous = "";
    }
  }
  nodes.push({ id: exitId, kind: "exit", label: `${fn.name} exit`, location: location(file, fn.end), reachable: true });
  if (previous) edges.push({ from: previous, to: exitId, kind: "next" });
  for (const node of nodes.filter(node => node.kind === "return" || node.kind === "revert")) edges.push({ from: node.id, to: exitId, kind: "abrupt" });
  const reachable = new Set(externallyReachable ? [entryId] : []); let changed = true;
  while (changed) { changed = false; for (const edge of edges) if (reachable.has(edge.from) && !reachable.has(edge.to) && nodes.find(node => node.id === edge.to)?.reachable !== false) { reachable.add(edge.to); changed = true; } }
  for (const node of nodes) node.reachable = reachable.has(node.id);
  return { id: `${file.name}:${fn.name}`, nodes, edges, entryId, immediateDominators: dominators(nodes, edges, entryId), unreachableNodeIds: nodes.filter(node => !node.reachable).map(node => node.id) };
}

function enclosing(ranges: FunctionRange[], index: number) { return ranges.find(range => index >= range.start && index <= range.end); }
function mitigation(fn: FunctionRange | undefined, kind: MitigationKind, file: SoliditySourceFile, sinkIndex?: number): Mitigation | undefined {
  if (!fn) return undefined; const text = `${fn.signature} ${fn.body}`;
  const patterns: Record<MitigationKind, RegExp> = {
    access_control: /\b(?:onlyOwner|onlyRole|_checkRole)\b|require\s*\(\s*msg\.sender\s*==/,
    reentrancy_guard: /\bnonReentrant\b|\b_reentrancyGuardEntered\b/,
    checked_arithmetic: /\bunchecked\b|SafeMath/,
    deadline_check: /require\s*\([^)]*(?:deadline|block\.timestamp)[^)]*(?:>=|<=|<|>)/,
    slippage_check: /require\s*\([^)]*(?:amountOutMin|minAmountOut|slippage)/,
    staleness_check: /updatedAt[\s\S]*require|require\s*\([^)]*updatedAt|answeredInRound[\s\S]*require|require\s*\([^)]*answeredInRound/,
    return_value_check: /\b(?:safeTransfer|safeTransferFrom|SafeERC20)\b|require\s*\([^)]*(?:transfer|success|ok)/
  };
  const match = text.match(patterns[kind]);
  if (!match) return undefined;
  const offset = text.indexOf(match[0]);
  const absolute = offset < fn.signature.length ? fn.start + offset : fn.open + 1 + offset - fn.signature.length - 1;
  if (sinkIndex !== undefined && absolute > sinkIndex && kind !== "staleness_check") return undefined;
  return { kind, evidence: match[0].slice(0, 160), location: location(file, absolute) };
}

export function analyzeSoliditySources(files: SoliditySourceFile[]): NativeAnalysisReport {
  const graphs: AnalysisGraph[] = []; const dependencies: DataDependency[] = []; const storage: StorageSurface[] = [];
  const calls: CrossContractCall[] = []; const findings: AnalysisFinding[] = []; const truncations: TruncationRecord[] = [];
  for (const file of files) {
    const ranges = functionRanges(file); const externallyReachable = externallyReachableFunctions(ranges); graphs.push(...ranges.map(fn => buildGraph(file, fn, externallyReachable.has(fn.name))));
    let slot = 0;
    for (const match of file.content.matchAll(DECLARATION_RE)) {
      const index = match.index ?? 0; if (enclosing(ranges, index)) continue;
      const typeHint = match[1]; const variable = match[3]; const immutable = /\b(?:constant|immutable)\b/.test(match[0]);
      storage.push({ variable, declaredAt: location(file, index), typeHint, visibility: match[2] || undefined, approximateSlot: immutable ? -1 : slot++, dynamic: /mapping|string|\[\]/.test(typeHint), writtenBy: [], occupiesSlot: !immutable });
    }
    const definitions = new Map<string, { at: SourceLocation; dependsOn: string[]; fn?: FunctionRange }>();
    for (const match of file.content.matchAll(ASSIGNMENT_RE)) {
      const index = match.index ?? 0; if (match[0].includes("=>")) continue;
      const lhs = match[1].replace(/\[.*$/, ""); const rhs = match[2]; const at = location(file, index); const fn = enclosing(ranges, index);
      const dependsOn = identifiers(rhs).filter(id => id !== lhs); definitions.set(lhs, { at, dependsOn, fn });
      const state = storage.find(item => item.variable === lhs); if (state && fn) state.writtenBy.push(fn.name);
      dependencies.push({ variable: lhs, definedAt: at, usedAt: [], dependsOn, stateVariable: Boolean(state), blockId: `${fn?.name ?? "contract"}:assignment`, transitive: true });
      const inherited = dependsOn.some(id => SOURCE_RE.test(id) || definitions.get(id)?.dependsOn.some(source => SOURCE_RE.test(source)));
      const sourceSymbol = dependsOn.find(id => SOURCE_RE.test(id) || fn?.parameters.includes(id));
      const sink = SINK_RE.test(match[0]) || (match[1].includes("[") && Boolean(state));
      const guard = mitigation(fn, /owner|admin|implementation|delegatecall/i.test(match[0]) ? "access_control" : "checked_arithmetic", file, index);
      if ((SOURCE_RE.test(rhs) || inherited || sourceSymbol) && sink) {
        const witness: WitnessStep[] = [
          { symbol: sourceSymbol ?? "external input", role: "source", location: at },
          ...dependsOn.filter(value => value !== sourceSymbol).map(symbol => ({ symbol, role: "propagation" as const, location: definitions.get(symbol)?.at ?? at })),
          { symbol: lhs, role: "sink", location: at }
        ];
        findings.push(finalizeFinding({ id: stableId("taint", file.name, String(at.line), lhs), kind: "taint", engine: "native", severity: guard ? "LOW" : /delegatecall|implementation|owner|admin/i.test(match[0]) ? "HIGH" : "MEDIUM", evidenceStrength: "STRUCTURAL", title: `Untrusted value may reach sensitive sink: ${lhs}`, description: guard ? "A source-to-sink path exists, but a function-scoped mitigation was observed." : "An externally influenced value reaches a sensitive state expression without a recognized dominating mitigation.", remediation: "Validate authorization, bounds, targets, and state-transition ordering.", primaryLocation: at, evidencePath: witness.map(step => step.symbol), witnessPath: witness, mitigations: guard ? [guard] : [], reachableFromExternalEntry: fn ? externallyReachable.has(fn.name) : false }));
      }
    }
    for (const match of file.content.matchAll(CALL_RE)) {
      const index = match.index ?? 0; const operation = match[2] as CrossContractCall["operation"]; const fn = enclosing(ranges, index);
      const nearby = file.content.slice(Math.max(fn?.open ?? 0, index - 180), Math.min(file.content.length, index + 500));
      const checked = /\b(?:success|ok)\b\s*(?:,|=)|require\s*\(/.test(nearby); const guard = mitigation(fn, "reentrancy_guard", file, index);
      const later = fn ? fn.body.slice(Math.max(0, index - fn.open)).match(ASSIGNMENT_RE) : null;
      calls.push({ caller: fn?.name ?? "<contract>", functionName: fn?.name, targetExpression: match[1], operation, valueBearing: operation === "send" || operation === "transfer" || /\bvalue\s*:/.test(match[3] || ""), location: location(file, index), returnValueChecked: checked, guardedBy: guard ? [guard] : [], stateWritesAfter: later ? [later[1].replace(/\[.*$/, "")] : [] });
      if ((operation === "call" || operation === "delegatecall") && !checked) {
        const at = location(file, index); findings.push(finalizeFinding({ id: stableId("call", file.name, String(at.line), operation), kind: "cross_contract_calls", engine: "native", severity: guard ? "LOW" : operation === "delegatecall" ? "HIGH" : "MEDIUM", evidenceStrength: "STRUCTURAL", title: `Unchecked ${operation} result`, description: "The low-level call result is not checked in its function.", primaryLocation: at, mitigations: guard ? [guard] : [], reachableFromExternalEntry: fn ? externallyReachable.has(fn.name) : false }));
      }
    }
    if (/\bdelegatecall\b/.test(file.content) && /\b(implementation|admin|owner)\b/.test(file.content)) findings.push(finalizeFinding({ id: stableId("storage", file.name, "proxy"), kind: "storage_state", engine: "native", severity: "HIGH", evidenceStrength: "HEURISTIC", title: "Proxy storage-layout review required", description: "Delegatecall and implementation/admin state coexist; token parsing cannot prove layout compatibility." }));
    for (const rule of REVIEW_RULES) {
      const matches = [...file.content.matchAll(new RegExp(rule.pattern.source, rule.pattern.flags))];
      if (matches.length > RULE_LIMIT) truncations.push({ ruleId: rule.id, dropped: matches.length - RULE_LIMIT, limit: RULE_LIMIT });
      for (const match of matches.slice(0, RULE_LIMIT)) {
        const index = match.index ?? 0; const fn = enclosing(ranges, index); if (!fn) continue; const observed = rule.mitigation ? mitigation(fn, rule.mitigation, file, index) : undefined;
        if (rule.id === "stale-oracle" && observed) continue;
        const reachable = fn ? externallyReachable.has(fn.name) : false; const severity = observed || !reachable ? stepSeverity(rule.severity, -1) : rule.severity;
        findings.push(finalizeFinding({ id: stableId(rule.id, file.name, String(location(file, index).line)), kind: rule.kind, engine: "native", severity, evidenceStrength: "HEURISTIC", title: rule.title, description: rule.description, remediation: rule.remediation, primaryLocation: location(file, index), mitigations: observed ? [observed] : [], reachableFromExternalEntry: reachable }));
      }
    }
  }
  for (const dependency of dependencies) for (const other of dependencies) if (other.dependsOn.includes(dependency.variable)) dependency.usedAt.push(other.definedAt);
  return { engine: "native", analyzedAt: new Date().toISOString(), filesAnalyzed: files.length, functionsAnalyzed: graphs.length, graphs, dependencies, storage, calls, findings, truncations, parseBasis: "tokens", layoutAuthoritative: false, partial: truncations.length > 0, limitations: ["Token-aware front end: reachability, dominance, and scoped mitigations are conservative; compiler IR remains authoritative.", "A structural or heuristic finding is a review surface, not proof of exploitability."], notes: truncations.length ? ["One or more rule result sets were capped; see truncations for dropped counts."] : [] };
}
