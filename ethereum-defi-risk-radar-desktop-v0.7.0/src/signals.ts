import type { SignalKind } from "./types.js";

export const SIGNAL_PATTERNS: Array<{
  kind: SignalKind;
  weight: number;
  patterns: RegExp[];
}> = [
  {
    kind: "deprecated",
    weight: 25,
    patterns: [
      /\bdeprecated\b/i,
      /\bdecommissioned\b/i,
      /\bsunset(?:ted)?\b/i,
      /\bno longer supported\b/i
    ]
  },
  {
    kind: "dormant",
    weight: 18,
    patterns: [
      /\bno longer maintained\b/i,
      /\bunmaintained\b/i,
      /\binactive\b/i,
      /\babandoned\b/i,
      /\bmaintenance mode\b/i
    ]
  },
  {
    kind: "migration",
    weight: 14,
    patterns: [
      /\bmigrat(?:e|ed|ion)\b/i,
      /\bupgrade required\b/i,
      /\bmove funds\b/i,
      /\bnew version\b/i
    ]
  },
  {
    kind: "public_audit_finding",
    weight: 22,
    patterns: [
      /\bhigh severity\b/i,
      /\bcritical finding\b/i,
      /\baudit finding\b/i,
      /\bsecurity review\b/i
    ]
  },
  {
    kind: "historical_incident",
    weight: 20,
    patterns: [
      /\bpost[- ]?mortem\b/i,
      /\bsecurity incident\b/i,
      /\bexploit(?:ed)?\b/i,
      /\bhack(?:ed)?\b/i
    ]
  },
  {
    kind: "admin_governance_risk",
    weight: 12,
    patterns: [
      /\badmin key\b/i,
      /\bcentralization risk\b/i,
      /\bprivileged role\b/i,
      /\bguardian role\b/i,
      /\bemergency admin\b/i
    ]
  },
  {
    kind: "archived_code",
    weight: 16,
    patterns: [
      /\brepository archived\b/i,
      /\barchived repository\b/i,
      /\bthis repository has been archived\b/i
    ]
  },
  {
    kind: "upgradeability_surface",
    weight: 8,
    patterns: [
      /\bupgradeable proxy\b/i,
      /\bproxy admin\b/i,
      /\bimplementation contract\b/i
    ]
  }
];

export function detectSignals(text: string) {
  return SIGNAL_PATTERNS
    .filter(group => group.patterns.some(pattern => pattern.test(text)))
    .map(group => ({ kind: group.kind, weight: group.weight }));
}
