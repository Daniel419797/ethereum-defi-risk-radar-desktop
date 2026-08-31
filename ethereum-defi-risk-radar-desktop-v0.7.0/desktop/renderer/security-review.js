(() => {
  "use strict";

  const api = window.riskRadar;
  if (!api) return;

  const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const EVIDENCE_ORDER = { REPRODUCED_FORK: 0, REPRODUCED_MODEL: 1, EXECUTED: 2, STRUCTURAL: 3, HEURISTIC: 4 };
  const LEGACY_SEVERITY = { HIGH_REVIEW: "HIGH", MEDIUM: "MEDIUM", LOW: "LOW", INFO: "INFO" };
  const SOURCE_REVIEW_ONLY_EXCLUSIONS = new Set(["reentrancy_guard_present"]);
  const LEGACY_TO_ADVANCED_KIND = {
    tx_origin: ["authorization"],
    delegatecall: ["upgradeability", "cross_contract_calls"],
    low_level_call: ["cross_contract_calls", "reentrancy"],
    value_transfer_call: ["cross_contract_calls", "reentrancy"],
    privileged_access: ["authorization", "governance_risk"],
    upgradeability_pattern: ["upgradeability"],
    initializer_pattern: ["upgradeability"],
    unchecked_block: ["arithmetic_precision"],
    signature_recovery: ["signature_replay"],
    oracle_price_surface: ["oracle_risk"],
    legacy_solidity: ["arithmetic_precision"]
  };

  const reviewState = { candidates: [], paths: null, renderKey: "", renderQueued: false };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function humanize(value) {
    return String(value ?? "")
      .replaceAll("_", " ")
      .toLowerCase()
      .replace(/\b\w/g, letter => letter.toUpperCase());
  }

  function evidenceKey(finding) {
    if (finding.evidenceStrength === "REPRODUCED") {
      const scope = finding.evidenceScope || finding.counterexample?.scope;
      return scope === "fork" ? "REPRODUCED_FORK" : "REPRODUCED_MODEL";
    }
    if (finding.evidenceStrength === "EXECUTED") return "EXECUTED";
    if (finding.evidenceStrength === "STRUCTURAL") return "STRUCTURAL";
    return "HEURISTIC";
  }

  function evidenceLabel(finding) {
    const key = finding.evidenceKey || evidenceKey(finding);
    if (key === "REPRODUCED_FORK") return "Reproduced · fork";
    if (key === "REPRODUCED_MODEL") return "Reproduced · model";
    if (key === "EXECUTED") return "Executed";
    if (key === "STRUCTURAL") return "Structural";
    return "Heuristic";
  }

  function sourceFindingShadowedByAdvanced(finding, advanced) {
    const mappedKinds = LEGACY_TO_ADVANCED_KIND[finding.kind];
    if (!mappedKinds?.length) return false;
    return advanced.some(candidate => {
      const location = candidate.primaryLocation;
      return mappedKinds.includes(candidate.kind) &&
        location?.file === finding.file &&
        Math.abs(Number(location.line || 0) - Number(finding.line || 0)) <= 2;
    });
  }

  function collectFindings(candidate) {
    const findings = [];
    for (const inspection of candidate?.ethereum?.sourceInspections || []) {
      const contractName = inspection.contractName || inspection.contractRefId || "Verified contract";
      const contractRefId = inspection.contractRefId || "unknown";
      const advanced = inspection.inspection?.advancedAnalysis?.findings || [];

      for (const finding of advanced) {
        findings.push({
          ...finding,
          sourceLayer: "advanced",
          contractName,
          contractRefId,
          compilerVersion: inspection.compilerVersion || "",
          proxy: Boolean(inspection.proxy),
          severity: SEVERITY_ORDER[finding.severity] === undefined ? "INFO" : finding.severity,
          file: finding.primaryLocation?.file || "Structural analysis",
          line: Number(finding.primaryLocation?.line || 0),
          column: Number(finding.primaryLocation?.column || 0),
          evidenceKey: evidenceKey(finding)
        });
      }

      for (const finding of inspection.inspection?.findings || []) {
        if (SOURCE_REVIEW_ONLY_EXCLUSIONS.has(finding.kind)) continue;
        if (sourceFindingShadowedByAdvanced(finding, advanced)) continue;
        findings.push({
          id: `source:${contractRefId}:${finding.kind}:${finding.file}:${finding.line}`,
          kind: finding.kind,
          engine: "native",
          severity: LEGACY_SEVERITY[finding.severity] || "INFO",
          confidence: "LOW",
          evidenceStrength: "HEURISTIC",
          evidenceKey: "HEURISTIC",
          title: finding.title,
          description: finding.description,
          limitations: ["Pattern-level source review signal; presence alone does not establish exploitability."],
          sourceLayer: "source-review",
          contractName,
          contractRefId,
          compilerVersion: inspection.compilerVersion || "",
          proxy: Boolean(inspection.proxy),
          file: finding.file || "Verified source",
          line: Number(finding.line || 0),
          column: 0
        });
      }
    }

    const seen = new Set();
    return findings.filter(finding => {
      const key = [
        finding.contractRefId,
        finding.kind,
        finding.file,
        finding.line,
        finding.title,
        finding.evidenceKey,
        finding.evidenceScope || finding.counterexample?.scope || ""
      ].join("|");
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  function completeness(candidate) {
    let partial = false;
    let dropped = 0;
    let truncatedSourceCharacters = 0;
    const notices = [];

    for (const inspection of candidate?.ethereum?.sourceInspections || []) {
      const sourceInspection = inspection.inspection || {};
      const advanced = sourceInspection.advancedAnalysis || {};
      const advancedDropped = (advanced.truncations || []).reduce((sum, item) => sum + Number(item.dropped || 0), 0);
      const legacyDropped = Number(sourceInspection.truncatedFindingCount || 0);
      const sourceDropped = Number(sourceInspection.truncatedSourceCharacters || 0);
      dropped += advancedDropped + legacyDropped;
      truncatedSourceCharacters += sourceDropped;
      partial = partial || Boolean(advanced.partial || sourceInspection.partial || sourceInspection.sourceTruncated || advancedDropped || legacyDropped);

      const name = inspection.contractName || inspection.contractRefId || "Contract";
      if (advancedDropped) notices.push(`${name}: ${advancedDropped} advanced findings omitted by configured caps.`);
      if (legacyDropped) notices.push(`${name}: ${legacyDropped} source-review signals omitted by configured caps.`);
      if (sourceDropped) notices.push(`${name}: ${sourceDropped} source characters were outside the configured analysis budget.`);
    }

    return { partial, dropped, truncatedSourceCharacters, notices };
  }

  function assessment(findings, completenessState) {
    const counts = {
      severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      evidence: { REPRODUCED_FORK: 0, REPRODUCED_MODEL: 0, EXECUTED: 0, STRUCTURAL: 0, HEURISTIC: 0 }
    };
    for (const finding of findings) {
      counts.severity[finding.severity] = (counts.severity[finding.severity] || 0) + 1;
      counts.evidence[finding.evidenceKey] = (counts.evidence[finding.evidenceKey] || 0) + 1;
    }

    const highestSeverity = Object.keys(SEVERITY_ORDER).find(level => counts.severity[level] > 0) || "INFO";
    const strongestEvidence = Object.keys(EVIDENCE_ORDER).find(level => counts.evidence[level] > 0) || "HEURISTIC";
    let label = "No findings in analyzed scope";
    let tone = "neutral";
    if (findings.length) {
      if (strongestEvidence === "REPRODUCED_FORK") { label = "Reproduced on pinned fork"; tone = "critical"; }
      else if (strongestEvidence === "REPRODUCED_MODEL") { label = "Reproduced in bounded model"; tone = "high"; }
      else if (strongestEvidence === "EXECUTED") { label = "Executed counterexample captured"; tone = "high"; }
      else if (strongestEvidence === "STRUCTURAL") { label = "Structural security findings"; tone = "review"; }
      else { label = "Heuristic review signals"; tone = "review"; }
    }
    if (completenessState.partial) label += " · partial analysis";
    return { counts, highestSeverity, strongestEvidence, label, tone };
  }

  function currentCandidate() {
    const screen = document.getElementById("screen-candidate");
    if (!screen || screen.classList.contains("hidden")) return null;
    const title = document.getElementById("candidate-title")?.textContent?.trim();
    const hostname = document.getElementById("candidate-host-link")?.textContent?.replace("↗", "").trim();
    if (!title) return null;
    return reviewState.candidates.find(candidate => candidate.label === title && (!hostname || candidate.hostname === hostname)) ||
      reviewState.candidates.find(candidate => candidate.label === title) || null;
  }

  function stat(label, value, emphasis = "") {
    const card = el("article", `security-stat ${emphasis}`.trim());
    card.append(el("small", "", label), el("strong", "", value));
    return card;
  }

  function badge(text, kind) {
    return el("span", `security-badge ${kind}`, text);
  }

  function metadataRow(label, value) {
    const row = el("div", "security-meta-row");
    row.append(el("span", "", label), el("strong", "", value));
    return row;
  }

  function renderFinding(finding) {
    const card = el("article", `security-finding severity-${finding.severity.toLowerCase()}`);
    const heading = el("div", "security-finding-heading");
    const titleWrap = el("div");
    const badges = el("div", "security-badge-row");
    badges.append(
      badge(finding.severity, `severity ${finding.severity.toLowerCase()}`),
      badge(evidenceLabel(finding), `evidence ${finding.evidenceKey.toLowerCase()}`),
      badge(humanize(finding.kind), "kind")
    );
    titleWrap.append(badges, el("h3", "", finding.title));

    const location = finding.line > 0 ? `${finding.file}:${finding.line}${finding.column ? `:${finding.column}` : ""}` : finding.file;
    const locationWrap = el("div", "security-location");
    locationWrap.append(el("code", "", location));
    heading.append(titleWrap, locationWrap);

    const meta = el("div", "security-meta-grid");
    meta.append(
      metadataRow("Confidence", humanize(finding.confidence || "unknown")),
      metadataRow("Engine", humanize(finding.engine || "native")),
      metadataRow("Reachable externally", finding.reachableFromExternalEntry === undefined ? "Unknown" : finding.reachableFromExternalEntry ? "Yes" : "No"),
      metadataRow("Source layer", finding.sourceLayer === "advanced" ? "Structural analyzer" : "Pattern review")
    );
    card.append(heading, el("p", "security-description", finding.description), meta);

    if (finding.remediation) {
      const guidance = el("div", "security-guidance");
      guidance.append(el("strong", "", "Recommended remediation"), el("p", "", finding.remediation));
      card.append(guidance);
    }

    if (finding.mitigations?.length) {
      const section = el("div", "security-inline-section");
      section.append(el("strong", "", "Detected mitigations"));
      const chips = el("div", "security-chip-row");
      for (const mitigation of finding.mitigations) chips.append(badge(humanize(mitigation.kind), "mitigation"));
      section.append(chips);
      card.append(section);
    }

    if (finding.witnessPath?.length) {
      const details = el("details", "security-details");
      details.append(el("summary", "", `Witness path · ${finding.witnessPath.length} step(s)`));
      const list = el("ol", "security-witness-list");
      for (const step of finding.witnessPath) {
        const item = el("li");
        item.append(
          el("strong", "", `${humanize(step.role)}: ${step.symbol}`),
          el("code", "", `${step.location?.file || "source"}:${step.location?.line || 0}`)
        );
        if (step.detail) item.append(el("span", "", step.detail));
        list.append(item);
      }
      details.append(list);
      card.append(details);
    }

    if (finding.counterexample) {
      const details = el("details", "security-details counterexample");
      details.append(el("summary", "", `Counterexample · ${finding.counterexample.sequence?.length || 0} ordered step(s)`));
      const body = el("div", "security-counterexample");
      body.append(metadataRow("Observed violation", finding.counterexample.observedViolation || "Captured violation"));
      if (finding.counterexample.seed !== undefined) body.append(metadataRow("Seed", finding.counterexample.seed));
      if (finding.counterexample.blockNumber !== undefined) body.append(metadataRow("Pinned block", finding.counterexample.blockNumber));
      if (finding.counterexample.invariantId) body.append(metadataRow("Invariant", finding.counterexample.invariantId));
      if (finding.counterexample.sequence?.length) {
        const sequence = el("ol", "security-sequence");
        for (const step of finding.counterexample.sequence.slice(0, 50)) sequence.append(el("li", "", String(step)));
        if (finding.counterexample.sequence.length > 50) {
          sequence.append(el("li", "", `${finding.counterexample.sequence.length - 50} additional steps omitted from the UI.`));
        }
        body.append(sequence);
      }
      details.append(body);
      card.append(details);
    }

    if (finding.limitations?.length) {
      const details = el("details", "security-details limitations");
      details.append(el("summary", "", "Limitations"));
      const list = el("ul");
      for (const limitation of finding.limitations) list.append(el("li", "", limitation));
      details.append(list);
      card.append(details);
    }
    return card;
  }

  function createToolbar(findings, onChange) {
    const toolbar = el("div", "security-review-toolbar");
    const severity = el("select");
    const evidence = el("select");
    for (const value of ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]) {
      const option = el("option", "", value === "ALL" ? "All severities" : humanize(value));
      option.value = value;
      severity.append(option);
    }
    for (const value of ["ALL", "REPRODUCED_FORK", "REPRODUCED_MODEL", "EXECUTED", "STRUCTURAL", "HEURISTIC"]) {
      const label = value === "ALL" ? "All evidence" : value === "REPRODUCED_FORK" ? "Reproduced · fork" : value === "REPRODUCED_MODEL" ? "Reproduced · model" : humanize(value);
      const option = el("option", "", label);
      option.value = value;
      evidence.append(option);
    }
    const apply = () => onChange({ severity: severity.value, evidence: evidence.value });
    severity.addEventListener("change", apply);
    evidence.addEventListener("change", apply);
    toolbar.append(severity, evidence, el("span", "security-toolbar-count", `${findings.length} normalized security finding(s)`));
    return toolbar;
  }

  function renderFindingGroups(root, findings, filters) {
    root.replaceChildren();
    const filtered = findings
      .filter(finding => filters.severity === "ALL" || finding.severity === filters.severity)
      .filter(finding => filters.evidence === "ALL" || finding.evidenceKey === filters.evidence)
      .sort((a, b) =>
        (EVIDENCE_ORDER[a.evidenceKey] ?? 99) - (EVIDENCE_ORDER[b.evidenceKey] ?? 99) ||
        (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99) ||
        `${a.contractName}:${a.file}:${a.line}`.localeCompare(`${b.contractName}:${b.file}:${b.line}`)
      );

    if (!filtered.length) {
      const empty = el("div", "security-empty");
      empty.append(el("strong", "", "No security findings match these filters."), el("span", "", "Change severity or evidence filters to broaden the view."));
      root.append(empty);
      return;
    }

    const contracts = new Map();
    for (const finding of filtered) {
      const key = `${finding.contractRefId}:${finding.contractName}`;
      const rows = contracts.get(key) || [];
      rows.push(finding);
      contracts.set(key, rows);
    }

    for (const rows of contracts.values()) {
      const group = el("section", "security-contract-group");
      const first = rows[0];
      const header = el("div", "security-contract-header");
      const copy = el("div");
      copy.append(el("h3", "", first.contractName), el("small", "", `${first.compilerVersion || "Compiler unknown"}${first.proxy ? " · proxy" : ""}`));
      header.append(copy, badge(`${rows.length} finding${rows.length === 1 ? "" : "s"}`, "contract-count"));
      group.append(header);
      for (const finding of rows) group.append(renderFinding(finding));
      root.append(group);
    }
  }

  function renderReview(candidate) {
    const panel = document.getElementById("candidate-tab-findings");
    if (!panel) return;

    const findings = collectFindings(candidate);
    const completenessState = completeness(candidate);
    const summary = assessment(findings, completenessState);
    const fingerprint = findings.map(finding => `${finding.id}:${finding.severity}:${finding.evidenceKey}:${finding.file}:${finding.line}`).join(";");
    const renderKey = `${candidate.id}:${fingerprint}:${completenessState.dropped}:${reviewState.paths?.securityReviewPath || ""}:${reviewState.paths?.findingsCsvPath || ""}`;
    if (reviewState.renderKey === renderKey && document.getElementById("security-review-shell")) return;
    reviewState.renderKey = renderKey;

    for (const id of ["findings-severity-metrics", "candidate-findings-list", "candidate-findings-empty"]) {
      document.getElementById(id)?.classList.add("security-review-legacy-hidden");
    }
    panel.querySelector(".findings-toolbar")?.classList.add("security-review-legacy-hidden");
    document.getElementById("security-review-shell")?.remove();

    const shell = el("section", "security-review-shell");
    shell.id = "security-review-shell";
    const hero = el("article", `security-assessment-hero ${summary.tone}`);
    const heroCopy = el("div");
    heroCopy.append(
      el("small", "security-eyebrow", "Security assessment"),
      el("h2", "", summary.label),
      el("p", "", "Severity describes potential impact. Evidence strength describes how strongly the finding has been demonstrated. These are intentionally kept separate.")
    );
    const heroBadges = el("div", "security-hero-badges");
    heroBadges.append(
      badge(`Highest severity · ${summary.highestSeverity}`, `severity ${summary.highestSeverity.toLowerCase()}`),
      badge(`Strongest evidence · ${summary.strongestEvidence === "REPRODUCED_FORK" ? "Reproduced fork" : summary.strongestEvidence === "REPRODUCED_MODEL" ? "Reproduced model" : humanize(summary.strongestEvidence)}`, "evidence-summary")
    );
    hero.append(heroCopy, heroBadges);

    const stats = el("div", "security-stat-grid");
    stats.append(
      stat("Critical", summary.counts.severity.CRITICAL, "critical"),
      stat("High", summary.counts.severity.HIGH, "high"),
      stat("Executed / reproduced", summary.counts.evidence.EXECUTED + summary.counts.evidence.REPRODUCED_MODEL + summary.counts.evidence.REPRODUCED_FORK, "evidence"),
      stat("Structural", summary.counts.evidence.STRUCTURAL),
      stat("Heuristic", summary.counts.evidence.HEURISTIC),
      stat("Contracts inspected", candidate.ethereum?.sourceContractsInspected || 0)
    );

    const evidenceLadder = el("article", "security-evidence-ladder");
    evidenceLadder.append(el("h3", "", "Evidence ledger"));
    const ladder = el("div", "security-ladder-grid");
    for (const [label, count, description] of [
      ["Reproduced · fork", summary.counts.evidence.REPRODUCED_FORK, "Pinned fork replay; evidence about deployed bytecode at that block."],
      ["Reproduced · model", summary.counts.evidence.REPRODUCED_MODEL, "Deterministic replay in the bounded protocol/economic model."],
      ["Executed", summary.counts.evidence.EXECUTED, "Analyzer captured an ordered counterexample; independent replay still required."],
      ["Structural", summary.counts.evidence.STRUCTURAL, "Control/data-flow, taint, storage, call-graph, or analyzer evidence."],
      ["Heuristic", summary.counts.evidence.HEURISTIC, "Pattern-level review signal; not proof of exploitability."]
    ]) {
      const row = el("div", "security-ladder-row");
      const copy = el("div");
      copy.append(el("b", "", label), el("span", "", description));
      row.append(el("strong", "", count), copy);
      ladder.append(row);
    }
    evidenceLadder.append(ladder);

    const actions = el("div", "security-report-actions");
    const htmlButton = el("button", "outline-button", "Show Security Review File");
    const csvButton = el("button", "outline-button", "Show Findings CSV File");
    htmlButton.type = "button";
    csvButton.type = "button";
    htmlButton.disabled = !reviewState.paths?.securityReviewPath;
    csvButton.disabled = !reviewState.paths?.findingsCsvPath;
    htmlButton.addEventListener("click", () => reviewState.paths?.securityReviewPath && api.showReport(reviewState.paths.securityReviewPath));
    csvButton.addEventListener("click", () => reviewState.paths?.findingsCsvPath && api.showReport(reviewState.paths.findingsCsvPath));
    actions.append(htmlButton, csvButton);

    shell.append(hero, stats, evidenceLadder, actions);
    if (completenessState.partial) {
      const warning = el("article", "security-completeness-warning");
      warning.append(el("strong", "", "Analysis completeness warning"));
      const list = el("ul");
      for (const notice of completenessState.notices) list.append(el("li", "", notice));
      if (!completenessState.notices.length) list.append(el("li", "", "One or more analysis stages reported partial output."));
      warning.append(list);
      shell.append(warning);
    }

    const list = el("div", "security-finding-groups");
    const filters = { severity: "ALL", evidence: "ALL" };
    shell.append(createToolbar(findings, next => {
      filters.severity = next.severity;
      filters.evidence = next.evidence;
      renderFindingGroups(list, findings, filters);
    }), list);
    renderFindingGroups(list, findings, filters);
    panel.prepend(shell);

    const count = document.getElementById("candidate-findings-count");
    if (count) count.textContent = String(findings.length);
  }

  function queueRender() {
    if (reviewState.renderQueued) return;
    reviewState.renderQueued = true;
    queueMicrotask(() => {
      reviewState.renderQueued = false;
      const candidate = currentCandidate();
      if (candidate) renderReview(candidate);
    });
  }

  async function hydrate() {
    try {
      const last = await api.getLastScan();
      if (last) {
        reviewState.candidates = last.candidates || [];
        reviewState.paths = last.paths || null;
      }
    } catch {
      reviewState.candidates = [];
    }

    api.onScanComplete(result => {
      reviewState.candidates = result?.candidates || [];
      reviewState.paths = result?.paths || null;
      reviewState.renderKey = "";
      queueRender();
    });

    const observer = new MutationObserver(() => queueRender());
    observer.observe(document.body, {
      subtree: true,
      childList: true,
      characterData: true,
      attributes: true,
      attributeFilter: ["class"]
    });
    queueRender();
  }

  void hydrate();
})();
