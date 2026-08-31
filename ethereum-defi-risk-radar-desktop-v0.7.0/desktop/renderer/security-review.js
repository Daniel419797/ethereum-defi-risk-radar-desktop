(() => {
  "use strict";

  const api = window.riskRadar;
  if (!api) return;

  const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const EVIDENCE_ORDER = { REPRODUCED_FORK: 0, REPRODUCED_MODEL: 1, EXECUTED: 2, STRUCTURAL: 3, HEURISTIC: 4 };
  const LEGACY_SEVERITY = { HIGH_REVIEW: "HIGH", MEDIUM: "MEDIUM", LOW: "LOW", INFO: "INFO" };

  const reviewState = {
    candidates: [],
    paths: null,
    renderKey: "",
    renderQueued: false
  };

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
    const key = evidenceKey(finding);
    if (key === "REPRODUCED_FORK") return "Reproduced · fork";
    if (key === "REPRODUCED_MODEL") return "Reproduced · model";
    if (key === "EXECUTED") return "Executed";
    if (key === "STRUCTURAL") return "Structural";
    return "Heuristic";
  }

  function collectFindings(candidate) {
    const findings = [];
    for (const inspection of candidate?.ethereum?.sourceInspections || []) {
      const contractName = inspection.contractName || inspection.contractRefId || "Verified contract";
      const contractRefId = inspection.contractRefId || "unknown";
      const advanced = inspection.inspection?.advancedAnalysis || {};

      for (const finding of advanced.findings || []) {
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
        finding.sourceLayer,
        finding.kind,
        finding.file,
        finding.line,
        finding.title
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

      if (advancedDropped) notices.push(`${inspection.contractName || inspection.contractRefId}: ${advancedDropped} advanced findings omitted by configured caps.`);
      if (legacyDropped) notices.push(`${inspection.contractName || inspection.contractRefId}: ${legacyDropped} source-review signals omitted by configured caps.`);
      if (sourceDropped) notices.push(`${inspection.contractName || inspection.contractRefId}: ${sourceDropped} source characters were outside the configured analysis budget.`);
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
    return reviewState.candidates.find(candidate => candidate.label === title && (!hostname || candidate.hostname === hostname))
      || reviewState.candidates.find(candidate => candidate.label === title)
      || null;
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

    const description = el("p", "security-description", finding.description);
    const meta = el("div", "security-meta-grid");
    meta.append(
      metadataRow("Confidence", humanize(finding.confidence || "unknown")),
      metadataRow("Engine", humanize(finding.engine || "native")),
      metadataRow("Reachable externally", finding.reachableFromExternalEntry === undefined ? "Unknown" : finding.reachableFromExternalEntry ? "Yes" : "No"),
      metadataRow("Source layer", finding.sourceLayer === "advanced" ? "Structural analyzer" : "Pattern review")
    );

    card.append(heading, description, meta);

    if (finding.remediation) {
      const remediation = el("div", "security-guidance");
      remediation.append(el("strong", "", "Recommended remediation"), el("p", "", finding.remediation));
      card.append(remediation);
    }

    if (finding.mitigations?.length) {
      const mitigations = el("div", "security-inline-section");
      mitigations.append(el("strong", "", "Detected mitigations"));
      const list = el("div", "security-chip-row");
      for (const mitigation of finding.mitigations) list.append(badge(humanize(mitigation.kind), "mitigation"));
      mitigations.append(list);
      card.append(mitigations);
    }

    if (finding.witnessPath?.length) {
      const details = el("details", "security-details");
      details.append(el("summary", "", `Witness path · ${finding.witnessPath.length} step(s)`));
      const list = el("ol", "security-witness-list");
      for (const step of finding.witnessPath) {
        const item = el("li");
        item.append(
          el("strong", "", `${humanize(step.role)}: ${step.symbol}`),
          el("code", "", `${step.location?.file || "source"}:${step.location?.line || 0}`),
          step.detail ? el("span", "", step.detail) : document.createTextNode("")
        );
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
        if (finding.counterexample.sequence.length > 50) sequence.append(el("li", "", `${finding.counterexample.sequence.length - 50} additional steps omitted from the UI.`));
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
    const severityOptions = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    const evidenceOptions = ["ALL", "REPRODUCED_FORK", "REPRODUCED_MODEL", "EXECUTED", "STRUCTURAL", "HEURISTIC"];
    for (const optionValue of severityOptions) {
      const option = el("option", "", optionValue === "ALL" ? "All severities" : humanize(optionValue));
      option.value = optionValue;
      severity.append(option);
    }
    for (const optionValue of evidenceOptions) {
      const label = optionValue === "ALL" ? "All evidence" : optionValue === "REPRODUCED_FORK" ? "Reproduced · fork" : optionValue === "REPRODUCED_MODEL" ? "Reproduced · model" : humanize(optionValue);
      const option = el("option", "", label);
      option.value = optionValue;
      evidence.append(option);
    }
    const apply = () => onChange({ severity: severity.value, evidence: evidence.value });
    severity.addEventListener("change", apply);
    evidence.addEventListener("change", apply);
    toolbar.append(severity, evidence, el("span", "security-toolbar-count", `${findings.length} security finding(s)`));
    return toolbar;
  }

  function renderFindingGroups(root, findings, filters) {
    root.replaceChildren();
    const filtered = findings
      .filter(finding => filters.severity === "ALL" || finding.severity === filters.severity)
      .filter(finding => filters.evidence === "ALL" || finding.evidenceKey === filters.evidence)
      .sort((a, b) => {
        const evidenceDelta = (EVIDENCE_ORDER[a.evidenceKey] ?? 99) - (EVIDENCE_ORDER[b.evidenceKey] ?? 99);
        if (evidenceDelta !== 0) return evidenceDelta;
        const severityDelta = (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
        if (severityDelta !== 0) return severityDelta;
        return `${a.contractName}:${a.file}:${a.line}`.localeCompare(`${b.contractName}:${b.file}:${b.line}`);
      });

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
    const renderKey = `${candidate.id}:${findings.length}:${summary.strongestEvidence}:${summary.highestSeverity}:${completenessState.dropped}:${reviewState.paths?.securityReviewPath || ""}`;
    if (reviewState.renderKey === renderKey && document.getElementById("security-review-shell")) return;
    reviewState.renderKey = renderKey;

    for (const id of ["findings-severity-metrics", "candidate-findings-list", "candidate-findings-empty"]) {
      const node = document.getElementById(id);
      if (node) node.classList.add("security-review-legacy-hidden");
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
    const ladderRows = [
      ["Reproduced · fork", summary.counts.evidence.REPRODUCED_FORK, "Pinned fork replay; evidence about deployed bytecode at that block."],
      ["Reproduced · model", summary.counts.evidence.REPRODUCED_MODEL, "Deterministic replay in the bounded protocol/economic model."],
      ["Executed", summary.counts.evidence.EXECUTED, "Analyzer captured an ordered counterexample; independent replay still required."],
      ["Structural", summary.counts.evidence.STRUCTURAL, "Control/data-flow, taint, storage, call-graph, or analyzer evidence."],
      ["Heuristic", summary.counts.evidence.HEURISTIC, "Pattern-level review signal; not proof of exploitability."]
    ];
    for (const [label, count, description] of ladderRows) {
      const row = el("div", "security-ladder-row");
      row.append(el("strong", "", count), el("div", "", ""));
      row.children[1].append(el("b", "", label), el("span", "", description));
      ladder.append(row);
    }
    evidenceLadder.append(ladder);

    const actions = el("div", "security-report-actions");
    const htmlButton = el("button", "outline-button", "Open Security Review");
    const csvButton = el("button", "outline-button", "Open Findings CSV");
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
    const toolbar = createToolbar(findings, next => {
      filters.severity = next.severity;
      filters.evidence = next.evidence;
      renderFindingGroups(list, findings, filters);
    });
    shell.append(toolbar, list);
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
      if (!candidate) return;
      renderReview(candidate);
    });
  }

  function injectStyles() {
    if (document.getElementById("security-review-styles")) return;
    const style = document.createElement("style");
    style.id = "security-review-styles";
    style.textContent = `
      .security-review-legacy-hidden { display: none !important; }
      .security-review-shell { display: grid; gap: 18px; }
      .security-assessment-hero { display: flex; justify-content: space-between; gap: 24px; padding: 22px; border: 1px solid var(--border, #dce2ea); border-radius: 14px; background: var(--panel, #fff); }
      .security-assessment-hero.critical { border-left: 5px solid #b42318; }
      .security-assessment-hero.high { border-left: 5px solid #d92d20; }
      .security-assessment-hero.review { border-left: 5px solid #b54708; }
      .security-assessment-hero.neutral { border-left: 5px solid #667085; }
      .security-assessment-hero h2 { margin: 4px 0 8px; font-size: 22px; }
      .security-assessment-hero p { margin: 0; max-width: 760px; color: #667085; line-height: 1.55; }
      .security-eyebrow { text-transform: uppercase; letter-spacing: .08em; font-weight: 700; color: #475467; }
      .security-hero-badges, .security-badge-row, .security-chip-row, .security-report-actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: flex-start; }
      .security-badge { display: inline-flex; align-items: center; min-height: 26px; padding: 4px 9px; border-radius: 999px; font-size: 12px; font-weight: 700; border: 1px solid #d0d5dd; background: #f9fafb; color: #344054; }
      .security-badge.severity.critical { background: #fef3f2; color: #912018; border-color: #fecdca; }
      .security-badge.severity.high { background: #fff4ed; color: #9c2a10; border-color: #ffd6ae; }
      .security-badge.severity.medium { background: #fffaeb; color: #93370d; border-color: #fedf89; }
      .security-badge.severity.low { background: #ecfdf3; color: #027a48; border-color: #abefc6; }
      .security-badge.evidence.reproduced_fork, .security-badge.evidence.reproduced_model { background: #f4f3ff; color: #5925dc; border-color: #d9d6fe; }
      .security-badge.evidence.executed { background: #eef4ff; color: #3538cd; border-color: #c7d7fe; }
      .security-badge.evidence.structural { background: #eff8ff; color: #175cd3; border-color: #b2ddff; }
      .security-badge.evidence.heuristic { background: #f9fafb; color: #475467; }
      .security-stat-grid { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 10px; }
      .security-stat { padding: 14px; border: 1px solid #e4e7ec; border-radius: 12px; background: #fff; display: grid; gap: 6px; }
      .security-stat small { color: #667085; }
      .security-stat strong { font-size: 22px; }
      .security-stat.critical strong { color: #b42318; }
      .security-stat.high strong { color: #d92d20; }
      .security-stat.evidence strong { color: #5925dc; }
      .security-evidence-ladder { border: 1px solid #e4e7ec; border-radius: 14px; background: #fff; padding: 18px; }
      .security-evidence-ladder h3 { margin: 0 0 12px; }
      .security-ladder-grid { display: grid; gap: 8px; }
      .security-ladder-row { display: grid; grid-template-columns: 44px 1fr; gap: 12px; align-items: center; padding: 10px 0; border-top: 1px solid #f2f4f7; }
      .security-ladder-row:first-child { border-top: 0; }
      .security-ladder-row > strong { font-size: 20px; text-align: center; }
      .security-ladder-row div { display: grid; gap: 2px; }
      .security-ladder-row span { color: #667085; font-size: 13px; }
      .security-completeness-warning { border: 1px solid #fedf89; background: #fffaeb; color: #7a2e0e; border-radius: 12px; padding: 14px 16px; }
      .security-completeness-warning ul { margin: 8px 0 0 18px; }
      .security-review-toolbar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
      .security-review-toolbar select { min-width: 180px; padding: 9px 12px; border: 1px solid #d0d5dd; border-radius: 9px; background: #fff; }
      .security-toolbar-count { color: #667085; font-size: 13px; margin-left: auto; }
      .security-finding-groups { display: grid; gap: 16px; }
      .security-contract-group { display: grid; gap: 10px; }
      .security-contract-header { display: flex; justify-content: space-between; align-items: end; padding: 0 2px; }
      .security-contract-header h3 { margin: 0; font-size: 17px; }
      .security-contract-header small { color: #667085; }
      .security-finding { display: grid; gap: 14px; padding: 18px; border: 1px solid #e4e7ec; border-radius: 14px; background: #fff; border-left-width: 4px; }
      .security-finding.severity-critical { border-left-color: #b42318; }
      .security-finding.severity-high { border-left-color: #d92d20; }
      .security-finding.severity-medium { border-left-color: #dc6803; }
      .security-finding.severity-low { border-left-color: #039855; }
      .security-finding.severity-info { border-left-color: #2e90fa; }
      .security-finding-heading { display: flex; justify-content: space-between; gap: 20px; align-items: flex-start; }
      .security-finding-heading h3 { margin: 8px 0 0; font-size: 17px; }
      .security-location code { white-space: nowrap; font-size: 12px; }
      .security-description { margin: 0; color: #475467; line-height: 1.6; }
      .security-meta-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; }
      .security-meta-row { display: grid; gap: 3px; padding: 9px 10px; border: 1px solid #f2f4f7; border-radius: 8px; background: #fcfcfd; }
      .security-meta-row span { color: #667085; font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }
      .security-meta-row strong { font-size: 13px; overflow-wrap: anywhere; }
      .security-guidance { padding: 12px 14px; border-radius: 10px; background: #f8fafc; border: 1px solid #e4e7ec; }
      .security-guidance p { margin: 5px 0 0; line-height: 1.55; }
      .security-inline-section { display: grid; gap: 8px; }
      .security-details { border-top: 1px solid #f2f4f7; padding-top: 10px; }
      .security-details summary { cursor: pointer; font-weight: 700; color: #344054; }
      .security-witness-list, .security-sequence { display: grid; gap: 7px; margin: 10px 0 0 20px; }
      .security-witness-list li { display: grid; gap: 2px; }
      .security-counterexample { display: grid; gap: 8px; margin-top: 10px; }
      .security-empty { display: grid; gap: 5px; text-align: center; padding: 36px 20px; border: 1px dashed #d0d5dd; border-radius: 12px; color: #667085; }
      @media (max-width: 1100px) {
        .security-stat-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
        .security-meta-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      }
      @media (max-width: 760px) {
        .security-assessment-hero, .security-finding-heading { flex-direction: column; }
        .security-stat-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .security-meta-grid { grid-template-columns: 1fr; }
        .security-toolbar-count { width: 100%; margin-left: 0; }
      }
    `;
    document.head.append(style);
  }

  async function hydrate() {
    injectStyles();
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
    observer.observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ["class"] });
    queueRender();
  }

  void hydrate();
})();
