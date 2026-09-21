(() => {
  "use strict";

  const api = window.riskRadar;
  if (!api) {
    document.body.textContent = "Desktop bridge unavailable. Launch through the Electron application.";
    return;
  }

  const $ = id => document.getElementById(id);
  const screens = [
    "onboarding-keys",
    "onboarding-advanced",
    "dashboard",
    "results",
    "candidate",
    "analysis",
    "activity",
    "settings"
  ];
  const currentYear = new Date().getUTCFullYear();
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const evidenceOrder = { REPRODUCED_FORK: 0, REPRODUCED_MODEL: 1, EXECUTED: 2, STRUCTURAL: 3, HEURISTIC: 4 };
  const legacySeverity = { HIGH_REVIEW: "HIGH", MEDIUM: "MEDIUM", LOW: "LOW", INFO: "INFO" };
  const sourceReviewOnlyExclusions = new Set(["reentrancy_guard_present"]);
  const legacyToAdvancedKind = { tx_origin: ["authorization"], delegatecall: ["upgradeability", "cross_contract_calls"], low_level_call: ["cross_contract_calls", "reentrancy"], value_transfer_call: ["cross_contract_calls", "reentrancy"], privileged_access: ["authorization", "governance_risk"], upgradeability_pattern: ["upgradeability"], initializer_pattern: ["upgradeability"], unchecked_block: ["arithmetic_precision"], signature_recovery: ["signature_replay"], oracle_price_surface: ["oracle_risk"], permit_signature_surface: ["signature_replay"], cross_chain_surface: ["bridge_messaging"], liquidation_surface: ["oracle_risk"], mev_slippage_surface: ["mev_ordering"], token_accounting_surface: ["token_integration"] };

  const state = {
    settings: null,
    appInfo: null,
    currentScreen: "dashboard",
    onboarding: false,
    onboardingStep: 1,
    draftKeys: { tinyfishApiKey: "", etherscanApiKey: "" },
    candidates: [],
    reportPaths: null,
    lastScan: null,
    running: false,
    progress: { overallPercent: 0, phase: "READY", message: "Ready to begin a passive scan.", completed: 0, total: 0 },
    logs: [],
    scanStartedAt: null,
    selectedCandidate: null,
    selectedCandidateTab: "overview",
    keyModalProvider: null,
    connection: { tinyfish: "unknown", etherscan: "unknown" },
    analysisCapabilities: [],
    analysisRunning: false,
    analysisResult: null,
    cliStatus: null,
    toastTimer: null
  };

  function clamp(value, min, max, fallback) {
    const parsed = Number.parseInt(String(value ?? ""), 10);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.max(min, Math.min(parsed, max));
  }

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function showToast(message, type = "") {
    const toast = $("toast");
    toast.textContent = message;
    toast.className = `toast ${type}`.trim();
    if (state.toastTimer) clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => toast.classList.add("hidden"), 4500);
  }

  function applyAppInfo(info) {
    state.appInfo = info || null;
    if (!info) return;
    $("brand-version").textContent = `v${info.version}`;
    if (info.platform === "darwin") {
      $("setup-secure-info").textContent = "ⓘ Credentials are encrypted using macOS Keychain-backed secure storage.";
      document.documentElement.dataset.platform = "macos";
    } else if (info.platform === "win32") {
      $("setup-secure-info").textContent = "ⓘ Credentials are encrypted using Windows OS-backed secure storage.";
      document.documentElement.dataset.platform = "windows";
    } else {
      $("setup-secure-info").textContent = "ⓘ Credentials are encrypted with OS-backed secure storage.";
      document.documentElement.dataset.platform = info.platform || "other";
    }
    if ($("setup-cli-note")) {
      $("setup-cli-note").textContent = info.platform === "darwin"
        ? "Adds risk-radar to ~/.local/bin and configures your shell PATH."
        : info.platform === "win32"
          ? "Makes risk-radar available from Command Prompt, PowerShell and Windows Terminal."
          : "Installs a user-level risk-radar terminal launcher.";
    }
  }

  function formatTime(iso) {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleTimeString([], {
        hour12: false,
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
      });
    } catch {
      return "—";
    }
  }

  function formatDateTime(iso) {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleString();
    } catch {
      return "—";
    }
  }

  function formatDuration(ms) {
    if (!Number.isFinite(Number(ms)) || Number(ms) < 0) return "—";
    const totalSeconds = Math.floor(Number(ms) / 1000);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    if (hours > 0) return `${hours}h ${minutes}m ${seconds}s`;
    if (minutes > 0) return `${minutes}m ${seconds}s`;
    return `${seconds}s`;
  }

  function humanize(value) {
    return String(value ?? "").replaceAll("_", " ").toLowerCase().replace(/\b\w/g, c => c.toUpperCase());
  }

  function classificationClass(value) {
    if (value === "HIGH_RESEARCH_PRIORITY") return "high";
    if (value === "REVIEW") return "review";
    return "low";
  }

  function findingEvidenceKey(finding) {
  if (finding.evidenceStrength === "REPRODUCED") {
    const scope = finding.evidenceScope || finding.counterexample?.scope;
    return scope === "fork" ? "REPRODUCED_FORK" : "REPRODUCED_MODEL";
  }
  if (finding.evidenceStrength === "EXECUTED") return "EXECUTED";
  if (finding.evidenceStrength === "STRUCTURAL") return "STRUCTURAL";
  return "HEURISTIC";
}

  function findingEvidenceLabel(finding) {
  const key = finding.evidenceKey || findingEvidenceKey(finding);
  if (key === "REPRODUCED_FORK") return "Reproduced · fork";
  if (key === "REPRODUCED_MODEL") return "Reproduced · model";
  if (key === "EXECUTED") return "Executed";
  if (key === "STRUCTURAL") return "Structural";
  return "Heuristic";
}

  function sourceFindingShadowedByAdvanced(finding, advanced) {
  const mappedKinds = legacyToAdvancedKind[finding.kind];
  if (!mappedKinds?.length) return false;
  return advanced.some(candidate => {
    const location = candidate.primaryLocation;
    return mappedKinds.includes(candidate.kind) &&
      location?.file === finding.file &&
      Math.abs(Number(location.line || 0) - Number(finding.line || 0)) <= 2;
  });
}

  function analysisCompleteness(candidate) {
  const notices = [];
  let dropped = 0;
  let truncatedSourceCharacters = 0;
  for (const inspection of candidate?.ethereum?.sourceInspections || []) {
    const label = inspection.contractName || inspection.contractRefId || "Verified contract";
    const source = inspection.inspection || {};
    const advanced = source.advancedAnalysis || {};
    const advancedDropped = (advanced.truncations || []).reduce((sum, item) => sum + Number(item.dropped || 0), 0);
    dropped += advancedDropped + Number(source.truncatedFindingCount || 0);
    truncatedSourceCharacters += Number(source.truncatedSourceCharacters || 0);
    if (advanced.partial) notices.push(`${label}: advanced analysis reported a partial run.`);
    if (advancedDropped > 0) notices.push(`${label}: ${advancedDropped} advanced match${advancedDropped === 1 ? "" : "es"} omitted by configured caps.`);
    if (Number(source.truncatedFindingCount || 0) > 0) notices.push(`${label}: ${source.truncatedFindingCount} source-review signal${source.truncatedFindingCount === 1 ? "" : "s"} omitted by the finding limit.`);
    if (source.sourceTruncated) notices.push(`${label}: ${source.truncatedSourceCharacters || 0} verified-source characters were outside the analysis byte budget.`);
  }
  return {
    partial: notices.length > 0,
    dropped,
    truncatedSourceCharacters,
    notices: [...new Set(notices)]
  };
}

  function aggregateCandidates(candidates = state.candidates) {
  return {
    candidates: candidates.length,
    high: candidates.filter(c => c.classification === "HIGH_RESEARCH_PRIORITY").length,
    reviewed: candidates.reduce((sum, c) => sum + (c.ethereum?.sourceContractsInspected || 0), 0),
    flags: candidates.reduce((sum, c) => sum + flattenFindings(c).filter(f => f.severity === "CRITICAL" || f.severity === "HIGH").length, 0)
  };
}

  function inspectionSourceRole(inspection) {
    if (inspection.sourceRole) return inspection.sourceRole;
    return inspection.proxy ? "PROXY" : "DIRECT";
  }

  function inspectionFindingContext(inspection) {
    return {
      contractName: inspection.contractName || inspection.contractRefId || "Verified contract",
      contractRefId: inspection.contractRefId || "unknown",
      sourceRole: inspectionSourceRole(inspection),
      compilerVersion: inspection.compilerVersion || "",
      proxy: Boolean(inspection.proxy)
    };
  }

  function advancedUiFinding(inspection, finding, historical) {
    return {
      ...finding,
      ...inspectionFindingContext(inspection),
      sourceLayer: "advanced",
      severity: severityOrder[finding.severity] === undefined ? "INFO" : finding.severity,
      file: finding.primaryLocation?.file || "Structural analysis",
      line: Number(finding.primaryLocation?.line || 0),
      column: Number(finding.primaryLocation?.column || 0),
      evidenceKey: findingEvidenceKey(finding),
      historical: historical.get("advanced:" + finding.id) || null
    };
  }

  function sourceUiFinding(inspection, finding, historical) {
    const context = inspectionFindingContext(inspection);
    const id = ["source", context.contractRefId, finding.kind, finding.file, finding.line].join(":");
    const historicalId = ["source", finding.kind, finding.file, finding.line].join(":");
    return {
      id,
      kind: finding.kind,
      engine: "native",
      severity: legacySeverity[finding.severity] || "INFO",
      confidence: "LOW",
      evidenceStrength: "HEURISTIC",
      evidenceKey: "HEURISTIC",
      exploitabilityVerdict: "UNKNOWN",
      title: finding.title,
      description: finding.description,
      limitations: ["Pattern-level source review signal; presence alone does not establish exploitability."],
      sourceLayer: "source-review",
      ...context,
      file: finding.file || "Verified source",
      line: Number(finding.line || 0),
      column: 0,
      historical: historical.get(historicalId) || null
    };
  }

  function includeSourceFinding(finding, advanced) {
    return !sourceReviewOnlyExclusions.has(finding.kind) &&
      !sourceFindingShadowedByAdvanced(finding, advanced);
  }

  function inspectionUiFindings(inspection) {
    const advanced = inspection.inspection?.advancedAnalysis?.findings || [];
    const historyRows = inspection.inspection?.historicalIntelligence?.findings || [];
    const historical = new Map(historyRows.map(item => [item.findingId, item]));
    const advancedRows = advanced.map(finding => advancedUiFinding(inspection, finding, historical));
    const sourceRows = (inspection.inspection?.findings || [])
      .filter(finding => includeSourceFinding(finding, advanced))
      .map(finding => sourceUiFinding(inspection, finding, historical));
    return [...advancedRows, ...sourceRows];
  }

  function findingDedupeKey(finding) {
    const scope = finding.evidenceScope || finding.counterexample?.scope || "";
    return [
      finding.contractRefId,
      finding.kind,
      finding.file,
      finding.line,
      finding.title,
      finding.evidenceKey,
      scope
    ].join("|");
  }

  function dedupeUiFindings(findings) {
    const seen = new Set();
    return findings.filter(finding => {
      const key = findingDedupeKey(finding);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  function flattenFindings(candidate) {
    const inspections = candidate?.ethereum?.sourceInspections || [];
    return dedupeUiFindings(inspections.flatMap(inspection => inspectionUiFindings(inspection)));
  }

    function candidateEvidenceYears(candidate) {
    const years = (candidate?.evidence || []).map(e => Number(e.year)).filter(Number.isFinite);
    if (!years.length) return "—";
    const min = Math.min(...years);
    const max = Math.max(...years);
    return min === max ? String(min) : `${min}–${max}`;
  }

  function setScreenVisibility(name) {
    for (const screen of screens) {
      $("screen-" + screen)?.classList.toggle("hidden", screen !== name);
    }
  }

  function updateNav(name) {
    document.querySelectorAll(".nav-button").forEach(button => {
      const target = button.dataset.screen;
      const activeTarget = name === "candidate" ? "results" : name;
      button.classList.toggle("active", target === activeTarget);
    });
  }

  function showScreen(name) {
    if (state.onboarding) return;
    state.currentScreen = name;
    setScreenVisibility(name);
    updateNav(name);
    if (name === "dashboard") renderDashboard();
    if (name === "results") renderResults();
    if (name === "candidate") renderCandidate();
    if (name === "analysis") renderAnalysisLab();
    if (name === "activity") renderActivity();
    if (name === "settings") renderSettings();
  }

  function setOnboarding(enabled) {
    state.onboarding = enabled;
    $("setup-rail").classList.toggle("hidden", !enabled);
    document.querySelectorAll(".nav-button").forEach(button => { button.disabled = enabled; });
    if (!enabled) {
      $("setup-rail").classList.add("hidden");
      document.querySelectorAll(".nav-button").forEach(button => { button.disabled = false; });
    }
  }

  function showOnboardingStep(step) {
    state.onboardingStep = step;
    setScreenVisibility(step === 1 ? "onboarding-keys" : "onboarding-advanced");
    $("setup-rail-step-1").classList.toggle("active", step === 1);
    $("setup-rail-step-2").classList.toggle("active", step === 2);
  }

  function populateSetupAdvanced() {
    const s = state.settings;
    if (!s) return;
    $("setup-endpoint").value = s.tinyfishEndpoint;
    $("setup-pages").value = String(s.maxPagesPerQuery);
    $("setup-min-signals").value = String(s.minPublicSignals);
    $("setup-etherscan-lookups").value = String(s.maxEtherscanLookupsPerCandidate);
    $("setup-inspect-source").checked = Boolean(s.inspectVerifiedSource);
    $("setup-source-bytes").value = String(s.maxSourceBytes);
    $("setup-max-findings").value = String(s.maxSourceFindingsPerContract);
    $("setup-output-dir").value = s.outputDir;
  }

  function publicSettingsPayloadFromSetup() {
    return {
      tinyfishApiKey: state.draftKeys.tinyfishApiKey,
      etherscanApiKey: state.draftKeys.etherscanApiKey || undefined,
      tinyfishEndpoint: $("setup-endpoint").value.trim(),
      maxPagesPerQuery: clamp($("setup-pages").value, 1, 10, 1),
      minPublicSignals: clamp($("setup-min-signals").value, 2, 8, 2),
      maxEtherscanLookupsPerCandidate: clamp($("setup-etherscan-lookups").value, 0, 5, 2),
      inspectVerifiedSource: $("setup-inspect-source").checked,
      maxSourceBytes: clamp($("setup-source-bytes").value, 10000, 5000000, 2000000),
      maxSourceFindingsPerContract: clamp($("setup-max-findings").value, 1, 250, 80),
      outputDir: $("setup-output-dir").value.trim()
    };
  }

  function updateConnectionStateFromSettings() {
    if (!state.settings) return;
    if (state.connection.tinyfish === "unknown") {
      state.connection.tinyfish = state.settings.hasTinyfishApiKey ? "configured" : "missing";
    }
    if (state.connection.etherscan === "unknown") {
      state.connection.etherscan = state.settings.hasEtherscanApiKey ? "configured" : "optional";
    }
    if (!state.settings.hasEtherscanApiKey && state.connection.etherscan !== "testing") {
      state.connection.etherscan = "optional";
    }
    updateConnectionUI();
  }

  function setProviderStatus(provider, status) {
    state.connection[provider] = status;
    updateConnectionUI();
  }

  function providerStatusText(status) {
    if (status === "connected") return "Connected";
    if (status === "failed") return "Failed";
    if (status === "testing") return "Testing…";
    if (status === "optional") return "Optional";
    if (status === "configured") return "Configured";
    if (status === "missing") return "Required";
    return "Unknown";
  }

  function providerStatusClass(status) {
    if (status === "connected") return "good";
    if (status === "failed" || status === "missing") return "bad";
    if (status === "testing") return "pending";
    return "neutral";
  }

  function updateConnectionUI() {
    const tf = state.connection.tinyfish;
    const es = state.connection.etherscan;

    $("dashboard-tinyfish-status").textContent = providerStatusText(tf);
    $("dashboard-etherscan-status").textContent = providerStatusText(es);
    $("dashboard-tinyfish-status").className = providerStatusClass(tf);
    $("dashboard-etherscan-status").className = providerStatusClass(es);
    $("dashboard-tinyfish-check").className = `status-check ${providerStatusClass(tf)}`;
    $("dashboard-etherscan-check").className = `status-check ${providerStatusClass(es)}`;
    $("dashboard-tinyfish-check").textContent = tf === "connected" ? "✓" : tf === "failed" ? "×" : "•";
    $("dashboard-etherscan-check").textContent = es === "connected" ? "✓" : es === "failed" ? "×" : "•";

    if (state.settings) {
      $("settings-tinyfish-badge").textContent = providerStatusText(tf);
      $("settings-tinyfish-badge").className = `connected-badge ${tf === "failed" ? "bad" : tf === "connected" ? "" : "neutral"}`.trim();
      $("settings-etherscan-badge").textContent = providerStatusText(es);
      $("settings-etherscan-badge").className = `connected-badge ${es === "failed" ? "bad" : es === "connected" ? "" : "neutral"}`.trim();
    }
  }

  function openModal(id) {
    $(id).classList.remove("hidden");
  }

  function closeModal(id) {
    $(id).classList.add("hidden");
  }

  async function runConnectionTest(open = true) {
    if (!state.settings?.hasTinyfishApiKey) {
      showToast("TinyFish API key is not configured.", "error");
      return;
    }

    setProviderStatus("tinyfish", "testing");
    setProviderStatus("etherscan", state.settings.hasEtherscanApiKey ? "testing" : "optional");

    $("connection-modal-subtitle").textContent = "Testing all configured connections...";
    $("connection-tinyfish-result").className = "test-result pending";
    $("connection-tinyfish-result").textContent = "Testing…";
    $("connection-tinyfish-message").textContent = "Waiting for response";
    $("connection-tinyfish-endpoint").textContent = state.settings.tinyfishEndpoint;
    $("connection-etherscan-result").className = state.settings.hasEtherscanApiKey ? "test-result pending" : "test-result neutral";
    $("connection-etherscan-result").textContent = state.settings.hasEtherscanApiKey ? "Testing…" : "Not configured";
    $("connection-etherscan-message").textContent = state.settings.hasEtherscanApiKey ? "Waiting for response" : "Optional enrichment disabled";
    if (open) openModal("connection-modal");

    try {
      const result = await api.testConnections();
      const tfStatus = result.tinyfish.ok ? "connected" : "failed";
      setProviderStatus("tinyfish", tfStatus);
      $("connection-tinyfish-result").className = `test-result ${result.tinyfish.ok ? "good" : "bad"}`;
      $("connection-tinyfish-result").textContent = result.tinyfish.ok ? "Connected" : "Failed";
      $("connection-tinyfish-message").textContent = result.tinyfish.message;

      if (result.etherscan.ok === null) {
        setProviderStatus("etherscan", "optional");
        $("connection-etherscan-result").className = "test-result neutral";
        $("connection-etherscan-result").textContent = "Not configured";
        $("connection-etherscan-message").textContent = result.etherscan.message;
      } else {
        const esStatus = result.etherscan.ok ? "connected" : "failed";
        setProviderStatus("etherscan", esStatus);
        $("connection-etherscan-result").className = `test-result ${result.etherscan.ok ? "good" : "bad"}`;
        $("connection-etherscan-result").textContent = result.etherscan.ok ? "Connected" : "Failed";
        $("connection-etherscan-message").textContent = result.etherscan.message;
      }
      $("connection-modal-subtitle").textContent = "Connection test complete.";
    } catch (error) {
      setProviderStatus("tinyfish", "failed");
      $("connection-tinyfish-result").className = "test-result bad";
      $("connection-tinyfish-result").textContent = "Failed";
      $("connection-tinyfish-message").textContent = error?.message || String(error);
      $("connection-modal-subtitle").textContent = "Connection test failed.";
      if (!open) showToast(error?.message || String(error), "error");
    }
  }

  function addLog(message, at = new Date().toISOString()) {
    state.logs.push({ message: String(message), at });
    if (state.logs.length > 500) state.logs.splice(0, state.logs.length - 500);
    renderDashboardLog();
    renderActivityLog();
  }

  function buildLogRow(item) {
    const row = element("div", "log-row");
    const time = element("time", "", formatTime(item.at));
    const text = element("span", "", item.message);
    row.append(time, text);
    return row;
  }

  function renderDashboardLog() {
    const root = $("dashboard-live-log");
    root.replaceChildren();
    const recent = state.logs.slice(-8);
    if (!recent.length) {
      root.append(element("div", "empty-inline", "No activity yet."));
      return;
    }
    for (const item of recent) root.append(buildLogRow(item));
  }

  function renderActivityLog() {
    const root = $("activity-log");
    root.replaceChildren();
    if (!state.logs.length) {
      root.append(element("div", "empty-inline", "Scanner is idle."));
      return;
    }
    for (const item of state.logs) root.append(buildLogRow(item));
    root.scrollTop = root.scrollHeight;
  }

  function updateProgress(event) {
    state.progress = {
      overallPercent: clamp(event?.overallPercent, 0, 100, state.progress.overallPercent || 0),
      phase: String(event?.phase || "SCANNING"),
      message: String(event?.message || "Scanning"),
      completed: Number(event?.completed || 0),
      total: Number(event?.total || 0)
    };
    renderDashboardProgress();
  }

  function renderDashboardProgress() {
    const p = state.progress;
    const percent = clamp(p.overallPercent, 0, 100, 0);
    const circumference = 370.7;
    const offset = circumference - (percent / 100) * circumference;
    $("dashboard-progress-ring").setAttribute("stroke-dashoffset", offset.toFixed(2));
    $("dashboard-progress-percent").textContent = `${percent}%`;
    $("dashboard-progress-linear").value = percent;
    $("dashboard-progress-phase").textContent = p.phase.replaceAll("_", " ");
    $("dashboard-progress-counter").textContent = p.total > 0 ? `${p.completed} / ${p.total}` : "";
    $("dashboard-progress-message").textContent = p.message;
    $("dashboard-progress-heading").textContent = state.running ? "Scan in progress" : percent === 100 ? "Last scan complete" : "Scan status";
  }

  function setRunning(running) {
    state.running = Boolean(running);
    $("dashboard-start-scan").disabled = state.running;
    $("dashboard-start-year").disabled = state.running;
    $("dashboard-end-year").disabled = state.running;
    $("dashboard-pages").disabled = state.running;
    $("dashboard-start-scan").textContent = state.running ? "SCANNING…" : "▷ START SCAN";
    renderActivity();
  }

  function renderMetrics() {
    const metrics = aggregateCandidates();
    const ids = [
      ["dashboard-metric-candidates", metrics.candidates],
      ["dashboard-metric-high", metrics.high],
      ["dashboard-metric-reviewed", metrics.reviewed],
      ["dashboard-metric-flags", metrics.flags],
      ["results-metric-candidates", metrics.candidates],
      ["results-metric-high", metrics.high],
      ["results-metric-reviewed", metrics.reviewed],
      ["results-metric-flags", metrics.flags]
    ];
    for (const [id, value] of ids) $(id).textContent = String(value);
  }

  function renderDashboard() {
    if (!state.settings) return;
    $("dashboard-start-year").max = String(currentYear);
    $("dashboard-end-year").max = String(currentYear);
    if (!$("dashboard-start-year").value) $("dashboard-start-year").value = "2016";
    if (!$("dashboard-end-year").value) $("dashboard-end-year").value = String(currentYear);
    if (!$("dashboard-pages").value) $("dashboard-pages").value = String(state.settings.maxPagesPerQuery);
    renderMetrics();
    renderDashboardProgress();
    renderDashboardLog();
    updateConnectionUI();
  }

  async function startScan() {
    if (state.running) return;
    if (!state.settings?.hasTinyfishApiKey) {
      showToast("Configure a TinyFish API key before scanning.", "error");
      showScreen("settings");
      return;
    }

    const startYear = clamp($("dashboard-start-year").value, 2016, currentYear, 2016);
    const endYear = clamp($("dashboard-end-year").value, 2016, currentYear, currentYear);
    const pagesPerQuery = clamp($("dashboard-pages").value, 1, 10, state.settings.maxPagesPerQuery || 1);
    if (endYear < startYear) {
      showToast("End year must be greater than or equal to start year.", "error");
      return;
    }

    state.candidates = [];
    state.reportPaths = null;
    state.lastScan = null;
    state.logs = [];
    state.scanStartedAt = new Date().toISOString();
    updateProgress({ overallPercent: 0, phase: "STARTING", message: `Starting Ethereum Mainnet scan for ${startYear}-${endYear}`, completed: 0, total: 0 });
    addLog(`Scan started: Ethereum ${startYear}-${endYear}`, state.scanStartedAt);
    renderMetrics();
    renderResults();
    setRunning(true);

    try {
      await api.startScan({ startYear, endYear, pagesPerQuery });
    } catch (error) {
      showToast(error?.message || String(error), "error");
      setRunning(false);
    }
  }

  function renderResults() {
    renderMetrics();
    const root = $("results-table-body");
    root.replaceChildren();

    const query = $("results-search").value.trim().toLowerCase();
    const sort = $("results-sort").value;
    let rows = state.candidates.filter(candidate => {
      if (!query) return true;
      const haystack = `${candidate.label} ${candidate.hostname} ${candidate.classification} ${(candidate.kinds || []).join(" ")}`.toLowerCase();
      return haystack.includes(query);
    });

    rows = [...rows].sort((a, b) => {
      if (sort === "confidence-desc") return b.ethereumConfidence - a.ethereumConfidence;
      if (sort === "name-asc") return a.label.localeCompare(b.label);
      return b.researchScore - a.researchScore;
    });

    $("results-empty").classList.toggle("hidden", rows.length > 0);
    $("results-report-actions").classList.toggle("hidden", !state.reportPaths);

    for (const candidate of rows) {
      const tr = document.createElement("tr");
      const score = element("td");
      score.append(element("span", "score-value", candidate.researchScore));

      const candidateTd = element("td", "candidate-cell");
      candidateTd.append(element("strong", "", candidate.label), element("small", "", candidate.hostname));

      const confidence = element("td", "", `${candidate.ethereumConfidence}%`);
      const signals = element("td", "", candidate.signalCount);
      const verified = element("td", "", candidate.ethereum?.verifiedSourceContracts || 0);

      const statusTd = element("td");
      const badge = element("span", `status-badge ${classificationClass(candidate.classification)}`, humanize(candidate.classification));
      statusTd.append(badge);

      const actionTd = element("td");
      const button = element("button", "review-button", flattenFindings(candidate).length ? "View Findings ›" : "Review ›");
      button.type = "button";
      button.addEventListener("click", () => openCandidate(candidate));
      actionTd.append(button);

      tr.append(score, candidateTd, confidence, signals, verified, statusTd, actionTd);
      root.append(tr);
    }
  }

  function openCandidate(candidate) {
    state.selectedCandidate = candidate;
    state.selectedCandidateTab = "overview";
    renderCandidate();
    state.currentScreen = "candidate";
    setScreenVisibility("candidate");
    updateNav("candidate");
  }

  function renderCandidateHeader(candidate) {
    $("candidate-title").textContent = candidate.label;
    $("candidate-priority").textContent = humanize(candidate.classification);
    $("candidate-priority").className = `priority-badge ${classificationClass(candidate.classification)}`;
    $("candidate-score").textContent = `${candidate.researchScore} / 100`;
    $("candidate-score-progress").value = candidate.researchScore;
    $("candidate-confidence").textContent = `${candidate.ethereumConfidence}%`;
    $("candidate-confidence-progress").value = candidate.ethereumConfidence;
    $("candidate-host-link").textContent = `${candidate.hostname} ↗`;
    $("candidate-host-link").disabled = !(candidate.evidence || []).some(e => e.sourceUrl);
    const findings = flattenFindings(candidate);
    $("candidate-findings-count").textContent = String(findings.length);
    $("candidate-intelligence-count").textContent = String(candidate.ethereum?.intelligence?.invariants?.length || 0);
    $("candidate-evidence-count").textContent = String((candidate.evidence || []).length);
  }

  function createCompactStat(glyph, label, value) {
    const card = element("article", "compact-stat-card");
    card.append(element("span", "stat-glyph", glyph), element("small", "", label), element("strong", "", value));
    return card;
  }

  function renderCandidateOverview(candidate) {
  const findings = flattenFindings(candidate);
  const criticalHigh = findings.filter(finding => finding.severity === "CRITICAL" || finding.severity === "HIGH").length;
  const reproduced = findings.filter(finding => finding.evidenceKey === "REPRODUCED_FORK" || finding.evidenceKey === "REPRODUCED_MODEL").length;
  const metrics = $("candidate-overview-metrics");
  metrics.replaceChildren(
    createCompactStat("⌁", "Signal Categories", candidate.signalCount),
    createCompactStat("◌", "Source Diversity", candidate.sourceDiversity),
    createCompactStat("✓", "Verified Contracts", candidate.ethereum?.verifiedSourceContracts || 0),
    createCompactStat("⌕", "Contracts Analyzed", candidate.ethereum?.sourceContractsInspected || 0),
    createCompactStat("!", "Critical + High", criticalHigh),
    createCompactStat("◎", "Reproduced", reproduced)
  );

  const chips = $("candidate-signal-chips");
  chips.replaceChildren();
  for (const kind of candidate.kinds || []) chips.append(element("span", "signal-chip", humanize(kind)));

  const description = candidate.classification === "HIGH_RESEARCH_PRIORITY"
    ? "Multiple independent public signals make this protocol a high research priority for deeper manual review."
    : candidate.classification === "REVIEW"
      ? "The protocol has enough corroborated public signals to warrant manual review."
      : "The protocol has public signals, but they currently fall below the higher research-priority thresholds.";
  $("candidate-interpretation").textContent = description;
}

  function shortDigest(value) {
    if (!value) return "—";
    return value.length > 24 ? value.slice(0, 12) + "…" + value.slice(-8) : value;
  }

  function intelligenceStatusClass(status) {
    if (status === "SOURCE_RECOMPILED_EXACT" || status === "SOURCE_RECOMPILED_METADATA_EQUIVALENT") return "good";
    if (status === "RECOMPILE_MISMATCH") return "bad";
    return "neutral";
  }

  function renderKnowledgeGraph(intelligence) {
    const root = $("candidate-graph-list");
    root.replaceChildren();
    const nodes = new Map((intelligence?.graph?.nodes || []).map(node => [node.id, node]));
    const edges = intelligence?.graph?.edges || [];
    $("candidate-graph-digest").textContent = shortDigest(intelligence?.graph?.digest || "");

    for (const edge of edges.slice(0, 28)) {
      const from = nodes.get(edge.from);
      const to = nodes.get(edge.to);
      const row = element("div", "graph-edge-row");
      row.append(
        element("span", "graph-node-pill", from?.label || edge.from),
        element("span", "graph-edge-kind", humanize(edge.kind)),
        element("span", "graph-node-pill", to?.label || edge.to)
      );
      root.append(row);
    }
    if (!edges.length) root.append(element("div", "empty-inline", "No resolved graph edges."));
    if (edges.length > 28) root.append(element("small", "intelligence-more", "+" + (edges.length - 28) + " additional graph edges"));
  }

  function renderAttestations(candidate) {
    const root = $("candidate-attestation-list");
    root.replaceChildren();
    const inspections = candidate.ethereum?.sourceInspections || [];
    for (const inspection of inspections) {
      const attestation = inspection.bytecodeAttestation;
      const card = element("article", "attestation-card");
      const head = element("div", "attestation-head");
      head.append(
        element("strong", "", inspection.contractName || inspection.contractRefId),
        element("span", "test-result " + intelligenceStatusClass(attestation?.status), humanize(attestation?.status || "not captured"))
      );
      card.append(
        head,
        element("small", "", (inspection.sourceRole || "DIRECT") + " · " + (inspection.compilerVersion || "compiler unknown"))
      );
      if (attestation) {
        card.append(
          element("code", "attestation-hash", shortDigest(attestation.observedRuntimeHash || "")),
          element("p", "", attestation.observedRuntimeBytes + " runtime bytes · " + (attestation.metadataStripped ? "metadata-normalized comparison" : "raw runtime comparison"))
        );
        for (const note of attestation.limitations || []) card.append(element("small", "attestation-note", note));
      } else {
        card.append(element("p", "", "No RPC-backed bytecode observation was captured for this scan."));
      }
      root.append(card);
    }
    if (!inspections.length) root.append(element("div", "empty-inline", "No inspected contracts."));
  }

  function renderInvariants(intelligence) {
    const root = $("candidate-invariant-list");
    root.replaceChildren();
    for (const selected of intelligence?.invariants || []) {
      const invariant = selected.invariant;
      const card = element("article", "invariant-card");
      const head = element("div", "invariant-head");
      head.append(
        element("span", "finding-badge", invariant.category),
        element("span", "finding-badge evidence structural", selected.confidence + " CONFIDENCE")
      );
      card.append(
        head,
        element("h3", "", invariant.title),
        element("p", "", invariant.statement),
        element("small", "", "If violated: " + invariant.severityIfViolated + " · " + invariant.executionKinds.map(humanize).join(" → ")),
        element("small", "invariant-rationale", selected.rationale.join(" · "))
      );
      root.append(card);
    }
    if (!(intelligence?.invariants || []).length) root.append(element("div", "empty-inline", "No protocol-specific invariants selected."));
  }

  function renderAttackPaths(intelligence) {
    const root = $("candidate-attack-paths");
    root.replaceChildren();
    const plans = new Map((intelligence?.escalationPlans || []).map(plan => [plan.findingId, plan]));
    for (const path of intelligence?.attackPaths || []) {
      const card = element("article", "attack-path-card");
      const head = element("div", "attack-path-head");
      head.append(
        element("h3", "", path.title),
        element("span", "finding-badge", path.severity),
        element("span", "finding-badge evidence " + String(path.evidenceStrength).toLowerCase(), humanize(path.evidenceStrength))
      );
      card.append(head);

      const flow = element("div", "attack-path-flow");
      path.nodes.forEach((node, index) => {
        if (index > 0) flow.append(element("span", "attack-arrow", "→"));
        const nodeEl = element("div", "attack-node");
        nodeEl.append(
          element("small", "", node.kind),
          element("strong", "", node.label),
          node.sourceLocation ? element("span", "", node.sourceLocation.file + ":" + node.sourceLocation.line) : element("span", "", "")
        );
        flow.append(nodeEl);
      });
      card.append(flow);

      const plan = plans.get(path.findingId);
      if (plan) {
        const escalation = element("div", "escalation-track");
        for (const step of plan.steps) {
          const item = element("span", "escalation-step " + step.status.toLowerCase(), humanize(step.stage));
          item.title = step.reason;
          escalation.append(item);
        }
        card.append(element("small", "escalation-label", "Automatic evidence escalation"), escalation);
      }
      root.append(card);
    }
    if (!(intelligence?.attackPaths || []).length) root.append(element("div", "empty-inline", "No source-linked attack path could be constructed from current findings."));
  }

  function renderSnapshot(candidate) {
    const snapshot = candidate.ethereum?.pinnedStateSnapshot;
    const root = $("candidate-snapshot-list");
    root.replaceChildren();
    $("candidate-snapshot-block").textContent = snapshot ? "#" + snapshot.blockNumber : "NOT CAPTURED";
    if (!snapshot) {
      root.append(element("div", "empty-inline", "Configure a read-only Ethereum RPC to capture canonical state and proxy-control slots."));
      return;
    }
    for (const contract of snapshot.contracts || []) {
      const card = element("article", "snapshot-card");
      card.append(
        element("strong", "", contract.contractRefId),
        element("code", "", shortDigest(contract.codeHash)),
        element("small", "", contract.codeBytes + " runtime bytes"),
        element("span", "", "Implementation: " + (contract.implementationSlot ? "set" : "—")),
        element("span", "", "Admin: " + (contract.adminSlot ? "set" : "—")),
        element("span", "", "Beacon: " + (contract.beaconSlot ? "set" : "—"))
      );
      root.append(card);
    }
  }

  function renderCandidateIntelligence(candidate) {
    const intelligence = candidate.ethereum?.intelligence;
    const contentRoot = $("candidate-intelligence-content");
    $("candidate-intelligence-empty").classList.toggle("hidden", Boolean(intelligence));
    contentRoot.classList.toggle("hidden", !intelligence);
    if (!intelligence) return;

    const snapshot = candidate.ethereum?.pinnedStateSnapshot;
    const attested = (candidate.ethereum?.sourceInspections || []).filter(inspection =>
      ["SOURCE_RECOMPILED_EXACT", "SOURCE_RECOMPILED_METADATA_EQUIVALENT"].includes(inspection.bytecodeAttestation?.status)
    ).length;
    $("candidate-intelligence-metrics").replaceChildren(
      createCompactStat("◎", "Graph Nodes", intelligence.graph?.nodes?.length || 0),
      createCompactStat("↔", "Graph Edges", intelligence.graph?.edges?.length || 0),
      createCompactStat("◇", "Invariants", intelligence.invariants?.length || 0),
      createCompactStat("⇧", "Escalation Plans", intelligence.escalationPlans?.length || 0),
      createCompactStat("⌁", "Attack Paths", intelligence.attackPaths?.length || 0),
      createCompactStat("✓", "Bytecode Attested", attested)
    );
    renderKnowledgeGraph(intelligence);
    renderAttestations(candidate);
    renderInvariants(intelligence);
    renderAttackPaths(intelligence);
    renderSnapshot(candidate);
    if (snapshot?.partial) showToast("Pinned protocol snapshot is partial; inspect its limitations before relying on absence of state changes.", "error");
  }

    function renderSeverityMetrics(findings) {
  const severity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  const evidence = { REPRODUCED_FORK: 0, REPRODUCED_MODEL: 0, EXECUTED: 0, STRUCTURAL: 0, HEURISTIC: 0 };
  for (const finding of findings) {
    if (severity[finding.severity] !== undefined) severity[finding.severity] += 1;
    if (evidence[finding.evidenceKey] !== undefined) evidence[finding.evidenceKey] += 1;
  }
  const root = $("findings-severity-metrics");
  root.replaceChildren();
  const configs = [
    ["red", "!", "Critical", severity.CRITICAL],
    ["red", "▲", "High", severity.HIGH],
    ["purple", "◎", "Reproduced", evidence.REPRODUCED_FORK + evidence.REPRODUCED_MODEL],
    ["blue", "▶", "Executed", evidence.EXECUTED],
    ["blue", "◇", "Structural", evidence.STRUCTURAL],
    ["green", "⌕", "Heuristic", evidence.HEURISTIC]
  ];
  for (const [color, icon, label, value] of configs) {
    const card = element("article", `metric-card ${color}`);
    card.append(element("div", "metric-icon", icon));
    const copy = element("div");
    copy.append(element("small", "", label), element("strong", "", value));
    card.append(copy);
    root.append(card);
  }
}

  function syncFindingKindOptions(findings) {
  const select = $("findings-kind-filter");
  const current = select.value || "ALL";
  const kinds = [...new Set(findings.map(f => f.kind))].sort();
  select.replaceChildren();
  const all = element("option", "", "All");
  all.value = "ALL";
  select.append(all);
  for (const kind of kinds) {
    const option = element("option", "", humanize(kind));
    option.value = kind;
    select.append(option);
  }
  select.value = kinds.includes(current) ? current : "ALL";
}

  function findingIcon(severity) {
  if (severity === "CRITICAL") return "!";
  if (severity === "HIGH") return "▲";
  if (severity === "MEDIUM") return "◇";
  if (severity === "LOW") return "△";
  return "i";
}

  function appendFindingDetails(copy, title, values) {
  const items = (values || []).filter(Boolean);
  if (!items.length) return;
  const details = element("details", "finding-details");
  details.append(element("summary", "", title));
  const list = element("ul", "finding-detail-list");
  for (const value of items) list.append(element("li", "", value));
  details.append(list);
  copy.append(details);
}

  function renderAnalysisCompleteness(candidate) {
    const completeness = analysisCompleteness(candidate);
    const warning = $("candidate-analysis-warning");
    warning.replaceChildren();
    warning.classList.toggle("hidden", !completeness.partial);
    if (!completeness.partial) return;

    warning.append(element("strong", "", "Partial analysis — absence of a finding is not a clean pass."));
    const list = element("ul");
    for (const notice of completeness.notices) list.append(element("li", "", notice));
    warning.append(list);
  }

  function activeFindingFilters() {
    return {
      severity: $("findings-severity-filter").value,
      evidence: $("findings-evidence-filter").value,
      kind: $("findings-kind-filter").value,
      sort: $("findings-sort").value
    };
  }

  function findingMatchesFilters(finding, filters) {
    const severityMatches = filters.severity === "ALL" || finding.severity === filters.severity;
    const evidenceMatches = filters.evidence === "ALL" || finding.evidenceKey === filters.evidence;
    const kindMatches = filters.kind === "ALL" || finding.kind === filters.kind;
    return severityMatches && evidenceMatches && kindMatches;
  }

  function sortFindings(findings, sort) {
    const rows = [...findings];
    if (sort === "file") {
      return rows.sort((a, b) => {
        const fileCompare = String(a.file).localeCompare(String(b.file));
        return fileCompare || Number(a.line || 0) - Number(b.line || 0);
      });
    }
    if (sort === "evidence") {
      return rows.sort((a, b) =>
        (evidenceOrder[a.evidenceKey] ?? 99) - (evidenceOrder[b.evidenceKey] ?? 99) ||
        (severityOrder[a.severity] ?? 99) - (severityOrder[b.severity] ?? 99)
      );
    }
    return rows.sort((a, b) =>
      (severityOrder[a.severity] ?? 99) - (severityOrder[b.severity] ?? 99) ||
      (evidenceOrder[a.evidenceKey] ?? 99) - (evidenceOrder[b.evidenceKey] ?? 99)
    );
  }

  function groupFindingsByContract(findings) {
    const groups = new Map();
    for (const finding of findings) {
      const key = finding.contractRefId + "|" + finding.contractName;
      const current = groups.get(key) || [];
      current.push(finding);
      groups.set(key, current);
    }
    return [...groups.values()];
  }

  function findingContractSubtitle(finding) {
    const role = finding.sourceRole || "DIRECT";
    return finding.compilerVersion ? role + " · " + finding.compilerVersion : role;
  }

  function pluralizedFindingCount(count) {
    return count + (count === 1 ? " finding" : " findings");
  }

  function createFindingGroupHeader(first, count) {
    const header = element("div", "finding-contract-header");
    const headerCopy = element("div");
    headerCopy.append(
      element("h3", "", first.contractName),
      element("small", "", findingContractSubtitle(first))
    );
    header.append(headerCopy, element("strong", "", pluralizedFindingCount(count)));
    return header;
  }

  function externalReachabilityValue(finding) {
    if (finding.reachableFromExternalEntry === undefined) return "Unknown";
    return finding.reachableFromExternalEntry ? "Yes" : "No";
  }

  function createFindingMeta(finding) {
    const meta = element("div", "finding-meta-grid");
    const values = [
      ["Confidence", humanize(finding.confidence || "unknown")],
      ["Engine", humanize(finding.engine || "native")],
      ["Exploitability", humanize(finding.exploitabilityVerdict || "unknown")],
      ["External reachability", externalReachabilityValue(finding)]
    ];
    for (const [label, value] of values) {
      const item = element("div", "finding-meta-item");
      item.append(element("span", "", label), element("strong", "", value));
      meta.append(item);
    }
    return meta;
  }

  function appendFindingRemediation(copy, finding) {
    if (!finding.remediation) return;
    const guidance = element("div", "finding-guidance");
    guidance.append(
      element("strong", "", "Recommended remediation"),
      element("p", "", finding.remediation)
    );
    copy.append(guidance);
  }

  function historicalSummary(finding) {
    const history = finding.historical;
    if (!history?.analogues?.length) return "";
    const category = humanize(history.predictedCategory);
    const confidence = Math.round(Number(history.categoryConfidence || 0) * 100);
    const analogueLabel = history.analogues.length === 1 ? " analogue" : " analogues";
    return category + " · " + confidence + "% category confidence · review-priority context " +
      history.historicalRiskScore + "/100 · " + history.analogues.length + analogueLabel +
      ". Supporting context only.";
  }

  function appendFindingHistory(copy, finding) {
    const summary = historicalSummary(finding);
    if (!summary) return;
    const history = element("div", "finding-history");
    history.append(
      element("strong", "", "Historical Audit Intelligence"),
      element("p", "", summary)
    );
    copy.append(history);
  }

  function mitigationDetailRows(finding) {
    return (finding.mitigations || []).map(item => {
      const evidence = item.evidence ? " — " + item.evidence : "";
      return humanize(item.kind) + evidence;
    });
  }

  function witnessDetailRows(finding) {
    return (finding.witnessPath || []).map(step => {
      const file = step.location?.file || "unknown";
      const line = step.location?.line || 0;
      return humanize(step.role) + " · " + step.symbol + " · " + file + ":" + line;
    });
  }

  function counterexampleDetailRows(finding) {
    const counterexample = finding.counterexample;
    if (!counterexample) return [];
    const rows = [];
    if (counterexample.observedViolation) rows.push(counterexample.observedViolation);
    rows.push(...(counterexample.sequence || []).map((step, index) => (index + 1) + ". " + step));
    if (counterexample.seed !== undefined) rows.push("Seed: " + counterexample.seed);
    if (counterexample.blockNumber !== undefined) rows.push("Pinned block: " + counterexample.blockNumber);
    return rows;
  }

  function findingLocationValue(finding) {
    if (finding.line <= 0) return finding.file;
    const column = finding.column ? ":" + finding.column : "";
    return finding.file + " · line " + finding.line + column;
  }

  function findingLayerLabel(finding) {
    return finding.sourceLayer === "advanced" ? "Advanced analysis" : "Source review";
  }

  function createFindingCard(finding) {
    const card = element("article", "finding-card finding-card-detailed");
    const severityClass = "severity-block " + String(finding.severity).toLowerCase();
    const severity = element("div", severityClass);
    severity.append(
      element("strong", "", finding.severity),
      element("span", "", findingIcon(finding.severity))
    );

    const copy = element("div", "finding-copy");
    const heading = element("div", "finding-heading-row");
    heading.append(element("h3", "", finding.title));
    const badges = element("div", "finding-badges");
    const evidenceClass = "finding-badge evidence " + String(finding.evidenceKey).toLowerCase();
    badges.append(
      element("span", evidenceClass, findingEvidenceLabel(finding)),
      element("span", "finding-badge", humanize(finding.kind))
    );
    heading.append(badges);
    copy.append(heading, element("p", "", finding.description), createFindingMeta(finding));

    appendFindingRemediation(copy, finding);
    appendFindingHistory(copy, finding);
    appendFindingDetails(copy, "Detected mitigations", mitigationDetailRows(finding));
    appendFindingDetails(copy, "Witness path", witnessDetailRows(finding));
    appendFindingDetails(copy, "Counterexample", counterexampleDetailRows(finding));
    appendFindingDetails(copy, "Limitations", finding.limitations || []);

    const side = element("div", "finding-side");
    side.append(
      element("div", "finding-location", findingLocationValue(finding)),
      element("div", "", finding.contractName),
      element("span", "kind-chip", findingLayerLabel(finding))
    );
    card.append(severity, copy, side);
    return card;
  }

  function createFindingGroup(group) {
    const root = element("section", "finding-contract-group");
    root.append(createFindingGroupHeader(group[0], group.length));
    for (const finding of group) root.append(createFindingCard(finding));
    return root;
  }

  function renderCandidateFindings(candidate) {
    const allFindings = flattenFindings(candidate);
    renderSeverityMetrics(allFindings);
    syncFindingKindOptions(allFindings);
    renderAnalysisCompleteness(candidate);

    const filters = activeFindingFilters();
    const matches = allFindings.filter(finding => findingMatchesFilters(finding, filters));
    const findings = sortFindings(matches, filters.sort);
    const root = $("candidate-findings-list");
    root.replaceChildren();
    $("candidate-findings-empty").classList.toggle("hidden", findings.length > 0);

    for (const group of groupFindingsByContract(findings)) {
      root.append(createFindingGroup(group));
    }
  }

    function evidenceIcon(kind) {
    if (kind === "historical_incident") return "!";
    if (kind === "archived_code") return "▤";
    if (kind === "public_audit_finding") return "◇";
    if (kind === "upgradeability_surface") return "↟";
    return "⌁";
  }

  function renderCandidateEvidence(candidate) {
    const evidence = candidate.evidence || [];
    const root = $("candidate-evidence-list");
    root.replaceChildren();
    $("candidate-evidence-empty").classList.toggle("hidden", evidence.length > 0);

    for (const item of evidence) {
      const card = element("article", "evidence-card");
      card.append(element("div", "evidence-icon", evidenceIcon(item.kind)));

      const copy = element("div", "evidence-copy");
      const titleRow = element("div", "evidence-meta");
      const trustClass = item.sourceTrust === "HIGH" ? "high" : item.sourceTrust === "MEDIUM" ? "medium" : "general";
      titleRow.append(
        element("span", `trust-badge ${trustClass}`, `${item.sourceTrust} TRUST`),
        element("span", "", item.year),
        element("span", "", humanize(item.kind))
      );
      copy.append(
        element("h3", "", item.sourceTitle || item.sourceHost),
        titleRow,
        element("p", "", item.snippet || "No source snippet available."),
        element("div", "evidence-meta", item.sourceHost)
      );

      const button = element("button", "primary-button open-source-button", "Open Source ↗");
      button.type = "button";
      button.addEventListener("click", () => api.openExternal(item.sourceUrl));
      card.replaceChildren(element("div", "evidence-icon", evidenceIcon(item.kind)), copy, button);
      root.append(card);
    }
  }

  function switchCandidateTab(tab) {
    state.selectedCandidateTab = tab;
    document.querySelectorAll(".candidate-tab").forEach(button => button.classList.toggle("active", button.dataset.candidateTab === tab));
    $("candidate-tab-overview").classList.toggle("hidden", tab !== "overview");
    $("candidate-tab-intelligence").classList.toggle("hidden", tab !== "intelligence");
    $("candidate-tab-findings").classList.toggle("hidden", tab !== "findings");
    $("candidate-tab-evidence").classList.toggle("hidden", tab !== "evidence");
    if (tab === "intelligence" && state.selectedCandidate) renderCandidateIntelligence(state.selectedCandidate);
    if (tab === "findings" && state.selectedCandidate) renderCandidateFindings(state.selectedCandidate);
    if (tab === "evidence" && state.selectedCandidate) renderCandidateEvidence(state.selectedCandidate);
  }

  function renderCandidate() {
    const candidate = state.selectedCandidate;
    if (!candidate) {
      showScreen("results");
      return;
    }
    renderCandidateHeader(candidate);
    renderCandidateOverview(candidate);
    renderCandidateIntelligence(candidate);
    renderCandidateFindings(candidate);
    renderCandidateEvidence(candidate);
    switchCandidateTab(state.selectedCandidateTab);
  }

  function renderActivity() {
    const scan = state.lastScan;
    const metrics = aggregateCandidates();
    $("activity-last-scan").textContent = scan ? String(scan.endYear) : "—";
    $("activity-status").textContent = state.running ? "Running" : scan ? "Complete" : "Idle";
    $("activity-candidates").textContent = String(metrics.candidates);
    $("summary-range").textContent = scan ? `${scan.startYear} – ${scan.endYear}` : "—";
    $("summary-pages").textContent = scan ? String(scan.pagesPerQuery ?? state.settings?.maxPagesPerQuery ?? "—") : "—";
    $("summary-reviewed").textContent = String(metrics.reviewed);
    $("summary-high").textContent = String(metrics.high);
    $("summary-flags").textContent = String(metrics.flags);
    $("summary-started").textContent = scan ? formatDateTime(scan.startedAt) : "—";
    $("summary-completed").textContent = scan ? formatDateTime(scan.completedAt) : "—";
    $("summary-duration").textContent = scan ? formatDuration(scan.durationMs) : "—";
    $("highlight-years").textContent = scan ? `${scan.startYear} – ${scan.endYear}` : "—";
    $("highlight-reviewed").textContent = String(metrics.reviewed);
    $("highlight-flags").textContent = String(metrics.flags);
    $("highlight-high").textContent = String(metrics.high);
    $("highlight-candidates").textContent = String(metrics.candidates);
    $("activity-export-summary").disabled = !scan;
    renderActivityLog();
  }

  function renderCliStatus() {
    const status = state.cliStatus;
    if (!status || !$("settings-cli-badge")) return;
    const installed = Boolean(status.installed);
    const pathReady = Boolean(status.pathConfigured);
    $("settings-cli-badge").textContent = installed ? (pathReady ? "Installed" : "Installed · restart terminal") : "Not installed";
    $("settings-cli-badge").className = `connected-badge ${installed ? (pathReady ? "" : "neutral") : "neutral"}`.trim();
    $("settings-cli-path").textContent = status.commandPath || "";
    $("settings-install-cli").textContent = installed ? "Repair CLI" : "Install CLI";
    $("settings-remove-cli").classList.toggle("hidden", !installed);
    $("settings-cli-detail").textContent = installed
      ? pathReady
        ? "The global command is ready and shares this app's OS-encrypted API keys and scan settings."
        : "The launcher is installed. Open a new terminal so the updated PATH is picked up."
      : status.packaged
        ? "Install the user-level command to use the same secure desktop configuration from Terminal."
        : "Global CLI installation is available from packaged releases only.";
    $("settings-install-cli").disabled = !status.packaged;
  }

  function renderAnalysisCapabilities() {
    const root = $("analysis-capability-list");
    if (!root) return;
    root.replaceChildren();
    const capabilities = [{ id: "native", available: true, version: "Built in" }, ...state.analysisCapabilities];
    for (const capability of capabilities) {
      const card = element("div", "capability-card");
      const copy = element("div");
      copy.append(
        element("strong", "", humanize(capability.id)),
        element("small", "", capability.available ? capability.version || "Available" : "Not installed · optional")
      );
      const badge = element("span", `connected-badge ${capability.available ? "" : "neutral"}`.trim(), capability.available ? "Available" : "Optional");
      card.append(copy, badge);
      root.append(card);
    }
  }

  function renderLabCapabilities() {
    const root = $("analysis-capabilities");
    if (!root) return;
    root.replaceChildren();
    for (const capability of [{ id: "native", available: true, version: "Built in" }, ...state.analysisCapabilities]) {
      const card = element("div", "capability-card");
      const copy = element("div");
      copy.append(element("strong", "", humanize(capability.id)), element("small", "", capability.available ? capability.version || "Available" : capability.reason || "Not installed - optional"));
      card.append(copy, element("span", `connected-badge ${capability.available ? "" : "neutral"}`.trim(), capability.available ? "Available" : "Optional"));
      root.append(card);
    }
  }

  async function refreshAnalysisCapabilities() {
    try {
      state.analysisCapabilities = await api.getAnalysisCapabilities();
    } catch {
      state.analysisCapabilities = [];
    }
    renderAnalysisCapabilities();
    renderLabCapabilities();
  }

  async function refreshCliStatus() {
    try {
      state.cliStatus = await api.getCliStatus();
      renderCliStatus();
      if ($("setup-install-cli")) $("setup-install-cli").checked = !state.cliStatus.installed || !state.cliStatus.pathConfigured;
      return state.cliStatus;
    } catch (error) {
      state.cliStatus = null;
      if ($("settings-cli-badge")) {
        $("settings-cli-badge").textContent = "Unavailable";
        $("settings-cli-badge").className = "connected-badge bad";
      }
      return null;
    }
  }

  async function installCliFromUi() {
    $("settings-install-cli").disabled = true;
    try {
      state.cliStatus = await api.installCli();
      renderCliStatus();
      showToast("risk-radar CLI installed. Open a new terminal and run risk-radar doctor.", "success");
    } catch (error) {
      showToast(error?.message || String(error), "error");
    } finally {
      if ($("settings-install-cli")) $("settings-install-cli").disabled = !state.cliStatus?.packaged;
    }
  }

  async function uninstallCliFromUi() {
    $("settings-remove-cli").disabled = true;
    try {
      state.cliStatus = await api.uninstallCli();
      renderCliStatus();
      showToast("risk-radar CLI launcher removed.", "success");
    } catch (error) {
      showToast(error?.message || String(error), "error");
    } finally {
      $("settings-remove-cli").disabled = false;
    }
  }

  function renderSettings() {
    if (!state.settings) return;
    const s = state.settings;
    $("settings-tinyfish-endpoint").textContent = s.tinyfishEndpoint;
    $("settings-pages").value = String(s.maxPagesPerQuery);
    $("settings-min-signals").value = String(s.minPublicSignals);
    $("settings-etherscan-lookups").value = String(s.maxEtherscanLookupsPerCandidate);
    $("settings-inspect-source").checked = Boolean(s.inspectVerifiedSource);
    $("settings-source-bytes").value = String(s.maxSourceBytes);
    $("settings-max-findings").value = String(s.maxSourceFindingsPerContract);
    $("settings-output-dir").value = s.outputDir;
    $("settings-remove-etherscan").classList.toggle("hidden", !s.hasEtherscanApiKey);
    updateConnectionUI();
    renderCliStatus();
    renderAnalysisCapabilities();
  }

  async function refreshSettings() {
    state.settings = await api.getSettings();
    updateConnectionStateFromSettings();
    populateSetupAdvanced();
    renderSettings();
    return state.settings;
  }

  async function saveSettingsForm(event) {
    event.preventDefault();
    $("settings-error").classList.add("hidden");
    $("settings-save").disabled = true;
    try {
      state.settings = await api.saveSettings({
        maxPagesPerQuery: clamp($("settings-pages").value, 1, 10, 1),
        minPublicSignals: clamp($("settings-min-signals").value, 2, 8, 2),
        maxEtherscanLookupsPerCandidate: clamp($("settings-etherscan-lookups").value, 0, 5, 2),
        inspectVerifiedSource: $("settings-inspect-source").checked,
        maxSourceBytes: clamp($("settings-source-bytes").value, 10000, 5000000, 2000000),
        maxSourceFindingsPerContract: clamp($("settings-max-findings").value, 1, 250, 80),
        outputDir: $("settings-output-dir").value.trim()
      });
      $("dashboard-pages").value = String(state.settings.maxPagesPerQuery);
      renderSettings();
      showToast("Settings saved.", "success");
    } catch (error) {
      $("settings-error").textContent = error?.message || String(error);
      $("settings-error").classList.remove("hidden");
    } finally {
      $("settings-save").disabled = false;
    }
  }

  function openKeyModal(provider) {
    state.keyModalProvider = provider;
    const name = provider === "tinyfish" ? "TinyFish" : "Etherscan";
    $("key-modal-title").textContent = `Replace ${name} API Key`;
    $("key-modal-description").textContent = provider === "tinyfish"
      ? "Enter a new TinyFish key. The existing encrypted key will be replaced after you save."
      : "Enter a new Etherscan key. The existing encrypted key will be replaced after you save.";
    $("key-modal-label").textContent = `${name} API Key`;
    $("key-modal-input").value = "";
    $("key-modal-error").classList.add("hidden");
    openModal("key-modal");
    setTimeout(() => $("key-modal-input").focus(), 60);
  }

  async function saveReplacementKey(event) {
    event.preventDefault();
    const key = $("key-modal-input").value.trim();
    if (!key) return;
    $("key-modal-save").disabled = true;
    $("key-modal-error").classList.add("hidden");
    try {
      const payload = state.keyModalProvider === "tinyfish" ? { tinyfishApiKey: key } : { etherscanApiKey: key };
      state.settings = await api.saveSettings(payload);
      state.connection[state.keyModalProvider] = "configured";
      renderSettings();
      updateConnectionUI();
      closeModal("key-modal");
      showToast(`${state.keyModalProvider === "tinyfish" ? "TinyFish" : "Etherscan"} API key replaced securely.`, "success");
    } catch (error) {
      $("key-modal-error").textContent = error?.message || String(error);
      $("key-modal-error").classList.remove("hidden");
    } finally {
      $("key-modal-save").disabled = false;
    }
  }

  async function removeEtherscanKey() {
    $("confirm-remove-etherscan").disabled = true;
    try {
      state.settings = await api.saveSettings({ clearEtherscanApiKey: true });
      state.connection.etherscan = "optional";
      renderSettings();
      updateConnectionUI();
      closeModal("confirm-modal");
      showToast("Etherscan API key removed. TinyFish discovery remains enabled.", "success");
    } catch (error) {
      showToast(error?.message || String(error), "error");
    } finally {
      $("confirm-remove-etherscan").disabled = false;
    }
  }

  async function exportSummary() {
    try {
      const path = await api.exportScanSummary();
      if (path) showToast("Scan summary exported.", "success");
    } catch (error) {
      showToast(error?.message || String(error), "error");
    }
  }

  function setAnalysisRunning(running, message) {
    state.analysisRunning = running;
    $("analysis-cancel").classList.toggle("hidden", !running);
    for (const id of ["analysis-project-run", "protocol-run", "economic-run", "fork-run"]) $(id).disabled = running;
    if (message) $("analysis-status").textContent = message;
  }

  function summaryItem(label, value) {
    const node = element("div", "analysis-summary-item");
    node.append(element("small", "", label), element("strong", "", value));
    return node;
  }

  function resultRow(title, detail) {
    const node = element("div", "analysis-result-row");
    node.append(element("strong", "", title), element("small", "", detail));
    return node;
  }

  function renderAnalysisResult(kind, result) {
    state.analysisResult = { kind, result };
    const root = $("analysis-result-content");
    root.replaceChildren();
    $("analysis-result-summary").classList.add("hidden");
    root.classList.remove("hidden");
    $("analysis-result-state").textContent = "COMPLETE";
    const summary = element("div", "analysis-summary-grid");
    if (kind === "project") {
      summary.append(summaryItem("State", result.state || "complete"), summaryItem("Findings", result.findings?.length || 0), summaryItem("Contracts", result.protocol?.contracts?.length || 0), summaryItem("Engine runs", result.engines?.length || 0));
      root.append(summary);
      for (const finding of (result.findings || []).slice(0, 100)) root.append(resultRow(`${finding.severity} - ${finding.title}`, `${humanize(finding.evidenceStrength)} / ${humanize(finding.exploitabilityVerdict || "unknown")}. ${(finding.limitations || []).join(" ")}`));
      for (const engine of result.engines || []) root.append(resultRow(`${humanize(engine.engine)}: ${humanize(engine.state)}`, (engine.diagnostics || []).join(" ") || `${engine.findings?.length || 0} finding(s)`));
    } else if (kind === "protocol") {
      const findings = (result.results || []).filter(item => item.finding);
      summary.append(summaryItem("Contracts", result.protocol?.contracts?.length || 0), summaryItem("Call edges", result.protocol?.calls?.length || 0), summaryItem("Scenarios", result.results?.length || 0), summaryItem("Model violations", findings.length));
      root.append(summary);
      for (const item of result.results || []) root.append(resultRow(item.scenarioId, item.finding ? `${item.finding.title}. ${item.finding.limitations.join(" ")}` : item.reason || humanize(item.state)));
    } else if (kind === "economic") {
      const failed = (result.invariants || []).filter(item => !item.passed);
      summary.append(summaryItem("Steps", result.finalState?.step || 0), summaryItem("Invariants", result.invariants?.length || 0), summaryItem("Failed", failed.length), summaryItem("Pools", Object.keys(result.protocolSolvency || {}).length));
      root.append(summary);
      for (const item of result.invariants || []) root.append(resultRow(`${item.passed ? "PASS" : "FAIL"} - ${item.id}`, item.description));
    } else {
      summary.append(summaryItem("Observed violation", result.observedViolation ? "Yes" : "No"), summaryItem("Evidence", result.finding?.evidenceStrength || "None"), summaryItem("Scope", result.finding?.evidenceScope || "None"), summaryItem("Exploitability", result.finding?.exploitabilityVerdict || "UNKNOWN"));
      root.append(summary);
      if (result.finding) root.append(resultRow(result.finding.title, `${result.finding.description} ${result.finding.limitations.join(" ")}`));
      else root.append(resultRow("No requested invariant violation observed", "The replay completed without producing a vulnerability finding."));
    }
  }

  function renderAnalysisLab() {
    renderLabCapabilities();
    if (state.analysisResult) renderAnalysisResult(state.analysisResult.kind, state.analysisResult.result);
  }

  async function chooseInto(inputId, chooser) {
    const selected = await chooser();
    if (selected) $(inputId).value = selected;
  }

  async function runLab(kind, action) {
    setAnalysisRunning(true, `${humanize(kind)} is running...`);
    $("analysis-result-state").textContent = "RUNNING";
    try {
      const result = await action();
      renderAnalysisResult(kind, result);
      $("analysis-status").textContent = `${humanize(kind)} completed. Review evidence scope and limitations below.`;
      showToast(`${humanize(kind)} completed.`, "success");
    } catch (error) {
      $("analysis-result-state").textContent = "FAILED";
      $("analysis-status").textContent = error?.message || String(error);
      showToast(error?.message || String(error), "error");
    } finally { setAnalysisRunning(false); }
  }

  function bindEvents() {
    document.querySelectorAll(".nav-button").forEach(button => {
      button.addEventListener("click", () => showScreen(button.dataset.screen));
    });

    $("setup-keys-form").addEventListener("submit", event => {
      event.preventDefault();
      $("setup-keys-error").classList.add("hidden");
      const tinyfish = $("setup-tinyfish-key").value.trim();
      if (!state.settings?.secureStorageAvailable) {
        $("setup-keys-error").textContent = "Secure OS encryption is unavailable; credentials cannot be stored safely.";
        $("setup-keys-error").classList.remove("hidden");
        return;
      }
      if (!tinyfish) {
        $("setup-keys-error").textContent = "TinyFish API key is required.";
        $("setup-keys-error").classList.remove("hidden");
        return;
      }
      state.draftKeys.tinyfishApiKey = tinyfish;
      state.draftKeys.etherscanApiKey = $("setup-etherscan-key").value.trim();
      showOnboardingStep(2);
    });

    $("setup-back").addEventListener("click", () => showOnboardingStep(1));
    $("setup-change-folder").addEventListener("click", async () => {
      const chosen = await api.chooseOutputDir();
      if (chosen) $("setup-output-dir").value = chosen;
    });
    $("setup-advanced-form").addEventListener("submit", async event => {
      event.preventDefault();
      $("setup-advanced-error").classList.add("hidden");
      $("setup-launch").disabled = true;
      try {
        state.settings = await api.saveSettings(publicSettingsPayloadFromSetup());
        if ($("setup-install-cli").checked) {
          try { state.cliStatus = await api.installCli(); }
          catch (cliError) { showToast(`Setup completed, but CLI installation needs attention: ${cliError?.message || String(cliError)}`, "error"); }
        } else {
          await refreshCliStatus();
        }
        state.connection.tinyfish = "configured";
        state.connection.etherscan = state.settings.hasEtherscanApiKey ? "configured" : "optional";
        setOnboarding(false);
        $("dashboard-start-year").value = "2016";
        $("dashboard-end-year").value = String(currentYear);
        $("dashboard-pages").value = String(state.settings.maxPagesPerQuery);
        showScreen("dashboard");
        showToast("Setup complete. API credentials are stored securely.", "success");
      } catch (error) {
        $("setup-advanced-error").textContent = error?.message || String(error);
        $("setup-advanced-error").classList.remove("hidden");
      } finally {
        $("setup-launch").disabled = false;
      }
    });

    document.querySelectorAll("[data-reveal]").forEach(button => {
      button.addEventListener("click", () => {
        const input = $(button.dataset.reveal);
        const reveal = input.type === "password";
        input.type = reveal ? "text" : "password";
        button.textContent = reveal ? "Hide" : "Show";
      });
    });

    document.querySelectorAll("[data-close-modal]").forEach(node => {
      node.addEventListener("click", () => closeModal(node.dataset.closeModal));
    });

    $("dashboard-test-connections").addEventListener("click", () => runConnectionTest(true));
    $("dashboard-start-scan").addEventListener("click", startScan);
    $("dashboard-view-activity").addEventListener("click", () => showScreen("activity"));

    $("results-search").addEventListener("input", renderResults);
    $("results-sort").addEventListener("change", renderResults);
    $("results-open-folder").addEventListener("click", () => api.openOutputFolder());
    $("results-show-json").addEventListener("click", () => state.reportPaths?.jsonPath && api.showReport(state.reportPaths.jsonPath));
    $("results-show-summary-csv").addEventListener("click", () => state.reportPaths?.summaryCsvPath && api.showReport(state.reportPaths.summaryCsvPath));
    $("results-show-findings-csv").addEventListener("click", () => state.reportPaths?.findingsCsvPath && api.showReport(state.reportPaths.findingsCsvPath));
    $("results-show-security-html").addEventListener("click", () => state.reportPaths?.securityReviewPath && api.showReport(state.reportPaths.securityReviewPath));
    $("results-show-sarif").addEventListener("click", () => state.reportPaths?.sarifPath && api.showReport(state.reportPaths.sarifPath));

    $("candidate-back").addEventListener("click", () => showScreen("results"));
    $("candidate-host-link").addEventListener("click", () => {
      const url = state.selectedCandidate?.evidence?.find(e => e.sourceUrl)?.sourceUrl;
      if (url) api.openExternal(url);
    });
    document.querySelectorAll(".candidate-tab").forEach(button => {
      button.addEventListener("click", () => switchCandidateTab(button.dataset.candidateTab));
    });
    $("findings-severity-filter").addEventListener("change", () => state.selectedCandidate && renderCandidateFindings(state.selectedCandidate));
    $("findings-evidence-filter").addEventListener("change", () => state.selectedCandidate && renderCandidateFindings(state.selectedCandidate));
    $("findings-kind-filter").addEventListener("change", () => state.selectedCandidate && renderCandidateFindings(state.selectedCandidate));
    $("findings-sort").addEventListener("change", () => state.selectedCandidate && renderCandidateFindings(state.selectedCandidate));

    $("analysis-project-choose").addEventListener("click", () => chooseInto("analysis-project-path", () => api.chooseAnalysisProject()));
    $("protocol-project-choose").addEventListener("click", () => chooseInto("protocol-project-path", () => api.chooseAnalysisProject()));
    $("protocol-observations-choose").addEventListener("click", () => chooseInto("protocol-observations-path", () => api.chooseAnalysisJson()));
    $("economic-scenario-choose").addEventListener("click", () => chooseInto("economic-scenario-path", () => api.chooseAnalysisJson()));
    $("fork-spec-choose").addEventListener("click", () => chooseInto("fork-spec-path", () => api.chooseAnalysisJson()));
    $("analysis-project-run").addEventListener("click", () => runLab("project", () => {
      const engines = [...document.querySelectorAll(".engine-picker input:checked")].map(node => node.value);
      return api.runProjectAnalysis({ projectPath: $("analysis-project-path").value, engines, trusted: $("analysis-project-trust").checked, timeoutSeconds: Number($("analysis-timeout").value), seed: Number($("analysis-seed").value) });
    }));
    $("protocol-run").addEventListener("click", () => runLab("protocol", () => api.simulateProtocol({ projectPath: $("protocol-project-path").value, observationsPath: $("protocol-observations-path").value, seed: Number($("protocol-seed").value) })));
    $("economic-run").addEventListener("click", () => runLab("economic", () => api.simulateEconomic({ scenarioPath: $("economic-scenario-path").value, maxSteps: Number($("economic-max-steps").value) })));
    $("fork-run").addEventListener("click", () => runLab("fork replay", () => api.replayFork({ specPath: $("fork-spec-path").value, confirmed: $("fork-confirm").checked })));
    $("analysis-cancel").addEventListener("click", async () => { await api.cancelAnalysis(); $("analysis-status").textContent = "Cancellation requested..."; });

    $("activity-clear-log").addEventListener("click", () => {
      state.logs = [];
      renderDashboardLog();
      renderActivityLog();
      showToast("Activity log cleared.");
    });
    $("activity-export-summary").addEventListener("click", exportSummary);

    $("settings-form").addEventListener("submit", saveSettingsForm);
    $("settings-replace-tinyfish").addEventListener("click", () => openKeyModal("tinyfish"));
    $("settings-replace-etherscan").addEventListener("click", () => openKeyModal("etherscan"));
    $("settings-remove-etherscan").addEventListener("click", () => openModal("confirm-modal"));
    $("settings-test-connections").addEventListener("click", () => runConnectionTest(true));
    $("settings-change-folder").addEventListener("click", async () => {
      const chosen = await api.chooseOutputDir();
      if (chosen) $("settings-output-dir").value = chosen;
    });
    $("settings-open-folder").addEventListener("click", () => api.openOutputFolder());
    $("settings-install-cli").addEventListener("click", installCliFromUi);
    $("settings-remove-cli").addEventListener("click", uninstallCliFromUi);
    $("key-modal-form").addEventListener("submit", saveReplacementKey);
    $("confirm-remove-etherscan").addEventListener("click", removeEtherscanKey);

    document.addEventListener("keydown", event => {
      if (event.key !== "Escape") return;
      for (const id of ["connection-modal", "key-modal", "confirm-modal"]) {
        if (!$(id).classList.contains("hidden")) closeModal(id);
      }
    });

    api.onNavigate(payload => {
      const view = payload?.view;
      if (["dashboard", "results", "analysis", "activity", "settings"].includes(view)) showScreen(view);
    });

    api.onScanProgress(payload => updateProgress(payload));
    api.onScanLog(payload => addLog(payload.message, payload.at));
    api.onScanState(payload => setRunning(payload.running));
    api.onScanComplete(result => {
      state.lastScan = result;
      state.candidates = result.candidates || [];
      state.reportPaths = result.paths || null;
      state.progress = { overallPercent: 100, phase: "COMPLETE", message: `Scan complete · ${state.candidates.length} candidates`, completed: 1, total: 1 };
      setRunning(false);
      renderMetrics();
      renderDashboardProgress();
      renderResults();
      renderActivity();
      addLog(`Scan completed: ${state.candidates.length} candidate(s); reports generated.`, result.completedAt);
      showToast(`Scan complete: ${state.candidates.length} candidate(s).`, "success");
    });
    api.onScanError(payload => {
      setRunning(false);
      addLog(`ERROR: ${payload.message || "Unknown scan error"}`);
      showToast(payload.message || "Scan failed.", "error");
    });
    api.onAnalysisState(payload => setAnalysisRunning(Boolean(payload?.running), payload?.running ? `${payload.label || "Analysis"} is running...` : undefined));
    api.onAnalysisProgress(payload => { if (payload?.message) $("analysis-status").textContent = payload.message; });
    api.onAnalysisError(payload => { if (payload?.message) $("analysis-status").textContent = payload.message; });
  }

  async function initialize() {
    bindEvents();
    $("dashboard-start-year").max = String(currentYear);
    $("dashboard-end-year").max = String(currentYear);
    $("dashboard-start-year").value = "2016";
    $("dashboard-end-year").value = String(currentYear);

    try {
      applyAppInfo(await api.getAppInfo());
      await refreshSettings();
      await refreshCliStatus();
      await refreshAnalysisCapabilities();
      $("setup-secure-warning").classList.toggle("hidden", Boolean(state.settings.secureStorageAvailable));

      const last = await api.getLastScan();
      if (last) {
        state.lastScan = last;
        state.candidates = last.candidates || [];
        state.reportPaths = last.paths || null;
        state.progress = { overallPercent: 100, phase: "COMPLETE", message: `Last scan complete · ${state.candidates.length} candidates`, completed: 1, total: 1 };
      }

      if (state.settings.firstRun) {
        setOnboarding(true);
        populateSetupAdvanced();
        showOnboardingStep(1);
      } else {
        setOnboarding(false);
        $("dashboard-pages").value = String(state.settings.maxPagesPerQuery);
        updateConnectionStateFromSettings();
        renderMetrics();
        renderResults();
        renderActivity();
        showScreen("dashboard");
        addLog("Application ready. Defensive passive-research mode enabled.");
        if (state.cliStatus?.packaged && !state.cliStatus?.installed) {
          showToast("This release includes the risk-radar CLI. Install it from Settings → Command Line.");
        }
      }
    } catch (error) {
      showToast(error?.message || String(error), "error");
    }
  }

  void initialize();
})();
