(() => {
  "use strict";

  const api = window.riskRadar;
  if (!api) return;

  const byLabel = new Map();
  let decorating = false;
  let refreshQueued = false;

  function humanize(value) {
    return String(value ?? "")
      .replaceAll("_", " ")
      .toLowerCase()
      .replace(/\b\w/g, character => character.toUpperCase());
  }

  function findingCounts(candidate) {
    let total = 0;
    let highReview = 0;

    for (const inspection of candidate?.ethereum?.sourceInspections ?? []) {
      const legacy = inspection?.inspection?.findings ?? [];
      const advanced = inspection?.inspection?.advancedAnalysis?.findings ?? [];
      total += legacy.length + advanced.length;
      highReview += legacy.filter(finding => finding?.severity === "HIGH_REVIEW").length;
      highReview += advanced.filter(finding =>
        ["CRITICAL", "HIGH", "HIGH_REVIEW"].includes(finding?.severity)
      ).length;
    }

    return { total, highReview };
  }

  function presentation(candidate) {
    const verified = Number(candidate?.ethereum?.verifiedSourceContracts ?? 0);
    const inspected = Number(candidate?.ethereum?.sourceContractsInspected ?? 0);
    const counts = findingCounts(candidate);
    const analyzed = candidate?.resolutionStatus === "SOURCE_ANALYZED" || inspected > 0;

    return {
      verified,
      inspected,
      totalFindings: counts.total,
      highReviewFindings: counts.highReview,
      phase: analyzed ? "SOURCE ANALYZED" : "CONTRACTS VERIFIED",
      phaseClass: analyzed ? "low" : "review"
    };
  }

  function candidateMap(scan) {
    byLabel.clear();
    for (const candidate of scan?.candidates ?? []) {
      if (candidate?.entityKind === "PROTOCOL" && candidate?.label) {
        byLabel.set(candidate.label, candidate);
      }
    }
  }

  function setText(node, value) {
    if (node && node.textContent !== value) node.textContent = value;
  }

  function decorateStaticCopy() {
    const resultsTitle = document.getElementById("results-title");
    setText(resultsTitle, "Verified Protocols");

    const resultsHeaderCopy = resultsTitle?.parentElement?.querySelector("p");
    setText(
      resultsHeaderCopy,
      "Ethereum Mainnet protocols promoted only after Etherscan-verified source resolution; findings remain evidence-scoped review signals."
    );

    const headers = document.querySelectorAll(".results-table thead th");
    const labels = [
      "Score",
      "Protocol",
      "ETH Confidence",
      "Signals",
      "Verified Contracts",
      "Analysis Status",
      "Actions"
    ];
    headers.forEach((header, index) => setText(header, labels[index] ?? header.textContent));

    const resultsMetric = document.getElementById("results-metric-candidates")?.closest("article")?.querySelector("small");
    setText(resultsMetric, "Verified Protocols");

    const dashboardMetric = document.getElementById("dashboard-metric-candidates")?.closest("article")?.querySelector("small");
    setText(dashboardMetric, "Verified Protocols");

    const empty = document.getElementById("results-empty");
    const emptyStrong = empty?.querySelector("strong");
    const emptyCopy = empty?.querySelector("span");
    setText(emptyStrong, "No verified protocols to show");
    setText(
      emptyCopy,
      "Run a scan or adjust the filter. Document-only leads stay out of Results until an Ethereum Mainnet deployment with verified source is resolved."
    );
  }

  function makeBadge(text, className) {
    const badge = document.createElement("span");
    badge.className = `status-badge ${className}`;
    badge.textContent = text;
    return badge;
  }

  function decorateResults() {
    const rows = document.querySelectorAll("#results-table-body tr");
    for (const row of rows) {
      const label = row.querySelector(".candidate-cell strong")?.textContent?.trim();
      const candidate = label ? byLabel.get(label) : null;
      if (!candidate) continue;

      const cells = row.querySelectorAll("td");
      if (cells.length < 7) continue;

      const view = presentation(candidate);
      setText(cells[4], String(view.verified));

      const signature = [
        view.phase,
        view.totalFindings,
        view.highReviewFindings
      ].join("|");

      if (cells[5].dataset.protocolPresentation !== signature) {
        const badges = [makeBadge(view.phase, view.phaseClass)];
        if (view.highReviewFindings > 0) {
          badges.push(makeBadge(`${view.highReviewFindings} HIGH REVIEW`, "review"));
        } else if (view.totalFindings > 0) {
          badges.push(makeBadge(`${view.totalFindings} FINDINGS`, "low"));
        }
        cells[5].replaceChildren(...badges);
        cells[5].dataset.protocolPresentation = signature;
        cells[5].title = "Security findings are review signals and do not prove current exploitability.";
      }

      const action = cells[6].querySelector("button");
      if (action) {
        const actionText = view.totalFindings > 0 ? "View Findings ›" : "View Analysis ›";
        setText(action, actionText);
        action.setAttribute(
          "aria-label",
          `${actionText.replace(" ›", "")} for ${candidate.label}`
        );
      }
    }
  }

  function candidateSummaryText(candidate, view) {
    if (view.highReviewFindings > 0) {
      return `${view.verified} verified contract${view.verified === 1 ? "" : "s"}; ${view.inspected} source contract${view.inspected === 1 ? "" : "s"} analyzed. ${view.highReviewFindings} high-review finding${view.highReviewFindings === 1 ? "" : "s"} and ${view.totalFindings} total source-analysis finding${view.totalFindings === 1 ? "" : "s"} require manual validation. Findings are not proof of current exploitability.`;
    }
    if (view.totalFindings > 0) {
      return `${view.verified} verified contract${view.verified === 1 ? "" : "s"}; ${view.inspected} source contract${view.inspected === 1 ? "" : "s"} analyzed. ${view.totalFindings} source-analysis finding${view.totalFindings === 1 ? "" : "s"} identified for review; none is currently labelled high-review. Findings are not proof of current exploitability.`;
    }
    return `${view.verified} verified contract${view.verified === 1 ? "" : "s"}; ${view.inspected} source contract${view.inspected === 1 ? "" : "s"} analyzed. The bounded source review emitted no findings. This does not prove the protocol is vulnerability-free.`;
  }

  function decorateCandidate() {
    const title = document.getElementById("candidate-title")?.textContent?.trim();
    const candidate = title ? byLabel.get(title) : null;
    if (!candidate) return;

    const view = presentation(candidate);
    const titleRow = document.querySelector("#screen-candidate .candidate-title-row");
    if (titleRow) {
      let resolution = document.getElementById("candidate-resolution-badge");
      if (!resolution) {
        resolution = makeBadge("", view.phaseClass);
        resolution.id = "candidate-resolution-badge";
        titleRow.append(resolution);
      }
      resolution.className = `status-badge ${view.phaseClass}`;
      setText(resolution, view.phase);
    }

    const screen = document.getElementById("screen-candidate");
    const tabs = screen?.querySelector(".candidate-tabs");
    if (screen && tabs) {
      let summary = document.getElementById("candidate-security-summary");
      if (!summary) {
        summary = document.createElement("div");
        summary.id = "candidate-security-summary";
        summary.className = "notice info";
        summary.setAttribute("role", "status");
        screen.insertBefore(summary, tabs);
      }
      setText(summary, candidateSummaryText(candidate, view));
    }

    const findingsTab = document.querySelector('[data-candidate-tab="findings"]');
    if (findingsTab?.firstChild?.nodeType === Node.TEXT_NODE) {
      const labelText = "Security Findings ";
      if (findingsTab.firstChild.nodeValue !== labelText) {
        findingsTab.firstChild.nodeValue = labelText;
      }
    }

    const interpretation = document.getElementById("candidate-interpretation");
    const resolutionNote = view.highReviewFindings > 0
      ? `${view.highReviewFindings} high-review source finding${view.highReviewFindings === 1 ? "" : "s"} should be investigated first.`
      : view.totalFindings > 0
        ? `${view.totalFindings} source-analysis finding${view.totalFindings === 1 ? "" : "s"} should be reviewed in context.`
        : "No bounded source-review findings were emitted; absence of findings is not a security guarantee.";
    if (interpretation && !interpretation.textContent.includes(resolutionNote)) {
      interpretation.textContent = `${interpretation.textContent} ${resolutionNote}`.trim();
    }
  }

  function decorate() {
    if (decorating) return;
    decorating = true;
    try {
      decorateStaticCopy();
      decorateResults();
      decorateCandidate();
    } finally {
      decorating = false;
    }
  }

  function queueDecorate() {
    if (refreshQueued) return;
    refreshQueued = true;
    queueMicrotask(() => {
      refreshQueued = false;
      decorate();
    });
  }

  async function refreshLastScan() {
    try {
      const scan = await api.getLastScan();
      candidateMap(scan);
      decorate();
    } catch {
      // The main renderer owns connection/error reporting; presentation enhancement stays fail-soft.
    }
  }

  api.onScanComplete(scan => {
    candidateMap(scan);
    decorate();
  });

  const observer = new MutationObserver(queueDecorate);
  observer.observe(document.body, { childList: true, subtree: true });

  decorateStaticCopy();
  refreshLastScan();
})();
