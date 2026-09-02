"use strict";

const { contextBridge, ipcRenderer } = require("electron");

function subscribe(channel, callback) {
  const listener = (_event, payload) => callback(payload);
  ipcRenderer.on(channel, listener);
  return () => ipcRenderer.removeListener(channel, listener);
}

function loadProtocolPresentation() {
  if (!document.head || document.querySelector('script[data-risk-radar-protocol-ui="true"]')) {
    return;
  }
  const script = document.createElement("script");
  script.src = "./protocol-status.js";
  script.defer = true;
  script.dataset.riskRadarProtocolUi = "true";
  document.head.append(script);
}

window.addEventListener("DOMContentLoaded", loadProtocolPresentation, { once: true });

contextBridge.exposeInMainWorld("riskRadar", {
  getAppInfo: () => ipcRenderer.invoke("app:get-info"),
  getSettings: () => ipcRenderer.invoke("settings:get"),
  saveSettings: payload => ipcRenderer.invoke("settings:save", payload),
  chooseOutputDir: () => ipcRenderer.invoke("settings:choose-output"),
  testConnections: () => ipcRenderer.invoke("connections:test"),
  getAnalysisCapabilities: () => ipcRenderer.invoke("analysis:capabilities"),
  chooseAnalysisProject: () => ipcRenderer.invoke("analysis:choose-project"),
  chooseAnalysisJson: () => ipcRenderer.invoke("analysis:choose-json"),
  runProjectAnalysis: payload => ipcRenderer.invoke("analysis:run-project", payload),
  simulateEconomic: payload => ipcRenderer.invoke("analysis:simulate-economic", payload),
  simulateProtocol: payload => ipcRenderer.invoke("analysis:simulate-protocol", payload),
  replayFork: payload => ipcRenderer.invoke("analysis:replay-fork", payload),
  cancelAnalysis: () => ipcRenderer.invoke("analysis:cancel"),
  startScan: payload => ipcRenderer.invoke("scan:start", payload),
  getLastScan: () => ipcRenderer.invoke("scan:last"),
  exportScanSummary: () => ipcRenderer.invoke("scan:export-summary"),
  showReport: filePath => ipcRenderer.invoke("app:show-report", filePath),
  openOutputFolder: () => ipcRenderer.invoke("app:open-output"),
  openExternal: url => ipcRenderer.invoke("app:open-external", url),
  getCliStatus: () => ipcRenderer.invoke("cli:status"),
  installCli: () => ipcRenderer.invoke("cli:install"),
  uninstallCli: () => ipcRenderer.invoke("cli:uninstall"),
  onScanProgress: callback => subscribe("scan:progress", callback),
  onScanLog: callback => subscribe("scan:log", callback),
  onScanComplete: callback => subscribe("scan:complete", callback),
  onScanError: callback => subscribe("scan:error", callback),
  onScanState: callback => subscribe("scan:state", callback),
  onNavigate: callback => subscribe("app:navigate", callback),
  onAnalysisState: callback => subscribe("analysis:state", callback),
  onAnalysisProgress: callback => subscribe("analysis:progress", callback),
  onAnalysisError: callback => subscribe("analysis:error", callback)
});
