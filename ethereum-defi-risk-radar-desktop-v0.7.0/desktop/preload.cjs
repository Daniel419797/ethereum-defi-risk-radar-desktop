"use strict";

const { contextBridge, ipcRenderer } = require("electron");

function subscribe(channel, callback) {
  const listener = (_event, payload) => callback(payload);
  ipcRenderer.on(channel, listener);
  return () => ipcRenderer.removeListener(channel, listener);
}

contextBridge.exposeInMainWorld("riskRadar", {
  getAppInfo: () => ipcRenderer.invoke("app:get-info"),
  getSettings: () => ipcRenderer.invoke("settings:get"),
  saveSettings: payload => ipcRenderer.invoke("settings:save", payload),
  chooseOutputDir: () => ipcRenderer.invoke("settings:choose-output"),
  testConnections: () => ipcRenderer.invoke("connections:test"),
  getAnalysisCapabilities: () => ipcRenderer.invoke("analysis:capabilities"),
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
  onNavigate: callback => subscribe("app:navigate", callback)
});
