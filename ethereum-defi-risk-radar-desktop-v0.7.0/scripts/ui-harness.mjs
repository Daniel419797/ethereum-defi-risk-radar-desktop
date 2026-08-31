import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "desktop", "renderer");
const port = Number(process.env.RISK_RADAR_UI_PORT || 4177);
const mock = `
window.riskRadar = {
  getAppInfo: async () => ({ version: "0.7.0", platform: "win32", packaged: false }),
  getSettings: async () => ({
    tinyfishEndpoint: "https://agent.tinyfish.ai/v1/automation/run-sse",
    maxEtherscanLookupsPerCandidate: 2,
    inspectVerifiedSource: true,
    maxSourceBytes: 2000000,
    maxSourceFindingsPerContract: 80,
    maxPagesPerQuery: 1,
    minPublicSignals: 2,
    outputDir: "C:\\\\RiskRadarReports",
    hasTinyfishApiKey: true,
    hasEtherscanApiKey: false,
    secureStorageAvailable: true,
    firstRun: false
  }),
  getCliStatus: async () => ({ installed: false, pathConfigured: false, packaged: false }),
  getAnalysisCapabilities: async () => ([
    { id: "slither", available: false, reason: "not installed" },
    { id: "mythril", available: false, reason: "not installed" },
    { id: "foundry", available: false, reason: "not installed" },
    { id: "anvil", available: false, reason: "not installed" },
    { id: "echidna", available: false, reason: "not installed" },
    { id: "python", available: true, version: "Python 3.14.5" },
    { id: "docker", available: true, version: "Docker 29.2.1" }
  ]),
  getLastScan: async () => null,
  saveSettings: async payload => ({ ...(await window.riskRadar.getSettings()), ...payload }),
  chooseOutputDir: async () => null,
  testConnections: async () => ({ tinyfish: { ok: true, message: "Connected" }, etherscan: { ok: null, message: "Optional" } }),
  startScan: async () => null,
  exportScanSummary: async () => null,
  showReport: async () => null,
  openOutputFolder: async () => null,
  openExternal: async () => null,
  installCli: async () => ({ installed: true, pathConfigured: true, packaged: true }),
  uninstallCli: async () => ({ installed: false, pathConfigured: false, packaged: true }),
  onScanProgress: () => () => {}, onScanLog: () => () => {}, onScanComplete: () => () => {},
  onScanError: () => () => {}, onScanState: () => () => {}, onNavigate: () => () => {}
};
`;

const server = http.createServer(async (request, response) => {
  try {
    const requestPath = new URL(request.url || "/", `http://127.0.0.1:${port}`).pathname;
    if (requestPath === "/mock.js") {
      response.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8", "Cache-Control": "no-store" });
      response.end(mock);
      return;
    }
    const relative = requestPath === "/" ? "index.html" : requestPath.slice(1);
    if (!new Set(["index.html", "app.js", "styles.css"]).has(relative)) {
      response.writeHead(404); response.end("Not found"); return;
    }
    let body = await fs.readFile(path.join(root, relative));
    if (relative === "index.html") body = Buffer.from(body.toString("utf8").replace('<script src="./app.js"></script>', '<script src="./mock.js"></script><script src="./app.js"></script>'));
    response.writeHead(200, {
      "Content-Type": relative.endsWith(".html") ? "text/html; charset=utf-8" : relative.endsWith(".css") ? "text/css; charset=utf-8" : "text/javascript; charset=utf-8",
      "Cache-Control": "no-store"
    });
    response.end(body);
  } catch (error) {
    response.writeHead(500); response.end(error instanceof Error ? error.message : "Server error");
  }
});

server.listen(port, "127.0.0.1", () => console.log(`Risk Radar UI harness listening on http://127.0.0.1:${port}`));
