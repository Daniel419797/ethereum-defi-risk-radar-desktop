import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { analyzeProjectFromDesktop, replayForkFromDesktop, simulateEconomicFromDesktop, simulateProtocolFromDesktop } from "../dist/desktop/analysisLab.js";

const root = path.resolve(new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
const html = await fs.readFile(path.join(root, "desktop", "renderer", "index.html"), "utf8");
const appJs = await fs.readFile(path.join(root, "desktop", "renderer", "app.js"), "utf8");
const preload = await fs.readFile(path.join(root, "desktop", "preload.cjs"), "utf8");
const main = await fs.readFile(path.join(root, "src", "desktop", "main.ts"), "utf8");

const contracts = [
  ["runProjectAnalysis", "analysis:run-project", "analysis-project-run"],
  ["simulateEconomic", "analysis:simulate-economic", "economic-run"],
  ["simulateProtocol", "analysis:simulate-protocol", "protocol-run"],
  ["replayFork", "analysis:replay-fork", "fork-run"],
  ["cancelAnalysis", "analysis:cancel", "analysis-cancel"]
];
for (const [bridge, channel, control] of contracts) {
  assert.ok(preload.includes(`${bridge}:`), `preload is missing ${bridge}`);
  assert.ok(main.includes(`ipcMain.handle("${channel}"`), `main is missing ${channel}`);
  assert.ok(html.includes(`id="${control}"`), `renderer is missing ${control}`);
  assert.ok(appJs.includes(`$("${control}").addEventListener`), `renderer handler is missing ${control}`);
}
assert.ok(html.includes('data-screen="analysis"') && appJs.includes('"analysis"'), "Analysis Lab must be navigable");

const temp = await fs.mkdtemp(path.join(os.tmpdir(), "risk-radar-analysis-lab-"));
try {
  const source = `pragma solidity ^0.8.20; contract LendingPool { mapping(address=>uint) balances; function withdraw(address target) external { target.call(""); } }`;
  await fs.writeFile(path.join(temp, "Pool.sol"), source, "utf8");
  const project = await analyzeProjectFromDesktop({ projectPath: temp, engines: ["native"], trusted: false, timeoutSeconds: 5, seed: 7 });
  assert.equal(project.targetType, "local_project");
  assert.ok(project.native?.filesAnalyzed === 1 && project.protocol?.contracts.length === 1);
  await assert.rejects(analyzeProjectFromDesktop({ projectPath: temp, engines: ["slither"], trusted: false }), /explicit project trust/);
  await assert.rejects(analyzeProjectFromDesktop({ projectPath: temp, engines: ["unexpected-engine"], trusted: true }), /unsupported engine/);

  const economicPath = path.join(temp, "economic.json");
  await fs.writeFile(economicPath, JSON.stringify({ initial: { actors: { user: { id: "user", balances: { ETH: 2 }, debt: {} } }, pools: {}, prices: { ETH: 1000 }, step: 0 }, actions: [{ type: "price_shock", asset: "ETH", multiplier: 0.5 }] }), "utf8");
  const economic = await simulateEconomicFromDesktop({ scenarioPath: economicPath, maxSteps: 10 });
  assert.equal(economic.finalState.prices.ETH, 500);
  await fs.writeFile(economicPath, JSON.stringify({ initial: { actors: {}, pools: {}, prices: { ETH: -1 }, step: 0 }, actions: [] }), "utf8");
  await assert.rejects(simulateEconomicFromDesktop({ scenarioPath: economicPath, maxSteps: 10 }), /finite and non-negative/);

  const observationsPath = path.join(temp, "observations.json");
  await fs.writeFile(observationsPath, JSON.stringify({ prices: { ETH: 1000, USD: 1 }, pools: { LendingPool: { reserves: { ETH: 1 }, liabilities: { USD: 750 } } }, actor: { id: "researcher", balances: { ETH: 1 }, debt: {} } }), "utf8");
  const protocol = await simulateProtocolFromDesktop({ projectPath: temp, observationsPath, seed: 11 });
  assert.ok(protocol.protocol.contracts.length === 1 && protocol.results.length > 0);
  await assert.rejects(replayForkFromDesktop({ specPath: observationsPath, confirmed: false }), /explicit confirmation/);
} finally {
  await fs.rm(temp, { recursive: true, force: true });
}

console.log("Desktop Analysis Lab checks passed: four workflows, bridge/IPC/UI contracts, trust gate, native analysis, economic and protocol execution.");
