import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const preload = await fs.readFile(path.join(root, "desktop", "preload.cjs"), "utf8");
const ui = await fs.readFile(path.join(root, "desktop", "renderer", "protocol-status.js"), "utf8");
const packageJson = JSON.parse(await fs.readFile(path.join(root, "package.json"), "utf8"));

if (!preload.includes('script.src = "./protocol-status.js"')) {
  throw new Error("Protocol presentation script is not loaded from the packaged renderer.");
}
if (!preload.includes('window.addEventListener("DOMContentLoaded"')) {
  throw new Error("Protocol presentation bootstrap must wait for the renderer DOM.");
}

for (const unsafe of ["innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "Function("]) {
  if (ui.includes(unsafe)) throw new Error(`Unsafe protocol renderer API found: ${unsafe}`);
}

for (const marker of [
  "Verified Protocols",
  "Verified Contracts",
  "Analysis Status",
  "Security Findings",
  "resolutionStatus",
  "verifiedSourceContracts",
  "sourceContractsInspected",
  "sourceInspections",
  "View Findings ›",
  "not proof of current exploitability",
  "does not prove the protocol is vulnerability-free"
]) {
  if (!ui.includes(marker)) throw new Error(`Protocol presentation missing marker: ${marker}`);
}

if (!String(packageJson.scripts?.check || "").includes("protocol-ui-check.mjs")) {
  throw new Error("npm run check must execute protocol-ui-check.mjs.");
}
if (packageJson.scripts?.["test:protocol-ui"] !== "node scripts/protocol-ui-check.mjs") {
  throw new Error("Dedicated protocol UI regression script is missing.");
}

console.log("Protocol UI checks passed: verified-protocol status, finding presentation, evidence-honest copy, and safe DOM APIs.");
