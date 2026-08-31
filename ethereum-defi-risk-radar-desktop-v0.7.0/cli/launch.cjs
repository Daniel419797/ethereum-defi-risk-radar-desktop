"use strict";

const { spawn } = require("node:child_process");

// This file is executed by the packaged Electron binary in ELECTRON_RUN_AS_NODE
// mode. It immediately starts the same application normally in headless CLI mode.
// That second process has Electron APIs available, so the CLI can use the same
// safeStorage-encrypted credentials as the desktop UI.
const args = process.argv.slice(2);
const env = { ...process.env };
delete env.ELECTRON_RUN_AS_NODE;

const child = spawn(process.execPath, ["--cli", ...args], {
  env,
  stdio: "inherit",
  windowsHide: false
});

child.on("error", error => {
  console.error(`risk-radar: unable to start desktop CLI runtime: ${error.message}`);
  process.exitCode = 1;
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exitCode = Number.isInteger(code) ? code : 1;
});
