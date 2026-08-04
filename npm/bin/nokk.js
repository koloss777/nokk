#!/usr/bin/env node
// `npx nokk …` / the `nokk` bin — run the embedded binary, passing through args
// (e.g. `nokk --port 9222` starts the CDP server).
"use strict";

const { spawn } = require("child_process");
const { binaryPath } = require("../index.js");

let bin;
try {
  bin = binaryPath();
} catch (e) {
  console.error("[nokk] " + e.message);
  process.exit(1);
}

const child = spawn(bin, process.argv.slice(2), { stdio: "inherit" });
child.on("exit", (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  else process.exit(code == null ? 1 : code);
});
