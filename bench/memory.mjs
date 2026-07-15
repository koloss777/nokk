// Reproduces the memory / start-time numbers in the README.
//
//   1. Start a server:  cargo run --release --bin nokk -- --port 9222 --workers 1 --max-contexts 300
//   2. Find its PID:    NOKK_PID=$(ss -ltnp | grep :9222 | grep -oP 'pid=\K[0-9]+')
//   3. Run:             cd bench && npm i puppeteer-core && NOKK_PID=$NOKK_PID node memory.mjs
//
// Engine start time is printed by the server itself ("engine ready elapsed_ms=…").
// This script measures RSS (via /proc/<pid>/status) before and after opening N
// contexts, so per-context memory is (loaded - baseline) / N.
import puppeteer from 'puppeteer-core';
import fs from 'fs';

const PID = process.env.NOKK_PID;
if (!PID) { console.error('set NOKK_PID to the running nokk server pid'); process.exit(1); }
const N = Number(process.env.N || 100);
const rssMB = () => (+/VmRSS:\s+(\d+)/.exec(fs.readFileSync(`/proc/${PID}/status`, 'utf8'))[1]) / 1024;

const browser = await puppeteer.connect({ browserWSEndpoint: 'ws://localhost:9222/devtools/browser/nokk' });
const base = rssMB();
const t0 = Date.now();
const pages = [];
for (let i = 0; i < N; i++) pages.push(await browser.newPage());
const perPage = (Date.now() - t0) / N;
await new Promise((r) => setTimeout(r, 700)); // let allocation settle
const loaded = rssMB();

console.log(`baseline RSS (0 contexts):   ${base.toFixed(1)} MB`);
console.log(`after ${N} contexts:          ${loaded.toFixed(1)} MB`);
console.log(`per-context increment:       ${((loaded - base) / N).toFixed(2)} MB`);
console.log(`avg newPage latency (CDP):   ${perPage.toFixed(1)} ms`);

await browser.disconnect();
