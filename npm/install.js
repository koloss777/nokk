// postinstall: download the prebuilt `nokk` binary from the matching GitHub
// Release and extract it into vendor/, so the package ships no binary in the
// tarball (kept small) but `require('nokk')` / `npx nokk` work after install.
// Linux x64 only for now (matches what the release workflow builds).
"use strict";

const https = require("https");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const pkg = require("./package.json");
const REPO = "koloss777/nokk";
const VENDOR = path.join(__dirname, "vendor");
const BIN = path.join(VENDOR, "nokk");

function fail(msg) {
  console.error("[nokk] " + msg);
  process.exit(1);
}

// Allow skipping (e.g. CI that provides NOKK_BINARY, or offline installs).
if (process.env.NOKK_SKIP_DOWNLOAD || process.env.NOKK_BINARY) {
  console.log("[nokk] skipping binary download (NOKK_BINARY / NOKK_SKIP_DOWNLOAD set)");
  process.exit(0);
}

if (process.platform !== "linux" || process.arch !== "x64") {
  fail(
    `prebuilt binary is currently Linux x64 only (got ${process.platform}/${process.arch}). ` +
      `See ${pkg.homepage} — macOS/Windows are on the roadmap.`
  );
}

const tag = "v" + pkg.version; // 0.1.20-alpha -> v0.1.20-alpha
const asset = `nokk-${tag}-linux-x86_64.tar.gz`;
const url = `https://github.com/${REPO}/releases/download/${tag}/${asset}`;

function download(from, dest, cb, redirects) {
  redirects = redirects || 0;
  https
    .get(from, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume();
        if (redirects > 10) return cb(new Error("too many redirects"));
        return download(res.headers.location, dest, cb, redirects + 1);
      }
      if (res.statusCode !== 200) {
        res.resume();
        return cb(new Error(`HTTP ${res.statusCode} for ${from}`));
      }
      const file = fs.createWriteStream(dest);
      res.pipe(file);
      file.on("finish", () => file.close(() => cb(null)));
      file.on("error", cb);
    })
    .on("error", cb);
}

fs.mkdirSync(VENDOR, { recursive: true });
const tmp = path.join(os.tmpdir(), asset);
console.log(`[nokk] downloading ${asset} …`);
download(url, tmp, (err) => {
  if (err) fail(`download failed: ${err.message}\n  ${url}`);
  try {
    execFileSync("tar", ["-xzf", tmp, "-C", VENDOR, "nokk"]);
    fs.chmodSync(BIN, 0o755);
    fs.unlinkSync(tmp);
    console.log("[nokk] installed " + BIN);
  } catch (e) {
    fail("extract failed: " + e.message);
  }
});
