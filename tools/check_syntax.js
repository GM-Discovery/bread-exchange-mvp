"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

function listJsFiles(dir) {
  const out = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      out.push(...listJsFiles(full));
      continue;
    }
    if (e.isFile() && e.name.endsWith(".js")) out.push(full);
  }
  return out;
}

const root = process.cwd();
const files = [
  path.join(root, "server.js"),
  ...listJsFiles(path.join(root, "lib", "federation")),
  ...listJsFiles(path.join(root, "lib", "discovery")),
];

let failed = 0;
for (const f of files) {
  const r = spawnSync(process.execPath, ["--check", f], { stdio: "inherit" });
  if (r.status !== 0) failed += 1;
}

if (failed > 0) {
  console.error(`Syntax check failed for ${failed} file(s).`);
  process.exit(1);
}

console.log(`Syntax check passed for ${files.length} file(s).`);

