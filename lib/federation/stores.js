"use strict";

/**
 * stores.js
 *
 * Purpose:
 * - Read/write federation stores in the mounted data directory (/app/data).
 * - Atomic writes: write temp file then rename.
 *
 * Notes:
 * - DATA_DIR can be overridden for tests, but defaults to /app/data.
 */

const fs = require("fs");
const path = require("path");

const DATA_DIR = process.env.DATA_DIR || "/app/data";

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function filePath(filename) {
  return path.join(DATA_DIR, filename);
}

function readJson(filename, fallbackObject) {
  ensureDataDir();
  const p = filePath(filename);

  if (!fs.existsSync(p)) return fallbackObject;

  const raw = fs.readFileSync(p, "utf8");
  try {
    return JSON.parse(raw);
  } catch (e) {
    // If a store is corrupted, we return fallback so the server doesn't crash.
    // Routes/status should surface an error later.
    return fallbackObject;
  }
}

function writeJsonAtomic(filename, obj) {
  ensureDataDir();
  const p = filePath(filename);
  const tmp = p + ".tmp";

  const body = JSON.stringify(obj, null, 2) + "\n";
  fs.writeFileSync(tmp, body, "utf8");
  fs.renameSync(tmp, p);
}

module.exports = {
  DATA_DIR,
  filePath,
  readJson,
  writeJsonAtomic,
};
