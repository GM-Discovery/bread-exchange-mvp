"use strict";

/**
 * canonical.js
 *
 * Purpose:
 * - Deterministic JSON serialization for federation signatures/hashes
 * - SHA256 hashing helpers
 *
 * Why:
 * - JSON key order must be stable across machines/languages.
 * - We normalize objects by sorting keys recursively.
 */

const crypto = require("crypto");

function normalize(value) {
  if (value === null) return null;

  const t = typeof value;

  if (t === "number") {
    if (!Number.isFinite(value)) return null;
    return value;
  }

  if (t === "string" || t === "boolean") return value;

  if (Array.isArray(value)) {
    return value.map(v => normalize(v));
  }

  if (t === "object") {
    const out = {};
    const keys = Object.keys(value).sort();
    for (const k of keys) {
      const v = value[k];
      if (v === undefined) continue; // JSON would drop it; we drop explicitly
      out[k] = normalize(v);
    }
    return out;
  }

  // functions/symbols/etc -> null deterministically
  return null;
}

function canonicalJson(value) {
  return JSON.stringify(normalize(value));
}

function sha256HexUtf8(s) {
  return crypto.createHash("sha256").update(String(s), "utf8").digest("hex");
}

function canonicalHashHex(value) {
  return sha256HexUtf8(canonicalJson(value));
}

module.exports = {
  normalize,
  canonicalJson,
  sha256HexUtf8,
  canonicalHashHex,
};
