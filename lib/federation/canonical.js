"use strict";

/**
 * canonical.js
 *
 * Purpose:
 * - Deterministic JSON serialization for federation signatures/hashes
 * - SHA256 hashing helpers
 *
 * Why:
 * - JSON objects are unordered (RFC 8259), so hashing/signing must use canonical
 *   serialization to avoid cross-runtime key-order drift.
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

/**
 * canonicalStringify(value)
 *
 * Locked canonical JSON routine for federation hashing/signing.
 * - Object keys sorted lexicographically at every level
 * - Arrays preserved in original order
 * - Undefined keys omitted
 * - ISO strings treated as raw strings (no parsing)
 * - Numbers serialized exactly as JSON
 * - Stable UTF-8 encoding
 */
function canonicalStringify(value) {
  return JSON.stringify(normalize(value));
}

// Back-compat alias
function canonicalJson(value) {
  return canonicalStringify(value);
}

function sha256HexUtf8(s) {
  return crypto.createHash("sha256").update(String(s), "utf8").digest("hex");
}

function canonicalHashHex(value) {
  return sha256HexUtf8(canonicalStringify(value));
}

// Alias to match Phase 0.1 naming
function canonicalHash(value) {
  return canonicalHashHex(value);
}

// ---- Guardrail self-test (fail-fast) ----
function _selfTestOnce() {
  if (_selfTestOnce.ran) return;
  _selfTestOnce.ran = true;

  const objA = {
    b: 1,
    a: 2,
    nested: { y: true, x: false },
    arr: [{ z: 3, a: 1 }, 2],
  };

  const objB = {
    a: 2,
    b: 1,
    arr: [{ a: 1, z: 3 }, 2],
    nested: { x: false, y: true },
  };

  const sA = canonicalStringify(objA);
  const sB = canonicalStringify(objB);
  if (sA !== sB) throw new Error("CANONICAL_SELF_TEST_FAILED:stringify_mismatch");

  const hA = canonicalHashHex(objA);
  const hB = canonicalHashHex(objB);
  if (hA !== hB) throw new Error("CANONICAL_SELF_TEST_FAILED:hash_mismatch");
}
_selfTestOnce();

module.exports = {
  normalize,
  canonicalStringify,
  canonicalJson,
  sha256HexUtf8,
  canonicalHash,
  canonicalHashHex,
};
