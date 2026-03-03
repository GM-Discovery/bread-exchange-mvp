"use strict";

/**
 * compat.js
 *
 * Purpose:
 * - Single source of truth for federation protocol identity + compatibility checks
 * - Deterministic contract hashing (normalized text)
 * - Version parsing/comparison (boring + deterministic)
 */

const fs = require("fs");
const path = require("path");
const { sha256HexUtf8 } = require("./canonical");

function nowIso() {
  return new Date().toISOString();
}

function readTextFileNormalized(absPath) {
  // Normalize line endings + avoid volatile hash drift.
  // Rules:
  // - convert CRLF/CR -> LF
  // - (optional) do NOT strip all whitespace; only normalize line endings
  // - ensure exactly one trailing newline
  let s = fs.readFileSync(absPath, "utf8");
  s = s.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  if (!s.endsWith("\n")) s += "\n";
  return s;
}

function safeReadPackageVersion() {
  try {
    // lib/federation/compat.js -> lib/federation -> lib -> repo root
    const pj = path.resolve(__dirname, "..", "..", "package.json");
    const raw = fs.readFileSync(pj, "utf8");
    const j = JSON.parse(raw);
    const v = String(j.version || "").trim();
    if (!v) return null;
    // normalize to vX.Y.Z
    return v.startsWith("v") ? v : ("v" + v);
  } catch {
    return null;
  }
}

// ---- Version parsing: vMAJOR.MINOR[.PATCH] ----
function parseVersion(v) {
  const s = String(v || "").trim();
  // allow optional "fed_" prefix, allow leading "v"
  const cleaned = s.replace(/^fed[_-]?/i, "");
  const m = cleaned.match(/^v?(\d+)\.(\d+)(?:\.(\d+))?$/);
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3] || 0),
  };
}

function cmpVersion(a, b) {
  // returns -1,0,1
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;
  return 0;
}

function gte(vA, vB) {
  const a = parseVersion(vA);
  const b = parseVersion(vB);
  if (!a || !b) return null; // unparsable
  return cmpVersion(a, b) >= 0;
}

// ---- Local identity ----
const LOCAL_CONTRACT_ID = "exchange_contract_v0_1";

function computeLocalContractHash() {
  // Hardwired path hook: repo root/exchange_contract_v0_1.md
  const fp = path.resolve(__dirname, "..", "..", "exchange_contract_v0_1.md");
  const txt = readTextFileNormalized(fp);
  return sha256HexUtf8(txt);
}

function localIdentity() {
  const pkgV = safeReadPackageVersion() || "v0.0.0";

  const protocol = String(process.env.FED_PROTOCOL_VERSION || pkgV);
  const minSup = String(process.env.FED_MIN_SUPPORTED_VERSION || protocol);

  const contractHash = String(process.env.FED_CONTRACT_HASH || computeLocalContractHash());

  const accepted = String(process.env.FED_ACCEPTED_CONTRACT_HASHES || contractHash)
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);

  return {
    protocol_version: protocol,
    min_supported_version: minSup,
    contract_id: String(process.env.FED_CONTRACT_ID || LOCAL_CONTRACT_ID),
    contract_hash: contractHash,
    accepted_contract_hashes: accepted,
  };
}

// ---- Compatibility logic ----
function checkCompatibility(peerMeta) {
  const local = localIdentity();

  const peer = {
    protocol_version: String(peerMeta && peerMeta.protocol_version || ""),
    min_supported_version: String(peerMeta && peerMeta.min_supported_version || ""),
    contract_id: String(peerMeta && peerMeta.contract_id || ""),
    contract_hash: String(peerMeta && peerMeta.contract_hash || ""),
  };

  // Missing required fields => fail closed
  if (!peer.protocol_version || !peer.min_supported_version) {
    return { ok: false, reason: "missing_required_field", local, peer };
  }

  if (!parseVersion(peer.protocol_version) || !parseVersion(peer.min_supported_version)) {
    return { ok: false, reason: "bad_protocol_version", local, peer };
  }
  if (!parseVersion(local.protocol_version) || !parseVersion(local.min_supported_version)) {
    return { ok: false, reason: "bad_local_protocol_version", local, peer };
  }

  // Floors (mutual)
  const peerOk = gte(peer.protocol_version, local.min_supported_version);
  if (peerOk === null) return { ok: false, reason: "bad_protocol_version", local, peer };
  if (!peerOk) {
    return {
      ok: false,
      reason: "peer_too_old",
      required_min_version: local.min_supported_version,
      suggested_action: "upgrade_exchange",
      local,
      peer,
    };
  }

  const localOk = gte(local.protocol_version, peer.min_supported_version);
  if (localOk === null) return { ok: false, reason: "bad_protocol_version", local, peer };
  if (!localOk) {
    return {
      ok: false,
      reason: "local_too_old",
      required_min_version: peer.min_supported_version,
      suggested_action: "upgrade_exchange",
      local,
      peer,
    };
  }

  // Contract
  if (peer.contract_id !== local.contract_id) {
    return { ok: false, reason: "contract_id_mismatch", local, peer };
  }
  if (!local.accepted_contract_hashes.includes(peer.contract_hash)) {
    return { ok: false, reason: "contract_mismatch", local, peer };
  }

  return { ok: true, local, peer };
}

function refusalPayload(out) {
  // timestamped, small, actionable
  return {
    ok: false,
    error: "incompatible_peer",
    ts: nowIso(),
    reason: String(out.reason || "incompatible_peer"),
    required_min_version: out.required_min_version || undefined,
    suggested_action: out.suggested_action || undefined,
    local: {
      protocol_version: out.local.protocol_version,
      min_supported_version: out.local.min_supported_version,
      contract_id: out.local.contract_id,
      contract_hash: out.local.contract_hash,
    },
    peer: {
      protocol_version: out.peer.protocol_version,
      min_supported_version: out.peer.min_supported_version,
      contract_id: out.peer.contract_id,
      contract_hash: out.peer.contract_hash,
    },
  };
}

module.exports = {
  localIdentity,
  parseVersion,
  checkCompatibility,
  refusalPayload,
};