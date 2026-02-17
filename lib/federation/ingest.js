"use strict";

/**
 * ingest.js
 *
 * Purpose:
 * - Validate incoming commitment payload
 * - Enforce partner allowlist
 * - Verify signature (Ed25519)
 * - Store received commitment
 * - Create Dispute v0 when received conflicts with local for same poll_id
 *
 * Key correction:
 * - Local store entries may not have local.commitment_hash.
 * - We recompute local hash deterministically from required fields.
 */

const { COMMITMENT_REQUIRED_FIELDS } = require("./schemas");
const { canonicalHashHex } = require("./canonical");
const { loadPublicKeyFromB64, verifyHashHex } = require("./ed25519");
const {
  readPartners,
  readReceived,
  writeReceived,
  readLocalCommitments,
} = require("./state");
const { createDispute } = require("./disputes");

function validateCommitmentShape(payload) {
  for (const f of COMMITMENT_REQUIRED_FIELDS) {
    if (!(f in payload)) return false;
    if (payload[f] === null || payload[f] === undefined) return false;
  }
  return true;
}

function validateNonBlankRequired(obj) {
  for (const f of COMMITMENT_REQUIRED_FIELDS) {
    const v = obj[f];
    if (v === null || v === undefined) return false;
    if (typeof v === "string" && v.trim() === "") return false;
  }
  return true;
}

function buildUnsignedFromLocal(pollId, localEntry) {
  // Local entry shape may include extra keys.
  // We rehydrate only the canonical required v1 fields.
  return {
    poll_id: pollId,
    final_tally_hash: localEntry.final_tally_hash,
    override_delta_hash: localEntry.override_delta_hash,
    represented_map_hash: localEntry.represented_map_hash,
    finalized_at: localEntry.finalized_at,
    published_at: localEntry.published_at,
    ts: localEntry.ts || localEntry.published_at || localEntry.finalized_at,
    exchange_id: localEntry.exchange_id || process.env.EXCHANGE_ID || null,
    canonical_base_url: localEntry.canonical_base_url || process.env.CANONICAL_BASE_URL || null,
  };
}

function diffFields(localUnsigned, receivedUnsigned) {
  const diffs = [];
  for (const k of COMMITMENT_REQUIRED_FIELDS) {
    if (localUnsigned[k] !== receivedUnsigned[k]) diffs.push(k);
  }
  return diffs;
}

/**
 * Returns:
 * { ok: true, idempotent?: true }
 * or
 * { ok: false, error: "..." }
 */
function ingestCommitment(payload) {
  if (!validateCommitmentShape(payload)) {
    return { ok: false, error: "invalid_commitment_shape" };
  }

  // Federation posture: only accept published commitments.
  if (!payload.published_at) {
    return { ok: false, error: "commitment_not_published" };
  }

  // Allowlist enforcement by exchange_id
  const partners = readPartners();
  let partnerRecord = null;

  for (const pid of Object.keys(partners.partners || {})) {
    const p = partners.partners[pid];
    if (p.exchange_id === payload.exchange_id && p.status === "ACTIVE") {
      partnerRecord = p;
      break;
    }
  }

  if (!partnerRecord) {
    return { ok: false, error: "issuer_not_allowlisted" };
  }

  // Canonical hash of payload WITHOUT signature
  const { signature, ...unsignedPayload } = payload;
  const commitmentHash = canonicalHashHex(unsignedPayload);

  // Verify signature against any of partner's keys (rotation-safe)
  let signatureValid = false;
  const keys = partnerRecord.public_keys_b64 || [];

  for (const pubB64 of keys) {
    const pubKey = loadPublicKeyFromB64(String(pubB64));
    if (!pubKey) continue;

    if (verifyHashHex(commitmentHash, signature, pubKey)) {
      signatureValid = true;
      break;
    }
  }

  if (!signatureValid) {
    return { ok: false, error: "invalid_signature" };
  }

  // Store received (idempotent by issuer+poll+commitment_hash)
  const receivedStore = readReceived();
  if (!receivedStore.received[payload.exchange_id]) {
    receivedStore.received[payload.exchange_id] = {};
  }
  const issuerBucket = receivedStore.received[payload.exchange_id];

  if (
    issuerBucket[payload.poll_id] &&
    issuerBucket[payload.poll_id].commitment_hash === commitmentHash
  ) {
    return { ok: true, idempotent: true };
  }

  issuerBucket[payload.poll_id] = {
    commitment_hash: commitmentHash,
    payload: unsignedPayload,
    signature_valid: true,
    received_at: new Date().toISOString(),
  };

  writeReceived(receivedStore);

  // ---- Dispute creation (corrected) ----
  const localStore = readLocalCommitments(process.env.EXCHANGE_ID, process.env.CANONICAL_BASE_URL);
  const localEntry = localStore && localStore.local ? localStore.local[payload.poll_id] : null;

  if (localEntry) {
    // Prefer stored local.commitment_hash if present; else recompute deterministically.
    let localHash = null;

    if (typeof localEntry.commitment_hash === "string" && localEntry.commitment_hash.trim() !== "") {
      localHash = localEntry.commitment_hash.trim();
    } else {
      const localUnsigned = buildUnsignedFromLocal(payload.poll_id, localEntry);

      // If local is missing required fields (legacy), we don't auto-dispute.
      if (validateNonBlankRequired(localUnsigned)) {
        localHash = canonicalHashHex(localUnsigned);
      }
    }

    if (localHash && localHash !== commitmentHash) {
      const localUnsignedForDiff = buildUnsignedFromLocal(payload.poll_id, localEntry);
      const diffs = diffFields(localUnsignedForDiff, unsignedPayload);

      createDispute({
        pollId: payload.poll_id,
        issuerExchangeId: payload.exchange_id,
        localCommitmentHash: localHash,
        receivedCommitmentHash: commitmentHash,
        diffFields: diffs,
      });
    }
  }

  return { ok: true };
}

module.exports = {
  ingestCommitment,
};
