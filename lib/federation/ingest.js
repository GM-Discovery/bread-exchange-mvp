"use strict";

/**
 * ingest.js
 *
 * Purpose:
 * - Validate incoming commitment payload
 * - Enforce allowlist
 * - Verify signature
 * - Enforce published-only policy
 * - Detect disputes
 * - Store received commitment
 */

const {
  COMMITMENT_REQUIRED_FIELDS,
} = require("./schemas");

const {
  canonicalHashHex,
} = require("./canonical");

const {
  loadPublicKeyFromB64,
  verifyHashHex,
} = require("./ed25519");

const {
  readPartners,
  readReceived,
  writeReceived,
  readLocalCommitments,
} = require("./state");

const { createDispute } = require("./disputes");

/**
 * Validate required fields exist and are non-null.
 */
function validateCommitmentShape(payload) {
  for (const f of COMMITMENT_REQUIRED_FIELDS) {
    if (!(f in payload)) return false;
    if (payload[f] === null || payload[f] === undefined) return false;
  }
  return true;
}

function diffFields(localPayload, receivedPayload) {
  const diffs = [];
  for (const k of COMMITMENT_REQUIRED_FIELDS) {
    if (localPayload[k] !== receivedPayload[k]) {
      diffs.push(k);
    }
  }
  return diffs;
}

/**
 * Main ingest function.
 *
 * Returns:
 * { ok: true }
 * or
 * { ok: false, error: "..." }
 */
function ingestCommitment(payload) {
  if (!validateCommitmentShape(payload)) {
    return { ok: false, error: "invalid_commitment_shape" };
  }

  if (!payload.published_at) {
    return { ok: false, error: "commitment_not_published" };
  }

  const partners = readPartners();

  // Find partner by exchange_id
  let partnerRecord = null;
  for (const pid of Object.keys(partners.partners)) {
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

  let signatureValid = false;

  // Try all partner public keys (rotation-safe)
  for (const pubB64 of partnerRecord.public_keys_b64 || []) {
    const pubKey = loadPublicKeyFromB64(pubB64);
    if (!pubKey) continue;

    if (verifyHashHex(commitmentHash, signature, pubKey)) {
      signatureValid = true;
      break;
    }
  }

  if (!signatureValid) {
    return { ok: false, error: "invalid_signature" };
  }

  const receivedStore = readReceived();

  if (!receivedStore.received[payload.exchange_id]) {
    receivedStore.received[payload.exchange_id] = {};
  }

  const issuerBucket = receivedStore.received[payload.exchange_id];

  // Idempotency check
  if (
    issuerBucket[payload.poll_id] &&
    issuerBucket[payload.poll_id].commitment_hash === commitmentHash
  ) {
    return { ok: true, idempotent: true };
  }

  // Store received
  issuerBucket[payload.poll_id] = {
    commitment_hash: commitmentHash,
    payload: unsignedPayload,
    signature_valid: true,
    received_at: new Date().toISOString(),
  };

  writeReceived(receivedStore);

  // Compare against local commitment (if exists)
  const localStore = readLocalCommitments();
  const local = localStore.local[payload.poll_id];

  if (local && local.commitment_hash && local.commitment_hash !== commitmentHash) {
    const diffs = diffFields(local, unsignedPayload);

    createDispute({
      pollId: payload.poll_id,
      issuerExchangeId: payload.exchange_id,
      localCommitmentHash: local.commitment_hash,
      receivedCommitmentHash: commitmentHash,
      diffFields: diffs,
    });
  }

  return { ok: true };
}

module.exports = {
  ingestCommitment,
};
