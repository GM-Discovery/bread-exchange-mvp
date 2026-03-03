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

const { COMMITMENT_REQUIRED_FIELDS_V1, COMMITMENT_REQUIRED_FIELDS_V2 } = require("./schemas");
const { checkCompatibility, refusalPayload, localIdentity } = require("./compat");
const { canonicalHashHex } = require("./canonical");
const { loadPublicKeyFromB64 } = require("./ed25519");
const { verifyCommitmentHashHex } = require("./verify");
const { compareCommitments } = require("./compare");
const {
  readPartners,
  writePartners,
  readReceived,
  writeReceived,
  readLocalCommitments,
} = require("./state");
const { createDispute } = require("./disputes");

function pickRequiredFields(payload) {
  const hasV2 =
    payload &&
    typeof payload === "object" &&
    ("protocol_version" in payload || "contract_hash" in payload);

  return hasV2 ? COMMITMENT_REQUIRED_FIELDS_V2 : COMMITMENT_REQUIRED_FIELDS_V1;
}

function validateCommitmentShape(payload, requiredFields) {
  for (const f of requiredFields) {
    if (!(f in payload)) return false;
    if (payload[f] === null || payload[f] === undefined) return false;
  }
  return true;
}

function validateNonBlankRequired(obj, requiredFields) {
  for (const f of requiredFields) {
    const v = obj[f];
    if (v === null || v === undefined) return false;
    if (typeof v === "string" && v.trim() === "") return false;
  }
  return true;
}

function buildUnsignedFromLocalV2(pollId, localEntry) {
  const base = buildUnsignedFromLocal(pollId, localEntry);
  const ident = localIdentity();
  return {
    ...base,
    protocol_version: ident.protocol_version,
    min_supported_version: ident.min_supported_version,
    contract_id: ident.contract_id,
    contract_hash: ident.contract_hash,
  };
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
    poll_fingerprint: localEntry.poll_fingerprint,
    stamp_set_hash: localEntry.stamp_set_hash,
    canonical_base_url: localEntry.canonical_base_url || process.env.CANONICAL_BASE_URL || null,
  };
}

function diffFields(localUnsigned, receivedUnsigned, requiredFields) {
  const diffs = [];
  for (const k of requiredFields) {
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
  const requiredFields = pickRequiredFields(payload);

  if (!validateCommitmentShape(payload, requiredFields)) {
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

  // Compatibility gate (fail fast, fail closed) for v2 payloads
  if (requiredFields === COMMITMENT_REQUIRED_FIELDS_V2) {
    const comp = checkCompatibility(payload);
    if (!comp.ok) return refusalPayload(comp);
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

    if (verifyCommitmentHashHex(commitmentHash, signature, pubKey)) {
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

  // Record peer metadata + last seen (best-effort, operator visibility)
  try {
    const partnersStore = readPartners();
    for (const pid of Object.keys(partnersStore.partners || {})) {
      const p = partnersStore.partners[pid];
      if (p && p.exchange_id === payload.exchange_id) {
        partnersStore.partners[pid] = {
          ...p,
          protocol_version: payload.protocol_version || p.protocol_version || null,
          min_supported_version: payload.min_supported_version || p.min_supported_version || null,
          contract_id: payload.contract_id || p.contract_id || null,
          contract_hash: payload.contract_hash || p.contract_hash || null,
          last_seen_at: new Date().toISOString(),
          compatibility_status: (requiredFields === COMMITMENT_REQUIRED_FIELDS_V2) ? "OK" : (p.compatibility_status || "UNKNOWN"),
          incompatibility_reason: "",
        };
        writePartners(partnersStore);
        break;
      }
    }
  } catch {}

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
      if (validateNonBlankRequired(localUnsigned, COMMITMENT_REQUIRED_FIELDS_V1)) {
        localHash = canonicalHashHex(localUnsigned);
      }
    }
    if (localHash && localHash !== commitmentHash) {
      const localUnsignedForDiff =
        (requiredFields === COMMITMENT_REQUIRED_FIELDS_V2)
          ? buildUnsignedFromLocalV2(payload.poll_id, localEntry)
          : buildUnsignedFromLocal(payload.poll_id, localEntry);

      const diffs = diffFields(localUnsignedForDiff, unsignedPayload, requiredFields);
      const cmp = compareCommitments(localUnsignedForDiff, unsignedPayload, {
        ignore_exchange_id: true,
        authoritative_finalized_at: false,
        authoritative_published_at: false,
      });

      // Only open a dispute if meaning-bearing fields differ.
      if (cmp.meaningful_diff_fields.length > 0) {
        createDispute({
          pollId: payload.poll_id,
          issuerExchangeId: payload.exchange_id,
          localCommitmentHash: localHash,
          receivedCommitmentHash: commitmentHash,
          diffFields: cmp.meaningful_diff_fields,
        });
      }
    }
  
  return { ok: true };
}
}
module.exports = {
  ingestCommitment,
};
