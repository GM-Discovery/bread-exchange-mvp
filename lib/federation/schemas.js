"use strict";

/**
 * schemas.js
 *
 * Purpose:
 * - Define schema versions and default empty store shapes.
 * - Define required fields for Commitment v1.
 */

const SCHEMA_VERSION = 2;

// Commitment v1 required fields (signed body)
const COMMITMENT_REQUIRED_FIELDS_V1 = [
  "poll_id",
  "final_tally_hash",
  "override_delta_hash",
  "represented_map_hash",
  "finalized_at",
  "published_at",
  "ts",
  "exchange_id",
  "canonical_base_url",
];

// Commitment v2 required fields (signed body)
// Adds protocol + contract identity to prevent silent drift.
const COMMITMENT_REQUIRED_FIELDS_V2 = [
  ...COMMITMENT_REQUIRED_FIELDS_V1,
  "protocol_version",
  "min_supported_version",
  "contract_id",
  "contract_hash",
];

function emptyPartnersStore() {
  return {
    schema_version: SCHEMA_VERSION,
    partners: {
      // partner_id: { exchange_id, canonical_base_url, public_keys_b64:[], status, added_at, notes }
    },
  };
}

function emptyReceivedStore() {
  return {
    schema_version: SCHEMA_VERSION,
    received: {
      // issuer_exchange_id: { poll_id: { commitment_hash, payload, signature_valid, received_at, seen_hashes:[] } }
    },
  };
}

function emptyDisputesStore() {
  return {
    schema_version: SCHEMA_VERSION,
    disputes: {
      // dispute_id: { poll_id, issuer_exchange_id, local_commitment_hash, received_commitment_hash, diff_fields, created_at, status, notes }
    },
  };
}

function emptyLocalCommitmentsStore(exchangeId, canonicalBaseUrl) {
  return {
    schema_version: SCHEMA_VERSION,
    exchange_id: exchangeId || null,
    canonical_base_url: canonicalBaseUrl || null,
    local: {
      // poll_id: { commitment_hash, ...payload, signature }
    },
  };
}

module.exports = {
  SCHEMA_VERSION,
  COMMITMENT_REQUIRED_FIELDS_V1,
  COMMITMENT_REQUIRED_FIELDS_V2,
  emptyPartnersStore,
  emptyReceivedStore,
  emptyDisputesStore,
  emptyLocalCommitmentsStore,
};
