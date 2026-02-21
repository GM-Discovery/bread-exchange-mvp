"use strict";

/**
 * compare.js
 *
 * Dispute equivalence rules for federation commitments.
 *
 * Goal:
 * - disputes only on meaning-bearing fields (hashes / poll identity),
 *   not on metadata drift (timestamps, base URLs, fingerprints).
 */

function hasOwn(obj, k) {
  return !!(obj && typeof obj === "object" && Object.prototype.hasOwnProperty.call(obj, k));
}

function diffFields(a, b, fields) {
  const diffs = [];
  for (const k of fields) {
    const av = hasOwn(a, k) ? a[k] : undefined;
    const bv = hasOwn(b, k) ? b[k] : undefined;
    if (av !== bv) diffs.push(k);
  }
  return diffs;
}

// Meaning-bearing fields (default). Some are optional and may be absent.
// Note: timestamps only become "meaning-bearing" if explicitly configured as authoritative.
const BASE_MEANING_FIELDS = [
  "poll_id",
  "exchange_id",
  "poll_fingerprint",
  "stamp_set_hash",
  "represented_map_hash",
  "override_delta_hash",
  "final_tally_hash",
];

// Informational fields (default). These must NOT trigger disputes.
const BASE_INFO_FIELDS = [
  "ts",
  "canonical_base_url",
  "exchange_fingerprint",
  "published_at",
  "finalized_at",
];

function unique(xs) {
  return Array.from(new Set(xs));
}

function buildMeaningfulFields(opts = {}) {
  let fields = BASE_MEANING_FIELDS.slice();

  // Many deployments compare local vs received across exchanges.
  // In that mode, exchange_id differences are expected and MUST NOT trigger disputes.
  if (opts.ignore_exchange_id) {
    fields = fields.filter(f => f !== "exchange_id");
  }

  if (opts.authoritative_finalized_at && !fields.includes("finalized_at")) {
    fields.push("finalized_at");
  }
  if (opts.authoritative_published_at && !fields.includes("published_at")) {
    fields.push("published_at");
  }

  return unique(fields);
}

function buildInformationalFields(opts = {}) {
  let fields = BASE_INFO_FIELDS.slice();

  if (opts.authoritative_finalized_at) fields = fields.filter(f => f !== "finalized_at");
  if (opts.authoritative_published_at) fields = fields.filter(f => f !== "published_at");

  // If exchange_id is ignored for disputes, it is still useful as an informational diff.
  if (opts.ignore_exchange_id) fields.push("exchange_id");

  return unique(fields);
}

/**
 * Compare two unsigned commitment bodies.
 *
 * Returns:
 * {
 *   meaningful_diff_fields: string[],
 *   informational_diff_fields: string[]
 * }
 */
function compareCommitments(localUnsigned, receivedUnsigned, opts = {}) {
  const meaningfulFields = buildMeaningfulFields(opts);
  const informationalFields = buildInformationalFields(opts);

  return {
    meaningful_diff_fields: diffFields(localUnsigned, receivedUnsigned, meaningfulFields),
    informational_diff_fields: diffFields(localUnsigned, receivedUnsigned, informationalFields),
  };
}

module.exports = {
  compareCommitments,
  BASE_MEANING_FIELDS,
  BASE_INFO_FIELDS,
};
