"use strict";

/**
 * disputes.js
 *
 * Purpose:
 * - Create dispute records when commitment hashes conflict.
 * - Keep logic small and deterministic.
 */

const crypto = require("crypto");
const { readDisputes, writeDisputes } = require("./state");

function newDisputeId() {
  return "d_" + crypto.randomBytes(12).toString("hex");
}

/**
 * Create a dispute record.
 * Does not deduplicate; caller should check first if desired.
 */
function createDispute({
  pollId,
  issuerExchangeId,
  localCommitmentHash,
  receivedCommitmentHash,
  diffFields,
}) {
  const store = readDisputes();

  const disputeId = newDisputeId();

  store.disputes[disputeId] = {
    dispute_id: disputeId,
    poll_id: pollId,
    issuer_exchange_id: issuerExchangeId,
    local_commitment_hash: localCommitmentHash,
    received_commitment_hash: receivedCommitmentHash,
    diff_fields: Array.isArray(diffFields) ? diffFields : [],
    created_at: new Date().toISOString(),
    status: "OPEN",
    notes: "",
  };

  writeDisputes(store);

  return store.disputes[disputeId];
}

module.exports = {
  createDispute,
};
