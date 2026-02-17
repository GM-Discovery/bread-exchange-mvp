"use strict";

/**
 * state.js
 *
 * Purpose:
 * - Centralize read/write for federation JSON stores.
 * - Keep filenames stable and consistent.
 */

const { readJson, writeJsonAtomic } = require("./stores");
const {
  emptyPartnersStore,
  emptyReceivedStore,
  emptyDisputesStore,
  emptyLocalCommitmentsStore,
} = require("./schemas");

const FN_PARTNERS = "federation.partners.json";
const FN_RECEIVED = "federation.received_commitments.json";
const FN_DISPUTES = "federation.disputes.json";
const FN_LOCAL = "federation.local_commitments.json";

// ---- Partners ----
function readPartners() {
  return readJson(FN_PARTNERS, emptyPartnersStore());
}
function writePartners(store) {
  return writeJsonAtomic(FN_PARTNERS, store);
}

// ---- Received ----
function readReceived() {
  return readJson(FN_RECEIVED, emptyReceivedStore());
}
function writeReceived(store) {
  return writeJsonAtomic(FN_RECEIVED, store);
}

// ---- Disputes ----
function readDisputes() {
  return readJson(FN_DISPUTES, emptyDisputesStore());
}
function writeDisputes(store) {
  return writeJsonAtomic(FN_DISPUTES, store);
}

// ---- Local commitments ----
// NOTE: you said local commitments already exist and are populated.
// We will not overwrite; we load existing if present, otherwise initialize.
function readLocalCommitments(exchangeId, canonicalBaseUrl) {
  return readJson(FN_LOCAL, emptyLocalCommitmentsStore(exchangeId, canonicalBaseUrl));
}
function writeLocalCommitments(store) {
  return writeJsonAtomic(FN_LOCAL, store);
}

module.exports = {
  FN_PARTNERS,
  FN_RECEIVED,
  FN_DISPUTES,
  FN_LOCAL,

  readPartners,
  writePartners,

  readReceived,
  writeReceived,

  readDisputes,
  writeDisputes,

  readLocalCommitments,
  writeLocalCommitments,
};
