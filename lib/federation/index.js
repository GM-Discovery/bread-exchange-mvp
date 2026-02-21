"use strict";

const { installFederationRouter } = require("./routes");

/**
 * Federation module public API.
 * Only export installFederationRoutes to prevent export drift.
 */
function installFederationRoutes(app, deps = {}) {
  try {
    installFederationRouter(app, deps);
  } catch (e) {
    console.error("FEDERATION_ROUTES_INSTALL_FAILED:", e && e.message ? e.message : e);
  }
}

// Expose local commitment writer used by server.js finalize/backfill hooks.
// Implementation lives in federation.legacy.js for now (Phase 0.1 minimal refactor).
const legacy = require("../federation.legacy");

module.exports = {
  installFederationRoutes,
  upsertLocalCommitmentForPoll: legacy.upsertLocalCommitmentForPoll,
};
