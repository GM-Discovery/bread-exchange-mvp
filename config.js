"use strict";

/**
 * Central config for Exchange.
 *
 * RULES:
 * - Defaults in here MUST match current behavior.
 * - No renames of existing stored JSON fields.
 * - This file should only hold parameters, not logic.
 */
module.exports = {
  stamps: {
    // Current behavior in server.js:
    // STAMP_POOL_TARGET = 1
    // STAMP_POOL_MAX = 1
    // STAMP_ROTATE_EVERY_USES = 1 (skeleton only)
    pool_target: 1,
    pool_max: 1,
    rotate_every_uses: 1,
  },

  lifecycle: {
    // Current behavior in lifecycle.js DEFAULTS:
    // OPINION_RETENTION_SECONDS = 7 days
    // GOVERNANCE_RETENTION_SECONDS = 30 days
    // GOVERNANCE_COOLDOWN_SECONDS = 1 hour
    opinion_retention_seconds: 7 * 24 * 60 * 60,
    governance_retention_seconds: 30 * 24 * 60 * 60,
    governance_cooldown_seconds: 60 * 60,
  },

  security: {
    ballot_uid_salt: {
      // Current behavior in server.js:
      // accept existing salt if length >= 16
      // generate new salt using randomBytes(32)
      min_length: 16,
      bytes: 32,
    },
  },
};
