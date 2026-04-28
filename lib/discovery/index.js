"use strict";

const { scoreDiscoveryPoll, compareDiscoveryScores } = require("./score");
const { assignDiscoveryBracket } = require("./brackets");
const {
  applyDiscoveryPenalties,
  detectDuplicatePolls,
  detectTagHijacking,
  detectMisleadingStructure,
} = require("./penalties");
const {
  placePollInDiscoverySlots,
  expireDiscoveryPolls,
  grantDailySlotCredit,
} = require("./queue");

module.exports = {
  scoreDiscoveryPoll,
  assignDiscoveryBracket,
  applyDiscoveryPenalties,
  placePollInDiscoverySlots,
  expireDiscoveryPolls,
  grantDailySlotCredit,

  // Optional helpers
  compareDiscoveryScores,
  detectDuplicatePolls,
  detectTagHijacking,
  detectMisleadingStructure,
};

