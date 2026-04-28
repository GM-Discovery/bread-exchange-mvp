"use strict";

const assert = require("assert/strict");
const discovery = require("../lib/discovery");

function poll(id, title, options, extra = {}) {
  return {
    id: String(id),
    title: String(title),
    options: options.slice(),
    poll_class: "OPINION",
    status: "open",
    created_at: new Date("2026-04-28T00:00:00.000Z").toISOString(),
    meta: { tags: ["topic:test"] },
    ...extra,
  };
}

function run() {
  const p1 = poll("p1", "Build a new local transit lane", ["Yes", "No"], {
    results: { total_votes: 20, represented_weight: 36, people_voted: 18 },
  });
  const p2 = poll("p2", "Build a new local transit lane", ["Absolutely yes", "No"], {
    results: { total_votes: 4, represented_weight: 4, people_voted: 4 },
  });

  const queue = { bySlot: {}, byPollId: {}, meta: {} };
  const pollIndex = { p1, p2 };
  const resultsByPollId = { p1: p1.results, p2: p2.results };

  const s1 = discovery.scoreDiscoveryPoll(p1, {
    now: "2026-04-28T01:00:00.000Z",
    existing_polls: [p1, p2],
    civic_relevance_score: 5,
    clarity_score: 4,
    structural_integrity_score: 6,
  });
  assert.ok(Number.isFinite(s1.score), "p1 score should be numeric");

  const s2 = discovery.scoreDiscoveryPoll(p2, {
    now: "2026-04-28T01:00:00.000Z",
    existing_polls: [p1, p2],
    civic_relevance_score: 3,
    clarity_score: 2,
    structural_integrity_score: 3,
  });
  assert.ok(Number.isFinite(s2.score), "p2 score should be numeric");

  const placed1 = discovery.placePollInDiscoverySlots(p1, queue, {
    now: "2026-04-28T01:00:00.000Z",
    existing_polls: [p1, p2],
    pollIndex,
    resultsByPollId,
    local_exchange_id: "ex_local",
  });
  const placed2 = discovery.placePollInDiscoverySlots(p2, queue, {
    now: "2026-04-28T01:00:00.000Z",
    existing_polls: [p1, p2],
    pollIndex,
    resultsByPollId,
    local_exchange_id: "ex_local",
  });

  assert.ok(Number.isFinite(placed1.slot), "p1 should get a slot");
  assert.ok(Number.isFinite(placed2.slot), "p2 should get a slot");
  assert.notEqual(queue.byPollId.p1, undefined, "queue should track p1");
  assert.notEqual(queue.byPollId.p2, undefined, "queue should track p2");

  const credit = discovery.grantDailySlotCredit(queue, "2026-04-28T12:00:00.000Z", {
    pollIndex,
    resultsByPollId,
  });
  assert.ok(credit.credited >= 1, "at least one poll should receive daily slot credit");

  p2.status = "archived";
  const exp = discovery.expireDiscoveryPolls(queue, "2026-04-28T13:00:00.000Z", { pollIndex });
  assert.ok(Array.isArray(exp.removed), "expire result shape");

  console.log("Discovery kernel tests passed.");
}

run();

