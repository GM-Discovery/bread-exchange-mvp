"use strict";

const lifecycle = require("../lifecycle");
const { assignDiscoveryBracket, bracketByName } = require("./brackets");
const { scoreDiscoveryPoll, compareDiscoveryScores } = require("./score");

function dayKey(s) {
  const d = new Date(String(s || Date.now()));
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, 10);
}

function hasInteraction(poll, context = {}) {
  const results = context.resultsByPollId?.[poll.id] || poll.results || {};
  const votes = Number(results.total_votes ?? poll?.discovery?.signals?.votes_count ?? 0);
  const crossPull = Number(poll?.discovery?.signals?.cross_exchange_boost ?? 0);
  const shares = Number(poll?.meta?.share_count ?? 0);
  return votes > 0 || crossPull > 0 || shares > 0;
}

function getQueueState(queue = {}) {
  if (!queue.bySlot || typeof queue.bySlot !== "object") queue.bySlot = {};
  if (!queue.byPollId || typeof queue.byPollId !== "object") queue.byPollId = {};
  if (!queue.meta || typeof queue.meta !== "object") queue.meta = {};
  return queue;
}

function placeInBracket(poll, queue, bracketSpec, context = {}) {
  const state = getQueueState(queue);
  const [start, end] = bracketSpec.range;
  let current = poll;
  let placedSlot = null;
  let displacementCount = 0;

  for (let slot = start; slot <= end; slot += 1) {
    const occupantId = state.bySlot[slot];
    if (!occupantId) {
      state.bySlot[slot] = current.id;
      state.byPollId[current.id] = slot;
      placedSlot = slot;
      break;
    }
    const occupant = context.pollIndex?.[occupantId];
    if (!occupant) {
      state.bySlot[slot] = current.id;
      state.byPollId[current.id] = slot;
      placedSlot = slot;
      break;
    }
    const cmp = compareDiscoveryScores(current, occupant);
    if (cmp < 0) continue;

    state.bySlot[slot] = current.id;
    state.byPollId[current.id] = slot;
    current = occupant;
    displacementCount += 1;
  }

  if (placedSlot === null) {
    placedSlot = end;
    state.bySlot[end] = current.id;
    state.byPollId[current.id] = end;
  }

  if (!poll.discovery) poll.discovery = {};
  poll.discovery.slot = placedSlot;
  return { slot: placedSlot, displacement_count: displacementCount };
}

function placePollInDiscoverySlots(poll, queue, context = {}) {
  const state = getQueueState(queue);
  const bracketOut = assignDiscoveryBracket(poll, context);
  const scoreOut = scoreDiscoveryPoll(poll, context);
  if (!poll.discovery) poll.discovery = {};
  poll.discovery.bracket = bracketOut.bracket;

  // Gatekeeper 1 (friction): weak polls can be delayed a few slots, never erased.
  const lookahead = Math.max(1, Math.min(10, Number(context.gatekeeper1_lookahead ?? 5)));
  const weakThreshold = Number(context.gatekeeper1_weak_score ?? 1.0);
  let frictionPush = 0;
  if (scoreOut.score < weakThreshold) {
    frictionPush = Math.min(3, Math.ceil((weakThreshold - scoreOut.score) / 2));
  }

  const bracketSpec = bracketByName(bracketOut.bracket, context) || { range: [200, 299], weight: 3 };
  const shiftedBracket = {
    range: [
      Math.min(bracketSpec.range[1], bracketSpec.range[0] + frictionPush * lookahead),
      bracketSpec.range[1],
    ],
  };
  const placement = placeInBracket(poll, state, shiftedBracket, context);

  return {
    slot: placement.slot,
    bracket: bracketOut.bracket,
    score: scoreOut.score,
    explain: [
      ...bracketOut.explain,
      frictionPush > 0 ? `gatekeeper1_delay:+${frictionPush}` : "gatekeeper1:no_delay",
      "gatekeeper3:placed_by_score",
    ],
  };
}

function expireDiscoveryPolls(queue, now, context = {}) {
  const state = getQueueState(queue);
  const pollIndex = context.pollIndex || {};
  const removed = [];

  for (const pollId of Object.keys(state.byPollId)) {
    const poll = pollIndex[pollId];
    if (!poll) continue;
    lifecycle.applyLifecycle(poll, now);
    if (lifecycle.isVisibleInList(poll, now)) continue;
    const slot = Number(state.byPollId[pollId]);
    delete state.byPollId[pollId];
    delete state.bySlot[slot];
    removed.push({ poll_id: pollId, slot });
  }
  return { removed };
}

function grantDailySlotCredit(queue, day, context = {}) {
  const state = getQueueState(queue);
  const pollIndex = context.pollIndex || {};
  const today = dayKey(day);
  if (!today) return { credited: 0, details: [] };
  const credited = [];

  for (const pollId of Object.keys(state.byPollId)) {
    const poll = pollIndex[pollId];
    if (!poll) continue;
    if (!poll.discovery) poll.discovery = {};
    if (String(poll.discovery.last_slot_credit_day || "") === today) continue;
    if (!hasInteraction(poll, context)) continue;

    const slot = Number(poll.discovery.slot ?? state.byPollId[pollId] ?? 1000);
    const bracket = String(poll.discovery.bracket || "local_deep");
    const spec = bracketByName(bracket, context) || { weight: 1 };
    const credit = Number(spec.weight || 1) / Math.max(1, slot);

    poll.discovery.discovery_standing = Number(poll.discovery.discovery_standing || 0) + credit;
    poll.discovery.standing_delta = credit;
    poll.discovery.last_slot_credit_day = today;
    credited.push({ poll_id: pollId, slot, bracket, credit: Number(credit.toFixed(6)) });
  }

  return { credited: credited.length, details: credited };
}

module.exports = {
  placePollInDiscoverySlots,
  expireDiscoveryPolls,
  grantDailySlotCredit,
  getQueueState,
};

