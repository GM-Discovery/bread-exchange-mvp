"use strict";

const { applyDiscoveryPenalties } = require("./penalties");

function clamp(n, min, max) {
  const x = Number(n);
  if (!Number.isFinite(x)) return min;
  return Math.max(min, Math.min(max, x));
}

function scoreSignals(poll, context = {}) {
  const signalsIn = (poll?.discovery?.signals && typeof poll.discovery.signals === "object")
    ? poll.discovery.signals
    : {};
  const results = context.results || poll?.results || {};
  const votes_count = Number(signalsIn.votes_count ?? results.total_votes ?? context.votes_count ?? 0);
  const represented_weight = Number(signalsIn.represented_weight ?? results.represented_weight ?? context.represented_weight ?? 0);
  const unique_personas = Number(signalsIn.unique_personas ?? results.people_voted ?? context.unique_personas ?? 0);
  const source_exchange_count = Number(signalsIn.source_exchange_count ?? context.source_exchange_count ?? 1);
  const cross_exchange_boost = Number(signalsIn.cross_exchange_boost ?? context.cross_exchange_boost ?? 0);
  const civic_relevance_score = clamp(signalsIn.civic_relevance_score ?? context.civic_relevance_score ?? 0, 0, 10);
  const clarity_score = clamp(signalsIn.clarity_score ?? context.clarity_score ?? 0, 0, 10);
  const structural_integrity_score = clamp(
    signalsIn.structural_integrity_score ?? context.structural_integrity_score ?? 0,
    0,
    10
  );

  return {
    votes_count,
    represented_weight,
    unique_personas,
    source_exchange_count,
    cross_exchange_boost,
    civic_relevance_score,
    clarity_score,
    structural_integrity_score,
  };
}

function scoreDiscoveryPoll(poll, context = {}) {
  const discovery = poll.discovery || (poll.discovery = {});
  const signals = scoreSignals(poll, context);
  const discovery_standing = Number(discovery.discovery_standing ?? context.discovery_standing ?? 0);

  const vote_motion_score = Math.log2(1 + Math.max(0, signals.votes_count));
  const represented_weight_score = Math.log2(1 + Math.max(0, signals.represented_weight));

  const penaltyOut = applyDiscoveryPenalties(poll, context);

  const score =
    discovery_standing +
    vote_motion_score +
    represented_weight_score +
    Number(signals.cross_exchange_boost || 0) +
    Number(signals.civic_relevance_score || 0) +
    Number(signals.clarity_score || 0) +
    Number(signals.structural_integrity_score || 0) -
    Number(penaltyOut.structural_integrity_penalty || 0) -
    Number(penaltyOut.abuse_pattern_penalty || 0);

  discovery.signals = Object.assign({}, signals);
  discovery.score = Number(score.toFixed(4));
  discovery.discovery_standing = discovery_standing;
  discovery.last_scored_at = context.now || new Date().toISOString();

  return {
    score: discovery.score,
    discovery_standing,
    components: {
      discovery_standing,
      vote_motion_score,
      represented_weight_score,
      cross_exchange_boost: Number(signals.cross_exchange_boost || 0),
      civic_relevance_score: Number(signals.civic_relevance_score || 0),
      clarity_score: Number(signals.clarity_score || 0),
      structural_integrity_score: Number(signals.structural_integrity_score || 0),
      structural_integrity_penalty: Number(penaltyOut.structural_integrity_penalty || 0),
      abuse_pattern_penalty: Number(penaltyOut.abuse_pattern_penalty || 0),
    },
    explain: [
      "score=standing+activity+quality-penalties",
      ...(penaltyOut.explain || []),
    ],
  };
}

function compareDiscoveryScores(a, b) {
  const as = Number(a?.discovery?.score ?? a?.score ?? 0);
  const bs = Number(b?.discovery?.score ?? b?.score ?? 0);
  if (as !== bs) return bs - as;
  const at = String(a?.created_at || "");
  const bt = String(b?.created_at || "");
  if (at !== bt) return bt.localeCompare(at);
  return String(a?.id || "").localeCompare(String(b?.id || ""));
}

module.exports = {
  scoreSignals,
  scoreDiscoveryPoll,
  compareDiscoveryScores,
};

