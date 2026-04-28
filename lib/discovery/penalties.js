"use strict";

const STRUCTURAL_KEYS = [
  "low_integrity_framing",
  "biased_question_design",
  "misleading_poll_structure",
];

const ABUSE_KEYS = [
  "delegation_capture_abuse",
  "framing_convergence_trap",
  "early_vote_manipulation",
  "tag_relevance_hijacking",
  "duplicate_swarm",
  "consensus_theater",
  "ambiguity_farming",
];

const ALL_PENALTY_KEYS = [...STRUCTURAL_KEYS, ...ABUSE_KEYS];

const DEFAULT_PENALTY_DELTAS = {
  low_integrity_framing: -1,
  biased_question_design: -2,
  misleading_poll_structure: -2,
  delegation_capture_abuse: -3,
  framing_convergence_trap: -3,
  early_vote_manipulation: -3,
  tag_relevance_hijacking: -3,
  duplicate_swarm: -5,
  consensus_theater: -10,
  ambiguity_farming: -2,
};

function normalizeText(s) {
  return String(s || "")
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim();
}

function countWords(s) {
  const t = normalizeText(s);
  if (!t) return 0;
  return t.split(" ").filter(Boolean).length;
}

function getOptions(poll) {
  if (!Array.isArray(poll?.options)) return [];
  return poll.options
    .map((o, idx) => {
      if (o && typeof o === "object") {
        return String(o.label ?? o.text ?? o.id ?? idx + 1);
      }
      return String(o);
    })
    .filter(Boolean);
}

function ensurePenaltyShape(discovery) {
  if (!discovery.penalties || typeof discovery.penalties !== "object") discovery.penalties = {};
  for (const k of ALL_PENALTY_KEYS) {
    if (!Number.isFinite(Number(discovery.penalties[k]))) discovery.penalties[k] = 0;
  }
}

function detectDuplicatePolls(poll, existingPolls) {
  const title = normalizeText(poll?.title);
  if (!title || !Array.isArray(existingPolls) || existingPolls.length === 0) return false;
  const tags = new Set((poll?.meta?.tags || []).map((t) => normalizeText(t)));
  let duplicateCount = 0;

  for (const p of existingPolls) {
    if (!p || p.id === poll.id) continue;
    const t = normalizeText(p.title);
    if (!t) continue;
    if (t !== title) continue;

    const pTags = new Set((p?.meta?.tags || []).map((x) => normalizeText(x)));
    let overlap = 0;
    for (const tag of tags) if (pTags.has(tag)) overlap += 1;
    if (overlap > 0 || tags.size === 0) duplicateCount += 1;
    if (duplicateCount >= 2) return true;
  }
  return false;
}

function detectTagHijacking(poll) {
  const tags = Array.isArray(poll?.meta?.tags) ? poll.meta.tags.map((x) => String(x).toLowerCase()) : [];
  if (tags.length === 0) return false;
  if (tags.length > 12) return true;
  const unique = new Set(tags);
  if (unique.size < tags.length * 0.6) return true;
  return tags.some((t) => t.length > 40);
}

function detectMisleadingStructure(poll) {
  const type = String(poll?.type || poll?.poll_type || "").toUpperCase();
  const options = getOptions(poll);
  const title = normalizeText(poll?.title);
  const longIssue = countWords(title) > 18;
  const yesNoOnly = options.length === 2 &&
    normalizeText(options[0]).startsWith("yes") &&
    normalizeText(options[1]).startsWith("no");
  if ((type === "YES_NO" || yesNoOnly) && longIssue) return true;
  if ((type === "RANKED" || type === "SINGLE_SELECT") && options.length < 2) return true;
  return false;
}

function applyDiscoveryPenalties(poll, context = {}) {
  const discovery = poll.discovery || (poll.discovery = {});
  ensurePenaltyShape(discovery);
  const explain = [];

  const title = normalizeText(poll?.title);
  const options = getOptions(poll);
  const deltas = Object.assign({}, DEFAULT_PENALTY_DELTAS, context.penalty_deltas || {});
  const structuralFlags = context.structural_flags || {};

  const lowIntegrityDetected =
    structuralFlags.low_integrity_framing === true ||
    /\b(obviously|everyone knows|only an idiot|traitor|real patriots)\b/.test(title);
  if (lowIntegrityDetected) {
    discovery.penalties.low_integrity_framing += 1;
    explain.push("low_integrity_framing");
  }

  const biasedDesignDetected =
    structuralFlags.biased_question_design === true ||
    (options.length >= 2 && options.filter((o) => countWords(o) >= 6).length === 1);
  if (biasedDesignDetected) {
    discovery.penalties.biased_question_design += 1;
    explain.push("biased_question_design");
  }

  const misleadingDetected =
    structuralFlags.misleading_poll_structure === true || detectMisleadingStructure(poll);
  if (misleadingDetected) {
    discovery.penalties.misleading_poll_structure += 1;
    explain.push("misleading_poll_structure");
  }

  const existing = Array.isArray(context.existing_polls) ? context.existing_polls : [];
  if (detectDuplicatePolls(poll, existing)) {
    discovery.penalties.duplicate_swarm += 1;
    explain.push("duplicate_swarm");
  }

  if (detectTagHijacking(poll)) {
    discovery.penalties.tag_relevance_hijacking += 1;
    explain.push("tag_relevance_hijacking");
  }

  const turnout = Number(context.turnout_ratio || 0);
  const consensus = Number(context.consensus_ratio || 0);
  const veryEarly = Number(context.minutes_since_created || 999999) < 15;
  if (veryEarly && turnout > 0.5) {
    discovery.penalties.early_vote_manipulation += 1;
    explain.push("early_vote_manipulation");
  }
  if (veryEarly && consensus > 0.96 && turnout > 0.35) {
    discovery.penalties.consensus_theater += 1;
    explain.push("consensus_theater");
  }

  const ambiguitySignal = options.some((o) => /\bother|unclear|both|none of the above\b/i.test(String(o)));
  if (ambiguitySignal && options.length <= 2) {
    discovery.penalties.ambiguity_farming += 1;
    explain.push("ambiguity_farming");
  }

  let structural_integrity_penalty = 0;
  let abuse_pattern_penalty = 0;
  for (const k of STRUCTURAL_KEYS) structural_integrity_penalty += Number(discovery.penalties[k] || 0) * Math.abs(Number(deltas[k] || 0));
  for (const k of ABUSE_KEYS) abuse_pattern_penalty += Number(discovery.penalties[k] || 0) * Math.abs(Number(deltas[k] || 0));

  return {
    penalties: discovery.penalties,
    structural_integrity_penalty,
    abuse_pattern_penalty,
    explain,
  };
}

module.exports = {
  STRUCTURAL_KEYS,
  ABUSE_KEYS,
  ALL_PENALTY_KEYS,
  DEFAULT_PENALTY_DELTAS,
  applyDiscoveryPenalties,
  detectDuplicatePolls,
  detectTagHijacking,
  detectMisleadingStructure,
};

