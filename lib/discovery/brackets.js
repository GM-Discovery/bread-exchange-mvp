"use strict";

const DEFAULT_BRACKETS = [
  { name: "featured", range: [0, 9], weight: 20 },
  { name: "local_always", range: [10, 19], weight: 14 },
  { name: "worldwide_civic", range: [20, 24], weight: 12 },
  { name: "region_of_nations", range: [25, 29], weight: 10 },
  { name: "topical", range: [30, 99], weight: 8 },
  { name: "broad_rotation", range: [100, 199], weight: 5 },
  { name: "local_deep", range: [200, 299], weight: 3 },
  { name: "long_queue", range: [300, 1000], weight: 1 },
];

function getBrackets(context = {}) {
  return Array.isArray(context.brackets) && context.brackets.length > 0
    ? context.brackets
    : DEFAULT_BRACKETS;
}

function bracketByName(name, context = {}) {
  const brackets = getBrackets(context);
  return brackets.find((b) => String(b.name) === String(name)) || null;
}

function pickDefaultBracketByPoll(poll, context = {}) {
  const tags = Array.isArray(poll?.meta?.tags) ? poll.meta.tags.map((x) => String(x).toLowerCase()) : [];
  const pollClass = String(poll?.poll_class || "").toUpperCase();
  const origin = String(poll?.source_exchange_id || context.local_exchange_id || "");
  const localId = String(context.local_exchange_id || "");
  const jurisdiction = String(poll?.meta?.jurisdiction || "").toLowerCase();

  if (tags.includes("featured")) return "featured";
  if (origin && localId && origin !== localId) return "region_of_nations";
  if (tags.includes("worldwide") || tags.includes("global")) return "worldwide_civic";
  if (jurisdiction === "regional" || tags.includes("regional")) return "region_of_nations";
  if (pollClass === "GOVERNANCE" || pollClass === "LEGITIMACY") return "local_always";
  if (tags.some((t) => t.startsWith("topic:"))) return "topical";
  return "local_deep";
}

function assignDiscoveryBracket(poll, context = {}) {
  const requested = String(poll?.discovery?.bracket || poll?.meta?.discovery_bracket || "");
  let chosen = requested || pickDefaultBracketByPoll(poll, context);
  if (!bracketByName(chosen, context)) chosen = "local_deep";
  const spec = bracketByName(chosen, context) || bracketByName("local_deep", context) || DEFAULT_BRACKETS[6];
  return {
    bracket: chosen,
    range: spec.range,
    weight: Number(spec.weight || 1),
    explain: [`matched_bracket:${chosen}`],
  };
}

module.exports = {
  DEFAULT_BRACKETS,
  getBrackets,
  bracketByName,
  assignDiscoveryBracket,
};

