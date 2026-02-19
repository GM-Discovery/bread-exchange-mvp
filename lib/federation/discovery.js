"use strict";

const crypto = require("crypto");
const { rateLimit } = require("./rate_limit");
const lifecycle = require("../lifecycle");

function sha256Hex(s) {
  return crypto.createHash("sha256").update(String(s), "utf8").digest("hex");
}

// Minimal deterministic JSON for fingerprinting (informational)
function canonicalStringify(x) {
  if (x === null) return "null";
  const t = typeof x;

  if (t === "string") return JSON.stringify(x);
  if (t === "number") return Number.isFinite(x) ? String(x) : "null";
  if (t === "boolean") return x ? "true" : "false";

  if (Array.isArray(x)) return "[" + x.map(canonicalStringify).join(",") + "]";

  if (t === "object") {
    const keys = Object.keys(x).sort();
    const parts = [];
    for (const k of keys) parts.push(JSON.stringify(k) + ":" + canonicalStringify(x[k]));
    return "{" + parts.join(",") + "}";
  }

  return "null";
}

function parseBool(v) {
  return v === true || v === "true" || v === "1" || v === 1;
}

function parseIsoOrNull(s) {
  if (!s) return null;
  const d = new Date(String(s));
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString();
}

function getClientIp(req) {
  return String(req.ip || "");
}

function splitTags(s) {
  if (!s) return [];
  return String(s)
    .split(",")
    .map(x => x.trim())
    .filter(Boolean);
}

function hasAllTags(pollTags, wantTags) {
  if (!wantTags.length) return true;
  const set = new Set((pollTags || []).map(String));
  for (const t of wantTags) if (!set.has(t)) return false;
  return true;
}

function cmpCreatedDesc(a, b) {
  const aa = String(a.created_at || "");
  const bb = String(b.created_at || "");
  if (aa === bb) return String(b.id || "").localeCompare(String(a.id || ""));
  return bb.localeCompare(aa);
}

// Cursor: "<created_at>|<poll_id>"
function parseCursorStrict(s) {
  if (!s) return { cur: null }; // no cursor = start
  const raw = String(s);
  const idx = raw.indexOf("|");
  if (idx < 0) return { error: "bad_cursor" };

  const created_at = raw.slice(0, idx);
  const poll_id = raw.slice(idx + 1);

  // minimal sanity checks (avoid weird huge cursors)
  if (!created_at || created_at.length > 64) return { error: "bad_cursor" };
  if (!poll_id || poll_id.length > 128) return { error: "bad_cursor" };

  return { cur: { created_at, poll_id } };
}

// Strict cursor parsing: "<created_at>|<poll_id>" or 400
function parseCursorStrict(s) {
  if (!s) return { cur: null };
  const raw = String(s);
  const idx = raw.indexOf("|");
  if (idx < 0) return { error: "bad_cursor" };

  const created_at = raw.slice(0, idx);
  const poll_id = raw.slice(idx + 1);

  if (!created_at || created_at.length > 64) return { error: "bad_cursor" };
  if (!poll_id || poll_id.length > 128) return { error: "bad_cursor" };

  return { cur: { created_at, poll_id } };
}

function afterCursor(p, cur) {
  const c = String(p.created_at || "");
  if (c < String(cur.created_at)) return true;
  if (c > String(cur.created_at)) return false;
  return String(p.id || "") < String(cur.poll_id || "");
}

function makeNextCursor(lastRow) {
  if (!lastRow) return null;
  return String(lastRow.created_at || "") + "|" + String(lastRow.id || "");
}

function getPollTags(p) {
  const tags = p && p.meta && Array.isArray(p.meta.tags) ? p.meta.tags : [];
  return tags.map(String);
}

function pollFingerprint(p) {
  const fpObj = {
    poll_id: p.id || null,
    created_at: p.created_at || null,
    status: p.status || null,
    queue_no: p.queue_no || null,
    type: p.type || null,
    poll_class: p.poll_class || null,
    options: Array.isArray(p.options) ? p.options.map(o => ({ id: String(o.id), label: String(o.label) })) : [],
    tags: getPollTags(p),
  };
  return "sha256:" + sha256Hex(canonicalStringify(fpObj));
}

function summaryCountsForPoll(db, pollId) {
  // votes for poll
  const votes = db.votes.filter(v => v && v.poll_id === pollId);

  const ballotsStored = votes.length;

  // unique voters: persona_ballot_uid / voter_token
  const voterSet = new Set();
  const personaSet = new Set();

  for (const v of votes) {
    const token = v.persona_ballot_uid || v.voter_token || "";
    if (token) voterSet.add(String(token));
    if (v.persona_id) personaSet.add(String(v.persona_id));
  }

  // identified vs anonymous by persona meta identity assignment
  const personaById = new Map(db.personas.map(p => [String(p.id), p]));
  let identified = 0;
  let anonymous = 0;

  for (const pid of personaSet) {
    const persona = personaById.get(String(pid));
    const hasIdentity = !!(persona && persona.meta && persona.meta.identity_internal_id);
    if (hasIdentity) identified++;
    else anonymous++;
  }

  // If some votes lacked persona_id (shouldn�t in your current flow),
  // treat those as anonymous voters in addition to the persona-based counts.
  const missingPersonaVotes = votes.filter(v => !v.persona_id).length;
  if (missingPersonaVotes > 0) anonymous += 1; // collapse to �at least one anonymous bucket�

  return {
    ballots_stored: ballotsStored,
    people_voted_total: voterSet.size,          // token-based
    people_voted_identified: identified,        // persona-based
    people_voted_anonymous: anonymous,          // persona-based (+ fallback)
  };
}

function getActivePartner(partnersStore, partnerId) {
  const pid = String(partnerId || "");
  if (!pid) return null;
  const p = (partnersStore.partners || {})[pid];
  if (!p) return null;
  if (p.status !== "ACTIVE") return null;
  return { partner_id: pid, ...p };
}

function handleDiscovery(req, res, partnersStore, loadDB, opts = {}) {
  const db = loadDB();

  // Prefer "boring" error helper provided by routes.js
  const sendErr = typeof opts.sendErr === "function"
    ? opts.sendErr
    : (r, status, code, detail) => {
        const out = { ok: false, error: code };
        if (detail) out.detail = String(detail);
        return r.status(status).json(out);
      };

  const PAGE_MAX = Number.isFinite(opts.PAGE_MAX) ? opts.PAGE_MAX : 10;
  const RESP_MAX_BYTES = Number.isFinite(opts.RESP_MAX_BYTES) ? opts.RESP_MAX_BYTES : (200 * 1024);

  // Identify client + partner
  const ip = getClientIp(req) || "unknown";
  const partnerHeader = String(req.get("X-Federation-Partner") || "");
  const partner = getActivePartner(partnersStore, partnerHeader);

  // Rate limit (prefer the new token bucket from routes.js)
  if (typeof opts.allowPublicRead === "function") {
    if (!opts.allowPublicRead("fed:discovery:" + ip)) return sendErr(res, 429, "rate_limited");
  } else {
    const ipRL = rateLimit({ key: "ip:" + ip, capacity: 60, refillPerSec: 0.5, cost: 1 });
    if (!ipRL.ok) return sendErr(res, 429, "rate_limited");
  }

  if (partner) {
    if (typeof opts.allowPartnerRead === "function") {
      if (!opts.allowPartnerRead("fed:discovery:" + partner.partner_id)) return sendErr(res, 429, "rate_limited");
    } else {
      const pRL = rateLimit({ key: "partner:" + partner.partner_id, capacity: 240, refillPerSec: 2, cost: 1 });
      if (!pRL.ok) return sendErr(res, 429, "rate_limited");
    }
  }

  // Filters (preserve semantics)
  const qStatus = String(req.query.status || "");
  const wantTags = splitTags(req.query.tags);
  const createdAfter = parseIsoOrNull(req.query.created_after);
  const publishedAfter = parseIsoOrNull(req.query.published_after);
  const needsMoreVoters = parseBool(req.query.needs_more_voters);

  // limit: clamp to PAGE_MAX (default PAGE_MAX)
  const limit = (() => {
    const raw = req.query.limit;
    if (raw == null || raw === "") return PAGE_MAX;
    const n = Number(raw);
    if (!Number.isFinite(n) || n <= 0) return PAGE_MAX;
    return Math.max(1, Math.min(PAGE_MAX, Math.floor(n)));
  })();

  // cursor: strict (bad => 400)
  const pc = parseCursorStrict(req.query.cursor);
  if (pc && pc.error) return sendErr(res, 400, pc.error);
  const cursor = pc.cur;

  const rows = [];

  for (const poll of db.polls) {
    if (!poll) continue;

    lifecycle.applyLifecycle(poll);

    if (!lifecycle.isVisibleInList(poll)) continue;

    // public only sees published
    if (!partner && poll.status !== "published") continue;

    // status filter (strict)
    if (qStatus === "open") {
      if (poll.status !== "open") continue;
    } else if (qStatus === "closed") {
      if (!(poll.status === "closed" || poll.status === "cooldown")) continue;
    } else if (qStatus === "published") {
      if (poll.status !== "published") continue;
    } else if (qStatus) {
      return sendErr(res, 400, "bad_status_filter");
    }

    const tags = getPollTags(poll);
    if (!hasAllTags(tags, wantTags)) continue;

    if (createdAfter && String(poll.created_at || "") <= createdAfter) continue;
    if (publishedAfter && String(poll.published_at || "") <= publishedAfter) continue;

    if (needsMoreVoters) {
      const min = poll && poll.meta ? Number(poll.meta.min_voters) : NaN;
      if (!Number.isFinite(min) || min <= 0) continue;

      const sc = summaryCountsForPoll(db, poll.id);
      if (sc.people_voted_total >= min) continue;
    }

    rows.push(poll);
  }

  rows.sort(cmpCreatedDesc);

  let paged = rows;
  if (cursor) paged = rows.filter(p => afterCursor(p, cursor));
  paged = paged.slice(0, limit);

  const outPolls = paged.map(p => ({
    poll_id: p.id,
    poll_fingerprint: pollFingerprint(p),
    status: p.status,
    created_at: p.created_at || null,
    published_at: p.published_at || null,
    tags: getPollTags(p),
    queue_no: p.queue_no || null,
    summary_counts: summaryCountsForPoll(db, p.id),
  }));

  const respObj = {
    exchange_id: process.env.EXCHANGE_ID || null,
    canonical_base_url: process.env.CANONICAL_BASE_URL || null,
    polls: outPolls,
    next_cursor: makeNextCursor(paged[paged.length - 1]),
  };

  // response size cap (defensive)
  const s = JSON.stringify(respObj);
  if (Buffer.byteLength(s, "utf8") > RESP_MAX_BYTES) {
    // trim polls until under cap
    let trimmed = outPolls.slice(0);
    while (trimmed.length > 0) {
      const tryObj = { ...respObj, polls: trimmed, truncated: true };
      const ss = JSON.stringify(tryObj);
      if (Buffer.byteLength(ss, "utf8") <= RESP_MAX_BYTES) return res.json(tryObj);
      trimmed = trimmed.slice(0, trimmed.length - 1);
    }
    return sendErr(res, 500, "response_too_large");
  }

  return res.type("application/json").send(s);
}

module.exports = { handleDiscovery };
