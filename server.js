/**
 * Bread Standard "Exchange spine" MVP server
 * - Implements the endpoints your front-end expects:
 *   GET  /api/health
 *   GET  /api/polls
 *   POST /api/polls
 *   POST /api/polls/:id/vote
 *   GET  /api/polls/:id/stream   (SSE)
 *
 * - Persistence: JSON file on disk (data/db.json)
 * - Notes:
 *   This is a deliberately small, non-magical baseline that you can extend into the full Exchange.
 */

const express = require("express");
const cors = require("cors");
const { nanoid } = require("nanoid");
const fs = require("fs");
const path = require("path");

const { applyLifecycle, canVote, isVisibleInList, nowIso } = require("./lib/lifecycle");
const STAMP_POOL_TARGET = 3;        // How many active stamps a persona should hold
const STAMP_POOL_MAX = 7;           // Hard cap for active stamps per persona
const STAMP_ROTATE_EVERY_USES = 1000; // Not implemented yet (skeleton only)
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");

// Header name is locked by your decision:
const STAMP_HEADER = "X-Stamp";

const crypto = require("crypto");

// Hash a stamp token so we never store plaintext tokens in db.json.
// If db.json leaks, attackers still shouldn't get working stamps.
function hashStampToken(token) {
  return crypto.createHash("sha256").update(String(token)).digest("hex");
}

/**
 * Ballot UID helpers
 *
 * Goal: derive a stable "ballot identity" per (stamp, poll) without storing stamp IDs in votes.
 *
 * ballot_uid = SHA256(stamp_token_hash + ":" + pollId + ":" + server_salt)
 *
 * - stamp_token_hash is already stored in identity.private.json as stampRec.token_hash
 * - server_salt is stored once in db.keys so it survives restarts
 * - pollId scopes the uid so the same stamp can't be linked across different polls via uid
 */

function getOrCreateBallotSalt(db) {
  const kind = "ballot_uid_salt";

  // Look for an existing salt in db.keys (identity DB section)
  let rec = Array.isArray(db.keys) ? db.keys.find(k => k && k.kind === kind) : null;
  if (rec && typeof rec.value === "string" && rec.value.length >= 16) return rec.value;

  // Create a new salt and persist it
  const salt = crypto.randomBytes(32).toString("hex"); // 64 hex chars
  if (!Array.isArray(db.keys)) db.keys = [];

  db.keys.push({
    id: "key_" + nanoid(10),
    kind,
    value: salt,
    created_at: nowIso(),
  });

  return salt;
}

function makeBallotUid(db, pollId, stampTokenHash) {
  const salt = getOrCreateBallotSalt(db);
  const input = `${String(stampTokenHash)}:${String(pollId)}:${salt}`;
  return crypto.createHash("sha256").update(input).digest("hex");
}

// Generate a new opaque stamp token to hand to the client.
// We *do not* store this raw token in the DB, only the hash.
function generateStampToken() {
  // 32 bytes -> 64 hex chars. Prefixed for readability.
  return "s_" + crypto.randomBytes(32).toString("hex");
}

// Find a stamp record by the *presented* raw token.
function findStampByToken(db, token) {
  const tokenHash = hashStampToken(token);
  return db.stamps.find(s => s.token_hash === tokenHash && s.status === "ACTIVE") || null;
}

// Ensure a persona exists. For MVP, a persona is simply "an entity that holds stamps".
// No identity, no device IDs, no recovery.
function createPersona(db) {
  const persona = {
    id: "per_" + nanoid(12),
    created_at: nowIso(),
    meta: {},
  };
  db.personas.push(persona);
  return persona;
}

// Issue exactly one new stamp and persist it.
// Returns the raw token (client must store it), and the record is stored hashed.
function issueOneStamp(db, personaId, options = {}) {
  const token = generateStampToken();

  const rec = {
    id: "st_" + nanoid(12),
    persona_id: personaId,
    token_hash: hashStampToken(token),
    status: "ACTIVE",
    issued_at: nowIso(),
    use_count: 0,
    last_used_at: null,
    weight: typeof options.weight === "number" ? options.weight : 1.0,
    tags: Array.isArray(options.tags) ? options.tags : [],
    // Future fields: rotated_at, replaced_by, revoked_at, etc.
  };

  db.stamps.push(rec);
  return token;
}

// Count ACTIVE stamps for a persona
function countActiveStamps(db, personaId) {
  return db.stamps.filter(s => s.persona_id === personaId && s.status === "ACTIVE").length;
}

const app = express();
// app.use(cors());
app.use(express.json({ limit: "1mb" }));

const REQUIRE_KEY_SESSION = process.env.REQUIRE_KEY_SESSION === "1"; // reserved for later
// ---- Persistence (split DB) ----
// Goal: keep identity material separate from poll/vote material.
// We keep the old db.json as a one-time migration source only.

const LEGACY_DB_PATH = path.join(DATA_DIR, "db.json");

// NEW: split stores
const EXCHANGE_DB_PATH = path.join(DATA_DIR, "exchange.private.json"); // polls/votes/events
const IDENTITY_DB_PATH = path.join(DATA_DIR, "identity.private.json"); // personas/stamps (+future)

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function readJsonOrInit(filePath, emptyObj) {
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, JSON.stringify(emptyObj, null, 2));
    return emptyObj;
  }
  return JSON.parse(fs.readFileSync(filePath, "utf-8"));
}

function writeJson(filePath, obj) {
  fs.writeFileSync(filePath, JSON.stringify(obj, null, 2));
}

// One-time migration:
// If legacy db.json exists but split files don't, split it.
// This keeps behavior stable after deploy, without manual steps.
function migrateLegacyDbIfNeeded() {
  const legacyExists = fs.existsSync(LEGACY_DB_PATH);
  const exchangeExists = fs.existsSync(EXCHANGE_DB_PATH);
  const identityExists = fs.existsSync(IDENTITY_DB_PATH);

  if (!legacyExists) return;
  if (exchangeExists && identityExists) return;

  const legacy = JSON.parse(fs.readFileSync(LEGACY_DB_PATH, "utf-8"));

  const exchangeEmpty = { polls: [], votes: [], events: [] };
  const identityEmpty = { personas: [], stamps: [], keys: [], challenges: [] };

  const exchange = {
    polls: Array.isArray(legacy.polls) ? legacy.polls : [],
    votes: Array.isArray(legacy.votes) ? legacy.votes : [],
    events: Array.isArray(legacy.events) ? legacy.events : [],
  };

  const identity = {
    // If these exist in your current db.json, carry them forward.
    personas: Array.isArray(legacy.personas) ? legacy.personas : [],
    stamps: Array.isArray(legacy.stamps) ? legacy.stamps : [],
    // Keep placeholders you already had (harmless):
    keys: Array.isArray(legacy.keys) ? legacy.keys : [],
    challenges: Array.isArray(legacy.challenges) ? legacy.challenges : [],
  };

  // If missing, initialize new files
  if (!exchangeExists) writeJson(EXCHANGE_DB_PATH, exchangeEmpty);
  if (!identityExists) writeJson(IDENTITY_DB_PATH, identityEmpty);

  // Overwrite with migrated content
  writeJson(EXCHANGE_DB_PATH, exchange);
  writeJson(IDENTITY_DB_PATH, identity);

  // Keep legacy as a backup (do NOT delete automatically)
  // Optional: rename legacy file to make it obvious it's legacy
  // fs.renameSync(LEGACY_DB_PATH, `${LEGACY_DB_PATH}.migrated`);
}

// loadDB returns a merged view so the rest of server.js does not need refactors.
function loadDB() {
  migrateLegacyDbIfNeeded();

  const exchange = readJsonOrInit(EXCHANGE_DB_PATH, { polls: [], votes: [], events: [] });
  const identity = readJsonOrInit(IDENTITY_DB_PATH, { personas: [], stamps: [], keys: [], challenges: [] });

  // Backfill new arrays if someone hand-edited files
  if (!Array.isArray(exchange.polls)) exchange.polls = [];
  if (!Array.isArray(exchange.votes)) exchange.votes = [];
  if (!Array.isArray(exchange.events)) exchange.events = [];

  if (!Array.isArray(identity.personas)) identity.personas = [];
  if (!Array.isArray(identity.stamps)) identity.stamps = [];
  if (!Array.isArray(identity.keys)) identity.keys = [];
  if (!Array.isArray(identity.challenges)) identity.challenges = [];

  // Merge for existing code compatibility
  return {
    polls: exchange.polls,
    votes: exchange.votes,
    events: exchange.events,

    personas: identity.personas,
    stamps: identity.stamps,
    keys: identity.keys,
    challenges: identity.challenges,
  };
}

// saveDB splits the merged view back into the correct files.
function saveDB(db) {
  // Exchange runtime state
  writeJson(EXCHANGE_DB_PATH, {
    polls: Array.isArray(db.polls) ? db.polls : [],
    votes: Array.isArray(db.votes) ? db.votes : [],
    events: Array.isArray(db.events) ? db.events : [],
  });

  // Identity / authority state
  writeJson(IDENTITY_DB_PATH, {
    personas: Array.isArray(db.personas) ? db.personas : [],
    stamps: Array.isArray(db.stamps) ? db.stamps : [],
    keys: Array.isArray(db.keys) ? db.keys : [],
    challenges: Array.isArray(db.challenges) ? db.challenges : [],
  });
}

// (Optional helper; ok to keep even if unused right now)
function parseIsoToMs(s) {
  const t = Date.parse(String(s || ""));
  return Number.isFinite(t) ? t : null;
}

// ---- SSE subscribers per poll ----
const subscribers = new Map(); // pollId -> Set(res)

function sseSend(res, event, data) {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

function broadcast(pollId, event, data) {
  const set = subscribers.get(pollId);
  if (!set) return;
  for (const res of set) {
    try {
      sseSend(res, event, data);
    } catch (_) {}
  }
}

// ---- Static frontend ----
app.use(express.static(path.join(__dirname, "public")));

// ---- API ----
app.get("/api/health", (req, res) => {
  res.json({ ok: true, time: nowIso() });
});

// ---- STAMP ISSUANCE ----
// Uses existing Caddy Basic Auth gate (treat as a "write").
// Behavior:
// - If client provides a valid X-Stamp -> resolve persona, top up if below target
// - If no/invalid stamp -> create new persona, issue target stamps
app.post("/api/stamp", (req, res) => {
  const presented = req.get(STAMP_HEADER); // "X-Stamp"
  const db = loadDB();

  // Try to resolve existing persona from presented stamp (if any)
  let personaId = null;
  if (presented) {
    const stampRec = findStampByToken(db, presented);
    if (stampRec) {
      personaId = stampRec.persona_id;
      // (Optional) track last-used time (doesn't change behavior yet)
      stampRec.last_used_at = nowIso();
    }
  }

  // If no valid stamp, create a brand new persona (MVP "no recovery" model)
  if (!personaId) {
    const persona = createPersona(db);
    personaId = persona.id;

    // Issue initial pool
    const issued = [];
    const toIssue = Math.min(STAMP_POOL_TARGET, STAMP_POOL_MAX);
    for (let i = 0; i < toIssue; i++) {
      issued.push(issueOneStamp(db, personaId, req.body));
    }

    db.events.push({ kind: "stamp_issued", persona_id: personaId, at: nowIso(), count: issued.length });
    saveDB(db);

    return res.json({
      ok: true,
      persona_id: personaId, // INTERNAL-ish; fine for now, remove later if you want less leakage
      issued,
      active_count: countActiveStamps(db, personaId),
      target: STAMP_POOL_TARGET,
      max: STAMP_POOL_MAX,
    });
  }

  // Persona exists: top-up logic (rotation later)
  const active = countActiveStamps(db, personaId);
  const issued = [];

  // Top up to target (but never exceed max)
  const desired = Math.min(STAMP_POOL_TARGET, STAMP_POOL_MAX);
  const room = Math.max(0, STAMP_POOL_MAX - active);
  const need = Math.max(0, desired - active);
  const toIssue = Math.min(room, need);

  for (let i = 0; i < toIssue; i++) {
    issued.push(issueOneStamp(db, personaId, req.body));
  }

  if (issued.length > 0) {
    db.events.push({ kind: "stamp_topped_up", persona_id: personaId, at: nowIso(), count: issued.length });
  }

  saveDB(db);

  return res.json({
    ok: true,
    persona_id: personaId, // INTERNAL-ish; fine for now
    issued,                // empty array means "you already have enough"
    active_count: countActiveStamps(db, personaId),
    target: STAMP_POOL_TARGET,
    max: STAMP_POOL_MAX,
  });
});

app.get("/api/polls", (req, res) => {
  const db = loadDB();

  // Apply lifecycle transitions before listing
  let changed = false;
  for (const p of db.polls) {
    const r = applyLifecycle(p, nowIso());
    if (r.changed) changed = true;
  }
  if (changed) saveDB(db);

  const polls = db.polls
    .filter(p => isVisibleInList(p, nowIso()))
    .map(p => ({
      ...p,
      results: computeResults(db, p.id),
    }));

  res.json({ polls });
});

app.post("/api/polls", (req, res) => {
  const { title, description, type, options } = req.body || {};
  if (!title || !Array.isArray(options) || options.length < 2) {
    return res.status(400).json({ error: "title and at least 2 options are required" });
  }

  const db = loadDB();
  const id = nanoid(10);

  const poll = {
    id,
    title: String(title).slice(0, 200),
    description: description ? String(description).slice(0, 5000) : "",
    type: type ? String(type) : "single",
    options: options.map((o, idx) => ({
      id: o && o.id ? String(o.id) : String(idx + 1),
      label: o && o.label ? String(o.label).slice(0, 200) : `Option ${idx + 1}`,
    })),
    status: "open",
    closed_at: null,
    created_at: nowIso(),
    expires_at: req.body?.expires_at ? String(req.body.expires_at) : null,
    meta: req.body?.meta || {},
  };

  db.polls.unshift(poll);
  db.events.push({ kind: "poll_created", poll_id: id, at: nowIso() });
  saveDB(db);

  broadcast(id, "poll", { kind: "poll_created", poll });
  res.json({ poll });
});

app.post("/api/polls/:id/vote", (req, res) => {
  const pollId = req.params.id;
  const { option_id } = req.body || {};
  if (!option_id) return res.status(400).json({ error: "option_id is required" });

  const db = loadDB();

  // ---- STAMP REQUIRED (MVP) ----
  const presented = req.get(STAMP_HEADER); // "X-Stamp"
  if (!presented) return res.status(401).json({ error: "missing X-Stamp" });

  // Stamp must exist
  const stampRec = findStampByToken(db, presented);
  if (!stampRec) return res.status(403).json({ error: "invalid X-Stamp" });

  // ---- WEIGHT VALIDATION (authoritative) ----
  // Missing / invalid / <= 0 weight => assume forgery; expire stamp; reject vote.
  const rawWeight = stampRec.weight;
  const weight = Number(rawWeight);

  if (!Number.isFinite(weight) || weight <= 0) {
    stampRec.status = "EXPIRED";
    stampRec.last_used_at = nowIso();

    db.events.push({
      kind: "stamp_expired_invalid_weight",
      stamp_id: stampRec.id,
      at: nowIso(),
      note: `weight=${String(rawWeight)}`,
    });

    saveDB(db);
    return res.status(403).json({ error: "try voting again at a different time" });
  }

  // Poll must exist
  const poll = db.polls.find(p => p.id === pollId);
  if (!poll) return res.status(404).json({ error: "poll not found" });

  // Apply lifecycle on access
  const life = applyLifecycle(poll, nowIso());
  if (life.changed) saveDB(db);

  if (!canVote(poll)) return res.status(400).json({ error: "poll is closed" });

  // Server-derived ballot identity (one per stamp per poll)
  // NOTE: makeBallotUid() must already exist (we added it in Step 2).
  const ballotUid = makeBallotUid(db, pollId, stampRec.token_hash);

  // One vote per ballotUid per poll: replace existing vote from same ballotUid
  const prev = db.votes.find(v => v.poll_id === pollId && v.voter_token === ballotUid);
  db.votes = db.votes.filter(v => !(v.poll_id === pollId && v.voter_token === ballotUid));

  db.votes.push({
    id: nanoid(12),
    poll_id: pollId,
    option_id: String(option_id),

    // Stored as voter_token for backward compatibility with existing API shape.
    // Semantically this is the ballot_uid.
    voter_token: ballotUid,

    // Authoritative stamp weight used for tally.
    weight,

    created_at: prev ? prev.created_at : nowIso(),
    updated_at: prev ? nowIso() : null,
    meta: req.body?.meta || {},
  });

  db.events.push({ kind: "vote_cast", poll_id: pollId, at: nowIso() });
  saveDB(db);

  const results = computeResults(db, pollId);
  broadcast(pollId, "results", { poll_id: pollId, results });

  res.json({ ok: true, voter_token: ballotUid, results });
});

function computeResults(db, pollId) {
  const poll = db.polls.find(p => p.id === pollId);
  if (!poll) return { totals: {}, total_votes: 0 };

  const totals = {};
  for (const opt of poll.options) totals[opt.id] = 0;

  const votes = db.votes.filter(v => v.poll_id === pollId);

  // Stats for audit clarity (computational weights given)
  let wMin = null;
  let wMax = null;
  let wSum = 0;
  let wCount = 0;

  for (const v of votes) {
    if (totals[v.option_id] === undefined) continue;

    // Defensive: a bad stored weight must never turn totals into NaN.
    // (Vote endpoint should already enforce weight > 0.)
    const w = Number(v.weight);
    if (!Number.isFinite(w) || w <= 0) continue;

    totals[v.option_id] += w;

    wMin = (wMin === null) ? w : Math.min(wMin, w);
    wMax = (wMax === null) ? w : Math.max(wMax, w);
    wSum += w;
    wCount += 1;
  }

  return {
    totals,

    // Backward compatibility
    total_votes: votes.length,

    // New explicit fields
    people_voted: votes.length,        // one stored vote per ballotUid (unique stamp per poll)
    represented_people: wSum,          // sum of weights
    weights_used: { min: wMin, max: wMax, sum: wSum, count: wCount },

    validated: true,
  };
}


const PORT = process.env.PORT || 8787;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Bread Exchange MVP running on http://localhost:${PORT}`);
});
