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

// Header name is locked by your decision:
const STAMP_HEADER = "X-Stamp";

const crypto = require("crypto");

// Hash a stamp token so we never store plaintext tokens in db.json.
// If db.json leaks, attackers still shouldn't get working stamps.
function hashStampToken(token) {
  return crypto.createHash("sha256").update(String(token)).digest("hex");
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
function issueOneStamp(db, personaId) {
  const token = generateStampToken();
  const rec = {
    id: "st_" + nanoid(12),
    persona_id: personaId,
    token_hash: hashStampToken(token),
    status: "ACTIVE",
    issued_at: nowIso(),
    use_count: 0,
    last_used_at: null,
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

// ---- Persistence ----
const DATA_DIR = path.join(__dirname, "data");
const DB_PATH = path.join(DATA_DIR, "db.json");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function loadDB() {
  if (!fs.existsSync(DB_PATH)) {
    // Minimal "empty DB" shape.
    // Keep existing arrays even if unused (keys/challenges) to avoid breaking future plans.
    const empty = {
      polls: [],
      votes: [],
      events: [],

      // Future-facing placeholders (currently unused, but harmless to keep):
      keys: [],
      challenges: [],

      // NEW: MVP persona + stamp system
      personas: [], // Each persona = holder of stamps (device for now)
      stamps: [],   // Stores ONLY hashes of stamp tokens + mapping to persona
    };

    fs.writeFileSync(DB_PATH, JSON.stringify(empty, null, 2));
    return empty;
  }

  // File exists → read it
  const db = JSON.parse(fs.readFileSync(DB_PATH, "utf-8"));

  // Backfill new fields for older DB files
  if (!Array.isArray(db.personas)) db.personas = [];
  if (!Array.isArray(db.stamps)) db.stamps = [];

  return db;
}


function saveDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
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
      issued.push(issueOneStamp(db, personaId));
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
    issued.push(issueOneStamp(db, personaId));
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
  const { option_id, voter_token } = req.body || {};
  if (!option_id) return res.status(400).json({ error: "option_id is required" });

  const db = loadDB();

  // ---- STAMP REQUIRED (MVP) ----
  const presented = req.get(STAMP_HEADER); // "X-Stamp"
  if (!presented) return res.status(401).json({ error: "missing X-Stamp" });

  const stampRec = findStampByToken(db, presented);
  if (!stampRec) return res.status(403).json({ error: "invalid X-Stamp" });

  const poll = db.polls.find(p => p.id === pollId);
  if (!poll) return res.status(404).json({ error: "poll not found" });

  // Apply lifecycle on access
  const life = applyLifecycle(poll, nowIso());
  if (life.changed) saveDB(db);

  if (!canVote(poll)) return res.status(400).json({ error: "poll is closed" });

  const token = voter_token ? String(voter_token) : nanoid(16);

  const prev = db.votes.find(v => v.poll_id === pollId && v.voter_token === token);

  // One vote per token per poll: replace existing vote from same token
  db.votes = db.votes.filter(v => !(v.poll_id === pollId && v.voter_token === token));

  db.votes.push({
    id: nanoid(12),
    poll_id: pollId,
    option_id: String(option_id),
    voter_token: token,
    created_at: prev ? prev.created_at : nowIso(),
    updated_at: prev ? nowIso() : null,
    meta: req.body?.meta || {},
  });

  db.events.push({ kind: "vote_cast", poll_id: pollId, at: nowIso() });
  saveDB(db);

  const results = computeResults(db, pollId);
  broadcast(pollId, "results", { poll_id: pollId, results });

  res.json({ ok: true, voter_token: token, results });
});

app.get("/api/polls/:id/stream", (req, res) => {
  const pollId = req.params.id;
  const db = loadDB();
  const poll = db.polls.find(p => p.id === pollId);
  if (!poll) return res.status(404).end();

  // SSE headers
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  // Register subscriber
  if (!subscribers.has(pollId)) subscribers.set(pollId, new Set());
  subscribers.get(pollId).add(res);

  // Send initial snapshot
  const results = computeResults(db, pollId);
  sseSend(res, "poll", { kind: "snapshot", poll, results });

  // Keepalive
  const interval = setInterval(() => {
    try {
      res.write(":keepalive\n\n");
    } catch (_) {}
  }, 15000);

  req.on("close", () => {
    clearInterval(interval);
    const set = subscribers.get(pollId);
    if (set) set.delete(res);
  });
});

function computeResults(db, pollId) {
  const poll = db.polls.find(p => p.id === pollId);
  if (!poll) return { totals: {}, total_votes: 0 };

  const totals = {};
  for (const opt of poll.options) totals[opt.id] = 0;

  const votes = db.votes.filter(v => v.poll_id === pollId);
  for (const v of votes) {
    if (totals[v.option_id] === undefined) continue;
    totals[v.option_id] += 1; // Future: add computed_weight
  }
  return { totals, total_votes: votes.length };
}

const PORT = process.env.PORT || 8787;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Bread Exchange MVP running on http://localhost:${PORT}`);
});
