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

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));

// ---- Persistence ----
const DATA_DIR = path.join(__dirname, "data");
const DB_PATH = path.join(DATA_DIR, "db.json");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function loadDB() {
  if (!fs.existsSync(DB_PATH)) {
    const empty = { polls: [], votes: [], events: [] };
    fs.writeFileSync(DB_PATH, JSON.stringify(empty, null, 2));
    return empty;
  }
  return JSON.parse(fs.readFileSync(DB_PATH, "utf-8"));
}

function saveDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

function nowIso() {
  return new Date().toISOString();
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
    try { sseSend(res, event, data); } catch (_) {}
  }
}

// ---- Static frontend ----
app.use(express.static(path.join(__dirname, "public")));

// ---- API ----
app.get("/api/health", (req, res) => {
  res.json({ ok: true, time: nowIso() });
});

app.get("/api/polls", (req, res) => {
  const db = loadDB();
  const polls = db.polls.map(p => ({
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
      id: (o && o.id) ? String(o.id) : String(idx + 1),
      label: (o && o.label) ? String(o.label).slice(0, 200) : `Option ${idx + 1}`,
    })),
    status: "open",
    created_at: nowIso(),
    // Future: domain tags, weighting policy, protected-voices config
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
  const poll = db.polls.find(p => p.id === pollId);
  if (!poll) return res.status(404).json({ error: "poll not found" });
  if (poll.status !== "open") return res.status(400).json({ error: "poll is closed" });

  const token = voter_token ? String(voter_token) : nanoid(16);

  const prev = db.votes.find(
    v => v.poll_id === pollId && v.voter_token === token
  );

  db.votes = db.votes.filter(
    v => !(v.poll_id === pollId && v.voter_token === token)
  );

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
    try { res.write(":keepalive\n\n"); } catch (_) {}
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
