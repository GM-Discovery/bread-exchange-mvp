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

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");

// Header name is locked by your decision:
const STAMP_HEADER = "X-Stamp";
const VOTER_TOKEN_HEADER = "X-Voter-Token";
// self_id proof header (private secret; never public; store hashed only)
const SELF_ID_HEADER = "X-Self-ID";

const crypto = require("crypto");

// --- Persona-unique ballot UID (one persona -> one vote per poll) ---
// This computes a stable, non-raw key for a (persona_id, poll_id) pair.
function sha256Hex(s) {
  return crypto.createHash("sha256").update(String(s), "utf8").digest("hex");
}

function getBallotSalt(db) {
  return (
    db?.keys?.ballot_uid_salt ||
    process.env.BALLOT_UID_SALT ||
    process.env.SERVER_SALT ||
    "dev_salt_change_me"
  );
}

function personaBallotUid(db, pollId, personaId) {
  const salt = getBallotSalt(db);
  return sha256Hex(`${personaId}:${pollId}:${salt}`);
}

const app = express();

// CORS FIRST
app.use(cors({
  origin: true, // reflect origin
  credentials: false,
}));

// PRE-FLIGHT MUST ALWAYS SUCCEED
app.options("*", cors());

// THEN body parsing
app.use(express.json({ limit: "1mb" }));

// Hash for Stamp Tokens
function hashStampToken(token) {
  return crypto.createHash("sha256").update(String(token)).digest("hex");
}

// ---- Config (loaded once at startup) ----
// If config.js is missing or invalid, fall back to current behavior defaults.
function loadConfig() {
  const defaults = {
    stamps: { pool_target: 3, pool_max: 7, rotate_every_uses: 1000 },
    lifecycle: {
      opinion_retention_seconds: 7 * 24 * 60 * 60,
      governance_retention_seconds: 30 * 24 * 60 * 60,
      governance_cooldown_seconds: 60 * 60,
    },
    security: { ballot_uid_salt: { min_length: 16, bytes: 32 } },
  };

  const cfgPath = path.join(__dirname, "config.js");
  if (!fs.existsSync(cfgPath)) return defaults;

  try {
    const userCfg = require(cfgPath);
    return mergeConfig(defaults, userCfg);
  } catch (e) {
    console.warn("[config] failed to load config.js; using defaults");
    return defaults;
  }
}

// Small object-only deep merge.
// If a value is missing or invalid, default is preserved.
function mergeConfig(base, override) {
  if (!override || typeof override !== "object") return base;
  const out = { ...base };

  for (const k of Object.keys(base)) {
    const bv = base[k];
    const ov = override[k];

    if (bv && typeof bv === "object" && !Array.isArray(bv)) {
      out[k] = mergeConfig(bv, ov);
    } else {
      out[k] = ov === undefined ? bv : ov;
    }
  }
  return out;
}

const cfg = loadConfig();
// Load lifecycle as an object so we can call lifecycle.setDefaults(...)
const lifecycle = require("./lib/lifecycle");
const { applyLifecycle, canVote, isVisibleInList, nowIso } = lifecycle;

// ---- Config fingerprint (safe subset only) ----
// We fingerprint ONLY the safe public subset (stamps + lifecycle).
function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);

  if (Array.isArray(value)) {
    return "[" + value.map(stableStringify).join(",") + "]";
  }

  const keys = Object.keys(value).sort();
  return "{" + keys.map(k => JSON.stringify(k) + ":" + stableStringify(value[k])).join(",") + "}";
}

// Safe public subset (also used by GET /api/config in Step 2)
const CFG_PUBLIC = {
  stamps: {
    pool_target: cfg.stamps.pool_target,
    pool_max: cfg.stamps.pool_max,
    rotate_every_uses: cfg.stamps.rotate_every_uses,
  },
  lifecycle: {
    opinion_retention_seconds: cfg.lifecycle.opinion_retention_seconds,
    governance_retention_seconds: cfg.lifecycle.governance_retention_seconds,
    governance_cooldown_seconds: cfg.lifecycle.governance_cooldown_seconds,
  },
};

const CFG_FINGERPRINT = crypto
  .createHash("sha256")
  .update(stableStringify(CFG_PUBLIC))
  .digest("hex");

// Centralize lifecycle defaults (behavior unchanged with default config)
if (typeof lifecycle.setDefaults === "function") {
  lifecycle.setDefaults(cfg.lifecycle);
}

// Values now come from config (defaults match previous constants)
const STAMP_POOL_TARGET = cfg.stamps.pool_target; // general average active signatures, too high = salt guesses too low = no vote
const STAMP_POOL_MAX = cfg.stamps.pool_max; // max active signatures
const STAMP_ROTATE_EVERY_USES = cfg.stamps.rotate_every_uses; // How many times a single stamp can be used on a vote



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
  if (rec && typeof rec.value === "string" && rec.value.length >= cfg.security.ballot_uid_salt.min_length) return rec.value;

  // Create a new salt and persist it
  const salt = crypto.randomBytes(cfg.security.ballot_uid_salt.bytes).toString("hex"); // default 32 bytes => 64 hex chars
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
    kind: options.kind === "DELEGATED" ? "DELEGATED" : "STANDARD",
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

app.use((req, res, next) => {
  console.log("[REQ]", req.method, req.url);
  next();
});

// Enable CORS for browser clients (dev UI is on 127.0.0.1:1430)
app.use(cors());

// IMPORTANT: respond to preflight (OPTIONS) requests with 204/200
app.options("*", cors());

app.use(express.json({ limit: "1mb" }));

const REQUIRE_KEY_SESSION = process.env.REQUIRE_KEY_SESSION === "1"; // reserved for later
// ---- Persistence (split DB) ----
// Goal: keep identity material separate from poll/vote material.
// We keep the old db.json as a one-time migration source only.

const LEGACY_DB_PATH = path.join(DATA_DIR, "db.json");

// NEW: split stores
const EXCHANGE_DB_PATH = path.join(DATA_DIR, "exchange.private.json"); // polls/votes/events
const IDENTITY_DB_PATH = path.join(DATA_DIR, "identity.private.json"); // personas/stamps (+future)

// Identity layer stores (operator-readable state + append-only ledger)
const IDENTITY_STATE_PATH = path.join(DATA_DIR, "identity.state.json");
const IDENTITY_LEDGER_PATH = path.join(DATA_DIR, "identity.ledger.json");
// Delegation store (private; audit via identity ledger)
const DELEGATION_DB_PATH = path.join(DATA_DIR, "delegation.private.json");

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

// Delegation API v0 (minimal)
// Helper: operator override (optional). If OPERATOR_KEY is not set, operator mode is disabled.
function isOperator(req) {
  const operatorKey = process.env.OPERATOR_KEY;
  if (!operatorKey) return false;
  const presented = req.get("X-Operator-Key");
  return presented === operatorKey;
}


// IDENTITY LAYER v0 — helpers (backend-only)
// Semantics lock:
// - Votes use stampRec.weight ONLY (stamp is authoritative audit artifact).
// - Identity is consulted ONLY at stamp issuance time to SET stamp weight.
// - self_id is a *private stable secret* held by the user (stored hashed at rest).
// - public_alias is a rotatable *public handle* (not a secret).
// - internal_id is server-only and never exposed.

// ---- Identity State + Ledger IO ----
function readIdentityState() {
  // State is a cache for fast reads; ledger is the audit source of truth.
  // We keep state consistent by always writing state + ledger in the same request.
  return readJsonOrInit(IDENTITY_STATE_PATH, {
    identities: [],
    aliases: {},     // public_alias -> internal_id
    // Optional, helps fast lookup without scanning arrays:
    self_index: {},  // self_id_hash -> internal_id
  });
}

function writeIdentityState(state) {
  writeJson(IDENTITY_STATE_PATH, state);
}

function readIdentityLedger() {
  return readJsonOrInit(IDENTITY_LEDGER_PATH, { events: [] });
}

function appendIdentityLedgerEvent(evt) {
  const ledger = readIdentityLedger();
  if (!Array.isArray(ledger.events)) ledger.events = [];
  ledger.events.push(evt);
  writeJson(IDENTITY_LEDGER_PATH, ledger);
}

// ---- Lookup helpers ----
function findIdentityBySelfIdHash(state, selfIdHash) {
  const internalId = state?.self_index?.[selfIdHash];
  if (!internalId) return null;
  return (state.identities || []).find(x => x && x.internal_id === internalId) || null;
}

function findIdentityByAlias(state, alias) {
  const internalId = state?.aliases?.[String(alias || "")];
  if (!internalId) return null;
  return (state.identities || []).find(x => x && x.internal_id === internalId) || null;
}

function findIdentityByInternalId(state, internalId) {
  // Helper for internal-only lookups (server-only stable id).
  if (!internalId) return null;
  return (state.identities || []).find(x => x && x.internal_id === String(internalId)) || null;
}

// ---- Self-ID hashing (store only hashes at rest) ----
function hashSelfId(selfIdRaw) {
  // IMPORTANT: never store plaintext self_id.
  return crypto.createHash("sha256").update(String(selfIdRaw), "utf8").digest("hex");
}

function clampEarnedPersonal(x) {
  // Earned/personal points are capped at 10 by your rule.
  const n = Number(x);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(10, n));
}
function writeDelegations(d) {
  writeJson(DELEGATION_DB_PATH, d);
}

// Helper: resolve delegator identity
// - Normal: body.self_id
// - Operator: body.delegator_alias (only if OPERATOR_KEY is enabled)
function resolveDelegatorIdentity(state, req, res) {
  if (isOperator(req)) {
    const delegator_alias = req.body?.delegator_alias;
    if (!delegator_alias) {
      res.status(400).json({ error: "missing delegator_alias for operator call" });
      return null;
    }
    const delegator = findIdentityByAlias(state, String(delegator_alias));
    if (!delegator) {
      res.status(404).json({ error: "delegator_not_found" });
      return null;
    }
    return { delegator, by: "operator" };
  }

  const self_id = req.body?.self_id;
  if (!self_id) {
    res.status(401).json({ error: "missing self_id" });
    return null;
  }

  const selfHash = hashSelfId(String(self_id));
  const delegator = findIdentityBySelfIdHash(state, selfHash);
  if (!delegator) {
    res.status(404).json({ error: "delegator_not_found" });
    return null;
  }
  return { delegator, by: "self" };
}

// ---- Delegation Store IO (private) ----
function readDelegations() {
  return readJsonOrInit(DELEGATION_DB_PATH, { delegations: [] });
}

// ---- Weight math (v0: delegations deferred) ----
// - earned/personal points capped at 10
// For now we return 0 delegated weight until the delegation kernel lands.
function sumActiveDelegationsOut(delegatorInternalId) {
  const d = readDelegations();
  const rows = Array.isArray(d.delegations) ? d.delegations : [];
  let sum = 0;

  for (const r of rows) {
    if (!r) continue;
    if (r.status !== "ACTIVE") continue;
    if (r.delegator_internal_id !== delegatorInternalId) continue;
    const amt = Number(r.amount);
    if (!Number.isFinite(amt) || amt <= 0) continue;
    sum += amt;
  }
  return sum;
}

function sumActiveDelegationsIn(delegateeInternalId) {
  const d = readDelegations();
  const rows = Array.isArray(d.delegations) ? d.delegations : [];
  let sum = 0;

  for (const r of rows) {
    if (!r) continue;
    if (r.status !== "ACTIVE") continue;
    if (r.delegatee_internal_id !== delegateeInternalId) continue;
    const amt = Number(r.amount);
    if (!Number.isFinite(amt) || amt <= 0) continue;
    sum += amt;
  }
  return sum;
}

// v0 semantics: inbound delegations are aggregated at issuance time
function computeDelegatedInWeight(state, internalId) {
  // state is present for future expansions; v0 reads the delegation store directly.
  return sumActiveDelegationsIn(String(internalId || ""));
}

// Write delegation store
function writeDelegations(d) {
  writeJson(DELEGATION_DB_PATH, d);
}

// Sum ACTIVE outbound delegations for a delegator
function sumActiveDelegationsOut(delegatorInternalId) {
  const d = readDelegations();
  const rows = Array.isArray(d.delegations) ? d.delegations : [];
  let sum = 0;

  for (const r of rows) {
    if (!r) continue;
    if (r.status !== "ACTIVE") continue;
    if (r.delegator_internal_id !== delegatorInternalId) continue;
    const amt = Number(r.amount);
    if (!Number.isFinite(amt) || amt <= 0) continue;
    sum += amt;
  }
  return sum;
}

// Sum ACTIVE inbound delegations for a delegatee
function sumActiveDelegationsIn(delegateeInternalId) {
  const d = readDelegations();
  const rows = Array.isArray(d.delegations) ? d.delegations : [];
  let sum = 0;

  for (const r of rows) {
    if (!r) continue;
    if (r.status !== "ACTIVE") continue;
    if (r.delegatee_internal_id !== delegateeInternalId) continue;
    const amt = Number(r.amount);
    if (!Number.isFinite(amt) || amt <= 0) continue;
    sum += amt;
  }
  return sum;
}

// POST /api/delegation/revoke
// Body:
//   - self_id (delegator) OR (operator) delegator_alias
//   - delegatee_alias
app.post("/api/delegation/revoke", (req, res) => {
  const { delegatee_alias } = req.body || {};
  if (!delegatee_alias) return res.status(400).json({ error: "delegatee_alias is required" });

  const state = readIdentityState();
  const resolved = resolveDelegatorIdentity(state, req, res);
  if (!resolved) return;

  const delegator = resolved.delegator;
  const by = resolved.by;

  const delegatee = findIdentityByAlias(state, String(delegatee_alias));
  if (!delegatee) return res.status(404).json({ error: "delegatee_not_found" });

  const delegatorInternalId = String(delegator.internal_id);
  const delegateeInternalId = String(delegatee.internal_id);

  const d = readDelegations();
  if (!Array.isArray(d.delegations)) d.delegations = [];

  const edge = d.delegations.find(r =>
    r &&
    r.delegator_internal_id === delegatorInternalId &&
    r.delegatee_internal_id === delegateeInternalId &&
    r.status === "ACTIVE"
  );

  if (!edge) return res.json({ ok: true }); // idempotent

  const now = nowIso();
  const prior = edge.amount;

  edge.status = "REVOKED";
  edge.updated_at = now;

  writeDelegations(d);

  appendIdentityLedgerEvent({
    id: "evt_" + nanoid(12),
    ts: now,
    type: "DELEGATION_REVOKED",
    delegator_internal_id: delegatorInternalId,
    delegatee_internal_id: delegateeInternalId,
    prior_amount: prior,
    meta: { by },
  });

  return res.json({ ok: true });
});

// POST /api/delegation/set
// Body:
//   - self_id (delegator) OR (operator) delegator_alias
//   - delegatee_alias
//   - amount (integer; 0 revokes)
app.post("/api/delegation/set", (req, res) => {
  const { delegatee_alias, amount } = req.body || {};
  if (!delegatee_alias || amount === undefined) {
    return res.status(400).json({ error: "delegatee_alias and amount are required" });
  }

  const amt = Number(amount);
  if (!Number.isInteger(amt) || amt < 0) {
    return res.status(400).json({ error: "amount must be an integer >= 0" });
  }

  const state = readIdentityState();
  const resolved = resolveDelegatorIdentity(state, req, res);
  if (!resolved) return;

  const delegator = resolved.delegator;
  const by = resolved.by;

  const delegatee = findIdentityByAlias(state, String(delegatee_alias));
  if (!delegatee) return res.status(404).json({ error: "delegatee_not_found" });

  const delegatorInternalId = String(delegator.internal_id);
  const delegateeInternalId = String(delegatee.internal_id);

  const d = readDelegations();
  if (!Array.isArray(d.delegations)) d.delegations = [];

  // Find existing edge (one per pair)
  let edge = d.delegations.find(r =>
    r &&
    r.delegator_internal_id === delegatorInternalId &&
    r.delegatee_internal_id === delegateeInternalId
  );

  const now = nowIso();

  // amount=0 => revoke (audit-friendly)
  if (amt === 0) {
    if (edge && edge.status === "ACTIVE") {
      const prior = edge.amount;
      edge.status = "REVOKED";
      edge.updated_at = now;

      writeDelegations(d);

      appendIdentityLedgerEvent({
        id: "evt_" + nanoid(12),
        ts: now,
        type: "DELEGATION_REVOKED",
        delegator_internal_id: delegatorInternalId,
        delegatee_internal_id: delegateeInternalId,
        prior_amount: prior,
        meta: { by },
      });
    }

    const W = clampEarnedPersonal(delegator.earned_personal ?? 0);
    const outSumNow = sumActiveDelegationsOut(delegatorInternalId);
    return res.json({
      ok: true,
      delegated_out_sum: outSumNow,
      delegator_available_weight: Math.max(0, W - outSumNow),
    });
  }

  // Budget enforcement: sum(out) <= current earned_personal
  const W = clampEarnedPersonal(delegator.earned_personal ?? 0);

  // Compute current out sum excluding this edge (if updating)
  let outSum = 0;
  for (const r of d.delegations) {
    if (!r || r.status !== "ACTIVE") continue;
    if (r.delegator_internal_id !== delegatorInternalId) continue;
    if (edge && r === edge) continue;
    const a = Number(r.amount);
    if (!Number.isFinite(a) || a <= 0) continue;
    outSum += a;
  }

  if ((outSum + amt) > W) {
    return res.status(400).json({
      error: "delegation_budget_exceeded",
      weight: W,
      delegated_out_sum: outSum,
      attempted_amount: amt,
    });
  }

  // Upsert ACTIVE edge
  if (!edge) {
    edge = {
      id: "del_" + nanoid(12),
      delegator_internal_id: delegatorInternalId,
      delegatee_internal_id: delegateeInternalId,
      amount: amt,
      status: "ACTIVE",
      created_at: now,
      updated_at: now,
    };
    d.delegations.push(edge);
  } else {
    edge.amount = amt;
    edge.status = "ACTIVE";
    edge.updated_at = now;
  }

  writeDelegations(d);

  appendIdentityLedgerEvent({
    id: "evt_" + nanoid(12),
    ts: now,
    type: "DELEGATION_SET",
    delegator_internal_id: delegatorInternalId,
    delegatee_internal_id: delegateeInternalId,
    amount: amt,
    meta: { by },
  });

  const outSumNow = sumActiveDelegationsOut(delegatorInternalId);

  return res.json({
    ok: true,
    delegated_out_sum: outSumNow,
    delegator_available_weight: Math.max(0, W - outSumNow),
  });
});

// ---- Static frontend ----
app.use(express.static(path.join(__dirname, "public")));

// ---- API ----
app.get("/api/health", (req, res) => {
  res.json({ ok: true, time: nowIso() });
});

// Safe config introspection (no secrets).
// Returns only the same safe subset used for fingerprinting.
app.get("/api/config", (req, res) => {
  res.json({
    fingerprint: CFG_FINGERPRINT,
    config: CFG_PUBLIC,
  });
});

////////////////////////////////////////////////////////////////////////////////
// IDENTITY API v0 (backend-only primitives)
//
// Public:
// - GET  /api/identity/challenge   (PoW-lite challenge)
// - POST /api/identity/create      (verify PoW + create identity)
// Operator-gated (via Caddy Basic Auth OR optional OPERATOR_KEY header):
// - POST /api/identity/grant-trust (set earned/personal points; ledgered)
////////////////////////////////////////////////////////////////////////////////

// Tunables (env override if needed)
const POW_DIFFICULTY = Number(process.env.POW_DIFFICULTY ?? 3); // leading hex zeros
const POW_TTL_MS = Number(process.env.POW_TTL_MS ?? (10 * 60 * 1000)); // 10 minutes
const IDENTITY_CREATE_RL_LIMIT = Number(process.env.IDENTITY_CREATE_RL_LIMIT ?? 10); // per hour per IP
const IDENTITY_CREATE_RL_WINDOW = Number(process.env.IDENTITY_CREATE_RL_WINDOW ?? (60 * 60 * 1000));
const IDENTITY_CHALLENGE_RL_LIMIT = Number(process.env.IDENTITY_CHALLENGE_RL_LIMIT ?? 30); // per hour per IP
const IDENTITY_CHALLENGE_RL_WINDOW = Number(process.env.IDENTITY_CHALLENGE_RL_WINDOW ?? (60 * 60 * 1000));

app.get("/api/identity/challenge", (req, res) => {
  const ip = req.ip || "unknown";

  // Soft rate limit to prevent challenge spamming.
  if (rateLimitHit(`id_chal:${ip}`, IDENTITY_CHALLENGE_RL_LIMIT, IDENTITY_CHALLENGE_RL_WINDOW)) {
    return res.status(429).json({ error: "rate_limited" });
  }

  const db = loadDB();

  // Store challenges in identity.private.json's challenges[] (already present in your split DB).
  const challenge = "chal_" + crypto.randomBytes(16).toString("hex");
  const rec = {
    id: "pow_" + nanoid(10),
    challenge,
    difficulty: POW_DIFFICULTY,
    created_at: nowIso(),
    expires_at: new Date(Date.now() + POW_TTL_MS).toISOString(),
    ip,
    used: false,
  };

  db.challenges.push(rec);
  saveDB(db);

  // Client solves: find nonce where sha256(challenge + ":" + nonce) starts with N zeros.
  return res.json({
    ok: true,
    challenge,
    difficulty: POW_DIFFICULTY,
    expires_at: rec.expires_at,
  });
});

app.post("/api/identity/create", (req, res) => {
  const ip = req.ip || "unknown";

  if (rateLimitHit(`id_create:${ip}`, IDENTITY_CREATE_RL_LIMIT, IDENTITY_CREATE_RL_WINDOW)) {
    return res.status(429).json({ error: "rate_limited" });
  }

  const { challenge, nonce } = req.body || {};
  if (!challenge || nonce === undefined || nonce === null) {
    return res.status(400).json({ error: "challenge and nonce are required" });
  }

  const db = loadDB();

  // Find a live, unused challenge
  const rec = (db.challenges || []).find(c =>
    c &&
    c.challenge === String(challenge) &&
    c.used !== true &&
    c.ip === ip
  );

  if (!rec) return res.status(403).json({ error: "invalid_challenge" });

  const expMs = Date.parse(String(rec.expires_at || ""));
  if (!Number.isFinite(expMs) || Date.now() > expMs) {
    rec.used = true;
    saveDB(db);
    return res.status(403).json({ error: "challenge_expired" });
  }

  // Verify PoW
  if (!verifyPow(rec.challenge, nonce, rec.difficulty)) {
    return res.status(403).json({ error: "invalid_pow" });
  }

  // Mark challenge used (prevents replay)
  rec.used = true;
  saveDB(db);

  // Create identity
  const self_id = generateSelfId();
  const public_alias = generatePublicAlias();

  const internal_id = "id_" + nanoid(12);
  const self_id_hash = hashSelfId(self_id);

  const state = readIdentityState();

  // Defensive: ensure arrays/maps exist
  if (!Array.isArray(state.identities)) state.identities = [];
  if (!state.aliases || typeof state.aliases !== "object") state.aliases = {};
  if (!state.self_index || typeof state.self_index !== "object") state.self_index = {};

  const now = nowIso();

  state.identities.push({
    internal_id,
    self_id_hash,       // hashed at rest
    public_alias,
    display_name: null,
    earned_personal: 1, // operator grants up to 10 later
    tags: [],
    status: "ACTIVE",
    created_at: now,
    updated_at: now,
  });

  state.aliases[public_alias] = internal_id;
  state.self_index[self_id_hash] = internal_id;

  writeIdentityState(state);

  appendIdentityLedgerEvent({
    id: "evt_" + nanoid(12),
    ts: now,
    type: "IDENTITY_CREATED",
    internal_id,
    delta_weight: 1,
    meta: { by: "system", ip },
  });

  // DO NOT return internal_id.
  return res.json({ ok: true, self_id, public_alias });
});

app.post("/api/identity/grant-trust", (req, res) => {
  // v0 security:
  // Require OPERATOR_KEY and require X-Operator-Key.
  const operatorKey = process.env.OPERATOR_KEY;
  if (operatorKey) {
    const presented = req.get("X-Operator-Key");
    if (presented !== operatorKey) return res.status(401).json({ error: "unauthorized" });
  }

  // Expect an explicit personal weight change (earned trust)
  const { public_alias, weight_delta, reason } = req.body || {};

  // Validate required fields
  if (!public_alias || !Number.isFinite(Number(weight_delta))) {
    return res.status(400).json({
      error: "public_alias and weight_delta are required"
    });
  }

  const delta = Number(weight_delta);

  // Allow adjustments up or down, but require an explicit non-zero integer
  if (!Number.isInteger(delta) || delta === 0) {
    return res.status(400).json({
      error: "weight_delta must be a non-zero integer"
    });
  }

  const eventType = delta > 0 ? "EARNED_TRUST" : "TRUST_ADJUST";
  const state = readIdentityState();
  const identity = findIdentityByAlias(state, public_alias);
  if (!identity) return res.status(404).json({ error: "identity_not_found" });

  const before = clampEarnedPersonal(identity.earned_personal ?? 1);
  const after = clampEarnedPersonal(Math.max(1, before + delta));
  identity.earned_personal = after;
  identity.updated_at = nowIso();

  writeIdentityState(state);

  appendIdentityLedgerEvent({
    id: "evt_" + nanoid(12),
    ts: nowIso(),
    type: eventType,
    internal_id: identity.internal_id,
    delta_weight: delta,
    meta: {
      by: "operator",
      reason: reason ? String(reason).slice(0, 500) : "",
      applied_delta: after - before
    },
  });

  return res.json({ ok: true, new_earned_personal: after });
});

// DELEGATION API v0
//
// Auth: either
// - operator header X-Operator-Key (if OPERATOR_KEY is set), OR
// - self_id in body (delegator proves stable identity)
//
// Body uses self_id + delegatee_alias per kernel.

function isOperator(req) {
  const operatorKey = process.env.OPERATOR_KEY;
  if (!operatorKey) return false;
  const presented = req.get("X-Operator-Key");
  return presented === operatorKey;
}

function requireSelfOrOperator(req, res) {
  if (isOperator(req)) return { ok: true, by: "operator" };

  const self_id = req.body?.self_id;
  if (!self_id) {
    res.status(401).json({ error: "missing self_id" });
    return null;
  }
  return { ok: true, by: "self", self_id: String(self_id) };
}

app.post("/api/stamp", (req, res) => {
  const db = loadDB();

  let personaId = null;
  const presented = req.get(STAMP_HEADER);
  if (presented) {
    const stampRec = findStampByToken(db, presented);
    if (stampRec) personaId = stampRec.persona_id;
  }

  // ---- STAMP ISSUANCE ----
  // Uses existing Caddy Basic Auth gate (treat as a "write").
  // - If client provides a valid X-Stamp -> resolve persona, top up if below target
  // - If no/invalid stamp -> create new persona, issue target stamps
if (!personaId) {
  // Optional identity proof:
  // - If X-Self-ID is present and valid, we mint a stamp whose weight is derived from identity.
  // - If absent, we mint an anonymous stamp (weight=1).
  const selfIdRaw = req.get(SELF_ID_HEADER); // "X-Self-ID" (private secret)
  let issuedWeight = 1.0;                   // anonymous default
  let issuedTags = [];                      // snapshot tags written onto stamps
  let standardWeight = 0.0;
  let delegatedWeight = 0.0;

  if (selfIdRaw) {
    const state = readIdentityState();
    const selfHash = hashSelfId(selfIdRaw);
    const identity = findIdentityBySelfIdHash(state, selfHash);

    if (!identity) {
      // IMPORTANT: do not reveal whether a self_id exists.
      // We simply deny weighted issuance (client can retry anonymous).
      return res.status(403).json({ error: "invalid self_id" });
    }

    // Find or create a persona bound to this identity (server-only).
    const persona = findOrCreatePersonaForIdentity(db, identity.internal_id);
    personaId = persona.id;

    // Snapshot weight for this stamp issuance.
    standardWeight = computeStandardSnapshotWeightFromIdentity(state, identity);
    delegatedWeight = computeDelegatedSnapshotWeightFromIdentity(state, identity);

    // We still snapshot tags the same way
    if (Array.isArray(identity.tags)) issuedTags = identity.tags.slice(0, 50);

    // Issue stamps with explicit kinds below.
    issuedWeight = null; // keep variable but mark unused in this branch
  } else {
    // Anonymous persona (no recovery model)
    const persona = createPersona(db);
    personaId = persona.id;
    issuedWeight = 1.0;
  }

  // Issue pool with enforcement (identity persona may already have active stamps).
  // This prevents active_count from exceeding pool_max when pool_max is small.
  const active = countActiveStamps(db, personaId);
  const issued = [];

  const desired = Math.min(STAMP_POOL_TARGET, STAMP_POOL_MAX);
  const room = Math.max(0, STAMP_POOL_MAX - active);
  const need = Math.max(0, desired - active);
  const toIssue = Math.min(room, need);

  // v0 rule: if we have both weights > 0 and room for 2+, try to mint at least 1 of each.
  let wantStandard = (typeof standardWeight === "number" && standardWeight > 0);
  let wantDelegated = (typeof delegatedWeight === "number" && delegatedWeight > 0);

  let nStandard = 0;
  let nDelegated = 0;

  if (wantStandard && wantDelegated) {
    if (toIssue >= 2) {
      nStandard = 1;
      nDelegated = 1;
      // any remaining slots: bias to STANDARD (so sovereign voice is never starved)
      const remainingSlots = toIssue - 2;
      nStandard += remainingSlots;
    } else if (toIssue === 1) {
      nStandard = 1;
    }
  } else if (wantStandard) {
    nStandard = toIssue;
  } else if (wantDelegated) {
    nDelegated = toIssue;
  }

  // Mint STANDARD
  for (let i = 0; i < nStandard; i++) {
    issued.push(issueOneStamp(db, personaId, { weight: standardWeight, tags: issuedTags, kind: "STANDARD" }));
  }

  // Mint DELEGATED
  for (let i = 0; i < nDelegated; i++) {
    issued.push(issueOneStamp(db, personaId, { weight: delegatedWeight, tags: issuedTags, kind: "DELEGATED" }));
  }


  if (issued.length > 0) {
    db.events.push({
      kind: "stamp_issued",
      persona_id: personaId,
      at: nowIso(),
      count: issued.length,
      note: selfIdRaw ? "identity_weighted" : "anonymous",
      weights: { standard: standardWeight ?? null, delegated: delegatedWeight ?? null },
    });
  }

  saveDB(db);

  return res.json({
    ok: true,
    issued,
    issued_weight: null, // legacy single-field; identity issuance may mint multiple kinds
    issued_weights: { standard: standardWeight ?? null, delegated: delegatedWeight ?? null },
    issued_tags: issued.length > 0 ? issuedTags : null,
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

  // Decide weight/tags for THIS issuance (top-up is still "issuance")
  let topUpWeight = 1.0;
  let topUpTags = [];

  // If this persona is identity-bound, use identity state to snapshot the weight now.
  const personaRec = (db.personas || []).find(p => p && p.id === personaId) || null;
  const identityInternalId = personaRec?.meta?.identity_internal_id;

  if (identityInternalId) {
    const state = readIdentityState();
    const identity = findIdentityByInternalId(state, identityInternalId);

    let topUpStandardWeight = 1.0;
    let topUpDelegatedWeight = 0.0;

    if (identity) {
      topUpStandardWeight = computeStandardSnapshotWeightFromIdentity(state, identity);
      topUpDelegatedWeight = computeDelegatedSnapshotWeightFromIdentity(state, identity);

      if (Array.isArray(identity.tags)) topUpTags = identity.tags.slice(0, 50);
    }

  const wantStandard = Number.isFinite(topUpStandardWeight) && topUpStandardWeight > 0;
  const wantDelegated = Number.isFinite(topUpDelegatedWeight) && topUpDelegatedWeight > 0;

  let nStandard = 0;
  let nDelegated = 0;

  if (wantStandard && wantDelegated) {
    if (toIssue >= 2) {
      nStandard = 1;
      nDelegated = 1;
      nStandard += (toIssue - 2);
    } else if (toIssue === 1) {
      nStandard = 1;
    }
  } else if (wantStandard) {
    nStandard = toIssue;
  } else if (wantDelegated) {
    nDelegated = toIssue;
  }

  for (let i = 0; i < nStandard; i++) {
    issued.push(issueOneStamp(db, personaId, { weight: topUpStandardWeight, tags: topUpTags, kind: "STANDARD" }));
  }
  for (let i = 0; i < nDelegated; i++) {
    issued.push(issueOneStamp(db, personaId, { weight: topUpDelegatedWeight, tags: topUpTags, kind: "DELEGATED" }));
  }


  if (issued.length > 0) {
    db.events.push({ kind: "stamp_topped_up", persona_id: personaId, at: nowIso(), count: issued.length });
  }

  saveDB(db);

  return res.json({
    ok: true,
    issued,                // empty array means "you already have enough"
    issued_weight: null,
    issued_weights: { standard: topUpStandardWeight ?? null, delegated: topUpDelegatedWeight ?? null },
    issued_tags: issued.length > 0 ? topUpTags : null,
    active_count: countActiveStamps(db, personaId),
    target: STAMP_POOL_TARGET,
    max: STAMP_POOL_MAX,
  });
};

app.get("/api/polls", (req, res) => {
  const db = loadDB();
  const t = nowIso();
  let changedAny = false;

  // Apply lifecycle + snapshot persistence
  for (const p of db.polls) {
    const life = applyLifecycle(p, t);

    const usesFinalSnapshot =
      p.poll_class === "LEGITIMACY" || p.poll_class === "GOVERNANCE";

    const isLocked =
      p.status === "published" || !!p.finalized_at;

    // Persist snapshot at finalize, or backfill once if already locked
    if (usesFinalSnapshot && (life.didFinalize || isLocked) && !p.snapshot_results) {
      p.snapshot_results = computeResults(db, p.id);
      changedAny = true;
    }

    if (life.changed) changedAny = true;
  }

  if (changedAny) saveDB(db);

  // Build response using authoritative results
  const polls = db.polls
    .filter(p => isVisibleInList(p, nowIso()))
    .map(p => ({
      ...p,
      results: getAuthoritativeResults(db, p),
    }));

  res.json({ polls });
});

app.get("/api/polls/:id/results", (req, res) => {
  const pollId = req.params.id;
  const db = loadDB();

  const poll = db.polls.find(p => p.id === pollId);
  if (!poll) return res.status(404).json({ error: "poll not found" });

  const r = getAuthoritativeResults(db, poll);

  // Legacy-friendly shape + keep modern fields
  return res.json({
    poll_id: pollId,
    total_votes: r.total_votes,
    counts: r.totals,              // legacy name
    totals: r.totals,              // modern name
    people_voted: r.people_voted,
    represented_people: r.represented_people,
    weights_used: r.weights_used,
    validated: r.validated,
  });
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

  // Send initial state on connect (so UI can render immediately)
  sseSend(res, "poll", { poll });
  sseSend(res, "results", { poll_id: pollId, results: getAuthoritativeResults(db, poll) });

  // Cleanup on disconnect
  req.on("close", () => {
    const set = subscribers.get(pollId);
    if (set) {
      set.delete(res);
      if (set.size === 0) subscribers.delete(pollId);
    }
  });
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
    cooldown_seconds: req.body?.cooldown_seconds ?? null,
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

  // If present, X-Voter-Token is a poll-scoped revote capability.
  // It must ONLY be allowed to REPLACE an existing vote on the same poll.
  const presentedVoterToken = req.get(VOTER_TOKEN_HEADER);

  // Poll must exist (both first-vote and revote paths need it)
  const poll = db.polls.find(p => p.id === pollId);
  if (!poll) return res.status(404).json({ error: "poll not found" });

  // Apply lifecycle on access
  const life = applyLifecycle(poll, nowIso());
  if (life.changed) saveDB(db);

  if (!canVote(poll)) return res.status(400).json({ error: "poll is closed" });

  // ----------------------------
  // REVOTE PATH (no stamp)
  // ----------------------------
  if (presentedVoterToken) {
    const token = String(presentedVoterToken);

    // Must already have an existing vote for this poll + token.
    const prev = db.votes.find(v =>
      v.poll_id === pollId &&
      (v.persona_ballot_uid === token || v.voter_token === token)
    );

    if (!prev) {
      // Critical safety: do NOT allow X-Voter-Token to create a first vote.
      return res.status(403).json({ error: "invalid X-Voter-Token" });
    }

    // Replace vote (no amplification): remove any existing row for this token+poll, then reinsert updated record.
    db.votes = db.votes.filter(v =>
      !(v.poll_id === pollId && (v.persona_ballot_uid === token || v.voter_token === token))
    );

    db.votes.push({
      ...prev,
      option_id: String(option_id),
      updated_at: nowIso(),
      // Keep original created_at, weight, stamp_hash, issued_weight_used intact (Option A snapshot semantics)
      meta: req.body?.meta || prev.meta || {},
    });

    db.events.push({ kind: "vote_recast", poll_id: pollId, at: nowIso() });
    saveDB(db);

    const results = getAuthoritativeResults(db, poll);
    broadcast(pollId, "results", { poll_id: pollId, results });

    return res.json({ ok: true, voter_token: token, results });
  }

  // ----------------------------
  // FIRST-VOTE PATH (stamp required)
  // ----------------------------

  // ---- STAMP REQUIRED (MVP) ----
  const presentedStamp = req.get(STAMP_HEADER); // "X-Stamp"
  if (!presentedStamp) return res.status(401).json({ error: "missing X-Stamp" });

  // Stamp must exist and must be ACTIVE (findStampByToken only returns ACTIVE).
  const stampRec = findStampByToken(db, presentedStamp);
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

  // One persona -> one vote per poll (revote replaces)
  const personaId = stampRec.persona_id;
  const personaUid = personaBallotUid(db, pollId, personaId);

  const prev = db.votes.find(v =>
    v.poll_id === pollId &&
    (v.persona_ballot_uid === personaUid || v.voter_token === personaUid)
  );

  // Remove prior vote record (replacement semantics)
  db.votes = db.votes.filter(v =>
    !(v.poll_id === pollId && (v.persona_ballot_uid === personaUid || v.voter_token === personaUid))
  );

  // Persist vote record with a non-reversible stamp reference
  db.votes.push({
    id: nanoid(12),
    poll_id: pollId,
    option_id: String(option_id),

    // Stored as voter_token for backward compatibility with existing API shape.
    // Semantically this is the poll-scoped ballot uid.
    voter_token: personaUid,
    persona_ballot_uid: personaUid,

    // Authoritative stamp weight used for tally.
    weight,

    // New: audit fields (non-reversible stamp reference + explicit weight snapshot used)
    stamp_hash: String(stampRec.token_hash || ""),      // already sha256(raw_stamp_token)
    issued_weight_used: weight,

    created_at: prev ? prev.created_at : nowIso(),
    updated_at: prev ? nowIso() : null,
    meta: req.body?.meta || {},
  });

  // Consume the stamp now that it has successfully cast a vote.
  // This is what fixes pool_max=1 deadlocks (ACTIVE stamps are what count).
  consumeStampForVote(db, stampRec, pollId);

  db.events.push({ kind: "vote_cast", poll_id: pollId, at: nowIso() });
  saveDB(db);

  const results = getAuthoritativeResults(db, poll);
  broadcast(pollId, "results", { poll_id: pollId, results });

  // Return the poll-scoped voter_token so client can revote without burning a new stamp.
  return res.json({ ok: true, voter_token: personaUid, results });
});

// Legitimacy Snapshot at Close
function isLegitimacyPoll(poll) {
  // Tag-driven classification (minimal “tags”, not a full tag system)
  const tags = (poll && poll.meta && Array.isArray(poll.meta.tags)) ? poll.meta.tags : [];
  const hasLegitimacyTag = tags.includes("legitimacy");

  // If class explicitly set, honor it. Otherwise infer from tag.
  const cls = poll && poll.poll_class;
  if (cls === "LEGITIMACY") return true;

  // Back-compat: if you still have GOV polls in test data, you can optionally count them here.
  // If you do NOT want that, delete the next line.
  if (cls === "GOVERNANCE") return true;

  return !cls && hasLegitimacyTag;
}

function isLockedLegitimacy(poll) {
  // “Lock moment” for this phase: finalized_at timestamp (and published_at is effectively same tick today)
  return Boolean(poll && (poll.finalized_at || poll.published_at) && (poll.status === "finalized" || poll.status === "published"));
}

/**
 * Returns authoritative results:
 * - live computeResults before lock
 * - snapshot_results after lock (and never drifts)
 *
 * If snapshot is missing post-lock, we compute it once and persist it (db is test junk per your note).
 */
function getAuthoritativeResults(db, poll) {
  if (!poll) return { totals: {}, total_votes: 0 };

  if (isLegitimacyPoll(poll) && isLockedLegitimacy(poll)) {
    if (poll.snapshot_results) return poll.snapshot_results;

    // Fallback: create snapshot if for some reason it wasn't persisted at lock time.
    const snap = computeResults(db, poll.id);
    poll.snapshot_results = snap;
    return snap;
  }

  return computeResults(db, poll.id);
}

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
    people_voted: new Set(
      votes.map(v => v.persona_ballot_uid || v.voter_token).filter(Boolean)
    ).size,       // one stored vote per ballotUid (unique stamp per poll)
    represented_people: wSum,          // sum of weights
    weights_used: { min: wMin, max: wMax, sum: wSum, count: wCount },

    validated: true,
  };
}

// IMPORTANT: stamp remains authoritative, so this is a snapshot at issuance.
  // - Identity-based stamps must not mint with weight < 1.
function computeStandardSnapshotWeightFromIdentity(state, identityRec) {
  // Standard weight is what the identity can personally spend after delegating out.
  const earned = clampEarnedPersonal(identityRec?.earned_personal ?? identityRec?.weight ?? 0);
  const out = sumActiveDelegationsOut(String(identityRec?.internal_id || ""));
  const remaining = earned - out;

  return Math.max(0, Number(remaining) || 0);
}

function computeDelegatedSnapshotWeightFromIdentity(state, identityRec) {
  const inbound = computeDelegatedInWeight(state, identityRec?.internal_id);
  return Math.max(0, Number(inbound) || 0);
}

// ---- Persona binding (identity -> persona is internal only) ----
function findOrCreatePersonaForIdentity(db, identityInternalId) {
  // We keep persona internal; client never sees persona IDs.
  // We store linkage on persona.meta.identity_internal_id (server-only).
  const existing = (db.personas || []).find(p => p?.meta?.identity_internal_id === identityInternalId);
  if (existing) return existing;

  const persona = createPersona(db);
  if (!persona.meta || typeof persona.meta !== "object") persona.meta = {};
  persona.meta.identity_internal_id = identityInternalId;
  return persona;
}

// ---- Stamp consumption on vote (capability lifecycle) ----
// - It produces an audit trail (identity.ledger.json) without storing raw tokens
function consumeStampForVote(db, stampRec, pollId) {
  if (!db || !stampRec) return;

  // Only ACTIVE stamps can be consumed. If it's already USED/EXPIRED/etc, do nothing.
  if (stampRec.status !== "ACTIVE") return;

  const at = nowIso();

  // Transition: ACTIVE -> USED
  stampRec.status = "USED";
  stampRec.used_at = at;

  // Keep existing housekeeping fields consistent
  stampRec.last_used_at = at;
  stampRec.use_count = (Number(stampRec.use_count) || 0) + 1;

  // Exchange event log (private exchange file)
  if (Array.isArray(db.events)) {
    db.events.push({
      kind: "stamp_used",
      poll_id: String(pollId),
      stamp_id: String(stampRec.id),
      at,
      reason: "vote",
    });
  }

  // Identity ledger (append-only audit log)
  // NOTE: This is operator-readable. We can include persona_id server-side for accountability.
  appendIdentityLedgerEvent({
    type: "STAMP_USED",
    at,
    poll_id: String(pollId),
    stamp_id: String(stampRec.id),
    persona_id: String(stampRec.persona_id || ""),
    stamp_hash_prefix: String(stampRec.token_hash || "").slice(0, 12),
    reason: "vote",
  });
}
});

// ---- Simple in-memory rate limit (resets on restart; good enough for MVP) ----
const _rl = new Map(); // key -> { count, resetAtMs }

function rateLimitHit(key, limit, windowMs) {
  const now = Date.now();
  const rec = _rl.get(key);
  if (!rec || now >= rec.resetAtMs) {
    _rl.set(key, { count: 1, resetAtMs: now + windowMs });
    return false; // not limited
  }
  rec.count += 1;
  return rec.count > limit;
}

// ---- PoW-lite (Hashcash-style) ----
// We use "leading hex zeros" as the difficulty measure.
// Example difficulty=3 => hash must start with "000" (roughly 4096 trials on average).
function powHash(challenge, nonce) {
  return crypto
    .createHash("sha256")
    .update(`${String(challenge)}:${String(nonce)}`, "utf8")
    .digest("hex");
}

function verifyPow(challenge, nonce, difficulty) {
  const d = Number(difficulty);
  if (!Number.isFinite(d) || d < 0 || d > 10) return false; // sanity cap
  const h = powHash(challenge, nonce);
  return h.startsWith("0".repeat(d));
}

// Helper to generate safe random tokens for self_id
function generateSelfId() {
  // Long-lived secret the user stores.
  return "self_" + crypto.randomBytes(24).toString("hex");
}

function generatePublicAlias() {
  // Rotatable public handle.
  return "a_" + nanoid(12);
}

// Log once at startup for “what config is live?” debugging
console.log(`[config] fingerprint sha256=${CFG_FINGERPRINT}`);

const PORT = process.env.PORT || 8787;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Bread Exchange MVP running on http://localhost:${PORT}`);
});