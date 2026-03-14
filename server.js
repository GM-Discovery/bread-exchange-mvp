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
 *   
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
// Hash helper for string-based IDs (ballot IDs, salts, etc.)
function sha256HexString(s) {
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
  return sha256HexString(`${personaId}:${pollId}:${salt}`);
}

const app = express();
app.set("trust proxy", 1);

// CORS FIRST
app.use(cors({
  origin: true, // reflect origin
  credentials: false,
}));

// PRE-FLIGHT MUST ALWAYS SUCCEED
app.options("*", cors());

// THEN body parsing
app.use(express.json({
  limit: "1mb",
  // Capture the raw request body so HMAC signing can hash exact bytes.
  verify: (req, res, buf) => {
    req.rawBody = buf; // Buffer
  },
}));

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
      governance_cooldown_seconds: 3 * 24 * 60 * 60,
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

// ============================================================================
// HMAC signed-request helpers (v0)
// - Used later to protect sensitive endpoints
// - Replay defense: timestamp window + nonce uniqueness per identity
// ============================================================================

const SIGN_SKEW_MS = 5 * 60 * 1000; // 5 minutes in milliseconds

// In-memory replay cache:
// Map<self_id_hash, Map<nonce, expiresAtMs>>
const seenNoncesBySelf = new Map();

function nowMs() {
  return Date.now();
}

// Hash raw request bodies (Buffer or string)
function sha256HexRaw(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

// Compute HMAC-SHA256 (hex) from a hex key + string data
function hmacSha256Hex(keyHex, dataStr) {
  const keyBuf = Buffer.from(String(keyHex || ""), "hex");
  return crypto.createHmac("sha256", keyBuf).update(dataStr).digest("hex");
}

// Remove expired nonces so memory does not grow forever
function cleanupNonceCache() {
  const t = nowMs();
  for (const [selfHash, nonceMap] of seenNoncesBySelf.entries()) {
    for (const [nonce, expiresAt] of nonceMap.entries()) {
      if (expiresAt <= t) nonceMap.delete(nonce);
    }
    if (nonceMap.size === 0) seenNoncesBySelf.delete(selfHash);
  }
}

// Remember a nonce or reject if already seen
function rememberNonceOrReject(selfHash, nonce, tsMs) {
  cleanupNonceCache();

  const expiresAt = tsMs + SIGN_SKEW_MS;
  let nonceMap = seenNoncesBySelf.get(selfHash);
  if (!nonceMap) {
    nonceMap = new Map();
    seenNoncesBySelf.set(selfHash, nonceMap);
  }

  if (nonceMap.has(nonce)) {
    return { ok: false, reason: "replay" };
  }

  nonceMap.set(nonce, expiresAt);
  return { ok: true };
}

// ============================================================================
// Identity signing-key private store
// - Separate from identity.state.json
// - Keys are indexed by self_id_hash (never plaintext self_id)
// ============================================================================

function readSigningStore() {
  try {
    if (!fs.existsSync(IDENTITY_SIGNING_DB_PATH)) {
      return { keys: {} };
    }
    return JSON.parse(fs.readFileSync(IDENTITY_SIGNING_DB_PATH, "utf8"));
  } catch (e) {
    console.error("Failed to read signing key store:", e);
    return { keys: {} };
  }
}

function writeSigningStore(db) {
  fs.mkdirSync(path.dirname(IDENTITY_SIGNING_DB_PATH), { recursive: true });
  fs.writeFileSync(
    IDENTITY_SIGNING_DB_PATH,
    JSON.stringify(db, null, 2),
    "utf8"
  );
}

// Save or replace signing key for an identity
function upsertSigningKey(selfIdHash, internalId, signingKeyHex) {
  const db = readSigningStore();
  if (!db.keys) db.keys = {};

  db.keys[selfIdHash] = {
    internal_id: internalId,
    signing_key: signingKeyHex,
    created_at: new Date().toISOString(),
  };

  writeSigningStore(db);
}

// Look up signing key by self_id_hash
function getSigningKeyBySelfHash(selfIdHash) {
  const db = readSigningStore();
  return db?.keys?.[selfIdHash]?.signing_key || null;
}

// ============================================================================
// HMAC signature verification middleware
// ============================================================================

function requireSignature(req, res, next) {
  try {
    const selfId = req.get(SELF_ID_HEADER);
    const sig = req.get("X-Signature");
    const tsRaw = req.get("X-Timestamp");
    const nonce = req.get("X-Nonce");

    if (!selfId || !sig || !tsRaw || !nonce) {
      return res.status(401).json({ error: "missing_signature_headers" });
    }

    const tsMs = Number(tsRaw);
    if (!Number.isFinite(tsMs)) {
      return res.status(401).json({ error: "invalid_timestamp" });
    }

    const now = nowMs();
    if (Math.abs(now - tsMs) > SIGN_SKEW_MS) {
      return res.status(401).json({ error: "timestamp_out_of_window" });
    }

    const selfIdHash = hashSelfId(selfId);
    const signingKey = getSigningKeyBySelfHash(selfIdHash);
    if (!signingKey) {
      return res.status(403).json({ error: "unknown_identity" });
    }

    const replay = rememberNonceOrReject(selfIdHash, nonce, tsMs);
    if (!replay.ok) {
      return res.status(403).json({ error: "replay_detected" });
    }

    // Hash the raw request body exactly as received
    const bodyHash = sha256HexRaw(req.rawBody || "");

    // Use full URL including query string
    const base = [
      req.method.toUpperCase(),
      req.originalUrl,
      tsRaw,
      nonce,
      bodyHash,
    ].join("\n");

    const expected = hmacSha256Hex(signingKey, base);

    if (expected !== String(sig)) {
      return res.status(401).json({ error: "bad_signature" });
    }

    // Attach verified identity info for downstream handlers
    req.auth = {
      self_id: selfId,
      self_id_hash: selfIdHash,
    };

    return next();
  } catch (err) {
    console.error("Signature verification error:", err);
    return res.status(500).json({ error: "signature_verification_failed" });
  }
}

// ============================================================================
// Operator key middleware (fail-closed)
// ============================================================================

function requireOperatorKey(req, res, next) {
  const expected = process.env.OPERATOR_KEY;

  // FAIL-CLOSED: if missing, disable this endpoint entirely
  if (!expected) {
    console.error("[SECURITY] OPERATOR_KEY missing; /api/identity/grant-trust disabled (fail-closed).");
    return res.status(503).json({ error: "operator_key_missing" });
  }

  const got = req.get("X-Operator-Key");
  if (!got || String(got) !== String(expected)) {
    return res.status(403).json({ error: "bad_operator_key" });
  }

  return next();
}

// =========================================================================
// Operator-only route mounting (fail-closed at registration time)
// =========================================================================
//
// If OPERATOR_KEY is missing at startup, we still register the route,
// but it becomes a stub that returns 503. This makes “operator endpoints
// accidentally exposed if env var missing” impossible.
//
// IMPORTANT: This is evaluated at process start. If you set OPERATOR_KEY later,
// you must restart the container/server to enable operator endpoints.

function mountOperatorRoute(method, routePath, ...handlers) {
  const m = String(method || "").toLowerCase();
  if (typeof app[m] !== "function") {
    throw new Error(`mountOperatorRoute: unsupported method: ${method}`);
  }

  if (!process.env.OPERATOR_KEY) {
    console.error(`[SECURITY] OPERATOR_KEY missing; ${method.toUpperCase()} ${routePath} disabled (fail-closed).`);
    return app[m](routePath, (req, res) => res.status(503).json({ error: "operator_key_missing" }));
  }

  return app[m](routePath, ...handlers);
}

const cfg = loadConfig();
// Load lifecycle as an object so we can call lifecycle.setDefaults(...)
const lifecycle = require("./lib/lifecycle");
const federation = require("./lib/federation");
const { applyLifecycle, canVote, isVisibleInList, nowIso } = lifecycle;

// --- Canonical JSON + hashing (for commitments) ---
// We use deterministic JSON serialization to produce stable hashes.
// This is NOT meant to be fast; it's meant to be predictable.
function canonicalJsonStringify(value) {
  function sortObject(obj) {
    if (obj === null || obj === undefined) return obj;
    if (Array.isArray(obj)) return obj.map(sortObject);
    if (typeof obj !== "object") return obj;

    const keys = Object.keys(obj).sort();
    const out = {};
    for (const k of keys) out[k] = sortObject(obj[k]);
    return out;
  }
  return JSON.stringify(sortObject(value));
}

function sha256Hex(s) {
  return crypto.createHash("sha256").update(String(s), "utf8").digest("hex");
}

// --- Delegation chain resolver (deterministic single-path) ---
// For v0 represented-map snapshotting, we resolve a single "effective rep" by:
// - taking the ACTIVE outbound delegation edge with the largest amount
// - following that edge recursively until no outbound edge exists
// - if a cycle is detected, we stop at the last safe node and flag it
function resolveEffectiveRepresentativeInternalId(state, originInternalId) {
  const d = readDelegations();
  const rows = Array.isArray(d.delegations) ? d.delegations : [];

  const seen = new Set();
  let cur = String(originInternalId || "");
  let chainLen = 0;
  const flags = {};

  while (cur && !seen.has(cur)) {
    seen.add(cur);

    // Find strongest ACTIVE outbound edge
    let best = null;
    for (const r of rows) {
      if (!r) continue;
      if (r.status !== "ACTIVE") continue;
      if (String(r.delegator_internal_id) !== cur) continue;
      const amt = Number(r.amount);
      if (!Number.isFinite(amt) || amt <= 0) continue;

      if (!best) {
        best = { delegatee_internal_id: String(r.delegatee_internal_id), amount: amt };
        continue;
      }

      // Prefer larger amount; tie-break lexicographically for determinism
      if (amt > best.amount) {
        best = { delegatee_internal_id: String(r.delegatee_internal_id), amount: amt };
      } else if (amt === best.amount) {
        const a = String(r.delegatee_internal_id);
        const b = String(best.delegatee_internal_id);
        if (a < b) best = { delegatee_internal_id: a, amount: amt };
      }
    }

    if (!best || !best.delegatee_internal_id) break;

    cur = best.delegatee_internal_id;
    chainLen += 1;
  }

  if (seen.has(cur) && chainLen > 0) {
    flags.cycle = true;
  }

  return { effective_internal_id: cur || String(originInternalId || ""), chain_len: chainLen, flags };
}

function computePollFingerprint(p) {
  // Fingerprint the poll *definition* (what it is), not its lifecycle timestamps.
  // Keep stable + deterministic. No created_at/closed_at/finalized_at/published_at/ts.
  const def = {
    id: String(p.id || ""),
    poll_class: p.poll_class != null ? String(p.poll_class) : null,
    type: p.type != null ? String(p.type) : null,
    title: p.title != null ? String(p.title) : null,
    description: p.description != null ? String(p.description) : null,

    // Preserve option order. Each option’s identity + display label matter.
    options: Array.isArray(p.options)
      ? p.options.map(o => ({
          option_id: String((o && (o.option_id || o.id)) || ""),
          label: o && o.label != null
            ? String(o.label)
            : (o && o.text != null ? String(o.text) : null),
        }))
      : null,

    // Meta can affect meaning; include it canonically if present.
    meta: (p && p.meta && typeof p.meta === "object") ? p.meta : null,
  };

  return sha256Hex(canonicalJsonStringify(def));
}

// Compute + persist represented_map on FIRST close.
// Returns { ok, represented_map, represented_map_hash } or null if not applicable.
function computeRepresentedMapSnapshotIfNeeded(db, poll) {
  if (!db || !poll) return null;

  // Only run once per poll.
  if (poll.represented_map && poll.represented_map_hash) return null;

  const tClose = poll.closed_at ? String(poll.closed_at) : nowIso();

  // Origin set: voters-only, derived from vote records.
  const votes = (db.votes || []).filter(v => v && v.poll_id === poll.id);

  const state = readIdentityState();

  // Build entries keyed by origin public_alias.
  // We skip votes that don't carry persona_id (older data).
  const entries = [];

  for (const v of votes) {
    const personaId = v.persona_id ? String(v.persona_id) : "";
    if (!personaId) continue;

    const persona = (db.personas || []).find(p => p && String(p.id) === personaId) || null;
    const originInternalId = persona?.meta?.identity_internal_id ? String(persona.meta.identity_internal_id) : "";
    if (!originInternalId) continue;

    const originIdentity = findIdentityByInternalId(state, originInternalId);
    const originAlias = originIdentity ? String(originIdentity.public_alias || "") : "";
    if (!originAlias) continue;

    const rep = resolveEffectiveRepresentativeInternalId(state, originInternalId);
    const repIdentity = findIdentityByInternalId(state, rep.effective_internal_id);
    const repAlias = repIdentity ? String(repIdentity.public_alias || "") : originAlias;

    // voters-only => origin voted, so represented option is origin's option.
    const representedOptionId = v.option_id !== undefined ? String(v.option_id) : null;

    entries.push({
      origin_key: originAlias,
      effective_rep_key: repAlias,
      represented_option_id: representedOptionId,
      chain_len: rep.chain_len,
      flags: rep.flags && Object.keys(rep.flags).length ? rep.flags : {},
    });
  }

  // Deterministic ordering:
  entries.sort((a, b) => (a.origin_key < b.origin_key ? -1 : (a.origin_key > b.origin_key ? 1 : 0)));

  const canonical = canonicalJsonStringify(entries);
  const h = sha256Hex(canonical);

  poll.t_close = poll.t_close || tClose;
  poll.represented_map = entries;
  poll.represented_map_hash = h;

  return { ok: true, represented_map: entries, represented_map_hash: h };
}


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

// Federation v0 (partner-allowlisted commitments + dispute artifacts)
// - Uses Ed25519 signatures (separate from HMAC client auth)
// - Stores private federation identity and partner allowlist in DATA_DIR
try {
  federation.installFederationRoutes(app, { loadDB });
} catch (e) {
  console.error("[federation] failed to install federation routes:", e);
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

  // Never mint unusable stamps (vote path rejects weight < 1).
  const w = Number(options.weight);
  if (!Number.isFinite(w) || w < 1) return null;

  const rec = {
    id: "st_" + nanoid(12),
    persona_id: personaId,
    token_hash: hashStampToken(token),
    status: "ACTIVE",
    issued_at: nowIso(),
    use_count: 0,
    last_used_at: null,

    // Preserve declared kind (STANDARD / DELEGATED / COMBINED). Default to STANDARD.
    kind: (typeof options.kind === "string" && options.kind) ? options.kind : "STANDARD",

    // Store the validated numeric weight.
    weight: w,

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
const IDENTITY_SIGNING_DB_PATH = path.join(DATA_DIR, "identity.signing.private.json");
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

  const exchange = readJsonOrInit(EXCHANGE_DB_PATH, { polls: [], votes: [], events: [], overrides: [] });
  const identity = readJsonOrInit(IDENTITY_DB_PATH, { personas: [], stamps: [], keys: [], challenges: [] });

  // Backfill new arrays if someone hand-edited files
  if (!Array.isArray(exchange.polls)) exchange.polls = [];
  if (!Array.isArray(exchange.votes)) exchange.votes = [];
  if (!Array.isArray(exchange.events)) exchange.events = [];
  if (!Array.isArray(exchange.overrides)) exchange.overrides = [];

  if (!Array.isArray(identity.personas)) identity.personas = [];
  if (!Array.isArray(identity.stamps)) identity.stamps = [];
  if (!Array.isArray(identity.keys)) identity.keys = [];
  if (!Array.isArray(identity.challenges)) identity.challenges = [];

  // Merge for existing code compatibility
  return {
    polls: exchange.polls,
    votes: exchange.votes,
    events: exchange.events,
    overrides: exchange.overrides,

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
    overrides: Array.isArray(db.overrides) ? db.overrides : [],
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

// POST /api/delegation/revoke
// Body:
//   - self_id (delegator) OR (operator) delegator_alias
//   - delegatee_alias
app.post("/api/delegation/revoke", requireSignature, (req, res) => {
  const { delegatee_alias } = req.body || {};
  if (!delegatee_alias) return res.status(400).json({ error: "delegatee_alias is required" });

  const state = readIdentityState();
  const resolved = resolveDelegatorIdentity(state, req, res);
  if (!resolved) return;

  const delegator = resolved.delegator;
  const by = resolved.by;

  const delegatee = findIdentityByAlias(state, String(delegatee_alias));
  if (!delegatee) return res.status(404).json({ error: "delegatee_not_found" });

  // Disallow self-delegation (delegator -> same identity)
  if (delegatee && delegator && String(delegatee.internal_id) === String(delegator.internal_id)) {
    return res.status(400).json({ error: "self_delegation_not_allowed" });
  }

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
app.post("/api/delegation/set", requireSignature, (req, res) => {
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

  // Disallow self-delegation (delegator and delegatee are the same identity)
  if (delegatee && delegator && String(delegatee.internal_id) === String(delegator.internal_id)) {
    return res.status(400).json({ error: "self_delegation_not_allowed" });
  }

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

  // Budget enforcement (v0): STANDARD delegation only.
  // - This route represents "I delegate some of MY standard points to an expert."
  // - Budget is earned_personal only (NOT earned + inbound).
  // TODO (Pass-through lifecycle): delegated/inbound pool should be routed via a separate
  // PASS_THROUGH primitive (all-or-none), not by increasing the budget here.
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
      weight: W, // earned_personal budget (standard-only)
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

// GET /api/delegation/outbound
// Auth: signed (HMAC) only.
// Returns ACTIVE outbound delegations for the caller identity (no internal ids).
app.get("/api/delegation/outbound", requireSignature, (req, res) => {
  try {
    const state = readIdentityState();

    // req.auth is set by requireSignature
    const selfHash = String(req.auth?.self_id_hash || "");
    const identity = findIdentityBySelfIdHash(state, selfHash);
    if (!identity) return res.status(403).json({ error: "unknown_identity" });

    const delegatorInternalId = String(identity.internal_id || "");

    const d = readDelegations();
    const rows = Array.isArray(d.delegations) ? d.delegations : [];

    // Derive an informational expiry timestamp (not yet enforced).
    // v0 aspiration: a delegation expires 1 year after created_at.
    function deriveExpiresAt(createdAtIso) {
      const t = Date.parse(String(createdAtIso || ""));
      if (!Number.isFinite(t)) return null;
      const oneYearMs = 365 * 24 * 60 * 60 * 1000;
      return new Date(t + oneYearMs).toISOString();
    }

    const outbound = [];
    for (const r of rows) {
      if (!r) continue;
      if (r.status !== "ACTIVE") continue;
      if (String(r.delegator_internal_id || "") !== delegatorInternalId) continue;

      const amt = Number(r.amount);
      if (!Number.isFinite(amt) || amt <= 0) continue;

      const delegatee = findIdentityByInternalId(state, String(r.delegatee_internal_id || ""));
      outbound.push({
        delegatee_alias: delegatee?.public_alias ? String(delegatee.public_alias) : null,
        amount: amt,
        status: "ACTIVE",
        created_at: r.created_at || null,
        updated_at: r.updated_at || null,
        expires_at: deriveExpiresAt(r.created_at),
      });
    }

    // Newest-first (updated_at, then created_at)
    outbound.sort((a, b) => {
      const ta = Date.parse(String(a.updated_at || a.created_at || "")) || 0;
      const tb = Date.parse(String(b.updated_at || b.created_at || "")) || 0;
      return tb - ta;
    });

    // Guardrail cap for UI legibility
    const cap = 200;

    return res.json({ ok: true, outbound: outbound.slice(0, cap), cap });
  } catch (e) {
    console.error("/api/delegation/outbound failed:", e);
    return res.status(500).json({ error: "outbound_failed" });
  }
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

  // Generate a signing key for HMAC request authentication.
  // This is returned ONCE to the client and stored privately.
  const signing_key = crypto.randomBytes(32).toString("hex");
  upsertSigningKey(self_id_hash, internal_id, signing_key);

  // DO NOT return internal_id.
  return res.json({
    ok: true,
    self_id,
    signing_key,
    public_alias,
  });
});

mountOperatorRoute("post", "/api/identity/grant-trust", requireSignature, requireOperatorKey, (req, res) => {  // v0 security:
  // Require OPERATOR_KEY and require X-Operator-Key.

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

// GET /api/identity/summary (signed)
// Truthful trust visibility for the current identity (no internal identifiers).
// Response fields are safe for UI display.
app.get("/api/identity/summary", requireSignature, (req, res) => {
  try {
    const selfHash = req?.auth?.self_id_hash;
    if (!selfHash) return res.status(401).json({ error: "missing_identity" });

    const state = readIdentityState();
    const identity = findIdentityBySelfIdHash(state, String(selfHash));
    if (!identity) return res.status(404).json({ error: "identity_not_found" });

    const earned = clampEarnedPersonal(identity?.earned_personal ?? identity?.weight ?? 0);
    const internalId = String(identity?.internal_id || "");

    // ACTIVE delegation sums
    const inbound = Number(sumActiveDelegationsIn(internalId)) || 0;
    const outbound = Number(sumActiveDelegationsOut(internalId)) || 0;

    // Available pools (waterfall semantics already encoded in these helpers)
    const standard_available = Number(computeStandardSnapshotWeightFromIdentity(state, identity)) || 0;
    const delegated_available = Number(computeDelegatedSnapshotWeightFromIdentity(state, identity)) || 0;
    const combined_available = Math.max(0, standard_available) + Math.max(0, delegated_available);

    return res.json({
      ok: true,
      public_alias: String(identity?.public_alias || ""),
      earned_personal: earned,
      inbound_delegated: Math.max(0, inbound),
      outbound_delegated: Math.max(0, outbound),
      standard_available: Math.max(0, standard_available),
      delegated_available: Math.max(0, delegated_available),
      combined_available: Math.max(0, combined_available),
    });
  } catch (e) {
    console.error("/api/identity/summary failed:", e);
    return res.status(500).json({ error: "summary_failed" });
  }
});

// Auto-update checker API
app.get("/api/update-available", (req, res) => {
  const fs = require("fs");
  const path = require("path");
  const flagPath = path.join(__dirname, "data", "update-available");
  try {
    const tag = fs.readFileSync(flagPath, "utf8").trim();
    if (tag) return res.json({ available: true, tag });
  } catch {}
  res.json({ available: false });
});

// DELEGATION API v0
//
// Auth: either
// - operator header X-Operator-Key (if OPERATOR_KEY is set), OR
// - self_id in body (delegator proves stable identity)
//
// Body uses self_id + delegatee_alias per kernel.

function requireSelfOrOperator(req, res) {
  if (isOperator(req)) return { ok: true, by: "operator" };

  const self_id = req.body?.self_id;
  if (!self_id) {
    res.status(401).json({ error: "missing self_id" });
    return null;
  }
  return { ok: true, by: "self", self_id: String(self_id) };
}

app.post("/api/stamp", requireSignature, (req, res) => {
  const db = loadDB();

  // Try to resolve persona from an ACTIVE presented stamp (optional)
  let personaId = null;
  const presented = req.get(STAMP_HEADER);
  if (presented) {
    const stampRec = findStampByToken(db, presented);
    if (stampRec) personaId = stampRec.persona_id;
  }

  // Helper: mint stamps into a persona up to target (bounded by max)
  function mintUpToTarget({ personaId, standardWeight, delegatedWeight, tags, note }) {
    const active = countActiveStamps(db, personaId);
    const desired = Math.min(STAMP_POOL_TARGET, STAMP_POOL_MAX);
    const room = Math.max(0, STAMP_POOL_MAX - active);
    const need = Math.max(0, desired - active);
    const toIssue = Math.min(room, need);

    const issued = [];

    const wantStandard = Number.isFinite(Number(standardWeight)) && Number(standardWeight) > 0;
    const wantDelegated = Number.isFinite(Number(delegatedWeight)) && Number(delegatedWeight) > 0;

    let nStandard = 0;
    let nDelegated = 0;

    if (wantStandard && wantDelegated) {
      if (toIssue >= 2) {
        // ensure at least one of each, bias remaining to STANDARD
        nStandard = 1 + (toIssue - 2);
        nDelegated = 1;
      } else if (toIssue === 1) {
        // only room for one: mint combined so delegated isn't stranded
        nStandard = 1;
        nDelegated = 1;
      }
    } else if (wantStandard) {
      nStandard = toIssue;
    } else if (wantDelegated) {
      nDelegated = toIssue;
    }

    // If both are requested, mint a single COMBINED stamp instead (vote path spends one stamp)
    if (nStandard > 0 && nDelegated > 0) {
      const combined = Number(standardWeight) + Number(delegatedWeight);
      const t = issueOneStamp(db, personaId, { weight: combined, tags, kind: "COMBINED" });
      if (t) issued.push(t);
      nStandard = 0;
      nDelegated = 0;
    }

    for (let i = 0; i < nStandard; i++) {
      const t = issueOneStamp(db, personaId, { weight: Number(standardWeight), tags, kind: "STANDARD" });
      if (t) issued.push(t);
    }

    for (let i = 0; i < nDelegated; i++) {
      const t = issueOneStamp(db, personaId, { weight: Number(delegatedWeight), tags, kind: "DELEGATED" });
      if (t) issued.push(t);
    }

    if (issued.length > 0) {
      db.events.push({
        kind: note || "stamp_issued",
        persona_id: personaId,
        at: nowIso(),
        count: issued.length,
        weights: {
          standard: wantStandard ? Number(standardWeight) : null,
          delegated: wantDelegated ? Number(delegatedWeight) : null,
        },
      });
    }

    return {
      issued,
      active_count: countActiveStamps(db, personaId),
      target: STAMP_POOL_TARGET,
      max: STAMP_POOL_MAX,
      issued_weights: {
        standard: wantStandard ? Number(standardWeight) : null,
        delegated: wantDelegated ? Number(delegatedWeight) : null,
      },
      issued_weight_combined:
        wantStandard && wantDelegated ? (Number(standardWeight) + Number(delegatedWeight)) : null,
    };
  }

  // ==========================
  // If no persona yet: create/bind and issue initial pool
  // ==========================
  if (!personaId) {
    const selfIdRaw = req.get(SELF_ID_HEADER); // optional (identity-weighted issuance)

    let standardWeight = 1.0;
    let delegatedWeight = 0.0;
    let issuedTags = [];
    let note = "anonymous";

    if (selfIdRaw) {
      const state = readIdentityState();
      const selfHash = hashSelfId(selfIdRaw);
      const identity = findIdentityBySelfIdHash(state, selfHash);

      if (!identity) {
        // Do not reveal whether self_id exists; just deny weighted issuance.
        return res.status(403).json({ error: "invalid self_id" });
      }

      const persona = findOrCreatePersonaForIdentity(db, identity.internal_id);
      personaId = persona.id;

      standardWeight = computeStandardSnapshotWeightFromIdentity(state, identity);
      delegatedWeight = computeDelegatedSnapshotWeightFromIdentity(state, identity);

      if (Array.isArray(identity.tags)) issuedTags = identity.tags.slice(0, 50);
      note = "identity_weighted";
    } else {
      const persona = createPersona(db);
      personaId = persona.id;
      // keep default weights/tags
    }

    const minted = mintUpToTarget({
      personaId,
      standardWeight,
      delegatedWeight,
      tags: issuedTags,
      note: "stamp_issued",
    });

    saveDB(db);

    return res.json({
      ok: true,
      persona_id: personaId,
      issued: minted.issued,
      issued_weight: null, // legacy field (unused now)
      issued_weights: minted.issued_weights,
      issued_weight_combined: minted.issued_weight_combined,
      issued_tags: minted.issued.length > 0 ? issuedTags : null,
      active_count: minted.active_count,
      target: minted.target,
      max: minted.max,
    });
  }

  // ==========================
  // Persona exists: top-up (respect pool_target/pool_max)
  // ==========================
  let topUpStandardWeight = 1.0;
  let topUpDelegatedWeight = 0.0;
  let topUpTags = [];

  const personaRec = (db.personas || []).find(p => p && p.id === personaId) || null;
  const identityInternalId = personaRec?.meta?.identity_internal_id;

  if (identityInternalId) {
    const state = readIdentityState();
    const identity = findIdentityByInternalId(state, identityInternalId);
    if (identity) {
      topUpStandardWeight = computeStandardSnapshotWeightFromIdentity(state, identity);
      topUpDelegatedWeight = computeDelegatedSnapshotWeightFromIdentity(state, identity);
      if (Array.isArray(identity.tags)) topUpTags = identity.tags.slice(0, 50);
    }
  }

  const minted = mintUpToTarget({
    personaId,
    standardWeight: topUpStandardWeight,
    delegatedWeight: topUpDelegatedWeight,
    tags: topUpTags,
    note: "stamp_topped_up",
  });

  saveDB(db);

  return res.json({
    ok: true,
    persona_id: personaId,
    issued: minted.issued,
    issued_weight: null,
    issued_weights: minted.issued_weights,
    issued_weight_combined: minted.issued_weight_combined,
    issued_tags: minted.issued.length > 0 ? topUpTags : null,
    active_count: minted.active_count,
    target: minted.target,
    max: minted.max,
  });
});

app.get("/api/polls", (req, res) => {
  const db = loadDB();
  const t = nowIso();
  let changedAny = false;

  // Apply lifecycle + snapshot persistence
  for (const p of db.polls) {
    const prevClosedAt = p.closed_at ? String(p.closed_at) : null;

    const life = applyLifecycle(p, t);

    // If this tick caused the FIRST close, persist represented_map snapshot (voters-only).
    // We key off closed_at becoming non-null (works even if GOV immediately enters cooldown).
    if (!prevClosedAt && p.closed_at) {
      const snap = computeRepresentedMapSnapshotIfNeeded(db, p);
      if (snap) changedAny = true;
    }

    const usesFinalSnapshot =
      p.poll_class === "LEGITIMACY" || p.poll_class === "GOVERNANCE";

    const isLocked =
      p.status === "published" || !!p.finalized_at;

    // Persist snapshot at finalize, or backfill once if already locked
    if (usesFinalSnapshot && (life.didFinalize || isLocked) && !p.snapshot_results) {
      p.snapshot_results = computeResults(db, p.id);

      // Commitment for the final tally (based on canonical totals)
      try {
        const canonicalTotals = canonicalJsonStringify(p.snapshot_results?.totals || {});
        p.final_tally_hash = sha256Hex(canonicalTotals);
      } catch (_) {
        // fail-closed: don't block poll listing
      }

      // Poll definition fingerprint (canonical, meaning-bearing)
      try {
        // Ensure poll_fingerprint exists (definition-level)
        if (!p.poll_fingerprint) {
          try {
            p.poll_fingerprint = computePollFingerprint(p);
            changedAny = true; // <-- REQUIRED so saveDB(db) happens
          } catch (_) {
            // fail-closed
          }
        }
      } catch (_) {
        // fail-closed: don't block poll listing
      }

      // -------------------------------
      // Federation commitment injection
      // -------------------------------
      try {
        // Deterministic override delta hash (content-only)
        const overridesForPoll = (db.overrides || [])
          .filter(o => o && o.poll_id === p.id)
          .map(o => ({
            voter_token: String(o.voter_token || ""),
            override_option_id: String(o.override_option_id || ""),
            override_ts: o.override_ts ? String(o.override_ts) : null
          }))
          .sort((a, b) => {
            if (a.voter_token !== b.voter_token) {
              return a.voter_token < b.voter_token ? -1 : 1;
            }
            if (a.override_ts !== b.override_ts) {
              return a.override_ts < b.override_ts ? -1 : 1;
            }
            return a.override_option_id < b.override_option_id ? -1 : 1;
          });

        const canonicalOverrides = canonicalJsonStringify(overridesForPoll);
        p.override_delta_hash = sha256Hex(canonicalOverrides);

        // Represented map hash already exists from close snapshot
        const representedMapHash = p.represented_map_hash || null;

        // Install/update federation commitment
        if (federation && typeof federation.upsertLocalCommitmentForPoll === "function") {
          federation.upsertLocalCommitmentForPoll(db, p, {
            final_tally_hash: p.final_tally_hash,
            override_delta_hash: p.override_delta_hash,
            represented_map_hash: representedMapHash,
            config_fingerprint: CFG_FINGERPRINT
          });
        }
      } catch (e) {
        console.error("[federation] commitment injection failed:", e);
      }

      changedAny = true;
    }

    // -----------------------------------------------
    // Federation commitment backfill for already-locked polls
    // (If snapshot_results already existed before federation landed)
    // -----------------------------------------------
    if (usesFinalSnapshot && (life.didFinalize || isLocked) && p.snapshot_results) {
      try {
        // Ensure final_tally_hash exists
        if (!p.final_tally_hash) {
          const canonicalTotals = canonicalJsonStringify(p.snapshot_results?.totals || {});
          p.final_tally_hash = sha256Hex(canonicalTotals);
          changedAny = true;
        }

        // Ensure override_delta_hash exists (content-only)
        if (!p.override_delta_hash) {
          const overridesForPoll = (db.overrides || [])
            .filter(o => o && o.poll_id === p.id)
            .map(o => ({
              voter_token: String(o.voter_token || ""),
              override_option_id: String(o.override_option_id || ""),
              override_ts: o.override_ts ? String(o.override_ts) : null,
            }))
            .sort((a, b) => {
              if (a.voter_token !== b.voter_token) return a.voter_token < b.voter_token ? -1 : 1;
              const at = String(a.override_ts || "");
              const bt = String(b.override_ts || "");
              if (at !== bt) return at < bt ? -1 : 1;
              return a.override_option_id < b.override_option_id ? -1 : 1;
            });

          p.override_delta_hash = sha256Hex(canonicalJsonStringify(overridesForPoll));
          changedAny = true;
        }
        
        // Ensure poll_fingerprint exists (definition-level; meaning-bearing)
        if (!p.poll_fingerprint) {
          try {
            p.poll_fingerprint = computePollFingerprint(p);
            changedAny = true;
          } catch (_) {
            // fail-closed
          }
        }

        // Upsert local commitment (idempotent)
        if (federation && typeof federation.upsertLocalCommitmentForPoll === "function") {
          federation.upsertLocalCommitmentForPoll(db, p, {
            final_tally_hash: p.final_tally_hash,
            override_delta_hash: p.override_delta_hash,
            represented_map_hash: p.represented_map_hash || null,
            config_fingerprint: CFG_FINGERPRINT,
          });
          changedAny = true;
        }
      } catch (e) {
        console.error("[federation] commitment backfill failed:", e);
      }
    }

    if (life.changed) changedAny = true;
  }

  if (changedAny) saveDB(db);

  // Build response using authoritative results
  const polls = db.polls
    .filter(p => isVisibleInList(p, nowIso()))
    .map(p => {
      // Privacy posture: represented_map must never be public.
      const pub = { ...p, results: getAuthoritativeResults(db, p) };
      delete pub.represented_map;
      return pub;
    });

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

// ---------------------------------------------------------------------------
// My ballot (authoritative "what did I vote for?") â€” identity-only (HMAC)
// ---------------------------------------------------------------------------
// GET /api/polls/:id/my-ballot
// - Requires HMAC (X-Self-ID, X-Timestamp, X-Nonce, X-Signature)
// - Resolves identity -> persona internally (no client-supplied persona)
// - Returns minimal shape for UI selection rehydration (no internal ids / tokens)

app.get("/api/polls/:id/my-ballot", requireSignature, (req, res) => {
  const pollId = String(req.params.id || "");
  const db = loadDB();

  const poll = db.polls.find(p => String(p?.id) === pollId);
  if (!poll) return res.status(404).json({ error: "poll_not_found" });

  const state = readIdentityState();
  const selfHash = req.auth?.self_id_hash;
  const ident = findIdentityBySelfIdHash(state, selfHash);

  // If the identity exists but isn't present in state for any reason, fail like other signed endpoints.
  if (!ident) return res.status(403).json({ error: "unknown_identity" });

  // Resolve persona bound to this identity. (If missing, treat as no vote.)
  const persona = (db.personas || []).find(p => p?.meta?.identity_internal_id === ident.internal_id);
  if (!persona) return res.json({ ok: true, has_vote: false });

  // Persona-scoped uniqueness key used by vote storage
  const uid = personaBallotUid(db, pollId, persona.id);

  const v = (db.votes || []).find(x =>
    String(x?.poll_id) === pollId && String(x?.persona_ballot_uid || x?.voter_token || "") === uid
  );

  if (!v) return res.json({ ok: true, has_vote: false });

  // Optional convenience: look up label from poll options
  const optId = String(v.option_id);
  const opt = (poll.options || []).find(o => String(o?.id) === optId);
  const out = {
    ok: true,
    has_vote: true,
    option_id: optId,
    weight_used: Number(v.issued_weight_used ?? v.weight ?? 0) || 0,
  };

  const at = v.updated_at || v.created_at;
  if (at) out.voted_at = String(at);

  if (opt && typeof opt.label !== "undefined") out.option_label = String(opt.label);

  return res.json(out);
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
  {
    const pub = { ...poll };
    delete pub.represented_map;
    sseSend(res, "poll", { poll: pub });
  }
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
    poll_class: req.body?.poll_class ? String(req.body.poll_class) : null,
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

  // ---- queue_no (assert-time; informational; operator may later clear it) ----
  // We only assign queue_no if it is currently missing.
  // Band selection comes from meta.tags scope:* (default scope:exchange).
  if (poll.queue_no == null) {
    const tags = Array.isArray(poll?.meta?.tags) ? poll.meta.tags.map(String) : [];
    const scopeTag = tags.find(t => t.startsWith("scope:")) || "scope:exchange";

    const BANDS = {
      "scope:device": 1,
      "scope:exchange": 101,
      "scope:supernode": 201,
      "scope:municipality": 301,
      "scope:national": 401,
      "scope:state": 501,
      "scope:county": 601,
    };

    const bandStart = BANDS[scopeTag] || 101;

    // Slot within the 100-wide band.
    // MVP: derive from current poll count so it is stable and cheap.
    const slot = (Number(db.polls.length) % 100); // 0..99
    poll.queue_no = bandStart + slot;
  }

  // Default expiry to reduce clutter for non-legitimacy polls:
  // - If not flagged LEGITIMACY/GOVERNANCE and expires_at is unset, expire in 7 days.
  // (Legitimacy polls may run longer and should be configured explicitly by UI later.)
  const isLegitimacyish =
    poll.poll_class === "LEGITIMACY" ||
    poll.poll_class === "GOVERNANCE" ||
    (Array.isArray(poll?.meta?.tags) && poll.meta.tags.includes("legitimacy")) ||
    (typeof poll.cooldown_seconds === "number" && poll.cooldown_seconds > 0);

  if (!poll.expires_at && !isLegitimacyish) {
    const nowMs = Date.now();
    const weekMs = 7 * 24 * 60 * 60 * 1000;
    poll.expires_at = new Date(nowMs + weekMs).toISOString();
  }
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

  // Cooldown (governance/legitimacy) is override-only: no new stamp votes.
  // Voters-only eligibility is enforced by requiring an existing X-Voter-Token.
  if (String(poll.status) === "cooldown" && !presentedVoterToken) {
    return res.status(403).json({ error: "cooldown_override_only" });
  }

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
    persona_id: String(personaId),

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

app.post("/api/polls/:id/vote-anonymous", (req, res) => {
  const pollId = req.params.id;
  const { option_id, voter_token } = req.body || {};
  if (!option_id) return res.status(400).json({ error: "option_id is required" });

  const db = loadDB();

  const poll = db.polls.find(p => p.id === pollId);
  if (!poll) return res.status(404).json({ error: "poll not found" });

  // Apply lifecycle on access
  const life = applyLifecycle(poll, nowIso());
  if (life.changed) saveDB(db);

  if (!canVote(poll)) return res.status(400).json({ error: "poll is closed" });

  // Anonymous voting must be explicitly allowed on the poll
  const anonymousAllowed = poll?.meta?.anonymous_allowed === true;
  if (!anonymousAllowed) {
    return res.status(403).json({ error: "identity_required" });
  }

  // Cooldown stays override-only. Anonymous first-votes are not allowed there.
  if (String(poll.status) === "cooldown") {
    return res.status(403).json({ error: "cooldown_override_only" });
  }

  // Validate option exists on this poll
  const options = Array.isArray(poll.options) ? poll.options : [];
  const optionExists = options.some((o, idx) => {
    if (o && typeof o === "object" && o.id != null) return String(o.id) === String(option_id);
    return String(idx + 1) === String(option_id);
  });

  if (!optionExists) {
    return res.status(400).json({ error: "bad_option_id" });
  }

  const now = nowIso();

  // Anonymous voter token:
  // - if client already has one, reuse it
  // - otherwise mint one now
  const anonVoterToken =
    (typeof voter_token === "string" && voter_token.trim())
      ? voter_token.trim()
      : `anon_${nanoid(24)}`;

  // If this token already has a ballot on this poll, replace it instead of stacking duplicates.
  const existingVote = db.votes.find(v =>
    String(v.poll_id) === String(pollId) &&
    String(v.voter_token || "") === String(anonVoterToken) &&
    String(v.mode || "") === "ANONYMOUS"
  );

  if (existingVote) {
    existingVote.option_id = String(option_id);
    existingVote.updated_at = now;
    existingVote.weight = 1;
    existingVote.issued_weight_used = 1;
    existingVote.meta = {
      ...(existingVote.meta || {}),
      ...(req.body?.meta || {}),
      anonymous: true,
    };

    db.events.push({
      kind: "vote_recast_anonymous",
      poll_id: pollId,
      vote_id: existingVote.id,
      at: now,
    });
  } else {
    // First anonymous vote: fixed weight 1, no identity, no representation, no stamp
    db.votes.push({
      id: nanoid(12),
      poll_id: pollId,
      option_id: String(option_id),

      persona_id: null,
      voter_token: anonVoterToken,
      persona_ballot_uid: null,

      weight: 1,
      issued_weight_used: 1,
      stamp_hash: null,

      mode: "ANONYMOUS",
      created_at: now,
      updated_at: null,
      meta: {
        ...(req.body?.meta || {}),
        anonymous: true,
      },
    });

    db.events.push({
      kind: "vote_cast_anonymous",
      poll_id: pollId,
      voter_token: anonVoterToken,
      at: now,
    });
  }

  saveDB(db);

  const results = getAuthoritativeResults(db, poll);
  broadcast(pollId, "results", { poll_id: pollId, results });

  return res.json({
    ok: true,
    anonymous: true,
    voter_token: anonVoterToken,
    message: "Vote counted anonymously. Sign in to assign a representative or use earned voting weight.",
    results,
  });
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

  // Overrides (delta-only): if present for a given voter_token, use override option_id for tally.
  // We intentionally do NOT mutate the original vote record.
  const overrideByToken = new Map();
  if (Array.isArray(db.overrides)) {
    for (const o of db.overrides) {
      if (!o) continue;
      if (o.poll_id !== pollId) continue;
      if (!o.voter_token) continue;
      overrideByToken.set(String(o.voter_token), String(o.override_option_id));
    }
  }

  // Stats for audit clarity (computational weights given)
  let wMin = null;
  let wMax = null;
  let wSum = 0;
  let wCount = 0;

  for (const v of votes) {
    const tokenKey = v.voter_token || v.persona_ballot_uid || "";
    const overrideOpt = tokenKey ? overrideByToken.get(String(tokenKey)) : null;
    const effOptionId = overrideOpt ? String(overrideOpt) : String(v.option_id);

    if (totals[effOptionId] === undefined) continue;

    // Defensive: a bad stored weight must never turn totals into NaN.
    // (Vote endpoint should already enforce weight > 0.)
    const w = Number(v.weight);
    if (!Number.isFinite(w) || w <= 0) continue;

    totals[effOptionId] += w;

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
    represented_weight: wSum,          // sum of weights
    represented_people: null,          // future - use representational graph to determine unique people represented per vote then sum
    weights_used: { min: wMin, max: wMax, sum: wSum, count: wCount },

    validated: true,
  };
}

// IMPORTANT: stamp remains authoritative, so this is a snapshot at issuance.
  // - Identity-based stamps must not mint with weight < 1.
function computeStandardSnapshotWeightFromIdentity(state, identityRec) {
  // STANDARD remaining (what is still "mine") after outbound delegation.
  // Important design choice (matches federation / pass-through intuition):
  //   standard_remaining + delegated_remaining == max(0, earned + inbound - out)
     const internalId = String(identityRec?.internal_id || "");
  const earned = clampEarnedPersonal(identityRec?.earned_personal ?? identityRec?.weight ?? 0);
  const inbound = computeDelegatedInWeight(state, identityRec?.internal_id);
  const out = sumActiveDelegationsOut(internalId);

  const outBeyondInbound = Math.max(0, Number(out) - Number(inbound));
  const standardRemaining = Number(earned) - outBeyondInbound;

  return Math.max(0, Number(standardRemaining) || 0);
}

function computeDelegatedSnapshotWeightFromIdentity(state, identityRec) {
   // DELEGATED remaining (represented pool still held) after outbound delegation.
   // Delegated-first waterfall: outbound reduces delegated pool before touching standard.
  const inbound = computeDelegatedInWeight(state, identityRec?.internal_id);
  const out = sumActiveDelegationsOut(String(identityRec?.internal_id || ""));

  const delegatedRemaining = Number(inbound) - Number(out);
  return Math.max(0, Number(delegatedRemaining) || 0);
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
};

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


// POST /api/polls/:id/override
// - Cooldown-only replacement of the origin's own choice (voters-only eligibility)
// - Auth: X-Voter-Token only (no stamps issued or consumed)
app.post("/api/polls/:id/override", (req, res) => {
  const pollId = req.params.id;
  const { option_id } = req.body || {};
  if (!option_id) return res.status(400).json({ error: "option_id is required" });

  const token = req.get(VOTER_TOKEN_HEADER);
  if (!token) return res.status(401).json({ error: "missing X-Voter-Token" });

  const db = loadDB();
  const poll = db.polls.find(p => p.id === pollId);
  if (!poll) return res.status(404).json({ error: "poll not found" });

  // Apply lifecycle (ensures status/cooldown timing is current)
  const life = applyLifecycle(poll, nowIso());
  if (life.changed) saveDB(db);

  // Override window == cooldown
  if (String(poll.status) !== "cooldown") {
    return res.status(403).json({ error: "poll_finalized_or_override_closed" });
  }

  // option_id must exist on this poll
  const optOk = Array.isArray(poll.options) && poll.options.some(o => o && String(o.id) === String(option_id));
  if (!optOk) return res.status(400).json({ error: "invalid_option_id" });

  const t = String(token);

  // Voters-only: token must already correspond to an existing vote for this poll
  const prev = db.votes.find(v =>
    v && v.poll_id === pollId && (String(v.voter_token) === t || String(v.persona_ballot_uid) === t)
  );
  if (!prev) return res.status(403).json({ error: "voters_only_override" });

  // Record override (separate store; last-write-wins)
  if (!Array.isArray(db.overrides)) db.overrides = [];
  db.overrides = db.overrides.filter(o => !(o && o.poll_id === pollId && String(o.voter_token) === t));

  const at = nowIso();

  // Best-effort enrich for future analytics ("who gets overridden a lot").
  // This is not required for correctness; we avoid failing the override if enrichment can't be derived.
  let origin_key = null;
  let effective_rep_key = null;
  try {
    const personaId = prev.persona_id ? String(prev.persona_id) : "";
    if (personaId) {
      const persona = (db.personas || []).find(p => p && String(p.id) === personaId) || null;
      const originInternalId = persona?.meta?.identity_internal_id ? String(persona.meta.identity_internal_id) : "";
      if (originInternalId) {
        const state = readIdentityState();
        const originIdentity = findIdentityByInternalId(state, originInternalId);
        origin_key = originIdentity ? String(originIdentity.public_alias || "") : null;

        const rep = resolveEffectiveRepresentativeInternalId(state, originInternalId);
        const repIdentity = findIdentityByInternalId(state, rep.effective_internal_id);
        effective_rep_key = repIdentity ? String(repIdentity.public_alias || "") : origin_key;
      }
    }
  } catch (_) {}

  db.overrides.push({
    poll_id: pollId,
    voter_token: t,
    override_option_id: String(option_id),
    override_ts: at,
    origin_key,
    effective_rep_key,
  });

  // Do NOT change stored vote weights; override is delta-only choice replacement.
  // We keep the original vote record intact and apply overrides at final tally time.
  db.events.push({ kind: "vote_override_set", poll_id: pollId, at });
  saveDB(db);

  return res.json({ ok: true });
});
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Bread Exchange MVP running on http://localhost:${PORT}`);
});
