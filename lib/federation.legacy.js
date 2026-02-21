/**
 * Federation v0 — Partner-allowlisted commitments + dispute artifacts
 *
 * This module is intentionally self-contained so server.js changes stay small.
 *
 * Design goals:
 * - Partner-only (operator allowlist) using Ed25519 signatures.
 * - Default is “commitment sync”; proofs only on demand.
 * - Audit-first: store everything in /app/data JSON files.
 *
 * Security notes:
 * - This is NOT HMAC client auth. This is exchange-to-exchange auth.
 * - Replay defense is ts+nonce (in-memory TTL) + message_id hash (persisted rolling window).
 * - v0 assumes single-node (no shared nonce cache across replicas).
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { canonicalHashHex } = require("./federation/canonical");

// ------------------------------
// Data dir + file helpers
// ------------------------------

function dataDir() {
  // Matches docker-compose: /app/data bind mount in the container.
  // Allow override for local dev.
  return process.env.DATA_DIR || "/app/data";
}

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}

function readJson(filePath, fallback) {
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    return JSON.parse(raw);
  } catch (_e) {
    return fallback;
  }
}

function writeJsonAtomic(filePath, obj) {
  const tmp = `${filePath}.tmp.${process.pid}.${Date.now()}`;
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), "utf8");
  fs.renameSync(tmp, filePath);
}

// ------------------------------
// Canonical JSON + hashing
// ------------------------------

function isPlainObject(x) {
  return x && typeof x === "object" && !Array.isArray(x) && x.constructor === Object;
}

function canonicalize(x) {
  // Recursively sort keys for stable JSON.
  if (Array.isArray(x)) return x.map(canonicalize);
  if (isPlainObject(x)) {
    const out = {};
    const keys = Object.keys(x).sort();
    for (const k of keys) {
      const v = x[k];
      // IMPORTANT: omit undefined to avoid node-specific JSON differences.
      if (v === undefined) continue;
      out[k] = canonicalize(v);
    }
    return out;
  }
  return x;
}

function canonicalJson(x) {
  // No whitespace, keys sorted.
  return JSON.stringify(canonicalize(x));
}

function sha256HexFromObj(x) {
  return crypto.createHash("sha256").update(canonicalJson(x), "utf8").digest("hex");
}

function sha256BytesFromObj(x) {
  return crypto.createHash("sha256").update(canonicalJson(x), "utf8").digest();
}

function stripSignature(obj) {
  // Deep clone via canonicalization so we also normalize key ordering.
  const c = canonicalize(obj);
  if (isPlainObject(c) && "signature" in c) delete c.signature;
  return c;
}

// ------------------------------
// Ed25519 key handling
// ------------------------------

function genEd25519Keypair() {
  // Use node's built-in crypto; export keys in DER so they can be reloaded.
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pubDer = publicKey.export({ type: "spki", format: "der" });
  const privDer = privateKey.export({ type: "pkcs8", format: "der" });
  return {
    pubkey_b64: Buffer.from(pubDer).toString("base64"),
    privkey_b64: Buffer.from(privDer).toString("base64"),
  };
}

function pubKeyFromB64(b64) {
  return crypto.createPublicKey({
    key: Buffer.from(String(b64 || ""), "base64"),
    format: "der",
    type: "spki",
  });
}

function privKeyFromB64(b64) {
  return crypto.createPrivateKey({
    key: Buffer.from(String(b64 || ""), "base64"),
    format: "der",
    type: "pkcs8",
  });
}

function signObj(objWithoutSignature, privkey_b64) {
  // We sign the 32-byte sha256 digest (bytes), not the hex string.
  const digest = sha256BytesFromObj(objWithoutSignature);
  const sig = crypto.sign(null, digest, privKeyFromB64(privkey_b64));
  return Buffer.from(sig).toString("base64");
}

function verifyObj(objWithoutSignature, signature_b64, pubkey_b64) {
  try {
    const digest = sha256BytesFromObj(objWithoutSignature);
    const sig = Buffer.from(String(signature_b64 || ""), "base64");
    return crypto.verify(null, digest, pubKeyFromB64(pubkey_b64), sig);
  } catch (_e) {
    return false;
  }
}

// ------------------------------
// Identity + partner stores
// ------------------------------

function identityPath() {
  return path.join(dataDir(), "federation.identity.private.json");
}
function partnersPath() {
  return path.join(dataDir(), "federation.partners.json");
}
function localCommitmentsPath() {
  return path.join(dataDir(), "federation.local_commitments.json");
}
function receivedCommitmentsPath() {
  return path.join(dataDir(), "federation.commitments.json");
}
function disputesPath() {
  return path.join(dataDir(), "federation.disputes.json");
}

function loadOrCreateIdentity() {
  ensureDir(dataDir());

  const existing = readJson(identityPath(), null);
  if (existing && existing.exchange_id && existing.exchange_pubkey_b64 && existing.exchange_privkey_b64) {
    return existing;
  }

  // NOTE: exchange_id must be stable. We derive from canonical_base_url + operator_salt.
  const canonicalBaseUrl = String(process.env.CANONICAL_BASE_URL || "").trim();
  if (!canonicalBaseUrl) {
    throw new Error("CANONICAL_BASE_URL is required to initialize federation identity");
  }

  const operatorSalt = crypto.randomBytes(32).toString("hex");
  const kp = genEd25519Keypair();

  const exchangeId =
    "ex_" +
    crypto
      .createHash("sha256")
      .update(`bread-exchange:${canonicalBaseUrl}:${operatorSalt}`, "utf8")
      .digest("hex")
      .slice(0, 32);

  // Warn-only fingerprint (never gates acceptance)
  const exchangeFingerprint =
    "sha256:" +
    crypto
      .createHash("sha256")
      .update(`fed_v0:${canonicalBaseUrl}`, "utf8")
      .digest("hex");

  const now = new Date().toISOString();
  const ident = {
    schema_version: "fed_v0",
    exchange_id: exchangeId,
    canonical_base_url: canonicalBaseUrl,
    operator_salt_hex: operatorSalt,
    exchange_pubkey_b64: kp.pubkey_b64,
    exchange_privkey_b64: kp.privkey_b64,
    exchange_fingerprint: exchangeFingerprint,
    protocol_versions: ["fed_v0"],
    created_at: now,
    updated_at: now,
  };

  writeJsonAtomic(identityPath(), ident);
  return ident;
}

function loadPartners() {
  ensureDir(dataDir());
  const fallback = { schema_version: "fed_v0", partners: [] };
  const p = readJson(partnersPath(), fallback);
  if (!p || !Array.isArray(p.partners)) return fallback;
  return p;
}

function findActivePartner(partnersDoc, exchangeId) {
  const id = String(exchangeId || "");
  const rec = (partnersDoc.partners || []).find((x) => String(x.exchange_id) === id);
  if (!rec) return null;
  if (String(rec.status || "active") !== "active") return null;
  return rec;
}

function upsertPartnerSeen(exchangeId, patch) {
  const doc = loadPartners();
  const id = String(exchangeId || "");
  const rec = (doc.partners || []).find((x) => String(x.exchange_id) === id);
  if (!rec) return; // unknown partner: never create here.
  Object.assign(rec, patch);
  writeJsonAtomic(partnersPath(), doc);
}

// ------------------------------
// Replay defense
// ------------------------------

const NONCE_TTL_MS = 10 * 60 * 1000;
const TS_WINDOW_MS = 5 * 60 * 1000;
const _nonceCache = new Map(); // key: exchange_id:nonce -> expiresAt

function nonceSeen(exchangeId, nonce) {
  const key = `${String(exchangeId)}:${String(nonce)}`;
  const now = Date.now();
  // purge opportunistically
  for (const [k, exp] of _nonceCache.entries()) {
    if (exp <= now) _nonceCache.delete(k);
  }
  const exp = _nonceCache.get(key);
  if (exp && exp > now) return true;
  _nonceCache.set(key, now + NONCE_TTL_MS);
  return false;
}

function isFreshTs(ts) {
  const n = Number(ts);
  if (!Number.isFinite(n)) return false;
  const now = Date.now();
  return Math.abs(now - n) <= TS_WINDOW_MS;
}

function loadReceivedCommitments() {
  const fallback = { schema_version: "fed_v0", received: {}, recent_message_ids: [] };
  return readJson(receivedCommitmentsPath(), fallback) || fallback;
}

function saveReceivedCommitments(doc) {
  writeJsonAtomic(receivedCommitmentsPath(), doc);
}

function messageIdFor(objWithoutSignature) {
  return sha256HexFromObj(objWithoutSignature);
}

function persistMessageId(doc, mid) {
  // rolling window; keep last 500
  if (!Array.isArray(doc.recent_message_ids)) doc.recent_message_ids = [];
  doc.recent_message_ids.unshift(String(mid));
  doc.recent_message_ids = Array.from(new Set(doc.recent_message_ids)).slice(0, 500);
}

function isReplayPersisted(doc, mid) {
  return Array.isArray(doc.recent_message_ids) && doc.recent_message_ids.includes(String(mid));
}

// ------------------------------
// Commitment creation helpers (local)
// ------------------------------

function pollFingerprint(poll) {
  // Only include fields that define “the question”.
  // Avoid timestamps/status/results/etc.
  const def = {
    id: String(poll?.id || ""),
    poll_class: String(poll?.poll_class || ""),
    domain: String(poll?.domain || "governance"),
    jurisdiction_id: String(poll?.jurisdiction_id || "local"),
    title: String(poll?.title || ""),
    question: String(poll?.question || ""),
    options: Array.isArray(poll?.options)
      ? poll.options.map((o) => ({ id: String(o?.id || ""), label: String(o?.label || "") }))
      : [],
  };
  return sha256HexFromObj(def);
}

function computeRepresentedMapV0(db, pollId) {
  // v0 voters-only: no origin export. Represented map is ballot_uid -> weight.
  // We use persona_ballot_uid first (newer) and fall back to voter_token.
  const votes = (db?.votes || []).filter((v) => String(v?.poll_id) === String(pollId));
  const m = {};
  for (const v of votes) {
    const uid = String(v?.persona_ballot_uid || v?.voter_token || "");
    if (!uid) continue;
    const w = Number(v?.weight);
    if (!Number.isFinite(w) || w <= 0) continue;
    // Keep max weight if duplicates exist (should not, but defensive).
    m[uid] = Math.max(Number(m[uid] || 0), w);
  }
  return m;
}

function buildLocalCommitment({ db, poll, identity }) {
  // We require snapshot_results to exist for finalized governance/legitimacy.
  const snapshot = poll?.snapshot_results || null;
  if (!snapshot) return null;

  const representedMap = computeRepresentedMapV0(db, poll.id);
  const representedMapHash = sha256HexFromObj(representedMap);

  const overrideList = []; // v0: overrides not first-class in this repo yet
  const overrideDeltaHash = sha256HexFromObj(overrideList);

  const finalTallyHash = sha256HexFromObj(snapshot);

  const body = {
    exchange_id: identity.exchange_id,
    poll_id: String(poll.id),
    jurisdiction_id: String(poll.jurisdiction_id || "local"),
    domain: String(poll.domain || "governance"),
    poll_fingerprint: pollFingerprint(poll),
    snapshot_version: "snapshot_v0_voters_only",
    t_close: poll.closed_at || poll.t_close || null,
    override_deadline: poll.cooldown_ends_at || poll.override_deadline || null,
    t_final: poll.finalized_at || poll.t_final || null,
    ledger_heads: {
      trust_head: { cutoff_ts: poll.finalized_at || null, head_hash: null },
      delegation_head: { cutoff_ts: poll.finalized_at || null, head_hash: null },
      stamps_head: { cutoff_ts: poll.finalized_at || null, head_hash: null },
      ballots_head: { cutoff_ts: poll.finalized_at || null, head_hash: null },
    },
    represented_map_hash: representedMapHash,
    override_delta_hash: overrideDeltaHash,
    final_tally_hash: finalTallyHash,
    exchange_fingerprint: String(identity.exchange_fingerprint || ""),
    ts: Date.now(),
    nonce: crypto.randomBytes(12).toString("hex"),
  };

  const sig = signObj(body, identity.exchange_privkey_b64);
  return { ...body, signature: sig };
}

function loadLocalCommitments() {
  const fallback = { schema_version: "fed_v0", local: {} };
  return readJson(localCommitmentsPath(), fallback) || fallback;
}

function saveLocalCommitments(doc) {
  writeJsonAtomic(localCommitmentsPath(), doc);
}

function ensureLocalCommitmentForPoll({ db, poll, identity }) {
  // Only create once we have a finalized timestamp.
  if (!poll || !(poll.finalized_at || poll.published_at)) return false;

  const doc = loadLocalCommitments();
  if (!doc.local) doc.local = {};
  const pollId = String(poll.id);
  if (doc.local[pollId]) return false; // already created

  const c = buildLocalCommitment({ db, poll, identity });
  if (!c) return false;

  doc.local[pollId] = { commitment: c, created_at: new Date().toISOString() };
  saveLocalCommitments(doc);
  return true;
}

function getLocalCommitment(pollId) {
  const doc = loadLocalCommitments();
  return doc?.local?.[String(pollId)]?.commitment || null;
}

// ------------------------------
// Verification helper
// ------------------------------

function verifyFederationRequest(reqBody, partnersDoc) {
  // Determine sender exchange id: common fields across endpoints.
  const from = String(reqBody?.from_exchange_id || reqBody?.exchange_id || "");
  if (!from) return { ok: false, status: 400, error: "missing_exchange_id" };

  const partner = findActivePartner(partnersDoc, from);
  if (!partner) return { ok: false, status: 403, error: "unknown_partner" };

  const ts = reqBody?.ts;
  const nonce = reqBody?.nonce;
  if (!isFreshTs(ts)) return { ok: false, status: 400, error: "stale_ts" };
  if (!nonce) return { ok: false, status: 400, error: "missing_nonce" };
  if (nonceSeen(from, nonce)) return { ok: false, status: 409, error: "replay_nonce" };

  const sig = reqBody?.signature;
  if (!sig) return { ok: false, status: 400, error: "missing_signature" };

  const bodyNoSig = stripSignature(reqBody);
  const valid = verifyObj(bodyNoSig, sig, partner.pubkey_b64);
  if (!valid) return { ok: false, status: 403, error: "bad_signature" };

  return { ok: true, partner };
}

// ------------------------------
// Routes
// ------------------------------

function installFederationRoutes(app) {
  const identity = loadOrCreateIdentity();

  // Ensure store files exist so operators can inspect them.
  ensureDir(dataDir());
  if (!fs.existsSync(receivedCommitmentsPath())) {
    writeJsonAtomic(receivedCommitmentsPath(), {
      schema_version: "fed_v0",
      received: {},
      recent_message_ids: [],
    });
  }
  if (!fs.existsSync(disputesPath())) {
    writeJsonAtomic(disputesPath(), { schema_version: "fed_v0", disputes: {} });
  }
  if (!fs.existsSync(localCommitmentsPath())) {
    writeJsonAtomic(localCommitmentsPath(), { schema_version: "fed_v0", local: {} });
  }

  // 0) POST /federation/hello
  app.post("/federation/hello", (req, res) => {
    const body = req.body || {};
    const partnersDoc = loadPartners();

    // hello includes exchange_pubkey and must match allowlist.
    const v = verifyFederationRequest(body, partnersDoc);
    if (!v.ok) return res.status(v.status).json({ ok: false, error: v.error });

    const partnerRec = v.partner;
    if (String(body.exchange_pubkey || "") !== String(partnerRec.pubkey_b64 || "")) {
      return res.status(403).json({ ok: false, error: "pubkey_mismatch" });
    }

    // Update last-seen metadata (operator helpful, not security gating).
    upsertPartnerSeen(body.exchange_id, {
      base_url: String(body.base_url || partnerRec.base_url || ""),
      last_seen_ts: Number(body.ts) || Date.now(),
      last_seen_fingerprint: String(body.exchange_fingerprint || ""),
    });

    const responseBody = {
      ok: true,
      accepted: true,
      this_exchange_id: identity.exchange_id,
      this_pubkey: identity.exchange_pubkey_b64,
      this_fingerprint: identity.exchange_fingerprint,
      protocol_versions: identity.protocol_versions,
      ts: Date.now(),
      nonce: crypto.randomBytes(12).toString("hex"),
    };

    const sig = signObj(responseBody, identity.exchange_privkey_b64);
    return res.json({ ...responseBody, signature: sig });
  });

  // 1) POST /federation/polls/offer
  app.post("/federation/polls/offer", (req, res) => {
    const body = req.body || {};
    const partnersDoc = loadPartners();

    const v = verifyFederationRequest(body, partnersDoc);
    if (!v.ok) return res.status(v.status).json({ ok: false, error: v.error });

    // Persisted replay defense (message_id) for outer envelope.
    const recvDoc = loadReceivedCommitments();
    const mid = messageIdFor(stripSignature(body));
    if (isReplayPersisted(recvDoc, mid)) {
      return res.status(409).json({ ok: false, error: "replay_message" });
    }
    persistMessageId(recvDoc, mid);

    const from = String(body.from_exchange_id || body.exchange_id || "");
    const commitments = Array.isArray(body.commitments) ? body.commitments : [];

    let accepted = 0;
    const rejected = [];

    for (const c of commitments) {
      try {
        if (!c || typeof c !== "object") throw new Error("bad_commitment");
        if (String(c.exchange_id || "") !== from) throw new Error("commitment_exchange_mismatch");
        if (!c.signature) throw new Error("missing_commitment_signature");

        const partner = findActivePartner(partnersDoc, from);
        if (!partner) throw new Error("unknown_partner");

        const ok = verifyObj(stripSignature(c), c.signature, partner.pubkey_b64);
        if (!ok) throw new Error("bad_commitment_signature");

        const pollId = String(c.poll_id || "");
        if (!pollId) throw new Error("missing_poll_id");

        if (!recvDoc.received) recvDoc.received = {};
        if (!recvDoc.received[pollId]) recvDoc.received[pollId] = {};

        // Compare to local commitment if present.
        const local = getLocalCommitment(pollId);
        let status = "UNKNOWN_LOCAL";
        if (local) {
          const keys = [
            "poll_fingerprint",
            "snapshot_version",
            "represented_map_hash",
            "override_delta_hash",
            "final_tally_hash",
          ];
          const mismatch = keys.find((k) => String(local[k] || "") !== String(c[k] || ""));
          status = mismatch ? "MISMATCH" : "MATCH";
        }

        recvDoc.received[pollId][from] = {
          commitment: c,
          received_at: new Date().toISOString(),
          status,
        };

        accepted += 1;
      } catch (e) {
        rejected.push({ poll_id: String(c?.poll_id || ""), reason: String(e?.message || "rejected") });
      }
    }

    saveReceivedCommitments(recvDoc);
    return res.json({ ok: true, accepted_count: accepted, rejected });
  });

  // 2) POST /federation/polls/:poll_id/challenge
  app.post("/federation/polls/:poll_id/challenge", (req, res) => {
    const pollId = String(req.params.poll_id || "");
    const body = req.body || {};
    const partnersDoc = loadPartners();

    const v = verifyFederationRequest(body, partnersDoc);
    if (!v.ok) return res.status(v.status).json({ ok: false, error: v.error });

    const challengeId = String(body.challenge_id || "");
    if (!challengeId) return res.status(400).json({ ok: false, error: "missing_challenge_id" });

    const disputes = readJson(disputesPath(), { schema_version: "fed_v0", disputes: {} });
    if (!disputes.disputes) disputes.disputes = {};

    disputes.disputes[challengeId] = {
      poll_id: pollId,
      from_exchange_id: String(body.from_exchange_id || body.exchange_id || ""),
      reason: String(body.reason || ""),
      requested_artifacts: Array.isArray(body.requested_artifacts) ? body.requested_artifacts : [],
      created_at: new Date().toISOString(),
      proofs: [],
    };

    writeJsonAtomic(disputesPath(), disputes);
    return res.json({ ok: true, accepted: true });
  });

  // 3) POST /federation/polls/:poll_id/proof
  app.post("/federation/polls/:poll_id/proof", (req, res) => {
    const pollId = String(req.params.poll_id || "");
    const body = req.body || {};
    const partnersDoc = loadPartners();

    const v = verifyFederationRequest(body, partnersDoc);
    if (!v.ok) return res.status(v.status).json({ ok: false, error: v.error });

    const challengeId = String(body.challenge_id || "");
    if (!challengeId) return res.status(400).json({ ok: false, error: "missing_challenge_id" });

    const disputes = readJson(disputesPath(), { schema_version: "fed_v0", disputes: {} });
    if (!disputes.disputes) disputes.disputes = {};
    const dispute = disputes.disputes[challengeId];
    if (!dispute) return res.status(404).json({ ok: false, error: "challenge_not_found" });

    const artifacts = body.artifacts && typeof body.artifacts === "object" ? body.artifacts : {};

    // Recompute hashes when artifacts are provided.
    const recompute = {};
    if (artifacts.represented_map) {
      recompute.represented_map_hash = sha256HexFromObj(artifacts.represented_map);
    }
    if (artifacts.overrides) {
      recompute.override_delta_hash = sha256HexFromObj(artifacts.overrides);
    }
    if (artifacts.tally_breakdown) {
      recompute.final_tally_hash = sha256HexFromObj(artifacts.tally_breakdown);
    }

    // Compare against the received commitment (if any).
    const recv = loadReceivedCommitments();
    const from = String(body.from_exchange_id || body.exchange_id || "");
    const receivedCommitment = recv?.received?.[pollId]?.[from]?.commitment || null;
    let status = "still_mismatch";

    if (receivedCommitment) {
      const checks = [
        ["represented_map_hash", recompute.represented_map_hash],
        ["override_delta_hash", recompute.override_delta_hash],
        ["final_tally_hash", recompute.final_tally_hash],
      ].filter(([, v]) => v);

      const mismatch = checks.find(([k, v]) => String(receivedCommitment[k] || "") !== String(v || ""));
      status = mismatch ? "still_mismatch" : "resolved";
    }

    dispute.proofs.push({
      at: new Date().toISOString(),
      from_exchange_id: from,
      artifacts,
      recompute,
      status,
    });

    writeJsonAtomic(disputesPath(), disputes);
    return res.json({ ok: true, stored: true, recompute, status });
  });

  // Operator-local shortcut
  app.get("/federation/status", (_req, res) => {
    const partners = loadPartners();
    const recv = loadReceivedCommitments();
    const local = loadLocalCommitments();
    res.json({
      ok: true,
      this_exchange_id: identity.exchange_id,
      partners: partners.partners || [],
      local_polls: Object.keys(local.local || {}).length,
      received_polls: Object.keys(recv.received || {}).length,
    });
  });

  return {
    identity,
    ensureLocalCommitmentForPoll: ({ db, poll }) => ensureLocalCommitmentForPoll({ db, poll, identity }),
  };
}

function upsertLocalCommitmentForPoll(db, poll, opts = {}) {
  if (!db || !poll) return { ok: false, reason: "missing_inputs" };

  const path = require("path");
  const fs = require("fs");

  const dataDir = opts.dataDir || path.join(__dirname, "..", "data");
  const filePath = path.join(dataDir, "federation.local_commitments.json");

  let store = { local: {} };

  try {
    if (fs.existsSync(filePath)) {
      store = JSON.parse(fs.readFileSync(filePath, "utf8"));
      if (!store || typeof store !== "object") store = { local: {} };
      if (!store.local || typeof store.local !== "object") {
        store.local = {};
      }
    }
  } catch (_) {
    store = { local: {} };
  }

  const pollId = String(poll.id);

  // Only commit finalized/published polls
  const isLocked =
    poll.status === "published" || !!poll.finalized_at;

  if (!isLocked || !poll.snapshot_results) {
    return { ok: false, reason: "not_locked" };
  }

  // Compute deterministic poll fingerprint from poll definition (not lifecycle timestamps)
  let pollFingerprint = null;
  try {
    const def = {
      id: String(poll.id || ""),
      poll_class: poll.poll_class != null ? String(poll.poll_class) : null,
      type: poll.type != null ? String(poll.type) : null,
      title: poll.title != null ? String(poll.title) : null,
      description: poll.description != null ? String(poll.description) : null,
      options: Array.isArray(poll.options)
        ? poll.options.map(o => ({
            option_id: String((o && (o.option_id || o.id)) || ""),
            label: o && o.label != null
              ? String(o.label)
              : (o && o.text != null ? String(o.text) : null),
          }))
        : null,
      meta: (poll.meta && typeof poll.meta === "object") ? poll.meta : null,
    };
    pollFingerprint = canonicalHashHex(def);
  } catch (_) {
    pollFingerprint = null;
  }

  // Compute deterministic stamp_set_hash from represented_map (privacy-safe: no vote contents).
  // We only commit to the set of stamp IDs involved, not who they represented.
  let stampSetHash = null;
  try {
    const rm = poll.represented_map;

    // Normalize to a sorted array of unique stamp ids
    const ids = [];

    if (Array.isArray(rm)) {
      for (const e of rm) {
        const sid =
          e && (e.stamp_id != null || e.stampId != null || e.stamp != null)
            ? String(e.stamp_id ?? e.stampId ?? e.stamp)
            : null;
        if (sid) ids.push(sid);
      }
    } else if (rm && typeof rm === "object") {
      // If it's a map, keys might be stamp ids
      for (const k of Object.keys(rm)) {
        if (k) ids.push(String(k));
      }
    }

    ids.sort();

    // Unique
    const uniq = [];
    for (const s of ids) {
      if (!uniq.length || uniq[uniq.length - 1] !== s) uniq.push(s);
    }

    // Hash canonical JSON array of stamp ids
    stampSetHash = canonicalHashHex(uniq);
  } catch (_) {
    stampSetHash = null;
  }

  const commitment = {
    poll_id: pollId,

    // Deterministic poll fingerprint (definition-level)
    poll_fingerprint: pollFingerprint,

    // Stamp set hash (who participated, not how they voted)
    stamp_set_hash: stampSetHash,

    final_tally_hash: poll.final_tally_hash || null,
    override_delta_hash: poll.override_delta_hash || null,
    represented_map_hash: poll.represented_map_hash || null,

    finalized_at: poll.finalized_at || null,
    published_at: poll.published_at || null,
    ts: new Date().toISOString(),
  };



  store.local[pollId] = commitment;

  fs.writeFileSync(
    filePath,
    JSON.stringify(store, null, 2),
    "utf8"
  );

  return { ok: true };
}

// ---------------------------------------------------------------------------
// Exported helpers (keep stable for server.js + tooling)
// These were previously exported; if they went missing, reintroduce them.
// ---------------------------------------------------------------------------

function _canonicalJson(value) {
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

function _sha256HexFromObj(obj) {
  const crypto = require("crypto");
  return crypto.createHash("sha256").update(_canonicalJson(obj), "utf8").digest("hex");
}

module.exports = {
  installFederationRoutes,
  upsertLocalCommitmentForPoll,
  _canonicalJson,
  _sha256HexFromObj
};
