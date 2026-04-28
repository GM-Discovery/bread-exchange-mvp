"use strict";

const express = require("express");
const crypto = require("crypto");

const { ingestCommitment } = require("./ingest");
const { pushToPartner, sendHelloToPartner } = require("./push");
const {
  readPartners, writePartners,
  readReceived,
  readDisputes,
  readLocalCommitments,
} = require("./state");

const { handleDiscovery } = require("./discovery");

const { localIdentity, checkCompatibility, refusalPayload } = require("./compat");
const { canonicalHashHex } = require("./canonical");
const { loadPublicKeyFromB64 } = require("./ed25519");
const { verifyCommitmentHashHex } = require("./verify");

function nowIso() {
  return new Date().toISOString();
}

const autoPushRuntime = {
  started: false,
  inFlight: false,
  last_run_at: null,
  last_result: null,
};

function envBool(name, fallback = false) {
  const raw = process.env[name];
  if (raw == null || raw === "") return fallback;
  const v = String(raw).trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

function envInt(name, fallback) {
  const n = Number(process.env[name]);
  if (!Number.isFinite(n) || n < 0) return fallback;
  return Math.floor(n);
}

function operatorOk(req) {
  const want = process.env.OPERATOR_KEY || "";
  if (!want) return false;

  const got = String(req.get("X-Operator-Key") || "");

  const a = Buffer.from(got, "utf8");
  const b = Buffer.from(want, "utf8");
  if (a.length !== b.length) return false;

  return crypto.timingSafeEqual(a, b);
}

function requireOperator(req, res) {
  if (!process.env.OPERATOR_KEY) {
    res.status(503).json({ error: "operator_key_missing" });
    return false;
  }
  if (!operatorOk(req)) {
    res.status(403).json({ error: "bad_operator_key" });
    return false;
  }
  return true;
}

function summarizePartners(store) {
  const out = [];
  const partners = store.partners || {};
  for (const partnerId of Object.keys(partners)) {
    const p = partners[partnerId];
    out.push({
      partner_id: partnerId,
      exchange_id: p.exchange_id,
      canonical_base_url: p.canonical_base_url,
      status: p.status,
      added_at: p.added_at,
      notes: p.notes || "",
      public_keys_count: Array.isArray(p.public_keys_b64) ? p.public_keys_b64.length : 0,

      protocol_version: p.protocol_version || null,
      min_supported_version: p.min_supported_version || null,
      contract_id: p.contract_id || null,
      contract_hash: p.contract_hash || null,
      last_seen_at: p.last_seen_at || null,
      compatibility_status: p.compatibility_status || "UNKNOWN",
      incompatibility_reason: p.incompatibility_reason || "",
      last_push_attempt_at: p.last_push_attempt_at || null,
      last_push_success_at: p.last_push_success_at || null,
      last_push_mode: p.last_push_mode || null,
      last_push_sent: Number(p.last_push_sent) || 0,
      last_push_failed: Number(p.last_push_failed) || 0,
      last_push_error: p.last_push_error || "",
      last_push_error_at: p.last_push_error_at || null,
      push_attempt_count: Number(p.push_attempt_count) || 0,
      push_success_count: Number(p.push_success_count) || 0,
      push_failure_count: Number(p.push_failure_count) || 0,
    });
  }
  out.sort((a, b) => String(a.exchange_id).localeCompare(String(b.exchange_id)));
  return out;
}

function summarizeReceived(store) {
  const rows = [];
  const received = store.received || {};
  for (const issuer of Object.keys(received)) {
    const bucket = received[issuer] || {};
    for (const pollId of Object.keys(bucket)) {
      const r = bucket[pollId];
      rows.push({
        poll_id: pollId,
        from_exchange_id: issuer,
        commitment_hash: r.commitment_hash,
        received_at: r.received_at,
      });
    }
  }
  rows.sort((a, b) => String(b.received_at || "").localeCompare(String(a.received_at || "")));
  return rows;
}

function summarizeDisputes(store) {
  const rows = [];
  const disputes = store.disputes || {};
  for (const id of Object.keys(disputes)) {
    const d = disputes[id];
    rows.push({
      dispute_id: d.dispute_id,
      poll_id: d.poll_id,
      issuer_exchange_id: d.issuer_exchange_id,
      created_at: d.created_at,
      status: d.status,
      diff_fields: d.diff_fields || [],
    });
  }
  rows.sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")));
  return rows;
}

function countOpenDisputes(disputesStore) {
  let n = 0;
  const disputes = disputesStore.disputes || {};
  for (const id of Object.keys(disputes)) {
    if (disputes[id] && disputes[id].status === "OPEN") n++;
  }
  return n;
}

// --- Phase 3 Hardening: simple in-memory rate limiting (token bucket) ---
// NOTE: This is intentionally boring and dependency-free.
// If you restart the server, buckets reset. That's fine for MVP Phase 3.

function makeTokenBucket({ capacity, refillPerSec }) {
  // Map key -> { tokens, lastMs }
  const buckets = new Map();

  return function allow(key) {
    const now = Date.now();
    let b = buckets.get(key);
    if (!b) {
      b = { tokens: capacity, lastMs: now };
      buckets.set(key, b);
    }

    // Refill tokens based on time elapsed
    const elapsedSec = Math.max(0, (now - b.lastMs) / 1000);
    b.lastMs = now;
    b.tokens = Math.min(capacity, b.tokens + elapsedSec * refillPerSec);

    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  };
}

// Partner burst: ~10 requests/sec, allow brief spikes
const allowPartnerRead = makeTokenBucket({ capacity: 20, refillPerSec: 10 });

// Public burst: tighter so random internet can�t hammer you
const allowPublicRead  = makeTokenBucket({ capacity: 6,  refillPerSec: 2 });

// Consistent �boring� error helper
function sendErr(res, status, code, detail) {
  const out = { ok: false, error: code };
  if (detail) out.detail = String(detail);
  return res.status(status).json(out);
}

function rollupStatus() {
  const partnersStore = readPartners();
  const receivedStore = readReceived();
  const disputesStore = readDisputes();
  const localStore = readLocalCommitments(process.env.EXCHANGE_ID, process.env.CANONICAL_BASE_URL);

  const partnersCount = Object.keys(partnersStore.partners || {}).length;

  let receivedPolls = 0;
  const received = receivedStore.received || {};
  for (const issuer of Object.keys(received)) {
    receivedPolls += Object.keys(received[issuer] || {}).length;
  }

  const openDisputes = countOpenDisputes(disputesStore);

  let localPolls = 0;
  if (localStore && localStore.local) localPolls = Object.keys(localStore.local).length;
  
  const ident = localIdentity();
  const partnersRows = summarizePartners(partnersStore);
  const pushAttempts = partnersRows.reduce((s, p) => s + (Number(p.push_attempt_count) || 0), 0);
  const pushSuccess = partnersRows.reduce((s, p) => s + (Number(p.push_success_count) || 0), 0);
  const pushFailures = partnersRows.reduce((s, p) => s + (Number(p.push_failure_count) || 0), 0);
  const autoPushIntervalMs = envInt("FED_AUTO_PUSH_INTERVAL_MS", 0);
  const autoPushEnabled = envBool("FED_AUTO_PUSH_ENABLED", autoPushIntervalMs > 0) && autoPushIntervalMs > 0;
  
  return {
    ok: true,
    ts: nowIso(),
    exchange_id: process.env.EXCHANGE_ID || null,
    canonical_base_url: process.env.CANONICAL_BASE_URL || null,
    
    protocol_version: ident.protocol_version,
    min_supported_version: ident.min_supported_version,
    contract_id: ident.contract_id,
    contract_hash: ident.contract_hash,
    
    partners_count: partnersCount,
    local_polls: localPolls,
    received_polls: receivedPolls,
    disputes_open: openDisputes,
    push_attempts_total: pushAttempts,
    push_success_total: pushSuccess,
    push_fail_total: pushFailures,
    auto_push: {
      enabled: autoPushEnabled,
      interval_ms: autoPushIntervalMs,
      in_flight: autoPushRuntime.inFlight,
      last_run_at: autoPushRuntime.last_run_at,
      last_result: autoPushRuntime.last_result,
    },
    
  };
}

function scheduleAutoPushTick() {
  const intervalMs = envInt("FED_AUTO_PUSH_INTERVAL_MS", 0);
  const jitterMs = envInt("FED_AUTO_PUSH_JITTER_MS", 0);
  const enabled = envBool("FED_AUTO_PUSH_ENABLED", intervalMs > 0) && intervalMs > 0;
  if (!enabled) return;

  const nextDelay = intervalMs + (jitterMs > 0 ? Math.floor(Math.random() * jitterMs) : 0);
  setTimeout(async () => {
    if (autoPushRuntime.inFlight) {
      scheduleAutoPushTick();
      return;
    }
    try {
      await runAutoPushOnce();
    } finally {
      scheduleAutoPushTick();
    }
  }, nextDelay);
}

async function runAutoPushOnce() {
  if (autoPushRuntime.inFlight) {
    return { ok: false, error: "auto_push_in_flight", ts: nowIso() };
  }
  autoPushRuntime.inFlight = true;
  autoPushRuntime.last_run_at = nowIso();
  try {
    const partnersStore = readPartners();
    const activeIds = Object.keys(partnersStore.partners || {}).filter((pid) => {
      const p = partnersStore.partners[pid];
      return p && p.status === "ACTIVE";
    });

    const results = await Promise.all(activeIds.map((pid) => pushToPartner(pid, { full_sync: false })));
    const failed = results.filter(r => !r || !r.ok).length;
    const out = {
      ok: true,
      ts: nowIso(),
      mode: "incremental",
      partners_total: activeIds.length,
      partners_ok: activeIds.length - failed,
      partners_failed: failed,
      results,
    };
    autoPushRuntime.last_result = out;
    return out;
  } catch (e) {
    const out = {
      ok: false,
      ts: nowIso(),
      error: "auto_push_failed",
    };
    autoPushRuntime.last_result = out;
    return out;
  } finally {
    autoPushRuntime.inFlight = false;
  }
}

function newPartnerId() {
  return "p_" + crypto.randomBytes(10).toString("hex");
}

function installFederationRouter(app, deps = {}) {
  const loadDB = deps.loadDB;
  if (typeof loadDB !== "function") {
    throw new Error("installFederationRouter requires deps.loadDB");
  }
  const router = express.Router();

  if (!autoPushRuntime.started) {
    autoPushRuntime.started = true;
    scheduleAutoPushTick();
  }

  router.get("/status", (req, res) => {
    try {
      const ip = req.ip || req.connection?.remoteAddress || "unknown";
      if (!allowPublicRead("fed:status:" + ip)) return sendErr(res, 429, "rate_limited");
      res.json(rollupStatus());
    } catch (e) {
      return sendErr(res, 500, "status_failed");
    }
  });

  router.get("/partners", (req, res) => {
    try {
      const ip = req.ip || req.connection?.remoteAddress || "unknown";
      if (!allowPublicRead("fed:partners:" + ip)) return sendErr(res, 429, "rate_limited");
      const store = readPartners();
      res.json({ partners: summarizePartners(store) });
    } catch (e) {
      return sendErr(res, 500, "partners_read_failed");
    }
  });
  // ----- POST: Hello (signed handshake; stores peer protocol/contract metadata) -----
  router.post("/hello", express.json({ limit: "64kb" }), (req, res) => {
    try {
      const body = req.body || {};
      const signature = String(body.signature || "");
      const { signature: _sig, ...unsigned } = body;

      const issuerExchangeId = String(unsigned.exchange_id || "");
      if (!issuerExchangeId) return sendErr(res, 400, "missing_exchange_id");
      if (!signature) return sendErr(res, 400, "missing_signature");

      // Allowlist lookup (ACTIVE only) by exchange_id
      const partnersStore = readPartners();
      let partnerId = null;
      let partner = null;
      for (const pid of Object.keys(partnersStore.partners || {})) {
        const p = partnersStore.partners[pid];
        if (p && p.exchange_id === issuerExchangeId && p.status === "ACTIVE") {
          partnerId = pid;
          partner = p;
          break;
        }
      }
      if (!partner) return sendErr(res, 403, "issuer_not_allowlisted");

      // Verify signature against partner public keys
      const h = canonicalHashHex(unsigned);
      let okSig = false;
      for (const pubB64 of (partner.public_keys_b64 || [])) {
        const pub = loadPublicKeyFromB64(String(pubB64));
        if (!pub) continue;
        if (verifyCommitmentHashHex(h, signature, pub)) {
          okSig = true;
          break;
        }
      }
      if (!okSig) return sendErr(res, 400, "invalid_signature");

      // Compatibility check (fail closed)
      const comp = checkCompatibility(unsigned);
      if (!comp.ok) {
        partnersStore.partners[partnerId] = {
          ...partner,
          protocol_version: String(unsigned.protocol_version || ""),
          min_supported_version: String(unsigned.min_supported_version || ""),
          contract_id: String(unsigned.contract_id || ""),
          contract_hash: String(unsigned.contract_hash || ""),
          last_seen_at: nowIso(),
          compatibility_status: "INCOMPATIBLE",
          incompatibility_reason: String(comp.reason || "incompatible_peer"),
        };
        writePartners(partnersStore);
        return res.status(409).json(refusalPayload(comp));
      }

      // Store peer metadata as compatible
      partnersStore.partners[partnerId] = {
        ...partner,
        protocol_version: comp.peer.protocol_version,
        min_supported_version: comp.peer.min_supported_version,
        contract_id: comp.peer.contract_id,
        contract_hash: comp.peer.contract_hash,
        last_seen_at: nowIso(),
        compatibility_status: "OK",
        incompatibility_reason: "",
      };
      writePartners(partnersStore);

      return res.json({ ok: true, ts: nowIso(), local: localIdentity() });
    } catch (e) {
      return sendErr(res, 500, "hello_failed");
    }
  });

  // ----- GET: Discovery (informational, unsigned) -----
  router.get("/discovery", (req, res) => {
    try {
      const ip = req.ip || req.connection?.remoteAddress || "unknown";
      if (!allowPublicRead("fed:discovery:" + ip)) return sendErr(res, 429, "rate_limited");

      const partnersStore = readPartners();
      return handleDiscovery(req, res, partnersStore, loadDB, {
        // pass limiters so discovery can apply partner vs public correctly once it knows partner_id
        allowPartnerRead,
        allowPublicRead,
        sendErr,
        // Phase 3 constants
        PAGE_MAX: 10,
        RESP_MAX_BYTES: 200 * 1024,
      });
    } catch (e) {
      return sendErr(res, 500, "discovery_failed");
    }
  });


  router.post("/partners/add", express.json({ limit: "256kb" }), (req, res) => {
    if (!requireOperator(req, res)) return;

    const body = req.body || {};
    const exchangeId = String(body.exchange_id || "");
    const baseUrl = String(body.canonical_base_url || "");
    const keys = Array.isArray(body.public_keys_b64) ? body.public_keys_b64.map(String) : [];

    if (!exchangeId || !baseUrl || keys.length < 1) {
      return res.status(400).json({ error: "missing_partner_fields" });
    }

    const store = readPartners();

    // Update if partner with same exchange_id exists, else create new partner_id.
    let existingId = null;
    for (const pid of Object.keys(store.partners || {})) {
      if (store.partners[pid] && store.partners[pid].exchange_id === exchangeId) {
        existingId = pid;
        break;
      }
    }

    const pid = existingId || newPartnerId();
    const prev = store.partners[pid] || {};

    store.partners[pid] = {
      exchange_id: exchangeId,
      canonical_base_url: baseUrl,
      public_keys_b64: keys,
      status: (body.status === "DISABLED") ? "DISABLED" : "ACTIVE",
      added_at: prev.added_at || nowIso(),
      notes: String(body.notes || prev.notes || ""),
    };

    writePartners(store);
    res.json({ ok: true, partner_id: pid });
  });

  // ----- POST: Hello a partner (outbound operator endpoint; tidy grouping) -----
  router.post("/partners/:partner_id/hello", (req, res) => {
    if (!requireOperator(req, res)) return;

    const partnerId = String(req.params.partner_id || "");
    if (!partnerId) return res.status(400).json({ ok: false, error: "missing_partner_id" });

    sendHelloToPartner(partnerId)
      .then((out) => {
        if (!out.ok) {
          // meaningful codes
          if (out.error === "partner_not_found") return res.status(404).json(out);
          if (out.error === "partner_not_active") return res.status(409).json(out);
          if (out.error === "incompatible_peer") return res.status(409).json(out);
          return res.status(400).json(out);
        }
        res.json(out);
      })
      .catch(() => res.status(500).json({ ok: false, error: "hello_outbound_failed" }));
  });

  router.post("/partners/disable", express.json({ limit: "64kb" }), (req, res) => {
    if (!requireOperator(req, res)) return;

    const body = req.body || {};
    const pid = String(body.partner_id || "");
    if (!pid) return res.status(400).json({ error: "missing_partner_id" });

    const store = readPartners();
    if (!store.partners[pid]) return res.status(404).json({ error: "partner_not_found" });

    store.partners[pid].status = "DISABLED";
    writePartners(store);
    res.json({ ok: true });
  });

  router.post("/partners/remove", express.json({ limit: "64kb" }), (req, res) => {
    if (!requireOperator(req, res)) return;

    const body = req.body || {};
    const pid = String(body.partner_id || "");
    if (!pid) return res.status(400).json({ error: "missing_partner_id" });

    const store = readPartners();
    if (!store.partners[pid]) return res.status(404).json({ error: "partner_not_found" });

    delete store.partners[pid];
    writePartners(store);
    res.json({ ok: true });
  });

  router.post("/ingest", express.json({ limit: "512kb" }), (req, res) => {
    try {
      const payload = req.body || {};
      const out = ingestCommitment(payload);
      if (!out.ok) {
        if (out.error === "issuer_not_allowlisted") return res.status(403).json(out);
        if (out.error === "incompatible_peer") return res.status(409).json(out);
        return res.status(400).json(out);
      }      res.json(out);
    } catch (e) {
      res.status(500).json({ ok: false, error: "ingest_failed" });
    }
  });


  // ----- POST: Push local commitments to partner (operator gated) -----
  router.post("/push/:partner_id", (req, res) => {
    if (!requireOperator(req, res)) return;

    const partnerId = String(req.params.partner_id || "");
    if (!partnerId) return res.status(400).json({ ok: false, error: "missing_partner_id" });
    const fullSync = String(req.query.full || "") === "1" || String(req.query.full || "").toLowerCase() === "true";

    pushToPartner(partnerId, { full_sync: fullSync })
      .then((out) => {
        if (!out.ok) {
          if (out.error === "partner_not_found") return res.status(404).json(out);
          if (out.error === "partner_unknown_capabilities") return res.status(409).json(out);
          if (out.error === "incompatible_peer") return res.status(409).json(out);
          return res.status(400).json(out);
        }        res.json(out);
      })
      .catch(() => res.status(500).json({ ok: false, error: "push_failed" }));
  });

  // Push all ACTIVE partners in one operator call.
  // Default is incremental; pass ?full=1 to force full sync to each partner.
  router.post("/push-all", (req, res) => {
    if (!requireOperator(req, res)) return;
    const fullSync = String(req.query.full || "") === "1" || String(req.query.full || "").toLowerCase() === "true";
    const partnersStore = readPartners();
    const activeIds = Object.keys(partnersStore.partners || {}).filter((pid) => {
      const p = partnersStore.partners[pid];
      return p && p.status === "ACTIVE";
    });

    Promise.all(activeIds.map((pid) => pushToPartner(pid, { full_sync: fullSync })))
      .then((results) => {
        const summary = {
          ok: true,
          mode: fullSync ? "full" : "incremental",
          partners_total: activeIds.length,
          partners_ok: results.filter(r => r && r.ok).length,
          partners_failed: results.filter(r => !r || !r.ok).length,
          results,
        };
        res.json(summary);
      })
      .catch(() => res.status(500).json({ ok: false, error: "push_all_failed" }));
  });

  // Trigger one immediate incremental push across ACTIVE partners.
  router.post("/push-now", (req, res) => {
    if (!requireOperator(req, res)) return;
    runAutoPushOnce()
      .then((out) => {
        if (!out.ok && out.error === "auto_push_in_flight") return res.status(409).json(out);
        if (!out.ok) return res.status(500).json(out);
        res.json(out);
      })
      .catch(() => res.status(500).json({ ok: false, error: "push_now_failed", ts: nowIso() }));
  });

  router.get("/received", (req, res) => {
    try {
      const store = readReceived();
      let rows = summarizeReceived(store);

      const sinceRaw = req.query.since;
      if (sinceRaw) {
        const sinceMs = Date.parse(String(sinceRaw));
        if (!Number.isFinite(sinceMs)) return res.status(400).json({ error: "bad_since" });
        rows = rows.filter((r) => {
          const t = Date.parse(String(r.received_at || ""));
          return Number.isFinite(t) && t > sinceMs;
        });
      }

      const limitRaw = req.query.limit;
      if (limitRaw !== undefined) {
        const n = Number(limitRaw);
        if (!Number.isFinite(n) || n <= 0) return res.status(400).json({ error: "bad_limit" });
        rows = rows.slice(0, Math.min(500, Math.floor(n)));
      }

      res.json({ received: rows });
    } catch (e) {
      res.status(500).json({ error: "received_read_failed" });
    }
  });

  router.get("/disputes", (req, res) => {
    try {
      const store = readDisputes();
      res.json({ disputes: summarizeDisputes(store) });
    } catch (e) {
      res.status(500).json({ error: "disputes_read_failed" });
    }
  });

  router.get("/disputes/:id", (req, res) => {
    if (!requireOperator(req, res)) return;

    try {
      const store = readDisputes();
      const d = (store.disputes || {})[String(req.params.id || "")];
      if (!d) return res.status(404).json({ error: "dispute_not_found" });
      res.json({ dispute: d });
    } catch (e) {
      res.status(500).json({ error: "dispute_read_failed" });
    }
  });

  app.use("/federation", router);
}

module.exports = {
  installFederationRouter,
};
