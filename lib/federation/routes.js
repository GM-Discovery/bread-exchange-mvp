"use strict";

const express = require("express");
const crypto = require("crypto");

const { ingestCommitment } = require("./ingest");
const {
  readPartners, writePartners,
  readReceived,
  readDisputes,
  readLocalCommitments,
} = require("./state");

function nowIso() {
  return new Date().toISOString();
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

  return {
    ok: true,
    ts: nowIso(),
    exchange_id: process.env.EXCHANGE_ID || null,
    canonical_base_url: process.env.CANONICAL_BASE_URL || null,
    partners_count: partnersCount,
    local_polls: localPolls,
    received_polls: receivedPolls,
    disputes_open: openDisputes,
  };
}

function newPartnerId() {
  return "p_" + crypto.randomBytes(10).toString("hex");
}

function installFederationRouter(app) {
  const router = express.Router();

  router.get("/status", (req, res) => {
    try {
      res.json(rollupStatus());
    } catch (e) {
      res.status(500).json({ ok: false, error: "status_failed" });
    }
  });

  router.get("/partners", (req, res) => {
    try {
      const store = readPartners();
      res.json({ partners: summarizePartners(store) });
    } catch (e) {
      res.status(500).json({ error: "partners_read_failed" });
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
      if (!out.ok) return res.status(400).json(out);
      res.json(out);
    } catch (e) {
      res.status(500).json({ ok: false, error: "ingest_failed" });
    }
  });

  router.get("/received", (req, res) => {
    try {
      const store = readReceived();
      res.json({ received: summarizeReceived(store) });
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