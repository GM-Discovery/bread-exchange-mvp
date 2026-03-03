"use strict";

/**
 * push.js
 *
 * Purpose:
 * - Operator-triggered push of local commitments to a partner exchange.
 * - Signs each commitment with our Ed25519 private key.
 *
 * MVP behavior:
 * - Sends ALL local commitments every time (idempotent on receiver).
 * - Posts one-by-one (simple, debuggable). Batch later if desired.
 */

const http = require("http");
const https = require("https");

const { loadPrivateKeyFromEnv } = require("./ed25519");
const { signCommitment } = require("./verify");
const { readPartners, writePartners, readLocalCommitments } = require("./state");
const { COMMITMENT_REQUIRED_FIELDS_V2 } = require("./schemas");
const { localIdentity, checkCompatibility, refusalPayload } = require("./compat");

function pickUnsignedCommitment(pollId, localEntry) {
  // Local store might have extra fields; we only sign the canonical v1 body.
  // We also ensure poll_id is set correctly.
  const ident = localIdentity();

  const out = {    poll_id: pollId,
    final_tally_hash: localEntry.final_tally_hash,
    override_delta_hash: localEntry.override_delta_hash,
    represented_map_hash: localEntry.represented_map_hash,

    finalized_at: localEntry.finalized_at,
    published_at: localEntry.published_at,

    // "ts" = commitment creation timestamp. If local doesn't have it, we fall back to published_at or finalized_at.
    ts: localEntry.ts || localEntry.published_at || localEntry.finalized_at,

    // issuer identity
    exchange_id: process.env.EXCHANGE_ID || localEntry.exchange_id,
    canonical_base_url: process.env.CANONICAL_BASE_URL || localEntry.canonical_base_url,
    
    protocol_version: ident.protocol_version,
    min_supported_version: ident.min_supported_version,
    contract_id: ident.contract_id,
    contract_hash: ident.contract_hash,
  };

  return out;
}

function validateUnsigned(unsigned) {
  for (const f of COMMITMENT_REQUIRED_FIELDS_V2) {
    if (!(f in unsigned)) return { ok: false, error: "missing_" + f };
    if (unsigned[f] === null || unsigned[f] === undefined || unsigned[f] === "") {
      return { ok: false, error: "blank_" + f };
    }
  }
  return { ok: true };
}

function postJson(urlObj, payloadObj) {
  return new Promise((resolve) => {
    const body = Buffer.from(JSON.stringify(payloadObj), "utf8");

    const isHttps = urlObj.protocol === "https:";
    const mod = isHttps ? https : http;

    const req = mod.request(
      {
        protocol: urlObj.protocol,
        hostname: urlObj.hostname,
        port: urlObj.port || (isHttps ? 443 : 80),
        path: urlObj.pathname + (urlObj.search || ""),
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": body.length,
        },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve({ status: res.statusCode, body: data }));
      }
    );

    req.on("error", (e) => resolve({ status: 0, body: String(e && e.message ? e.message : e) }));
    req.write(body);
    req.end();
  });
}
async function sendHelloToPartner(partnerId) {
  const partnersStore = readPartners();
  const partner = (partnersStore.partners || {})[partnerId];

  if (!partner) return { ok: false, error: "partner_not_found" };
  if (partner.status !== "ACTIVE") return { ok: false, error: "partner_not_active" };

  const priv = loadPrivateKeyFromEnv();
  if (!priv) return { ok: false, error: "missing_private_key" };

  const ident = localIdentity();

  // Signed hello payload (partner verifies via our allowlisted public key)
  const unsigned = {
    exchange_id: process.env.EXCHANGE_ID || null,
    canonical_base_url: process.env.CANONICAL_BASE_URL || null,

    protocol_version: ident.protocol_version,
    min_supported_version: ident.min_supported_version,
    contract_id: ident.contract_id,
    contract_hash: ident.contract_hash,

    ts: new Date().toISOString(),
  };

  // Basic sanity
  if (!unsigned.exchange_id || !unsigned.canonical_base_url) {
    return { ok: false, error: "missing_local_identity" };
  }

  const signature = signCommitment(unsigned, priv);
  const payload = { ...unsigned, signature };

  const helloUrl = new URL(String(partner.canonical_base_url).replace(/\/+$/, "") + "/federation/hello");
  const resp = await postJson(helloUrl, payload);

  let data = null;
  try {
    data = JSON.parse(String(resp.body || ""));
  } catch {
    data = null;
  }

  // If partner refused incompatibility, keep their reason visible
  if (resp.status === 409 && data && data.error === "incompatible_peer") {
    partnersStore.partners[partnerId] = {
      ...partner,
      protocol_version: data.local?.protocol_version || partner.protocol_version || null,
      min_supported_version: data.local?.min_supported_version || partner.min_supported_version || null,
      contract_id: data.local?.contract_id || partner.contract_id || null,
      contract_hash: data.local?.contract_hash || partner.contract_hash || null,
      last_seen_at: new Date().toISOString(),
      compatibility_status: "INCOMPATIBLE",
      incompatibility_reason: String(data.reason || "incompatible_peer"),
    };
    writePartners(partnersStore);
    return data;
  }

  if (resp.status < 200 || resp.status >= 300) {
    return {
      ok: false,
      error: "hello_failed",
      status: resp.status,
      body: String(resp.body || "").slice(0, 400),
    };
  }

  // Expected response: { ok:true, ts, local:{...partner identity...} }
  const peerLocal = data && data.local ? data.local : null;
  if (!peerLocal) {
    return { ok: false, error: "hello_bad_response" };
  }

  partnersStore.partners[partnerId] = {
    ...partner,
    protocol_version: String(peerLocal.protocol_version || ""),
    min_supported_version: String(peerLocal.min_supported_version || ""),
    contract_id: String(peerLocal.contract_id || ""),
    contract_hash: String(peerLocal.contract_hash || ""),
    last_seen_at: new Date().toISOString(),
    compatibility_status: "OK",
    incompatibility_reason: "",
  };
  writePartners(partnersStore);

  return { ok: true, ts: new Date().toISOString(), partner_id: partnerId, peer: peerLocal };
}

async function pushToPartner(partnerId) {
  const partnersStore = readPartners();
  const partner = (partnersStore.partners || {})[partnerId];

  if (!partner) return { ok: false, error: "partner_not_found" };
  if (partner.status !== "ACTIVE") return { ok: false, error: "partner_not_active" };

    // Require that we have peer capabilities from a successful /hello
  if (!partner.protocol_version || !partner.min_supported_version || !partner.contract_id || !partner.contract_hash) {
    return { ok: false, error: "partner_unknown_capabilities", ts: new Date().toISOString() };
  }

  // Refuse pushing to incompatible peer (operator-visible, actionable)
  const comp = checkCompatibility({
    protocol_version: partner.protocol_version,
    min_supported_version: partner.min_supported_version,
    contract_id: partner.contract_id,
    contract_hash: partner.contract_hash,
  });

  if (!comp.ok) {
    return refusalPayload(comp);
  }
  const priv = loadPrivateKeyFromEnv();
  if (!priv) return { ok: false, error: "missing_private_key" };

  const localStore = readLocalCommitments(process.env.EXCHANGE_ID, process.env.CANONICAL_BASE_URL);
  const local = localStore && localStore.local ? localStore.local : {};

  const pollIds = Object.keys(local);
  pollIds.sort(); // stable order for operator sanity

  let sent = 0;
  let ok = 0;
  let failed = 0;

  const failures = [];

  // Partner ingest endpoint
  const ingestUrl = new URL(String(partner.canonical_base_url).replace(/\/+$/, "") + "/federation/ingest");

  for (const pollId of pollIds) {
    const entry = local[pollId] || {};

    const unsigned = pickUnsignedCommitment(pollId, entry);
    const v = validateUnsigned(unsigned);
    if (!v.ok) {
      failed++;
      failures.push({ poll_id: pollId, error: v.error });
      continue;
    }

    const signature = signCommitment(unsigned, priv);

    const payload = { ...unsigned, signature };

    sent++;
    const resp = await postJson(ingestUrl, payload);

    if (resp.status >= 200 && resp.status < 300) {
      ok++;
    } else {
      failed++;
      failures.push({
        poll_id: pollId,
        status: resp.status,
        body: String(resp.body || "").slice(0, 300),
      });
    }
  }

  return {
    ok: true,
    partner_id: partnerId,
    partner_exchange_id: partner.exchange_id,
    target: partner.canonical_base_url,
    local_commitments: pollIds.length,
    sent,
    success: ok,
    failed,
    failures,
  };
}

module.exports = {
  pushToPartner,
  sendHelloToPartner,
};
