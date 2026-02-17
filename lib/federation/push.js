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

const { canonicalHashHex } = require("./canonical");
const { loadPrivateKeyFromEnv, signHashHex } = require("./ed25519");
const { readPartners, readLocalCommitments } = require("./state");

const { COMMITMENT_REQUIRED_FIELDS } = require("./schemas");

function pickUnsignedCommitment(pollId, localEntry) {
  // Local store might have extra fields; we only sign the canonical v1 body.
  // We also ensure poll_id is set correctly.
  const out = {
    poll_id: pollId,

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
  };

  return out;
}

function validateUnsigned(unsigned) {
  for (const f of COMMITMENT_REQUIRED_FIELDS) {
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

async function pushToPartner(partnerId) {
  const partnersStore = readPartners();
  const partner = (partnersStore.partners || {})[partnerId];

  if (!partner) return { ok: false, error: "partner_not_found" };
  if (partner.status !== "ACTIVE") return { ok: false, error: "partner_not_active" };

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

    const commitmentHash = canonicalHashHex(unsigned);
    const signature = signHashHex(commitmentHash, priv);

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
};
