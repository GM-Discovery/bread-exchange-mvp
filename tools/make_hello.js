"use strict";

/*
 * tools/make_hello.js
 *
 * Generates a signed hello payload using the SAME canonical + signing
 * code the server uses.
 *
 * Usage on VPS:
 *   node tools/make_hello.js > /tmp/hello.json
 */

const { localIdentity } = require("../lib/federation/compat");
const { signCommitment } = require("../lib/federation/verify");

function nowIso() {
  return new Date().toISOString();
}

function die(msg) {
  console.error("ERROR:", msg);
  process.exit(1);
}

const EXCHANGE_ID = process.env.EXCHANGE_ID || "";
const BASE_URL = process.env.CANONICAL_BASE_URL || "";
const PRIV_B64 = process.env.FEDERATION_PRIVATE_KEY_B64 || "";

if (!EXCHANGE_ID) die("EXCHANGE_ID missing");
if (!BASE_URL) die("CANONICAL_BASE_URL missing");
if (!PRIV_B64) die("FEDERATION_PRIVATE_KEY_B64 missing");

const meta = localIdentity();

const unsigned = {
  exchange_id: EXCHANGE_ID,
  canonical_base_url: BASE_URL,
  protocol_version: meta.protocol_version,
  min_supported_version: meta.min_supported_version,
  contract_id: meta.contract_id,
  contract_hash: meta.contract_hash,
  kind: "hello",
  ts: nowIso()
};

const signature = signCommitment(unsigned, PRIV_B64);

const out = {
  ...unsigned,
  signature
};

process.stdout.write(JSON.stringify(out, null, 2) + "\n");