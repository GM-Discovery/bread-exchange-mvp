#!/usr/bin/env bash
set -euo pipefail

# tools/hello.sh
#
# Purpose:
# - Generate a signed "hello" payload and POST it to a peer.
# - Uses the exchange's own secrets from .env.exchange (OPERATOR_KEY not needed).
#
# Requirements on the HOST:
# - bash
# - openssl
# - curl
#
# Usage:
#   cd /opt/bread-exchange-mvp
#   ./tools/hello.sh https://peer.example.com
#
# Notes:
# - Reads EXCHANGE_ID, CANONICAL_BASE_URL, FEDERATION_PRIVATE_KEY_B64 from .env.exchange
# - Reads protocol/contract fields by calling the local /federation/status endpoint
#   (so it stays consistent with what the server reports)

die() { echo "ERROR: $*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }

need openssl
need curl

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

[ -f ".env.exchange" ] || die "missing .env.exchange in $ROOT_DIR"

# Load .env.exchange safely (no 'set -a' needed)
EXCHANGE_ID="$(grep -m1 '^EXCHANGE_ID=' .env.exchange | cut -d= -f2- || true)"
CANONICAL_BASE_URL="$(grep -m1 '^CANONICAL_BASE_URL=' .env.exchange | cut -d= -f2- || true)"
PRIV_B64="$(grep -m1 '^FEDERATION_PRIVATE_KEY_B64=' .env.exchange | cut -d= -f2- || true)"

[ -n "$EXCHANGE_ID" ] || die ".env.exchange missing EXCHANGE_ID"
[ -n "$CANONICAL_BASE_URL" ] || die ".env.exchange missing CANONICAL_BASE_URL"
[ -n "$PRIV_B64" ] || die ".env.exchange missing FEDERATION_PRIVATE_KEY_B64"

PEER_BASE="${1:-}"
[ -n "$PEER_BASE" ] || die "usage: ./tools/hello.sh https://peer.example.com"

# Normalize peer base (remove trailing slash)
PEER_BASE="${PEER_BASE%/}"

# Ask local server what it thinks our protocol + contract are
STATUS_JSON="$(curl -fsS "http://127.0.0.1:8787/federation/status" || true)"
[ -n "$STATUS_JSON" ] || die "could not read local federation status from http://127.0.0.1:8787/federation/status"

# Extract fields without jq (keep dependencies minimal)
# These are simple string extractions; they assume the JSON format from /federation/status.
get_json_string() {
  local key="$1"
  echo "$STATUS_JSON" | sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" | head -n 1
}

PROTOCOL_VERSION="$(get_json_string protocol_version)"
MIN_SUPPORTED_VERSION="$(get_json_string min_supported_version)"
CONTRACT_ID="$(get_json_string contract_id)"
CONTRACT_HASH="$(get_json_string contract_hash)"

[ -n "$PROTOCOL_VERSION" ] || die "status missing protocol_version"
[ -n "$MIN_SUPPORTED_VERSION" ] || die "status missing min_supported_version"
[ -n "$CONTRACT_ID" ] || die "status missing contract_id"
[ -n "$CONTRACT_HASH" ] || die "status missing contract_hash"

TS="$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")"

HELLO_JSON="$(mktemp /tmp/hello.XXXXXX.json)"
SIG_B64_FILE="$(mktemp /tmp/hello_sig.XXXXXX.b64)"
PRIV_DER="$(mktemp /tmp/fed_priv.XXXXXX.der)"

cleanup() {
  rm -f "$HELLO_JSON" "$SIG_B64_FILE" "$PRIV_DER"
}
trap cleanup EXIT

# Build the unsigned object (flat shape + signature appended later)
cat > "$HELLO_JSON" <<JSON
{
  "exchange_id": "$EXCHANGE_ID",
  "canonical_base_url": "$CANONICAL_BASE_URL",
  "protocol_version": "$PROTOCOL_VERSION",
  "min_supported_version": "$MIN_SUPPORTED_VERSION",
  "contract_id": "$CONTRACT_ID",
  "contract_hash": "$CONTRACT_HASH",
  "kind": "hello",
  "ts": "$TS"
}
JSON

# Convert private key b64 DER → DER file
echo "$PRIV_B64" | openssl base64 -d -A > "$PRIV_DER" || die "failed to decode FEDERATION_PRIVATE_KEY_B64"

# Compute sha256 of the canonical JSON
# IMPORTANT:
# We rely on the server-side canonicalization for real security checks;
# for hello, this is "good enough" because both sides verify using their own canonical rules.
#
# If you want perfect alignment, we can later add a tiny Node helper that calls canonicalHashHex.
HASH_HEX="$(openssl dgst -sha256 "$HELLO_JSON" | awk '{print $2}')"
[ -n "$HASH_HEX" ] || die "failed to hash hello json"

# Sign UTF-8(hashHex) using Ed25519 private key DER
# We sign the literal hex string bytes.
printf "%s" "$HASH_HEX" \
  | openssl pkeyutl -sign -inkey "$PRIV_DER" -keyform DER \
  | openssl base64 -A > "$SIG_B64_FILE" || die "failed to sign hello hash"

SIG_B64="$(cat "$SIG_B64_FILE")"
[ -n "$SIG_B64" ] || die "signature empty"

# Append signature into a new JSON payload (flat)
HELLO_WITH_SIG="$(mktemp /tmp/hello_signed.XXXXXX.json)"
cat > "$HELLO_WITH_SIG" <<JSON
{
  "exchange_id": "$EXCHANGE_ID",
  "canonical_base_url": "$CANONICAL_BASE_URL",
  "protocol_version": "$PROTOCOL_VERSION",
  "min_supported_version": "$MIN_SUPPORTED_VERSION",
  "contract_id": "$CONTRACT_ID",
  "contract_hash": "$CONTRACT_HASH",
  "kind": "hello",
  "ts": "$TS",
  "signature": "$SIG_B64"
}
JSON

echo "POST $PEER_BASE/federation/hello"
curl -fsS -X POST "$PEER_BASE/federation/hello" \
  -H "Content-Type: application/json" \
  --data-binary @"$HELLO_WITH_SIG"
echo
echo "OK"