#!/usr/bin/env bash
set -euo pipefail

# tools/net.sh
#
# Minimal operator CLI for network actions.
# - Auto-loads OPERATOR_KEY from .env.exchange when present (VPS-friendly).
#
# Usage (VPS):
#   bash tools/net.sh hello <partner_id> <domain>
#
# Usage (if you want to pass key explicitly):
#   bash tools/net.sh hello <partner_id> <domain> <operator_key>

ACTION="${1:-}"
PARTNER_ID="${2:-}"
DOMAIN="${3:-}"
OPKEY="${4:-}"

die() { echo "ERROR: $*" >&2; exit 1; }

if [[ -z "$ACTION" || -z "$PARTNER_ID" || -z "$DOMAIN" ]]; then
  echo "Usage: bash tools/net.sh hello <partner_id> <domain> [operator_key]"
  exit 1
fi

if [[ "$ACTION" != "hello" ]]; then
  die "Only supported action: hello"
fi

# If operator key not provided, try to load from .env.exchange (common on VPS).
if [[ -z "$OPKEY" ]]; then
  # Prefer repo-local .env.exchange
  if [[ -f "./.env.exchange" ]]; then
    OPKEY="$(grep -E '^OPERATOR_KEY=' ./.env.exchange | head -n1 | cut -d= -f2- || true)"
  fi

  # Fallback: typical install path (when tool is run from elsewhere)
  if [[ -z "$OPKEY" && -f "/opt/bread-exchange-mvp/.env.exchange" ]]; then
    OPKEY="$(grep -E '^OPERATOR_KEY=' /opt/bread-exchange-mvp/.env.exchange | head -n1 | cut -d= -f2- || true)"
  fi
fi

if [[ -z "$OPKEY" ]]; then
  die "OPERATOR_KEY not provided and could not be read from .env.exchange"
fi

curl -sS -X POST "https://$DOMAIN/federation/partners/$PARTNER_ID/hello" \
  -H "X-Operator-Key: $OPKEY" \
  -H "Content-Type: application/json"
echo