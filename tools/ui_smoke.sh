#!/usr/bin/env sh
set -eu

HOST="${1:-exchange.breadstandard.com}"
IP="${2:-127.0.0.1}"

fail() { echo "FAIL: $*" >&2; exit 1; }

# Always include a SPACE before flags, no concatenation tricks.
RESOLVE="--resolve ${HOST}:443:${IP}"

# HEAD checks (follow redirects, use https with correct SNI)
curl -fsSIL $RESOLVE "https://${HOST}/" >/dev/null || fail "HEAD / failed"
curl -fsSIL $RESOLVE "https://${HOST}/ui.js" >/dev/null || fail "HEAD /ui.js failed"
curl -fsSIL $RESOLVE "https://${HOST}/styles.css" >/dev/null || fail "HEAD /styles.css failed"

HTML="$(curl -fsSL $RESOLVE "https://${HOST}/")"

echo "$HTML" | grep -q '/ui.js' || fail "HTML missing /ui.js reference"
echo "$HTML" | grep -q '/styles.css' || fail "HTML missing /styles.css reference"

# Forbidden dev entrypoints
echo "$HTML" | grep -q '/src/main.js' && fail "HTML references /src/main.js (forbidden)"
echo "$HTML" | grep -q 'type="module"' && fail 'HTML contains type="module" (forbidden for static deploy)'

# Only require qrcode if HTML references it
if echo "$HTML" | grep -q 'qrcode\.min\.js'; then
  curl -fsSIL $RESOLVE "https://${HOST}/vendor/qrcode.min.js" >/dev/null || fail "HTML references qrcode.min.js but /vendor/qrcode.min.js is missing"
fi

echo "OK: UI static contract holds for https://${HOST}/ (resolved to ${IP})"
