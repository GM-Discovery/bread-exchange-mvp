#!/usr/bin/env bash
set -euo pipefail

# Bread Exchange — auto-update checker
# Runs via cron (daily). Fetches tags, verifies GPG signature against
# allowlist. By default only notifies; applies automatically if
# AUTO_APPLY=true is set in .env.
#
# Modes:
#   notify (default) — logs availability, writes flag file
#   auto-apply       — checks out new tag, rebuilds containers
#
# Manual apply (when in notify mode):
#   cd /opt/bread-exchange-mvp && git fetch --tags origin && git checkout -f <tag>
#   docker compose up -d --build --force-recreate

INSTALL_DIR="${BREAD_INSTALL_DIR:-/opt/bread-exchange-mvp}"
ENV_FILE="${INSTALL_DIR}/.env"
FLAG_FILE="${INSTALL_DIR}/data/update-available"
LOG_PREFIX="[bread-update $(date -u '+%Y-%m-%dT%H:%M:%SZ')]"

log()  { echo "$LOG_PREFIX $*"; }
fail() { log "FAIL: $*" >&2; exit 1; }

# --- load config from .env ---
AUTO_APPLY="false"
if [[ -f "$ENV_FILE" ]]; then
  _val="$(grep -E '^AUTO_APPLY=' "$ENV_FILE" | tail -n1 | cut -d= -f2 | tr -d '[:space:]')"
  [[ "$_val" == "true" ]] && AUTO_APPLY="true"
fi

# --- sanity checks ---
[[ -d "$INSTALL_DIR/.git" ]] || fail "$INSTALL_DIR is not a git repo"
cd "$INSTALL_DIR"

command -v gpg    >/dev/null 2>&1 || fail "gpg not found"
command -v git    >/dev/null 2>&1 || fail "git not found"
command -v docker >/dev/null 2>&1 || fail "docker not found"

# --- self-install cron if missing ---
CRON_CMD="0 3 * * * ${INSTALL_DIR}/tools/auto-update.sh >> /var/log/bread-update.log 2>&1"
if ! (crontab -l 2>/dev/null | grep -qF "auto-update.sh"); then
  ( crontab -l 2>/dev/null; echo "$CRON_CMD" ) | crontab -
  log "Cron entry self-installed."
fi

DOCKER_COMPOSE=""
if docker compose version >/dev/null 2>&1; then
  DOCKER_COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DOCKER_COMPOSE="docker-compose"
else
  fail "docker compose not found"
fi

# --- current state ---
CURRENT_TAG="$(git describe --tags --exact-match HEAD 2>/dev/null || echo "untagged")"
log "Current: $CURRENT_TAG | Mode: $([ "$AUTO_APPLY" = "true" ] && echo "auto-apply" || echo "notify")"

# --- fetch tags ---
if ! git fetch --tags --force --prune origin >/dev/null 2>&1; then
  fail "Failed to fetch tags from origin"
fi

# --- find latest semver tag ---
LATEST_TAG="$(git tag -l 'v[0-9]*.[0-9]*.[0-9]*' | sort -V | tail -n 1)"
[[ -n "$LATEST_TAG" ]] || fail "No semver tags found"

if [[ "$LATEST_TAG" == "$CURRENT_TAG" ]]; then
  log "Already on latest tag ($CURRENT_TAG). Nothing to do."
  rm -f "$FLAG_FILE"
  exit 0
fi

log "New tag available: $LATEST_TAG (current: $CURRENT_TAG)"

# --- GPG signature verification (mirrors install.sh logic) ---
# Import release signing key from the tag
if git show "${LATEST_TAG}:tools/release_pubkey.asc" >/dev/null 2>&1; then
  git show "${LATEST_TAG}:tools/release_pubkey.asc" | gpg --import >/dev/null 2>&1 || true
elif [[ -f "tools/release_pubkey.asc" ]]; then
  gpg --import tools/release_pubkey.asc >/dev/null 2>&1 || true
fi

# Verify signature exists and is valid
VERIFY_OUT=""
if ! VERIFY_OUT=$(git tag -v "$LATEST_TAG" 2>&1); then
  log "$VERIFY_OUT"
  fail "Tag $LATEST_TAG has no valid GPG signature. Refusing to update."
fi

# Extract signer key ID
KEYID="$(echo "$VERIFY_OUT" \
  | grep -Eo 'using [A-Z0-9]+ key [0-9A-F]{8,40}' \
  | head -n 1 \
  | awk '{print $NF}' \
  | tr '[:lower:]' '[:upper:]' \
  | tr -cd '0-9A-F' \
  || true)"

[[ -n "$KEYID" ]] || fail "Could not extract signer key ID from verification output"

# Derive full fingerprint
FP="$(gpg --batch --with-colons --fingerprint "$KEYID" 2>/dev/null \
  | awk -F: '$1=="fpr"{print $10; exit}' \
  | tr '[:lower:]' '[:upper:]' \
  | tr -cd '0-9A-F' \
  || true)"

[[ ${#FP} -eq 40 ]] || fail "Could not derive 40-hex fingerprint from key ID $KEYID"

# Check against allowlist in the tag
ALLOWLIST=""
if ! ALLOWLIST=$(git show "${LATEST_TAG}:tools/release_signers.txt" 2>/dev/null); then
  fail "Missing tools/release_signers.txt in tag $LATEST_TAG"
fi

MATCH="$(echo "$ALLOWLIST" \
  | sed 's/#.*$//' \
  | sed '/^[[:space:]]*$/d' \
  | tr '[:lower:]' '[:upper:]' \
  | tr -cd '0-9A-F\n' \
  | awk 'length($0)==40 {print $0}' \
  | grep -Fx "$FP" \
  || true)"

[[ -n "$MATCH" ]] || fail "Signer $FP not in allowlist for $LATEST_TAG. Refusing to update."

log "Signature verified. Signer: $FP"

# --- notify or apply ---
if [[ "$AUTO_APPLY" != "true" ]]; then
  echo "$LATEST_TAG" > "$FLAG_FILE"
  log "Update available: $LATEST_TAG (signature verified). Not applying — AUTO_APPLY is not enabled."
  log "To apply manually: cd $INSTALL_DIR && git checkout -f $LATEST_TAG && docker compose up -d --build --force-recreate"
  exit 0
fi

# --- apply update ---
COMMIT_SHA="$(git rev-list -n 1 "$LATEST_TAG")"
log "Checking out $LATEST_TAG ($COMMIT_SHA)"

git checkout -f "$LATEST_TAG"

# --- rebuild and restart ---
log "Rebuilding containers..."
$DOCKER_COMPOSE up -d --build --force-recreate

# --- health check ---
sleep 5
if curl -fsS http://127.0.0.1:8787/api/health >/dev/null 2>&1; then
  log "Health check passed."
else
  log "WARNING: Health check failed after update. Container may still be starting."
fi

rm -f "$FLAG_FILE"
log "Update complete: $CURRENT_TAG -> $LATEST_TAG"