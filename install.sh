#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# bread-exchange installer v0
# - Installs to fixed root: /opt/bread-exchange
# - Verifies signed git tag (no HEAD installs)
# - Generates secrets locally and writes .env with 600 perms
# - Brings up Docker Compose stack (Node + Caddy)
# - Gates success on /api/health, /federation/status, and tools/ui_smoke.sh
# -----------------------------------------------------------------------------

INSTALL_ROOT="/opt/bread-exchange"

# Change this to your canonical repo URL once decided.
DEFAULT_REPO_URL="https://github.com/GM-Discovery/bread-exchange-mvp.git"

FORCE=0
REPO_URL="$DEFAULT_REPO_URL"
DOMAIN=""
TLS_EMAIL=""
TAG="latest"
ENABLE_FEDERATION="yes"

die() { echo "ERROR: $*" >&2; exit 1; }
log() { echo "[install] $*"; }

usage() {
  cat <<'USAGE'
Usage:
  sudo ./install.sh --domain exchange.example.com [options]

Required:
  --domain <fqdn>          Domain name (e.g. exchange.example.com)

Options:
  --email <email>          Email for Let's Encrypt (recommended)
  --tag <tag|latest>       Install git tag (default: latest)
  --repo <git-url>         Repo URL (default compiled into script)
  --no-federation          Set ENABLE_FEDERATION=no in .env
  --force                  Overwrite existing /opt/bread-exchange (DANGEROUS)
  -h, --help               Show help

Notes:
- This installer will refuse to proceed unless it can verify the tag signature.
- Trusted release public keys must exist in the repo at: release/trusted_tag_pubkeys.gpg
USAGE
}

# --- Args --------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --email) TLS_EMAIL="${2:-}"; shift 2 ;;
    --tag) TAG="${2:-}"; shift 2 ;;
    --repo) REPO_URL="${2:-}"; shift 2 ;;
    --no-federation) ENABLE_FEDERATION="no"; shift 1 ;;
    --force) FORCE=1; shift 1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown arg: $1" ;;
  esac
done

[[ -n "$DOMAIN" ]] || die "--domain is required"
CANONICAL_BASE_URL="https://${DOMAIN}"

# --- Preflight ----------------------------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
  die "Run as root (use sudo)."
fi

if [[ -e "$INSTALL_ROOT" && "$FORCE" -ne 1 ]]; then
  die "$INSTALL_ROOT exists. Re-run with --force to replace (will destroy existing install)."
fi

# Keep secrets safe by default
umask 077

# --- OS check (Ubuntu 24.04 target) ------------------------------------------
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" ]]; then
    die "Target is Ubuntu 24.04. Detected ID=${ID:-unknown}."
  fi
  # VERSION_ID is "24.04" for Ubuntu 24.04
  if [[ "${VERSION_ID:-}" != "24.04" ]]; then
    die "Target is Ubuntu 24.04. Detected VERSION_ID=${VERSION_ID:-unknown}."
  fi
fi

# --- Packages -----------------------------------------------------------------
log "Installing base dependencies..."
apt-get update -y
apt-get install -y --no-install-recommends \
  ca-certificates curl git jq openssl

# --- Docker install (if missing) ---------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  log "Docker not found; installing Docker Engine + Compose plugin..."
  # Official Docker repo method (Ubuntu)
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

systemctl enable --now docker >/dev/null 2>&1 || true

# --- Prepare install root -----------------------------------------------------
if [[ "$FORCE" -eq 1 && -e "$INSTALL_ROOT" ]]; then
  log "--force set: removing existing $INSTALL_ROOT"
  rm -rf "$INSTALL_ROOT"
fi

log "Cloning repo into $INSTALL_ROOT ..."
git clone "$REPO_URL" "$INSTALL_ROOT"

cd "$INSTALL_ROOT"
git fetch --tags --force

# --- Tag selection ------------------------------------------------------------
resolve_latest_tag() {
  # Pick the most recent tag matching v* (customize if you want stricter "stable" rules).
  # Sorting by version sort gives reasonable results for v0.1.2 etc.
  git tag -l 'v*' | sort -V | tail -n 1
}

if [[ "$TAG" == "latest" ]]; then
  TAG="$(resolve_latest_tag)"
  [[ -n "$TAG" ]] || die "No tags found in repo; cannot install 'latest'."
fi

# --- Tag signature verification (hard gate) ----------------------------------
# Trusted keys must be provided by the repo at release/trusted_tag_pubkeys.gpg.
if [[ ! -f "release/trusted_tag_pubkeys.gpg" ]]; then
  die "Missing release/trusted_tag_pubkeys.gpg. Cannot verify signed tags. Refusing to proceed."
fi

log "Importing trusted release signing keys..."
GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
chmod 700 "$GNUPGHOME"
gpg --batch --import "release/trusted_tag_pubkeys.gpg" >/dev/null 2>&1 || die "Failed to import trusted tag keys"

log "Verifying signed tag: $TAG"
# git verify-tag uses gpg under the hood.
git verify-tag "$TAG" >/dev/null 2>&1 || die "Tag verification FAILED for $TAG. Refusing to install unsigned/untrusted tag."

log "Checking out tag: $TAG"
git checkout -f "$TAG"

# --- Secret bootstrap ---------------------------------------------------------
ENV_PATH="$INSTALL_ROOT/.env"
DATA_DIR="$INSTALL_ROOT/data"
BACKUPS_DIR="$INSTALL_ROOT/backups"

if [[ -e "$ENV_PATH" && "$FORCE" -ne 1 ]]; then
  die ".env exists; refusing to overwrite secrets without --force."
fi

log "Creating directories with required permissions..."
mkdir -p "$DATA_DIR" "$BACKUPS_DIR"
chmod 700 "$DATA_DIR" "$BACKUPS_DIR"

# Generate secrets:
# - OPERATOR_KEY: base64url-ish (no slashes) so it’s easier to copy around
OPERATOR_KEY="$(openssl rand -base64 48 | tr -d '\n' | tr '+/' '-_' | tr -d '=')"

EXCHANGE_SALT="$(openssl rand -hex 16)"

# Deterministic EXCHANGE_ID derivation: sha256(base_url + "\n" + salt)
EXCHANGE_ID_HEX="$(printf '%s\n%s' "$CANONICAL_BASE_URL" "$EXCHANGE_SALT" | openssl dgst -sha256 -hex | awk '{print $2}')"
EXCHANGE_ID="ex_${EXCHANGE_ID_HEX:0:32}"

# Ed25519 keypair generation using openssl; store as base64 of DER blobs
TMP_PRIV="$(mktemp)"
TMP_PUB="$(mktemp)"

openssl genpkey -algorithm ed25519 -out "$TMP_PRIV" >/dev/null 2>&1
openssl pkey -in "$TMP_PRIV" -pubout -out "$TMP_PUB" >/dev/null 2>&1

FEDERATION_PRIVATE_KEY_B64="$(openssl base64 -A < "$TMP_PRIV")"
FEDERATION_PUBLIC_KEY_B64="$(openssl base64 -A < "$TMP_PUB")"

rm -f "$TMP_PRIV" "$TMP_PUB"

log "Writing .env (600 perms)..."
cat > "$ENV_PATH" <<EOF
# --- bread-exchange v0 install (generated) ---
CANONICAL_BASE_URL=${CANONICAL_BASE_URL}
EXCHANGE_SALT=${EXCHANGE_SALT}
EXCHANGE_ID=${EXCHANGE_ID}

# Operator-gated endpoints
OPERATOR_KEY=${OPERATOR_KEY}

# Federation keys (Ed25519)
FEDERATION_PRIVATE_KEY_B64=${FEDERATION_PRIVATE_KEY_B64}
FEDERATION_PUBLIC_KEY_B64=${FEDERATION_PUBLIC_KEY_B64}

# Federation endpoints enabled flag (behavior must be handled by app)
ENABLE_FEDERATION=${ENABLE_FEDERATION}

# Caddy / TLS
DOMAIN=${DOMAIN}
TLS_EMAIL=${TLS_EMAIL}
EOF

chmod 600 "$ENV_PATH"

# --- Bring up stack -----------------------------------------------------------
log "Bringing up Docker Compose stack..."
docker compose up -d --build

# --- Verification gates -------------------------------------------------------
log "Gating checks..."

# --- TLS wait loop -----------------------------------------------------------
# Caddy may still be obtaining a Let's Encrypt cert when we first check.
# We wait up to 120 seconds for https://$DOMAIN/api/health to succeed.
TLS_WAIT_SECONDS=120
TLS_WAIT_SLEEP=2
deadline=$(( $(date +%s) + TLS_WAIT_SECONDS ))

log "Waiting for TLS/health (up to ${TLS_WAIT_SECONDS}s)..."
health_ok=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  if curl -fsS "https://${DOMAIN}/api/health" | jq -e '.ok == true' >/dev/null 2>&1; then
    health_ok=1
    break
  fi
  sleep "$TLS_WAIT_SLEEP"
done

if [ "$health_ok" -ne 1 ]; then
  log "FAILED: /api/health gate (TLS did not become ready in time)"
  docker compose logs --no-color --tail 200 || true
  exit 1
fi

if ! curl -fsS "https://${DOMAIN}/federation/status" | jq -e 'type == "object"' >/dev/null; then
  log "FAILED: /federation/status gate"
  docker compose logs --no-color --tail 200 || true
  exit 1
fi

if [[ ! -x "$INSTALL_ROOT/tools/ui_smoke.sh" ]]; then
  log "FAILED: tools/ui_smoke.sh not found or not executable"
  docker compose logs --no-color --tail 200 || true
  exit 1
fi

if ! "$INSTALL_ROOT/tools/ui_smoke.sh" "$DOMAIN" "127.0.0.1"; then
  log "FAILED: ui_smoke gate"
  docker compose logs --no-color --tail 200 || true
  exit 1
fi

# --- Completion output (one-time secret display) -----------------------------
echo
echo "✅ Install complete"
echo "URL: https://${DOMAIN}"
echo "Exchange ID: ${EXCHANGE_ID}"
echo "Federation Public Key (B64): ${FEDERATION_PUBLIC_KEY_B64}"
echo
echo "ONE-TIME OPERATOR KEY (store safely):"
echo "${OPERATOR_KEY}"
echo
echo "NOTE: OPERATOR_KEY is stored in ${ENV_PATH} (600 perms). Do not lose control of this host."