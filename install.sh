#!/usr/bin/env bash
set -euo pipefail

# Bread Exchange — installer v0.1.6 hardening
# - Deterministic tag pinning (explicit tag OR latest signed semver)
# - Tag signature verification (GPG) against tools/release_signers.txt in the tag
# - Optional ACME staging toggle (Caddy)
#
# Intended usage (two-command friendly):
#   curl -fsSL <RAW_GITHUB_URL>/install.sh | sudo bash -s -- --domain exchange.example.com
#   # or pin:
#   curl -fsSL <RAW_GITHUB_URL>/install.sh | sudo bash -s -- --domain exchange.example.com --tag v0.1.6
#   # staging:
#   curl -fsSL <RAW_GITHUB_URL>/install.sh | sudo bash -s -- --domain exchange.example.com --acme-staging

# === Maintainer constants ===
# Set this to the canonical GitHub repo for releases.
REPO_URL_DEFAULT="https://github.com/GM-Discovery/bread-exchange-mvp.git"
INSTALL_DIR_DEFAULT="/opt/bread-exchange-mvp"

ACME_PROD_CA="https://acme-v02.api.letsencrypt.org/directory"
ACME_STAGING_CA="https://acme-staging-v02.api.letsencrypt.org/directory"

usage() {
  cat <<USAGE
Usage:
  sudo bash install.sh --domain <exchange.domain> [--tag vX.Y.Z] [--acme-staging] [--repo <git_url>] [--dir <install_dir>]

Required:
  --domain <fqdn>         Domain name Caddy should serve (e.g. exchange.example.com)

Optional:
  --tag vX.Y.Z            Install an exact semver tag (strict). If omitted, installer selects latest signed semver tag.
  --acme-staging          Use Let's Encrypt staging CA (for repeated test installs).
  --repo <git_url>        Override repo URL (defaults to maintainer constant).
  --dir <path>            Install directory (default: /opt/bread-exchange-mvp)

Notes:
  - This installer FAILS if the selected tag is not GPG-signed by an allowlisted key.
  - Allowlist is read from: tools/release_signers.txt (from inside the tag).
USAGE
}

fail() { echo "FAIL: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Missing dependency: $1"; }

DOMAIN=""
TAG=""
ACME_CA=""
REPO_URL="${REPO_URL_DEFAULT}"
INSTALL_DIR="${INSTALL_DIR_DEFAULT}"

# --- args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2;;
    --tag) TAG="${2:-}"; shift 2;;
    --acme-staging) ACME_CA="$ACME_STAGING_CA"; shift 1;;
    --repo) REPO_URL="${2:-}"; shift 2;;
    --dir) INSTALL_DIR="${2:-}"; shift 2;;
    -h|--help) usage; exit 0;;
    *) fail "Unknown arg: $1";;
  esac
done

[[ -n "$DOMAIN" ]] || { usage; fail "--domain is required"; }

# If maintainer forgot to set REPO_URL_DEFAULT, force the operator to pass --repo.
[[ "$REPO_URL" != "REPO_URL_NOT_SET" ]] || fail "Installer maintainer must set REPO_URL_DEFAULT, or operator must pass --repo <git_url>."

# Default ACME CA is production unless staging requested.
if [[ -z "${ACME_CA}" ]]; then
  ACME_CA="$ACME_PROD_CA"
fi

# Root required (we write to /opt and install packages in some environments)
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  fail "Run as root (use sudo)."
fi

# --- deps ---
need curl
need git
need docker

# docker compose can be either "docker compose" (plugin) or "docker-compose" (legacy)
DOCKER_COMPOSE_BIN=""
if docker compose version >/dev/null 2>&1; then
  DOCKER_COMPOSE_BIN="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DOCKER_COMPOSE_BIN="docker-compose"
else
  fail "Missing dependency: docker compose (plugin) or docker-compose"
fi

# We require GPG for signature verification.
need gpg

# --- helpers ---
require_strict_tag_or_empty() {
  local t="$1"
  if [[ -z "$t" ]]; then return 0; fi
  [[ "$t" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "Tag must be strict semver like v0.1.6 (got: $t)"
}

normalize_fp() {
  # Normalize fingerprint to uppercase hex with no spaces.
  tr -d '[:space:]' | tr '[:lower:]' '[:upper:]'
}

select_latest_signed_semver_tag() {
  # We select the highest semver by sorting tags.
  # NOTE: This only chooses based on tag names; signature verification is enforced later.
  git tag -l 'v[0-9]*.[0-9]*.[0-9]*' | sort -V | tail -n 1
}

verify_tag_signature_and_allowlist() {
  local tag="$1"

  # Import release signing public key so "git tag -v" can verify on a fresh VPS.
  if git show "${tag}:tools/release_pubkey.asc" >/dev/null 2>&1; then
    git show "${tag}:tools/release_pubkey.asc" | gpg --import >/dev/null 2>&1 || true
  elif [ -f "tools/release_pubkey.asc" ]; then
    gpg --import tools/release_pubkey.asc >/dev/null 2>&1 || true
  fi

  # 1) Verify tag has a valid GPG signature.
  # git tag -v prints to stderr; capture all output.
  local out
  if ! out=$(git tag -v "$tag" 2>&1); then
    echo "$out" >&2
    fail "Tag signature verification failed (missing/invalid signature?) for $tag"
  fi

  # Extract fingerprint line if present.
  local fp
  fp=$(echo "$out" | grep -E "Primary key fingerprint" -m 1 | sed -E 's/.*=\s*//' || true)
  if [[ -z "$fp" ]]; then
    echo "$out" >&2
    fail "Could not extract signer fingerprint from 'git tag -v' output. Refusing to install."
  fi

  local fp_norm
  fp_norm=$(echo "$fp" | normalize_fp)

  # 2) Load allowlist FROM THE TAG (so installs can be audited per-release).
  local allow
  if ! allow=$(git show "${tag}:tools/release_signers.txt" 2>/dev/null); then
    fail "Missing tools/release_signers.txt in tag ${tag} (required for release integrity gate)."
  fi

  # Normalize allowlist lines and look for exact fingerprint match.
  local match=""
  match=$(echo "$allow" \
    | sed 's/#.*$//' \
    | sed '/^\s*$/d' \
    | normalize_fp \
    | grep -Fx "$fp_norm" || true)

  if [[ -z "$match" ]]; then
    echo "Signer fingerprint: $fp_norm" >&2
    echo "Allowlist (tools/release_signers.txt in tag $tag):" >&2
    echo "$allow" >&2
    fail "Signer fingerprint not allowlisted. Refusing to install."
  fi

  echo "$fp_norm"
}

# --- begin ---
require_strict_tag_or_empty "$TAG"

TMP=""
cleanup() { [[ -n "$TMP" && -d "$TMP" ]] && rm -rf "$TMP" || true; }
trap cleanup EXIT

TMP=$(mktemp -d)
cd "$TMP"

git init -q
git remote add origin "$REPO_URL"

# Fetch all tags (need tag objects for signature verification)
if ! git fetch --tags --force --prune origin >/dev/null 2>&1; then
  fail "Failed to fetch tags from $REPO_URL"
fi

if [[ -z "$TAG" ]]; then
  TAG=$(select_latest_signed_semver_tag)
  [[ -n "$TAG" ]] || fail "No semver tags found in repo."
  echo "Selected latest semver tag: $TAG"
fi

# Tag existence gate
if ! git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
  fail "Tag does not exist: ${TAG}"
fi

# Read allowlist fingerprints from the tag (ignore comments/blank lines),
# normalize to HEX ONLY so prefixes can't break installs.
allowlist_hex="$(git show "${TAG}:tools/release_signers.txt" \
  | sed 's/\r$//' \
  | sed '/^\s*#/d;/^\s*$/d' \
  | tr -cd '0-9A-Fa-f\n' \
  | tr '[:lower:]' '[:upper:]')"

# Signature + allowlist gate
signer_fp="$(verify_tag_signature_and_allowlist "$TAG")"

signer_fp="$(echo "$signer_fp" | tr -cd '0-9A-Fa-f' | tr '[:lower:]' '[:upper:]')"

if ! echo "$allowlist_hex" | grep -qx "$signer_fp"; then
  fail "Signer fingerprint not allowlisted. Refusing to install."
fi

# Resolve commit hash for receipt
COMMIT_SHA=$(git rev-list -n 1 "$TAG")

echo "Release Integrity OK"
echo "- repo:   $REPO_URL"
echo "- tag:    $TAG"
echo "- commit: $COMMIT_SHA"
echo "Signer fingerprint: $signer_fp"

# --- checkout/install ---
mkdir -p "$(dirname "$INSTALL_DIR")"

if [[ -d "$INSTALL_DIR/.git" ]]; then
  echo "Existing install found at $INSTALL_DIR — updating to $TAG"
  cd "$INSTALL_DIR"
  git remote set-url origin "$REPO_URL"
  git fetch --tags --force --prune origin
  git checkout -f "$TAG"
else
  echo "Cloning into $INSTALL_DIR"
  git clone "$REPO_URL" "$INSTALL_DIR"
  cd "$INSTALL_DIR"
  git checkout -f "$TAG"
fi

# Safety: show receipt again from the checked-out repo
ORIGIN_URL=$(git config --get remote.origin.url || true)
RESOLVED_SHA=$(git rev-parse HEAD)

echo ""
echo "Install Receipt"
echo "- origin: $ORIGIN_URL"
echo "- tag:    $TAG"
echo "- commit: $RESOLVED_SHA"
echo "- signer: $SIGNER_FP"
echo ""

# --- write .env ---
ENV_FILE="$INSTALL_DIR/.env"

if [[ ! -f "$ENV_FILE" ]]; then
  umask 077
  cat > "$ENV_FILE" <<ENV
# Bread Exchange runtime env
# Generated by install.sh
DOMAIN=$DOMAIN
ACME_CA=$ACME_CA
ENV
  chmod 600 "$ENV_FILE" || true
else
  grep -q '^DOMAIN=' "$ENV_FILE" && sed -i "s/^DOMAIN=.*/DOMAIN=$DOMAIN/" "$ENV_FILE" || echo "DOMAIN=$DOMAIN" >> "$ENV_FILE"
  grep -q '^ACME_CA=' "$ENV_FILE" && sed -i "s%^ACME_CA=.*%ACME_CA=$ACME_CA%" "$ENV_FILE" || echo "ACME_CA=$ACME_CA" >> "$ENV_FILE"
fi

# --- compose up ---
cd "$INSTALL_DIR"
$DOCKER_COMPOSE_BIN up -d --build

echo ""
echo "Done. Next checks:"
echo "- curl -fsS https://$DOMAIN/api/health"