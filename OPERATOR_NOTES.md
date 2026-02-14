All good — here is the third-person, neutral maintainer version of the operator notes. Same substance, different voice. You can paste this directly into OPERATOR_NOTES.md.

OPERATOR_NOTES.md

Bread Exchange / Poll Stack — Operator & Maintainer Notes

1) Scope and purpose

This document describes how the Bread Exchange backend currently operates, how it is deployed, and how to safely rebuild, test, and reason about it.

It is intended for operators and maintainers, not end users.

The Exchange implements:

stamp-based, weighted voting

lifecycle-driven poll locking

authoritative, server-side tallies

file-based persistence for auditability

a centralized configuration system with safe introspection

Frontend behavior is intentionally out of scope.

2) Repository, paths, and layout
Host paths
/opt/bread-exchange-mvp/        # Exchange repository root
/opt/bread-exchange-mvp/data/  # Persistent data directory

Container paths
/app/       # Application code (baked into image)
/app/data/  # Persistent JSON state (mounted)

Key files

server.js

core routing and authority logic

weighted voting enforcement

ballot UID derivation

snapshot persistence

config loading and fingerprinting

lib/lifecycle.js

poll lifecycle transitions

finalize / publish semantics

config.js

centralized configuration defaults

Runtime data:

data/exchange.private.json (polls, votes, snapshots)

data/identity.private.json (personas, stamps)

3) Deployment model (critical)

Application code is baked into the Docker image.

Only the data directory is bind-mounted:

/opt/bread-exchange-mvp/data → /app/data

Operational implication

Editing source files on the host does not affect the running Exchange until the image is rebuilt.

Required command after any code change
docker compose up -d --build bread-exchange


Failure to rebuild is the most common operational error.

4) Request flow and authority boundaries
Public poll application
browser
  → Caddy (bread-poll-mvp-caddy-1)
    → poll.breadstandard.com
      → /api/* → Poll API (Python)
      → /      → Web container (static UI)

Exchange API
browser / CLI
  → Caddy
    → exchange.breadstandard.com
      → bread-exchange:8787
        → Express (server.js)
          → lifecycle.js
          → JSON persistence

Authentication enforcement (Caddy)

POST /api/stamp → Basic Auth required

All write methods (POST/PUT/PATCH/DELETE) → Basic Auth required

POST /api/polls/{id}/vote → explicitly public

Most GET requests → public

A 401 Basic response means the request was blocked by Caddy and never reached the Exchange.

5) Voting model (authoritative behavior)

Votes must include a valid X-Stamp header

Stamps carry a numeric weight

Ballot identity is derived server-side

Vote tallies sum weights, not counts

Results expose audit-oriented fields:

people_voted

represented_people

weights_used { min, max, sum, count }

Invalid, missing, or non-positive weights invalidate the stamp and reject the vote

Client-supplied voter identity is ignored. The Exchange is authoritative.

6) Poll lifecycle and snapshots

For LEGITIMACY / GOVERNANCE polls, the lifecycle is:

open → closed → cooldown → finalized → published


At finalization/publish:

results are snapshotted exactly once

snapshot_results are persisted to exchange.private.json

future reads return the snapshot

further voting attempts are rejected (HTTP 400)

Lifecycle transitions are evaluated when routes are accessed (no cron job).

7) Configuration system
Features

Centralized configuration in config.js

Defaults preserve prior behavior exactly

Missing or invalid config falls back safely

Deterministic fingerprint computed at startup

Safe introspection endpoint:

GET /api/config


Returns:

{
  "fingerprint": "sha256:…",
  "config": {
    "stamps": {...},
    "lifecycle": {...}
  }
}

Explicit exclusions

Secrets, credentials, salts, tokens, and keys are never exposed.

8) Operational commands
Rebuild Exchange
docker compose up -d --build bread-exchange

Restart without rebuild
docker compose restart bread-exchange

Inspect logs (fingerprint)
docker logs bread-exchange | grep fingerprint

Exec into container
docker exec -it bread-exchange sh

Health check
wget -qO- http://127.0.0.1:8787/api/health

Config introspection
wget -qO- http://127.0.0.1:8787/api/config

Stamp issuance (inside container)
wget -qO- http://127.0.0.1:8787/api/stamp

Create poll
wget -qO- \
  --header='Content-Type: application/json' \
  --post-data='{"title":"Test","options":["A","B"],"meta":{"tags":["legitimacy"]}}' \
  http://127.0.0.1:8787/api/polls

Vote
wget -qO- \
  --header='X-Stamp: <STAMP>' \
  --header='Content-Type: application/json' \
  --post-data='{"option_id":"1"}' \
  http://127.0.0.1:8787/api/polls/<POLL_ID>/vote

9) Common failure modes

Code changes have no effect

Cause: image not rebuilt

Fix: rebuild with --build

401 Basic errors

Cause: blocked by Caddy

Fix: supply correct auth or test inside container

Host cannot reach :8787

Cause: port not published

Fix: exec into container or use proxy domain

Results mutate after close

Cause: snapshot not written

Fix: verify publish state and snapshot persistence

10) Explicit non-goals (deferred)

Frontend work

Delegation or councils

Delta systems

Federation

Ledger / blockchain

ZK proofs or Merkle trees

Stamp rotation enforcement (config knob exists only)

11) Critical operational reminder

Only /data is mounted.
All application code is baked into the image and requires a rebuild to change behavior.

---

## Security v0 � Signed Requests (HMAC) + Operator Key

### Overview

Basic Auth has been removed.

Sensitive Exchange endpoints now require **HMAC-signed requests** tied to an identity�s
private `signing_key`. Operator-grade actions additionally require an **operator key**
provided via environment variable.

This design enforces:
- explicit authorization
- replay protection
- fail-closed behavior for operator power

---

### Identity Secrets

Each identity has two secrets:

- `self_id`
  - Stable identity secret
  - Used to identify *which* identity is making a request
  - Sent via `X-Self-ID` header
  - Stored server-side **hashed**

- `signing_key`
  - Private signing secret (HMAC)
  - Generated at identity creation
  - Returned **once**
  - Used only to sign API requests
  - Stored server-side in `data/identity.signing.private.json`
  - Never returned again

Loss of `signing_key` requires future recovery/rotation (not yet implemented).

---

### Signed Request Contract (HMAC)

Protected endpoints require the following headers:

X-Self-ID: <self_id>
X-Timestamp: <unix milliseconds>
X-Nonce: <random string>
X-Signature: <hex HMAC-SHA256>


#### Signature Base String



METHOD
PATH
TIMESTAMP
NONCE
SHA256(body)


Example:



POST
/api/stamp
1707535000123
ab12cd34ef56
e3b0c44298fc1c149afbf4c8996fb924...


HMAC key = `signing_key`

---

### Replay Defense

- Timestamp must be within �5 minutes of server time
- Nonces are cached in memory with TTL
- Reuse of the same `(self_id, nonce)` within the window is rejected

Note: replay cache is per-process (single-node MVP).

---

### Protected Endpoints (v0)

| Endpoint | Protection |
|--------|------------|
| `POST /api/stamp` | HMAC signature |
| `POST /api/delegation/set` | HMAC signature |
| `POST /api/delegation/revoke` | HMAC signature |
| `POST /api/identity/grant-trust` | HMAC + Operator Key |

Unsigned requests return:


401 { "error": "missing_signature_headers" }


---

### Operator Key

Operator power (e.g. trust grants) requires **both**:
- valid HMAC signature
- valid operator key

The operator key is **not** stored in the repo.

#### Setup

1) Create `.env` in the exchange directory:

```bash
openssl rand -hex 32 | awk '{print "OPERATOR_KEY="$1}' > .env
chmod 600 .env


Ensure .env is git-ignored.

docker-compose.yml must reference:

environment:
  - OPERATOR_KEY=${OPERATOR_KEY}

Behavior

OPERATOR_KEY missing:

503 { "error": "operator_key_missing" }


Wrong operator key:

403 { "error": "bad_operator_key" }


Correct operator key:

200 OK


This endpoint fails closed by design.

Notes for Operators

Do not commit operator keys

Rotate operator keys by regenerating .env and recreating container

Admin UI will later prompt for operator key locally (never sent to server except per request)

Caddy Basic Auth is no longer used

Caddyfile comments must use # (not //)

Here�s a clean Operator Notes update section you can paste directly into OPERATOR_NOTES.updated.md (or merge into main notes).

?? 2026-02-14 � 403 Vote Loop Resolution
Symptom

Voting returned intermittent 403

Selection did not immediately reflect after assertion

Revotes attempted to use missing stamp

System failed to transition to voter_token lifecycle

Root Cause

/api/polls and /api/polls/:id/vote are served by bread-exchange:8787

Rebuilding bread-poll-mvp does not affect vote behavior.

bread-exchange container was not actually replaced after rebuild.

container_name: bread-exchange caused docker compose down to leave the container intact.

Old image continued running.

Stamp issuance logic had structural issues (now corrected), but fix was not active until proper container removal.

Correct Recovery Procedure

From /opt/bread-exchange-mvp:

docker stop bread-exchange
docker rm bread-exchange
docker compose build --no-cache
docker compose up -d --force-recreate

Verification Commands

Confirm exchange is serving polls:

docker exec -it bread-poll-mvp-caddy-1 sh -lc \
'curl -i http://bread-exchange:8787/api/polls'


Confirm patched server.js is live:

docker exec -it bread-exchange sh -lc \
'grep -n "mintUpToTarget" /app/server.js'

Lifecycle Validation (Post-Fix)

Confirmed working:

First vote consumes 1 stamp

Server issues voter_token

Revote uses X-Voter-Token

No additional stamp consumed

Refresh persists vote state

No 403 on toggle

Lifecycle restored:

assert ? stamp ? vote ? voter_token ? revote

Operational Lesson

When container_name: is explicitly set, docker compose down may not remove it.

Always verify running container contains expected code before debugging logic.

Use direct curl against internal service (bread-exchange:8787) to isolate UI vs backend faults.

Technical Stuff:

root@The-Bread-Standard-First-Exchange:/opt/bread-poll-mvp# docker compose config | sed -n '/bread-exchange:/,/^[^ ]/p'
  bread-exchange:
    build:
      context: /opt/bread-exchange-mvp
      dockerfile: Dockerfile
    container_name: bread-exchange
    expose:
      - "8787"
    networks:
      default: null
    restart: unless-stopped
    volumes:
      - type: bind
        source: /root/bread-exchange-data
        target: /app/data
        bind: {}
  caddy:
    depends_on:
      api:
        condition: service_started
        required: true
      web:
        condition: service_started
        required: true
    image: caddy:alpine
    networks:
      default: null
    ports:
      - mode: ingress
        target: 80
        published: "80"
        protocol: tcp
      - mode: ingress
        target: 443
        published: "443"
        protocol: tcp
    restart: unless-stopped
    volumes:
      - type: bind
        source: /opt/bread-poll-mvp/Caddyfile
        target: /etc/caddy/Caddyfile
        bind: {}
      - type: volume
        source: caddy_data
        target: /data
        volume: {}
      - type: volume
        source: caddy_config
        target: /config
        volume: {}
  db:
    container_name: bread_poll_db
    environment:
      POSTGRES_DB: breadpoll
      POSTGRES_PASSWORD: breadpoll_dev_password
      POSTGRES_USER: breadpoll
    image: postgres:16
    networks:
      default: null
    restart: unless-stopped
    volumes:
      - type: volume
        source: db_data
        target: /var/lib/postgresql/data
        volume: {}
  web:
    container_name: bread_poll_web
    image: nginx:alpine
    networks:
      default: null
    ports:
      - mode: ingress
        target: 80
        published: "8080"
        protocol: tcp
    restart: unless-stopped
    volumes:
      - type: bind
        source: /opt/bread-poll-mvp/web
        target: /usr/share/nginx/html
        read_only: true
        bind: {}
      - type: bind
        source: /opt/bread-poll-mvp/nginx/default.conf
        target: /etc/nginx/conf.d/default.conf
        read_only: true
        bind: {}
networks: