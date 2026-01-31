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