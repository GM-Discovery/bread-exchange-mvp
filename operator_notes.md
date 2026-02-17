



You said:



Can you combine these three files into one, remove any redundancy and make it flow as one document without cutting any material that isn't duplicative?

ChatGPT said:
Below is a single unified document that merges:


OPERATOR_NOTES.updated



OPERATOR_NOTES



OPERATOR_NOTES.3


All redundant sections have been consolidated.
No non-duplicative material has been removed.
Contradictions (Basic Auth vs HMAC) have been resolved in favor of the current security model.

You can paste this directly into OPERATOR_NOTES.md.

Bread Exchange / Poll Stack — Unified Operator & Maintainer Notes
1) Scope and Purpose
This document describes how the Bread Exchange backend operates, how it is deployed, how it is secured, and how to safely rebuild, test, and reason about it.

It is intended for operators and maintainers, not end users.

The Exchange implements:

Stamp-based, weighted voting

Lifecycle-driven poll locking

Authoritative, server-side tallies

File-based persistence for auditability

Centralized configuration with deterministic fingerprinting

HMAC-signed write endpoints (Security v0)

Operator-gated administrative actions

Federation v0 (partner allowlisted commitments)

Frontend behavior is intentionally out of scope unless explicitly noted.

2) Repository, Paths, and Layout
Host Paths
/opt/bread-exchange-mvp/ — Exchange repository root

/opt/bread-exchange-mvp/data/ — Repo copies (NOT authoritative at runtime)

Container Paths
/app/ — Application code (baked into image)

/app/data/ — Persistent JSON state (bind-mounted, authoritative)

Authoritative Data Mount (Example)
Host:

/root/bread-exchange-data
Mounted to:

/app/data
Operational Rule:
Always inspect the mounted host directory backing /app/data.
Never assume repo /data reflects runtime state.

3) Key Code Files
server.js — Core routing, authority logic, weighted voting, ballot UID derivation, snapshot persistence

lib/lifecycle.js — Poll lifecycle transitions (open ? close ? cooldown ? finalize ? publish)

config.js — Centralized configuration defaults and fingerprinting

4) Runtime Data Files (/app/data)
exchange.private.json — Polls, votes, snapshots

identity.private.json — Personas, stamps

identity.state.json — Current identity state (weights, aliases)

identity.ledger.json — Append-only identity events

delegation.private.json — Delegation edges

identity.signing.private.json — Signing keys (Security v0)

federation.identity.private.json — Ed25519 keypair (private)

federation.partners.json — Allowlisted partners

federation.local_commitments.json — Local finalization commitments

federation.commitments.json — Received commitments + match state

federation.disputes.json — Challenge/proof transcripts

5) Deployment Model (Critical)
Application code is baked into the Docker image.

Only /app/data is mounted.

Editing source files on the host does nothing until the image is rebuilt.

Required After Any Code Change
docker compose up -d --build --force-recreate bread-exchange
Failure to rebuild is the most common operational mistake.

6) Request Flow and Authority Boundaries
Public Poll App
Browser
? Caddy (bread-poll-mvp-caddy-1)
? poll.breadstandard.com
? /api/* ? Poll API (Python)
? / ? Web container (static UI)

Exchange API
Browser / CLI
? Caddy
? exchange.breadstandard.com
? bread-exchange:8787
? Express (server.js)
? Lifecycle engine
? JSON persistence

A 401 from Caddy means the request never reached Express.

7) Voting Model (Authoritative Behavior)
First vote requires valid X-Stamp

Stamps carry numeric weight

Identity derived server-side

Client-supplied identity ignored

Tallies sum weights, not counts

Results expose:

people_voted

represented_people

weights_used { min, max, sum, count }

Stamp Lifecycle
Stamp is consumed on first vote

Revote allowed via X-Voter-Token

Stamp replay rejected

Revote does not consume additional stamps

Lifecycle:

assert ? stamp ? vote ? voter_token ? revote
8) Poll Lifecycle
OPINION
open ? closed ? archived
GOVERNANCE / LEGITIMACY
open ? closed ? cooldown ? finalized ? published
At finalization/publish:

Snapshot written exactly once

snapshot_results persisted

Future reads return snapshot

Further voting rejected

Transitions occur during route access (no cron).

9) Configuration System
Features:

Centralized in config.js

Defaults preserve behavior

Safe fallback on invalid config

Deterministic fingerprint at startup

GET /api/config introspection

Excludes:

Secrets

Signing keys

Operator keys

Salts or credentials

Security v0 — Signed Requests (HMAC) + Operator Key
Overview
Caddy Basic Auth has been removed.

Write endpoints require HMAC-signed requests.

Operator actions require both:

Valid HMAC signature

Valid operator key

Identity Secrets
Each identity has:

self_id
Stable identity secret

Sent via X-Self-ID

Stored server-side (hashed)

signing_key
Private HMAC key

Returned once at identity creation

Stored in identity.signing.private.json

Never returned again

Loss requires future rotation (not yet implemented).

Signed Request Contract
Required headers:

X-Self-ID
X-Timestamp
X-Nonce
X-Signature
Signature base string:

METHOD
PATH
TIMESTAMP
NONCE
SHA256(body)
HMAC-SHA256 with signing_key.

Replay Defense
±5 minute timestamp window

Nonce cache with TTL

Reject duplicate (self_id, nonce)

Per-process (single-node MVP)

Protected Endpoints (v0)
Endpoint	Protection
POST /api/stamp	HMAC
POST /api/delegation/set	HMAC
POST /api/delegation/revoke	HMAC
POST /api/identity/grant-trust	HMAC + Operator Key
Missing signature:

{ "error": "missing_signature_headers" }
Operator Key
Required for trust grants.

Setup
openssl rand -hex 32 | awk '{print "OPERATOR_KEY="$1}' > .env
chmod 600 .env
Ensure:

.env is gitignored

docker-compose references ${OPERATOR_KEY}

Responses:

Missing:

{ "error": "operator_key_missing" }
Invalid:

{ "error": "bad_operator_key" }
Valid:

200 OK
Fail-closed by design.

Federation v0 — Partner Allowlisted Commitments
Exchange supports signed commitments on poll finalization.

Required Env
CANONICAL_BASE_URL=https://exchange.example.com
Used to derive stable exchange_id.

Add Partner
Edit:

/app/data/federation.partners.json
Add:

{
  "exchange_id": "ex_...",
  "pubkey_b64": "...",
  "base_url": "https://partner.example.com",
  "status": "active"
}
Federation Endpoints
POST /federation/hello

POST /federation/polls/offer

POST /federation/polls/:poll_id/challenge

POST /federation/polls/:poll_id/proof

GET /federation/status

Commitments created at FINALIZED.

Replay defense includes:

Timestamp freshness

Nonce TTL

Rolling message_id window

Operational Commands
Rebuild (Required After Code Change)
docker stop bread-exchange
docker rm bread-exchange
docker compose build --no-cache
docker compose up -d --force-recreate
Restart Only
docker compose restart bread-exchange
Logs
docker logs bread-exchange --tail 200
Exec
docker exec -it bread-exchange sh
Health
wget -qO- http://127.0.0.1:8787/api/health
2026-02-14 — 403 Vote Loop Resolution
Symptom
Intermittent 403

Vote did not persist

Revote attempted stamp reuse

Lifecycle failed to transition to voter_token

Root Cause
bread-exchange container not actually replaced

container_name: prevented docker compose down from removing container

Old image continued running

Recovery Procedure
docker stop bread-exchange
docker rm bread-exchange
docker compose build --no-cache
docker compose up -d --force-recreate
Verification
docker exec -it bread-poll-mvp-caddy-1 sh -lc \
'curl -i http://bread-exchange:8787/api/polls'
docker exec -it bread-exchange sh -lc \
'grep -n "mintUpToTarget" /app/server.js'
Operational Lesson
When container_name: is explicitly set, docker compose down may not remove it.

Always verify running container contains expected code before debugging logic.

Test backend directly (bread-exchange:8787) to isolate UI vs backend faults.

Explicit Non-Goals (Deferred)
Frontend redesign

Delegation decay scheduler

Delta systems

Merkle trees

ZK proofs

Blockchain anchoring (future)

Cross-exchange delegation

Critical Reminder
Only /app/data is authoritative.
All application logic is baked into the Docker image.
Rebuild after code changes.
Verify container contents before debugging behavior.


