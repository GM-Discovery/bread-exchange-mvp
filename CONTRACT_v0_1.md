# Bread Standard Governance App ↔ Exchange Contract (v0.1)

This is a **non-magical, auditable** contract that fixes the boundary between:

- **Governance App**: UI + human workflow (proposals, impact, deliberation UX)
- **Exchange**: canonical records + receipts/proofs + federation substrate

This v0.1 is intentionally minimal to support your existing front-end (polls + SSE), while reserving stable shapes for:
- trust allocations
- validator councils
- credential claims (“matches”) & weighting policies
- protected voices artifacts
- review/override windows
- federation

---

## 0. Canonical vocabulary (constitutional-first)

### Councils (required)
The constitution defines **mandatory validator councils** beginning with life-necessities (Air, Water, Land/Agriculture, Shelter/Housing, etc.), and also defines special structures like a **civil defense / unified defense command panel** with civilian oversight requirements.

**Contract implication:** “CouncilDomain” must be first-class and referenced by proposals, validators, and weighting policies.

> In v0.1, we include the type, but we do not hardcode the full list in the API responses yet.

---

## 1. Entities (minimal shapes)

### 1.1 Proposal (a/k/a Poll in the current UI)
Required:
- id (string)
- title (string)
- description (string)
- status ("open" | "closed")
- options: [{id, label}]
- created_at (ISO timestamp)

Reserved (future):
- domains: CouncilDomain[]
- weighting_policy_id
- protected_voices_config_id
- review_window_config_id
- impact_assessment_id

### 1.2 VoteRecord
Required:
- id
- proposal_id
- option_id
- voter_token (device receipt token; v0.1)
- created_at

Reserved:
- computed_weight (number)
- claims_snapshot_hash
- validator_route (who validated which claims, if applicable)
- receipt_hash (for later anchoring)
- signatures (validator/exchange)

### 1.3 Results
- totals: { option_id: number }  (v0.1: unweighted counts)
- total_votes: number

Reserved:
- weighted_totals
- dual tallies (expert vs civic)

---

## 2. API endpoints (v0.1)

### GET /api/health
**Response**
{ ok: true, time: ISO }

### GET /api/polls
**Response**
{ polls: ProposalWithResults[] }

### POST /api/polls
**Request**
{ title, description?, type?, options: [{id?, label}], meta? }

**Response**
{ poll: Proposal }

### POST /api/polls/:id/vote
**Request**
{ option_id, voter_token?, meta? }

**Response**
{ ok: true, voter_token, results }

### GET /api/polls/:id/stream  (Server-Sent Events)
Sends events:
- event: "poll"    data: { kind: "snapshot" | "poll_created", poll, results }
- event: "results" data: { poll_id, results }

---

## 3. Non-negotiable invariants (anti-magic)

1) **Receipts exist**
- Voter gets a stable `voter_token` for the vote they cast (v0.1: device token)
- Future: replace/augment with cryptographic receipt proofs

2) **Canonical record lives in the Exchange**
- Governance app may cache, but exchange is the authoritative store

3) **Policy hash freeze (future)**
- Weighting policy + protected voices config + review window rules must be hashable and stored so tallies can be audited later

---

## 4. Next expansion set (v0.2 targets)

### 4.1 Claim/Match attestation (doctor, civil engineer, etc.)
- POST /api/claims/request
- POST /api/claims/attest  (validator only)
- POST /api/claims/revoke  (issuer only)
- GET  /api/claims/my
- GET  /api/claims/verify

### 4.2 Weighting policy on proposals
- POST /api/polls with `domains[]` + `weighting_policy`
- Exchange computes `computed_weight` per vote at cast-time

### 4.3 Protected voices artifacts
- minority-trigger events, required response logs, deliberation extension records

### 4.4 Federation
- pull/push sync with signed batches
- conflict resolution rules

---

## 5. Operator transparency requirement (manual hook)
Every endpoint and entity above must have a plain-language explanation for:
- what it stores
- what it proves
- what can be audited by a voter
- what can be audited by a validator council

This contract is the spine of that operator manual.
