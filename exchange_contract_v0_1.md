# Exchange_Network_Node_Contract_v0_1

## Purpose
Defines the network node message and store contract that exchanges must agree on to interoperate safely.

Network nodes are hereby referred to their legacy name "federation" to avoid whitespace confusion. (See /lib)

## Signed envelope rule (all signed network messages)
- The signature is Ed25519 over UTF-8(sha256_hex(canonical_json(unsigned_payload))).
- canonical_json is the exchange-locked canonical serializer used by exchange network (keys sorted at all depths, undefined omitted).

## Protocol identity fields (must be present in signed bodies for v2)
- protocol_version
- min_supported_version
- contract_id
- contract_hash

## Commitment v2 (signed body fields)
- poll_id
- final_tally_hash
- override_delta_hash
- represented_map_hash
- finalized_at
- published_at
- ts
- exchange_id
- canonical_base_url
- protocol_version
- min_supported_version
- contract_id
- contract_hash