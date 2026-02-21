"use strict";

/**
 * verify.js
 *
 * Canonical signing/verification wrappers (Phase 0.1 lock).
 *
 * IMPORTANT:
 * - Input semantics must match existing behavior for backward compatibility.
 *   Current semantics are:
 *     commitment_hash_hex = SHA256_HEX( canonicalStringify(unsignedObj) )
 *     signature = Ed25519Sign( UTF8(commitment_hash_hex) )
 *
 * This module exists to:
 * - ensure every sign/verify flows through the same canonical bytes
 * - reject accidental signing/verifying of objects that already contain "signature"
 */

const crypto = require("crypto");
const { canonicalHashHex } = require("./canonical");
const { signHashHex, verifyHashHex } = require("./ed25519");

function hasOwn(obj, k) {
  return !!(obj && typeof obj === "object" && Object.prototype.hasOwnProperty.call(obj, k));
}

function assertUnsignedObject(unsignedObj) {
  if (!unsignedObj || typeof unsignedObj !== "object") {
    throw new Error("unsigned_payload_not_object");
  }
  if (hasOwn(unsignedObj, "signature")) {
    throw new Error("unsigned_payload_contains_signature");
  }
}

function assertHashHexLikeSha256(hashHex) {
  const h = String(hashHex || "");
  if (!/^[0-9a-f]{64}$/.test(h)) {
    throw new Error("hash_not_sha256_hex");
  }
  return h;
}

function toPrivateKey(privKeyOrB64) {
  if (!privKeyOrB64) return null;
  if (typeof privKeyOrB64 !== "string") return privKeyOrB64; // assume KeyObject

  try {
    const der = Buffer.from(String(privKeyOrB64), "base64");
    return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  } catch {
    return null;
  }
}

function toPublicKey(pubKeyOrB64) {
  if (!pubKeyOrB64) return null;
  if (typeof pubKeyOrB64 !== "string") return pubKeyOrB64; // assume KeyObject

  try {
    const der = Buffer.from(String(pubKeyOrB64), "base64");
    return crypto.createPublicKey({ key: der, format: "der", type: "spki" });
  } catch {
    return null;
  }
}

function commitmentHashHex(unsignedObj) {
  assertUnsignedObject(unsignedObj);
  return canonicalHashHex(unsignedObj);
}

function signCommitment(unsignedObj, privKeyOrB64) {
  assertUnsignedObject(unsignedObj);
  const priv = toPrivateKey(privKeyOrB64);
  if (!priv) throw new Error("missing_private_key");

  const hashHex = assertHashHexLikeSha256(canonicalHashHex(unsignedObj));
  return signHashHex(hashHex, priv);
}

function verifyCommitment(unsignedObj, signatureB64, pubKeyOrB64) {
  assertUnsignedObject(unsignedObj);
  const pub = toPublicKey(pubKeyOrB64);
  if (!pub) return false;

  const hashHex = assertHashHexLikeSha256(canonicalHashHex(unsignedObj));
  return verifyHashHex(hashHex, signatureB64, pub);
}

function signCommitmentHashHex(hashHex, privKeyOrB64) {
  const priv = toPrivateKey(privKeyOrB64);
  if (!priv) throw new Error("missing_private_key");
  return signHashHex(assertHashHexLikeSha256(hashHex), priv);
}

function verifyCommitmentHashHex(hashHex, signatureB64, pubKeyOrB64) {
  const pub = toPublicKey(pubKeyOrB64);
  if (!pub) return false;
  return verifyHashHex(assertHashHexLikeSha256(hashHex), signatureB64, pub);
}

module.exports = {
  commitmentHashHex,
  signCommitment,
  verifyCommitment,
  signCommitmentHashHex,
  verifyCommitmentHashHex,
};