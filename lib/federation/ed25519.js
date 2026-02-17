"use strict";

/**
 * ed25519.js
 *
 * Purpose:
 * - Load our Ed25519 keys from env (base64 DER)
 * - Verify partner signatures using allowlisted public keys
 *
 * Env:
 * - FEDERATION_PRIVATE_KEY_B64  (PKCS8 DER, base64)
 * - FEDERATION_PUBLIC_KEY_B64   (SPKI DER, base64)  (optional but useful)
 *
 * Notes:
 * - We use node:crypto KeyObjects. No external deps.
 * - We sign/verify the SHA256 hex of canonical JSON (see canonical.js).
 */

const crypto = require("crypto");

function b64ToBuf(b64) {
  if (!b64 || typeof b64 !== "string") return null;
  try {
    return Buffer.from(b64, "base64");
  } catch {
    return null;
  }
}

function loadPrivateKeyFromEnv() {
  const b64 = process.env.FEDERATION_PRIVATE_KEY_B64 || "";
  const der = b64ToBuf(b64);
  if (!der || der.length < 32) return null;

  try {
    return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  } catch {
    return null;
  }
}

function loadPublicKeyFromB64(b64) {
  const der = b64ToBuf(b64);
  if (!der || der.length < 32) return null;

  try {
    return crypto.createPublicKey({ key: der, format: "der", type: "spki" });
  } catch {
    return null;
  }
}

function loadOurPublicKeyFromEnv() {
  const b64 = process.env.FEDERATION_PUBLIC_KEY_B64 || "";
  return loadPublicKeyFromB64(b64);
}

/**
 * We sign bytes, not strings.
 * We will sign the UTF-8 bytes of the canonical hash hex string.
 */
function signHashHex(hashHex, privateKey) {
  if (!privateKey) throw new Error("missing_private_key");
  const msg = Buffer.from(String(hashHex), "utf8");
  const sig = crypto.sign(null, msg, privateKey); // Ed25519 ignores hash algorithm parameter
  return sig.toString("base64");
}

function verifyHashHex(hashHex, signatureB64, publicKey) {
  if (!publicKey) return false;
  if (!signatureB64) return false;

  let sigBuf;
  try {
    sigBuf = Buffer.from(String(signatureB64), "base64");
  } catch {
    return false;
  }

  const msg = Buffer.from(String(hashHex), "utf8");
  try {
    return crypto.verify(null, msg, publicKey, sigBuf);
  } catch {
    return false;
  }
}

module.exports = {
  loadPrivateKeyFromEnv,
  loadOurPublicKeyFromEnv,
  loadPublicKeyFromB64,
  signHashHex,
  verifyHashHex,
};
