"use strict";

/**
 * In-memory token bucket rate limiter (MVP).
 * - Resets on restart
 * - No external deps
 */

function nowMs() { return Date.now(); }

function makeBucket({ capacity, refillPerSec }) {
  return { capacity, refillPerSec, tokens: capacity, lastMs: nowMs() };
}

function refill(bucket) {
  const t = nowMs();
  const elapsedSec = Math.max(0, (t - bucket.lastMs) / 1000);
  bucket.lastMs = t;

  const add = elapsedSec * bucket.refillPerSec;
  bucket.tokens = Math.min(bucket.capacity, bucket.tokens + add);
}

function take(bucket, cost) {
  refill(bucket);
  if (bucket.tokens >= cost) {
    bucket.tokens -= cost;
    return true;
  }
  return false;
}

const buckets = new Map(); // key -> bucket

function rateLimit({ key, capacity, refillPerSec, cost }) {
  const k = String(key || "");
  if (!k) return { ok: true };

  let b = buckets.get(k);
  if (!b) {
    b = makeBucket({ capacity, refillPerSec });
    buckets.set(k, b);
  }

  const ok = take(b, Number(cost || 1));
  return ok ? { ok: true } : { ok: false };
}

module.exports = { rateLimit };
