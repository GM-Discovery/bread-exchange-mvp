"use strict";

/**
 * Poll lifecycle helpers.
 * Keep lifecycle + visibility rules out of server.js so core routing stays stable.
 *
 * States (OPINION):   open -> closed -> archived
 * States (GOVERNANCE): open -> closed -> cooldown -> finalized -> published
 *
 * Note: "published" currently means "exchange-immutable record created".
 * Chain anchoring is a later step.
 */

const DEFAULTS = {
  OPINION_RETENTION_SECONDS: 7 * 24 * 60 * 60,        // 7 days
  GOVERNANCE_RETENTION_SECONDS: 30 * 24 * 60 * 60,    // 30 days
  GOVERNANCE_COOLDOWN_SECONDS: 60 * 60,               // 1 hour (fallback)
};

function nowIso() {
  return new Date().toISOString();
}

function parseIso(s) {
  if (!s) return null;
  const d = new Date(String(s));
  if (Number.isNaN(d.getTime())) return null;
  return d;
}

function addSeconds(isoString, seconds) {
  const d = parseIso(isoString);
  if (!d) return null;
  const ms = Number(seconds) * 1000;
  if (!Number.isFinite(ms)) return null;
  return new Date(d.getTime() + ms).toISOString();
}

function ensureClass(poll) {
  // Allow tag-driven classification without requiring UI work.
  const tags = (poll && poll.meta && Array.isArray(poll.meta.tags)) ? poll.meta.tags : [];
  const hasLegitimacyTag = tags.includes("legitimacy");

  // If unset, infer from tag; otherwise keep existing.
  if (!poll.poll_class) {
    poll.poll_class = hasLegitimacyTag ? "LEGITIMACY" : "OPINION";
  }

  // Validate allowed classes (keep unknowns from poisoning lifecycle logic).
  if (poll.poll_class !== "OPINION" && poll.poll_class !== "GOVERNANCE" && poll.poll_class !== "LEGITIMACY") {
    poll.poll_class = "OPINION";
  }
}

function ensureStatus(poll) {
  if (!poll.status) poll.status = "open";
}

function ensureTimestamps(poll) {
  if (poll.closed_at === undefined) poll.closed_at = null;
  if (poll.expires_at === undefined) poll.expires_at = null;

  if (poll.poll_class === "GOVERNANCE" || poll.poll_class === "LEGITIMACY") {
    if (poll.cooldown_seconds === undefined) poll.cooldown_seconds = null;
    if (poll.cooldown_ends_at === undefined) poll.cooldown_ends_at = null;
    if (poll.finalized_at === undefined) poll.finalized_at = null;
    if (poll.published_at === undefined) poll.published_at = null;
  }

  if (poll.visibility_ends_at === undefined) poll.visibility_ends_at = null;
  if (poll.close_reason === undefined) poll.close_reason = null;
}

function defaultRetentionSeconds(poll) {
  return poll.poll_class === "GOVERNANCE"
    ? DEFAULTS.GOVERNANCE_RETENTION_SECONDS
    : DEFAULTS.OPINION_RETENTION_SECONDS;
}

function computeVisibilityEndsAt(poll, anchorIso) {
  const sec =
    (poll.meta && Number.isFinite(Number(poll.meta.visibility_seconds)))
      ? Number(poll.meta.visibility_seconds)
      : defaultRetentionSeconds(poll);

  return addSeconds(anchorIso, sec);
}

function closePoll(poll, closeAtIso, reason) {
  poll.status = "closed";
  poll.closed_at = poll.closed_at || closeAtIso;
  poll.close_reason = reason || poll.close_reason || "closed";
  poll.visibility_ends_at = poll.visibility_ends_at || computeVisibilityEndsAt(poll, poll.closed_at);
}

function governanceStartCooldown(poll) {
  const closeAt = poll.closed_at || nowIso();

  const cooldown =
    Number.isFinite(Number(poll.cooldown_seconds)) && Number(poll.cooldown_seconds) > 0
      ? Number(poll.cooldown_seconds)
      : DEFAULTS.GOVERNANCE_COOLDOWN_SECONDS;

  poll.cooldown_ends_at = poll.cooldown_ends_at || addSeconds(closeAt, cooldown);
  poll.status = "cooldown";
}

function finalizePoll(poll, atIso) {
  poll.status = "finalized";
  poll.finalized_at = poll.finalized_at || atIso;
  poll.visibility_ends_at = poll.visibility_ends_at || computeVisibilityEndsAt(poll, poll.finalized_at);
}

function publishPoll(poll, atIso) {
  poll.status = "published";
  poll.published_at = poll.published_at || atIso;
  poll.visibility_ends_at = poll.visibility_ends_at || computeVisibilityEndsAt(poll, poll.published_at);
}

/**
 * Applies lifecycle transitions based on timestamps.
 * Returns flags so server.js can emit events if it wants.
 */
function applyLifecycle(poll, atIso) {
  const tIso = atIso || nowIso();
  const t = parseIso(tIso);

  ensureClass(poll);
  ensureStatus(poll);
  ensureTimestamps(poll);

  const expires = parseIso(poll.expires_at);

  let changed = false;
  let didFinalize = false;
  let didPublish = false;
  let didArchive = false;

  // Expiry closes an OPEN poll
  if (poll.status === "open" && expires && t && t >= expires) {
    closePoll(poll, tIso, "expired");
    changed = true;
  }

  // OPINION lifecycle
  if (poll.poll_class === "OPINION") {
    if (poll.status === "closed" && poll.visibility_ends_at) {
      const ve = parseIso(poll.visibility_ends_at);
      if (ve && t && t >= ve) {
        poll.status = "archived";
        changed = true;
        didArchive = true;
      }
    }
    return { changed, didFinalize, didPublish, didArchive };
  }

  // LEGITIMACY/GOVERNANCE lifecycle (legitimacy mechanic)
  if (poll.poll_class === "GOVERNANCE" || poll.poll_class === "LEGITIMACY") {
    // Once closed, we enter cooldown (if not already progressed)
    if (poll.status === "closed") {
      governanceStartCooldown(poll);
      changed = true;
    }

    // If in cooldown and cooldown has ended -> finalize -> publish
    if (poll.status === "cooldown" && poll.cooldown_ends_at) {
      const ce = parseIso(poll.cooldown_ends_at);
      if (ce && t && t >= ce) {
        finalizePoll(poll, tIso);
        changed = true;
        didFinalize = true;

        // Publish immediately after finalize (exchange-immutable record)
        publishPoll(poll, tIso);
        changed = true;
        didPublish = true;
      }
    }
  }

  return { changed, didFinalize, didPublish, didArchive };
}

function canVote(poll) {
  ensureClass(poll);
  ensureStatus(poll);

  if (poll.poll_class === "OPINION") {
    return poll.status === "open";
  }

  if (poll.poll_class === "LEGITIMACY" || poll.poll_class === "GOVERNANCE") {
    return poll.status === "open" || poll.status === "cooldown";
  }


  // GOVERNANCE: voting allowed in open + cooldown
  return poll.status === "open" || poll.status === "cooldown";
}

function isVisibleInList(poll, atIso) {
  const tIso = atIso || nowIso();
  const t = parseIso(tIso);

  // Never list archived
  if (poll.status === "archived") return false;

  if (!poll.visibility_ends_at) return true;

  const ve = parseIso(poll.visibility_ends_at);
  if (!ve || !t) return true;

  return t < ve;
}

module.exports = {
  DEFAULTS,
  applyLifecycle,
  canVote,
  isVisibleInList,
  nowIso,
};
