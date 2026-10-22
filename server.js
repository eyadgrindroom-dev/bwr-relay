// ============================================================
//  OOB Avatar Sync Relay  —  server.js
//  Lightweight Express REST relay.
//  Stores encrypted peer payloads keyed by (jobId, userId).
//  Never interprets payload content — pure store-and-forward.
// ============================================================

"use strict";

const express = require("express");
const crypto  = require("crypto");
const app     = express();

app.use(express.json({ limit: "512kb" }));

// ── Config ───────────────────────────────────────────────────
const SECRET = process.env.RELAY_SECRET;
if (!SECRET || SECRET.length < 16) {
  console.error("[RELAY] RELAY_SECRET env var missing or too short. Exiting.");
  process.exit(1);
}

const MAX_AGE_MS    = 10 * 60 * 1000;  // evict entries after 10 minutes
const TS_WINDOW_MS  = 60  * 1000;      // reject timestamps > 60s old
const PORT          = process.env.PORT || 3000;

// ── In-memory store ──────────────────────────────────────────
// Map< jobId, Map< userId, { payload: any, updatedAt: number } > >
const store = new Map();

function getOrCreateBucket(jobId) {
  if (!store.has(jobId)) store.set(jobId, new Map());
  return store.get(jobId);
}

// Periodic eviction of stale entries (runs every 30 s)
setInterval(() => {
  const now = Date.now();
  for (const [jobId, bucket] of store) {
    for (const [uid, entry] of bucket) {
      if (now - entry.updatedAt > MAX_AGE_MS) bucket.delete(uid);
    }
    if (!bucket.size) store.delete(jobId);
  }
}, 30_000);

// ── Authentication middleware ─────────────────────────────────
// Every request must carry:
//   x-relay-secret  : the shared secret (RELAY_SECRET env var)
//   x-timestamp     : Unix milliseconds (current time on sender)
//
// Constant-time comparison prevents timing attacks.
// Timestamp window prevents replay attacks.
function authenticate(req, res, next) {
  const provided  = req.headers["x-relay-secret"]  || "";
  const tsHeader  = req.headers["x-timestamp"]     || "0";

  // Timestamp check — both sides use Unix ms
  const ts  = parseInt(tsHeader, 10);
  const now = Date.now();
  if (isNaN(ts) || Math.abs(now - ts) > TS_WINDOW_MS) {
    return res.status(401).json({ error: "Timestamp rejected" });
  }

  // Constant-time secret comparison
  // Pad both strings to the same length before comparing
  const padLen = Math.max(provided.length, SECRET.length, 1);
  try {
    const a = Buffer.alloc(padLen, 0);
    const b = Buffer.alloc(padLen, 0);
    a.write(provided);
    b.write(SECRET);
    if (!crypto.timingSafeEqual(a, b)) {
      return res.status(401).json({ error: "Unauthorized" });
    }
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }

  next();
}

// ── Routes ───────────────────────────────────────────────────

// POST /api/v1/sync/push
// Body: { jobId: string, userId: string, payload: any }
// Stores this player's current payload for other peers to pull.
app.post("/api/v1/sync/push", authenticate, (req, res) => {
  const { jobId, userId, payload } = req.body;
  if (!jobId || !userId || payload === undefined) {
    return res.status(400).json({ error: "Missing: jobId, userId, or payload" });
  }

  getOrCreateBucket(String(jobId))
    .set(String(userId), { payload, updatedAt: Date.now() });

  res.json({ ok: true });
});

// GET /api/v1/sync/pull?jobId=X&requesterId=Y
// Returns all peers EXCEPT the requester.
// The Roblox server uses requesterId = "server" so it gets ALL users.
app.get("/api/v1/sync/pull", authenticate, (req, res) => {
  const { jobId, requesterId } = req.query;
  if (!jobId || !requesterId) {
    return res.status(400).json({ error: "Missing: jobId or requesterId" });
  }

  const bucket = store.get(String(jobId));
  if (!bucket) return res.json({ peers: {} });

  const peers = {};
  for (const [uid, entry] of bucket) {
    if (uid !== String(requesterId)) {
      peers[uid] = entry.payload;
    }
  }

  res.json({ peers });
});

// DELETE /api/v1/sync/clear
// Body: { jobId: string, userId: string }
// Called when a player leaves the Roblox server.
app.delete("/api/v1/sync/clear", authenticate, (req, res) => {
  const { jobId, userId } = req.body || {};
  if (jobId && userId) {
    const bucket = store.get(String(jobId));
    if (bucket) {
      bucket.delete(String(userId));
      if (!bucket.size) store.delete(String(jobId));
    }
  }
  res.json({ ok: true });
});

// GET /health  — simple uptime check for Railway/Render
app.get("/health", (_req, res) => {
  res.json({ ok: true, ts: Date.now(), entries: store.size });
});

// ── Start ────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[RELAY] OOB Avatar Sync Relay running on port ${PORT}`);
});
