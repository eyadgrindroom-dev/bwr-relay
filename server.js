"use strict";

const express = require("express");
const crypto  = require("crypto");
const app     = express();

// keep raw bytes so the signature is checked against exactly what Roblox sent
app.use(express.json({
  limit: "512kb",
  verify: (req, _res, buf) => { req.rawBody = buf; },
}));

const SECRET = process.env.RELAY_SECRET;
if (!SECRET || SECRET.length < 16) {
  console.error("[RELAY] RELAY_SECRET env var missing or too short. Exiting.");
  process.exit(1);
}

const MAX_AGE_MS   = 10 * 60 * 1000;
const TS_WINDOW_MS = 60 * 1000;
const MAX_JOBS     = 500;
const MAX_PEERS    = 100;
const PORT         = process.env.PORT || 3000;

const store = new Map(); // jobId -> Map<userId, { payload, updatedAt }>

function getBucket(jobId, create) {
  let b = store.get(jobId);
  if (!b && create) {
    if (store.size >= MAX_JOBS) return null;
    b = new Map();
    store.set(jobId, b);
  }
  return b || null;
}

function putEntry(bucket, uid, payload) {
  uid = String(uid);
  if (!bucket.has(uid) && bucket.size >= MAX_PEERS) return;
  bucket.set(uid, { payload, updatedAt: Date.now() });
}

setInterval(() => {
  const now = Date.now();
  for (const [jobId, bucket] of store) {
    for (const [uid, entry] of bucket) {
      if (now - entry.updatedAt > MAX_AGE_MS) bucket.delete(uid);
    }
    if (!bucket.size) store.delete(jobId);
  }
}, 30_000);

const sha = (s) => crypto.createHash("sha256").update(String(s)).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

function authenticate(req, res, next) {
  const ts  = parseInt(req.headers["x-timestamp"] || "0", 10);
  if (isNaN(ts) || Math.abs(Date.now() - ts) > TS_WINDOW_MS) {
    return res.status(401).json({ error: "Timestamp rejected" });
  }
  if (!safeEqual(req.headers["x-relay-secret"] || "", SECRET)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// Must match hmacSign() in OOB_SyncHandler exactly.
function fnv(bytes, start) {
  let h = start >>> 0;
  for (const b of bytes) h = Math.imul(h ^ b, 16777619) >>> 0;
  return h;
}
const hex8 = (n) => (n >>> 0).toString(16).padStart(8, "0");

function expectedSignature(rawBuf, ts) {
  let seed = fnv(Buffer.from(SECRET, "utf8"), 0);
  seed = (seed ^ (Number(ts) % 4294967296)) >>> 0;
  const hash = fnv(Buffer.concat([rawBuf, Buffer.from(String(ts), "utf8")]), seed);
  return hex8(hash) + hex8(hash ^ seed);
}

function verifySignature(req, res, next) {
  const sig = String(req.headers["x-signature"] || "");
  const ts  = String(req.headers["x-timestamp"] || "");
  const raw = req.rawBody || Buffer.alloc(0);
  if (!sig || !safeEqual(sig, expectedSignature(raw, ts))) {
    return res.status(403).json({ error: "invalid signature" });
  }
  next();
}

// Single combined call: store everyone's payloads, drop leavers, return all peers.
app.post("/api/v1/sync/exchange", authenticate, verifySignature, (req, res) => {
  const { jobId, entries, remove } = req.body || {};
  if (!jobId) return res.status(400).json({ error: "Missing jobId" });

  const bucket = getBucket(String(jobId), true);
  if (!bucket) return res.status(503).json({ error: "Relay full" });

  if (Array.isArray(remove)) {
    for (const uid of remove) bucket.delete(String(uid));
  }
  if (entries && typeof entries === "object" && !Array.isArray(entries)) {
    for (const [uid, payload] of Object.entries(entries)) {
      if (payload !== undefined) putEntry(bucket, uid, payload);
    }
  }

  const peers = {};
  for (const [uid, entry] of bucket) peers[uid] = entry.payload;
  res.json({ peers });
});

// Legacy routes, kept so nothing else breaks.
app.post("/api/v1/sync/push", authenticate, verifySignature, (req, res) => {
  const { jobId, userId, payload } = req.body || {};
  if (!jobId || !userId || payload === undefined) {
    return res.status(400).json({ error: "Missing: jobId, userId, or payload" });
  }
  const bucket = getBucket(String(jobId), true);
  if (!bucket) return res.status(503).json({ error: "Relay full" });
  putEntry(bucket, userId, payload);
  res.json({ ok: true });
});

app.get("/api/v1/sync/pull", authenticate, (req, res) => {
  const { jobId, requesterId } = req.query;
  if (!jobId || !requesterId) {
    return res.status(400).json({ error: "Missing: jobId or requesterId" });
  }
  const bucket = getBucket(String(jobId), false);
  const peers = {};
  if (bucket) {
    for (const [uid, entry] of bucket) {
      if (uid !== String(requesterId)) peers[uid] = entry.payload;
    }
  }
  res.json({ peers });
});

app.delete("/api/v1/sync/clear", authenticate, (req, res) => {
  const { jobId, userId } = req.body || {};
  const bucket = jobId && getBucket(String(jobId), false);
  if (bucket && userId) {
    bucket.delete(String(userId));
    if (!bucket.size) store.delete(String(jobId));
  }
  res.json({ ok: true });
});

app.get("/health", (_req, res) => res.json({ ok: true, ts: Date.now() }));

app.use((err, _req, res, _next) => {
  res.status(400).json({ error: "Bad request" });
});

app.listen(PORT, () => console.log(`[RELAY] running on port ${PORT}`));
