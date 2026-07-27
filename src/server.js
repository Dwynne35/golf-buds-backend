"use strict";

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");

const { db } = require("./db");
const { signToken, requireAuth } = require("./auth");

const app = express();
app.use(cors());
// Default 100kb JSON limit is too small for base64-encoded profile picture
// uploads. The frontend resizes/compresses images before sending, but this
// gives enough headroom for that plus a safety margin.
app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 4000;
const uid = () => crypto.randomUUID();
const nowIso = () => new Date().toISOString();
const todayIso = () => new Date().toISOString().slice(0, 10);

const rateLimitBuckets = new Map();

function rateLimit({ windowMs, max }) {
    return (req, res, next) => {
          const key = req.ip + ":" + req.path;
          const now = Date.now();
          let bucket = rateLimitBuckets.get(key);
          if (!bucket || now - bucket.windowStart > windowMs) {
                  bucket = { count: 0, windowStart: now };
                  rateLimitBuckets.set(key, bucket);
          }
          bucket.count++;
          if (bucket.count > max) {
                  const retryAfterSec = Math.max(1, Math.ceil((bucket.windowStart + windowMs - now) / 1000));
                  res.set("Retry-After", String(retryAfterSec));
                  return res.status(429).json({ error: "Too many attempts. Please wait a bit and try again." });
          }
          next();
    };
}

setInterval(() => {
    const now = Date.now();
    for (const [key, bucket] of rateLimitBuckets) {
          if (now - bucket.windowStart > 60 * 60 * 1000) rateLimitBuckets.delete(key);
    }
}, 10 * 60 * 1000);

const authRateLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });

function toPublicUser(row) {
    if (!row) return null;
    return {
          id: row.id,
          email: row.email,
          name: row.name,
          handicap: row.handicap,
          area: row.area,
          homeCourse: row.home_course,
          bio: row.bio,
          avatar: row.avatar || null,
          location:
                  row.location_lat != null && row.location_lon != null
              ? { lat: row.location_lat, lon: row.location_lon, label: row.location_label }
                    : null,
    };
}

function getUserById(id) {
    return db.prepare("SELECT * FROM users WHERE id = ?").get(id);
}

function toPublicInvite(row) {
    return {
          id: row.id,
          fromId: row.from_id,
          toId: row.to_id,
          slotId: row.slot_id,
          date: row.date,
          time: row.time,
          course: row.course,
          status: row.status,
          createdAt: row.created_at,
    };
}

app.get("/api/health", (req, res) => res.json({ ok: true }));

app.post("/api/auth/signup", authRateLimit, (req, res) => {
    const { email, password, name, handicap, area, homeCourse, bio, location } = req.body || {};

           if (!email || !password || !name) {
                 return res.status(400).json({ error: "email, password, and name are required" });
           }
    if (typeof password !== "string" || password.length < 6) {
          return res.status(400).json({ error: "password must be at least 6 characters" });
    }

           const normalizedEmail = String(email).trim().toLowerCase();
    const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(normalizedEmail);
    if (existing) {
          return res.status(409).json({ error: "An account with that email already exists" });
    }

           const id = uid();
    const passwordHash = bcrypt.hashSync(password, 10);

           db.prepare(
                 `INSERT INTO users
                       (id, email, password_hash, name, handicap, area, home_course, bio, location_label, location_lat, location_lon, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
               ).run(
                 id,
                 normalizedEmail,
                 passwordHash,
                 String(name).trim(),
                 handicap != null ? String(handicap) : null,
                 area || null,
                 homeCourse || null,
                 bio || null,
                 location ? location.label : null,
                 location ? location.lat : null,
                 location ? location.lon : null,
                 nowIso()
               );

           const user = getUserById(id);
    res.status(201).json({ token: signToken(id), user: toPublicUser(user) });
});

app.post("/api/auth/login", authRateLimit, (req, res) => {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "email and password are required" });

           const normalizedEmail = String(email).trim().toLowerCase();
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(normalizedEmail);
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
          return res.status(401).json({ error: "Invalid email or password" });
    }

           res.json({ token: signToken(user.id), user: toPublicUser(user) });
});

app.get("/api/me", requireAuth, (req, res) => {
    const user = getUserById(req.userId);
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ user: toPublicUser(user) });
});

app.put("/api/me", requireAuth, (req, res) => {
    const { name, handicap, area, homeCourse, bio, location, avatar } = req.body || {};
    const current = getUserById(req.userId);
    if (!current) return res.status(404).json({ error: "User not found" });

          if (avatar != null && avatar !== "") {
                if (typeof avatar !== "string" || !avatar.startsWith("data:image/")) {
                        return res.status(400).json({ error: "avatar must be a data:image/... URL" });
                }
                if (avatar.length > 700_000) {
                        return res.status(400).json({ error: "avatar image is too large" });
                }
          }

          db.prepare(
                `UPDATE users SET
                      name = ?, handicap = ?, area = ?, home_course = ?, bio = ?, avatar = ?,
                            location_label = ?, location_lat = ?, location_lon = ?
                                 WHERE id = ?`
              ).run(
                name != null ? String(name).trim() : current.name,
                handicap != null ? String(handicap) : current.handicap,
                area != null ? area : current.area,
                homeCourse != null ? homeCourse : current.home_course,
                bio != null ? bio : current.bio,
                avatar !== undefined ? (avatar || null) : current.avatar,
                location ? location.label : location === null ? null : current.location_label,
                location ? location.lat : location === null ? null : current.location_lat,
                location ? location.lon : location === null ? null : current.location_lon,
                req.userId
              );

          res.json({ user: toPublicUser(getUserById(req.userId)) });
});

app.delete("/api/me", requireAuth, (req, res) => {
    const id = req.userId;
    if (!getUserById(id)) return res.status(404).json({ error: "User not found" });

             try {
                   db.exec("BEGIN");
                   db.prepare("DELETE FROM messages WHERE from_id = ? OR to_id = ?").run(id, id);
                   db.prepare("DELETE FROM buds WHERE user_id = ? OR golfer_id = ?").run(id, id);
                   db.prepare("DELETE FROM invites WHERE from_id = ? OR to_id = ?").run(id, id);
                   db.prepare("DELETE FROM availability WHERE user_id = ?").run(id);
                   db.prepare("DELETE FROM users WHERE id = ?").run(id);
                   db.exec("COMMIT");
             } catch (e) {
                   try { db.exec("ROLLBACK"); } catch (e2) {}
                   return res.status(500).json({ error: "Failed to delete account" });
             }

             res.json({ ok: true });
});

app.get("/api/golfers", requireAuth, (req, res) => {
    const search = (req.query.search || "").toString().trim().toLowerCase();

          const others = db.prepare("SELECT * FROM users WHERE id != ? ORDER BY name").all(req.userId);
    const slotStmt = db.prepare(
          "SELECT * FROM availability WHERE user_id = ? AND date >= ? ORDER BY date, time"
        );

          const results = others
      .map((u) => {
              let slots = slotStmt.all(u.id, todayIso());
              if (search) {
                        slots = slots.filter((s) => s.course.toLowerCase().includes(search));
              }
              return {
                        ...toPublicUser(u),
                        slots: slots.map((s) => ({
                                    id: s.id,
                                    date: s.date,
                                    time: s.time,
                                    course: s.course,
                                    notes: s.notes || "",
                        })),
              };
      })
      .filter((u) => u.slots.length > 0);

          res.json({ golfers: results });
});

app.get("/api/availability/me", requireAuth, (req, res) => {
    const slots = db
      .prepare("SELECT * FROM availability WHERE user_id = ? ORDER BY date, time")
      .all(req.userId);
    res.json({
          slots: slots.map((s) => ({ id: s.id, date: s.date, time: s.time, course: s.course, notes: s.notes || "" })),
    });
});

app.post("/api/availability", requireAuth, (req, res) => {
    const { date, time, course, notes } = req.body || {};
    if (!date || !time || !course) return res.status(400).json({ error: "date, time, and course are required" });

           const id = uid();
    db.prepare(
          "INSERT INTO availability (id, user_id, date, time, course, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
        ).run(id, req.userId, date, time, course, notes || "", nowIso());

           res.status(201).json({ slot: { id, date, time, course, notes: notes || "" } });
});

app.delete("/api/availability/:id", requireAuth, (req, res) => {
    const result = db
      .prepare("DELETE FROM availability WHERE id = ? AND user_id = ?")
      .run(req.params.id, req.userId);
    if (result.changes === 0) return res.status(404).json({ error: "Slot not found" });
    res.json({ ok: true });
});

app.get("/api/invites", requireAuth, (req, res) => {
    const incoming = db.prepare("SELECT * FROM invites WHERE to_id = ? ORDER BY created_at DESC").all(req.userId);
    const outgoing = db.prepare("SELECT * FROM invites WHERE from_id = ? ORDER BY created_at DESC").all(req.userId);
    res.json({
          incoming: incoming.map((row) => ({ ...toPublicInvite(row), otherUser: toPublicUser(getUserById(row.from_id)) })),
          outgoing: outgoing.map((row) => ({ ...toPublicInvite(row), otherUser: toPublicUser(getUserById(row.to_id)) })),
    });
});

app.post("/api/invites", requireAuth, (req, res) => {
    const { toId, slotId } = req.body || {};
    if (!toId || !slotId) return res.status(400).json({ error: "toId and slotId are required" });

           const slot = db.prepare("SELECT * FROM availability WHERE id = ? AND user_id = ?").get(slotId, toId);
    if (!slot) return res.status(404).json({ error: "That open time no longer exists" });

           const dupe = db
      .prepare("SELECT id FROM invites WHERE from_id = ? AND to_id = ? AND slot_id = ?")
      .get(req.userId, toId, slotId);
    if (dupe) return res.status(409).json({ error: "You already invited this golfer to that time" });

           const id = uid();
    db.prepare(
          `INSERT INTO invites (id, from_id, to_id, slot_id, date, time, course, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)`
        ).run(id, req.userId, toId, slotId, slot.date, slot.time, slot.course, nowIso());

           res.status(201).json({ invite: toPublicInvite(db.prepare("SELECT * FROM invites WHERE id = ?").get(id)) });
});

app.post("/api/invites/:id/accept", requireAuth, (req, res) => {
    const invite = db.prepare("SELECT * FROM invites WHERE id = ?").get(req.params.id);
    if (!invite) return res.status(404).json({ error: "Invite not found" });
    if (invite.to_id !== req.userId) return res.status(403).json({ error: "Not your invite to respond to" });
    if (invite.status !== "pending") return res.status(409).json({ error: "This invite is no longer pending" });

           db.prepare("UPDATE invites SET status = 'accepted' WHERE id = ?").run(invite.id);

           if (invite.slot_id) {
                 db.prepare("DELETE FROM availability WHERE id = ?").run(invite.slot_id);
                 db.prepare(
                         "UPDATE invites SET status = 'declined' WHERE slot_id = ? AND id != ? AND status = 'pending'"
                       ).run(invite.slot_id, invite.id);
           }

           res.json({ invite: toPublicInvite(db.prepare("SELECT * FROM invites WHERE id = ?").get(invite.id)) });
});

app.post("/api/invites/:id/decline", requireAuth, (req, res) => {
    const invite = db.prepare("SELECT * FROM invites WHERE id = ?").get(req.params.id);
    if (!invite) return res.status(404).json({ error: "Invite not found" });
    if (invite.to_id !== req.userId) return res.status(403).json({ error: "Not your invite to respond to" });
    if (invite.status !== "pending") return res.status(409).json({ error: "This invite is no longer pending" });

           db.prepare("UPDATE invites SET status = 'declined' WHERE id = ?").run(invite.id);
    res.json({ invite: toPublicInvite(db.prepare("SELECT * FROM invites WHERE id = ?").get(invite.id)) });
});

function haveAcceptedInvite(userA, userB) {
    const row = db
      .prepare(
              `SELECT id FROM invites
                     WHERE status = 'accepted'
                              AND ((from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?))
                                     LIMIT 1`
            )
      .get(userA, userB, userB, userA);
    return !!row;
}

app.get("/api/messages/:golferId", requireAuth, (req, res) => {
    const golferId = req.params.golferId;
    const rows = db
      .prepare(
              `SELECT * FROM messages
                     WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)
                            ORDER BY created_at ASC`
            )
      .all(req.userId, golferId, golferId, req.userId);

          db.prepare("UPDATE messages SET is_read = 1 WHERE from_id = ? AND to_id = ? AND is_read = 0").run(
                golferId,
                req.userId
              );

          res.json({
                messages: rows.map((m) => ({
                        id: m.id,
                        from: m.from_id === req.userId ? "me" : m.from_id,
                        text: m.text,
                        at: m.created_at,
                })),
          });
});

app.post("/api/messages/:golferId", requireAuth, (req, res) => {
    const golferId = req.params.golferId;
    const { text } = req.body || {};
    if (!text || !String(text).trim()) return res.status(400).json({ error: "text is required" });

           if (!haveAcceptedInvite(req.userId, golferId)) {
                 return res.status(403).json({ error: "You can only message golfers you have an accepted invite with" });
           }

           const id = uid();
    db.prepare(
          "INSERT INTO messages (id, from_id, to_id, text, is_read, created_at) VALUES (?, ?, ?, ?, 0, ?)"
        ).run(id, req.userId, golferId, String(text).trim(), nowIso());

           res.status(201).json({ message: { id, from: "me", text: String(text).trim(), at: nowIso() } });
});

app.get("/api/unread", requireAuth, (req, res) => {
    const pendingInvites = db
      .prepare("SELECT COUNT(*) AS n FROM invites WHERE to_id = ? AND status = 'pending'")
      .get(req.userId).n;

          const rows = db
      .prepare("SELECT DISTINCT from_id FROM messages WHERE to_id = ? AND is_read = 0")
      .all(req.userId);

          res.json({ pendingInvites, unreadGolferIds: rows.map((r) => r.from_id) });
});

app.get("/api/buds", requireAuth, (req, res) => {
    const rows = db.prepare("SELECT * FROM buds WHERE user_id = ?").all(req.userId);
    const buds = rows.map((b) => {
          const golfer = getUserById(b.golfer_id);
          return {
                  golferId: b.golfer_id,
                  rating: b.rating,
                  note: b.note || "",
                  addedAt: b.added_at,
                  ratedAt: b.rated_at,
                  golfer: golfer ? toPublicUser(golfer) : null,
          };
    });
    res.json({ buds });
});

app.post("/api/buds/:golferId", requireAuth, (req, res) => {
    const golferId = req.params.golferId;
    const { rating, note } = req.body || {};
    const ratingNum = parseInt(rating, 10);
    if (!ratingNum || ratingNum < 1 || ratingNum > 5) {
          return res.status(400).json({ error: "rating must be an integer from 1 to 5" });
    }
    if (!getUserById(golferId)) return res.status(404).json({ error: "Golfer not found" });

           const existing = db
      .prepare("SELECT * FROM buds WHERE user_id = ? AND golfer_id = ?")
      .get(req.userId, golferId);

           const now = nowIso();
    db.prepare(
          `INSERT INTO buds (user_id, golfer_id, rating, note, added_at, rated_at)
               VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(user_id, golfer_id) DO UPDATE SET rating = excluded.rating, note = excluded.note, rated_at = excluded.rated_at`
        ).run(req.userId, golferId, ratingNum, note || "", existing ? existing.added_at : now, now);

           res.json({
                 bud: {
                         golferId,
                         rating: ratingNum,
                         note: note || "",
                         addedAt: existing ? existing.added_at : now,
                         ratedAt: now,
                 },
           });
});

app.delete("/api/buds/:golferId", requireAuth, (req, res) => {
    db.prepare("DELETE FROM buds WHERE user_id = ? AND golfer_id = ?").run(req.userId, req.params.golferId);
    res.json({ ok: true });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

app.listen(PORT, () => {
    console.log(`Golf Buds API listening on http://localhost:${PORT}`);
});
