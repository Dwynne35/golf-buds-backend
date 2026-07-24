// Golf Buds data layer.
// Uses Node's built-in node:sqlite (experimental, ships with Node 22.5+) so there
// is no native module to compile and nothing extra to install beyond npm install.
"use strict";

const path = require("node:path");
const fs = require("node:fs");
const { DatabaseSync } = require("node:sqlite");

const DB_PATH = process.env.DB_PATH || path.join(__dirname, "..", "data", "golfbuds.db");
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new DatabaseSync(DB_PATH);
db.exec("PRAGMA foreign_keys = ON;");

db.exec(`
          CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                name TEXT NOT NULL,
                handicap TEXT,
                area TEXT,
                home_course TEXT,
                bio TEXT,
                location_label TEXT,
                location_lat REAL,
                location_lon REAL,
                created_at TEXT NOT NULL
              );

          CREATE TABLE IF NOT EXISTS availability (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                date TEXT NOT NULL,
                time TEXT NOT NULL,
                course TEXT NOT NULL,
                notes TEXT,
                created_at TEXT NOT NULL
              );
          CREATE INDEX IF NOT EXISTS idx_availability_user ON availability(user_id);

          CREATE TABLE IF NOT EXISTS invites (
                id TEXT PRIMARY KEY,
                from_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                to_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                slot_id TEXT,
                date TEXT NOT NULL,
                time TEXT NOT NULL,
                course TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL
              );
          CREATE INDEX IF NOT EXISTS idx_invites_to ON invites(to_id);
          CREATE INDEX IF NOT EXISTS idx_invites_from ON invites(from_id);

          CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                from_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                to_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                text TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
              );
          CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(from_id, to_id);

          CREATE TABLE IF NOT EXISTS buds (
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                golfer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                rating INTEGER NOT NULL,
                note TEXT,
                added_at TEXT NOT NULL,
                rated_at TEXT NOT NULL,
                PRIMARY KEY (user_id, golfer_id)
              );
        `);

        module.exports = { db };
        
