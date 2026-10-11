-- Apply with: npx wrangler d1 execute workshop-audit --remote --file=schema.sql

CREATE TABLE IF NOT EXISTS access_log (
  id          INTEGER PRIMARY KEY,
  ts          INTEGER NOT NULL,          -- unix ms
  attendee_id TEXT,                      -- null when no parsable token was presented
  workshop_id TEXT,                      -- slug from /workshops/<slug>/, null for site-wide paths
  path        TEXT NOT NULL,
  kind        TEXT NOT NULL,             -- join | page | print | search | pdf | json | feed | asset
  status      INTEGER NOT NULL,
  bytes       INTEGER,                   -- body bytes before compression; partial if aborted
  ip_hash     TEXT,                      -- keyed hash, not the IP
  ua          TEXT,
  referer     TEXT,
  country     TEXT,
  cf_ray      TEXT
);
CREATE INDEX IF NOT EXISTS access_log_attendee_ts ON access_log (attendee_id, ts);

CREATE TABLE IF NOT EXISTS attendees (
  attendee_id TEXT PRIMARY KEY,
  email       TEXT,
  name        TEXT,
  workshops   TEXT NOT NULL,             -- ";"-separated slugs
  expires     INTEGER NOT NULL           -- unix seconds
);

CREATE TABLE IF NOT EXISTS revoked (
  attendee_id TEXT PRIMARY KEY,
  revoked_at  INTEGER NOT NULL DEFAULT (unixepoch())
);
