#!/usr/bin/env node
// Turn a roster CSV into personal invite links and an attendees SQL file.
//
//   TOKEN_KEY=... node scripts/invites.mjs roster.csv --expires 2026-12-31 [--base https://workshop.hexaplex.ch]
//
// roster.csv header: attendee_id,email,name,workshops   (workshops ";"-separated slugs)
// Writes <roster>.links.csv and <roster>.attendees.sql next to the input.
// No quoted fields or embedded commas are supported; keep the roster simple.

import { readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { signToken } from "../src/token.js";

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    expires: { type: "string" },
    base: { type: "string", default: "https://workshop.hexaplex.ch" },
  },
});

const [rosterPath] = positionals;
const secret = process.env.TOKEN_KEY;
if (!rosterPath || !values.expires || !secret) {
  console.error("usage: TOKEN_KEY=... node scripts/invites.mjs roster.csv --expires YYYY-MM-DD [--base URL]");
  process.exit(2);
}
// Access ends at the end of the given day, UTC.
const expires = Math.floor(Date.parse(`${values.expires}T23:59:59Z`) / 1000);
if (!Number.isInteger(expires) || expires * 1000 <= Date.now()) {
  console.error(`--expires must be a future date, got ${values.expires}`);
  process.exit(2);
}

const lines = readFileSync(rosterPath, "utf8").split(/\r?\n/).filter((l) => l.trim());
const header = lines.shift().split(",").map((h) => h.trim());
const col = (name) => {
  const i = header.indexOf(name);
  if (i < 0) throw new Error(`roster is missing column "${name}"`);
  return i;
};
const [iId, iEmail, iName, iWs] = ["attendee_id", "email", "name", "workshops"].map(col);

const sqlStr = (s) => `'${String(s).replace(/'/g, "''")}'`;
const links = ["attendee_id,email,name,workshops,link"];
const sql = [];
const seen = new Set();

for (const line of lines) {
  const f = line.split(",").map((x) => x.trim());
  const attendee = f[iId];
  const workshops = f[iWs].split(";").map((w) => w.trim()).filter(Boolean);
  if (!attendee || !workshops.length) throw new Error(`bad roster row: ${line}`);
  if (seen.has(attendee)) throw new Error(`duplicate attendee_id: ${attendee}`);
  seen.add(attendee);
  const token = await signToken(secret, { attendee, workshops, expires });
  links.push([attendee, f[iEmail], f[iName], workshops.join(";"), `${values.base}/join?t=${token}`].join(","));
  sql.push(
    `INSERT OR REPLACE INTO attendees (attendee_id, email, name, workshops, expires) VALUES (${[attendee, f[iEmail], f[iName], workshops.join(";")].map(sqlStr).join(", ")}, ${expires});`,
  );
}

const stem = rosterPath.replace(/\.csv$/i, "");
writeFileSync(`${stem}.links.csv`, links.join("\n") + "\n");
writeFileSync(`${stem}.attendees.sql`, sql.join("\n") + "\n");
console.log(`${seen.size} invites -> ${stem}.links.csv, ${stem}.attendees.sql`);
