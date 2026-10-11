import { test } from "node:test";
import assert from "node:assert/strict";
import { signToken, verifyToken } from "../src/token.js";
import { classify, workshopOf } from "../src/index.js";

const KEY = "test-key";
const future = Math.floor(Date.now() / 1000) + 3600;

test("round-trips a valid token", async () => {
  const t = await signToken(KEY, { attendee: "a1", workshops: ["purple-team"], expires: future });
  assert.deepEqual(await verifyToken(KEY, t), { ok: true, attendee: "a1", workshops: ["purple-team"], expires: future });
});

test("rejects a tampered payload", async () => {
  const t = await signToken(KEY, { attendee: "a1", workshops: ["purple-team"], expires: future });
  const forged = await signToken("other", { attendee: "a1", workshops: ["purple-team", "other"], expires: future });
  const mixed = `${forged.split(".")[0]}.${t.split(".")[1]}`;
  assert.equal((await verifyToken(KEY, mixed)).reason, "bad_signature");
});

test("rejects a token signed with another key", async () => {
  const t = await signToken("other", { attendee: "a1", workshops: [], expires: future });
  assert.equal((await verifyToken(KEY, t)).reason, "bad_signature");
});

test("reports expiry with the attendee", async () => {
  const t = await signToken(KEY, { attendee: "a1", workshops: [], expires: 1000 });
  assert.deepEqual(await verifyToken(KEY, t), { ok: false, reason: "expired", attendee: "a1" });
});

test("rejects garbage", async () => {
  for (const t of [null, "", "abc", "a.b.c", "!!!.???", "x".repeat(3000)]) {
    assert.equal((await verifyToken(KEY, t)).ok, false, String(t).slice(0, 20));
  }
});

test("classifies Relearn outputs", () => {
  assert.equal(classify("/searchindex.en.min.184fcf.js"), "search");
  assert.equal(classify("/workshops/pt/emu/index.print.html"), "print");
  assert.equal(classify("/workshops/pt/emu/"), "page");
  assert.equal(classify("/workshops/pt/resources/slides.pdf"), "pdf");
  assert.equal(classify("/workshops/pt/cti/red/layer.json"), "json");
  assert.equal(classify("/workshops/pt/index.xml"), "feed");
  assert.equal(classify("/workshops/pt/images/x.png"), "asset");
});

test("extracts the workshop slug", () => {
  assert.equal(workshopOf("/workshops/purple-team/emu/"), "purple-team");
  assert.equal(workshopOf("/workshops/purple-team"), "purple-team");
  assert.equal(workshopOf("/searchindex.en.js"), null);
  assert.equal(workshopOf("/workshopsX/a/"), null);
});
