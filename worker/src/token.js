// Signed attendee tokens: base64url(JSON payload) + "." + base64url(HMAC-SHA256).
// Payload: { a: attendee_id, w: [workshop slugs], e: expiry (unix seconds) }.
// Runs unchanged in Workers and in Node >= 20 (both expose WebCrypto as globalThis.crypto).

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64urlEncode(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str) {
  const s = atob(str.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

export async function signToken(secret, { attendee, workshops, expires }) {
  if (!attendee || !Array.isArray(workshops) || !Number.isInteger(expires)) {
    throw new Error("signToken needs attendee, workshops[] and integer expires");
  }
  const body = b64urlEncode(enc.encode(JSON.stringify({ a: attendee, w: workshops, e: expires })));
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(secret), enc.encode(body));
  return `${body}.${b64urlEncode(new Uint8Array(sig))}`;
}

// Returns { ok: true, attendee, workshops, expires } or { ok: false, reason, attendee? }.
// `attendee` is set on an expired token so the denial can still be attributed in the log.
export async function verifyToken(secret, token, now = Math.floor(Date.now() / 1000)) {
  if (typeof token !== "string" || token.length > 2048) return { ok: false, reason: "malformed" };
  const parts = token.split(".");
  if (parts.length !== 2) return { ok: false, reason: "malformed" };
  const [body, sig] = parts;
  let valid;
  try {
    valid = await crypto.subtle.verify("HMAC", await hmacKey(secret), b64urlDecode(sig), enc.encode(body));
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (!valid) return { ok: false, reason: "bad_signature" };
  let p;
  try {
    p = JSON.parse(dec.decode(b64urlDecode(body)));
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (typeof p.a !== "string" || !Array.isArray(p.w) || !Number.isInteger(p.e)) {
    return { ok: false, reason: "malformed" };
  }
  if (p.e <= now) return { ok: false, reason: "expired", attendee: p.a };
  return { ok: true, attendee: p.a, workshops: p.w, expires: p.e };
}

// Keyed hash so the log can correlate IPs per attendee without storing them.
export async function keyedHash(secret, value) {
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(secret), enc.encode(`ip:${value}`));
  return [...new Uint8Array(sig).slice(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
