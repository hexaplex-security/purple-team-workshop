// Gate for workshop.hexaplex.ch: every request routed here (see run_worker_first in
// wrangler.jsonc) needs a valid attendee token, and every one is logged to D1.
// Theme CSS/JS/fonts bypass the Worker entirely and are served straight from assets.

import { verifyToken, keyedHash } from "./token.js";

const COOKIE = "wsess";

export function classify(pathname) {
  const p = pathname.toLowerCase();
  if (/\/searchindex\.[^/]*\.js$/.test(p) || p.endsWith("/search/") || p.endsWith("/search/index.html")) return "search";
  if (p.endsWith(".print.html")) return "print";
  if (p.endsWith(".pdf")) return "pdf";
  if (p.endsWith(".json")) return "json";
  if (p.endsWith(".xml")) return "feed";
  if (p.endsWith("/") || p.endsWith(".html")) return "page";
  return "asset";
}

// "/workshops/<slug>/..." -> slug; anything else -> null (site-wide path).
export function workshopOf(pathname) {
  const m = pathname.match(/^\/workshops\/([^/]+)(?:\/|$)/);
  return m ? decodeURIComponent(m[1]) : null;
}

function readCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

function safeNext(next) {
  return typeof next === "string" && next.startsWith("/") && !next.startsWith("//") && !next.includes("\\") ? next : null;
}

function page(status, title, message) {
  const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><body style="font-family:system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem"><h1>${title}</h1><p>${message}</p></body></html>`;
  return new Response(html, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Robots-Tag": "noindex" },
  });
}

async function isRevoked(env, attendee) {
  const row = await env.DB.prepare("SELECT 1 FROM revoked WHERE attendee_id = ?").bind(attendee).first();
  return row !== null;
}

async function log(env, request, url, fields) {
  const ip = request.headers.get("CF-Connecting-IP") || "";
  await env.DB.prepare(
    `INSERT INTO access_log (ts, attendee_id, workshop_id, path, kind, status, bytes, ip_hash, ua, referer, country, cf_ray)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      Date.now(),
      fields.attendee ?? null,
      fields.workshop ?? null,
      url.pathname,
      fields.kind,
      fields.status,
      fields.bytes ?? null,
      ip ? await keyedHash(env.TOKEN_KEY, ip) : null,
      (request.headers.get("User-Agent") || "").slice(0, 512),
      (request.headers.get("Referer") || "").slice(0, 512),
      request.cf?.country ?? null,
      request.headers.get("CF-Ray"),
    )
    .run();
}

async function handleJoin(request, env, ctx, url) {
  const v = await verifyToken(env.TOKEN_KEY, url.searchParams.get("t"));
  const ok = v.ok && !(await isRevoked(env, v.attendee));
  ctx.waitUntil(log(env, request, url, { attendee: v.attendee, kind: "join", status: ok ? 302 : 403 }));
  if (!ok) {
    return page(403, "Invite link not valid", "This link is invalid, expired or revoked. Contact your trainer for a new one.");
  }
  const target = safeNext(url.searchParams.get("next")) || (v.workshops.length === 1 ? `/workshops/${v.workshops[0]}/` : "/");
  const maxAge = v.expires - Math.floor(Date.now() / 1000);
  return new Response(null, {
    status: 302,
    headers: {
      Location: target,
      "Set-Cookie": `${COOKIE}=${url.searchParams.get("t")}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`,
      "Cache-Control": "no-store",
    },
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/join") return handleJoin(request, env, ctx, url);
    if (url.pathname === "/logout") {
      const res = page(200, "Signed out", "Open your invite link again to come back.");
      res.headers.set("Set-Cookie", `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
      return res;
    }

    const kind = classify(url.pathname);
    const workshop = workshopOf(url.pathname);
    const token = readCookie(request, COOKIE);

    if (!token) {
      return page(401, "Sign in with your invite link", "Open the personal link you received for this workshop.");
    }

    const v = await verifyToken(env.TOKEN_KEY, token);
    let status = 0;
    if (!v.ok || (await isRevoked(env, v.attendee))) status = 401;
    else if (workshop && !v.workshops.includes(workshop)) status = 403;

    if (status) {
      ctx.waitUntil(log(env, request, url, { attendee: v.attendee, workshop, kind, status }));
      return status === 403
        ? page(403, "Not part of your workshop", "Your invite does not include this workshop.")
        : page(401, "Session expired", "Your access has ended or was revoked. Contact your trainer.");
    }

    const upstream = await env.ASSETS.fetch(request);
    const entry = { attendee: v.attendee, workshop, kind, status: upstream.status, bytes: 0 };
    let body = upstream.body;
    if (body) {
      // Count bytes actually sent; Content-Length is often absent. An aborted download
      // still gets logged, with the partial byte count.
      const counter = new TransformStream({
        transform(chunk, controller) {
          entry.bytes += chunk.byteLength;
          controller.enqueue(chunk);
        },
      });
      ctx.waitUntil(body.pipeTo(counter.writable).catch(() => {}).then(() => log(env, request, url, entry)));
      body = counter.readable;
    } else {
      ctx.waitUntil(log(env, request, url, entry));
    }
    const response = new Response(body, upstream);
    response.headers.set("Cache-Control", "private, no-store");
    response.headers.set("X-Robots-Tag", "noindex");
    return response;
  },
};
