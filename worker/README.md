# workshop-gate

A Cloudflare Worker that serves the Hugo site at `workshop.hexaplex.ch` behind personal invite links and logs every gated request to D1.

- Everything is gated except theme `/css/*`, `/js/*` and `/fonts/*` (see `run_worker_first` in `wrangler.jsonc`). This covers Relearn's full-text `searchindex.*.js` at the site root and the `*.print.html` views.
- `/workshops/<slug>/...` is only served to tokens that include `<slug>`. Site-wide paths (home, search index, root print view, 404) need any valid token.
- `/join?t=<token>` sets the session cookie and redirects. `/logout` clears it.
- Revoke an attendee by inserting into `revoked`. It takes effect on their next request.

## Setup (once)

```sh
cd worker
npm install
npx wrangler login
npx wrangler d1 create workshop-audit        # paste the id into wrangler.jsonc
npx wrangler d1 execute workshop-audit --remote --file=schema.sql
openssl rand -base64 32 | npx wrangler secret put TOKEN_KEY
```

`assets.directory` points at `../site/public`. Change it if the Hugo `publishDir` differs.

## Deploy

```sh
(cd ../site && hugo --minify) && npx wrangler deploy
```

The custom domain route creates the DNS record on the `hexaplex.ch` zone.

## Invite a cohort

```sh
# roster.csv: attendee_id,email,name,workshops   (workshops ";"-separated)
TOKEN_KEY=<same secret> npm run invites -- roster.csv --expires 2026-12-31
npx wrangler d1 execute workshop-audit --remote --file=roster.attendees.sql
```

This sends links from `roster.links.csv` to each attendee. Rosters and links are gitignored.

Revoke:

```sh
npx wrangler d1 execute workshop-audit --remote --command "INSERT INTO revoked(attendee_id) VALUES('alice')"
```

Rotating `TOKEN_KEY` invalidates every outstanding link.

## Audit

`queries.sql` has per-attendee overview, smash-and-grab windows, referer-less downloads, non-browser UAs, link sharing, and page-by-page progression with gaps.

## Test

```sh
npm test       # token + routing unit tests
npm run dev    # local Worker with a local D1; use .dev.vars for TOKEN_KEY
```

## Known limits

- One search index covers all workshops. An attendee of workshop A can read B's text through it, unless each workshop is built as its own Hugo site or search is disabled.
- `bytes` counts the body before compression.
- A token is a bearer credential. Sharing is detected (query 5), not prevented.
