# Self-hosted ATT&CK Navigator

The site serves its own copy of [ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator) (Apache-2.0) at `/navigator/`, so layer links work behind the attendee gate.

**Why not mitre-attack.github.io:** Navigator fetches `#layerURL=` with Angular `HttpClient.get` and never sets `withCredentials`. From another origin the request carries no cookie, so the gate rejects it. Same-origin fetches send the cookie, need no CORS, and each layer open is logged in D1 as a `json` row for that attendee.

## Build

```sh
navigator/build.sh            # writes site/static/navigator/ (gitignored)
```

Run it in CI before `hugo`. It needs git, Node 20+ and npm. `NAV_VERSION` pins the upstream tag (default `v5.3.2`). Bump the tag when MITRE ships a Navigator release that adds support for a new ATT&CK major version.

ATT&CK STIX data still comes from `raw.githubusercontent.com/mitre-attack/attack-stix-data` (upstream `collection_index_url`). It is public and has CORS enabled. Self-hosting it isn't possible as-is: `enterprise-attack-19.2.json` is 53.8 MB, and Workers Static Assets caps a file at 25 MiB.

## Linking layers from content

```markdown
{{< navigator layers="resources/cti/purple/configured_vs_triggered.json,resources/cti/purple/black_basta_detection_coverage.json" >}}open them in Navigator{{< /navigator >}}
```

Paths are relative to the workshop root (`/workshops/<slug>/`).

## Gate

Exclude `/navigator/*` from `run_worker_first` in `worker/wrangler.jsonc`. The bundle is public code, so gating it would only add about 6 D1 rows per Navigator load. The layers stay gated under `/workshops/*`.
