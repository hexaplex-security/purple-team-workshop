#!/usr/bin/env bash
# Builds MITRE ATT&CK Navigator for same-origin hosting at /navigator/ on the workshop site.
# Same origin means layer fetches carry the attendee cookie, so layers stay behind the gate.
# Usage: navigator/build.sh [output dir]   (default: site/static/navigator)
set -euo pipefail

NAV_VERSION="${NAV_VERSION:-v5.3.2}"
BASE_HREF="${BASE_HREF:-/navigator/}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/site/static/navigator}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

git clone -q --depth 1 --branch "$NAV_VERSION" https://github.com/mitre-attack/attack-navigator.git "$WORK/src"
cd "$WORK/src/nav-app"
npm ci --no-audit --no-fund --ignore-scripts
NG_CLI_ANALYTICS=false npx ng build --configuration production --base-href "$BASE_HREF"

mkdir -p "$OUT"
find "$OUT" -mindepth 1 -delete
cp -R dist/browser/. "$OUT/"
# Upstream sample layers and docs aren't needed on the site.
rm -rf "$OUT/layers" "$OUT"/*.md
echo "$NAV_VERSION" > "$OUT/VERSION"
echo "Navigator $NAV_VERSION built into $OUT"
