#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="$ROOT/dist"

rm -rf "$DIST"
mkdir -p "$DIST/firefox"
cp "$ROOT"/{manifest.json,background.js,content-script.js,shared.js,blocked.html,blocked.js,blocked.css,options.html,options.js,options.css,popup.html,popup.js,popup.css} "$DIST/firefox/"
cp -R "$ROOT/blocklists" "$ROOT/icons" "$DIST/firefox/"

if command -v zip >/dev/null 2>&1; then
  (cd "$DIST/firefox" && zip -qr ../blockem-firefox.zip .)
fi

printf 'Built Firefox extension:\n  %s\n' "$DIST/firefox"
