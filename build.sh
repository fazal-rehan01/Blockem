#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="$ROOT/dist"

rm -rf "$DIST"
mkdir -p "$DIST/firefox"
cp "$ROOT"/{manifest.json,background.js,content-script.js,shared.js,blocked.html,blocked.js,blocked.css,options.html,options.js,options.css,popup.html,popup.js,popup.css} "$DIST/firefox/"
cp -R "$ROOT/blocklists" "$ROOT/icons" "$DIST/firefox/"

if command -v python3 >/dev/null 2>&1; then
  python3 "$ROOT/tools/zip_build.py" "$DIST/firefox" "$DIST/blockem-firefox.zip"
else
  printf 'python3 not available; skipping zip archive\n' >&2
fi

printf 'Built Firefox extension:\n  %s\n' "$DIST/firefox"
