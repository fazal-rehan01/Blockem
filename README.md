# Blockem

Blockem is a Firefox desktop extension (Manifest V2) that blocks adult and phishing/malware domains, filters adult-content URL keywords, enforces SafeSearch, and hides media whose metadata matches the selected keyword set.

## Install in Firefox

1. Open `about:debugging#/runtime/this-firefox`.
2. Choose **Load Temporary Add-on…**.
3. Select this project's `manifest.json`.

To create a distributable Firefox build, run `./build.sh`; the package is created at `dist/blockem-firefox.zip`. Temporary add-ons are removed when Firefox closes; signed installation is required for permanent use.

## Settings and lists

Blockem ships with starter blocklists you can use right away:

- `blocklists/adult-domains.txt` — adult-content domains
- `blocklists/phishing-malicious.txt` — phishing and malware domains
- `blocklists/nsfw-keywords.txt` — NSFW keywords matched against URL text

Add one domain per line, or use hosts-file lines such as `0.0.0.0 example.com`, then reload the list files in the dashboard. Custom adult and phishing lists can be pasted or imported as text in the dashboard; each list can be edited, cleared, and backed up as JSON. Domains match the exact hostname and its subdomains. Built-in keyword sets vary by Relaxed, Standard, and Strict mode.

Optional remote list updates let Blockem fetch refreshed lists from URLs you configure (disabled by default). When enabled, each download is capped at 2 MB and validated before replacing cached lists.

The popup provides per-site status, whitelist controls, protection toggles, strictness, recent activity, and timed or restart-lifetime pauses. In the dashboard, optional Firefox container profiles configure adult blocking, strictness, SafeSearch, and a whitelist per container. Password protection is opt-in; it stores only a cryptographically random salt and salted SHA-256 hash, never the password. Passwords cannot be recovered.

Optional scheduled remote list updates are disabled by default. Only after enabling the feature and configuring URL(s) may Blockem make network requests; each text response is size-limited to 2 MB and validated before replacing cached lists. No other remote calls are made. Optional strict response inspection is also disabled by default; when enabled it inspects (without changing or storing) main-frame `text/html` response bytes and reports detection of configured blocked-domain strings in the browser console. It is pass-through inspection, not a page rewrite or substitute for request blocking.

## Local data and privacy

Settings, custom lists, remote list caches, password hashes, temporary pause state, and the bounded 20-entry activity log are stored in `browser.storage.local`. Activity entries contain only a hostname, reason, and timestamp. Block pages do not retain the original URL, and response scanning does not store page contents. Blockem does not collect or transmit browsing history, page content, URLs, search terms, passwords, telemetry, or settings. The only network activity is the explicitly enabled remote-list fetches to the user's configured sources.

## Known limitations

Keyword filtering operates on URL text using word boundaries and may miss obfuscated terms or occasionally match a legitimate address. Visual/media filtering is heuristic: it checks media URLs and accessible metadata (`alt`, `title`, `aria-label`, and lazy-load attributes), not image pixels, so it cannot identify content from visual appearance alone. Dynamic filtering can be disabled independently to reduce page observation overhead. Response inspection is limited to main-frame HTML and only observes configured blocklist domain strings; encrypted content is inspected locally after Firefox receives it, but arbitrary content classification is not performed.

## Project layout

- `manifest.json` — Firefox Manifest V2 permissions and persistent background page.
- `background.js` — blocking, SafeSearch, local settings, activity, pause timers, remote list updates, container profiles, and optional response inspection.
- `shared.js` — pure normalization and matching helpers.
- `content-script.js` — local media metadata scanning.
- `popup.*`, `options.*`, `blocked.*` — accessible extension UI.
- `blocklists/` — intentionally empty built-in user-managed lists.
- `build.sh` — Firefox-only packager.
# Blockem
# Blockem
# Blockem
# Blockem
