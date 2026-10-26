# Exposure analysis: where does Brotli decoding happen?

Goal: set urgency and decide on interim hardening. It never replaces patching.

Labels: `reachable` (attacker-controlled data demonstrably reaches a decoder) · `possible` (plausible path, not confirmed) · `not_found_in_repo` (nothing found in first-party code; dependencies and infrastructure unchecked) · `unknown`.

## Paths to look for
1. **Direct use of Node's decoder in first-party code:** `zlib.brotliDecompress`, `brotliDecompressSync`, `createBrotliDecompress`. Ask: where does the input come from (uploads, webhooks, proxied responses, cache, message queues, user-supplied files)?
2. **Inbound request bodies:** frameworks or body parsers that decode `Content-Encoding: br` request bodies (reported for Express with body-parser by Imperva; verify in the versions you use rather than assuming). Check body-parser's `inflate` option and what the installed version supports.
3. **Outbound HTTP responses:** `fetch()`/undici decode a response by its `Content-Encoding` (reported by The Hacker News). A malicious or compromised upstream can answer `br` even if the client did not ask. Exposure grows with how untrusted the fetched hosts are (user-supplied URLs, webhooks, link previews, SSRF-adjacent features). Also check axios, got, node-fetch, needle, superagent (they may bundle their own decode paths or call `zlib`).
4. **Reverse proxies and CDNs:** a proxy that decompresses before Node sees the data changes the picture. Note it; do not assume.
5. **Dependencies:** anything that calls zlib's Brotli functions indirectly (static-file servers, `decompress` libraries, compression middleware). Pure-JS or WASM Brotli packages (`brotli`, `brotli-wasm`) use their own code and are outside this CVE; check their own advisories.
6. **Other CVEs in the same release:** outbound TLS to IP-literal hosts (hostname checks), `dns.resolve*()` on validated names (allowlists), snapshots/SEAs (`--build-snapshot`, `useSnapshot`), Permission Model flags, keep-alive HTTP Agent use.

## How to search
- `python scripts/detect-project.py <repo>` lists hints with file:line.
- `grep -rnE "brotli|content-encoding|accept-encoding" src --include=*.{js,ts,mjs,cjs}` (hints only).
- Read the proxy/CDN config in the repo (nginx, Caddy, Cloudflare, ingress) for encoding handling.

## Writing it up
For each app: label, the evidence (file:line), and what you could **not** see (infrastructure outside the repo, dependency internals). Example: "possible: server calls `fetch()` on user-supplied URLs (src/preview.ts:41); undetermined whether upstream responses can be `br` in production."
