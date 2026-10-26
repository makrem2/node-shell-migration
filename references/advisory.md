# October 2026 Node.js security release: facts

Primary source (official): https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
Released: 2026-10-21 · Data last checked by this skill: 2026-10-26 · Re-check before acting.

## Fixed versions
| Line | Fixed in | Release page |
|---|---|---|
| 26.x | **26.12.1** | https://nodejs.org/en/blog/release/v26.12.1/ |
| 24.x | **24.22.1** | https://nodejs.org/en/blog/release/v24.22.1/ |
| 22.x | **22.23.4** | https://nodejs.org/en/blog/release/v22.23.4/ |
| 20.x and older, odd-numbered lines | **no fix** | The advisory states end-of-life versions are always affected. |

Node.js 20's end-of-life date (reported as 2026-04-30 by a secondary source, vendure.io) should be confirmed at https://nodejs.org/en/about/eol .

Bundled dependency updates in this release: c-ares, ca-cert (eMudhra intermediate CA compromise), OpenSSL (24.x, 22.x), SQLite (22.x), Undici.

## The ten CVEs
| CVE | Severity | Lines | Summary |
|---|---|---|---|
| CVE-2026-111497 | high | 22, 24, 26 | Brotli decoder out-of-bounds write; crash, memory disclosure or remote code execution when an app decompresses attacker-supplied Brotli via `node:zlib` |
| CVE-2026-105482 | high | 22, 24, 26 | `dns.resolve*()` / `dns.reverse()` truncate hostnames at a NUL byte; allowlist checks can be bypassed (incomplete fix of CVE-2026-48930) |
| CVE-2026-105483 | high | 24, 26 | `tls.checkServerIdentity()` mishandles IPv4 written with fullwidth digits; cert with `DNS:127.0.0.1` accepted for an IP endpoint |
| CVE-2026-106069 | high | 22, 24, 26 | TLS check validates against a different IP than connected to for leading-zero IPv4 like `0127.0.0.1` (octal vs decimal; macOS) |
| CVE-2026-105481 | medium | 22, 24, 26 | HTTP Agent keep-alive socket can accept a pre-sent response as the answer to a new request |
| CVE-2026-106072 | medium | 22, 24, 26 | Non-canonical IPv4 spellings (`0x7f.0.0.1`, `2130706433`, `127.1`) let a DNS-SAN-only cert authenticate an IP endpoint |
| CVE-2026-106074 | medium | 22, 24, 26 | `randomUUID()`/`randomInt()` entropy caches baked into user-land snapshots and SEAs; repeated values across processes |
| CVE-2026-106070 | low | 26 | `zlib.ZipFile` returns attacker-controlled bytes after failed header validation |
| CVE-2026-106071 | low | 26 | Permission Model wildcard `--allow-fs-*` over-grants |
| CVE-2026-106073 | low | 22, 24, 26 | Permission Model: `fs.realpathSync()` lacks read-permission checks |

## What is established vs. disputed (CVE-2026-111497)
- **Established (official advisory):** the flaw is in the bundled Brotli decoder; an invalid block switch was treated as "need more input" so the decoder kept writing into an 8-byte buffer; attacker-supplied Brotli data decompressed with `node:zlib` can lead to RCE.
- **Reported by secondary sources, not the advisory:** Brotli is also decoded automatically when `fetch()` reads a response sent with `Content-Encoding: br` (The Hacker News). Imperva reportedly demonstrated code execution on the official 24.22.0 image via a Brotli response read by `fetch` and via a Brotli request body handled by Express/body-parser (konfirmity.com summary).
- **Conflicting:** The Hacker News says a public proof of concept reached code execution only on a deliberately weakened test build; the Imperva summary says the official image. Treat "reliably exploitable on stock builds" as **unconfirmed**; treat "patch now" as certain.
- No in-the-wild exploitation was reported as of 2026-10-23 (getastra.com). This can change; re-check.
- Severity is rated **high**, not critical.

## Secondary sources used
thehackernews.com/2026/10/nodejs-brotli-decoder-bug-could-allow.html · konfirmity.com/advisories/nodejs-october-2026-security-releases · getastra.com/blog/security-advisory/node-js-security-release/ · socprime.com · vendure.io/blog/nodejs-security-releases-october-2026
