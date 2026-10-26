# Interim mitigations (NOT fixes)

The Node.js advisory lists no official mitigation. The ideas below are defensive hardening derived from the advisory's description, **not vendor-endorsed and not verified here**. Updating Node.js is the only fix. Use these only to buy time, record them as `mitigation_applied` (never `fixed`), and remove the "fixed" claim from reports.

| Exposure | Stopgap | Caveats |
|---|---|---|
| Inbound request bodies | Reject requests with `Content-Encoding: br` at the proxy (nginx: `if ($http_content_encoding = "br") { return 415; }` in the server block) | Breaks legitimate clients that send Brotli bodies (rare). Test the rule. |
| Express/body-parser | Set `inflate: false` so compressed bodies are rejected | Rejects gzip/deflate too. Check your installed body-parser version's docs. |
| Direct `zlib.brotli*` on user data | Stop accepting Brotli input from untrusted sources until patched | A size limit alone does not prevent memory corruption. |
| Outbound `fetch`/HTTP clients | Restrict fetching to an allowlist of trusted hosts; block user-supplied URLs | No clean "disable Brotli decode" switch is known for fetch; do not assume one exists. |
| Any | Run as an unprivileged user in a minimal container with a read-only filesystem and restricted egress | Limits blast radius only. |

Always state in the report: "Mitigation applied; runtime still unpatched."
