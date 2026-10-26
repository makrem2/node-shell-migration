# node-shell-migration

**A skill for AI coding agents that finds out whether your Node.js application is exposed to the October 2026 Node.js security release, fixes it safely, and tells you honestly what was and wasn't verified.**

On 2026-10-21 Node.js fixed 10 CVEs in the 22.x, 24.x and 26.x lines. The most serious, **CVE-2026-111497**, is an out-of-bounds write in the bundled Brotli decoder that can lead to remote code execution when an app decompresses attacker-supplied Brotli data. Fixed in **22.23.4, 24.22.1 and 26.12.1**. Node.js 20 and older get no fix. ([official advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases))

Ask your agent (Claude Code, Codex, Copilot, Cursor, Gemini CLI, OpenCode, ...) something like *"check this project for the Node.js Brotli CVE"*. The agent then:

1. Works out which Node.js version **actually serves your traffic**, not just the one on your laptop.
2. Tells you whether it is affected, end-of-life, or fine.
3. Looks for places where untrusted Brotli data could reach a decoder (urgency, not an excuse to skip the patch).
4. Plans the fix, applies it on a separate git branch, one stage per commit, and runs your tests.
5. Writes a report that separates "fixed and checked" from "not checked yet".

It never deploys, never runs exploits, never sends malformed payloads, and never reports a test as passed unless it ran.

> Inspired by the structure of [Ademking/php2shell-migration](https://github.com/Ademking/php2shell-migration). No code or text was copied.

## Quick start
```bash
python scripts/install.py            # all supported agents on this computer (Python 3.8+)
```
Open your agent in your Node.js project and ask:

> Use node-shell-migration to check this project and make a plan. Don't change anything yet.

Other installs: `--scope project --project /path/to/repo` (share with your team) · `--tool claude-code` · `--mode symlink` (live edits) · `--zip dist/node-shell-migration.zip` (claude.ai or Claude API; the sandbox has no access to your servers, so you get analysis and a plan, not a verified fix) · `--uninstall` · `--list`.

## What to ask
| You want to... | Ask |
|---|---|
| Know if you're affected | "Use node-shell-migration to check this project. Report only, don't change files." |
| Get a plan | "Make a migration plan: target Node.js version, risks, rollback." |
| Patch fast | "Pin the Docker image and CI to the patched Node.js for our line, run the tests, write the report." |
| Escape an old Node | "This app runs Node 18. Plan an incremental move to a supported LTS and list the blockers." |
| Check a server you manage | "Here is `node -v` from our staging container: ... Is it patched?" |

## Scripts that work without an agent
Python only, offline, read-only.
```bash
python scripts/check-node-version.py "$(node -v)"          # exit 0 patched | 2 affected/EOL | 3 can't tell
python scripts/detect-project.py /path/to/repo             # runtimes, roles, exposure hints
python scripts/validate-results.py test-results.json --markdown test-results.md
```
`detect-project.py` never runs your code, never reads `.env*`, and prints only extracted version tokens and file:line (not whole config lines), so secrets in Dockerfiles/CI files are not echoed.

## Reading the result
| Result | Meaning |
|---|---|
| `verified` | Everything in scope ran and passed, the web runtime was **observed** patched, no open findings. Still not "the app is secure". |
| `partially_verified` | Progress, but something wasn't checked or a finding is open. Read the limitations. |
| `failed` | A check failed. |
| `blocked` | Nothing could be checked yet (no Node, no access...). |
| `not_verified` | Nothing run (plan only). |

The result is computed from recorded evidence by `validate-results.py`; the agent cannot round it up.

## Honest limits
- Static inspection reads declarations. Only observing the running web runtime proves what is deployed.
- Floating tags (`node:22`) are reported as **unknown**, not patched.
- Distro/vendor Node builds may backport fixes or use a system Brotli; the version string alone is then inconclusive.
- Advisory data was checked on 2026-10-26. Details of CVE-2026-111497 exploitability are partly disputed between secondary sources; see `references/advisory.md`.
- The helper scripts have unit tests (`python -m unittest discover -s tests`). The skill has **not** been tested end to end with any agent.
- Exposure analysis uses heuristics and can miss paths (dependencies, proxies, infrastructure).

## Layout
`SKILL.md` (agent instructions) · `scripts/` · `references/` · `templates/` · `examples/` · `tests/`. Built on the open [Agent Skills format](https://agentskills.io/specification). License: MIT.
