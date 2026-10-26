---
name: node-shell-migration
description: Detect, patch and verify Node.js applications exposed to the October 21, 2026 Node.js security release (Brotli decoder remote code execution CVE-2026-111497 plus nine other CVEs; fixed in 22.23.4, 24.22.1 and 26.12.1) or running an end-of-life Node.js. Use this skill whenever the user asks if their Node.js app, Docker image, CI, serverless function or server is vulnerable, mentions CVE-2026-111497, Brotli RCE, "Node.js security release", upgrading or patching Node 18/20/22/24/26, a Dockerfile `FROM node:`, .nvmrc, engines.node, or following up an npm audit, even if they do not name the CVE. Finds which Node.js version actually serves traffic, plans and applies the fix on a separate git branch, runs the project's tests, and reports honestly what was and was not verified.
---

# node-shell-migration

Find out whether a Node.js application is exposed to the October 2026 Node.js security release, fix it safely, and report honestly what was and was not verified.

**What the vulnerability is (verify before relying on it, see Step 0):** On 2026-10-21 Node.js fixed 10 CVEs in the 22.x, 24.x and 26.x lines. The headline one, CVE-2026-111497, is an out-of-bounds write in the Brotli decoder bundled with Node.js. Attacker-supplied Brotli data decompressed by the app can lead to a crash, memory disclosure or remote code execution. Fixed in **22.23.4, 24.22.1, 26.12.1**. Node.js 20 and older get no fix. Details: `references/advisory.md`.

This is "a flaw in the runtime", not "Node.js was hacked". Exposure depends on whether untrusted data reaches Brotli decompression, but **patching is required either way**: other fixed CVEs (TLS hostname checks, DNS) are exposed by ordinary outbound connections.

## Ground rules (never break these)

1. **Never run exploit code.** Do not craft, fetch or send malformed Brotli data, even to your own staging server. Verification is by observing the patched runtime version, not by attacking it.
2. **Never deploy** or touch production servers, production databases or production secrets. Prepare the change; a human deploys.
3. **Never print secrets.** Do not read or echo `.env*`, key files or CI secrets. `scripts/detect-project.py` already skips env files.
4. **Never report a check as passed unless it actually ran** in this session with exit code 0 and captured output. Unrunnable checks are `blocked` with the reason, never silently skipped.
5. **Never invent versions, CVEs or results.** Use only `references/advisory.md` and sources you fetched. If unsure, say "unknown".
6. **Never "fix" by weakening:** no `--force`, `--legacy-peer-deps` just to go green, no disabling `npm audit`, no deleting tests or features, no lowering TLS verification.
7. **Never discard the user's uncommitted work.** Work on a new branch; stash or ask first.
8. **"Not reachable" never means "skip the patch".** Exposure analysis only sets urgency and interim hardening.

## Workflow

### Step 0: Refresh the facts
Read `references/advisory.md`. If you have web access, re-check https://nodejs.org/en/blog/vulnerability/october-2026-security-releases and the release pages for newer patch releases (a later security release may raise the target versions). Record the date you checked, or record that you could not. Data in this skill was checked 2026-10-26.

### Step 1: Look around (no edits)
```bash
python scripts/detect-project.py <repo> --json --output detect.json   # plus human-readable run
node -v                                    # only if Node is present; this is the CLI runtime
node -p "process.versions.brotli + ' shared=' + process.config.variables.node_shared_brotli"
```
Find every Node.js app in the repo (monorepos have several) and every place a Node version is declared. Keep roles apart:

| Role | Meaning | Matters for |
|---|---|---|
| **web** | what serves production traffic (final Docker stage, serverless runtime, platform setting) | the RCE; this is the one that counts |
| **build** | earlier Docker stages | supply chain; lower priority |
| **ci** | what runs tests | test validity |
| **dev/cli** | `.nvmrc`, laptops | developer machines |
| **constraint** | `engines.node` | policy only; says nothing about what runs |

### Step 2: Classify
For each app, assign one or more:
- `runtime_affected`: version is below the fixed patch on a supported line. Patch now, same major.
- `runtime_unsupported`: line not covered by the fix (Node 20 and older, odd-numbered lines). Needs a major migration (see `references/migration-paths.md`).
- `deployment_mismatch`: repo declares one version, deployment uses another.
- `dependency_issue`: a package has its own advisory (`npm audit`, e.g. a separately installed `undici`).
- `unknown`: not enough evidence. State exactly what is missing. A floating tag (`node:22`) is `unknown`, not patched.

`python scripts/check-node-version.py "<version>" --context web|cli|ci` gives the verdict for any concrete version. Exit codes: 0 patched, 2 affected or end-of-life, 3 cannot tell.

### Step 3: Exposure analysis (urgency, not permission to skip)
Read `references/exposure-analysis.md`. Label each app `reachable`, `possible`, `not_found_in_repo` or `unknown`. Never write "not vulnerable". If reachable or possible, offer `references/interim-mitigations.md` as a stopgap that is **not a fix**.

### Step 4: Plan before touching anything
Fill `templates/migration-plan.md` into `migration-plan.md`: target versions with source URLs, stages, risks, rollback. Show it. If the user asked for report-only, stop here and give the findings.

### Step 5: Change (only when asked), on a branch
```bash
git switch -c security/node-patch-2026-10
```
One stage per commit, in this order:
1. **Runtime pin**: Dockerfile / `.nvmrc` / CI / platform setting to the exact patched version on the **same major** (e.g. `node:24.22.1-bookworm-slim`). Rebuild with `--pull` so a cached older layer is not reused. Pin to a patch version and note it needs bumping on future releases.
2. **Dependencies**: `npm audit`, then update flagged packages within semver. Report anything that needs a major bump instead of forcing it.
3. **Major migration** only if the line is unsupported, one major at a time (`references/migration-paths.md`), tests after each.
Do not raise `engines.node` minimums without telling the user; it can break their consumers.

### Step 6: Test what exists
Run what the project really has: install from the lockfile (`npm ci` / `pnpm i --frozen-lockfile` / `yarn --immutable`), build, lint, type-check, unit and integration tests, `npm audit --omit=dev`. Capture command, exit code and an output excerpt for each. No Docker, no DB, no network, no test script: mark `blocked` with the reason.

### Step 7: Verify the web runtime (the step people skip)
A patched Dockerfile does not prove production is patched. Strongest to weakest evidence:
1. `node -v` output from the **running** staging/production container or process (ask the user to run it and paste, or use access you legitimately have).
2. `docker run --rm <the built image> node -v` on the image that will be deployed.
3. Declared in a file. Record as `declared`. This is **not** verification.

Also record `process.versions.brotli` / `node_shared_brotli` if distro builds are involved. A managed platform (Lambda, Vercel, App Engine) patches on its own schedule; link the provider notice and say the repo cannot prove it.

### Step 8: Report
Write `test-results.json` (template: `templates/test-results.example.json`) then:
```bash
python scripts/validate-results.py test-results.json --markdown test-results.md
```
The validator computes the overall result from your evidence and rejects overstatements. Then write `migration-report.md` answering these five questions separately, because each can be true while the others are false:

1. Is the Node.js that serves the app patched, **observed by running it**?
2. Is the application migration complete?
3. Did the automated checks pass (counts, and which were blocked)?
4. Was the web runtime checked, or only declared?
5. Are security findings still open?

Overall result: `verified` (everything in scope ran and passed, web runtime observed patched, no open findings) · `partially_verified` · `failed` · `blocked` · `not_verified`. Even `verified` means "the checked things are fine", never "the app is secure". Always list limitations.

## Special cases
- **No shell or no internet (claude.ai sandbox):** analyse and plan only; every runtime-dependent step is `blocked`.
- **Distro/vendor Node builds:** version strings may mislead (backports, system Brotli). Result is `unknown` until the vendor's notice is checked.
- **Single executable apps / snapshots:** rebuild them with the patched runtime; old binaries embed the old runtime (CVE-2026-106074 also affects snapshot-built entropy).
- **Bun/Deno:** out of scope for these CVEs. Say so rather than guessing.

## Reference map
- `references/advisory.md`: all 10 CVEs, affected lines, fixed versions, sources, what is disputed
- `references/exposure-analysis.md`: where Brotli decoding happens in a Node app and how to look for it
- `references/interim-mitigations.md`: stopgaps (not fixes)
- `references/migration-paths.md`: major-version upgrade steps, Docker and CI specifics
- `templates/`: plan and results templates · `examples/`: worked example
