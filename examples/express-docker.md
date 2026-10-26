# Worked example: Express API in Docker, Node 24.22.0

**Ask:** "Use node-shell-migration to check this project. Report only."

**Findings (from `detect-project.py`):**
- web: `Dockerfile:4  FROM node:24.22.0-bookworm-slim` → `runtime_affected` (fixed in 24.22.1)
- build: `Dockerfile:2  FROM node:20-alpine AS build` → `runtime_unsupported` (lower priority; build stage only)
- ci: `.github/workflows/ci.yml  node-version: [20, 22, 24]` → 20 unsupported; 22 and 24 are floating majors → `unknown`
- exposure: `src/a.js:2` calls `zlib.brotliDecompress` → label `possible`; input origin must be checked.

**Plan:** (1) pin web image to `node:24.22.1-bookworm-slim`, build with `--pull`; (2) move build stage and CI matrix off Node 20 (separate commit); (3) `npm audit`.

**Report excerpt:**
| Question | Answer |
|---|---|
| Web runtime patched, observed? | **no**: image rebuilt and `docker run --rm app:rc1 node -v` printed `v24.22.1`, but production not observed |
| Migration complete? | runtime pin yes; CI matrix cleanup yes |
| Checks passed? | 3 passed, 0 failed, 1 blocked (staging smoke test: no access) |
| Open findings? | 1 (`possible` exposure at `src/a.js:2` pending input review) |

Overall: `partially_verified`.
