# Migration paths

## Patch within the same major (most cases)
22.x → 22.23.4+, 24.x → 24.22.1+, 26.x → 26.12.1+. Usually no code changes. Do this first, in its own commit.

## Unsupported lines (Node 20 and older, odd-numbered)
Preferred target: the newest **LTS** line that still receives fixes (24.x as of this skill's data; 22.x is also covered). Confirm current LTS/EOL dates at https://nodejs.org/en/about/eol and https://github.com/nodejs/release#release-schedule before choosing. Move **one major at a time**, with tests after each hop (e.g. 18 → 20 → 22). A direct jump is acceptable only if the test suite is strong and the user agrees.

Things that usually need attention on a major hop (check release notes for each major, do not assume):
- Native addons (`node-gyp`, `sharp`, `bcrypt`, `sqlite3`, `canvas`): rebuild with `npm rebuild`; check prebuilt-binary support for the new Node ABI.
- Removed or deprecated APIs and changed defaults (see each major's release notes).
- `engines.node`, `@types/node` major, TypeScript target, ESLint/Jest/Vitest versions.
- OpenSSL changes affecting legacy crypto or TLS settings.
- Package manager: lockfile format and Corepack behavior.

## Where versions hide (change all that apply)
Dockerfile(s) (every `FROM`, build args) · docker-compose · `.nvmrc` / `.node-version` / `.tool-versions` / Volta · CI (`actions/setup-node`, GitLab `image:`, CircleCI `cimg/node`) · serverless / SAM / Vercel / App Engine runtime · Netlify/Render `NODE_VERSION` · Helm charts and Kubernetes manifests · base images in other repos · developer docs.

## Docker specifics
- A floating tag like `node:22` only moves when the image is **rebuilt and pulled**. Use `docker build --pull` (and `--no-cache` if unsure) in CI.
- Prefer pinning an exact patch (`node:24.22.1-bookworm-slim`) or a digest, and schedule bumps.
- After building: `docker run --rm <image> node -v` and record it as `observed` evidence.
- Distroless/Chainguard/Alpine/Debian: confirm the tag you pick actually ships the patched version; do not assume the tag name equals the Node version.

## Rollback
Keep the previous image tag/digest. Each stage is one commit, so `git revert` per stage. Do not run database migrations in this change unless the user asks.
