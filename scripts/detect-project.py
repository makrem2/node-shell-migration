#!/usr/bin/env python3
"""Inventory a repository for Node.js runtime declarations and exposure signals.

Usage:
  python scripts/detect-project.py /path/to/repo
  python scripts/detect-project.py . --json --output detect.json

Read-only and offline. It never runs your code, never reads .env files, and prints only
extracted version tokens and file:line locations (never whole config lines), so secrets
in Dockerfiles or CI files are not echoed.
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _nodeadvisory as adv  # noqa: E402

SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", ".nuxt", ".turbo", ".cache",
             "coverage", ".svelte-kit", "out", ".output", "vendor", ".venv", "__pycache__"}
SRC_EXT = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx")
MAX_FILE = 1_000_000

FRAMEWORKS = {
    "express": "Express", "fastify": "Fastify", "koa": "Koa", "@hapi/hapi": "hapi", "@nestjs/core": "NestJS",
    "next": "Next.js", "nuxt": "Nuxt", "@remix-run/node": "Remix", "@sveltejs/kit": "SvelteKit",
    "astro": "Astro", "@adonisjs/core": "AdonisJS", "restify": "restify", "sails": "Sails",
    "@trpc/server": "tRPC", "hono": "Hono", "elysia": "Elysia (Bun-first)",
}
BODY_PARSERS = {"body-parser", "raw-body", "express", "koa-bodyparser", "@koa/bodyparser", "co-body", "fastify"}
HTTP_CLIENTS = {"undici", "axios", "got", "node-fetch", "needle", "superagent", "ky", "make-fetch-happen", "request"}
COMPRESSION = {"compression", "shrink-ray-current", "iltorb", "brotli", "brotli-wasm", "@fastify/compress",
               "koa-compress", "express-static-gzip", "decompress", "decompress-response"}

RE_BROTLI_API = re.compile(r"\b(brotliDecompress(?:Sync)?|createBrotliDecompress|BrotliDecompress)\b")
RE_BR_HEADER = re.compile(r"(content-encoding|accept-encoding)[^\n]{0,80}\bbr\b", re.I)
RE_FETCH = re.compile(r"(?<![\w.])fetch\s*\(|\bundici\b|\bnode-fetch\b|\bfrom\s+['\"]axios['\"]|\brequire\(['\"](axios|got|node-fetch)['\"]\)")
RE_ZLIB_FILE = re.compile(r"\bZipFile\b")
RE_SNAPSHOT = re.compile(r"--build-snapshot|useSnapshot|--experimental-sea-config|\bsea-config\b")
RE_PERMISSION = re.compile(r"--permission\b|--allow-fs-(?:read|write)")


def rel(path, root):
    return os.path.relpath(path, root).replace(os.sep, "/")


def read(path, limit=MAX_FILE):
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def walk(root):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for f in fn:
            yield os.path.join(dp, f)


def add_decl(decls, root, path, role, source, raw, line=None, extra=None):
    spec = adv.parse_spec(raw)
    cls = adv.classify_spec(spec)
    d = {"file": rel(path, root), "line": line, "role": role, "source": source,
         "declared": cls.get("declared") or raw, "kind": spec["kind"], "status": cls["status"],
         "fixed_in": cls.get("fixed_in"), "cves": cls.get("cves", []), "notes": cls.get("notes", [])}
    if extra:
        d.update(extra)
    decls.append(d)


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def parse_dockerfile(text, path, root, decls):
    aliases = {}
    stages = []
    for m in re.finditer(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", text, re.I | re.M):
        image, alias = m.group(1), m.group(2)
        ln = line_of(text, m.start())
        resolved = aliases.get(image, image)
        stages.append((resolved, alias, ln))
        if alias:
            aliases[alias] = resolved
    for i, (image, alias, ln) in enumerate(stages):
        final = i == len(stages) - 1
        role = "web" if final else "build"
        tag = None
        m = re.match(r"^(?:docker\.io/library/|library/)?node(?::([^@\s]+))?(@sha256:\S+)?$", image)
        m2 = re.search(r"nodejs(\d+)(?:-|$|:)", image) if "distroless" in image else None
        m3 = re.match(r"^cgr\.dev/chainguard/node:(\S+)$", image)
        if m:
            tag = m.group(1)
            if tag is None and m.group(2):
                add_decl(decls, root, path, role, "Dockerfile FROM node@digest", "unresolved-digest", ln,
                         {"declared": "node" + m.group(2)[:20] + "..."})
                continue
            tag = (tag or "latest").split("-")[0]
        elif m2:
            tag = m2.group(1)
        elif m3:
            tag = m3.group(1).split("-")[0]
        if tag is not None:
            add_decl(decls, root, path, role, "Dockerfile FROM", tag, ln,
                     {"note_stage": "final stage (probable production runtime)" if final else "earlier build stage"})
        elif "${" in image or image.startswith("$"):
            add_decl(decls, root, path, role, "Dockerfile FROM (variable)", image, ln)


def scan_config(path, root, decls, pkgs):
    name = os.path.basename(path)
    low = name.lower()
    text = None
    if low in (".nvmrc", ".node-version"):
        text = read(path, 4096)
        if text:
            first = text.strip().splitlines()[0] if text.strip() else ""
            add_decl(decls, root, path, "dev/cli", name, first, 1)
    elif low == ".tool-versions":
        text = read(path, 8192) or ""
        for i, ln in enumerate(text.splitlines(), 1):
            m = re.match(r"^\s*nodejs\s+(\S+)", ln)
            if m:
                add_decl(decls, root, path, "dev/cli", ".tool-versions", m.group(1), i)
    elif low == "package.json":
        text = read(path)
        try:
            data = json.loads(text) if text else {}
        except ValueError:
            data = {}
        if isinstance(data, dict):
            pkgs.append((path, data))
            eng = (data.get("engines") or {}).get("node")
            if eng:
                add_decl(decls, root, path, "constraint", "package.json engines.node", eng)
            vol = (data.get("volta") or {}).get("node")
            if vol:
                add_decl(decls, root, path, "dev/cli", "package.json volta.node", vol)
    elif low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile"):
        text = read(path)
        if text:
            parse_dockerfile(text, path, root, decls)
    elif re.match(r"^(docker-)?compose.*\.ya?ml$", low) or re.match(r"^docker-compose.*\.ya?ml$", low):
        text = read(path) or ""
        for m in re.finditer(r"^\s*image:\s*['\"]?([^\s'\"#]+)", text, re.M):
            mm = re.match(r"^(?:docker\.io/library/)?node:([^@\s]+)", m.group(1))
            if mm:
                add_decl(decls, root, path, "web", "compose image", mm.group(1).split("-")[0], line_of(text, m.start()))
    elif low.endswith((".yml", ".yaml", ".toml", ".json")) or low in ("procfile",):
        text = read(path, 300_000)
        if not text:
            return
        p = rel(path, root)
        in_wf = ".github/workflows/" in p
        for m in re.finditer(r"node-version:\s*\[?([^\]\n#]+)", text):
            for part in m.group(1).split(","):
                part = part.strip().strip("'\"")
                if part:
                    add_decl(decls, root, path, "ci", "setup-node node-version", part, line_of(text, m.start()))
        if in_wf and re.search(r"node-version-file:", text):
            add_decl(decls, root, path, "ci", "setup-node node-version-file", "see .nvmrc/.node-version", None)
            decls[-1].update({"kind": "unresolved", "status": "unknown", "notes": ["Resolved from a version file; see that file's entry."]})
        for m in re.finditer(r"\bimage:\s*['\"]?(?:docker\.io/)?(?:library/)?node:([^\s'\"@]+)", text):
            if not re.match(r"^(docker-)?compose", low):
                add_decl(decls, root, path, "ci", "CI image node:", m.group(1).split("-")[0], line_of(text, m.start()))
        for m in re.finditer(r"cimg/node:([^\s'\"]+)", text):
            add_decl(decls, root, path, "ci", "CircleCI cimg/node", m.group(1), line_of(text, m.start()))
        for m in re.finditer(r"\b[Rr]untime:\s*['\"]?nodejs(\d+)(?:\.x)?", text):
            add_decl(decls, root, path, "web", "serverless/SAM/GAE runtime", m.group(1), line_of(text, m.start()),
                     {"notes": ["Managed runtime: the provider patches on its own schedule. Check the provider's notice; the repo cannot prove the patch level."]})
        for m in re.finditer(r"\"runtime\"\s*:\s*\"nodejs(\d+)(?:\.x)?\"", text):
            add_decl(decls, root, path, "web", "vercel/functions runtime", m.group(1), line_of(text, m.start()))
        for m in re.finditer(r"\bNODE_VERSION\s*[=:]\s*['\"]?([0-9][^\s'\"#,]*)", text):
            add_decl(decls, root, path, "web", "platform NODE_VERSION (Netlify/Render/...)", m.group(1), line_of(text, m.start()))


def scan_source(path, root, sig):
    text = read(path)
    if text is None:
        return
    p = rel(path, root)
    for key, rx in (("brotli_api", RE_BROTLI_API), ("br_header", RE_BR_HEADER), ("fetch_or_http_client", RE_FETCH),
                    ("zipfile_api", RE_ZLIB_FILE), ("snapshot_or_sea", RE_SNAPSHOT), ("permission_model", RE_PERMISSION)):
        for m in rx.finditer(text):
            e = sig.setdefault(key, {"count": 0, "samples": []})
            e["count"] += 1
            if len(e["samples"]) < 5:
                e["samples"].append("%s:%d" % (p, line_of(text, m.start())))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--output")
    a = ap.parse_args()
    root = os.path.abspath(a.path)
    if not os.path.isdir(root):
        print("error: not a directory: %s" % root, file=sys.stderr)
        return 1

    decls, pkgs, sig = [], [], {}
    lockfiles = set()
    for path in walk(root):
        name = os.path.basename(path)
        if name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock", "npm-shrinkwrap.json"):
            lockfiles.add(rel(path, root))
        if name.startswith(".env"):
            continue  # never read env files
        scan_config(path, root, decls, pkgs)
        if name.endswith(SRC_EXT):
            scan_source(path, root, sig)

    apps = []
    for path, data in pkgs:
        deps = {}
        for k in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            if isinstance(data.get(k), dict):
                deps.update(data[k])
        names = set(deps)
        apps.append({
            "package_json": rel(path, root), "name": data.get("name"),
            "frameworks": sorted(FRAMEWORKS[n] for n in names if n in FRAMEWORKS),
            "body_parsers": sorted(names & BODY_PARSERS),
            "http_clients": sorted(names & HTTP_CLIENTS),
            "compression_libs": sorted(names & COMPRESSION),
            "package_manager": data.get("packageManager"),
            "has_native_addons_hint": sorted(n for n in names if n in ("node-gyp", "node-addon-api", "nan", "bindings", "prebuild-install", "sharp", "bcrypt", "sqlite3", "better-sqlite3", "canvas")),
        })

    findings = []
    web = [d for d in decls if d["role"] == "web"]
    for d in decls:
        if d["role"] in ("web", "ci", "dev/cli", "build") and d["status"] in ("runtime_affected", "runtime_unsupported"):
            sev = "high" if d["role"] == "web" else "medium"
            findings.append({"severity": sev, "type": d["status"], "where": "%s:%s" % (d["file"], d["line"] or "-"),
                             "role": d["role"], "text": "%s runtime Node.js %s declared in %s is %s" % (d["role"], d["declared"], d["source"], d["status"])})
    unresolved_web = [d for d in web if d["status"] == "unknown"]
    for d in unresolved_web:
        findings.append({"severity": "medium", "type": "unknown", "where": "%s:%s" % (d["file"], d["line"] or "-"), "role": "web",
                         "text": "web runtime %s in %s cannot be classified from the repo (%s). Observe the built or running artifact." % (d["declared"], d["source"], d["kind"])})
    if not web:
        findings.append({"severity": "medium", "type": "unknown", "where": "-", "role": "web",
                         "text": "No web runtime declaration found (no final-stage Docker node image, serverless runtime, or platform NODE_VERSION). Ask where this app runs."})
    if "brotli_api" in sig:
        findings.append({"severity": "high", "type": "exposure_signal", "where": ", ".join(sig["brotli_api"]["samples"][:3]), "role": "code",
                         "text": "First-party code calls Node's Brotli decompression API. Check whether the input can be attacker-influenced (CVE-2026-111497)."})
    if "snapshot_or_sea" in sig:
        findings.append({"severity": "low", "type": "exposure_signal", "where": ", ".join(sig["snapshot_or_sea"]["samples"][:3]), "role": "code",
                         "text": "Snapshot/SEA usage found: relevant to CVE-2026-106074 (repeated randomUUID/randomInt values)."})
    if "permission_model" in sig:
        findings.append({"severity": "low", "type": "exposure_signal", "where": ", ".join(sig["permission_model"]["samples"][:3]), "role": "code",
                         "text": "Permission Model flags found: relevant to CVE-2026-106071/106073. Do not rely on it as a sandbox until patched."})

    out = {"root": root, "advisory": {"url": adv.ADVISORY_URL, "date": adv.ADVISORY_DATE, "data_checked": adv.DATA_CHECKED},
           "apps": apps, "lockfiles": sorted(lockfiles), "runtime_declarations": decls,
           "exposure_signals": sig, "findings": findings}

    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
    if a.json and not a.output:
        print(json.dumps(out, indent=2))
        return 0
    print("Project: %s" % root)
    print("Advisory: %s (%s, data checked %s)\n" % (adv.ADVISORY_URL, adv.ADVISORY_DATE, adv.DATA_CHECKED))
    for ap_ in apps:
        print("[%s] %s" % (ap_["package_json"], ap_["name"] or "(unnamed)"))
        for k in ("frameworks", "body_parsers", "http_clients", "compression_libs"):
            if ap_[k]:
                print("  %s: %s" % (k.replace("_", " "), ", ".join(ap_[k])))
    if lockfiles:
        print("\nLockfiles: " + ", ".join(sorted(lockfiles)))
    print("\nRuntime declarations (role: web = what serves traffic, ci = tests, dev/cli = laptops, build = image build stage):")
    for d in decls:
        print("  [%s] %s:%s  %s = %s  -> %s" % (d["role"], d["file"], d["line"] or "-", d["source"], d["declared"], d["status"]))
    print("\nExposure signals (hints, not proof):")
    if not sig:
        print("  none found in first-party source")
    for k, v in sig.items():
        print("  %s: %d hit(s), e.g. %s" % (k, v["count"], ", ".join(v["samples"][:3])))
    print("\nFindings:")
    if not findings:
        print("  none from static inspection (this does NOT prove the running server is patched)")
    for f in findings:
        print("  [%s] %s: %s (%s)" % (f["severity"], f["type"], f["text"], f["where"]))
    print("\nStatic inspection reads declarations only. Only observing the running web runtime proves what is deployed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
