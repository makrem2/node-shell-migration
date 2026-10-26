"""Shared advisory data and version logic for node-shell-migration.

Data source: https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
Data last checked: 2026-10-26. Always re-verify against the official page before acting.
Stdlib only. No network access.
"""
import re

ADVISORY_URL = "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases"
ADVISORY_DATE = "2026-10-21"
DATA_CHECKED = "2026-10-26"

# First patched release per supported line (from the official advisory).
FIXED = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}

# lines = release lines the official advisory lists as affected.
CVES = [
    {"id": "CVE-2026-111497", "severity": "high", "lines": [22, 24, 26],
     "title": "Brotli decoder out-of-bounds write permits remote code execution"},
    {"id": "CVE-2026-105482", "severity": "high", "lines": [22, 24, 26],
     "title": "dns.resolve*() truncates names containing a NUL char"},
    {"id": "CVE-2026-105483", "severity": "high", "lines": [24, 26],
     "title": "TLS hostname bypass when the IP is written with fullwidth digits"},
    {"id": "CVE-2026-106069", "severity": "high", "lines": [22, 24, 26],
     "title": "TLS hostname bypass when the host loosely resolves to an IP address"},
    {"id": "CVE-2026-105481", "severity": "medium", "lines": [22, 24, 26],
     "title": "Keep-alive socket accepts a response written before the request was sent"},
    {"id": "CVE-2026-106072", "severity": "medium", "lines": [22, 24, 26],
     "title": "DNS SAN authenticates IP endpoints for non-canonical IPv4 hostnames"},
    {"id": "CVE-2026-106074", "severity": "medium", "lines": [22, 24, 26],
     "title": "randomUUID()/randomInt() entropy caches saved into snapshots and SEAs"},
    {"id": "CVE-2026-106070", "severity": "low", "lines": [26],
     "title": "zlib.ZipFile returns attacker-controlled bytes after failed header validation"},
    {"id": "CVE-2026-106071", "severity": "low", "lines": [26],
     "title": "Permission Model filesystem over-grant via wildcard radix lookup"},
    {"id": "CVE-2026-106073", "severity": "low", "lines": [22, 24, 26],
     "title": "Permission Model bypass with fs.realpathSync"},
]

_VER = re.compile(r"v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.\-]+))?")


def fmt(t):
    return ".".join(str(x) for x in t)


def parse_version(text):
    """Return ((major, minor, patch), prerelease_or_None) or None."""
    m = _VER.search(text or "")
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))), m.group(4)


def classify(ver, prerelease=None):
    """Classify an exact Node.js version tuple.

    status: patched | runtime_affected | runtime_unsupported | unknown
    """
    major = ver[0]
    res = {"version": fmt(ver), "status": "unknown", "cves": [], "fixed_in": None, "notes": []}
    if prerelease:
        res["notes"].append("Pre-release/nightly build (%s): cannot be compared to release versions." % prerelease)
        return res
    if major in FIXED:
        res["fixed_in"] = fmt(FIXED[major])
        if ver < FIXED[major]:
            res["status"] = "runtime_affected"
            res["cves"] = [c["id"] for c in CVES if major in c["lines"]]
        else:
            res["status"] = "patched"
        res["notes"].append(
            "Version string only. Distro or vendor builds (Debian, Ubuntu, RHEL, Alpine, NodeSource) "
            "may backport fixes or link a system Brotli (check process.config.variables.node_shared_brotli)."
        )
    elif major < 22 or major % 2 == 1:
        res["status"] = "runtime_unsupported"
        res["cves"] = [c["id"] for c in CVES]
        res["notes"].append(
            "Line is not covered by the October 2026 releases (even majors 20 and older, and odd-numbered "
            "lines). The advisory says end-of-life versions are always affected and Node.js 20 and older "
            "get no fix. Confirm status at https://nodejs.org/en/about/eol ; commercial support exists "
            "via OpenJS partners."
        )
    else:
        res["notes"].append(
            "Major %d is newer than the data in this skill. Check the official advisory and release page." % major
        )
    return res


def parse_spec(text):
    """Interpret a version *declaration* (.nvmrc, Docker tag, CI value, ...).

    Returns dict(kind=exact|major|alias|range|unresolved, ...).
    """
    t = (text or "").strip().strip("'\"")
    if not t:
        return {"kind": "unresolved", "raw": text}
    if "${" in t or t.startswith("$") or "{{" in t or "matrix." in t:
        return {"kind": "unresolved", "raw": t, "why": "variable or template, resolved at build time"}
    low = t.lower()
    if low in ("lts", "lts/*", "latest", "current", "node", "stable") or low.startswith("lts/"):
        return {"kind": "alias", "raw": t, "why": "floating alias resolves at build time"}
    if low.startswith("nodejs"):
        t = t[len("nodejs"):].strip()
    if t[:1] in "<>~^=" or " " in t or "||" in t:
        return {"kind": "range", "raw": t}
    pv = parse_version(t)
    if pv and re.match(r"^v?\d+\.\d+\.\d+", t):
        return {"kind": "exact", "version": pv[0], "pre": pv[1], "raw": t}
    m = re.match(r"^v?(\d+)(?:\.(?:x|\*|\d+))?(?:\.(?:x|\*))?(?:[-.].*)?$", t)
    if m:
        return {"kind": "major", "major": int(m.group(1)), "raw": t}
    return {"kind": "unresolved", "raw": t}


def classify_spec(spec):
    """Turn a parsed declaration into a classification dict."""
    k = spec["kind"]
    if k == "exact":
        r = classify(spec["version"], spec.get("pre"))
        r["declared"] = spec["raw"]
        return r
    if k == "major":
        major = spec["major"]
        r = {"version": None, "declared": spec["raw"], "status": "unknown", "cves": [], "fixed_in": None, "notes": []}
        if major in FIXED:
            r["fixed_in"] = fmt(FIXED[major])
            r["notes"].append(
                "Floating major tag: the patch level depends on when the image or runtime was last "
                "built or pulled. Patched only if it resolves to >= %s. Observe the built artifact." % fmt(FIXED[major])
            )
        else:
            r.update(classify((major, 0, 0)))
            r["version"], r["declared"] = None, spec["raw"]
            r["notes"].insert(0, "Major line only (no patch level declared).")
        return r
    why = spec.get("why") or ("version range, not a concrete runtime" if k == "range" else "cannot be resolved from the file")
    return {"version": None, "declared": spec.get("raw"), "status": "unknown", "cves": [], "fixed_in": None,
            "notes": ["Unresolved: " + why + "."]}
