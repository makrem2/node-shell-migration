#!/usr/bin/env python3
"""Is this Node.js version affected by the October 2026 security release?

Usage:
  python scripts/check-node-version.py v24.22.0
  python scripts/check-node-version.py "$(node -v)" --context web
  python scripts/check-node-version.py 22.23.4 --json

Exit codes: 0 patched | 2 affected or end-of-life | 3 cannot tell
Offline. Reads a version string; it does not inspect any server.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _nodeadvisory as adv  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("version", help='e.g. "v24.22.0" or the output of `node -v`')
    ap.add_argument("--context", choices=["web", "cli", "ci", "build", "unknown"], default="unknown",
                    help="where this version was observed (default: unknown)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    pv = adv.parse_version(a.version)
    if not pv:
        print("error: could not find a x.y.z version in %r" % a.version, file=sys.stderr)
        return 3
    res = adv.classify(*pv)
    res["context"] = a.context
    if a.context in ("cli", "ci", "build", "unknown"):
        res["notes"].append(
            "This does not verify the Node.js that serves production traffic. Observe the web runtime "
            "(running container or process) separately."
        )
    res["source"] = adv.ADVISORY_URL
    res["data_checked"] = adv.DATA_CHECKED

    if a.json:
        print(json.dumps(res, indent=2))
    else:
        print("Node.js %s (%s): %s" % (res["version"], a.context, res["status"]))
        if res["fixed_in"]:
            print("  fixed in: %s on this line" % res["fixed_in"])
        by_id = {c["id"]: c for c in adv.CVES}
        for cid in res["cves"]:
            c = by_id[cid]
            print("  %s [%s]: %s" % (cid, c["severity"], c["title"]))
        for n in res["notes"]:
            print("  note: " + n)
        print("  source: %s (data checked %s)" % (adv.ADVISORY_URL, adv.DATA_CHECKED))

    return {"patched": 0, "runtime_affected": 2, "runtime_unsupported": 2}.get(res["status"], 3)


if __name__ == "__main__":
    sys.exit(main())
