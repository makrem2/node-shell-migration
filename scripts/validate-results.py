#!/usr/bin/env python3
"""Check that a test-results.json report is honest, and render it as Markdown.

Usage:
  python scripts/validate-results.py test-results.json
  python scripts/validate-results.py test-results.json --markdown test-results.md

The overall result is COMPUTED from the recorded evidence. If the report claims a
better result than the evidence supports, validation fails (exit 1).

Expected shape (see templates/test-results.example.json):
{
  "scope": "...",
  "runtime": {"web": {"version": "24.22.1", "source": "observed|declared|unknown",
                      "evidence": {"command": "...", "exit_code": 0, "output_excerpt": "..."}},
              "cli": {...}, "ci": {...}},
  "checks": [{"id": "...", "status": "passed|failed|blocked|skipped|not_run",
              "command": "...", "exit_code": 0, "output_excerpt": "...", "reason": "..."}],
  "findings": [{"id": "...", "severity": "high", "status": "open|fixed", "summary": "..."}],
  "claims": {"overall": "verified|partially_verified|failed|blocked|not_verified"},
  "limitations": ["..."]
}
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _nodeadvisory as adv  # noqa: E402

STATUSES = {"passed", "failed", "blocked", "skipped", "not_run"}
OVERALL = ["verified", "partially_verified", "failed", "blocked", "not_verified"]


def web_state(rt):
    """Return (state, classification) for the web runtime. state: patched|affected|unknown, observed bool."""
    web = (rt or {}).get("web") or {}
    src = web.get("source", "unknown")
    pv = adv.parse_version(web.get("version") or "")
    cls = adv.classify(*pv) if pv else None
    return src, cls


def compute(report):
    errors = []
    checks = report.get("checks") or []
    for i, c in enumerate(checks):
        cid = c.get("id", "#%d" % i)
        st = c.get("status")
        if st not in STATUSES:
            errors.append("check %s: status %r is not one of %s" % (cid, st, sorted(STATUSES)))
            continue
        if st == "passed":
            if not c.get("command"):
                errors.append("check %s: 'passed' requires the command that was run" % cid)
            if c.get("exit_code") != 0:
                errors.append("check %s: 'passed' requires exit_code 0 (got %r)" % (cid, c.get("exit_code")))
            if not (c.get("output_excerpt") or "").strip():
                errors.append("check %s: 'passed' requires an output_excerpt as evidence" % cid)
        if st == "failed" and c.get("exit_code") in (0, None) and not c.get("reason"):
            errors.append("check %s: 'failed' needs a non-zero exit_code or a reason" % cid)
        if st in ("blocked", "skipped") and not c.get("reason"):
            errors.append("check %s: '%s' requires a reason" % (cid, st))

    src, cls = web_state(report.get("runtime"))
    web_observed_patched = bool(cls and cls["status"] == "patched" and src == "observed")
    web_ev = ((report.get("runtime") or {}).get("web") or {}).get("evidence") or {}
    if src == "observed" and not (web_ev.get("command") and (web_ev.get("output_excerpt") or "").strip()):
        errors.append("runtime.web: source 'observed' requires evidence.command and evidence.output_excerpt")
        web_observed_patched = False

    statuses = [c.get("status") for c in checks]
    open_findings = [f for f in (report.get("findings") or []) if f.get("status") == "open"]
    ran = [s for s in statuses if s in ("passed", "failed")]

    if "failed" in statuses:
        overall = "failed"
    elif not ran and src != "observed":
        overall = "blocked" if "blocked" in statuses else "not_verified"
    elif not ran and src == "observed":
        overall = "partially_verified"
    elif (web_observed_patched and all(s == "passed" for s in statuses) and not open_findings and statuses):
        overall = "verified"
    else:
        overall = "partially_verified"

    answers = {
        "web_runtime_patched_observed": web_observed_patched,
        "web_runtime_declared_or_unknown": (not web_observed_patched),
        "checks_passed": sum(1 for s in statuses if s == "passed"),
        "checks_failed": sum(1 for s in statuses if s == "failed"),
        "checks_blocked_or_skipped": sum(1 for s in statuses if s in ("blocked", "skipped", "not_run")),
        "open_findings": len(open_findings),
    }
    return overall, answers, errors


def render_md(report, overall, answers):
    L = ["# Node.js security migration: results", "", "**Overall: `%s`**" % overall, ""]
    if report.get("scope"):
        L += ["Scope: " + report["scope"], ""]
    L += ["## Five questions", "", "| Question | Answer |", "|---|---|"]
    rt = report.get("runtime") or {}
    web = rt.get("web") or {}
    L.append("| Is the Node.js that serves the app patched, **observed by running it**? | %s |" %
             ("yes: Node.js %s observed" % web.get("version") if answers["web_runtime_patched_observed"]
              else "**no**: web runtime is %s (%s)" % (web.get("source", "unknown"), web.get("version") or "version unknown")))
    L.append("| Did the automated checks pass? | %d passed, %d failed, %d blocked/skipped/not run |" %
             (answers["checks_passed"], answers["checks_failed"], answers["checks_blocked_or_skipped"]))
    L.append("| Are there open security findings? | %d |" % answers["open_findings"])
    L += ["", "## Checks", "", "| Check | Status | Evidence / reason |", "|---|---|---|"]
    for c in report.get("checks") or []:
        ev = c.get("reason") or ("`%s` exit %s" % (c.get("command"), c.get("exit_code")))
        L.append("| %s | %s | %s |" % (c.get("id"), c.get("status"), ev))
    if report.get("findings"):
        L += ["", "## Findings", ""]
        for f in report["findings"]:
            L.append("- [%s] %s (%s): %s" % (f.get("severity"), f.get("id"), f.get("status"), f.get("summary")))
    if report.get("limitations"):
        L += ["", "## Limitations (read these)", ""]
        L += ["- " + x for x in report["limitations"]]
    L += ["", "_This reports what was checked. It does not mean the application is secure._", ""]
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("report")
    ap.add_argument("--markdown", help="write a Markdown rendering to this path")
    a = ap.parse_args()
    try:
        with open(a.report, "r", encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, ValueError) as e:
        print("error: cannot read %s: %s" % (a.report, e), file=sys.stderr)
        return 1

    overall, answers, errors = compute(report)
    claimed = (report.get("claims") or {}).get("overall")
    if claimed:
        if claimed not in OVERALL:
            errors.append("claims.overall %r is not one of %s" % (claimed, OVERALL))
        elif OVERALL.index(claimed) < OVERALL.index(overall) and claimed != overall:
            errors.append("claims.overall is %r but evidence supports only %r (overstated)" % (claimed, overall))
        elif claimed != overall:
            errors.append("claims.overall is %r but the evidence computes to %r" % (claimed, overall))
    if (report.get("claims") or {}).get("overall") == "verified" and not report.get("limitations") and overall != "verified":
        errors.append("a report that is not fully verified must list limitations")

    if a.markdown:
        with open(a.markdown, "w", encoding="utf-8") as fh:
            fh.write(render_md(report, overall, answers))
    print("computed overall: %s" % overall)
    for e in errors:
        print("  ERROR: " + e)
    if not errors:
        print("  report is consistent with its evidence")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
