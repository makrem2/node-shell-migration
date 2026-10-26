import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(HERE), "scripts")
sys.path.insert(0, SCRIPTS)
import _nodeadvisory as adv  # noqa: E402


def run(script, *args):
    p = subprocess.run([sys.executable, os.path.join(SCRIPTS, script)] + list(args), capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


class Classify(unittest.TestCase):
    def test_patched_boundaries(self):
        for v in [(22, 23, 4), (22, 24, 0), (24, 22, 1), (26, 12, 1), (26, 13, 0)]:
            self.assertEqual(adv.classify(v)["status"], "patched", v)

    def test_affected_boundaries(self):
        for v in [(22, 23, 3), (24, 22, 0), (26, 12, 0), (22, 0, 0)]:
            self.assertEqual(adv.classify(v)["status"], "runtime_affected", v)

    def test_eol_and_odd_lines(self):
        for v in [(20, 99, 0), (18, 0, 0), (25, 1, 0), (23, 0, 0), (21, 0, 0)]:
            self.assertEqual(adv.classify(v)["status"], "runtime_unsupported", v)

    def test_newer_major_unknown(self):
        self.assertEqual(adv.classify((28, 0, 0))["status"], "unknown")

    def test_prerelease_unknown(self):
        self.assertEqual(adv.classify((24, 22, 1), "nightly2026")["status"], "unknown")

    def test_line_specific_cves(self):
        r = adv.classify((22, 23, 3))
        self.assertIn("CVE-2026-111497", r["cves"])
        self.assertNotIn("CVE-2026-105483", r["cves"])  # 24/26 only
        self.assertNotIn("CVE-2026-106070", r["cves"])  # 26 only
        r26 = adv.classify((26, 12, 0))
        self.assertIn("CVE-2026-106070", r26["cves"])


class Specs(unittest.TestCase):
    def test_floating_major_is_not_patched(self):
        r = adv.classify_spec(adv.parse_spec("22"))
        self.assertEqual(r["status"], "unknown")
        self.assertEqual(r["fixed_in"], "22.23.4")

    def test_exact(self):
        self.assertEqual(adv.classify_spec(adv.parse_spec("v24.22.1"))["status"], "patched")
        self.assertEqual(adv.classify_spec(adv.parse_spec("24.22.0"))["status"], "runtime_affected")

    def test_unresolved(self):
        for s in ["${NODE_VERSION}", "lts/*", "latest", ">=18", "^20.1.0"]:
            self.assertEqual(adv.classify_spec(adv.parse_spec(s))["status"], "unknown", s)

    def test_major_eol(self):
        self.assertEqual(adv.classify_spec(adv.parse_spec("20-alpine".split("-")[0]))["status"], "runtime_unsupported")


class Cli(unittest.TestCase):
    def test_exit_codes(self):
        self.assertEqual(run("check-node-version.py", "v24.22.1")[0], 0)
        self.assertEqual(run("check-node-version.py", "v24.22.0")[0], 2)
        self.assertEqual(run("check-node-version.py", "v18.0.0")[0], 2)
        self.assertEqual(run("check-node-version.py", "garbage")[0], 3)

    def test_detect_no_secret_leak(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "Dockerfile"), "w") as f:
                f.write('FROM node:24.22.0\nENV TOKEN="hunter2-secret"\n')
            with open(os.path.join(d, ".env"), "w") as f:
                f.write("KEY=hunter2-secret\n")
            code, out = run("detect-project.py", d)
            self.assertEqual(code, 0)
            self.assertNotIn("hunter2", out)
            self.assertIn("runtime_affected", out)

    def test_detect_multistage_roles(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "Dockerfile"), "w") as f:
                f.write("FROM node:20 AS b\nFROM node:24.22.1\n")
            code, out = run("detect-project.py", d, "--json")
            data = json.loads(out)
            roles = {x["declared"]: x["role"] for x in data["runtime_declarations"]}
            self.assertEqual(roles["20"], "build")
            self.assertEqual(roles["24.22.1"], "web")


class Validate(unittest.TestCase):
    def _report(self, **over):
        with open(os.path.join(os.path.dirname(HERE), "templates", "test-results.example.json")) as f:
            r = json.load(f)
        r.update(over)
        return r

    def _run(self, report):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(report, f)
        try:
            return run("validate-results.py", f.name)
        finally:
            os.unlink(f.name)

    def test_example_is_valid(self):
        code, out = self._run(self._report())
        self.assertEqual(code, 0, out)

    def test_overstated_claim_rejected(self):
        r = self._report()
        r["claims"] = {"overall": "verified"}
        code, out = self._run(r)
        self.assertEqual(code, 1)
        self.assertIn("overstated", out)

    def test_declared_web_runtime_cannot_be_verified(self):
        r = self._report()
        r["runtime"]["web"]["source"] = "declared"
        r["checks"] = [c for c in r["checks"] if c["status"] == "passed"]
        r["limitations"] = ["x"]
        r["claims"] = {"overall": "verified"}
        self.assertEqual(self._run(r)[0], 1)

    def test_full_verified_possible(self):
        r = self._report()
        r["checks"] = [c for c in r["checks"] if c["status"] == "passed"]
        r["claims"] = {"overall": "verified"}
        r["limitations"] = []
        code, out = self._run(r)
        self.assertEqual(code, 0, out)
        self.assertIn("verified", out)

    def test_passed_without_evidence_rejected(self):
        r = self._report()
        r["checks"][0] = {"id": "npm-ci", "status": "passed"}
        self.assertEqual(self._run(r)[0], 1)

    def test_failed_dominates(self):
        r = self._report()
        r["checks"].append({"id": "x", "status": "failed", "command": "false", "exit_code": 1})
        r["claims"] = {"overall": "failed"}
        self.assertEqual(self._run(r)[0], 0)


if __name__ == "__main__":
    unittest.main()
