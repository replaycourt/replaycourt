"""The check pipeline (replay.py) on paths that need no fork, no forge and no network:
UTC timestamps in every output, registration in the duplicate registry, and the S1 rule
end to end. Standard library only.

Run from the repository root:  python3 -I -m unittest discover -s engine/tests -v
"""

import contextlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import unittest

ENGINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ENGINE)

import replay  # noqa: E402
from replaylib import dedup  # noqa: E402
from replaylib import report as report_mod  # noqa: E402

UTC_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(Z|\+00:00)$")

# A report without an executable PoC: the engine judges it invalid before it would need forge.
NO_POC = """---
title: Reentrancy in the vault (PoC follows)
chain: ethereum
fork_block: 15725066
---

# Reentrancy in the vault

The withdraw function sends ETH before it updates the balance, so a contract can re-enter it
and drain every deposit. A Foundry PoC will follow in a later message.
"""

# Any executable works as "forge": this path never runs it except for `--version`.
FAKE_FORGE = shutil.which("true") or sys.executable


class Pipeline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="replaycourt-pipeline-test-")
        self.registry = os.path.join(self.tmp, "registry.jsonl")
        self.report = os.path.join(self.tmp, "report.md")
        with open(self.report, "w", encoding="utf-8") as fh:
            fh.write(NO_POC)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_check(self, report_id, *extra):
        dest = os.path.join(self.tmp, report_id)
        argv = ["check", self.report, "--json", "--quiet", "--forge", FAKE_FORGE, "--registry", self.registry,
                "--report-id", report_id, "--dest", dest] + list(extra)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = replay.main(argv)
        with open(os.path.join(dest, "verdict.json"), encoding="utf-8") as fh:
            verdict = json.load(fh)
        with open(os.path.join(dest, "summary.md"), encoding="utf-8") as fh:
            summary = fh.read()
        return code, verdict, summary, json.loads(out.getvalue())

    def seed_valid_original(self, rid="sub-1", triaged_at="2026-11-02T09:00:00Z"):
        rep = report_mod.load_report(self.report, [self.tmp])
        rep.report_id = rid
        dedup.save_entry(self.registry, dedup.make_entry(rep, None, "valid", triaged_at, None))

    def test_now_iso_is_utc(self):
        self.assertRegex(replay.now_iso(), UTC_RE)
        self.assertTrue(replay.now_iso().endswith("Z"))

    def test_timestamps_in_verdict_summary_and_registry_are_utc(self):
        # Even with a local time zone far from UTC (the worker also runs the engine with TZ=UTC).
        old_tz = os.environ.get("TZ")
        os.environ["TZ"] = "America/Los_Angeles"
        if hasattr(__import__("time"), "tzset"):
            __import__("time").tzset()
        try:
            code, v, summary, stdout = self.run_check("sub-1")
        finally:
            if old_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old_tz
            if hasattr(__import__("time"), "tzset"):
                __import__("time").tzset()
        self.assertEqual(code, 1)
        self.assertEqual(v["outcome"], "invalid")
        self.assertRegex(v["pipeline"]["started_at"], UTC_RE)
        self.assertRegex(v["pipeline"]["finished_at"], UTC_RE)
        self.assertEqual(stdout["pipeline"]["finished_at"], v["pipeline"]["finished_at"])
        self.assertIn("Checked %s" % v["pipeline"]["finished_at"], summary)
        entries = dedup.load_registry(self.registry)
        self.assertEqual([(e["id"], e["verdict_code"]) for e in entries], [("sub-1", "invalid")])
        self.assertRegex(entries[0]["triaged_at"], UTC_RE)

    def test_s1_resubmission_after_an_invalid_verdict_is_judged_on_its_own(self):
        code1, v1, _, _ = self.run_check("sub-1")
        self.assertEqual((code1, v1["outcome"]), (1, "invalid"))
        code2, v2, summary, _ = self.run_check("sub-2")
        self.assertEqual(code2, 1, "the same report after an invalid one must not be exit 3 (duplicate)")
        self.assertEqual(v2["outcome"], "invalid")
        d = v2["duplicate"]
        self.assertEqual((d["status"], d["of"]), ("none", None))
        self.assertEqual(d["candidates"][0]["id"], "sub-1")
        self.assertTrue(d["candidates"][0]["exact_copy"])
        self.assertFalse(d["candidates"][0]["eligible"])
        self.assertIn("not counted: only a valid report can be an original", summary)
        self.assertEqual([e["id"] for e in dedup.load_registry(self.registry)], ["sub-1", "sub-2"])

    def test_a_copy_of_a_valid_original_is_still_a_duplicate(self):
        self.seed_valid_original("sub-1")
        code, v, summary, _ = self.run_check("sub-4")
        self.assertEqual(code, 3)
        self.assertEqual(v["outcome"], "duplicate")
        self.assertEqual(v["duplicate"]["of"], "sub-1")
        self.assertIn("**DUPLICATE** of `sub-1`", summary)
        reg = {e["id"]: e for e in dedup.load_registry(self.registry)}
        self.assertEqual(reg["sub-4"]["duplicate_of"], "sub-1")

    def test_onchain_status_file_overrides_the_engine_record(self):
        self.seed_valid_original("sub-1")
        status = os.path.join(self.tmp, "status.json")
        with open(status, "w", encoding="utf-8") as fh:
            json.dump({"sub-1": "rejected"}, fh)  # the owner overruled the valid verdict on-chain
        code, v, _, _ = self.run_check("sub-4", "--onchain-status", status)
        self.assertEqual(code, 1)
        self.assertEqual(v["duplicate"]["status"], "none")
        self.assertEqual(v["duplicate"]["candidates"][0]["onchain_status"], "rejected")
        # the overlay is not written into the registry
        self.assertNotIn("onchain_status", dedup.load_registry(self.registry)[0])

    def test_no_register_leaves_the_registry_alone(self):
        code, _, _, _ = self.run_check("sub-1", "--no-register")
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(self.registry))


if __name__ == "__main__":
    unittest.main()
