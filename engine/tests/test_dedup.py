"""Duplicate registry and duplicate check (replaylib/dedup.py). Standard library only, no network.

Run from the repository root:  python3 -I -m unittest discover -s engine/tests -v
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

ENGINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ENGINE)

from replaylib import dedup  # noqa: E402
from replaylib import report as report_mod  # noqa: E402

REPORTS = os.path.join(ENGINE, "reports")

# Behaviour fingerprint of the TempleDAO/STAX drain (reports 01 and 03), as the engine computed it
# on the fork (`fingerprint` in the verdict.json of report 01).
FP_STAX = {
    "chain": "ethereum",
    "calls": ["0xd2869042e12a3506100af1d192b5b04d65137941:0x1c1c6fe5",
              "0xd2869042e12a3506100af1d192b5b04d65137941:0xbdcd9c80"],
    "losers": ["0xd2869042e12a3506100af1d192b5b04d65137941"],
    "gain_assets": ["0xbcb8b7fc9197feda75c101fa69d3211b5a30dcd9"],
}
FP_OTHER = {"chain": "ethereum", "calls": ["0x1111111111111111111111111111111111111111:0xa9059cbb"],
            "losers": ["0x2222222222222222222222222222222222222222"]}

# Same loser, one of three attack calls in common: fingerprint similarity (1/3 + 1) / 2 = 0.67,
# between the "possible" (0.50) and the "duplicate" (0.75) threshold.
FP_PARTIAL = {"chain": "ethereum",
              "calls": FP_OTHER["calls"] + ["0x3333333333333333333333333333333333333333:0x12345678",
                                            "0x4444444444444444444444444444444444444444:0x87654321"],
              "losers": FP_OTHER["losers"]}

# The judge's experiment: report 01 with one line added to the PoC, so that the first try fails.
TYPO = '        revert("typo in my first PoC");\n'


def read(name):
    with open(os.path.join(REPORTS, name), encoding="utf-8") as fh:
        return fh.read()


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="replaycourt-dedup-test-")
        self.registry = os.path.join(self.tmp, "registry.jsonl")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def report(self, text, rid):
        path = os.path.join(self.tmp, rid + ".md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        rep = report_mod.load_report(path, [self.tmp, ENGINE])
        rep.report_id = rid
        return rep

    def register(self, rep, verdict_code, triaged_at, fingerprint=None, duplicate_of=None):
        dedup.save_entry(self.registry, dedup.make_entry(rep, fingerprint, verdict_code, triaged_at, duplicate_of))

    def check(self, rep, fingerprint=None, statuses=None):
        entries = dedup.apply_onchain_status(dedup.load_registry(self.registry), statuses)
        return dedup.check(rep, fingerprint, entries)


def first_try_text():
    text = read("01_templedao_stax.md")
    marker = "    function testExploit() public {\n"
    assert marker in text
    return text.replace(marker, marker + TYPO, 1)


class RegistryFile(Tmp):
    def test_round_trip_keeps_order_and_replaces_a_re_check(self):
        a = self.report(read("01_templedao_stax.md"), "sub-1")
        b = self.report(read("02_seneca_chamber.md"), "sub-2")
        self.register(a, "valid", "2026-11-02T10:00:00Z", FP_STAX)
        self.register(b, "invalid", "2026-11-02T10:05:00Z")
        entries = dedup.load_registry(self.registry)
        self.assertEqual([e["id"] for e in entries], ["sub-1", "sub-2"])
        self.assertEqual(entries[0]["fingerprint"], FP_STAX)
        self.assertEqual(entries[0]["report_sha256"], a.sha256)
        self.assertTrue(entries[0]["text_tokens"] and entries[0]["code_tokens"])
        # A re-check of sub-1 replaces its entry (and moves it to the end); nothing is duplicated.
        self.register(a, "needs_human", "2026-11-02T11:00:00Z")
        entries = dedup.load_registry(self.registry)
        self.assertEqual([(e["id"], e["verdict_code"]) for e in entries], [("sub-2", "invalid"), ("sub-1", "needs_human")])
        self.assertFalse(os.path.exists(self.registry + ".tmp"))

    def test_missing_file_is_empty_and_broken_lines_are_skipped(self):
        self.assertEqual(dedup.load_registry(os.path.join(self.tmp, "nope.jsonl")), [])
        with open(self.registry, "w", encoding="utf-8") as fh:
            fh.write('{"id": "sub-1", "verdict_code": "valid"}\nnot json\n\n{"id": "sub-2"}\n')
        self.assertEqual([e["id"] for e in dedup.load_registry(self.registry)], ["sub-1", "sub-2"])

    def test_onchain_status_overlay_is_in_memory_only(self):
        rep = self.report(read("01_templedao_stax.md"), "sub-1")
        self.register(rep, "valid", "2026-11-02T10:00:00Z", FP_STAX)
        entries = dedup.load_registry(self.registry)
        over = dedup.apply_onchain_status(entries, {"sub-1": "rejected", "sub-9": "paid"})
        self.assertEqual(over[0]["onchain_status"], "rejected")
        self.assertNotIn("onchain_status", entries[0])
        self.assertNotIn("onchain_status", dedup.load_registry(self.registry)[0])
        self.assertIs(dedup.apply_onchain_status(entries, None), entries)

    def test_load_onchain_status_file(self):
        path = os.path.join(self.tmp, "status.json")
        self.assertEqual(dedup.load_onchain_status(None), {})
        self.assertEqual(dedup.load_onchain_status(path), {})
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"sub-1": "paid", "sub-2": 7}, fh)
        self.assertEqual(dedup.load_onchain_status(path), {"sub-1": "paid"})
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("[broken")
        self.assertEqual(dedup.load_onchain_status(path), {})


class Originals(unittest.TestCase):
    def test_only_valid_reports_are_originals(self):
        self.assertTrue(dedup.is_original({"verdict_code": "valid"}))
        for code in ("invalid", "needs_human", None):
            self.assertFalse(dedup.is_original({"verdict_code": code}), code)
        # a recorded duplicate is not an original itself (it points to one)
        self.assertFalse(dedup.is_original({"verdict_code": "valid", "duplicate_of": "sub-1"}))

    def test_onchain_status_decides_when_synced(self):
        for st in ("valid", "paid", "disputed"):
            self.assertTrue(dedup.is_original({"verdict_code": "needs_human", "onchain_status": st}), st)
        for st in ("rejected", "invalid", "expired", "withdrawn", "pending", "needs_human", "duplicate"):
            self.assertFalse(dedup.is_original({"verdict_code": "valid", "onchain_status": st}), st)

    def test_time_key_compares_utc_offsets(self):
        self.assertLess(dedup.time_key("2026-11-02T16:00:00+05:30"), dedup.time_key("2026-11-02T15:30:00Z"))
        self.assertEqual(dedup.time_key("2026-11-02T15:00:00Z"), dedup.time_key("2026-11-02T15:00:00+00:00"))
        self.assertEqual(dedup.time_key(None), float("inf"))
        self.assertEqual(dedup.time_key("yesterday"), float("inf"))


class DuplicateCheck(Tmp):
    def test_s1_invalid_first_try_does_not_make_the_fixed_report_a_duplicate(self):
        # Regression for S1 (judge review): the hunter's first try fails on the fork (typo), the
        # fixed report is the same text and almost the same PoC. Before v2 it was closed as a
        # duplicate of the hunter's own invalid report (text 1.00, code 0.98).
        first = self.report(first_try_text(), "sub-1")
        self.register(first, "invalid", "2026-11-02T15:13:06Z")  # failed PoC: no trace, no fingerprint
        fixed = self.report(read("01_templedao_stax.md"), "sub-2")
        d = self.check(fixed, FP_STAX)
        self.assertEqual(d["status"], "none")
        self.assertIsNone(d["of"])
        self.assertEqual(d["compared_with"], 1)
        cand = d["candidates"][0]
        self.assertEqual(cand["id"], "sub-1")
        self.assertEqual(cand["level"], "duplicate")  # it is similar, and the evidence says so ...
        self.assertGreaterEqual(cand["scores"]["text"], 0.99)
        self.assertGreaterEqual(cand["scores"]["code"], 0.95)
        self.assertFalse(cand["eligible"])  # ... but an invalid report is never an original
        self.assertIsNone(cand["original"])
        self.assertEqual(d["not_original"], ["sub-1"])

    def test_s1_the_same_registry_entry_marked_valid_would_be_the_original(self):
        # Control for the test above: the scores alone make it a duplicate.
        first = self.report(first_try_text(), "sub-1")
        self.register(first, "valid", "2026-11-02T15:13:06Z")
        d = self.check(self.report(read("01_templedao_stax.md"), "sub-2"), FP_STAX)
        self.assertEqual((d["status"], d["of"]), ("duplicate", "sub-1"))

    def test_identical_resubmission_after_an_invalid_verdict_is_not_a_duplicate(self):
        text = read("04_seneca_bogus.md")
        self.register(self.report(text, "sub-1"), "invalid", "2026-11-02T10:00:00Z")
        d = self.check(self.report(text, "sub-2"))
        self.assertTrue(d["candidates"][0]["exact_copy"])
        self.assertEqual(d["status"], "none")

    def test_needs_human_earlier_report_is_not_an_original(self):
        text = read("06_local_reentrancy.md")
        self.register(self.report(text, "sub-1"), "needs_human", "2026-11-02T10:00:00Z")
        self.assertEqual(self.check(self.report(text, "sub-2"))["status"], "none")

    def test_reworded_report_with_the_same_fingerprint_is_a_duplicate_of_the_valid_original(self):
        self.register(self.report(read("01_templedao_stax.md"), "sub-1"), "valid", "2026-11-02T10:00:00Z", FP_STAX)
        d = self.check(self.report(read("03_stax_duplicate.md"), "sub-3"), FP_STAX)
        self.assertEqual((d["status"], d["of"]), ("duplicate", "sub-1"))
        c = d["candidates"][0]
        self.assertEqual(c["scores"]["fingerprint"], 1.0)
        self.assertLess(c["scores"]["text"], 0.70)  # reworded: only the behaviour matches
        self.assertTrue(c["eligible"])
        self.assertEqual(d["not_original"], [])

    def test_a_possible_match_with_an_invalid_report_does_not_downgrade_a_valid_one(self):
        self.register(self.report(read("02_seneca_chamber.md"), "sub-1"), "invalid", "2026-11-02T10:00:00Z", FP_OTHER)
        partial = FP_PARTIAL
        d = self.check(self.report(read("01_templedao_stax.md"), "sub-2"), partial)
        self.assertEqual(d["candidates"][0]["level"], "possible")
        self.assertEqual(d["status"], "none")
        self.assertIsNone(d["of"])

    def test_possible_match_with_a_valid_report_is_still_reported(self):
        self.register(self.report(read("02_seneca_chamber.md"), "sub-1"), "valid", "2026-11-02T10:00:00Z", FP_OTHER)
        partial = FP_PARTIAL
        d = self.check(self.report(read("01_templedao_stax.md"), "sub-2"), partial)
        self.assertEqual((d["status"], d["of"]), ("possible", "sub-1"))

    def test_the_earliest_valid_original_is_named_across_utc_offsets(self):
        text = read("01_templedao_stax.md")
        # sub-7 was triaged at 15:30 UTC, sub-3 at 10:30 UTC (written with a local offset by engine 0.3).
        self.register(self.report(text + "\nlater copy\n", "sub-7"), "valid", "2026-11-02T15:30:00Z", FP_STAX)
        self.register(self.report(text + "\nearlier copy\n", "sub-3"), "valid", "2026-11-02T16:00:00+05:30", FP_STAX)
        self.register(self.report(text + "\nfirst, but invalid\n", "sub-1"), "invalid", "2026-11-02T14:00:00Z")
        d = self.check(self.report(text, "sub-9"), FP_STAX)
        self.assertEqual((d["status"], d["of"]), ("duplicate", "sub-3"))
        self.assertEqual(d["not_original"], ["sub-1"])

    def test_a_match_with_a_recorded_duplicate_points_to_its_original(self):
        self.register(self.report(read("01_templedao_stax.md"), "sub-1"), "valid", "2026-11-02T10:00:00Z", FP_STAX)
        self.register(self.report(read("03_stax_duplicate.md"), "sub-2"), "valid", "2026-11-02T10:05:00Z",
                      FP_STAX, duplicate_of="sub-1")
        d = self.check(self.report(read("03_stax_duplicate.md") + "\n(again)\n", "sub-3"), FP_STAX)
        self.assertEqual((d["status"], d["of"]), ("duplicate", "sub-1"))
        self.assertTrue(all(c["original"] == "sub-1" for c in d["candidates"] if c["eligible"]))

    def test_a_duplicate_of_an_original_that_is_no_longer_valid_points_nowhere(self):
        self.register(self.report(read("01_templedao_stax.md"), "sub-1"), "valid", "2026-11-02T10:00:00Z", FP_STAX)
        self.register(self.report(read("03_stax_duplicate.md"), "sub-2"), "valid", "2026-11-02T10:05:00Z",
                      FP_STAX, duplicate_of="sub-1")
        d = self.check(self.report(read("03_stax_duplicate.md") + "\n(again)\n", "sub-3"), FP_STAX,
                       statuses={"sub-1": "rejected", "sub-2": "duplicate"})
        self.assertEqual(d["status"], "none")
        self.assertEqual(sorted(d["not_original"]), ["sub-1", "sub-2"])

    def test_onchain_status_makes_a_resolved_needs_human_report_an_original(self):
        text = read("06_local_reentrancy.md")
        self.register(self.report(text, "sub-5"), "needs_human", "2026-11-02T10:00:00Z")
        later = self.report(text + "\n", "sub-8")
        self.assertEqual(self.check(later)["status"], "none")
        d = self.check(later, statuses={"sub-5": "paid"})  # the owner resolved it as valid
        self.assertEqual((d["status"], d["of"]), ("duplicate", "sub-5"))

    def test_onchain_status_removes_an_overruled_original(self):
        self.register(self.report(read("01_templedao_stax.md"), "sub-1"), "valid", "2026-11-02T10:00:00Z", FP_STAX)
        rep = self.report(read("03_stax_duplicate.md"), "sub-4")
        self.assertEqual(self.check(rep, FP_STAX, {"sub-1": "disputed"})["of"], "sub-1")
        self.assertEqual(self.check(rep, FP_STAX, {"sub-1": "rejected"})["status"], "none")

    def test_a_re_check_of_the_same_report_is_not_compared_with_itself(self):
        rep = self.report(read("01_templedao_stax.md"), "sub-1")
        self.register(rep, "valid", "2026-11-02T10:00:00Z", FP_STAX)
        d = self.check(rep, FP_STAX)
        self.assertEqual((d["status"], d["compared_with"]), ("none", 0))

    def test_reports_without_a_poc_are_not_exact_copies_of_each_other(self):
        self.register(self.report("# Bug A\n\nThe vault is broken, trust me.\n", "sub-1"), "valid", "2026-11-02T10:00:00Z")
        d = self.check(self.report("# Something else entirely\n\nUnrelated words about an oracle.\n", "sub-2"))
        self.assertFalse(d["candidates"][0]["exact_copy"])
        self.assertEqual(d["status"], "none")

    def test_different_bugs_are_not_duplicates(self):
        self.register(self.report(read("01_templedao_stax.md"), "sub-1"), "valid", "2026-11-02T10:00:00Z", FP_STAX)
        d = self.check(self.report(read("02_seneca_chamber.md"), "sub-2"), FP_OTHER)
        self.assertEqual(d["status"], "none")
        self.assertEqual(d["candidates"][0]["level"], "none")


class Similarity(unittest.TestCase):
    def test_text_normalisation_drops_code_blocks(self):
        toks = dedup.normalize_text("Drain the Vault\n```solidity\nfunction x() {}\n```\nat 0xAbCd")
        self.assertNotIn("function", toks)
        self.assertEqual(toks[:3], ["drain", "the", "vault"])

    def test_code_normalisation_ignores_comments_and_number_separators(self):
        a = dedup.normalize_code("uint a = 1_000; // note\n/* block */ address b = 0xABCDEF;")
        b = dedup.normalize_code("uint a = 1000;\naddress b = 0xABCDEF;")
        self.assertEqual(a, b)

    def test_jaccard_and_shingles(self):
        self.assertEqual(dedup.jaccard(set(), {"a"}), 0.0)
        self.assertEqual(dedup.jaccard({"a", "b"}, {"b", "c"}), 1 / 3)
        self.assertEqual(dedup.shingles(["a", "b"]), {"a b"})
        self.assertEqual(dedup.shingles(["a", "b", "c", "d"]), {"a b c", "b c d"})

    def test_fingerprint_similarity(self):
        self.assertEqual(dedup.fingerprint_similarity(FP_STAX, dict(FP_STAX)), 1.0)
        self.assertEqual(dedup.fingerprint_similarity(FP_STAX, dict(FP_STAX, chain="bsc")), 0.0)
        self.assertEqual(dedup.fingerprint_similarity(FP_STAX, None), 0.0)
        self.assertEqual(dedup.fingerprint_similarity({"chain": "ethereum"}, {"chain": "ethereum"}), 0.0)
        half = dict(FP_STAX, calls=FP_STAX["calls"][:1])
        self.assertAlmostEqual(dedup.fingerprint_similarity(FP_STAX, half), 0.75)


if __name__ == "__main__":
    unittest.main()
