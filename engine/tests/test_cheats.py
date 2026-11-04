"""Cheatcode classification and identity-takeover detection. Standard library only.

Run from the repository root:  python3 -I -m unittest discover -s engine/tests -v
"""

import os
import sys
import unittest

ENGINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ENGINE)

from replaylib.trace import CHEAT, CONSOLE, DEFAULT_SENDER, TraceAnalysis, cheat_category, spoofed_callers  # noqa: E402

TEST = "0x00000000000000000000000000000000000000aa"
TOKEN = "0x00000000000000000000000000000000000000bb"
WHALE = "0x00000000000000000000000000000000000000cc"
PROXY = "0x00000000000000000000000000000000000000dd"
LOGIC = "0x00000000000000000000000000000000000000ee"


def node(idx, parent, caller, address, kind="CALL"):
    return {"idx": idx, "parent": parent, "trace": {"caller": caller, "address": address, "kind": kind}}


class CheatCategory(unittest.TestCase):
    def test_every_identity_cheat_is_impersonation(self):
        for name in ("prank", "startPrank", "broadcast", "startBroadcast"):
            self.assertEqual(cheat_category(name), "impersonation", name)

    def test_tracing_and_rollback_cheats_count_as_state(self):
        for name in ("pauseTracing", "resumeTracing", "revertTo", "revertToState", "broadcastRawTransaction", "mockCalls"):
            self.assertEqual(cheat_category(name), "state", name)

    def test_unknown_cheats_fail_closed(self):
        self.assertEqual(cheat_category("someFutureCheat"), "state")
        self.assertEqual(cheat_category("0xdeadbeef"), "state")

    def test_harmless_cheats_stay_neutral(self):
        for name in ("label", "stopPrank", "assertGt", "assertEq", "parseJsonUint", "serializeString", "toBase64",
                     "getBlockNumber", "recordLogs", "addr"):
            self.assertEqual(cheat_category(name), "neutral", name)

    def test_host_access_is_host(self):
        for name in ("ffi", "readFileBinary", "writeFileBinary", "envString", "envOr"):
            self.assertEqual(cheat_category(name), "host", name)


class SpoofedCallers(unittest.TestCase):
    def test_honest_call_tree_has_no_spoofed_caller(self):
        nodes = [node(0, None, DEFAULT_SENDER, TEST), node(1, 0, TEST, TOKEN), node(2, 1, TOKEN, WHALE)]
        self.assertEqual(spoofed_callers(nodes), [])

    def test_caller_that_did_not_make_the_call_is_spoofed(self):
        # No cheatcode in sight: the mismatch alone gives it away (hidden or unknown cheat).
        nodes = [node(0, None, DEFAULT_SENDER, TEST), node(1, 0, WHALE, TOKEN)]
        self.assertEqual(spoofed_callers(nodes), [WHALE])

    def test_delegatecall_keeps_the_parents_identity(self):
        nodes = [node(0, None, DEFAULT_SENDER, TEST), node(1, 0, TEST, PROXY),
                 node(2, 1, TEST, LOGIC, "DELEGATECALL"), node(3, 2, PROXY, TOKEN)]
        self.assertEqual(spoofed_callers(nodes), [])

    def test_spoof_below_a_delegatecall_is_found(self):
        nodes = [node(0, None, DEFAULT_SENDER, TEST), node(1, 0, TEST, PROXY),
                 node(2, 1, TEST, LOGIC, "DELEGATECALL"), node(3, 2, WHALE, TOKEN)]
        self.assertEqual(spoofed_callers(nodes), [WHALE])

    def test_cheatcode_and_console_calls_are_ignored(self):
        nodes = [node(0, None, DEFAULT_SENDER, TEST), node(1, 0, WHALE, CHEAT), node(2, 0, WHALE, CONSOLE)]
        self.assertEqual(spoofed_callers(nodes), [])

    def test_default_sender_is_not_an_identity_takeover(self):
        # vm.broadcast() without an argument sends from Foundry's default sender.
        nodes = [node(0, None, DEFAULT_SENDER, TEST), node(1, 0, DEFAULT_SENDER, TOKEN)]
        self.assertEqual(spoofed_callers(nodes), [])

    def test_each_address_is_reported_once(self):
        nodes = [node(0, None, DEFAULT_SENDER, TEST), node(1, 0, WHALE, TOKEN), node(2, 0, WHALE, PROXY)]
        self.assertEqual(spoofed_callers(nodes), [WHALE])


SCOPED = "0x00000000000000000000000000000000000000f1"
OTHER = "0x00000000000000000000000000000000000000f2"
VICTIM = "0x00000000000000000000000000000000000000f3"
ERC20 = "0x00000000000000000000000000000000000000f4"
ATTACKER = TEST
TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def word(addr):
    return "0x" + "0" * 24 + addr[2:]


def log_node(idx, parent, emitter, src, dst, amount=5):
    return {"idx": idx, "parent": parent, "trace": {"caller": "", "address": emitter, "kind": "CALL", "success": True},
            "logs": [{"address": emitter, "raw_log": {"topics": [TOPIC, word(src), word(dst)], "data": "0x" + "%064x" % amount}}]}


def analysis(nodes):
    for n in nodes:
        n["trace"].setdefault("success", True)
    nodes = [{**n, "children": [m["idx"] for m in nodes if m.get("parent") == n["idx"]]} for n in nodes]
    return TraceAnalysis({"traces": [["Execution", {"arena": nodes}]]}, {}, [], [])


class LossThroughScope(unittest.TestCase):
    def test_victim_itself_in_scope(self):
        an = analysis([node(0, None, "", ATTACKER), log_node(1, 0, ERC20, SCOPED, ATTACKER)])
        self.assertTrue(an.loss_through([SCOPED]))
        self.assertFalse(an.loss_through([OTHER]))

    def test_outside_victim_drained_through_an_in_scope_contract(self):
        an = analysis([node(0, None, "", ATTACKER), node(1, 0, ATTACKER, SCOPED), log_node(2, 1, ERC20, VICTIM, ATTACKER)])
        self.assertTrue(an.loss_through([SCOPED]))

    def test_callback_from_an_in_scope_contract_does_not_cover_the_theft(self):
        an = analysis([node(0, None, "", ATTACKER), node(1, 0, ATTACKER, SCOPED), node(2, 1, SCOPED, ATTACKER),
                       log_node(3, 2, ERC20, VICTIM, ATTACKER)])
        self.assertFalse(an.loss_through([SCOPED]))

    def test_harmless_call_to_an_in_scope_contract_does_not_count(self):
        an = analysis([node(0, None, "", ATTACKER), node(1, 0, ATTACKER, SCOPED), log_node(2, 0, ERC20, VICTIM, ATTACKER)])
        self.assertFalse(an.loss_through([SCOPED]))

    def test_empty_scope_covers_nothing(self):
        an = analysis([node(0, None, "", ATTACKER), log_node(1, 0, ERC20, VICTIM, ATTACKER)])
        self.assertFalse(an.loss_through([]))


if __name__ == "__main__":
    unittest.main()
