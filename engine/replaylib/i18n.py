"""Message catalog for the human-readable output: CLI messages, reasons, warnings and summary.md.

Machine-readable values in verdict.json (verdict codes, severity levels, roles, statuses) are
plain codes and do not come from this catalog.
"""

from typing import Optional


def t(key: str, *args) -> str:
    msg = MESSAGES.get(key)
    if msg is None:
        return key if not args else "%s %r" % (key, args)
    return msg % args if args else msg


def fmt_int(n) -> str:
    return "{:,}".format(int(n))


def fmt_number(x: float, digits: Optional[int] = 2) -> str:
    """Thousands separator and decimal point; digits=None -> 6 significant digits."""
    if digits is None:
        return "%.6g" % x
    return "{:,.{d}f}".format(x, d=digits)


MESSAGES = {
    # ------------------------------------------------------------------ verdict labels
    "verdict.valid": "valid",
    "verdict.invalid": "invalid",
    "verdict.needs_human": "needs human",
    "sevlevel.critical": "critical",
    "sevlevel.high": "high",
    "sevlevel.medium": "medium",
    "sevlevel.low": "low",
    "sevlevel.none": "none",
    "sevlevel.unclear": "unclear",
    "dupstatus.duplicate": "duplicate",
    "dupstatus.possible": "possible duplicate",
    "dupstatus.none": "no duplicate",

    # ------------------------------------------------------------------ report.py
    "report.file_missing": "report file not found: %s",
    "poc.outside_roots": "PoC path is outside the allowed directories: %s",
    "poc.ref_missing": "referenced PoC file is missing: %s",
    "poc.none_found": "no Foundry PoC found (neither a ```solidity block nor a 'poc:' reference).",
    "poc.no_pragma": "PoC has no 'pragma solidity' - not a Solidity test file.",
    "poc.no_test": "PoC has no test function (function test...).",
    "static.ffi": "vm.ffi - shell call (disabled in foundry.toml)",
    "static.fs": "file-system cheatcode (disabled)",
    "static.env": "reads/sets environment variables",
    "static.rpc": "vm.rpc - arbitrary RPC request",
    "static.http": "HTTP cheatcode",
    "static.rpcurl": "reads the configured RPC URLs (vm.rpcUrl*)",
    "static.external_url": "PoC forks via its own URL (%s) instead of an alias",

    # ------------------------------------------------------------------ rpc.py
    "rpc.error": "RPC error %s: %s",
    "rpc.unexpected": "unexpected response: %r",
    "rpc.wrong_chain": "wrong chain id %d (expected %d)",
    "rpc.block_after_head": "fork block %d is after the current head %d",
    "rpc.no_archive": "no archive access: %s",

    # ------------------------------------------------------------------ trace.py (call summary)
    "trace.creates": "creates %s",
    "trace.value": " [value %.6g %s]",
    "trace.callback": " [callback to attacker]",
    "trace.as_prank": " [as %s via vm.prank]",
    "trace.undone": " [rolled back]",
    "trace.hidden": "  (… %d more calls hidden)",
    "role.attacker": "attacker",
    "role.attacker_declared": "attacker (declared)",
    "role.attacker_creates_contracts": "attacker (creates contracts)",
    "role.attacker_eoa_with_gain": "attacker (EOA with gain)",
    "role.victim_impersonated": "victim (identity taken over)",
    "role.foreign_identity": "foreign identity (privileged action?)",

    # ------------------------------------------------------------------ verdict.py
    "sev.damage_usd": "damage approx. %s USD",
    "sev.fraction": "up to %d %% of a victim's holdings",
    "sev.not_valued": "amount cannot be valued",
    "sev.griefing_capped": "no gain for the attacker (griefing) - capped",
    "sev.scale": "Direct theft: critical from 1M USD or 50 % of a holding, high from 100,000 USD or 10 %, "
        "medium from 1,000 USD or 1 %.",
    "sev.not_executed": "not executed",
    "sev.timeout": "timeout",
    "sev.not_checked": "not checked",
    "r.not_executed": "The PoC was not executed for safety reasons: %s",
    "r.no_compile": "The PoC does not compile - the report proves nothing.",
    "r.no_test_ran": "Forge ran no test (no matching test in the PoC).",
    "r.timeout": "The PoC run exceeded the time limit.",
    "r.test_fails": "The PoC test fails on the fork: %s",
    "r.no_reason": "no reason given",
    "r.test_passes": "PoC test `%s` passes on the fork.",
    "r.test_passes_local": "PoC test `%s` passes (local mode, no fork).",
    "r.prank_as_victim": "The \"damage\" only happens because the PoC acts as the victim via a cheatcode such as vm.prank or vm.broadcast (%s). "
        "A real attacker cannot do that.",
    "r.out_of_scope": "The value does not leave through a contract in the program's scope (%s).",
    "r.scope_none_on_chain": "none on this chain",
    "r.below_min_block": "The fork block %s is older than this program's first accepted block %s: a bug "
        "that old is not new to this program.",
    "r.no_value_moved": "No measurable value movement: neither a gain for the attacker nor a loss for third "
        "parties. The test passes but proves no damage.",
    "r.balances_from_cheats": "The balances shown come from cheatcodes (deal/store), not from the attack.",
    "r.valid": "Real outflow of value from third parties to the attacker, without taking over identities "
        "and without faked state.",
    "h.local": "Local mode: the bundled code was checked, not a deployment. Whether it matches the "
        "protocol's code must be checked by a human.",
    "h.block_mismatch": "The PoC forks at block %s, the report names block %s.",
    "h.target_no_code": "The declared vulnerable contract %s has no code at the fork block.",
    "h.state_cheat": "State changed via cheatcode (%s).",
    "h.funding_cheat": "Attacker's starting capital comes from a cheatcode (%s) - check the net gain "
        "against that capital.",
    "h.foreign_prank": "The PoC acts as a foreign address via a cheatcode such as vm.prank or vm.broadcast (%s) - privileged precondition?",
    "h.host_cheats": "The PoC calls host cheatcodes (%s).",
    "h.foreign_fork": "The PoC forks from an RPC the engine did not choose (%s); the state on that fork is "
        "not verified. Only the aliases of the generated foundry.toml (e.g. \"mainnet\") are "
        "trusted.",
    "h.declared_victims_lose_nothing": "The victims named in the report lose nothing; actual losers: %s.",
    "h.gain_without_loser": "Gain without an identifiable victim (e.g. mint out of thin air) - assess the "
        "damage to the protocol.",
    "h.loss_without_gain": "Loss for third parties without a gain for the attacker (griefing/lock?) - "
        "assess the impact.",
    "h.own_capital_unpriced": "The attacker spends own capital (%d asset(s)); the net gain cannot be proven "
        "without complete prices.",
    "w.none": "none",
    "w.own_capital_net_positive": "The attacker spends own capital, but the net gain is positive at the "
        "known prices.",
    "w.time_cheat": "Time/block changed via cheatcode: %s %s",
    "w.roll_fork": "The PoC switches the fork block during the test (rollFork).",
    "w.host_cheats": "The PoC called host cheatcodes (%s); see poc_logs for what the sandbox answered.",
    "w.foreign_fork": "The PoC opened a fork from an RPC the engine did not choose (%s).",
    "w.ignored_created_token_flows": "Ignored %d Transfer/Deposit/Withdrawal event(s) emitted by contracts "
        "the PoC deployed itself (%s): anyone can emit such events, they are not "
        "value.",
    "w.expect_cheats": "The test uses expect* cheatcodes - make sure it does not only \"prove\" a revert.",

    # ------------------------------------------------------------------ replay.py
    "cli.report_not_found": "Report not found: %s",
    "cli.report_unreadable": "Report not readable: %s",
    "cli.bad_report_id": "Invalid --report-id: %r",
    "cli.report_read": "Read report %s (PoC: %s)",
    "cli.infra_reason": "Check not possible (infrastructure): %s",
    "cli.internal_reason": "Internal pipeline error: %s",
    "cli.verdict_done": "Verdict: %s (exit %d) -> %s",
    "cli.no_poc": "No executable PoC: %s",
    "cli.chain_unknown": "Chain '%s' is not configured (config/chains.json).",
    "cli.no_fork_block": "No fork block given - the latest block is used.",
    "cli.static_external_url": "The PoC forks via its own URL; that would let untrusted code reach arbitrary "
        "network targets.",
    "cli.searching_rpc": "Looking for an archive RPC for %s at block %s …",
    "cli.no_archive_rpc": "No RPC with archive access for %s at block %s is reachable (%s). Remedy: "
        "--rpc <archive-url> or local test contracts (chain: local).",
    "cli.fork_via": "Forking via %s",
    "cli.compiling": "Compiling the PoC …",
    "cli.build_timeout": "Compiling exceeded %d s.",
    "cli.no_solc": "Solidity compiler not available: %s",
    "cli.running_poc": "Running the PoC (forge test%s) …",
    "cli.fork_failed": "Fork/RPC failed during the run: %s",
    "cli.rpc_error_in_run": "RPC error in the PoC run: %s",
    "cli.infra_text_from_poc": "The failure text looks like an RPC error, but the PoC's own code reverted "
        "with it (no failed cheatcode call produced it); judged as a failing PoC, "
        "not as an infrastructure error.",
    "cli.foreign_fork_failed": "The PoC tried to fork from an RPC the engine did not choose (%s). Only the "
        "aliases of the generated foundry.toml are allowed.",
    "cli.other_tests_fail": "Other tests in the PoC fail: %s",
    "cli.analysing_trace": "Analysing the execution trace …",
    "cli.checking_dups": "Checking for duplicates …",
    "cli.possible_dup": "Possibly a duplicate of `%s` - compare before accepting.",
    "cli.dup_of": "Duplicate of `%s` (already triaged).",
    "cli.unknown_chain": "Unknown chain: %s",
    "cli.remove_needs_id": "registry remove needs --id",
    "cli.removed": "removed: %d",
    "cli.cleared": "Registry cleared.",
    "cli.forge_missing": "forge not found: %s (install Foundry or set REPLAYCOURT_FORGE)",
    "label.attack_contract": "attack contract",
    "label.test_contract": "test contract",
    "label.attacker": "attacker",
    "label.target": "target",
    "label.victim": "victim",
    "label.attacker_total": "attacker total (%d addr.)",

    # ------------------------------------------------------------------ render.py
    "render.title": "# Triage verdict: %s",
    "render.verdict_head": "**Verdict: %s**",
    "render.severity_head": " · severity hint: **%s**",
    "render.exit_head": " · exit code %d",
    "render.provisional": "provisional %s",
    "render.dup_line": "**DUPLICATE** of `%s` - close as duplicate (technical verdict above).",
    "render.possible_dup_line": "Possibly a duplicate of `%s` - please compare.",
    "render.report_line": "Report `%s` (%s), author: %s, claimed severity: %s. Checked %s, took %s s.",
    "render.h_reasons": "## Reasons",
    "render.sev_basis": "- Severity basis: %s",
    "render.claimed_vs_hint": "- The report claims \"%s\", the check suggests \"%s\".",
    "render.h_warnings": "## Warnings",
    "render.h_fork": "## Fork",
    "render.local_mode": "- Local mode without a fork (chain `%s`).",
    "render.fork_line": "- Chain `%s` (chain id %s), fork block per report: %s (source: %s), actually used "
        "in the PoC run: %s.",
    "render.rpc_line": "- RPC: %s",
    "render.none": "none",
    "render.rpc_rejected": "  - rejected: %s - %s",
    "render.h_run": "## PoC run",
    "render.build_line": "- Compile: %s (%s s, solc %s)",
    "render.error_caps": "ERROR",
    "render.test_line": "- Test `%s`: %s%s, gas %s, duration %s",
    "render.passed": "PASSED",
    "render.failed": "FAILED",
    "render.poc_logs": "- PoC output (for information only, not evidence):",
    "render.h_balances": "## Balance changes",
    "render.balances_note": "Computed from the Transfer/Deposit/Withdrawal events and ETH values in the "
        "execution trace - not from what the PoC prints.",
    "render.balances_header": "| Role | Address | Asset | Change | Share of holdings | approx. USD |",
    "rowrole.attacker": "attacker",
    "rowrole.victim": "victim (per report)",
    "rowrole.loser": "loser",
    "render.raw_amount": "%s%s (raw)",
    "render.damage": "damage approx. %s USD",
    "render.native_price": "native coin price at the block: %s USD (Chainlink)",
    "render.unpriced": "no price: %s",
    "render.valuation": "Valuation: %s.",
    "render.h_cheats": "## Cheatcodes",
    "render.cheat_calls": "- Calls: %s",
    "render.cheat_funding": "- Starting capital: `%s` to %s (%s)",
    "render.cheat_state": "- State change: `%s` at %s (%s)",
    "render.prank_identities": "- vm.prank identities:",
    "render.h_code_checks": "## Address check at the fork block",
    "ccrole.target": "target",
    "ccrole.victim": "victim",
    "render.has_code": "contract with code",
    "render.no_code": "no code (EOA or non-existent)",
    "render.not_checkable": "not checkable",
    "render.h_trace": "## Call trace (shortened, without reads and cheatcodes)",
    "render.h_static": "## Static findings in the PoC",
    "render.h_dedup": "## Duplicate check",
    "render.no_prior": "- No earlier reports in the registry.",
    "render.compared": "- Compared with %d earlier report(s); result: **%s**.",
    "render.candidate": "  - `%s`: text %.2f · code %.2f · fingerprint %.2f -> %s",
    "render.not_original": " (not counted: only a valid report can be an original; this one is `%s`)",
    "render.footer": "Machine-readable: `verdict.json` in the same folder. Tool: ReplayCourt engine %s, %s.",
}
