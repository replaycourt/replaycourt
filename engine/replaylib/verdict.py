"""Decision rules: valid / invalid / needs_human, plus a severity hint.

Principle: the burden of proof is on the report. 'valid' only when the PoC passes on the
fork AND the execution trace shows a real outflow of value from third parties to the
attacker, without taking over identities or faking state with cheatcodes. Anything doubtful
goes to a human.

The rules are the ones of the prototype, unchanged. Machine-readable values are plain codes:
verdict codes valid/invalid/needs_human, severity levels critical/high/medium/low (plus
none/unclear) and a 'provisional' flag.
"""

from typing import Dict, List, Optional

from .i18n import fmt_int, t
from .trace import ROLE_FOREIGN_IDENTITY, ROLE_VICTIM_IMPERSONATED

VALID, INVALID, HUMAN = "valid", "invalid", "needs_human"

EXIT_VALID, EXIT_INVALID, EXIT_HUMAN, EXIT_DUPLICATE = 0, 1, 2, 3
EXIT_USAGE, EXIT_BAD_REPORT, EXIT_UNAVAILABLE, EXIT_INTERNAL = 64, 65, 69, 70
EXIT_FOR = {VALID: EXIT_VALID, INVALID: EXIT_INVALID, HUMAN: EXIT_HUMAN}

SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]
UNCLEAR = "unclear"


def label(code: str) -> str:
    """Localized label of a verdict code."""
    return t("verdict." + code)


def severity_hint(usd: Optional[float], fraction: Optional[float], theft: bool) -> Dict:
    basis = []
    if usd is not None:
        basis.append(t("sev.damage_usd", fmt_int(round(usd))))
    if fraction is not None:
        basis.append(t("sev.fraction", round(fraction * 100)))
    if usd is None and fraction is None:
        level = "high" if theft else "medium"
        basis.append(t("sev.not_valued"))
    elif (usd or 0) >= 1e6 or (fraction or 0) >= 0.5:
        level = "critical"
    elif (usd or 0) >= 1e5 or (fraction or 0) >= 0.1:
        level = "high"
    elif (usd or 0) >= 1e3 or (fraction or 0) >= 0.01:
        level = "medium"
    else:
        level = "low"
    if not theft and SEVERITY_ORDER.index(level) > SEVERITY_ORDER.index("medium"):
        level = "medium"
        basis.append(t("sev.griefing_capped"))
    return {"level": level, "provisional": False, "basis": basis, "scale": t("sev.scale")}


def _sev(level: str, basis: List[str]) -> Dict:
    return {"level": level, "provisional": False, "basis": basis}


def decide(ctx: Dict) -> Dict:
    """ctx holds: static_block, build, tests, selected, analysis, cheat, local, fork, code_checks,
    declared_victims, valuation."""
    reasons, warnings = [], []  # type: List[str], List[str]

    def out(code, sev=None):
        return {"verdict_code": code, "verdict": label(code), "reasons": reasons, "warnings": warnings,
                "severity_hint": sev or _sev("none", [])}

    if ctx.get("static_block"):
        reasons.append(t("r.not_executed", ctx["static_block"]))
        return out(HUMAN, _sev(UNCLEAR, [t("sev.not_executed")]))

    build = ctx["build"]
    if not build["ok"]:
        reasons.append(t("r.no_compile"))
        return out(INVALID)

    sel = ctx.get("selected")
    if not sel:
        reasons.append(t("r.no_test_ran"))
        return out(INVALID)
    if sel.get("timed_out"):
        reasons.append(t("r.timeout"))
        return out(HUMAN, _sev(UNCLEAR, [t("sev.timeout")]))
    if sel["status"] != "Success":
        reasons.append(t("r.test_fails", sel.get("reason") or t("r.no_reason")))
        return out(INVALID)
    reasons.append(t("r.test_passes_local" if ctx.get("local") else "r.test_passes", sel["name"]))

    an = ctx["analysis"]
    cheat = ctx["cheat"]
    gains = {a: v for a, v in an.attacker_net.items() if v > 0}
    spent = {a: -v for a, v in an.attacker_net.items() if v < 0}
    losers = an.losers
    pranked = an.pranked_summary()

    imp = [p for p in pranked if p.get("role") == ROLE_VICTIM_IMPERSONATED]
    if imp:
        reasons.append(t("r.prank_as_victim", ", ".join(p["address"] for p in imp)))
        return out(INVALID)

    if not gains and not losers:
        reasons.append(t("r.no_value_moved"))
        if cheat["funding_to_attacker"] or cheat["state_manipulation"]:
            reasons.append(t("r.balances_from_cheats"))
        return out(INVALID)

    # What a program accepts: enforced for fork runs. A local run proves nothing about a deployment
    # and goes to a human below anyway.
    if not ctx.get("local"):
        min_block, used = ctx.get("min_block"), ctx["fork"].get("declared_block")
        if min_block is not None and (used is None or used < min_block):
            reasons.append(t("r.below_min_block", used if used is not None else "?", min_block))
            return out(INVALID)
        scope = ctx.get("scope")
        if scope is not None and not an.loss_through(scope):
            reasons.append(t("r.out_of_scope", ", ".join(scope) or t("r.scope_none_on_chain")))
            return out(INVALID)

    human = []
    if ctx.get("local"):
        human.append(t("h.local"))
    fork = ctx["fork"]
    if fork.get("declared_block") is not None and fork.get("poc_fork_block") is not None \
            and fork["declared_block"] != fork["poc_fork_block"]:
        human.append(t("h.block_mismatch", fork["poc_fork_block"], fork["declared_block"]))
    for cc in ctx.get("code_checks", []):
        if cc["role"] == "target" and cc.get("has_code") is False:
            human.append(t("h.target_no_code", cc["address"]))
    if cheat["state_manipulation"]:
        human.append(t("h.state_cheat", ", ".join(
            sorted({"%s@%s" % (c["cheat"].split("(")[0], (c.get("address") or "?")[:10]) for c in cheat["state_manipulation"]}))))
    if cheat["funding_to_attacker"]:
        human.append(t("h.funding_cheat", ", ".join(
            sorted({c["cheat"].split("(")[0] for c in cheat["funding_to_attacker"]}))))
    priv = [p for p in pranked if p.get("role") == ROLE_FOREIGN_IDENTITY]
    if priv:
        human.append(t("h.foreign_prank", ", ".join(p["address"] for p in priv)))
    if cheat["host"]:
        human.append(t("h.host_cheats", ", ".join(sorted({c["cheat"] for c in cheat["host"]}))))
    if ctx.get("foreign_forks"):
        human.append(t("h.foreign_fork", ", ".join(ctx["foreign_forks"])))
    dv = ctx.get("declared_victims") or []
    if dv:
        vd = an.victim_deltas(dv)
        if not any(v < 0 for d in vd.values() for v in d.values()):
            human.append(t("h.declared_victims_lose_nothing",
                           ", ".join(sorted({x["address"] for x in losers})[:3]) or t("w.none")))
    if gains and not losers:
        human.append(t("h.gain_without_loser"))
    if losers and not gains:
        human.append(t("h.loss_without_gain"))
    if spent:
        val = ctx.get("valuation") or {}
        g, s = val.get("attacker_gain_usd"), val.get("attacker_spent_usd")
        if g is not None and s is not None and val.get("attacker_fully_priced") and g > s:
            warnings.append(t("w.own_capital_net_positive"))
        else:
            human.append(t("h.own_capital_unpriced", len(spent)))

    for c in cheat["time"]:
        warnings.append(t("w.time_cheat", c["cheat"], c["args"]))
    for c in cheat["fork"]:
        if c["cheat"].startswith("rollFork"):
            warnings.append(t("w.roll_fork"))
    if any(c["phase"] == "Execution" for c in cheat["expect"]):
        warnings.append(t("w.expect_cheats"))

    val = ctx.get("valuation") or {}
    sev = severity_hint(val.get("damage_usd"), val.get("max_fraction"), theft=bool(gains))
    if human:
        reasons.extend(human)
        sev = dict(sev)
        sev["provisional"] = True
        return out(HUMAN, sev)

    reasons.append(t("r.valid"))
    return out(VALID, sev)
