"""Human-readable summary (summary.md) built from the verdict JSON, in the selected language."""

from decimal import Decimal, getcontext
from typing import Dict, List, Optional

from .i18n import fmt_int, fmt_number, t

getcontext().prec = 80


def fmt_amount(raw: int, decimals: Optional[int]) -> str:
    sign = "+" if raw > 0 else ("−" if raw < 0 else "")
    if decimals is None:
        return t("render.raw_amount", sign, fmt_int(abs(raw)))
    val = Decimal(abs(raw)) / (Decimal(10) ** decimals)
    if val >= 1:
        txt = fmt_number(float(val), 2)
    else:
        txt = fmt_number(float(val), None)
    return sign + txt


def _nz(x) -> str:
    return "–" if x is None else str(x)


def short(addr: Optional[str]) -> str:
    if not addr:
        return "?"
    return addr[:6] + "…" + addr[-4:]


def severity_text(sev: Dict) -> str:
    """'critical', 'provisional high', ... in the selected language."""
    level = sev.get("level")
    if not level:
        return ""
    txt = t("sevlevel." + level)
    if sev.get("provisional"):
        txt = t("render.provisional", txt)
    return txt


def render(v: Dict) -> str:
    L = []  # type: List[str]
    rep = v["report"]
    L.append(t("render.title", rep.get("title") or rep["id"]))
    L.append("")
    head = t("render.verdict_head", v["verdict_label"].upper())
    sev = v.get("severity_hint") or {}
    if sev.get("level"):
        head += t("render.severity_head", severity_text(sev))
    head += t("render.exit_head", v["exit_code"])
    L.append(head)
    dup = v.get("duplicate") or {}
    if dup.get("status") == "duplicate":
        L.append("")
        L.append(t("render.dup_line", dup.get("of")))
    elif dup.get("status") == "possible":
        L.append("")
        L.append(t("render.possible_dup_line", dup.get("of")))
    L.append("")
    L.append(t("render.report_line", rep["id"], rep.get("path_rel") or rep.get("file"), rep.get("author") or "–",
               rep.get("claimed_severity") or "–", v["pipeline"]["finished_at"], v["pipeline"]["duration_s"]))
    L.append("")
    L.append(t("render.h_reasons"))
    for r in v.get("reasons", []):
        L.append("- " + r)
    if sev.get("basis"):
        L.append(t("render.sev_basis", "; ".join(sev["basis"])))
    if rep.get("claimed_severity") and sev.get("level") and v["verdict"] != "invalid":
        L.append(t("render.claimed_vs_hint", rep["claimed_severity"], severity_text(sev)))
    if v.get("warnings"):
        L.append("")
        L.append(t("render.h_warnings"))
        for w in v["warnings"]:
            L.append("- " + w)

    f = v.get("fork") or {}
    L.append("")
    L.append(t("render.h_fork"))
    if f.get("local"):
        L.append(t("render.local_mode", f.get("chain")))
    else:
        L.append(t("render.fork_line", f.get("chain"), f.get("chain_id"), _nz(f.get("declared_block")),
                   f.get("block_source") or "–", _nz(f.get("poc_fork_block"))))
        L.append(t("render.rpc_line", f.get("rpc_url") or t("render.none")))
        for a in f.get("rpc_attempts", []):
            if not a.get("ok"):
                L.append(t("render.rpc_rejected", a.get("url"), a.get("reason")))

    ex = v.get("execution") or {}
    L.append("")
    L.append(t("render.h_run"))
    b = ex.get("build") or {}
    if b:
        L.append(t("render.build_line", "ok" if b.get("ok") else t("render.error_caps"), b.get("duration_s"),
                   ", ".join(b.get("solc") or []) or "?"))
        for e in (b.get("errors") or [])[:8]:
            L.append("  - `%s`" % e[:200])
    for tt in ex.get("tests") or []:
        L.append(t("render.test_line", tt["name"],
                   t("render.passed") if tt["status"] == "Success" else t("render.failed"),
                   (" – " + tt["reason"]) if tt.get("reason") else "", fmt_int(tt.get("gas") or 0),
                   tt.get("duration")))
    if ex.get("poc_logs"):
        L.append(t("render.poc_logs"))
        for line in ex["poc_logs"][:6]:
            L.append("  - `%s`" % line[:160])

    ev = v.get("evidence") or {}
    if ev.get("balance_changes"):
        L.append("")
        L.append(t("render.h_balances"))
        L.append(t("render.balances_note"))
        L.append("")
        L.append(t("render.balances_header"))
        L.append("|---|---|---|---|---|---|")
        for row in ev["balance_changes"]:
            frac = row.get("fraction_of_prebalance")
            L.append("| %s | %s `%s` | %s | %s | %s | %s |" % (
                t("rowrole." + row["role"]), row.get("label") or "", short(row["address"]),
                row.get("symbol") or short(row["asset"]), fmt_amount(int(row["delta_raw"]), row.get("decimals")),
                ("%d %%" % round(frac * 100)) if frac is not None else "–",
                fmt_number(row["usd"], 0) if row.get("usd") is not None else "–"))
    val = ev.get("valuation") or {}
    if val:
        bits = []
        if val.get("damage_usd") is not None:
            bits.append(t("render.damage", fmt_number(val["damage_usd"], 0)))
        if val.get("native_usd") is not None:
            bits.append(t("render.native_price", fmt_number(val["native_usd"], 2)))
        if val.get("unpriced_assets"):
            bits.append(t("render.unpriced", ", ".join(val["unpriced_assets"])))
        if bits:
            L.append("")
            L.append(t("render.valuation", "; ".join(bits)))

    ch = ev.get("cheatcodes") or {}
    if ch:
        L.append("")
        L.append(t("render.h_cheats"))
        counts = ch.get("counts") or {}
        L.append(t("render.cheat_calls", ", ".join("%s×%d" % (k, n) for k, n in counts.items()) or t("render.none")))
        for c in ch.get("funding_to_attacker", []):
            L.append(t("render.cheat_funding", c["cheat"], short(c.get("address")), c["phase"]))
        for c in ch.get("state_manipulation", []):
            L.append(t("render.cheat_state", c["cheat"], short(c.get("address")), c["phase"]))
    pr = ev.get("pranked") or []
    if pr:
        L.append(t("render.prank_identities"))
        for p in pr:
            L.append("  - `%s` (%s): %s" % (p["address"], "/".join(p["phases"]),
                                            t("role." + p["role"]) if p.get("role") else "?"))

    if ev.get("code_checks"):
        L.append("")
        L.append(t("render.h_code_checks"))
        for cc in ev["code_checks"]:
            L.append("- %s `%s`: %s" % (t("ccrole." + cc["role"]), cc["address"],
                                        {True: t("render.has_code"), False: t("render.no_code"),
                                         None: t("render.not_checkable")}[cc.get("has_code")]))

    if ev.get("trace_summary"):
        L.append("")
        L.append(t("render.h_trace"))
        L.append("```")
        L.extend(ev["trace_summary"])
        L.append("```")

    if ev.get("static_flags"):
        L.append("")
        L.append(t("render.h_static"))
        for s in ev["static_flags"]:
            L.append("- " + s["text"])

    L.append("")
    L.append(t("render.h_dedup"))
    if not dup or not dup.get("compared_with"):
        L.append(t("render.no_prior"))
    else:
        L.append(t("render.compared", dup["compared_with"], t("dupstatus." + dup["status"])))
        for c in dup.get("candidates", [])[:3]:
            s = c["scores"]
            line = t("render.candidate", c["id"], s["text"], s["code"], s["fingerprint"], c["level"])
            if c.get("eligible") is False and c.get("level") != "none":
                line += t("render.not_original", c.get("onchain_status") or c.get("verdict_code") or "?")
            L.append(line)
    L.append("")
    L.append("---")
    L.append(t("render.footer", v["pipeline"]["version"], v["pipeline"].get("forge_version")))
    return "\n".join(L) + "\n"
