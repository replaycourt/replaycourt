#!/usr/bin/env python3
"""ReplayCourt engine - automatic triage of smart-contract bug reports by fork replay.

Examples:
  python3 -I replay.py check reports/01_templedao_stax.md
  python3 -I replay.py check report.md --chain ethereum --block 15725066 --json
  python3 -I replay.py check report.md --registry reg.jsonl --report-id sub-12 --dest runs/x/12
  python3 -I replay.py rpc --chain ethereum --block 15725066
  python3 -I replay.py registry list

Exit codes of 'check':
  0 valid · 1 invalid · 2 needs human · 3 duplicate (technical verdict is in the JSON)
  64 usage error · 65 report unreadable · 69 infrastructure missing (RPC/archive, forge, compiler)
  70 internal error
"""

import argparse
import datetime as _dt
import json
import os
import re
import shutil
import sys
import time
import traceback
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # our own code; with -I the script directory is not on the path otherwise

from replaylib import VERSION  # noqa: E402
from replaylib import dedup, forge, rpc  # noqa: E402
from replaylib import report as report_mod  # noqa: E402
from replaylib import render as render_mod  # noqa: E402
from replaylib import verdict as vmod  # noqa: E402
from replaylib.i18n import t  # noqa: E402
from replaylib.trace import NATIVE, ZERO, TraceAnalysis, failure_origin, fork_calls  # noqa: E402


def _default_forge() -> str:
    """forge binary: $REPLAYCOURT_FORGE, forge on PATH, or ~/.foundry/bin/forge (foundryup's default)."""
    if os.environ.get("REPLAYCOURT_FORGE"):
        return os.environ["REPLAYCOURT_FORGE"]
    found = shutil.which("forge")
    if found:
        return found
    cand = os.path.join(os.path.expanduser("~"), ".foundry", "bin", "forge")
    if os.path.isfile(cand):
        return cand
    return "forge"


DEFAULTS = {
    "chains": os.path.join(HERE, "config", "chains.json"),
    "out": os.path.join(HERE, "verdicts"),
    "registry": os.path.join(HERE, "register", "registry.jsonl"),
    "work": os.path.join(HERE, "work"),
    "home": os.path.join(HERE, ".sandbox-home"),
    "forge_std": os.path.join(HERE, "vendor", "forge-std", "src"),
    "support": os.path.join(HERE, "vendor", "DeFiHackLabs", "src", "test"),
}


# (text, replacement) pairs applied to every file written into the evidence directory: the
# evidence is published, so absolute local paths and a secret --rpc URL must not end up in it
# (a PoC can log vm.projectRoot() or vm.rpcUrl(...)). Filled in cmd_check / _check.
_SCRUB = []


def _scrub(text: str) -> str:
    for old, new in _SCRUB:
        if old:
            text = text.replace(old, new)
    return text


def _write_evidence(path: str, text: str):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_scrub(text))


class InfraError(Exception):
    """Missing infrastructure (exit 69)."""


def now_iso() -> str:
    """Current time in UTC, ISO 8601 with "Z" (never local time: evidence is compared across machines)."""
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def redact_url(url):
    """scheme://host/… - hides API keys in a user-supplied RPC URL before it lands in evidence."""
    if not url:
        return url
    try:
        parts = urlsplit(url)
        host = parts.hostname or "?"
        port = ":%d" % parts.port if parts.port else ""
    except ValueError:
        return "<redacted>"
    hidden = parts.path not in ("", "/") or parts.query or parts.fragment or parts.username or parts.password
    return "%s://%s%s%s" % (parts.scheme, host, port, "/…" if hidden else "")


class Progress:
    def __init__(self, quiet: bool):
        self.quiet = quiet

    def __call__(self, msg: str):
        if not self.quiet:
            sys.stderr.write("[engine] %s\n" % msg)
            sys.stderr.flush()


def load_chains(path: str) -> dict:
    with open(path) as fh:
        data = json.load(fh)
    return {k: v for k, v in data.items() if not k.startswith("_")}


def resolve_chain(name, chains):
    if not name:
        return None
    n = name.strip().lower()
    for key, cfg in chains.items():
        if n == key or n in cfg.get("aliases", []):
            return key
    return None


# --------------------------------------------------------------------------- check
def cmd_check(args) -> int:
    t0 = time.time()
    say = Progress(args.quiet or args.json)
    chains = load_chains(args.chains)
    if not os.path.isfile(args.report):
        sys.stderr.write(t("cli.report_not_found", args.report) + "\n")
        return vmod.EXIT_BAD_REPORT
    allowed = [os.path.dirname(os.path.abspath(args.report)), HERE] + (args.allow_path or [])
    try:
        rep = report_mod.load_report(args.report, allowed)
    except (OSError, report_mod.ReportError) as exc:
        sys.stderr.write(t("cli.report_unreadable", exc) + "\n")
        return vmod.EXIT_BAD_REPORT
    if args.report_id is not None:
        rid = report_mod.sanitize_id(args.report_id)
        if not rid:
            sys.stderr.write(t("cli.bad_report_id", args.report_id) + "\n")
            return vmod.EXIT_USAGE
        rep.report_id = rid
    say(t("cli.report_read", rep.report_id, rep.poc_origin or t("render.none")))

    v = {
        "schema": "replaycourt.verdict/v1",
        "report": {"id": rep.report_id, "title": rep.title, "file": os.path.basename(rep.path),
                   "path_rel": os.path.relpath(rep.path, HERE), "sha256": rep.sha256, "author": rep.author,
                   "claimed_severity": rep.claimed_severity, "declared": {
                       "attackers": rep.attackers, "victims": rep.victims, "targets": rep.targets}},
        "outcome": None, "verdict": None, "verdict_label": None, "exit_code": None,
        "severity_hint": None, "reasons": [], "warnings": [],
        "duplicate": None, "fork": {}, "poc": {}, "execution": {}, "evidence": {}, "fingerprint": None,
        "pipeline": {"engine": "replaycourt-engine", "version": VERSION, "started_at": now_iso()},
    }
    out_dir = os.path.abspath(args.dest) if args.dest else os.path.join(args.out, rep.report_id)
    ws = os.path.join(DEFAULTS["work"], "%s-%d" % (rep.report_id, os.getpid()))
    home = os.path.expanduser("~")
    _SCRUB[:] = [(ws, "<workspace>"), (os.path.dirname(HERE), "<repo>")] + (
        [(home, "~")] if home not in ("", "/") else [])
    env = forge.sandbox_env(DEFAULTS["home"])
    v["pipeline"]["forge_version"] = forge.forge_version(args.forge, env)
    try:
        code = _check(args, rep, chains, v, ws, env, say, out_dir)
    except InfraError as exc:
        _set_verdict(v, vmod.HUMAN)
        v["reasons"].append(t("cli.infra_reason", exc))
        v["severity_hint"] = {"level": vmod.UNCLEAR, "provisional": False, "basis": [t("sev.not_checked")]}
        v["status"] = "infrastructure_error"
        code = vmod.EXIT_UNAVAILABLE
    except Exception as exc:  # noqa: BLE001
        _set_verdict(v, vmod.HUMAN)
        v["reasons"].append(t("cli.internal_reason", exc))
        v["status"] = "internal_error"
        v["pipeline"]["traceback"] = traceback.format_exc()[-3000:]
        code = vmod.EXIT_INTERNAL
    finally:
        if not args.keep_workspace and os.path.isdir(ws):
            shutil.rmtree(ws, ignore_errors=True)
    v["exit_code"] = code
    v.setdefault("status", "ok")
    d = v.get("duplicate") or {}
    if code in (vmod.EXIT_VALID, vmod.EXIT_INVALID, vmod.EXIT_HUMAN, vmod.EXIT_DUPLICATE):
        v["outcome"] = "duplicate" if code == vmod.EXIT_DUPLICATE else v["verdict"]
    else:
        v["outcome"] = None  # 69/70: no verdict about the report
    v["pipeline"]["finished_at"] = now_iso()
    v["pipeline"]["duration_s"] = round(time.time() - t0, 1)
    v["pipeline"]["workspace_kept"] = ws if args.keep_workspace else None

    os.makedirs(out_dir, exist_ok=True)
    _write_evidence(os.path.join(out_dir, "verdict.json"), json.dumps(v, ensure_ascii=False, indent=2, sort_keys=False))
    summary = _scrub(render_mod.render(v))
    _write_evidence(os.path.join(out_dir, "summary.md"), summary)
    if code in (vmod.EXIT_VALID, vmod.EXIT_INVALID, vmod.EXIT_HUMAN, vmod.EXIT_DUPLICATE) and not args.no_register:
        dedup.save_entry(args.registry, dedup.make_entry(
            rep, v.get("fingerprint"), v["verdict"], v["pipeline"]["finished_at"],
            d.get("of") if d.get("status") == "duplicate" else None))
    if args.json:
        sys.stdout.write(_scrub(json.dumps(v, ensure_ascii=False, indent=2)) + "\n")
    else:
        sys.stdout.write(summary)
    say(t("cli.verdict_done", v["outcome"] or v["verdict_label"], code, os.path.relpath(out_dir, os.getcwd())))
    return code


def _set_verdict(v, code):
    v["verdict"] = code
    v["verdict_label"] = vmod.label(code)


def _check(args, rep, chains, v, ws, env, say, out_dir) -> int:
    os.makedirs(out_dir, exist_ok=True)

    # ---------------------------------------------------------------- 0. no PoC
    if rep.poc_error:
        _set_verdict(v, vmod.INVALID)
        v["reasons"].append(t("cli.no_poc", rep.poc_error))
        v["severity_hint"] = {"level": "none", "provisional": False, "basis": []}
        v["poc"] = {"origin": rep.poc_origin or None, "error": rep.poc_error}
        v["duplicate"] = dedup.check(rep, None, _registry(args))
        return _final_exit(v)

    _write_evidence(os.path.join(out_dir, "PoC.t.sol"), rep.poc_source)
    v["poc"] = {"origin": rep.poc_origin, "sha256": rep.poc_sha256, "fork_calls": rep.poc_fork_calls,
                "copy": "PoC.t.sol"}

    # ---------------------------------------------------------------- 1. chain and block
    chain_src = "cli" if args.chain else rep.sources.get("chain")
    chain_name = args.chain or rep.chain
    poc_alias = next((fc for fc in rep.poc_fork_calls if not re.match(r"(?i)^(https?|wss?)://", fc["arg"])), None)
    if not chain_name and poc_alias:
        chain_name, chain_src = poc_alias["arg"], "poc"
    if not chain_name and not rep.poc_fork_calls:
        chain_name, chain_src = "local", "default (PoC does not fork)"
    chain_key = resolve_chain(chain_name, chains)
    if not chain_key:
        raise InfraError(t("cli.chain_unknown", chain_name))
    ccfg = chains[chain_key]
    local = bool(ccfg.get("local"))
    rep.chain = chain_key
    block, block_src = None, None
    if args.block is not None:
        block, block_src = args.block, "cli"
    elif rep.fork_block is not None:
        block, block_src = rep.fork_block, rep.sources.get("fork_block")
    elif poc_alias and poc_alias.get("block") is not None:
        block, block_src = poc_alias["block"], "poc"
    rep.fork_block = block
    v["fork"] = {"chain": chain_key, "chain_src": chain_src, "chain_id": ccfg["chain_id"], "local": local,
                 "declared_block": block, "block_source": block_src}
    if not local and block is None:
        v["warnings"].append(t("cli.no_fork_block"))

    # ---------------------------------------------------------------- 2. static check
    flags = report_mod.static_flags(rep)
    v["evidence"]["static_flags"] = flags
    static_block = None
    if any(f["code"] == "external_url" for f in flags) and not args.allow_external_urls:
        static_block = t("cli.static_external_url")
    if static_block:
        dec = vmod.decide({"static_block": static_block})
        _apply(v, dec)
        v["duplicate"] = dedup.check(rep, None, _registry(args))
        return _final_exit(v)

    # ---------------------------------------------------------------- 3. prepare the fork
    rpc_url = None
    shown = (lambda u: redact_url(u)) if args.rpc else (lambda u: u)
    if not local:
        say(t("cli.searching_rpc", chain_key, block))
        rpc_url, attempts = rpc.select_rpc(ccfg, block, args.rpc)
        for a in attempts:
            a["url"] = shown(a.get("url"))
        v["fork"]["rpc_attempts"] = attempts
        v["fork"]["rpc_url"] = shown(rpc_url)
        if args.rpc and rpc_url:
            _SCRUB.append((rpc_url, shown(rpc_url)))
        if not rpc_url:
            raise InfraError(t("cli.no_archive_rpc", chain_key, block,
                               "; ".join("%s: %s" % (a["url"], a.get("reason")) for a in attempts)))
        say(t("cli.fork_via", shown(rpc_url)))
    endpoints = {}
    for key, cfg in chains.items():
        if cfg.get("local") or not cfg.get("rpcs"):
            continue
        url = rpc_url if key == chain_key else cfg["rpcs"][0]
        for alias in cfg.get("aliases", []):
            endpoints.setdefault(alias, url)

    # A PoC may only fork through these: the aliases of the generated foundry.toml or exactly the
    # URLs behind them. Anything else is a fork the engine did not choose (checked in the trace).
    allowed_fork_targets = set(endpoints) | set(endpoints.values()) | ({rpc_url} if rpc_url else set())

    def fork_target_shown(target):
        if target in endpoints:
            return target
        # A foreign target is the submitter's own text (shown as given, shortened); one of ours
        # may carry a key and is redacted like --rpc.
        return shown(target) if target in allowed_fork_targets else target[:120]

    evm_version = rep.evm_version or args.evm_version or ccfg.get("evm_version", "shanghai")
    forge.build_workspace(ws, rep.poc_source, DEFAULTS["forge_std"], DEFAULTS["support"], endpoints, evm_version)
    with open(os.path.join(ws, "foundry.toml"), encoding="utf-8") as fh:
        toml_text = fh.read()
    if args.rpc and rpc_url:
        toml_text = toml_text.replace(rpc_url.replace('"', ""), shown(rpc_url))
    _write_evidence(os.path.join(out_dir, "foundry.toml"), toml_text)

    # ---------------------------------------------------------------- 4. compile
    say(t("cli.compiling"))
    b = forge.forge_build(args.forge, ws, env, timeout=args.build_timeout)
    build = {"ok": b["rc"] == 0 and not b["timed_out"], "duration_s": b["duration_s"],
             "solc": forge.solc_versions(ws), "evm_version": evm_version}
    if not build["ok"]:
        text = b["stderr"] + b["stdout"]
        if b["timed_out"]:
            raise InfraError(t("cli.build_timeout", args.build_timeout))
        if "Compiler run failed" not in text and re.search(r"(?i)(install|download).{0,40}solc|svm|error sending request", text):
            raise InfraError(t("cli.no_solc", text.strip()[:300]))
        build["errors"] = forge.compile_errors(b["stderr"], b["stdout"])
    v["execution"]["build"] = build
    _write_evidence(os.path.join(out_dir, "forge-build.log"), b["stdout"] + "\n--- stderr ---\n" + b["stderr"])
    if not build["ok"]:
        _apply(v, vmod.decide({"build": build}))
        v["duplicate"] = dedup.check(rep, None, _registry(args))
        return _final_exit(v)
    sigmap = forge.load_selectors(ws)

    # ---------------------------------------------------------------- 5. run the PoC
    match_test = args.test or rep.test
    say(t("cli.running_poc", (" --match-test " + match_test) if match_test else ""))
    tres = forge.forge_test(args.forge, ws, env, timeout=args.test_timeout, match_test=match_test,
                            fork_url=rpc_url, fork_block=block)
    _write_evidence(os.path.join(out_dir, "forge-test.json"), tres["stdout"])
    _write_evidence(os.path.join(out_dir, "forge-test.stderr.txt"), tres["stderr"])
    tests = []
    for suite, name, res in forge.extract_tests(tres["json"]):
        tests.append({"suite": suite, "name": name, "status": res.get("status"), "reason": res.get("reason"),
                      "gas": ((res.get("kind") or {}).get("Unit") or {}).get("gas"),
                      "duration": res.get("duration"), "fork_block_number": res.get("fork_block_number"),
                      "_res": res})
    selected = _select_test(tests, match_test)
    if tres["timed_out"]:
        selected = {"name": match_test or "?", "status": "Timeout", "timed_out": True}
    elif not tests and tres["rc"] != 0:
        msg = (tres["stderr"] or tres["stdout"]).strip()
        if re.search(r"(?i)(429|rate.?limit|timed out|connection|error sending request|failed to get)", msg):
            raise InfraError(t("cli.fork_failed", msg[:300]))
        build_fail = {"ok": False, "errors": forge.compile_errors(tres["stderr"], tres["stdout"])}
        v["execution"]["build"].update(build_fail)
        _apply(v, vmod.decide({"build": build_fail}))
        v["duplicate"] = dedup.check(rep, None, _registry(args))
        return _final_exit(v)
    v["execution"]["tests"] = [{k: x for k, x in tt.items() if not k.startswith("_")} for tt in tests]
    # Every fork the PoC opened, with the URL/alias decoded from the raw cheatcode call data.
    forks = fork_calls(selected["_res"], sigmap) if selected and selected.get("_res") else []
    foreign = [f for f in forks if f["target"] is not None and f["target"] not in allowed_fork_targets]
    foreign_shown = sorted({fork_target_shown(f["target"]) for f in foreign})
    if forks:
        v["evidence"]["fork_cheatcodes"] = [
            {"phase": f["phase"], "cheat": f["cheat"], "target": fork_target_shown(f["target"]),
             "allowed": f not in foreign, "success": f["success"]} for f in forks]
    if selected and not selected.get("timed_out"):
        v["execution"]["selected_test"] = selected["name"]
        v["execution"]["poc_logs"] = selected["_res"].get("decoded_logs") or []
        if selected["status"] != "Success" and selected.get("reason") and \
                re.search(r"(?i)(429|rate.?limit|too many requests|error sending request|could not instantiate forked environment)", selected["reason"]):
            # Only an error the infrastructure produced is retried. A PoC can revert with any text
            # ("429 Too Many Requests") or fork from a dead URL of its own; retrying those forever
            # would stall the verifier's queue.
            origin = failure_origin(selected["_res"], selected["reason"])
            if origin == "contract":
                v["warnings"].append(t("cli.infra_text_from_poc"))
            elif not any(not f["success"] for f in foreign):
                raise InfraError(t("cli.rpc_error_in_run", selected["reason"][:300]))
        others = [x["name"] for x in tests if x is not selected and x["status"] != "Success"]
        if others:
            v["warnings"].append(t("cli.other_tests_fail", ", ".join(others)))
    if not selected or selected.get("timed_out") or selected["status"] != "Success":
        dec = vmod.decide({"build": build, "selected": selected})
        _apply(v, dec)
        if foreign:
            v["reasons"].append(t("cli.foreign_fork_failed", ", ".join(foreign_shown)))
        if selected and selected.get("_res"):
            v["fork"]["poc_fork_block"] = selected["_res"].get("fork_block_number")
        v["duplicate"] = dedup.check(rep, None, _registry(args))
        return _final_exit(v)

    # ---------------------------------------------------------------- 6. analyse the trace
    res = selected["_res"]
    poc_block = res.get("fork_block_number")
    v["fork"]["poc_fork_block"] = poc_block
    q_block = poc_block if poc_block is not None else block
    code_cache = {}

    def has_code(addr):
        if local or not rpc_url:
            return None
        if addr not in code_cache:
            try:
                code_cache[addr] = rpc.get_code(rpc_url, addr, q_block) not in ("0x", "0x0", "")
            except rpc.RpcError:
                code_cache[addr] = None
        return code_cache[addr]

    say(t("cli.analysing_trace"))
    an = TraceAnalysis(res, sigmap, rep.attackers, rep.victims, has_code=has_code,
                       native_symbol=ccfg.get("native_symbol", "ETH"), ignore_created_tokens=not local)
    if an.ignored_flows:
        emitters = sorted({f["emitter"] for f in an.ignored_flows})
        v["warnings"].append(t("w.ignored_created_token_flows", len(an.ignored_flows), ", ".join(emitters[:5])))
        v["evidence"]["ignored_flows"] = {"count": len(an.ignored_flows), "emitters": emitters}
    cheat = an.cheat_summary()
    if cheat["host"]:
        v["warnings"].append(t("w.host_cheats", ", ".join(sorted({c["cheat"].split("(")[0] for c in cheat["host"]}))))
    if foreign_shown:
        v["warnings"].append(t("w.foreign_fork", ", ".join(foreign_shown)))
    meta = _asset_meta(an, ccfg, rpc_url, q_block, local)
    labels = _labels(an, rep, meta)
    rows, valuation = _balance_rows(an, rep, ccfg, meta, labels, rpc_url, q_block, local)
    code_checks = []
    for role, addrs in (("target", rep.targets), ("victim", rep.victims)):
        for a in addrs:
            code_checks.append({"role": role, "address": a, "has_code": has_code(a)})
    fp = an.fingerprint(chain_key)
    v["fingerprint"] = fp
    v["evidence"].update({
        "attacker_addresses": sorted(an.attackers),
        "balance_changes": rows,
        "valuation": valuation,
        "cheatcodes": cheat,
        "pranked": an.pranked_summary(),
        "code_checks": code_checks,
        "nft_transfers": an.nft_transfers,
        "trace_summary": an.call_summary(lambda a: labels.get(a, a[:6] + "…" + a[-4:])),
        "gas": {"test_gas": selected.get("gas"),
                "execution_gas_used": (an.arenas.get("Execution") or [{}])[0].get("trace", {}).get("gas_used")},
    })
    dec = vmod.decide({
        "build": build, "selected": selected, "analysis": an, "cheat": cheat, "local": local,
        "fork": v["fork"], "code_checks": code_checks, "declared_victims": rep.victims, "valuation": valuation,
        "foreign_forks": foreign_shown,
    })
    _apply(v, dec)

    # ---------------------------------------------------------------- 7. duplicates
    say(t("cli.checking_dups"))
    d = dedup.check(rep, fp, _registry(args))
    v["duplicate"] = d
    if d["status"] == "possible" and v["verdict"] == vmod.VALID:
        _set_verdict(v, vmod.HUMAN)
        v["reasons"].append(t("cli.possible_dup", d["of"]))
    return _final_exit(v)


def _registry(args):
    """Registry entries for the duplicate check, with the worker's on-chain statuses overlaid."""
    return dedup.apply_onchain_status(dedup.load_registry(args.registry),
                                      dedup.load_onchain_status(getattr(args, "onchain_status", None)))


def _final_exit(v) -> int:
    d = v.get("duplicate") or {}
    if d.get("status") == "duplicate":
        v["reasons"].append(t("cli.dup_of", d["of"]))
        return vmod.EXIT_DUPLICATE
    return vmod.EXIT_FOR[v["verdict"]]


def _apply(v, dec):
    _set_verdict(v, dec["verdict_code"])
    v["reasons"].extend(dec["reasons"])
    v["warnings"].extend(dec["warnings"])
    v["severity_hint"] = dec["severity_hint"]


def _select_test(tests, match_test):
    if not tests:
        return None
    if match_test:
        for tt in tests:
            if tt["name"].split("(")[0] == match_test:
                return tt
    passing = [tt for tt in tests if tt["status"] == "Success"]
    pool = passing or tests
    for tt in pool:
        if re.search(r"(?i)exploit|attack|poc|hack|drain", tt["name"]):
            return tt
    return pool[0]


def _asset_meta(an, ccfg, rpc_url, block, local):
    meta = {NATIVE: {"symbol": ccfg.get("native_symbol", "ETH"), "decimals": 18}}
    for asset in an.assets():
        if asset == NATIVE:
            continue
        sym, dec = (None, None)
        if not local and rpc_url:
            sym, dec = rpc.token_meta(rpc_url, asset, block)
        if not sym:
            sym = an.labels.get(asset)
        meta[asset] = {"symbol": sym, "decimals": dec}
    return meta


def _labels(an, rep, meta):
    lab = {}
    for a in an.attackers:
        lab[a] = t("label.attack_contract")
    if an.test_contract:
        lab[an.test_contract] = t("label.test_contract")
    for a in rep.attackers:
        lab[a] = t("label.attacker")
    for a in rep.targets:
        lab[a] = t("label.target")
    for a in rep.victims:
        lab[a] = t("label.victim")
    for asset, m in meta.items():
        if asset != NATIVE and m.get("symbol"):
            lab[asset] = m["symbol"]
    lab.update({k: v for k, v in an.labels.items()})
    return lab


def _price(asset, ccfg, native_usd):
    stables = {k.lower(): s for k, s in (ccfg.get("stablecoins") or {}).items()}
    if asset == NATIVE or asset == (ccfg.get("wrapped_native") or "").lower():
        return native_usd
    if asset in stables:
        return 1.0
    return None


def _balance_rows(an, rep, ccfg, meta, labels, rpc_url, block, local):
    native_usd = None
    if not local and rpc_url and ccfg.get("native_usd_feed"):
        native_usd = rpc.chainlink_price(rpc_url, ccfg["native_usd_feed"], block)

    def usd(asset, raw):
        p = _price(asset, ccfg, native_usd)
        dec = meta.get(asset, {}).get("decimals")
        if p is None or dec is None:
            return None
        return raw / (10 ** dec) * p

    def prebalance(asset, addr):
        if local or not rpc_url:
            return None
        try:
            if asset == NATIVE:
                return rpc.get_balance(rpc_url, addr, block)
            return rpc.erc20_balance(rpc_url, asset, addr, block)
        except rpc.RpcError:
            return None

    rows = []
    for asset, d in sorted(an.attacker_net.items(), key=lambda x: -abs(x[1])):
        rows.append({"role": "attacker", "address": an.test_contract,
                     "label": t("label.attacker_total", len(an.attackers)),
                     "asset": asset, "symbol": meta.get(asset, {}).get("symbol"),
                     "decimals": meta.get(asset, {}).get("decimals"), "delta_raw": str(d), "usd": usd(asset, d),
                     "sources": [{"from": s, "amount": str(a)} for s, a in
                                 sorted(an.inflow.get(asset, {}).items(), key=lambda x: -x[1])[:5]] if d > 0 else []})
    declared = set(rep.victims)
    loser_rows = []
    for vaddr in rep.victims:
        for asset, d in an.net.get(vaddr, {}).items():
            if d:
                loser_rows.append(("victim", vaddr, asset, d))
    for x in an.losers:
        if x["address"] not in declared:
            loser_rows.append(("loser", x["address"], x["asset"], x["delta"]))
    max_fraction = None
    damage_victims = 0.0
    damage_priced = False
    for role, addr, asset, d in loser_rows[:10]:
        pre = prebalance(asset, addr) if d < 0 else None
        frac = min(1.0, -d / pre) if (pre and d < 0) else None
        u = usd(asset, d)
        rows.append({"role": role, "address": addr, "label": labels.get(addr, ""), "asset": asset,
                     "symbol": meta.get(asset, {}).get("symbol"), "decimals": meta.get(asset, {}).get("decimals"),
                     "delta_raw": str(d), "prebalance_raw": str(pre) if pre is not None else None,
                     "fraction_of_prebalance": round(frac, 4) if frac is not None else None, "usd": u})
        counts = (role == "victim") or not declared
        if counts and d < 0:
            if frac is not None:
                max_fraction = max(max_fraction or 0.0, frac)
            if u is not None:
                damage_victims += -u
                damage_priced = True
    gain_usd, spent_usd, fully = 0.0, 0.0, True
    any_gain_priced = False
    for asset, d in an.attacker_net.items():
        u = usd(asset, abs(d))
        if u is None:
            fully = False
            continue
        if d > 0:
            gain_usd += u
            any_gain_priced = True
        else:
            spent_usd += u
    damage = None
    if any_gain_priced or damage_priced:
        damage = max(gain_usd if any_gain_priced else 0.0, damage_victims if damage_priced else 0.0)
    unpriced = sorted({(meta.get(a, {}).get("symbol") or a) for a in an.assets()
                       if _price(a, ccfg, native_usd) is None})
    valuation = {"native_usd": native_usd, "damage_usd": damage, "max_fraction": max_fraction,
                 "attacker_gain_usd": gain_usd if any_gain_priced else None,
                 "attacker_spent_usd": spent_usd, "attacker_fully_priced": fully,
                 "unpriced_assets": unpriced, "price_block": block}
    return rows, valuation


# --------------------------------------------------------------------------- rpc / registry
def cmd_rpc(args) -> int:
    chains = load_chains(args.chains)
    key = resolve_chain(args.chain, chains)
    if not key:
        sys.stderr.write(t("cli.unknown_chain", args.chain) + "\n")
        return vmod.EXIT_USAGE
    url, attempts = rpc.select_rpc(chains[key], args.block, args.rpc)
    out = {"chain": key, "block": args.block, "selected": url, "attempts": attempts}
    sys.stdout.write(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    return 0 if url else vmod.EXIT_UNAVAILABLE


def cmd_registry(args) -> int:
    entries = dedup.load_registry(args.registry)
    if args.action == "list":
        rows = [{"id": e["id"], "title": e.get("title"), "verdict_code": e.get("verdict_code"),
                 "duplicate_of": e.get("duplicate_of"), "chain": e.get("chain"), "fork_block": e.get("fork_block"),
                 "triaged_at": e.get("triaged_at"), "original": dedup.is_original(e)} for e in entries]
        sys.stdout.write(json.dumps(rows, indent=2, ensure_ascii=False) + "\n")
    elif args.action == "remove":
        if not args.id:
            sys.stderr.write(t("cli.remove_needs_id") + "\n")
            return vmod.EXIT_USAGE
        keep = [e for e in entries if e.get("id") != args.id]
        if os.path.exists(args.registry):
            os.remove(args.registry)
        for e in keep:
            dedup.save_entry(args.registry, e)
        sys.stdout.write(t("cli.removed", len(entries) - len(keep)) + "\n")
    elif args.action == "clear":
        if os.path.exists(args.registry):
            os.remove(args.registry)
        sys.stdout.write(t("cli.cleared") + "\n")
    return 0


def _common_options(parser, suppress: bool):
    """Options accepted before and after the sub-command (SPEC: 'check <report> --registry <file>')."""
    d = (lambda value: argparse.SUPPRESS) if suppress else (lambda value: value)
    parser.add_argument("--chains", default=d(DEFAULTS["chains"]), help="chain configuration (JSON)")
    parser.add_argument("--registry", default=d(DEFAULTS["registry"]),
                        help="duplicate registry (JSON Lines); the worker uses one file per program")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="replay.py",
                                description="ReplayCourt engine: replay-verify a smart-contract bug report on a fork.")
    _common_options(p, suppress=False)
    common = argparse.ArgumentParser(add_help=False)
    _common_options(common, suppress=True)
    sub = p.add_subparsers(dest="cmd")

    c = sub.add_parser("check", parents=[common], help="check a report and write the verdict")
    c.add_argument("report", help="report file (Markdown with a Foundry PoC)")
    c.add_argument("--chain", help="override the chain (name or alias from chains.json)")
    c.add_argument("--block", type=int, help="override the fork block")
    c.add_argument("--rpc", help="own archive RPC (skips the list in chains.json; redacted in the evidence)")
    c.add_argument("--test", help="run only this test function")
    c.add_argument("--evm-version")
    c.add_argument("--report-id", help="register and file the report under this id (the worker passes sub-<id>)")
    c.add_argument("--out", default=DEFAULTS["out"], help="parent directory; outputs go to OUT/<report-id>/")
    c.add_argument("--dest", help="write the outputs directly into this directory (instead of OUT/<report-id>/)")
    c.add_argument("--forge", default=_default_forge(), help="path of the forge binary")
    c.add_argument("--json", action="store_true", help="print the verdict JSON on stdout")
    c.add_argument("--quiet", action="store_true")
    c.add_argument("--no-register", action="store_true", help="do not add the result to the duplicate registry")
    c.add_argument("--onchain-status", metavar="FILE",
                   help="JSON {report-id: on-chain status} from the worker; an original must be valid, paid or "
                        "disputed on-chain (otherwise: the engine's own verdict must be valid)")
    c.add_argument("--keep-workspace", action="store_true")
    c.add_argument("--allow-external-urls", action="store_true")
    c.add_argument("--allow-path", action="append", help="additional allowed directory for poc: references")
    c.add_argument("--build-timeout", type=int, default=900, help="seconds")
    c.add_argument("--test-timeout", type=int, default=900, help="seconds")

    r = sub.add_parser("rpc", parents=[common], help="probe archive access for chain/block")
    r.add_argument("--chain", required=True)
    r.add_argument("--block", type=int)
    r.add_argument("--rpc")

    g = sub.add_parser("registry", parents=[common], help="show or edit the duplicate registry")
    g.add_argument("action", choices=["list", "remove", "clear"])
    g.add_argument("--id")

    try:
        args = p.parse_args(argv)
    except SystemExit as exc:
        return vmod.EXIT_USAGE if exc.code else 0
    if args.cmd == "check":
        forge_bin = args.forge if os.path.isfile(args.forge) else shutil.which(args.forge)
        if not forge_bin:
            sys.stderr.write(t("cli.forge_missing", args.forge) + "\n")
            return vmod.EXIT_UNAVAILABLE
        args.forge = forge_bin
        return cmd_check(args)
    if args.cmd == "rpc":
        return cmd_rpc(args)
    if args.cmd == "registry":
        return cmd_registry(args)
    p.print_help(sys.stderr)
    return vmod.EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
