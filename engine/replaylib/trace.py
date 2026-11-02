"""Analysis of the Forge execution trace (forge test --json -vvvv).

Everything here is computed independently of what the PoC prints: balance changes come
from the raw Transfer/Deposit/Withdrawal events and the ETH values of the calls, cheatcodes
from the calls to the HEVM address. What a PoC says about itself (console.log,
log_named_*) is never taken as evidence.
"""

from collections import defaultdict
from typing import Callable, Dict, List, Optional, Set

from . import i18n

# Roles of addresses the PoC impersonated with vm.prank (codes; render.py translates them).
ROLE_ATTACKER = "attacker"
ROLE_ATTACKER_DECLARED = "attacker_declared"
ROLE_ATTACKER_CREATES = "attacker_creates_contracts"
ROLE_ATTACKER_EOA_GAIN = "attacker_eoa_with_gain"
ROLE_VICTIM_IMPERSONATED = "victim_impersonated"
ROLE_FOREIGN_IDENTITY = "foreign_identity"

CHEAT = "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d"
CONSOLE = "0x000000000000000000636f6e736f6c652e6c6f67"
DEFAULT_SENDER = "0x1804c8ab1f12e6bbf3894d4083f33e07309d1f38"
CREATE2_DEPLOYER = "0x4e59b44847b379578588920ca78fbf26c0b4956c"
ZERO = "0x0000000000000000000000000000000000000000"
NATIVE = "native"

TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
TOPIC_DEPOSIT = "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c"
TOPIC_WITHDRAWAL = "0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65"

# Cheatcodes the engine must recognize even when the PoC does not compile forge-std's Vm
# interface (the selector map is built from the compiled artifacts).
KNOWN_CHEATS = {
    "0x31ba3498": "createFork(string)",
    "0x6ba3ba2b": "createFork(string,uint256)",
    "0x7ca29682": "createFork(string,bytes32)",
    "0x98680034": "createSelectFork(string)",
    "0x71ee464d": "createSelectFork(string,uint256)",
    "0x84d52b7a": "createSelectFork(string,bytes32)",
    "0x0199a220": "rpc(string,string,string)",
    "0x1206c8a8": "rpc(string,string)",
    "0x975a6ce9": "rpcUrl(string)",
    "0xa85a8418": "rpcUrls()",
    "0x9d2ad72a": "rpcUrlStructs()",
    "0x89160467": "ffi(string[])",
    "0xf45c1ce7": "tryFfi(string[])",
    "0x60f9bb11": "readFile(string)",
    "0xf877cb19": "envString(string)",
}
# Cheatcodes whose first argument is a fork URL or an rpc_endpoints alias.
FORK_URL_CHEATS = {"createFork", "createSelectFork"}
# Revert payloads that carry a string: Error(string) and Foundry's CheatcodeError(string).
STRING_ERRORS = {"0x08c379a0", "0xeeaa9e6f"}

# Selectors that say nothing about the kind of attack in the fingerprint.
GENERIC_SELECTORS = {"0xa9059cbb", "0x095ea7b3", "0x23b872dd", "0xd0e30db0", "0x2e1a7d4d", "0x"}

CHEAT_CATEGORIES = {
    "impersonation": {"prank", "startPrank", "broadcast", "startBroadcast"},
    "funding": {"deal"},
    "state": {"store", "etch", "mockCall", "mockCalls", "mockCallRevert", "mockFunction", "setNonce",
              "setNonceUnsafe", "resetNonce", "copyStorage", "setArbitraryStorage", "cloneAccount",
              "loadAllocs", "signDelegation", "attachDelegation", "signAndAttachDelegation",
              "allowCheatcodes", "setBlockhash", "interceptInitcode", "broadcastRawTransaction",
              "pauseTracing", "resumeTracing", "revertTo", "revertToAndDelete", "revertToState",
              "revertToStateAndDelete"},
    "time": {"warp", "roll", "fee", "difficulty", "prevrandao", "coinbase", "txGasPrice", "blobBaseFee",
             "blobhashes", "chainId", "setBlockGasLimit"},
    "fork": {"createSelectFork", "createFork", "selectFork", "rollFork", "makePersistent",
             "revokePersistent", "transact", "activeFork"},
    "host": {"ffi", "tryFfi", "readFile", "readFileBinary", "writeFile", "writeFileBinary", "writeLine",
             "readLine", "removeFile", "createDir", "removeDir", "readDir", "copyFile", "writeJson",
             "writeToml", "setEnv", "rpc", "eth_getLogs", "httpGet", "httpPost", "prompt", "promptSecret",
             "promptSecretUint", "promptAddress", "promptUint", "fsMetadata", "exists", "isDir", "isFile",
             "readLink", "closeFile", "projectRoot"},
    "expect": {"expectRevert", "expectPartialRevert", "expectEmit", "expectCall", "expectCallMinGas",
               "expectSafeMemory", "expectEmitAnonymous", "expectCreate", "expectCreate2"},
}
# Cheatcodes known to change neither identities nor chain state. Everything that is in no list above
# and not here, including selectors the engine cannot name, counts as state manipulation: the check
# fails closed, so a cheatcode nobody thought of leads to a human, not to a valid verdict.
NEUTRAL_CHEATS = {
    "stopPrank", "stopBroadcast", "readCallers", "label", "getLabel", "addr", "sign", "signCompact", "signP256",
    "publicKeyP256", "deriveKey", "rememberKey", "rememberKeys", "createWallet", "getWallets", "randomAddress",
    "randomBool", "randomBytes", "randomBytes4", "randomBytes8", "randomInt", "randomUint", "getNonce",
    "getBlockNumber", "getBlockTimestamp", "getBlobBaseFee", "getBlobhashes", "load", "getCode", "getDeployedCode",
    "deployCode", "computeCreateAddress", "computeCreate2Address", "ensNamehash", "record", "accesses", "recordLogs",
    "getRecordedLogs", "lastCallGas", "pauseGasMetering", "resumeGasMetering", "resetGasMetering",
    "snapshotGasLastCall", "snapshotValue", "startSnapshotGas", "stopSnapshotGas", "snapshot", "snapshotState",
    "deleteSnapshot", "deleteSnapshots", "deleteStateSnapshot", "deleteStateSnapshots", "isPersistent", "isContext",
    "assume", "assumeNoRevert", "breakpoint", "getMappingKeyAndParentOf", "getMappingLength", "getMappingSlotAt",
    "startMappingRecording", "stopMappingRecording", "startStateDiffRecording", "stopAndReturnStateDiff",
    "getStateDiff", "getStateDiffJson", "startDebugTraceRecording", "stopAndReturnDebugTraceRecording",
    "foundryVersionAtLeast", "foundryVersionCmp", "getFoundryVersion", "contains", "indexOf", "replace", "shuffle",
    "sort", "split", "toLowercase", "toUppercase", "toString", "trim", "unixTime", "sleep", "rpcUrl", "rpcUrls",
    "rpcUrlStructs",
}
NEUTRAL_PREFIXES = ("assert", "parse", "serialize", "keyExists", "toBase64")


def cheat_category(name: str) -> str:
    for cat, names in CHEAT_CATEGORIES.items():
        if name in names:
            return cat
    if name.startswith("env"):
        return "host"
    if name in NEUTRAL_CHEATS or name.startswith(NEUTRAL_PREFIXES):
        return "neutral"
    return "state"


def spoofed_callers(nodes: List[Dict]) -> List[str]:
    """Addresses that appear as msg.sender of a call their parent frame did not make.

    In the EVM the caller of a call is the identity of the frame that makes it, so any mismatch means
    a cheatcode set msg.sender, whichever cheatcode it was. This does not depend on recognising it.
    """
    identity = {}  # type: Dict[int, Optional[str]]
    out = []
    for n in nodes:
        t = n["trace"]
        addr = (t.get("address") or "").lower()
        par = n.get("parent")
        if par is None:
            identity[n["idx"]] = addr
            continue
        parent_identity = identity.get(par)
        # DELEGATECALL and CALLCODE run the target's code under the parent's identity.
        if t.get("kind") in ("DELEGATECALL", "CALLCODE"):
            identity[n["idx"]] = parent_identity
            continue
        identity[n["idx"]] = addr
        if addr in (CHEAT, CONSOLE):
            continue
        caller = (t.get("caller") or "").lower()
        if parent_identity and caller and caller != parent_identity \
                and caller not in (DEFAULT_SENDER, CREATE2_DEPLOYER) and caller not in out:
            out.append(caller)
    return out


def _words(data: str) -> List[str]:
    body = data[10:] if data.startswith("0x") else data[8:]
    return [body[i:i + 64] for i in range(0, len(body), 64)]


def _addr_from_word(w: str) -> str:
    return "0x" + w[-40:].lower()


def decode_static_args(sig: str, data: str) -> List:
    if "(" not in sig:
        return []
    types = sig[sig.index("(") + 1:sig.rindex(")")]
    types = [t for t in types.split(",") if t] if types else []
    words = _words(data)
    out = []
    for i, t in enumerate(types):
        if i >= len(words):
            break
        w = words[i]
        if t == "address":
            out.append(_addr_from_word(w))
        elif t.startswith("uint"):
            out.append(int(w, 16))
        elif t.startswith("int"):
            v = int(w, 16)
            out.append(v - 2 ** 256 if v >= 2 ** 255 else v)
        elif t == "bool":
            out.append(int(w, 16) != 0)
        elif t.startswith("bytes") and t != "bytes":
            out.append("0x" + w)
        else:
            out.append("<dyn>")
    return out


def decode_string_arg(data: str, index: int) -> Optional[str]:
    """The dynamic `string` argument number `index` of ABI-encoded call data (selector included)."""
    try:
        body = bytes.fromhex(data[10:] if data.startswith("0x") else data[8:])
        off = int.from_bytes(body[32 * index:32 * index + 32], "big")
        length = int.from_bytes(body[off:off + 32], "big")
        if len(body) < 32 * (index + 1) or off + 32 + length > len(body) or length > 65536:
            return None
        return body[off + 32:off + 32 + length].decode("utf-8", "replace")
    except (ValueError, TypeError, OverflowError):
        return None


def revert_text(output) -> Optional[str]:
    """Text of an Error(string) or CheatcodeError(string) revert payload, else None."""
    if not isinstance(output, str) or len(output) < 10 or output[:10].lower() not in STRING_ERRORS:
        return None
    return decode_string_arg(output, 0)


def _frames(test_result: Dict):
    for kind, arena in test_result.get("traces") or []:
        for n in (arena.get("arena", []) if isinstance(arena, dict) else []):
            yield kind, n


def cheat_signature(sel: str, sigmap: Dict[str, str]) -> str:
    return sigmap.get(sel) or KNOWN_CHEATS.get(sel, sel)


def fork_calls(test_result: Dict, sigmap: Dict[str, str]) -> List[Dict]:
    """Every createFork/createSelectFork call of a test run (all phases, also failed ones) with the
    URL or alias it was given, decoded from the raw call data - so it cannot be hidden by building
    the URL at run time."""
    out = []
    for kind, n in _frames(test_result):
        t = n["trace"]
        if (t.get("address") or "").lower() != CHEAT:
            continue
        data = t.get("data") or "0x"
        sig = cheat_signature(data[:10].lower(), sigmap)
        if sig.split("(")[0] not in FORK_URL_CHEATS:
            continue
        out.append({"phase": kind, "cheat": sig, "target": decode_string_arg(data, 0),
                    "success": bool(t.get("success")),
                    "error": None if t.get("success") else revert_text(t.get("output"))})
    return out


def failure_origin(test_result: Dict, reason: Optional[str]) -> str:
    """Where the reason text of a failing test comes from: "cheatcode" (a failed cheatcode call
    produced it, e.g. a fork that could not be created), "contract" (only contract frames - the PoC
    or a contract it called - reverted with it) or "unknown" (no frame carries it: a forge error)."""
    r = (reason or "").strip()
    if not r:
        return "unknown"
    cheat_hit = contract_hit = False
    for _kind, n in _frames(test_result):
        t = n["trace"]
        if t.get("success"):
            continue
        txt = (revert_text(t.get("output")) or "").strip()
        if not txt or not (txt in r or r in txt):
            continue
        if (t.get("address") or "").lower() == CHEAT:
            cheat_hit = True
        else:
            contract_hit = True
    if cheat_hit:
        return "cheatcode"
    return "contract" if contract_hit else "unknown"


def _effective(nodes: List[Dict]) -> Dict[int, bool]:
    eff = {}
    for n in nodes:
        t = n["trace"]
        par = n.get("parent")
        eff[n["idx"]] = bool(t.get("success")) and (par is None or eff.get(par, False))
    return eff


def _int(v) -> int:
    if v is None:
        return 0
    if isinstance(v, int):
        return v
    s = str(v)
    return int(s, 16) if s.startswith("0x") else int(s)


class TraceAnalysis:
    def __init__(self, test_result: Dict, sigmap: Dict[str, str], declared_attackers: List[str],
                 declared_victims: List[str], has_code: Optional[Callable[[str], Optional[bool]]] = None,
                 native_symbol: str = "ETH", ignore_created_tokens: bool = False):
        self.res = test_result
        # Fork mode: token events emitted by contracts the PoC deployed itself are not value
        # (anyone can emit a Transfer event). Local mode keeps them: there everything is deployed.
        self.ignore_created_tokens = ignore_created_tokens
        self.ignored_flows = []  # type: List[Dict]
        self.native_symbol = native_symbol
        self.sigmap = sigmap
        self.labels = {k.lower(): v for k, v in (test_result.get("labeled_addresses") or {}).items()}
        self.arenas = {}
        for kind, arena in test_result.get("traces") or []:
            self.arenas.setdefault(kind, []).extend(arena.get("arena", []) if isinstance(arena, dict) else [])
        self.declared_attackers = [a.lower() for a in declared_attackers]
        self.declared_victims = [a.lower() for a in declared_victims]
        self.has_code = has_code or (lambda _a: None)
        self.notes = []  # type: List[str]
        self._run()

    # ------------------------------------------------------------------ collect
    def _run(self):
        exe = self.arenas.get("Execution", [])
        self.test_contract = exe[0]["trace"]["address"].lower() if exe else None
        self.cheats = []
        self.creations = []
        for kind, nodes in self.arenas.items():
            eff = _effective(nodes)
            for n in nodes:
                t = n["trace"]
                addr = (t.get("address") or "").lower()
                if addr == CHEAT:
                    sel = (t.get("data") or "0x")[:10].lower()
                    sig = cheat_signature(sel, self.sigmap)
                    name = sig.split("(")[0]
                    self.cheats.append({
                        "phase": kind, "name": name, "signature": sig,
                        "category": cheat_category(name),
                        "args": decode_static_args(sig, t.get("data") or "0x") if "(" in sig else [],
                        "effective": eff[n["idx"]],
                        "caller": (t.get("caller") or "").lower(),
                    })
                if t.get("kind") in ("CREATE", "CREATE2") and eff[n["idx"]]:
                    self.creations.append({"phase": kind, "creator": (t.get("caller") or "").lower(),
                                           "created": addr})

        # Attacker set: test contract + declared attackers + everything they create.
        A = set(self.declared_attackers)
        if self.test_contract:
            A.add(self.test_contract)
        self.pranked = {}  # type: Dict[str, Dict]
        for c in self.cheats:
            if c["category"] == "impersonation" and c["args"] and isinstance(c["args"][0], str):
                p = c["args"][0]
                info = self.pranked.setdefault(p, {"address": p, "phases": set(), "count": 0})
                info["phases"].add(c["phase"])
                info["count"] += 1
        # Identities taken over without a recognised cheatcode: same treatment as a prank.
        for kind, nodes in self.arenas.items():
            for p in spoofed_callers(nodes):
                info = self.pranked.setdefault(p, {"address": p, "phases": set(), "count": 0})
                info["phases"].add(kind)
                info["count"] = info["count"] or 1
        # Whoever creates contracts under a prank acts like an attacker (own attack EOA).
        for p in list(self.pranked):
            if any(cr["creator"] == p for cr in self.creations):
                A.add(p)
                self.pranked[p]["role"] = ROLE_ATTACKER_CREATES
        self._close_over_creations(A)

        self._collect_flows()
        # Classify pranked addresses that have no role yet.
        for p, info in self.pranked.items():
            if p in A:
                info.setdefault("role", ROLE_ATTACKER_DECLARED if p in self.declared_attackers else info.get("role", ROLE_ATTACKER))
                continue
            net = self._net_of(p, A)
            losses = {a: v for a, v in net.items() if v < 0}
            gains = {a: v for a, v in net.items() if v > 0}
            code = self.has_code(p)
            info["has_code_at_fork"] = code
            if losses:
                info["role"] = ROLE_VICTIM_IMPERSONATED
            elif gains and code is False:
                info["role"] = ROLE_ATTACKER_EOA_GAIN
                A.add(p)
            else:
                info["role"] = ROLE_FOREIGN_IDENTITY
        self._close_over_creations(A)
        self.attackers = A
        self._compute_deltas()

    def _close_over_creations(self, A: Set[str]):
        # Only contracts that an attacker creates DURING the attack (Execution) belong to the
        # attacker. Contracts created in setUp are environment/victim - otherwise, in local
        # mode, the bundled victim contract would count as the attacker.
        changed = True
        while changed:
            changed = False
            for cr in self.creations:
                if cr["phase"] != "Execution":
                    continue
                if cr["creator"] in A and cr["created"] not in A:
                    A.add(cr["created"])
                    changed = True

    def _collect_flows(self):
        """All effective value movements of the execution phase: (asset, from, to, amount)."""
        self.flows = []
        self.nft_transfers = 0
        nodes = self.arenas.get("Execution", [])
        eff = _effective(nodes)
        # Contracts deployed during this run (any phase) and the test contract itself.
        made_here = {cr["created"] for cr in self.creations}
        if self.test_contract:
            made_here.add(self.test_contract)
        for n in nodes:
            if not eff[n["idx"]]:
                continue
            t = n["trace"]
            kind = t.get("kind")
            caller = (t.get("caller") or "").lower()
            addr = (t.get("address") or "").lower()
            val = _int(t.get("value"))
            if val and kind in ("CALL", "CREATE", "CREATE2") and addr != CHEAT:
                self.flows.append((NATIVE, caller, addr, val))
            sd_val = _int(t.get("selfdestruct_transferred_value"))
            if sd_val:
                src = (t.get("selfdestruct_address") or addr).lower()
                dst = (t.get("selfdestruct_refund_target") or "").lower()
                if dst:
                    self.flows.append((NATIVE, src, dst, sd_val))
            for lg in n.get("logs") or []:
                raw = lg.get("raw_log") or {}
                topics = [x.lower() for x in raw.get("topics") or []]
                data = raw.get("data") or "0x"
                token = (lg.get("address") or addr).lower()
                if not topics:
                    continue
                if self.ignore_created_tokens and token in made_here and topics[0] in (
                        TOPIC_TRANSFER, TOPIC_DEPOSIT, TOPIC_WITHDRAWAL):
                    self.ignored_flows.append({"emitter": token, "topic": topics[0][:10]})
                    continue
                amount = int(data[2:66], 16) if len(data) >= 66 else 0
                if topics[0] == TOPIC_TRANSFER:
                    if len(topics) == 3:
                        self.flows.append((token, _addr_from_word(topics[1]), _addr_from_word(topics[2]), amount))
                    elif len(topics) == 4:
                        self.nft_transfers += 1
                elif topics[0] == TOPIC_DEPOSIT and len(topics) == 2:
                    self.flows.append((token, ZERO, _addr_from_word(topics[1]), amount))
                elif topics[0] == TOPIC_WITHDRAWAL and len(topics) == 2:
                    self.flows.append((token, _addr_from_word(topics[1]), ZERO, amount))

    def _net_of(self, who: str, A: Set[str]) -> Dict[str, int]:
        net = defaultdict(int)
        for asset, src, dst, amt in self.flows:
            if src == who:
                net[asset] -= amt
            if dst == who:
                net[asset] += amt
        return {k: v for k, v in net.items() if v}

    def _compute_deltas(self):
        A = self.attackers
        net = defaultdict(lambda: defaultdict(int))
        inflow = defaultdict(lambda: defaultdict(int))   # asset -> source -> amount (into A)
        outflow = defaultdict(lambda: defaultdict(int))  # asset -> dest -> amount (out of A)
        for asset, src, dst, amt in self.flows:
            if src == dst:
                continue
            net[src][asset] -= amt
            net[dst][asset] += amt
            if dst in A and src not in A:
                inflow[asset][src] += amt
            if src in A and dst not in A:
                outflow[asset][dst] += amt
        self.net = net
        self.attacker_net = defaultdict(int)
        for a in A:
            for asset, v in net.get(a, {}).items():
                self.attacker_net[asset] += v
        self.attacker_net = {k: v for k, v in self.attacker_net.items() if v}
        self.inflow = inflow
        self.outflow = outflow
        losers = []
        for addr, assets in net.items():
            if addr in A or addr in (ZERO, CHEAT, CONSOLE):
                continue
            for asset, v in assets.items():
                if v < 0:
                    losers.append({"address": addr, "asset": asset, "delta": v})
        losers.sort(key=lambda x: x["delta"])
        self.losers = losers
        self.mints_to_attacker = {asset: srcs[ZERO] for asset, srcs in inflow.items() if srcs.get(ZERO)}

    # ------------------------------------------------------------------ results
    def assets(self) -> Set[str]:
        s = set(self.attacker_net)
        s.update(x["asset"] for x in self.losers)
        return s

    def victim_deltas(self, victims: List[str]) -> Dict[str, Dict[str, int]]:
        out = {}
        for v in victims:
            d = {a: x for a, x in self.net.get(v.lower(), {}).items() if x}
            out[v.lower()] = d
        return out

    def cheat_summary(self) -> Dict:
        by_cat = defaultdict(list)
        for c in self.cheats:
            if c["category"] == "neutral":
                continue
            by_cat[c["category"]].append(c)
        funding = []
        state = []
        for c in by_cat.get("funding", []):
            who = c["args"][0] if c["args"] else None
            amt = c["args"][1] if len(c["args"]) > 1 and isinstance(c["args"][1], int) else None
            if amt == 0:
                continue  # deal(x, 0) only resets (e.g. balanceLog in DeFiHackLabs)
            target = "attacker" if who in self.attackers else "foreign"
            (funding if target == "attacker" else state).append({
                "phase": c["phase"], "cheat": c["signature"], "address": who, "amount": amt, "target": target})
        for c in by_cat.get("state", []):
            who = c["args"][0] if c["args"] and isinstance(c["args"][0], str) else None
            if c["name"] == "store" and who in self.attackers:
                continue  # the attacker's own storage
            state.append({"phase": c["phase"], "cheat": c["signature"], "address": who})
        counts = defaultdict(int)
        for c in self.cheats:
            counts[c["name"]] += 1
        return {
            "counts": dict(sorted(counts.items())),
            "funding_to_attacker": funding,
            "state_manipulation": state,
            "time": [{"phase": c["phase"], "cheat": c["signature"], "args": c["args"]} for c in by_cat.get("time", [])],
            "fork": [{"phase": c["phase"], "cheat": c["signature"], "args": [a for a in c["args"] if a != "<dyn>"]}
                     for c in by_cat.get("fork", [])],
            "host": [{"phase": c["phase"], "cheat": c["signature"]} for c in by_cat.get("host", [])],
            "expect": [{"phase": c["phase"], "cheat": c["signature"]} for c in by_cat.get("expect", [])],
        }

    def pranked_summary(self) -> List[Dict]:
        out = []
        for p, info in self.pranked.items():
            out.append({"address": p, "phases": sorted(info["phases"]), "count": info["count"],
                        "role": info.get("role"), "has_code_at_fork": info.get("has_code_at_fork")})
        return out

    def fingerprint(self, chain: str) -> Dict:
        calls = set()
        nodes = self.arenas.get("Execution", [])
        eff = _effective(nodes)
        for n in nodes:
            t = n["trace"]
            if not eff[n["idx"]] or t.get("kind") not in ("CALL", "CALLCODE"):
                continue
            caller = (t.get("caller") or "").lower()
            to = (t.get("address") or "").lower()
            if caller not in self.attackers or to in self.attackers or to in (CHEAT, CONSOLE):
                continue
            sel = (t.get("data") or "0x")[:10].lower()
            if sel in GENERIC_SELECTORS:
                continue
            calls.add("%s:%s" % (to, sel))
        losers = sorted({x["address"] for x in self.losers})
        gains = sorted(a for a, v in self.attacker_net.items() if v > 0)
        return {"chain": chain, "calls": sorted(calls), "losers": losers, "gain_assets": gains}

    def call_summary(self, label: Callable[[str], str], max_lines: int = 28, max_depth: int = 3) -> List[str]:
        nodes = self.arenas.get("Execution", [])
        if not nodes:
            return []
        by_idx = {n["idx"]: n for n in nodes}
        eff = _effective(nodes)
        lines = []
        hidden = [0]

        def fname(t):
            sel = (t.get("data") or "0x")[:10].lower()
            if t.get("kind") in ("CREATE", "CREATE2"):
                return "new"
            if sel == "0x" or len(sel) < 10:
                return "receive/fallback()"
            return self.sigmap.get(sel, sel)

        def walk(idx, depth):
            n = by_idx[idx]
            for cidx in n.get("children", []):
                c = by_idx[cidx]
                t = c["trace"]
                to = (t.get("address") or "").lower()
                kind = t.get("kind")
                if to in (CHEAT, CONSOLE) or kind == "STATICCALL":
                    continue
                if kind == "DELEGATECALL":
                    walk(cidx, depth)
                    continue
                if depth > max_depth:
                    hidden[0] += 1
                    walk(cidx, depth + 1)
                    continue
                caller = (t.get("caller") or "").lower()
                parts = ["  " * (depth - 1) + "- "]
                if kind in ("CREATE", "CREATE2"):
                    parts.append(i18n.t("trace.creates", label(to)))
                else:
                    parts.append("%s.%s" % (label(to), fname(t)))
                val = _int(t.get("value"))
                if val:
                    parts.append(i18n.t("trace.value", val / 1e18, self.native_symbol))
                if to in self.attackers and caller not in self.attackers and kind not in ("CREATE", "CREATE2"):
                    parts.append(i18n.t("trace.callback"))
                if caller in self.pranked and caller not in self.attackers:
                    parts.append(i18n.t("trace.as_prank", label(caller)))
                if not eff[cidx]:
                    parts.append(" [REVERT]" if not t.get("success") else i18n.t("trace.undone"))
                if len(lines) < max_lines:
                    lines.append("".join(parts))
                else:
                    hidden[0] += 1
                walk(cidx, depth + 1)

        walk(nodes[0]["idx"], 1)
        if hidden[0]:
            lines.append(i18n.t("trace.hidden", hidden[0]))
        return lines

