"""Read a bug report (Markdown) together with its Foundry PoC.

Format: optional front matter between two '---' lines with 'key: value' lines, then free
Markdown text. The PoC is either a ```solidity block in the text or is referenced with
'poc: <path>' (path relative to the report).
"""

import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .i18n import t

ADDR_RE = re.compile(r"0x[0-9a-fA-F]{40}\b")

KEY_ALIASES = {
    "id": "id",
    "title": "title",
    "chain": "chain", "network": "chain",
    "fork_block": "fork_block", "forkblock": "fork_block", "fork-block": "fork_block",
    "block": "fork_block",
    "poc": "poc", "poc_file": "poc",
    "test": "test", "test_function": "test",
    "attacker": "attackers", "attackers": "attackers",
    "victim": "victims", "victims": "victims",
    "target": "targets", "targets": "targets",
    "vulnerable": "targets",
    "severity": "claimed_severity",
    "evm_version": "evm_version",
    "author": "author", "reporter": "author",
}
ADDRESS_KEYS = {"attackers", "victims", "targets"}

# Where a value came from (stored in verdict.json as a code).
SRC_FRONT_MATTER = "front-matter"
SRC_TEXT = "text"


class ReportError(Exception):
    """The report is unusable (exit 65)."""


@dataclass
class Report:
    path: str
    report_id: str
    text: str
    body: str
    sha256: str
    meta: Dict[str, str] = field(default_factory=dict)
    sources: Dict[str, str] = field(default_factory=dict)
    title: str = ""
    author: str = ""
    chain: Optional[str] = None
    fork_block: Optional[int] = None
    test: Optional[str] = None
    attackers: List[str] = field(default_factory=list)
    victims: List[str] = field(default_factory=list)
    targets: List[str] = field(default_factory=list)
    claimed_severity: str = ""
    evm_version: Optional[str] = None
    poc_source: str = ""
    poc_origin: str = ""
    poc_sha256: str = ""
    poc_fork_calls: List[Dict] = field(default_factory=list)
    poc_error: Optional[str] = None


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def sanitize_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value or "").strip("-")


def _parse_int(value: str) -> Optional[int]:
    v = value.strip().replace("_", "").replace(",", "").replace(".", "").replace(" ", "")
    if v.lower().startswith("0x"):
        try:
            return int(v, 16)
        except ValueError:
            return None
    return int(v) if v.isdigit() else None


def _split_front_matter(text: str):
    if not text.startswith("---"):
        return {}, text
    lines = text.splitlines()
    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end = i
            break
    if end is None:
        return {}, text
    meta = {}
    for line in lines[1:end]:
        if not line.strip() or line.lstrip().startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip().strip('"').strip("'")
        meta[key] = value
    return meta, "\n".join(lines[end + 1:])


FENCE_RE = re.compile(r"```([A-Za-z0-9_+-]*)[^\n]*\n(.*?)```", re.S)


def extract_inline_poc(body: str) -> Optional[str]:
    candidates = []
    for m in FENCE_RE.finditer(body):
        lang, code = m.group(1).lower(), m.group(2)
        if lang in ("solidity", "sol") or "pragma solidity" in code:
            candidates.append(code)
    for code in candidates:
        if re.search(r"function\s+test\w*\s*\(", code):
            return code
    return candidates[0] if candidates else None


FORK_CALL_RE = re.compile(
    r"(createSelectFork|createFork)\s*\(\s*(\"[^\"]*\"|'[^']*'|[A-Za-z_][\w.]*)\s*(?:,\s*([0-9][0-9_]*|0x[0-9a-fA-F]+))?\s*\)")


def find_fork_calls(poc: str) -> List[Dict]:
    out = []
    for m in FORK_CALL_RE.finditer(poc):
        arg = m.group(2)
        literal = arg[0] in "\"'"
        block = _parse_int(m.group(3)) if m.group(3) else None
        out.append({"call": m.group(1), "arg": arg.strip("\"'"), "literal": literal, "block": block})
    return out


def _body_guess(body: str, report: "Report"):
    if not report.chain:
        m = re.search(r"(?im)^[\s>*_-]*(?:chain|network)\**\s*[:=]\s*\**\s*([A-Za-z][A-Za-z0-9 _-]{1,30})", body)
        if m:
            report.chain = m.group(1).strip().lower()
            report.sources["chain"] = SRC_TEXT
    if report.fork_block is None:
        m = re.search(r"(?im)fork[\s_-]*block(?:[\s_-]*number)?\**\s*[:=#]?\s*\**\s*([0-9][0-9_,.]{3,})", body)
        if m:
            report.fork_block = _parse_int(m.group(1))
            report.sources["fork_block"] = SRC_TEXT


def _within(path: str, roots: List[str]) -> bool:
    real = os.path.realpath(path)
    for root in roots:
        r = os.path.realpath(root)
        if real == r or real.startswith(r + os.sep):
            return True
    return False


def load_report(path: str, allowed_roots: List[str]) -> Report:
    if not os.path.isfile(path):
        raise ReportError(t("report.file_missing", path))
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    meta_raw, body = _split_front_matter(text)
    meta = {}
    for k, v in meta_raw.items():
        meta[KEY_ALIASES.get(k, k)] = v

    stem = os.path.splitext(os.path.basename(path))[0]
    rid = sanitize_id(meta.get("id") or stem) or "report"
    rep = Report(path=os.path.abspath(path), report_id=rid, text=text, body=body,
                 sha256=_sha256(text), meta=meta)
    rep.title = meta.get("title", "")
    if not rep.title:
        m = re.search(r"(?m)^#\s+(.+)$", body)
        rep.title = m.group(1).strip() if m else stem
    rep.author = meta.get("author", "")
    rep.claimed_severity = meta.get("claimed_severity", "")
    rep.evm_version = meta.get("evm_version") or None
    rep.test = meta.get("test") or None
    if meta.get("chain"):
        rep.chain = meta["chain"].strip().lower()
        rep.sources["chain"] = SRC_FRONT_MATTER
    if meta.get("fork_block"):
        rep.fork_block = _parse_int(meta["fork_block"])
        rep.sources["fork_block"] = SRC_FRONT_MATTER
    for key in ADDRESS_KEYS:
        if meta.get(key):
            addrs = [a.lower() for a in ADDR_RE.findall(meta[key])]
            setattr(rep, key, list(dict.fromkeys(addrs)))
    _body_guess(body, rep)

    try:
        _load_poc(rep, meta, allowed_roots)
    except ReportError as exc:
        rep.poc_error = str(exc)
    rep.poc_sha256 = _sha256(rep.poc_source)
    rep.poc_fork_calls = find_fork_calls(rep.poc_source)
    return rep


def _load_poc(rep: Report, meta: Dict[str, str], allowed_roots: List[str]):
    if meta.get("poc"):
        poc_path = os.path.join(os.path.dirname(rep.path), meta["poc"])
        if not _within(poc_path, allowed_roots):
            raise ReportError(t("poc.outside_roots", meta["poc"]))
        if not os.path.isfile(poc_path):
            raise ReportError(t("poc.ref_missing", meta["poc"]))
        with open(poc_path, "r", encoding="utf-8", errors="replace") as fh:
            rep.poc_source = fh.read()
        rep.poc_origin = os.path.relpath(os.path.realpath(poc_path), os.path.dirname(rep.path))
    else:
        code = extract_inline_poc(rep.body)
        if code is None:
            raise ReportError(t("poc.none_found"))
        rep.poc_source = code
        rep.poc_origin = "inline"
    if "pragma solidity" not in rep.poc_source:
        raise ReportError(t("poc.no_pragma"))
    if not re.search(r"function\s+(test\w*|invariant\w*)\s*\(", rep.poc_source):
        raise ReportError(t("poc.no_test"))


# Static warning signs in the PoC (NOT executed, only reported). Text is looked up at call time.
STATIC_PATTERNS = [
    ("ffi", r"\b(vm|cheats?)\s*\.\s*(ffi|tryFfi)\s*\(", "static.ffi"),
    ("fs", r"\b(vm|cheats?)\s*\.\s*(readFile|readFileBinary|writeFile|writeFileBinary|writeLine|readLine|removeFile|createDir|removeDir|readDir|copyFile|writeJson|writeToml)\s*\(", "static.fs"),
    ("env", r"\b(vm|cheats?)\s*\.\s*(env\w*|setEnv)\s*\(", "static.env"),
    ("rpc", r"\b(vm|cheats?)\s*\.\s*rpc\s*\(", "static.rpc"),
    ("rpcurl", r"\b(vm|cheats?)\s*\.\s*rpcUrl\w*\s*\(", "static.rpcurl"),
    ("http", r"\b(vm|cheats?)\s*\.\s*http\w*\s*\(", "static.http"),
]


def static_flags(rep: Report) -> List[Dict]:
    flags = []
    src = rep.poc_source
    for code, pattern, key in STATIC_PATTERNS:
        if re.search(pattern, src):
            flags.append({"code": code, "text": t(key)})
    for fc in rep.poc_fork_calls:
        if fc["literal"] and re.match(r"(?i)^(https?|wss?)://", fc["arg"]):
            flags.append({"code": "external_url", "text": t("static.external_url", fc["arg"])})
    return flags
