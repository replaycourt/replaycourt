"""Duplicate check against previously triaged reports.

Three independent similarities:
- text: Jaccard over word 3-grams of the report text (code blocks removed),
- code: difflib ratio over the normalized token sequence of the PoC,
- fingerprint: Jaccard over the attack calls that actually executed (target:selector)
  and the addresses that lost value - catches reworded reports with a rewritten PoC
  for the same bug.
The registry is a JSON Lines file (one line per report). Entries are keyed by the report
id; the worker passes the on-chain submission id (e.g. "sub-12") so that the "of" field of
a duplicate block names an on-chain submission.

Only a valid earlier report can be the original of a duplicate (SPEC v2, "Duplicates"). Every
report is recorded, and invalid or needs-human entries are still compared and listed as
candidates, but they never make a later report a duplicate or a possible duplicate. Otherwise a
hunter whose first try failed (a typo in the PoC) could not resubmit the fixed report: it would
be closed as a duplicate of their own invalid report. When the worker has synced the on-chain
status of an entry ("onchain_status"), the contract's rule decides instead: an original must be
valid, paid or disputed on-chain.
"""

import datetime as _dt
import difflib
import json
import os
import re
from typing import Dict, List, Optional

FENCE_RE = re.compile(r"```.*?```", re.S)
WORD_RE = re.compile(r"0x[0-9a-f]{40}|[a-z0-9]+")
CODE_TOKEN_RE = re.compile(r"0x[0-9a-fA-F]+|[A-Za-z_][A-Za-z0-9_]*|[0-9][0-9_]*|\S")

# Engine verdict code an entry needs to be an original (registry field "verdict_code").
ORIGINAL_VERDICT = "valid"
# On-chain statuses a duplicate_of may point to (SPEC v2, post_verdict "duplicate").
ORIGINAL_ONCHAIN_STATUSES = ("valid", "paid", "disputed")

TH_DUP = {"fingerprint": 0.75, "text": 0.70, "code": 0.90}
TH_POSSIBLE = {"fingerprint": 0.50, "text": 0.45, "code": 0.70}
MAX_CODE_TOKENS = 6000


def normalize_text(body: str) -> List[str]:
    text = FENCE_RE.sub(" ", body).lower()
    return WORD_RE.findall(text)


def normalize_code(src: str) -> List[str]:
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
    src = re.sub(r"//[^\n]*", " ", src)
    toks = []
    for t in CODE_TOKEN_RE.findall(src):
        if t[0].isdigit():
            t = t.replace("_", "")
        elif t.lower().startswith("0x"):
            t = t.lower()
        toks.append(t)
    return toks[:MAX_CODE_TOKENS]


def shingles(tokens: List[str], k: int = 3) -> set:
    if len(tokens) < k:
        return {" ".join(tokens)} if tokens else set()
    return {" ".join(tokens[i:i + k]) for i in range(len(tokens) - k + 1)}


def jaccard(a, b) -> float:
    a, b = set(a), set(b)
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def fingerprint_similarity(fa: Optional[Dict], fb: Optional[Dict]) -> float:
    if not fa or not fb or fa.get("chain") != fb.get("chain"):
        return 0.0
    parts = []
    if fa.get("calls") or fb.get("calls"):
        parts.append(jaccard(fa.get("calls", []), fb.get("calls", [])))
    if fa.get("losers") or fb.get("losers"):
        parts.append(jaccard(fa.get("losers", []), fb.get("losers", [])))
    if not parts:
        return 0.0
    # Without attack calls and without losers there is nothing to compare.
    if not (fa.get("calls") or fa.get("losers")) or not (fb.get("calls") or fb.get("losers")):
        return 0.0
    return sum(parts) / len(parts)


def load_registry(path: str) -> List[Dict]:
    entries = []
    if not os.path.isfile(path):
        return entries
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except ValueError:
                    continue
    return entries


def apply_onchain_status(entries: List[Dict], statuses: Optional[Dict[str, str]]) -> List[Dict]:
    """Overlay on-chain statuses ({"sub-3": "paid", ...}, from the worker) on registry entries.
    In memory only; the registry file keeps the engine's own record."""
    if not statuses:
        return entries
    out = []
    for e in entries:
        st = statuses.get(e.get("id"))
        if isinstance(st, str) and st:
            e = dict(e, onchain_status=st)
        out.append(e)
    return out


def load_onchain_status(path: Optional[str]) -> Dict[str, str]:
    """Read the worker's {report_id: on-chain status} file; a missing or broken file is no overlay."""
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): v for k, v in data.items() if isinstance(v, str)}


def save_entry(path: str, entry: Dict):
    entries = [e for e in load_registry(path) if e.get("id") != entry["id"]]
    entries.append(entry)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")
    os.replace(tmp, path)


def make_entry(report, fingerprint: Optional[Dict], verdict_code: str, triaged_at: str,
               duplicate_of: Optional[str]) -> Dict:
    return {
        "id": report.report_id,
        "title": report.title,
        "report_sha256": report.sha256,
        "poc_sha256": report.poc_sha256,
        "chain": report.chain,
        "fork_block": report.fork_block,
        "verdict_code": verdict_code,
        "duplicate_of": duplicate_of,
        "triaged_at": triaged_at,
        "text_tokens": normalize_text(report.body),
        "code_tokens": normalize_code(report.poc_source),
        "fingerprint": fingerprint,
    }


def is_original(entry: Dict) -> bool:
    """Can this registry entry be the original of a later duplicate? Only a valid report can.

    With an "onchain_status" (synced by the worker) the contract's rule decides: valid, paid or
    disputed. This also covers a needs-human report that the owner resolved as valid (paid), and
    a valid verdict the owner overruled (rejected). Without it, the engine's own verdict decides:
    "valid", and not itself a duplicate of another report.
    """
    status = entry.get("onchain_status")
    if status:
        return status in ORIGINAL_ONCHAIN_STATUSES
    return entry.get("verdict_code") == ORIGINAL_VERDICT and not entry.get("duplicate_of")


def time_key(value) -> float:
    """Sort key for an ISO 8601 timestamp; mixed UTC offsets compare correctly. Unparseable: last."""
    if not value:
        return float("inf")
    text = str(value).strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    try:
        ts = _dt.datetime.fromisoformat(text)
    except ValueError:
        return float("inf")
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=_dt.timezone.utc)
    return ts.timestamp()


def _original_of(entry: Dict, by_id: Dict[str, Dict]) -> Optional[str]:
    """The original a match with `entry` points to, or None if it cannot be one.

    A valid entry is its own original. A recorded duplicate points to its original, if that is
    still an original."""
    if is_original(entry):
        return entry.get("id")
    orig_id = entry.get("duplicate_of")
    if orig_id and orig_id in by_id and is_original(by_id[orig_id]):
        return orig_id
    return None


def check(report, fingerprint: Optional[Dict], registry: List[Dict]) -> Dict:
    my_text = shingles(normalize_text(report.body))
    my_code = normalize_code(report.poc_source)
    by_id = {e.get("id"): e for e in registry}
    order = {e.get("id"): i for i, e in enumerate(registry)}
    candidates = []
    for e in registry:
        if e.get("id") == report.report_id:
            continue  # re-check of the same report
        # An empty PoC (report without one) has the same hash in every report: not a copy.
        exact = e.get("report_sha256") == report.sha256 or \
            bool(report.poc_source and e.get("poc_sha256") == report.poc_sha256)
        t = jaccard(my_text, shingles(e.get("text_tokens", [])))
        c = difflib.SequenceMatcher(None, my_code, e.get("code_tokens", []), autojunk=False).ratio() \
            if e.get("code_tokens") else 0.0
        f = fingerprint_similarity(fingerprint, e.get("fingerprint"))
        scores = {"text": round(t, 3), "code": round(c, 3), "fingerprint": round(f, 3)}
        if exact:
            level = "duplicate"
        elif any(scores[k] >= TH_DUP[k] for k in TH_DUP):
            level = "duplicate"
        elif any(scores[k] >= TH_POSSIBLE[k] for k in TH_POSSIBLE):
            level = "possible"
        else:
            level = "none"
        original = _original_of(e, by_id)
        candidates.append({"id": e.get("id"), "title": e.get("title"), "verdict_code": e.get("verdict_code"),
                           "onchain_status": e.get("onchain_status"),
                           "scores": scores, "level": level, "exact_copy": exact,
                           "eligible": original is not None, "original": original,
                           "triaged_at": e.get("triaged_at"), "duplicate_of": e.get("duplicate_of")})
    rank = {"duplicate": 2, "possible": 1, "none": 0}
    # Eligible matches first, so that the list shows what decided the status.
    candidates.sort(key=lambda x: (rank[x["level"]], x["eligible"], max(x["scores"].values())), reverse=True)
    # Only an entry that is (or points to) a valid original decides the status. Matches with
    # invalid or needs-human reports stay visible in "candidates" ("eligible": false).
    deciding = [c for c in candidates if c["eligible"] and c["level"] != "none"]
    status = max((c["level"] for c in deciding), key=lambda lvl: rank[lvl], default="none")
    # A duplicate must name the original: the earliest original among the matches of that level.
    of = None
    if status in ("duplicate", "possible"):
        originals = {c["original"] for c in deciding if c["level"] == status}
        of = min(originals, key=lambda oid: (time_key((by_id.get(oid) or {}).get("triaged_at")),
                                              order.get(oid, len(order))))
    ignored = [c["id"] for c in candidates if not c["eligible"] and c["level"] != "none"]
    return {"status": status, "of": of, "thresholds": {"duplicate": TH_DUP, "possible": TH_POSSIBLE},
            "candidates": candidates[:5], "compared_with": len(candidates),
            "not_original": ignored}
