"""Small JSON-RPC client (standard library only) for the archive probe and read access.

Only read methods are used (eth_chainId, eth_blockNumber, eth_getBalance, eth_getCode,
eth_call). No transactions, no keys.
"""

import json
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

from .i18n import t

USER_AGENT = "replaycourt-engine/0.2 (read-only triage)"


class RpcError(Exception):
    pass


def call(url: str, method: str, params: list, timeout: float = 25.0):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json", "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8", "replace")[:300]
        except Exception:  # noqa: BLE001
            detail = ""
        raise RpcError("HTTP %s: %s" % (exc.code, detail.strip()))
    except Exception as exc:  # noqa: BLE001  (network error, timeout, JSON)
        raise RpcError("%s: %s" % (type(exc).__name__, exc))
    if isinstance(payload, dict) and payload.get("error"):
        err = payload["error"]
        raise RpcError(t("rpc.error", err.get("code"), str(err.get("message"))[:300]))
    if not isinstance(payload, dict) or "result" not in payload:
        raise RpcError(t("rpc.unexpected", str(payload)[:200]))
    return payload["result"]


def _blk(block: Optional[int]) -> str:
    return hex(block) if block is not None else "latest"


def probe_archive(url: str, chain_cfg: Dict, block: Optional[int]) -> Tuple[bool, Dict]:
    info = {"url": url}
    try:
        cid = int(call(url, "eth_chainId", [], timeout=15), 16)
        info["chain_id"] = cid
        if cid != chain_cfg["chain_id"]:
            info["reason"] = t("rpc.wrong_chain", cid, chain_cfg["chain_id"])
            return False, info
        head = int(call(url, "eth_blockNumber", [], timeout=15), 16)
        info["head"] = head
        if block is not None and block > head:
            info["reason"] = t("rpc.block_after_head", block, head)
            return False, info
        probe_addr = chain_cfg.get("wrapped_native") or "0x0000000000000000000000000000000000000000"
        call(url, "eth_getBalance", [probe_addr, _blk(block)], timeout=20)
        call(url, "eth_getCode", [probe_addr, _blk(block)], timeout=20)
        info["archive_ok"] = True
        return True, info
    except RpcError as exc:
        msg = str(exc)
        low = msg.lower()
        if any(s in low for s in ("archive", "missing trie node", "historical state", "header not found",
                                  "state is not available", "pruned")):
            info["reason"] = t("rpc.no_archive", msg[:160])
        else:
            info["reason"] = msg[:200]
        return False, info


def select_rpc(chain_cfg: Dict, block: Optional[int], override: Optional[str] = None) -> Tuple[Optional[str], List[Dict]]:
    attempts = []
    urls = [override] if override else list(chain_cfg.get("rpcs", []))
    for url in urls:
        ok, info = probe_archive(url, chain_cfg, block)
        info["ok"] = ok
        attempts.append(info)
        if ok:
            return url, attempts
    return None, attempts


def eth_call(url: str, to: str, data: str, block: Optional[int]) -> str:
    return call(url, "eth_call", [{"to": to, "data": data}, _blk(block)])


def get_code(url: str, addr: str, block: Optional[int]) -> str:
    return call(url, "eth_getCode", [addr, _blk(block)])


def get_balance(url: str, addr: str, block: Optional[int]) -> int:
    return int(call(url, "eth_getBalance", [addr, _blk(block)]), 16)


def _pad_addr(addr: str) -> str:
    return addr.lower().replace("0x", "").rjust(64, "0")


def erc20_balance(url: str, token: str, holder: str, block: Optional[int]) -> Optional[int]:
    try:
        out = eth_call(url, token, "0x70a08231" + _pad_addr(holder), block)
        return int(out[2:66] or "0", 16)
    except (RpcError, ValueError):
        return None


def _decode_string(hexdata: str) -> Optional[str]:
    raw = bytes.fromhex(hexdata[2:]) if hexdata.startswith("0x") else bytes.fromhex(hexdata)
    if len(raw) == 32:  # bytes32 symbol (e.g. MKR)
        return raw.rstrip(b"\x00").decode("utf-8", "replace") or None
    if len(raw) >= 64:
        off = int.from_bytes(raw[0:32], "big")
        if off + 32 <= len(raw):
            ln = int.from_bytes(raw[off:off + 32], "big")
            return raw[off + 32:off + 32 + ln].decode("utf-8", "replace") or None
    return None


def token_meta(url: str, token: str, block: Optional[int]) -> Tuple[Optional[str], Optional[int]]:
    symbol, decimals = None, None
    try:
        symbol = _decode_string(eth_call(url, token, "0x95d89b41", block))
    except (RpcError, ValueError):
        pass
    try:
        out = eth_call(url, token, "0x313ce567", block)
        decimals = int(out[2:66] or "0", 16)
        if decimals > 77:
            decimals = None
    except (RpcError, ValueError):
        pass
    return symbol, decimals


def chainlink_price(url: str, feed: str, block: Optional[int]) -> Optional[float]:
    """latestAnswer() of a Chainlink feed (8 decimals) at the block."""
    try:
        out = eth_call(url, feed, "0x50d25bcd", block)
        val = int(out[2:66], 16)
        if val >= 2 ** 255:
            val -= 2 ** 256
        return val / 1e8 if val > 0 else None
    except (RpcError, ValueError):
        return None
