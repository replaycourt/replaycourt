# Triage verdict: Alleged drain: the attacker ends up holding 1,000,000 USDC

**Verdict: INVALID** · severity hint: **none** · exit code 1

Report `sub-4` (../runs-private/testnet/contract.replaycourt.testnet/4/report.md), author: Demo (deliberately invalid: the "profit" is faked with cheatcodes), claimed severity: critical. Checked 2026-11-02T20:48:32Z, took 17.7 s.

## Reasons
- PoC test `testExploit()` passes on the fork.
- The "damage" only happens because the PoC acts as the victim via vm.prank (0x28c6c06298d514db089934071355e5743bf21d60). A real attacker cannot do that.

## Fork
- Chain `ethereum` (chain id 1), fork block per report: 19000000 (source: front-matter), actually used in the PoC run: 19000000.
- RPC: https://eth.drpc.org
  - rejected: https://ethereum-rpc.publicnode.com - no archive access: HTTP 403: {"jsonrpc":"2.0","error":{"code":-32602,"message":"Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode"},"id":1

## PoC run
- Compile: ok (4.47 s, solc 0.8.38+commit.1835d247)
- Test `testExploit()`: PASSED, gas 328,556, duration 8ms 289µs 981ns
- PoC output (for information only, not evidence):
  - `Profit: USDC: 1001000`

## Balance changes
Computed from the Transfer/Deposit/Withdrawal events and ETH values in the execution trace - not from what the PoC prints.

| Role | Address | Asset | Change | Share of holdings | approx. USD |
|---|---|---|---|---|---|
| attacker | attacker total (1 addr.) `0x7fa9…1496` | USDC | +1,000.00 | – | 1,000 |
| victim (per report) | victim `0x28c6…1d60` | USDC | −1,000.00 | 0 % | -1,000 |

Valuation: damage approx. 1,000 USD; native coin price at the block: 2,562.92 USD (Chainlink).

## Cheatcodes
- Calls: accesses×1, assertGe×1, createSelectFork×1, load×3, prank×1, record×1, store×3
- State change: `store(address,bytes32,bytes32)` at 0xa0b8…eb48 (Execution)
- State change: `store(address,bytes32,bytes32)` at 0xa0b8…eb48 (Execution)
- State change: `store(address,bytes32,bytes32)` at 0xa0b8…eb48 (Execution)
- vm.prank identities:
  - `0x28c6c06298d514db089934071355e5743bf21d60` (Execution): victim (identity taken over)

## Address check at the fork block
- target `0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48`: contract with code
- victim `0x28c6c06298d514db089934071355e5743bf21d60`: no code (EOA or non-existent)

## Call trace (shortened, without reads and cheatcodes)
```
- USDC.transfer(address,uint256) [as victim via vm.prank]
```

## Duplicate check
- Compared with 4 earlier report(s); result: **no duplicate**.
  - `sub-2`: text 0.01 · code 0.47 · fingerprint 0.00 -> none
  - `sub-1`: text 0.00 · code 0.44 · fingerprint 0.00 -> none
  - `sub-3`: text 0.01 · code 0.70 · fingerprint 0.00 -> none

---
Machine-readable: `verdict.json` in the same folder. Tool: ReplayCourt engine 0.4.0, forge Version: 1.8.7.
