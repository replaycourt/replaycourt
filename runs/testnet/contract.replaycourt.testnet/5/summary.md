# Triage verdict: Reentrancy in Vault.withdraw() (local test contract, no fork)

**Verdict: NEEDS HUMAN** · severity hint: **provisional high** · exit code 2

Report `sub-5` (../runs-private/testnet/contract.replaycourt.testnet/5/report.md), author: Demo (local fallback case: no fork, bundled vulnerable contract), claimed severity: high. Checked 2026-11-02T20:50:12Z, took 6.6 s.

## Reasons
- PoC test `testExploit()` passes (local mode, no fork).
- Local mode: the bundled code was checked, not a deployment. Whether it matches the protocol's code must be checked by a human.
- State changed via cheatcode (deal@0x00000000).
- Attacker's starting capital comes from a cheatcode (deal) - check the net gain against that capital.
- The PoC acts as a foreign address via vm.prank (0x00000000000000000000000000000000000a11ce) - privileged precondition?
- Severity basis: amount cannot be valued
- The report claims "high", the check suggests "provisional high".

## Fork
- Local mode without a fork (chain `local`).

## PoC run
- Compile: ok (3.34 s, solc 0.8.38+commit.1835d247)
- Test `testExploit()`: PASSED, gas 326,100, duration 305µs 537ns

## Balance changes
Computed from the Transfer/Deposit/Withdrawal events and ETH values in the execution trace - not from what the PoC prints.

| Role | Address | Asset | Change | Share of holdings | approx. USD |
|---|---|---|---|---|---|
| attacker | attacker total (2 addr.) `0x7fa9…1496` | ETH | +10.00 | – | – |
| loser |  `0x5615…b72f` | ETH | −10.00 | – | – |

Valuation: no price: ETH.

## Cheatcodes
- Calls: assertEq×1, assertGt×1, deal×2, prank×1
- Starting capital: `deal(address,uint256)` to 0x2e23…470b (Execution)
- State change: `deal(address,uint256)` at 0x0000…11ce (Setup)
- vm.prank identities:
  - `0x00000000000000000000000000000000000a11ce` (Setup): foreign identity (privileged action?)

## Call trace (shortened, without reads and cheatcodes)
```
- creates attack contract
- attack contract.attack() [value 1 ETH]
  - 0x5615…b72f.deposit() [value 1 ETH]
  - 0x5615…b72f.withdraw()
    - attack contract.receive/fallback() [value 1 ETH] [callback to attacker]
  (… 20 more calls hidden)
```

## Duplicate check
- Compared with 5 earlier report(s); result: **no duplicate**.
  - `sub-2`: text 0.00 · code 0.36 · fingerprint 0.00 -> none
  - `sub-1`: text 0.00 · code 0.34 · fingerprint 0.00 -> none
  - `sub-0`: text 0.00 · code 0.34 · fingerprint 0.00 -> none

---
Machine-readable: `verdict.json` in the same folder. Tool: ReplayCourt engine 0.4.0, forge Version: 1.8.7.
