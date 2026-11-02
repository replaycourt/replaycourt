# Triage verdict: StaxLPStaking lets anyone withdraw all LP tokens via a fake old-staking address

**Verdict: VALID** · severity hint: **critical** · exit code 3

**DUPLICATE** of `sub-1` - close as duplicate (technical verdict above).

Report `sub-2` (../runs-private/testnet/contract.replaycourt.testnet/2/report.md), author: whitehat_ai_42 (demo: deliberate duplicate of 01, reworded, PoC rebuilt), claimed severity: high. Checked 2026-11-02T20:47:51Z, took 11.4 s.

## Reasons
- PoC test `testDrain()` passes on the fork.
- Real outflow of value from third parties to the attacker, without taking over identities and without faked state.
- Duplicate of `sub-1` (already triaged).
- Severity basis: up to 100 % of a victim's holdings
- The report claims "high", the check suggests "critical".

## Fork
- Chain `ethereum` (chain id 1), fork block per report: 15725066 (source: front-matter), actually used in the PoC run: 15725066.
- RPC: https://eth.drpc.org
  - rejected: https://ethereum-rpc.publicnode.com - no archive access: HTTP 403: {"jsonrpc":"2.0","error":{"code":-32602,"message":"Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode"},"id":1

## PoC run
- Compile: ok (3.59 s, solc 0.8.38+commit.1835d247)
- Test `testDrain()`: PASSED, gas 477,961, duration 10ms 622µs 279ns

## Balance changes
Computed from the Transfer/Deposit/Withdrawal events and ETH values in the execution trace - not from what the PoC prints.

| Role | Address | Asset | Change | Share of holdings | approx. USD |
|---|---|---|---|---|---|
| attacker | attacker total (2 addr.) `0x7fa9…1496` | xFraxTempleLP | +321,154.87 | – | – |
| loser |  `0xd286…7941` | xFraxTempleLP | −321,154.87 | 100 % | – |

Valuation: native coin price at the block: 1,285.92 USD (Chainlink); no price: xFraxTempleLP.

## Cheatcodes
- Calls: assertGt×1, createSelectFork×1

## Call trace (shortened, without reads and cheatcodes)
```
- creates attack contract
- attack contract.run()
  - 0xd286…7941.migrateStake(address,uint256)
    - attack contract.migrateWithdraw(address,uint256) [callback to attacker]
  - 0xd286…7941.withdrawAll(bool)
    - xFraxTempleLP.transfer(address,uint256)
  - xFraxTempleLP.transfer(address,uint256)
```

## Duplicate check
- Compared with 2 earlier report(s); result: **duplicate**.
  - `sub-1`: text 0.02 · code 0.39 · fingerprint 1.00 -> duplicate
  - `sub-0`: text 0.02 · code 0.39 · fingerprint 0.00 -> none

---
Machine-readable: `verdict.json` in the same folder. Tool: ReplayCourt engine 0.4.0, forge Version: 1.8.7.
