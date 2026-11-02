# Triage verdict: Missing access control in StaxLPStaking.migrateStake() allows draining all LP tokens

**Verdict: VALID** · severity hint: **critical** · exit code 0

Report `sub-1` (../runs-private/testnet/contract.replaycourt.testnet/1/report.md), author: Demo (re-enactment of the public TempleDAO/STAX incident of 2022-10-11, PoC from DeFiHackLabs), claimed severity: critical. Checked 2026-11-02T20:47:34Z, took 11.3 s.

## Reasons
- PoC test `testExploit()` passes on the fork.
- Real outflow of value from third parties to the attacker, without taking over identities and without faked state.
- Severity basis: up to 100 % of a victim's holdings
- The report claims "critical", the check suggests "critical".

## Fork
- Chain `ethereum` (chain id 1), fork block per report: 15725066 (source: front-matter), actually used in the PoC run: 15725066.
- RPC: https://eth.drpc.org
  - rejected: https://ethereum-rpc.publicnode.com - no archive access: HTTP 403: {"jsonrpc":"2.0","error":{"code":-32602,"message":"Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode"},"id":1

## PoC run
- Compile: ok (3.39 s, solc 0.8.38+commit.1835d247)
- Test `testExploit()`: PASSED, gas 248,665, duration 6ms 968µs 813ns
- PoC output (for information only, not evidence):
  - `[Start] Attacker xFraxTempleLP balance before exploit: 0.000000000000000000`
  - `[End] Attacker xFraxTempleLP balance after exploit: 321154.865567124596801893`

## Balance changes
Computed from the Transfer/Deposit/Withdrawal events and ETH values in the execution trace - not from what the PoC prints.

| Role | Address | Asset | Change | Share of holdings | approx. USD |
|---|---|---|---|---|---|
| attacker | attacker total (1 addr.) `0x7fa9…1496` | xFraxTempleLP | +321,154.87 | – | – |
| victim (per report) | StaxLPStaking `0xd286…7941` | xFraxTempleLP | −321,154.87 | 100 % | – |

Valuation: native coin price at the block: 1,285.92 USD (Chainlink); no price: xFraxTempleLP.

## Cheatcodes
- Calls: createSelectFork×1, label×2

## Address check at the fork block
- target `0xd2869042e12a3506100af1d192b5b04d65137941`: contract with code
- victim `0xd2869042e12a3506100af1d192b5b04d65137941`: contract with code

## Call trace (shortened, without reads and cheatcodes)
```
- StaxLPStaking.migrateStake(address,uint256)
  - test contract.migrateWithdraw(address,uint256) [callback to attacker]
- StaxLPStaking.withdrawAll(bool)
  - xFraxTempleLP.transfer(address,uint256)
```

## Duplicate check
- Compared with 1 earlier report(s); result: **no duplicate**.
  - `sub-0`: text 1.00 · code 0.98 · fingerprint 0.00 -> duplicate (not counted: only a valid report can be an original; this one is `invalid`)

---
Machine-readable: `verdict.json` in the same folder. Tool: ReplayCourt engine 0.4.0, forge Version: 1.8.7.
