# Triage verdict: Seneca Chamber.performOperations() executes arbitrary calls - theft of approved tokens

**Verdict: VALID** · severity hint: **critical** · exit code 0

Report `sub-6` (../runs-private/testnet/contract.replaycourt.testnet/6/report.md), author: Demo (re-enactment of the public Seneca incident of 2024-02-28, PoC after DeFiHackLabs), claimed severity: critical. Checked 2026-11-02T20:51:05Z, took 12.2 s.

## Reasons
- PoC test `testExploit()` passes on the fork.
- Real outflow of value from third parties to the attacker, without taking over identities and without faked state.
- Severity basis: up to 100 % of a victim's holdings
- The report claims "critical", the check suggests "critical".

## Fork
- Chain `ethereum` (chain id 1), fork block per report: 19325936 (source: front-matter), actually used in the PoC run: 19325936.
- RPC: https://eth.drpc.org
  - rejected: https://ethereum-rpc.publicnode.com - no archive access: HTTP 403: {"jsonrpc":"2.0","error":{"code":-32602,"message":"Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode"},"id":1

## PoC run
- Compile: ok (3.71 s, solc 0.8.38+commit.1835d247)
- Test `testExploit()`: PASSED, gas 89,213, duration 8ms 357µs 845ns

## Balance changes
Computed from the Transfer/Deposit/Withdrawal events and ETH values in the execution trace - not from what the PoC prints.

| Role | Address | Asset | Change | Share of holdings | approx. USD |
|---|---|---|---|---|---|
| attacker | attacker total (1 addr.) `0x7fa9…1496` | PT-rsETH-27JUN2024 | +1,385.24 | – | – |
| victim (per report) | victim `0x9cbf…06ce` | PT-rsETH-27JUN2024 | −1,385.24 | 100 % | – |

Valuation: native coin price at the block: 3,305.24 USD (Chainlink); no price: PT-rsETH-27JUN2024.

## Cheatcodes
- Calls: assertEq×1, createSelectFork×1, label×3

## Address check at the fork block
- target `0x65c210c59b43eb68112b7a4f75c8393c36491f06`: contract with code
- victim `0x9cbf099ff424979439dfba03f00b5961784c06ce`: no code (EOA or non-existent)

## Call trace (shortened, without reads and cheatcodes)
```
- Chamber.performOperations(uint8[],uint256[],bytes[])
  - PendlePrincipalToken.transferFrom(address,address,uint256)
```

## Duplicate check
- Compared with 6 earlier report(s); result: **no duplicate**.
  - `sub-1`: text 0.01 · code 0.40 · fingerprint 0.00 -> none
  - `sub-2`: text 0.00 · code 0.31 · fingerprint 0.00 -> none
  - `sub-5`: text 0.00 · code 0.30 · fingerprint 0.00 -> none

---
Machine-readable: `verdict.json` in the same folder. Tool: ReplayCourt engine 0.4.0, forge Version: 1.8.7.
