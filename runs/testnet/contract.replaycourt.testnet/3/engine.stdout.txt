# Triage verdict: Alleged arbitrary token theft via a direct transferFrom around the Seneca Chamber

**Verdict: INVALID** · severity hint: **none** · exit code 1

Report `sub-3` (../runs-private/testnet/contract.replaycourt.testnet/3/report.md), author: Demo (deliberately invalid: the PoC does not prove the claimed attack), claimed severity: critical. Checked 2026-11-02T20:48:10Z, took 12.9 s.

## Reasons
- The PoC test fails on the fork: ERC20: insufficient allowance

## Fork
- Chain `ethereum` (chain id 1), fork block per report: 19325936 (source: front-matter), actually used in the PoC run: 19325936.
- RPC: https://eth.drpc.org
  - rejected: https://ethereum-rpc.publicnode.com - no archive access: HTTP 403: {"jsonrpc":"2.0","error":{"code":-32602,"message":"Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode"},"id":1

## PoC run
- Compile: ok (4.72 s, solc 0.8.38+commit.1835d247)
- Test `testExploit()`: FAILED – ERC20: insufficient allowance, gas 38,242, duration 3ms 111µs 911ns

## Duplicate check
- Compared with 3 earlier report(s); result: **no duplicate**.
  - `sub-1`: text 0.00 · code 0.46 · fingerprint 0.00 -> none
  - `sub-2`: text 0.00 · code 0.46 · fingerprint 0.00 -> none
  - `sub-0`: text 0.00 · code 0.46 · fingerprint 0.00 -> none

---
Machine-readable: `verdict.json` in the same folder. Tool: ReplayCourt engine 0.4.0, forge Version: 1.8.7.
