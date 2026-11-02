# Triage verdict: Missing access control in StaxLPStaking.migrateStake() allows draining all LP tokens

**Verdict: INVALID** · severity hint: **none** · exit code 1

Report `sub-0` (../runs-private/testnet/contract.replaycourt.testnet/0/report.md), author: Demo (re-enactment of the public TempleDAO/STAX incident of 2022-10-11, PoC from DeFiHackLabs), claimed severity: critical. Checked 2026-11-02T20:47:17Z, took 10.7 s.

## Reasons
- The PoC test fails on the fork: typo in my first PoC

## Fork
- Chain `ethereum` (chain id 1), fork block per report: 15725066 (source: front-matter), actually used in the PoC run: 15725066.
- RPC: https://eth.drpc.org
  - rejected: https://ethereum-rpc.publicnode.com - no archive access: HTTP 403: {"jsonrpc":"2.0","error":{"code":-32602,"message":"Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode"},"id":1

## PoC run
- Compile: ok (3.84 s, solc 0.8.38+commit.1835d247)
- Test `testExploit()`: FAILED – typo in my first PoC, gas 289, duration 1ms 510µs 182ns

## Duplicate check
- No earlier reports in the registry.

---
Machine-readable: `verdict.json` in the same folder. Tool: ReplayCourt engine 0.4.0, forge Version: 1.8.7.
