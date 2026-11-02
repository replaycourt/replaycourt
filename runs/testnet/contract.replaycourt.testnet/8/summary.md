# Triage verdict: Oracle manipulation in the ETH/USD feed (PoC needs a few helpers)

**Verdict: INVALID** · severity hint: **none** · exit code 1

Report `sub-8` (../runs-private/testnet/contract.replaycourt.testnet/8/report.md), author: attack demo b (sandbox escape attempt from inside the PoC), claimed severity: critical. Checked 2026-11-02T20:52:35Z, took 10.5 s.

## Reasons
- PoC test `testExploit()` passes on the fork.
- No measurable value movement: neither a gain for the attacker nor a loss for third parties. The test passes but proves no damage.

## Warnings
- The PoC called host cheatcodes (envString, ffi, readFile); see poc_logs for what the sandbox answered.
- The PoC opened a fork from an RPC the engine did not choose (http://127.0.0.1:9/attacker-rpc).

## Fork
- Chain `ethereum` (chain id 1), fork block per report: 19000000 (source: front-matter), actually used in the PoC run: 19000000.
- RPC: https://eth.drpc.org
  - rejected: https://ethereum-rpc.publicnode.com - no archive access: HTTP 403: {"jsonrpc":"2.0","error":{"code":-32602,"message":"Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode"},"id":1

## PoC run
- Compile: ok (3.42 s, solc 0.8.38+commit.1835d247)
- Test `testExploit()`: PASSED, gas 358,273, duration 27ms 109µs 846ns
- PoC output (for information only, not evidence):
  - `ffi: sh -c 'cat .secrets' -> refused: vm.ffi: FFI is disabled; add the `--ffi` flag to allow tests to call external commands`
  - `readFile: ../.secrets/verifier-x25519.json -> refused: vm.readFile: the path ../.secrets/verifier-x25519.json is not allowed to be accessed for read operations`
  - `readFile: ../../../.secrets/showcase-v2/verifier-fc-key.json -> refused: vm.readFile: the path ../../../.secrets/showcase-v2/verifier-fc-key.json is not allowed`
  - `envString: PRIVATE_KEY -> refused: vm.envString: environment variable "PRIVATE_KEY" not found`
  - `envString: NEAR_PRIVATE_KEY -> refused: vm.envString: environment variable "NEAR_PRIVATE_KEY" not found`
  - `rpcUrl: mainnet -> GOT: https://eth.drpc.org`

Valuation: native coin price at the block: 2,562.92 USD (Chainlink).

## Cheatcodes
- Calls: createFork×1, createSelectFork×1, envString×2, ffi×1, readFile×2, rpcUrl×1

## Address check at the fork block
- target `0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419`: contract with code

## Duplicate check
- Compared with 8 earlier report(s); result: **no duplicate**.
  - `sub-1`: text 0.00 · code 0.21 · fingerprint 0.00 -> none
  - `sub-6`: text 0.00 · code 0.20 · fingerprint 0.00 -> none
  - `sub-5`: text 0.00 · code 0.17 · fingerprint 0.00 -> none

---
Machine-readable: `verdict.json` in the same folder. Tool: ReplayCourt engine 0.4.0, forge Version: 1.8.7.
