# Showcase deployment on NEAR testnet (2026-11-02)

The public demo of ReplayCourt v2. One bounty program holds the six demo reports from
`engine/reports/`, a failed first try that must not block the real report, a report from a scripted
client in the role of an AI hunter (through the MCP server, paid from an on-chain vault), a dispute the owner never resolves,
and the attack demos as extra submissions. Program 1 exists for attack d. Every verdict was signed
with a function-call key that can only call `post_verdict`.

Check it yourself: `cd agent && npm ci && npm run cli -- verify-onchain` (see [`README.md`](README.md),
path A). The attacks are written up in [`ATTACKS.md`](ATTACKS.md), the scripted hunter's run in
[`../mcp/DEMO.md`](../mcp/DEMO.md). Logs: [`logs/`](logs/).

| | |
|---|---|
| contract | [`contract.replaycourt.testnet`](https://testnet.nearblocks.io/address/contract.replaycourt.testnet) (the default of `verify-onchain` and of the explorer in `web/`), `version()` = `2.0.0` |
| deployed code | sha256 `456631c55d04492c6f4143a19f82ebd66942af4333d05997db910d7a1608bd32` (= [`../contract/WASM_SHA256`](../contract/WASM_SHA256), 295,116 bytes, built with `contract/build.sh`), on-chain `code_hash` `5fuWijh2LZQTuCtACJmpxkvoSLmZs99QWXC3Vjz3F42V` |
| contract owner (`new(owner_id)`, no power over funds) | `replaycourt.testnet` |
| program owner | `owner.replaycourt.testnet` |
| verifier | `verifier.replaycourt.testnet`, signing with the function-call key `ed25519:2soJjd3yo41ae17wgrNpZVeykFHuwiDWBGUPRJrD5L3D` (receiver = contract, methods = `post_verdict`, allowance 1 NEAR) |
| hunters | `hunter1.`, `hunter2.`, `hunter3.replaycourt.testnet` |
| agent role (scripted MCP client) | `agent.replaycourt.testnet`, signing with the function-call key `ed25519:37ugn3ZBbkH7oU6wp1JKYDi6Y7dS9fBjGWDvZNsnAmPD` (methods `submit_report_from_vault`, `finalize`, `withdraw_pending`, allowance 0.5 NEAR) |
| other accounts | `verifier2.` (program 1), `thief.` (attack e) |
| program 0 | "Ethereum DeFi replay bounty": pool 2.99438 NEAR (3 NEAR minus program storage), bond 0.05, verifier fee 0.01, dispute bond 0.1, payouts critical 0.4 / high 0.25 / medium 0.15 / low 0.05 NEAR, challenge window 120 s, resolve timeout 180 s, pending timeout 24 h |
| program 1 | "Attack demo d: program judged by another verifier", verifier `verifier2`, pool 1 NEAR (withdrawn after the attack), all windows 60 s |
| evidence | [`../runs/testnet/contract.replaycourt.testnet/`](../runs/testnet/contract.replaycourt.testnet/) |
| tools | agent: near-api-js 7.4.0 on Node 24.22.1; near-cli-rs 0.30.1; engine 0.4.0 (the current 0.5.0 replays every report with the same outcome): Python 3.8.7 + forge 1.8.7; fork RPC `https://eth.drpc.org` (chosen by the engine from `engine/config/chains.json`) |

## Submissions

Commit order is the id. "Bond" is what the contract kept after storage. Storage is listed under
"Money" only for the agent, whose vault pays it. All amounts are NEAR.

| # | report | hunter | `submit_report` | verdict (`post_verdict`, function-call key) | settlement | final status | money |
|---|---|---|---|---|---|---|---|
| 0 | [`demo/v2/s1-first-try.md`](v2/s1-first-try.md): report 01 with one line that breaks the PoC | hunter2 | [`5mCmGWEf…`](https://testnet.nearblocks.io/txns/5mCmGWEfHUNhYccu2wcaRuqWDbgrELCydFteLAHmP21G) | **invalid**: the PoC fails, `typo in my first PoC` [`E9BXf71d…`](https://testnet.nearblocks.io/txns/E9BXf71doNUV43E364pFocMNEoMGjVHLWXbBZp5jssV) | - | invalid | bond 0.05321 slashed: 0.04321 to the pool, 0.01 to the verifier |
| 1 | 01 TempleDAO/STAX `migrateStake()` | hunter1 | [`B9zDQa3f…`](https://testnet.nearblocks.io/txns/B9zDQa3f46rTFjAfE9ZpELeEiMJkcCA4EhSc6ktmTxzf) | **valid / critical**, fork block 15,725,066, **not** a duplicate of #0 [`GkFdHxRB…`](https://testnet.nearblocks.io/txns/GkFdHxRBQ96cQVXQXXC5fNToL8WtCUCmMYFsuXrSr2ws) | `finalize` by hunter3 [`HkGucff6…`](https://testnet.nearblocks.io/txns/HkGucff6D3Ms134KsHCrfXd3HBUaKZQyN9obvNkLBBWR) | **paid** | 0.4 payout + bond 0.05321 back to hunter1; 0.01 fee from the pool |
| 2 | 03 STAX drain, reworded, PoC rebuilt | hunter3 | [`6S4pXQLd…`](https://testnet.nearblocks.io/txns/6S4pXQLd1DN95mR5bzTDfTUPVGGFjdBMbgotT5Fzopuy) | **duplicate of #1** [`F9jjLYmF…`](https://testnet.nearblocks.io/txns/F9jjLYmFFXJRohiuDrYRkrxLWYjfqj9XATUkrkFjoLgW) | - | duplicate | bond 0.05321: 0.04321 refunded, 0.01 to the verifier |
| 3 | 04 Seneca "direct transferFrom" (bogus) | hunter2 | [`DkSABkQA…`](https://testnet.nearblocks.io/txns/DkSABkQARfMj831Sk4JgidVhvAKew7CnxKwcG6QAA4eu) | **invalid**: `ERC20: insufficient allowance` [`BfBiqFaW…`](https://testnet.nearblocks.io/txns/BfBiqFaWn1LLnV273jNp6kKfmjoGNrUxmf1m4V5Qtow2) | - | invalid | bond 0.05585 slashed: 0.04585 to the pool, 0.01 to the verifier |
| 4 | 05 fake profit (`deal` + `vm.prank`) | hunter3 | [`5ArVEop1…`](https://testnet.nearblocks.io/txns/5ArVEop1wb2gkGcX2W8h1Q7G967yQCKSkdCNVY52oz3H) | **invalid**: the "damage" only exists through `vm.prank` as the victim [`EMXodkQ5…`](https://testnet.nearblocks.io/txns/EMXodkQ5d4JPkmAQmb3TpKfN35txoR75ygATCEibqjvY) | - | invalid | bond 0.05585 slashed: 0.04585 to the pool, 0.01 to the verifier |
| 5 | 06 local reentrancy (no fork) | hunter1 | [`BjQFGwWQ…`](https://testnet.nearblocks.io/txns/BjQFGwWQdWJGaDT1ADcmU1g6fPs8sPKNVuW4DDnYteov) | **needs_human** [`7YK2Lhfq…`](https://testnet.nearblocks.io/txns/7YK2LhfqG8zGWHBGaxrJeGB8XbF8cXWFjGdmwkf939h) | owner `resolve` valid/high [`56yekiAw…`](https://testnet.nearblocks.io/txns/56yekiAwAX55NyVNPKfvudg7NA46ZHmhSqX1pK4BbbRS) | **paid** | 0.25 payout + bond 0.05585 back to hunter1; 0.01 fee from the pool |
| 6 | 02 Seneca `Chamber.performOperations()`, through MCP in vault mode | agent | `submit_report_from_vault` [`98c5qCNu…`](https://testnet.nearblocks.io/txns/98c5qCNuzrKM7F3d2o4TXdNSTsYW7wmj6W3aiK1n5XFy) | **valid / critical**, fork block 19,325,936 [`CZkNUyqE…`](https://testnet.nearblocks.io/txns/CZkNUyqELPKx3zjfcPmPc6M2hTQU3MJ3envRxgSfupEf) | owner `dispute` [`H8x5uNL1…`](https://testnet.nearblocks.io/txns/H8x5uNL1wKdLKCS3ScfPZXMr9VUL2SLb5JfEEv4dYmVx), no `resolve`; `finalize` by hunter3 after `resolve_until` [`6d82aM5X…`](https://testnet.nearblocks.io/txns/6d82aM5XoVGh5gnNkiVxEKcHNTDTYTUBcDNzW5pC8uzA) | **paid** | 0.13461 drawn from the vault (bond 0.05 + storage 0.08461); 0.4 payout + the owner's 0.1 dispute bond to the agent account, bond 0.05 back into the vault; 0.01 fee from the pool |
| 7 | attack a: prompt injection | hunter2 | [`523vugAV…`](https://testnet.nearblocks.io/txns/523vugAVB6FYFD1p6kSp9AeNSwzNTvNY7YJExTmGNuPg) | **invalid** [`BJ9w66rb…`](https://testnet.nearblocks.io/txns/BJ9w66rbY157MU2dgsEX68feFD7x2neJqyAd7D3bomwg) | - | invalid | bond 0.10585 (doubled) slashed: 0.09585 to the pool |
| 8 | attack b: sandbox escape | hunter3 | [`CWWY8XTM…`](https://testnet.nearblocks.io/txns/CWWY8XTMa2DHVFKdWKtSZskjD8yKxzP6d2Q5qDJmyi2i) | **invalid** [`8bpKNEdr…`](https://testnet.nearblocks.io/txns/8bpKNEdryEWZTP6GeYLzWaqNj8pE7tcYq1sQC2Lpje9E) | - | invalid | bond 0.10585 (doubled) slashed: 0.09585 to the pool |
| 9 | attack c: tampered seal | hunter2 | [`22T8dYze…`](https://testnet.nearblocks.io/txns/22T8dYzewhG2k7mCduswq1d5LteMDELy6SRYFtMG4A6L) | **invalid**: "sealed report does not match commitment" (engine not run) [`5AsP17ye…`](https://testnet.nearblocks.io/txns/5AsP17yeSjjiLdRtAMBfvQbDaHBqmgrz2q2j753ERrae) | - | invalid | bond 0.10585 (doubled) slashed: 0.09585 to the pool |
| 10 | attack e: copy of hunter1's failed transaction | thief | [`DxcggVbp…`](https://testnet.nearblocks.io/txns/DxcggVbpsgTkk4QjDZFmQ43BYf43LhWoFLcb5YkSDaBA) | **invalid**: "sealed report does not match commitment" (engine not run) [`BJumAuZS…`](https://testnet.nearblocks.io/txns/BJumAuZS1E4FE5dRGtAHZbtWEv9sTMei21Vk97MAe2iV) | - | invalid | bond 0.05323 slashed: 0.04323 to the pool |
| 11 | target of attack d, **program 1** | hunter1 | [`ETv6zQaM…`](https://testnet.nearblocks.io/txns/ETv6zQaMTkhUcEeVTYp513xuTQack8tA1r87S1F7smiy) | none: its verifier never ran | `withdraw_pending` after 60 s [`8DJu4uBE…`](https://testnet.nearblocks.io/txns/8DJu4uBE8mZ8UdhQE9wcgX3mNRDS3Jq7UkpYBNVQsTBr) | withdrawn | bond 0.05449 refunded; pool withdrawn by the owner [`DFqmHmca…`](https://testnet.nearblocks.io/txns/DFqmHmcazgSXrJuD37HZb9kTkvaygQhn8xfVgbZzNRbN) |

**The pool adds up.** 2.99438 at the start, minus 1.05 paid out and 0.03 in fees on paid reports,
plus 0.46569 slashed into it, is the final 2.38007, read back with `get_program(0)`.

**Bonds follow the hunter's record in this program.** hunter2 and hunter3 paid double for the attack
reports, once their invalid reports counted. hunter1 paid half (0.025) once a report was paid, as the refused
deposit in attack e shows.

## What the run shows

- **A failed first try does not block the real report (S1).** #0 and #1 are the same bug. #0 came
  first and failed. The engine's duplicate check on #1 lists `sub-0` with text similarity 1.00 and
  code similarity 0.976, level `duplicate`, but `"eligible": false`, because `sub-0` is invalid
  on-chain and only a valid, paid or disputed report can be an original
  ([`1/verdict.json`](../runs/testnet/contract.replaycourt.testnet/1/verdict.json)). #2, reworded
  and rebuilt (text 0.02, code 0.39, fingerprint 1.00), is a duplicate of #1, not of #0.
- **Disclosure after settlement.** The worker ran with `--disclose after-settlement`, so all
  evidence stayed in `runs-private/` until everything was final. Only then did `publish` move it to
  `runs/` ([log](logs/showcase-publish-verify.txt)).
- **A scripted agent earned a bounty inside an on-chain policy.** See below and
  [`../mcp/DEMO.md`](../mcp/DEMO.md).
- **An owner who disputes and then does nothing pays for it.** See below.

## The dispute and the auto-payout (#6)

| time (UTC) | step | result |
|---|---|---|
| 20:50:46 | the agent submits report 02 from its vault through MCP | vault balance 0.49596 -> 0.36135 |
| 20:51:07 | the worker posts `valid`, critical | window until 20:53:07 |
| 20:51:11 | the owner disputes with the 0.1 NEAR dispute bond [`H8x5uNL1…`](https://testnet.nearblocks.io/txns/H8x5uNL1wKdLKCS3ScfPZXMr9VUL2SLb5JfEEv4dYmVx) | status `disputed`, `resolve_until` 20:54:11, owner balance 0.99888 -> 0.89862 |
| before 20:54:11 | `finalize` by hunter3 | refused by the contract: `resolve deadline has not passed yet` |
| 20:54:11 | the owner has not resolved | nothing happens on its own: someone has to call `finalize` |
| after 20:54:11 | `finalize` by hunter3 [`6d82aM5X…`](https://testnet.nearblocks.io/txns/6d82aM5XoVGh5gnNkiVxEKcHNTDTYTUBcDNzW5pC8uzA) | status `paid`; events `report_paid` (payout 0.4, `dispute_bond_to: "hunter"`, dispute bond 0.1), `bond_refunded` (0.05, `to: "vault"`) |

Agent account: 0.49832 -> 0.99832, exactly +0.5 NEAR (payout 0.4 + dispute bond 0.1). Vault:
0.36135 -> 0.41135, the 0.05 bond. The owner's 0.1 NEAR is gone, and `stats.disputes` is 1 for
everyone to see. Screenshot: [`../docs/screenshots/submission-disputed.png`](../docs/screenshots/submission-disputed.png).

## Accounts and programs

Both top-level accounts came from the testnet faucet. `replaycourt-bank.testnet`
([`3mQaTLzP…`](https://testnet.nearblocks.io/txns/3mQaTLzPTQ146nU1WEAuxb52xjEUejcxhmS7xvT41iqg)) sent 9.8 NEAR
([`8AxtkP8o…`](https://testnet.nearblocks.io/txns/8AxtkP8o98UjuwqjxaSVKRpSUDgxjfk1hqwPQQ4LNSF)) to `replaycourt.testnet`
([`AfgsptcC…`](https://testnet.nearblocks.io/txns/AfgsptcC3XVKc2WirT4rQNhmiprfmDq9vntHPzEEjmKC)).

| step | tx |
|---|---|
| create `contract.` (3.5 NEAR) | [`3A1NiCT8…`](https://testnet.nearblocks.io/txns/3A1NiCT83AqVCdYXn9mXCytjC5X2KAu4zCkCVuVpdCFH) |
| create `owner.` (5) / `verifier.` (0.3) | [`HRZhNvZn…`](https://testnet.nearblocks.io/txns/HRZhNvZn5a6LNnTDg9NKeRfHKrMsgNDrKR86LXLhyyyy) / [`FocmB8Xe…`](https://testnet.nearblocks.io/txns/FocmB8Xejfan8dU6sAYDYpcLgr1WCRyvYK5vxd12tEuo) |
| create `hunter1.` / `hunter2.` / `hunter3.` (1 each) | [`9ZehAJ8k…`](https://testnet.nearblocks.io/txns/9ZehAJ8k175Y97JzcA3NT4d3GiCbU2xyH2Qhs9LvTzun) / [`6jBDizQi…`](https://testnet.nearblocks.io/txns/6jBDizQi3GWGkpHevu3fNpTKbnAwRhUP31VBvM2o3V6z) / [`BiM31ZPH…`](https://testnet.nearblocks.io/txns/BiM31ZPHxaWc8VD3wD2Gp7SNFR6J61SDPsJ6kqYLe9NX) |
| create `verifier2.` (0.2) / `agent.` (1) / `thief.` (0.5) | [`HrqpqE3z…`](https://testnet.nearblocks.io/txns/HrqpqE3z125MT75HVvWRKcR4QW4ztxZgX8VjrjmsLtC7) / [`EJYrHwR9…`](https://testnet.nearblocks.io/txns/EJYrHwR9DrTsogdWYZuKF16gwje9jdFdJUWVr2jFymu6) / [`3hfQs68V…`](https://testnet.nearblocks.io/txns/3hfQs68VdrPW974JEfBUU6wvdpYGGHpNpGEPxMD35abD) |
| deploy + `new(owner_id=replaycourt.testnet)` | [`8bfgJqjs…`](https://testnet.nearblocks.io/txns/8bfgJqjsqZFaTVt6sKYmCd4HoDWuJakp1YsDeTrosFie) |
| `create_program` -> program 0 | [`24fSxW7C…`](https://testnet.nearblocks.io/txns/24fSxW7Cf1WaaWND4sLcCSMKrHDcsnCLNzs62PaN5Z2w) |
| add the verifier's function-call key (full-access key, once) | [`J5EdUBaL…`](https://testnet.nearblocks.io/txns/J5EdUBaLU5B37dWu6FQgWzuYUTLErDLFnMD4eXAq7eP4) |
| `create_program` -> program 1 (attack d) | [`AhY8oTfS…`](https://testnet.nearblocks.io/txns/AhY8oTfSxdpSjBPb1MzyVsfXRUHqxq5cP4M5b7qNHnzu) |
| agent: `vault_deposit` 0.5 / `vault_set_policy` / add the function-call key | [`8XjFmKba…`](https://testnet.nearblocks.io/txns/8XjFmKbaszoXdDMExdRYy5NaTCazc7Xzr9iagqtEagTs) / [`FRwKEG1E…`](https://testnet.nearblocks.io/txns/FRwKEG1EyPFX97xrAw8WUT24kGfeXvjn3MNsgFTYeocw) / [`6eyXmmy3…`](https://testnet.nearblocks.io/txns/6eyXmmy3ho7nJiQFaBv3YnJME4Fjz7uP4uvMPNaA3E5W) |

## Commands

```sh
cd contract
./build.sh --check                              # privacy-checked build, sha256 = WASM_SHA256
NETWORK_CONFIG=testnet-fastnear RPC=https://test.rpc.fastnear.com HUNTERS=3 \
  EXTRA="verifier2=0.2 NEAR,agent=1 NEAR,thief=0.5 NEAR" \
  FUND_CONTRACT="3.5 NEAR" FUND_OWNER="5 NEAR" FUND_VERIFIER="0.3 NEAR" FUND_HUNTER="1 NEAR" \
  HANDOFF=../.secrets/showcase-v2.json HANDOFF_RPC=https://test.rpc.fastnear.com HANDOFF_SECRETS_DIR=showcase-v2 \
  scripts/setup-testnet.sh replaycourt.testnet
```

`.secrets/showcase-v2.json` holds account ids only, and the verifier's keys stay in
`.secrets/showcase-v2/`. The flow, from `agent/`, with `REPLAYCOURT_CONFIG` pointing at that file and
`REPLAYCOURT_WORKER_PROGRAMS=0`:

```sh
node src/cli.ts keygen
node src/cli.ts create-program --name "Ethereum DeFi replay bounty" --pool 3 --bond 0.05 --verifier-fee 0.01 \
  --dispute-bond 0.1 --payouts 0.4,0.25,0.15,0.05 --challenge 120 --pending-timeout 86400 --resolve-timeout 180 \
  --scope 1:0xd2869042E12a3506100af1D192b5b04D65137941,1:0x65c210c59B43EB68112b7a4f75C8393C36491F06
node src/cli.ts setup-verifier-key --allowance 1
node src/cli.ts submit --program 0 --report ../demo/v2/s1-first-try.md --as hunter2
node src/cli.ts submit --program 0 --report ../engine/reports/01_templedao_stax.md --as hunter1
node src/cli.ts submit --program 0 --report ../engine/reports/03_stax_duplicate.md --as hunter3
node src/cli.ts submit --program 0 --report ../engine/reports/04_seneca_bogus.md --as hunter2
node src/cli.ts submit --program 0 --report ../engine/reports/05_fake_profit.md --as hunter3
node src/cli.ts submit --program 0 --report ../engine/reports/06_local_reentrancy.md --as hunter1
node src/cli.ts worker --once --disclose after-settlement
node src/cli.ts resolve 5 --outcome valid --severity high --note "Owner review: the bundled Vault matches the audited code; reentrancy accepted as high."
node src/cli.ts finalize 1 --as hunter3         # after the 120 s window; anyone may call

node src/cli.ts vault-deposit --amount 0.5 --as agent
node src/cli.ts vault-set-policy --max-bond 0.1 --max-per-day 0.3 --programs 0 --as agent
node src/cli.ts setup-hunter-key --as agent
(cd ../mcp && node demo/client-demo.ts --config ../.secrets/showcase-v2.json --hunter agent \
  --policy demo/policy.vault-showcase.json --report 02_seneca_chamber.md --exact \
  --title "Seneca Chamber.performOperations() executes arbitrary calls - theft of approved tokens" --verify-seal)
node src/cli.ts worker --once --disclose after-settlement
node src/cli.ts dispute 6 --reason "Owner disputes the Seneca verdict and asks for a second look. Dispute demo: the owner posts the dispute bond and then does not resolve."
node src/cli.ts finalize 6 --as hunter3         # after resolve_until (180 s)

# the attacks: see ATTACKS.md
node src/cli.ts publish
node src/cli.ts verify-onchain
```

## Checks

- **Function-call key only.** Every `post_verdict` above is signed by
  `ed25519:2soJjd3yo41ae17wgrNpZVeykFHuwiDWBGUPRJrD5L3D`. The worker refuses to start unless that
  key's on-chain permission is `FunctionCall` with receiver `contract.replaycourt.testnet` and
  `method_names = ["post_verdict"]`.
- **Evidence.** `verify-onchain` recomputes the sha256 of every verdict's `evidence.json` in this
  repository, compares it with the on-chain `evidence_sha256`, and checks that the envelope names
  this contract, program, submission, hunter and commitment: 11 posted verdicts, 11 ok, 0 unbound.
  #11 has no verdict. The explorer does the same in the browser
  ([`../docs/screenshots/submission.png`](../docs/screenshots/submission.png)).
- **The wasm has no local path.** `contract/build.sh --check` passed, and the code read back from
  the chain has the same sha256 and no `/Users/` or `/home/`.
- **Same outcomes as the offline engine run** (`demo/engine-replay.sh`): 01 valid, 02 valid, 03
  duplicate of 01, 04 invalid, 05 invalid, 06 needs human, and the attack reports invalid.

## Final state

From `get_program`, `get_hunter` and `view_account` after the run:

```
program 0 "Ethereum DeFi replay bounty"  owner owner.replaycourt.testnet  verifier verifier.replaycourt.testnet  active
  pool 2.38007 NEAR, reserved 0, bond 0.05, dispute bond 0.1, fee 0.01, challenge 120 s, resolve 180 s, pending 24 h
  stats {"submissions":11,"paid":3,"invalid":7,"duplicate":1,"needs_human":1,"disputes":1,"overruled":0,"total_paid":"1050000000000000000000000"}
program 1 "Attack demo d: program judged by another verifier"  verifier verifier2.replaycourt.testnet  pool 0
  stats {"submissions":1,"paid":0,"invalid":0,"duplicate":0,"needs_human":0,"disputes":0,"overruled":0,"total_paid":"0"}

hunter reputation (global):
  hunter1: submissions 3, valid 2, invalid 0, duplicate 0, needs_human 1, earned 0.65 NEAR
  agent:   submissions 1, valid 1, invalid 0, duplicate 0, needs_human 0, earned 0.4 NEAR
  hunter2: submissions 4, valid 0, invalid 4, duplicate 0, needs_human 0, earned 0 NEAR
  hunter3: submissions 3, valid 0, invalid 2, duplicate 1, needs_human 0, earned 0 NEAR
  thief:   submissions 1, valid 0, invalid 1, duplicate 0, needs_human 0, earned 0 NEAR

agent vault: balance 0.41135 NEAR, policy max bond 0.1, max 0.3 per 24 h, programs [0], spent in window 0.13461
```

The verifier's balance rose from 0.3 to about 0.40 NEAR: 0.11 in fees (8 verdicts paid from bonds,
3 paid reports) minus the gas of its transactions.

## What this run found

Running the full flow on v2 turned up two bugs. Both are fixed, and both were invisible in the
earlier v2 runs, which did not use the reports involved.

- **Verdict reasons over the byte limit.** The worker cut the reason to 280 *characters* and added
  a 3-byte `…`. The v2 contract counts bytes, so any long reason was refused with `reason must be at
  most 280 bytes`. That hit #5 (report 06), whose reason is long. The worker behaved as designed: it
  posted nothing, slashed nobody, logged the error, and left the report for a retry
  ([log](logs/showcase-worker.txt)). The fix (`truncateBytes` in `agent/src/mapping.ts`, with tests)
  came before the second round, which posted #5 (exit 0).
- **Path C's contract funding.** `demo/testnet-setup.ts` funded the contract with 3 NEAR, too little
  for the 295 KB v2 wasm (`LackBalanceForState`). It now funds 3.2 NEAR, and so does the default of
  `contract/scripts/setup-testnet.sh`. See [`README.md`](README.md), path C.

Bonds differ between reports because the contract keeps `deposit - storage` as bond and adjusts the
required bond to the hunter's record in the program.

## Contract locked

After the run, the contract account's only access key was removed in tx
[`3Gt1BkmxVVBd32K5H6i8cUup6Fvg1zgYWghBTEhchecr`](https://testnet.nearblocks.io/txns/3Gt1BkmxVVBd32K5H6i8cUup6Fvg1zgYWghBTEhchecr).
`contract.replaycourt.testnet` has no keys now, so nobody can replace its code. Check it with a
`view_access_key_list` RPC query: the list is empty.

