# ReplayCourt demo: three ways to check it

| path | what you check | needs | time |
|---|---|---|---|
| **A** | the showcase on NEAR testnet: every verdict on chain matches an evidence file in this repository | Node >= 24 + npm; no account, no keys | 1 min |
| **B** | the engine's verdicts on your machine: replay the demo reports (and the attack reports) on a fork of Ethereum | Python >= 3.8, Foundry (`forge`), internet | 3-6 min |
| **C** | everything on your own testnet deployment: faucet accounts, your own contract, sealed reports, the worker with a function-call key, settlement, attacks c and d | A + B, internet (testnet faucet) | 4-15 min |

All commands run from the repository root unless stated otherwise. Testnet only; nothing here
touches mainnet or costs real money.

The showcase deployment is described in [`SHOWCASE.md`](SHOWCASE.md), the attack demos in
[`ATTACKS.md`](ATTACKS.md).

## A. Read-only check of the showcase (no keys)

```sh
cd agent
npm ci
npm run cli -- verify-onchain
```

Expected (run in a fresh copy without `.secrets/`, 2026-11-02):

```
verify-onchain: contract contract.replaycourt.testnet (testnet), version 2.0.0: evidence must be a replaycourt.evidence/v1 envelope bound to its submission
evidence files: below runs/ in the repository; pinned showcase programs 0, 1 (--all-programs checks every program)

program 0 "Ethereum DeFi replay bounty": 11 submission(s)
  id   status     outcome                       severity      payout (NEAR)  evidence
  ---  ---------  ----------------------------  ------------  -------------  --------
  #0   invalid    invalid                       -             -              ok
  #1   paid       valid                         critical      0.4            ok
  #2   duplicate  duplicate of #1               -             -              ok
  #3   invalid    invalid                       -             -              ok
  #4   invalid    invalid                       -             -              ok
  #5   paid       needs_human -> valid (owner)  high (owner)  0.25           ok
  #6   paid       valid                         critical      0.4            ok
  #7   invalid    invalid                       -             -              ok
  #8   invalid    invalid                       -             -              ok
  #9   invalid    invalid                       -             -              ok
  #10  invalid    invalid                       -             -              ok

program 1 "Attack demo d: program judged by another verifier": 1 submission(s)
  id   status     outcome  severity  payout (NEAR)  evidence
  ---  ---------  -------  --------  -------------  --------------
  #11  withdrawn  -        -         -              - (no verdict)

11 posted verdict(s) checked: 11 ok, 0 mismatch, 0 unbound, 0 refused, 0 missing, 0 not disclosed yet; 1 submission(s) without a verdict
result: every posted verdict matches its evidence file
```

The exit code is 0 only if every posted verdict matches. For each submission the command reads
the verdict with `list_submissions` and loads the file named by `evidence_uri`, which must be a
path below `runs/` (here `runs/testnet/contract.replaycourt.testnet/<id>/evidence.json`). It then
recomputes that file's sha256 and compares it with the on-chain `evidence_sha256`. Lines like
`TypeError: fetch failed` on stderr come from near-api-js switching RPC endpoints; they are not
failures.

The showcase contract is v2, so its evidence is an `evidence.json` envelope, and the command also
checks that it names the contract, program, submission, hunter and commitment it was posted for
(see [`../agent/README.md`](../agent/README.md)).

By default only the **pinned showcase programs** are checked (`SHOWCASE_PROGRAMS` in
`agent/src/config.ts`). Anyone can create a program on a public contract; such programs are
listed as "not part of the showcase" and do not fail the run. `--all-programs` checks every
program, `--program <id>` one.

Without `.secrets/` the command checks the showcase contract `contract.replaycourt.testnet`.
Other deployments:

- `--contract <your contract>` checks your own deployment from path C. A contract without pinned
  programs has all its programs checked.

To see the same in a browser, start a static server and open the explorer. The verdict page
recomputes the evidence hash in the browser.

```sh
python3 -m http.server 8000 --bind 127.0.0.1
# open http://127.0.0.1:8000/web/    (another deployment: http://127.0.0.1:8000/web/?contract=<account>)
```

## B. Replay the reports with the engine (no NEAR needed)

Needs Python >= 3.8 (standard library only) and Foundry
(`curl -L https://foundry.paradigm.xyz | bash && foundryup`). forge is found on `PATH`, in
`~/.foundry/bin/` or through `REPLAYCOURT_FORGE`. The fork uses a free public Ethereum archive RPC
from `engine/config/chains.json`.

```sh
demo/engine-replay.sh          # reports 01-06 in commit order, fresh duplicate registry
demo/engine-replay.sh --all    # plus the attack reports a/b and the engine probes
```

Expected (the 01-06 rows; `--all` adds 11 more):

```
report                                                  exit  outcome      expected     result
01_templedao_stax                                       0     valid        valid        ok
02_seneca_chamber                                       0     valid        valid        ok
03_stax_duplicate                                       3     duplicate of 01-templedao-stax duplicate of 01-templedao-stax ok
04_seneca_bogus                                         1     invalid      invalid      ok
05_fake_profit                                          1     invalid      invalid      ok
06_local_reentrancy                                     2     needs_human  needs_human  ok
...
ALL OUTCOMES AS EXPECTED
```

The script writes only to a temporary directory and prints its path. Each report's folder holds
`verdict.json`, `summary.md` and the raw forge trace. The full `--all` run of 2026-11-02 is in
[`attacks/logs/engine-replay-all.txt`](attacks/logs/engine-replay-all.txt). Free archive RPCs
sometimes fail. The engine then exits 69 ("infrastructure, no verdict") and the script retries
that report twice. A single report runs with
`python3 -I engine/replay.py check engine/reports/01_templedao_stax.md` (see
[`../engine/README.md`](../engine/README.md)).

## C. The whole flow on your own testnet deployment

```sh
demo/full-testnet.sh                      # random account name rc-judge-<hex>.testnet
demo/full-testnet.sh myname.testnet       # or a name of your choice (must not exist yet)
```

Needs Node >= 24, Python >= 3.8, forge and internet. Your Rust toolchain is not needed: the
script deploys `contract/target/near/replaycourt.wasm` if you built it, and otherwise the code of
the showcase contract, read over RPC. In both cases it checks that the sha256 is the pinned build
hash `456631c5…` (contract v2.0.0, `contract/WASM_SHA256`). Steps (every wait is bounded; on
failure, run the same command again and it continues where it stopped):

1. `<name>.testnet` from the testnet faucet (10 NEAR). Then the sub-accounts `contract.`,
   `owner.`, `verifier.`, `verifier2.`, `hunter1.` and `hunter2.<name>.testnet`, and your copy of
   the contract (`deploy` + `new`). Keys stay in `.secrets/<name>/credentials/` (git-ignored); the
   account ids go to `.secrets/<name>.json`.
2. The verifier's X25519 key (`keygen`), a program (1.5 NEAR pool, 60 s challenge window) and the
   verifier's function-call key (`post_verdict` only, 0.5 NEAR allowance).
3. Sealed submissions by two hunters: 01 (valid), 03 (duplicate of 01), 04 (invalid), 06 (needs a
   human), and attack c (the sealed blob is not the committed text).
4. `worker --once --disclose immediately` (the demo reports re-enact public incidents), serving only
   this program (`REPLAYCOURT_WORKER_PROGRAMS`): decrypt, check the commitment, replay with the
   engine, and post every verdict with the function-call key.
5. `finalize` of 01 after the challenge window; the owner resolves 06.
6. Attack d: a second program with another verifier, then all 11 stolen-key attempts. Each must
   fail.
7. The target report of attack d is withdrawn after its pending timeout, and program 2's pool is
   withdrawn.
8. `verify-onchain --contract <your contract> --all-programs` (must print `every posted verdict
   matches`) and `status`.

The script ends with `FULL TESTNET RUN PASSED` and prints your contract's explorer link. Run
`demo/full-testnet.sh` again with no argument to continue the last run; the run log is in
`.secrets/<name>/full-testnet.log`. Faucet accounts are free testnet accounts and can be left
alone afterwards.

Runs on contract v2 (2026-11-02), each with a fresh faucet account:

| account | invocations | what happened |
|---|---|---|
| `rc-judge-78f4f39c.testnet` | 1, stopped | the deploy failed with `LackBalanceForState`: 3 NEAR was too little for the v2 wasm. Fixed: the contract account now gets 3.2 NEAR |
| `rc-judge-8807c00f.testnet` | 1, passed | its first worker round hit the byte-limit bug in verdict reasons (`SHOWCASE.md`, "What this run found"). The fix landed while it ran, and the script's own retry loop posted the rest |
| `rc-judge-6610194e.testnet` | 1, passed | **the clean run**, after both fixes: a fresh copy with no `.secrets/` and no Rust build, so the wasm was read over RPC from the showcase contract and matched the pinned hash. No retry, about 4 minutes. Output: [`logs/full-testnet-rc-judge-6610194e.txt`](logs/full-testnet-rc-judge-6610194e.txt) |

Every passed run: 01 valid and paid after the window, 03 duplicate of 01, 04 invalid, 06
needs_human and resolved by the owner, attack c invalid ("sealed report does not match commitment"),
attack d 11 of 11 attempts refused, and `verify-onchain` 5 of 5 ok. The evidence folders of these
runs (`runs/testnet/contract.rc-judge-*/`) are git-ignored, because every judge creates their own.

## Files

| file | what |
|---|---|
| `engine-replay.sh` | path B |
| `full-testnet.sh` | path C (calls `testnet-setup.ts` and the agent CLI) |
| `testnet-setup.ts` | faucet account, sub-accounts, deploy + init, deployment file, without near-cli |
| `attacks/` | attack reports a and b, scripts c to f, engine probes, logs (`ATTACKS.md`) |
| `SHOWCASE.md` | the showcase deployment: commands, transactions, final state |
| `logs/` | output of the showcase run (setup, submissions, worker, settlement, publish and verify), the MCP demo, and the clean path C run |

The TypeScript files import `../agent/src/` and its `near-api-js`, so run `npm ci` in `agent/`
first (`full-testnet.sh` does that). They are type-checked by `cd agent && npm run typecheck`.
