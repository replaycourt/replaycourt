# ReplayCourt agent - hunter CLI and verifier worker (TypeScript, Node 24)

Off-chain half of ReplayCourt on NEAR (interface: [`../SPEC.md`](../SPEC.md), v2):

- **Hunters** seal a bug report (Markdown + Foundry PoC) to the program's verifier key and commit
  it to the ReplayCourt contract with a bond (`submit`). The commitment is bound to the submitting
  account, so a copied sealed blob is worthless from another account.
- **Hunter agents** can submit from a pre-funded **vault** inside the contract with a
  function-call key, within an on-chain spending policy (`vault-*`, `setup-hunter-key`,
  `submit --from-vault`).
- The **verifier worker** serves an allow-list of programs. It reads their pending submissions,
  decrypts them, checks the commitment and replays the PoC with the engine (`../engine/`, fork of
  the real chain). It then posts the verdict with `post_verdict`, signed by a **function-call
  access key that can call nothing else** (`worker`, `setup-verifier-key`). The evidence file
  binds the engine's verdict to the submission. It stays private until the submission is
  settled (`publish`).
- `verify-onchain` lets anyone check every posted verdict against the evidence in this repository.
- Thin wrappers for the demo: `create-program`, `finalize`, `dispute`, `resolve`, `status`.

The public showcase run on testnet is in [`../demo/SHOWCASE.md`](../demo/SHOWCASE.md); the attack
demos (including a stolen worker key) in [`../demo/ATTACKS.md`](../demo/ATTACKS.md).

Node 24 runs the TypeScript sources directly (built-in type stripping); there is no build step.

## Install and test

Requirements: Node >= 24 (tested 24.22.1). The worker additionally needs Python >= 3.8 and Foundry
(`forge`) for the engine - see `../engine/README.md`.

```bash
cd agent
npm ci                  # near-api-js 7.4.0 (+ typescript, @types/node for the type check)
npm test                # node:test, 96 tests, no network
npm run typecheck       # tsc --noEmit
node src/cli.ts --help  # list of commands; node src/cli.ts <command> --help for each
```

`npm test` covers the following, with the chain, the engine and the evidence files mocked:

- **Sealing:** seal/unseal round trip and the key derivation against an independent HKDF
  implementation. Tampering (ct/tag/iv/epk), a wrong key or version and garbage are detected.
- **Commitment v2:** checked against an independent implementation and a fixed vector. A sealed
  blob plus commitment copied to another account is judged invalid. v1 commitments are refused.
- **Worker:** the decision for every engine outcome:
  - valid, invalid, needs_human, duplicate, and a duplicate of a later id;
  - a duplicate whose original is no longer valid on-chain;
  - exit 69/70/64/65 and the memory/time cap;
  - commitment mismatch, a report sealed to another key, already judged;
  - the function-call key's allowance used up.
- **Worker v2:** the `evidence.json` envelope, both disclosure modes and the program allow-list
  (and its absence). The on-chain statuses are passed to the engine, and updated within a round.
  The engine runs with `TZ=UTC` behind a configured wrapper, and its own time limit applies.
- **`publish`:** settled evidence moves to `runs/`. A duplicate, or an invalid first try,
  waits for the related open report. Public evidence is never overwritten.
- **`verify-onchain`:**
  - hash, binding fields and v1 evidence mode;
  - only paths below `runs/`, also through symlinks;
  - undisclosed and held-back evidence;
  - pinned showcase programs and `--all-programs`;
  - paging.
- **CLI actions:** `create-program` (dispute bond, resolve timeout), `dispute` (attaches the
  dispute bond), `vault-deposit`/`-set-policy`/`-withdraw` (1 yoctoNEAR), `vault-status`,
  `setup-hunter-key` (exactly the three methods) and `submit` / `submit --from-vault`, including
  the refusals before signing.
- **Other:** the deployment file and the worker allow-list, the attack-demo helpers, and the
  testnet setup helpers.

`npm run typecheck` also checks the TypeScript in `../demo/`.

## Verify the on-chain verdicts (read-only, no keys)

Anyone with a clone can check that every verdict on the contract points at evidence that is in this
repository, byte for byte, and bound to its submission. No account, key or `.secrets/` file is
needed; without `.secrets/` the command uses the public showcase deployment
`contract.replaycourt.testnet` (`DEMO_CONTRACT` in `src/config.ts`).

```bash
cd agent
npm ci
npm run cli -- verify-onchain
```

For every submission it does the following:
- reads the on-chain verdict (`list_submissions`);
- loads the file named by `evidence_uri`. Only paths below `runs/` are accepted; anything else
  is `refused`, and so is a symlink that leaves `runs/`;
- recomputes the file's sha256 and compares it with the on-chain `evidence_sha256`.

**Evidence v2** (contracts from version 2.0.0) is the envelope `replaycourt.evidence/v1` written by
the worker (SPEC "Evidence"). Its `network`, `contract_id`, `program_id`, `submission_id`,
`hunter_id` and `commitment` must equal the on-chain submission. Otherwise the row is `unbound`:
evidence of another submission with a matching hash is caught. **v1 evidence** (the engine's
`verdict.json` without an envelope) is accepted only from contracts older than 2.0.0, as
"ok (v1 evidence)" with the hash checked. The showcase runs v2, so all its rows are checked as
bound envelopes.

Evidence that is not in `runs/` yet is fine while the submission is not final (`private (not
final)`), or while `publish` holds it back because a related submission is still open
(`private (held back)`, listed in `runs/<network>/<contract>/disclosure.json`). The command exits
**0 only if every posted verdict is ok or not disclosed yet**, and 1 on any `mismatch`, `unbound`,
`refused` or `missing`.

**Which programs.** Anyone can create a program on a public contract. By default the command checks
only the **pinned showcase programs** (`SHOWCASE_PROGRAMS` in `src/config.ts`: contract and program
ids per network; update them after a redeploy). Other programs on the same contract are listed as
"not part of the showcase" and do not fail the run. `--all-programs` checks every program,
`--program <id>` exactly one. A contract without pinned programs has all its programs checked.

Options: `--contract <account>` (another deployment), `--rpc <url,url>` (endpoints; default
`https://test.rpc.fastnear.com,https://near-testnet.drpc.org`, also `REPLAYCOURT_RPC_URL`),
`--verbose` (print both hashes for matching rows too).

## Configuration

Values come from environment variables, otherwise from `.secrets/<network>.json` in the repository
(written when the contract is deployed; git-ignored) or the file named by `REPLAYCOURT_CONFIG`:

```jsonc
{ "network": "testnet", "contract_id": "...", "owner_id": "...", "verifier_id": "...",
  "hunter1_id": "...", "hunter2_id": "...", "rpc_url": "https://test.rpc.fastnear.com",
  "secrets_dir": "showcase-v2",               // optional: verifier keys of this deployment, relative to the file
  "credentials_dir": "showcase-v2/credentials", // optional: full-access keys, instead of ~/.near-credentials/<network>/
  "programs": [0, 2] }                     // optional: the worker's program allow-list
```

Every `<role>_id` becomes a role for `--as` (`hunter3_id` -> `hunter3`, `verifier2_id` ->
`verifier2`). `secrets_dir` lets several deployments live side by side: the showcase uses
`REPLAYCOURT_CONFIG=.secrets/showcase-v2.json` with its keys in `.secrets/showcase-v2/`. A relative
`REPLAYCOURT_CONFIG` is looked up from the current directory, then from the repository root, so the
same value works from the root and from `agent/`.

| Variable | Meaning |
|---|---|
| `REPLAYCOURT_NETWORK` | `testnet` (default). Mainnet is refused unless `REPLAYCOURT_ALLOW_MAINNET=1`. |
| `REPLAYCOURT_CONTRACT_ID` | ReplayCourt contract account |
| `REPLAYCOURT_RPC_URL` | RPC URL(s), comma-separated (default `https://test.rpc.fastnear.com,https://near-testnet.drpc.org`) |
| `REPLAYCOURT_OWNER_ID`, `REPLAYCOURT_VERIFIER_ID`, `REPLAYCOURT_HUNTER1_ID`, ... | account for a role |
| `REPLAYCOURT_SECRETS_DIR` | default `.secrets/` in the repository, or `secrets_dir` of the JSON file |
| `REPLAYCOURT_CREDENTIALS_DIR` | full-access keys; default `credentials_dir` of the JSON file, else `~/.near-credentials/<network>` |
| `REPLAYCOURT_CONFIG` | path of the JSON file above |
| `REPLAYCOURT_WORKER_PROGRAMS` | the worker's program allow-list, e.g. `0,2` (wins over `"programs"` in the JSON file) |
| `REPLAYCOURT_ENGINE_WRAPPER` | optional command prefix for every engine run, e.g. a memory/time cap (`<cap-tool> --limit 4G --timeout 30m --`); split at whitespace, no shell quoting; default: none |
| `REPLAYCOURT_FORGE`, `REPLAYCOURT_PYTHON` | the forge binary for the engine (default: `PATH`, then `~/.foundry/bin/forge`), the Python interpreter (default `python3`) |

When an RPC endpoint fails, near-api-js' `FailoverRpcProvider` prints the error
(`TypeError: fetch failed ...`) to stderr and continues with the next endpoint; that output is
noise, not a failure. `rpc.testnet.near.org` is heavily rate-limited; prefer the defaults. If every
endpoint fails (`Exceeded 2 providers`), a transaction may or may not have landed: check with
`status` before you repeat it.

Full-access keys are read from `~/.near-credentials/<network>/<account>.json` (the near-cli
format). `--as <role|account>` picks the signer (`owner`, `verifier`, `hunter1`, `hunter2`, or an
account id).

Files the agent writes into the secrets directory (mode 600):
- `verifier-x25519.json`: the verifier's decryption key;
- `verifier-fc-key.json`: the function-call key the worker signs with;
- `hunter-fc-key.<account>.json`: a hunter's function-call key for the vault.

Evidence goes to `runs-private/<network>/<contract>/<submission_id>/` (git-ignored)
until `publish` moves it to `runs/<network>/<contract>/<submission_id>/`, which is
committed, so that anyone can check the on-chain `evidence_sha256` against it.

## Commands

All commands run from `agent/`.

| Command | What it does |
|---|---|
| `node src/cli.ts keygen` | creates the verifier's X25519 keypair in `.secrets/verifier-x25519.json` and prints the base64 public key (`verifier_pubkey`) |
| `node src/cli.ts create-program --name "Demo" --challenge 60` | `create_program` as `owner` with the key from `keygen`. Defaults: pool 3 NEAR, bond 0.1, fee 0.01, payouts 0.5/0.3/0.2/0.1 NEAR, `--dispute-bond` = the bond, `--pending-timeout` and `--resolve-timeout` 86,400 s. It refuses what the contract would refuse (dispute bond below the bond, timeouts out of range). Prints the program id |
| `node src/cli.ts setup-verifier-key` | adds an ed25519 **function-call key** (receiver = contract, methods = `post_verdict`, allowance 1 NEAR) to the verifier account, signed once with its full-access key; stores the new private key in `.secrets/verifier-fc-key.json` |
| `node src/cli.ts submit --program 0 --report ../engine/reports/01_templedao_stax.md --as hunter1` | reads `required_bond`, seals, computes the **v2 commitment** for the submitting account and calls `submit_report` with bond + storage. Prints the submission id and tx hash. The contract keeps `deposit - storage` as bond, so the storage estimate is tight (measured formula + 300 bytes; override with `--storage <NEAR>`) |
| `node src/cli.ts worker --once` | judges every pending submission of the served programs once and posts the verdicts (without `--once`: polls every `--interval` s); `--disclose after-settlement` (default) or `immediately` |
| `node src/cli.ts publish [--dry-run]` | moves the evidence of settled submissions from `runs-private/` to `runs/` (see "Disclosure") |
| `node src/cli.ts finalize <id> [--hunter-key]` | pays a `valid` submission after its challenge window, or a `disputed` one after `resolve_until` (anyone may call; `--hunter-key` signs with the hunter's function-call key) |
| `node src/cli.ts withdraw-pending <id> --as hunter1 [--hunter-key]` | the hunter takes the full bond back from a report that is still pending after the program's pending timeout |
| `node src/cli.ts withdraw-pool --program <id> (--amount <NEAR> \| --all)` | the program owner withdraws the unreserved part of the pool |
| `node src/cli.ts dispute <id> --reason "..."` | the owner disputes a valid verdict inside the window and **attaches the program's dispute bond** (read from the program; `--deposit <NEAR>` to attach more) |
| `node src/cli.ts resolve <id> --outcome valid --severity high --note "..."` | the owner resolves a `needs_human` / `disputed` submission |
| `node src/cli.ts vault-deposit --amount <NEAR> --as hunter1` | funds the hunter's vault (created on first use; its storage comes out of the deposit) |
| `node src/cli.ts vault-set-policy --max-bond <NEAR> --max-per-day <NEAR> (--programs 0,2 \| --any-program) --as hunter1` | sets the vault policy; attaches exactly 1 yoctoNEAR, so only the full-access key can do it |
| `node src/cli.ts vault-withdraw (--amount <NEAR> \| --all) --as hunter1` | withdraws from the vault; 1 yoctoNEAR, full-access key only |
| `node src/cli.ts vault-status [--account <role\|account>] [--json]` | read-only: balance, policy, spending in the current 24 h window |
| `node src/cli.ts setup-hunter-key --as hunter1` | adds a **function-call key** to the hunter account: receiver = contract, methods = `submit_report_from_vault`, `finalize`, `withdraw_pending`, allowance 0.5 NEAR. Stores it in `.secrets/hunter-fc-key.<account>.json` |
| `node src/cli.ts submit --from-vault --program 0 --report r.md --as hunter1` | signs `submit_report_from_vault` with that key: no deposit, the contract draws `required_bond + storage` from the vault. It checks the key's on-chain permission and refuses before signing if the policy would refuse (no policy, program not allowed, bond above the cap, daily cap, balance) |
| `node src/cli.ts status [--program <id>] [--json]` | programs, submissions with verdicts, payouts and slashed bonds, hunter reputation, account balances |
| `node src/cli.ts verify-onchain [--program <id> \| --all-programs]` (or `npm run cli -- verify-onchain ...`) | read-only, no keys: checks each verdict's evidence (see above); exit 0 only if all match |
| `node src/cli.ts seal --report r.md --program 0 --as hunter1 --out r.sealed` / `unseal --submission <id>` | the sealing step on its own (debugging) |

## Hunter vault (agent spending policy on-chain)

An AI agent that hunts bounties should not hold a key that can spend the hunter's money. With the
vault (SPEC "Hunter vault"), the hunter does the following with the full-access key:
1. deposits into the vault (`vault-deposit`);
2. sets a policy (`vault-set-policy`): max bond per report, max spend per rolling 24 h, the
   allowed programs;
3. gives the agent a function-call key (`setup-hunter-key`).

The agent's key can call only `submit_report_from_vault`, `finalize` and `withdraw_pending`, and
cannot attach a deposit. It therefore cannot:
- change the policy, or withdraw (both need exactly 1 yoctoNEAR);
- spend outside the policy (the contract checks it on every submission);
- transfer, add keys or call other contracts (the protocol refuses).

Bond refunds of vault submissions go back into the vault. Payouts and dispute bonds go to the
hunter account.

A vault submission reserves about 0.101 NEAR of the key's allowance while the protocol checks the
transaction (100 TGas prepaid, about 6 KB of arguments; measured on testnet), although it burns far
less. A key with a 0.1 NEAR allowance is refused with `NotEnoughAllowance`, so the default is
0.5 NEAR.

## How the worker decides

1. **Programs:** the allow-list (`REPLAYCOURT_WORKER_PROGRAMS` or `"programs"` in the deployment
   file). Every listed program must name this verifier, otherwise it is skipped. Without an
   allow-list the worker serves every program whose `verifier_id` is this verifier, and warns:
   anyone can create a program that names a verifier. For each program,
   `list_pending(program_id, …)` (all pages), oldest id first. A v1 contract has only the global
   `list_pending(verifier_id)`; it is filtered per program.
2. `get_sealed(id)`, decrypt with the X25519 key, then recompute the **v2 commitment** with the
   submission's `hunter_id`:
   `sha256("replaycourt/commit/v2" || 0x00 || hunter_id || 0x00 || report)`. If decryption fails
   or the commitment differs (for example a blob and commitment copied to another account), it
   posts **invalid** with the reason `sealed report does not match commitment` and does not run
   the report.
3. It writes `report.md` and runs the engine with `TZ=UTC`, in its own process group, behind
   `REPLAYCOURT_ENGINE_WRAPPER` if set:
   `[wrapper…] python3 -I engine/replay.py check <dir>/report.md --quiet --registry <root>/registry/program-<program>.jsonl --onchain-status <root>/registry/program-<program>.status.json --report-id sub-<id> --dest <dir>`.
   The worker's own time limit (`--engine-timeout`, default 30 min; 2 min later with a wrapper)
   ends the whole group with exit 124.
   - One duplicate registry per program. Reports are registered as `sub-<id>`, so a duplicate
     names an on-chain submission.
   - The status file holds the on-chain status of each of the program's submissions, updated
     after each verdict of the round. The engine offers only reports that are `valid`, `paid` or
     `disputed` on-chain as originals of a duplicate, the same rule the contract enforces.
     Invalid and needs-human reports never make a later report a duplicate.
4. Map the result:

| Engine exit | Posted outcome | Details |
|---|---|---|
| 0 | `valid` | severity from `severity_hint.level`: critical->critical, high->high, medium->medium, anything lower->low |
| 1 | `invalid` | bond slashed by the contract |
| 2 | `needs_human` | owner must `resolve` |
| 3 | `duplicate` | `duplicate_of` = the `<n>` of `sub-<n>`. It becomes `needs_human` if that is not an earlier id, or if the original is no longer `valid`/`paid`/`disputed` on-chain (re-checked just before posting) |
| 69, 70 | nothing | logged, retried later (69 is retried twice within the round, 20 s apart); later submissions of the same program wait, so duplicates stay in commit order |
| 64, 65, other | nothing | logged, retried later (the worker wrote the file itself, so a hunter is never slashed for a local error) |
| 124, 137 (time/memory cap) | `needs_human` | evidence: a worker verdict inside the envelope |

5. **Evidence:** `evidence.json` next to the engine files (schema `replaycourt.evidence/v1`). It
   holds `network`, `contract_id`, `program_id`, `submission_id`, `hunter_id`, `commitment`, and
   `engine` (the engine's `verdict.json`, or the worker's own verdict when the engine did not
   run). The verdict fields:
   - `evidence_sha256` = the sha256 of the `evidence.json` bytes;
   - `evidence_uri` = `runs/<network>/<contract>/<id>/evidence.json`. That is where the file is
     published, also while it is still private;
   - `fingerprint` = the sha256 of the engine's behaviour fingerprint (canonical JSON);
   - `chain_id`/`fork_block` from the fork (0/0 for local runs);
   - `reason` = the engine's reasons, cut to 280 bytes of UTF-8 (the contract counts bytes).

   The worker re-checks that the submission is still `pending`, then signs `post_verdict` (no
   deposit, 100 TGas).

The worker refuses to start unless the key in `verifier-fc-key.json` is, on-chain, a
function-call key of the verifier account for this contract with exactly
`method_names = ["post_verdict"]`. A leaked worker key can therefore post verdicts, but it cannot
move the verifier's funds, call any other method, or touch any other contract.

## Disclosure

A valid report describes a live bug. Publishing its exploit before the program owner can react
would hurt the program the bounty is meant to protect. So by default (`worker --disclose
after-settlement`):

- The worker writes everything (report, engine output, `evidence.json`) to
  `runs-private/<network>/<contract>/<id>/` (git-ignored). Only the hash is on-chain. The duplicate
  registry and the worker log live there too and are never published.
- `npm run cli -- publish` moves the folder of every **final** submission (paid, invalid,
  duplicate, rejected, expired, withdrawn) to `runs/<network>/<contract>/<id>/`. The posted
  `evidence_uri` points there.
- A final submission is still **held back** while a related submission of the program is open:
  - a duplicate waits for its original;
  - an invalid first try of a bug waits for the later valid report of the same bug (the engine
    listed them as similar).

  Held submissions are listed (ids only) in `runs/<network>/<contract>/disclosure.json`, so
  `verify-onchain` can tell "held back" from "missing". `publish --dry-run` shows the plan.
  Already published evidence is never overwritten.
- `verify-onchain` counts evidence that is not public yet as "private", not as a failure, as long
  as the submission (or the related one) is not final.

`--disclose immediately` writes straight to `runs/`. It is meant for demos whose reports re-enact
historical incidents (`demo/full-testnet.sh` uses it).

## Sealed report format

Node's built-in `crypto` only (SPEC.md):
- the verifier's X25519 key is published on-chain as base64 of the raw 32 bytes;
- the sender uses an ephemeral X25519 key;
- `key = HKDF-SHA256(shared, salt = epk || recipient_pk, info = "replaycourt/v1", 32)`;
- AES-256-GCM with a random 12-byte IV;
- `sealed = base64(JSON {"v":1,"alg":"x25519-hkdf-sha256-aes256gcm","epk","iv","ct","tag"})`.

The commitment (v2) is `sha256("replaycourt/commit/v2" || 0x00 || hunter_account_id || 0x00 ||
report_bytes)` in lowercase hex: `commitmentFor(hunterId, report)` in `src/seal.ts`. The v1
`commitmentOf(report)` (sha256 of the report alone) is kept, deprecated, for v1 deployments.

## NEAR library

`near-api-js` **7.4.0** (latest release on npm, published by NEAR). docs.near.org lists
near-api-js and near-kit side by side. near-api-js is the long-standing official library: it
has a stable major version, typed `Account.callFunctionRaw` / `addFunctionCallAccessKey` /
`Provider.callFunction` APIs and few dependencies. near-kit is still pre-1.0 (0.20) and pulls
in a native keyring module. Keys are used in memory only (`KeyPairString` from the credential
files); nothing is written to a system keychain.

## Code layout

```
agent/
  src/cli.ts         commands and argument parsing (node:util parseArgs)
  src/actions.ts     chain-facing actions of the CLI (programs, dispute, vault, hunter key, submit) with an injectable ChainClient
  src/config.ts      env + .secrets/<network>.json, ~/.near-credentials, secret files, showcase pins, worker allow-list
  src/near.ts        provider (failover), view/call helpers, the real ChainClient, explorer links
  src/seal.ts        sealed report format (X25519 + HKDF-SHA256 + AES-256-GCM), commitment v2
  src/mapping.ts     engine exit code / verdict.json -> on-chain VerdictInput
  src/evidence.ts    evidence envelope, status sets, evidence paths below runs/
  src/worker.ts      worker loop with injectable chain/engine dependencies, engine runner
  src/disclosure.ts  publish: which private evidence may go to runs/
  src/verify.ts      verify-onchain: hash, binding and disclosure checks with injectable view/reader
  src/attacks.ts     helpers of the attack demos in ../demo/attacks/ (not used by the CLI or worker)
  src/testnet.ts     faucet account, key files, deploy + init (../demo/testnet-setup.ts, judge path C)
  test/*.test.ts     node:test suites
```

AI disclosure: this agent was written with Claude Code (AI-generated code, reviewed and tested as
described above).
