# ReplayCourt contract (NEAR, Rust), v2

This is the on-chain half of ReplayCourt, a bug-bounty escrow. Each step below names a contract
method:

1. A program owner escrows a pool of NEAR (`create_program`).
2. A hunter commits a sealed (encrypted) report and posts a bond. The bond comes either from an
   attached deposit (`submit_report`) or from a pre-funded vault with an on-chain spending
   policy (`submit_report_from_vault`), which an AI agent can call with a function-call key.
3. The program's verifier agent posts a verdict (`post_verdict`): `valid`, `invalid`,
   `duplicate` or `needs_human`. It does this with a function-call access key that can call
   nothing else.
4. The money moves by these rules:
   - `valid`: the hunter is paid from the pool once a challenge window has passed (`finalize`).
   - `invalid`: the bond is slashed into the pool.
   - `duplicate` (only of a `valid`, `paid` or `disputed` original): the bond is refunded minus
     the verifier fee.
   - `needs_human`: the program owner decides (`resolve`) before a deadline. If they do not,
     anyone can `finalize` and the hunter gets the full bond back (`expired`).
   - The owner can contest a `valid` verdict inside the window (`dispute`). To do so, they post
     a dispute bond and must `resolve` before a deadline:
     - overruling the verifier (invalid) gives the hunter the bond plus the dispute bond;
     - confirming it (valid) pays the hunter and returns the dispute bond to the owner;
     - doing nothing lets anyone `finalize`, which pays the hunter plus the dispute bond.

- Interface and rules: [`../SPEC.md`](../SPEC.md) (v2). Deviations and interpretations:
  [`SPEC-DEVIATIONS.md`](SPEC-DEVIATIONS.md).
- Showcase deployment on testnet: **`contract.replaycourt.testnet`**, running the wasm whose
  sha256 is in [`WASM_SHA256`](WASM_SHA256) (on-chain `code_hash`
  `5fuWijh2LZQTuCtACJmpxkvoSLmZs99QWXC3Vjz3F42V`); see [`../demo/SHOWCASE.md`](../demo/SHOWCASE.md).

## Trust model

- **Contract owner.** The `owner_id` passed to `new` has no power over programs, vaults or
  funds. A production deployment removes the contract account's full-access keys, or hands
  upgrades to a DAO, so the code cannot be swapped.
- **Program owner.**
  - Can withdraw only `pool - reserved`. Every open submission reserves `max payout +
    verifier fee`.
  - Cannot post verdicts.
  - Can dispute only a `valid` verdict, inside the challenge window, by posting the dispute
    bond.
  - An overruled dispute costs the owner that bond, which goes to the hunter. It is public in
    `stats.disputes` and `stats.overruled`.
  - Every escalation has a deadline (`resolve_timeout_sec`), after which anyone can settle it.
- **Verifier.**
  - Only the program's `verifier_id` can post verdicts, and only on `pending` reports.
  - It earns its fee on invalid and duplicate verdicts and on paid reports, but not when the
    owner overrules a valid verdict.
  - A duplicate must point to an earlier `valid`, `paid` or `disputed` report of the same
    program.
- **Hunter.**
  - The bond depends on the hunter's record **in that program only**
    (`get_hunter_in_program`). Reputation farmed elsewhere buys nothing.
  - A pending report can be withdrawn after the pending timeout.
  - Every window and timeout is at least 60 s.
- **Hunter vault and agent keys.**
  - A function-call key limited to `submit_report_from_vault`, `finalize` and
    `withdraw_pending` can spend from the vault only inside the policy: `max_bond_per_report`,
    `max_spend_per_day` over a 24 h window, and `allowed_programs`.
  - `vault_set_policy` and `vault_withdraw` need exactly 1 yoctoNEAR. Function-call keys cannot
    attach deposits, so a leaked agent key can neither raise the limits nor withdraw.
  - Bond refunds of vault-funded reports go back into the vault. Payouts and dispute bonds go
    to the hunter account.
- **Storage.**
  - Every byte a submission causes is paid by the submitter, including the later writes:
    verdict, dispute reason and resolution note, pre-paid at their byte limits as
    `LATER_WRITES_STORAGE_BYTES = 1359`.
  - All text limits count bytes, not characters.
- **Sealed reports.** The commitment binds the report to the submitting account
  (`commit/v2`). The worker checks that binding off-chain. The contract only enforces that a
  commitment is used once.

## Layout

| path | content |
|---|---|
| `src/lib.rs` | contract: programs, submissions, verdicts, settlement, vault, views, NEP-297 events |
| `src/types.rs` | stored types and their JSON views |
| `src/tests.rs` | 195 unit tests: every rule, refusal and money path, the vault, regression tests S1 to S8 |
| `tests/sandbox.rs` | near-workspaces sandbox test of the full v2 flow, including the verifier key, the vault and the agent key (compiles; not executed yet, see below) |
| `build.sh` | path-remapped, privacy-checked wasm build; writes or checks `WASM_SHA256` |
| `WASM_SHA256` | sha256 of the wasm that `build.sh` produces from this source |
| `scripts/setup-testnet.sh` | creates faucet and sub-accounts, deploys and initializes on testnet |
| `scripts/e2e-testnet.sh` | end-to-end test of the v2 flows on testnet with near-cli-rs |
| `rust-toolchain.toml` | pins rustc 1.95.0 + `wasm32-unknown-unknown` |

## Prerequisites

- `rustup`. The toolchain pinned in `rust-toolchain.toml` (1.95.0 with the wasm target) is
  installed automatically on first use. To install it explicitly, run
  `rustup toolchain install 1.95.0 --target wasm32-unknown-unknown` (from this directory).
- `cargo-near` 0.22.0:
  `curl --proto '=https' --tlsv1.2 -LsSf https://github.com/near/cargo-near/releases/download/cargo-near-v0.22.0/cargo-near-installer.sh | sh`
- `near` CLI (near-cli-rs 0.30.1), only for testnet:
  `curl --proto '=https' --tlsv1.2 -LsSf https://github.com/near/near-cli-rs/releases/download/v0.30.1/near-cli-rs-installer.sh | sh`
- `python3`, `curl` and `strings` for the scripts.

Run every command below from this `contract/` directory.

## Build

```sh
./build.sh            # build, privacy check, write WASM_SHA256
./build.sh --check    # build, privacy check, compare with WASM_SHA256 (exit 3 if different)
```

`build.sh` runs `cargo near build non-reproducible-wasm --locked` and passes RUSTFLAGS through
cargo-near's `--env`. cargo-near appends `--cfg near` itself, and the script unsets
`CARGO_ENCODED_RUSTFLAGS`, which would drop it. The flags remap these paths with
`--remap-path-prefix`:

| local path | becomes |
|---|---|
| `$CARGO_HOME` | `/cargo` |
| `$RUSTUP_HOME` | `/rustup` |
| the repository | `/replaycourt` |
| the target directory | `/target` |

Panic messages in the wasm therefore name `/cargo/registry/...` instead of a home directory.
The script fails if `strings` finds `/Users/`, `/home/` or the current user name in the wasm.

The output is `target/near/replaycourt.wasm` (295,116 bytes) plus its ABI, with

```
sha256 456631c55d04492c6f4143a19f82ebd66942af4333d05997db910d7a1608bd32
```

The same hash is in [`WASM_SHA256`](WASM_SHA256). Two builds, one with a different
`CARGO_TARGET_DIR`, produced the same hash.

cargo-near's non-reproducible build is not guaranteed to be bit-identical on another operating
system. CI therefore runs `./build.sh --check`:
- a build error or a failed privacy check fails the job;
- a hash mismatch is reported as a warning.

`cargo near build reproducible-wasm` (Docker) is the route to cross-machine identical builds.

About the toolchain: rustc releases newer than the one nearcore is built with can emit wasm
features the NEAR runtime rejects. `rust-toolchain.toml` therefore pins **rustc 1.95.0**, which
is near-sdk 5.30's MSRV and the compiler nearcore 2.14 is built with. `cargo near` then runs
`wasm-opt` with exactly the features the runtime accepts (bulk-memory,
nontrapping-float-to-int).

## Test

```sh
cargo test --lib
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

`cargo test --lib` runs 195 unit tests, all passing. They cover:
- **Every rule and refusal of SPEC.md v2:**
  - byte limits, including 4-byte UTF-8 text;
  - minimum windows of 60 s;
  - `dispute_bond >= bond`;
  - per-program pending lists and hunter stats;
  - duplicates only of valid, paid or disputed originals;
  - the dispute bond, `resolve` deadlines and the `disputed → duplicate` refusal;
  - `finalize` of valid, disputed and needs_human reports;
  - `expired`, `stats.overruled`.
- **Money paths**, checked against the transfer receipts:
  - slash, refund, payout and dispute-bond amounts;
  - the payout cap.
- **Invariants:**
  - `reserved` never exceeds the pool and always equals the sum of open reservations;
  - every program's pending index matches its pending reports;
  - a conservation-of-money audit across every settlement path, the vault and the dispute
    bonds: every yoctoNEAR attached is held, kept for storage, or transferred out.
- **Storage pre-payment:** a minimal report followed by the maximal later writes (ASCII, 4-byte
  text, vault-funded) never uses more storage than the hunter pre-paid, and the constant is
  exact.
- **The vault:**
  - deposit and storage;
  - exactly 1 yoctoNEAR for `vault_set_policy` and `vault_withdraw`;
  - `max_bond_per_report`, `max_spend_per_day`, the 24 h window reset and `allowed_programs`;
  - refund routing (bond to the vault; payout and dispute bond to the account) for paid,
    duplicate, withdrawn, expired and overruled reports.
- **Regression tests for the findings of the separate AI review of v1:**

  | finding | test(s) |
  |---|---|
  | S1: duplicate of an invalid original | `s1_*` |
  | S2: replayed commitment, documented | `s2_*` |
  | S3: no exit after a dispute or for needs_human | `s3_*` |
  | S4: multibyte storage drain | `s4_*` |
  | S5: global pending scan | `s5_*` |
  | S6: self-farmed reputation | `s6_*` |
  | S8: zero windows | `s8_*` |

  Each S1 to S8 test (except S2, which documents an off-chain check) fails when the v1
  behaviour is put back into the contract, and passes on v2.

Sandbox integration test (near-workspaces 0.24, local NEAR sandbox node):

```sh
./build.sh
cargo test --test sandbox -- --nocapture
```

near-workspaces downloads the sandbox node on Linux x86_64/aarch64 and macOS arm64. On macOS
x86_64 it refuses, so point `NEAR_SANDBOX_BIN_PATH` at a sandbox binary:

```sh
mkdir -p ~/.near/sandbox-2.14.0 && cd ~/.near/sandbox-2.14.0 \
  && curl -sSLO https://s3-us-west-1.amazonaws.com/build.nearprotocol.com/nearcore/Darwin-x86_64/2.14.0/near-sandbox.tar.gz \
  && tar xzf near-sandbox.tar.gz && cd -
NEAR_SANDBOX_BIN_PATH=~/.near/sandbox-2.14.0/Darwin-x86_64/near-sandbox cargo test --test sandbox -- --nocapture
```

Status: `tests/sandbox.rs` compiles against v2 (`cargo clippy --all-targets`) but **has not
been executed yet**. CI runs it on Linux. `scripts/e2e-testnet.sh` runs the same flows against a
deployed contract on testnet.

## Deploy to testnet

Testnet only. The first command creates `<name>.testnet` through the faucet (10 testnet NEAR)
and these sub-accounts: `contract.`, `owner.`, `verifier.`, `hunter1.` and `hunter2.`. It then
deploys `target/near/replaycourt.wasm` and calls `new(owner_id=<name>.testnet)`. Keys go to the
legacy keychain `~/.near-credentials/testnet/`. The wasm (about 295 KB) needs about 3 NEAR of
storage stake on the contract account. The faucet's 10 NEAR may therefore not cover the
default funding: fund the master from a second faucet account, or lower the `FUND_*` amounts.

```sh
./build.sh
NETWORK_CONFIG=testnet-fastnear RPC=https://test.rpc.fastnear.com \
  FUND_CONTRACT='4 NEAR' scripts/setup-testnet.sh <name>.testnet
```

Options (environment):
- `HUNTERS=3` creates `hunter1.` to `hunter3.`.
- `EXTRA="verifier2=0.3 NEAR"` creates more accounts.
- `FUND_CONTRACT`, `FUND_OWNER`, `FUND_VERIFIER` and `FUND_HUNTER` set the amounts.
- `HANDOFF=<file>` writes the account ids (no keys) as JSON for the agent, with `HANDOFF_RPC`
  and `HANDOFF_SECRETS_DIR`.

## End-to-end test on testnet

```sh
NETWORK_CONFIG=testnet-fastnear RPC=https://test.rpc.fastnear.com scripts/e2e-testnet.sh <name>.testnet
```

The script exits non-zero if any step fails. Every window and timeout is 60 s. Steps:
1. Create a program: 3 NEAR pool, dispute bond 0.15 NEAR.
2. Add a verifier function-call key (`post_verdict` only); every verdict is signed with it.
3. Add an agent function-call key on hunter1, limited to `submit_report_from_vault`, `finalize`
   and `withdraw_pending`.
4. Set up the vault with hunter1's full-access key: deposit, then set the policy (1
   yoctoNEAR).
5. Submit two reports from the vault with the agent key. The third is refused by the daily
   spend limit.
6. Show that the agent key cannot call `vault_withdraw` or `vault_set_policy`, with or without
   1 yoctoNEAR. A second key that does allow those methods is refused by the contract without
   a deposit and by the runtime with one.
7. A duplicate of an invalid original is refused.
8. Dispute A with the bond plus excess, then resolve it invalid. The hunter's balance grows by
   exactly bond + dispute bond.
9. Dispute C and leave it: `finalize` is refused before `resolve_until`, and
   `resolve duplicate` is refused.
10. After the deadlines:
    - the needs_human report B expires through `finalize` (agent key), and its bond returns to
      the vault;
    - the pending report F is withdrawn (agent key), and its bond returns to the vault;
    - `resolve C` is refused;
    - `finalize C` pays payout + bond + dispute bond (exact balance check).
11. Withdraw the pool and empty the vault.

Every transaction is written to a Markdown report: the path is printed, and `REPORT=` sets it.
A run takes 6 to 20 minutes, depending on the public RPC. It needs about 3.4 NEAR on the owner (the pool comes back), 1.1
NEAR on hunter1 (the vault comes back) and 0.5 NEAR on hunter2.

## Methods

| method | who | money |
|---|---|---|
| `new(owner_id)` | deployer, once | none; the contract owner has no powers |
| `create_program(name, scope, verifier_id, verifier_pubkey, payouts, bond, verifier_fee, dispute_bond, challenge_period_sec, pending_timeout_sec, resolve_timeout_sec) -> u64` | anyone, payable (>= 1 NEAR) | deposit minus record storage becomes the pool; `dispute_bond >= bond`; windows 60 s ..= 30 days (pending: 365 days) |
| `top_up(program_id)` | anyone, payable | adds to the pool |
| `set_active(program_id, active)` | program owner | none |
| `withdraw_pool(program_id, amount)` | program owner | at most `pool - reserved` |
| `submit_report(program_id, title, commitment, sealed) -> u64` | hunter, payable | storage (incl. 1359 pre-paid bytes) + bond `>= required_bond`; reserves `max payout + verifier fee` |
| `submit_report_from_vault(program_id, title, commitment, sealed) -> u64` | hunter or its agent key, **not payable** | draws exactly `required_bond + storage` from the vault, inside the policy |
| `post_verdict(submission_id, verdict)` | program verifier, **not payable** | invalid: `min(fee, bond)` to the verifier, the rest to the pool; duplicate: fee to the verifier, the rest refunded |
| `finalize(submission_id)` | anyone | valid after the window: payout + bond to the hunter, fee to the verifier; disputed after `resolve_until`: the same plus the dispute bond to the hunter; needs_human after `resolve_until`: full bond back (`expired`) |
| `dispute(submission_id, reason)` | program owner, payable, inside the window | holds `dispute_bond` (excess refunded); `resolve_until = now + resolve_timeout` |
| `resolve(submission_id, outcome, severity, note)` | program owner, before `resolve_until` | needs_human: valid pays, invalid slashes, duplicate refunds minus fee; disputed: valid pays and returns the dispute bond to the owner, invalid gives the hunter bond + dispute bond, duplicate is refused |
| `withdraw_pending(submission_id)` | hunter or its agent key, after the pending timeout | full bond back |
| `vault_deposit()` | anyone, payable | creates the vault on first use (storage from the deposit) |
| `vault_set_policy(max_bond_per_report, max_spend_per_day, allowed_programs)` | vault owner, exactly 1 yoctoNEAR | none (the yoctoNEAR is credited to the vault) |
| `vault_withdraw(amount)` | vault owner, exactly 1 yoctoNEAR | at most the vault balance |

Bond refunds of vault-funded reports go back into the vault. Payouts and dispute bonds go to
the hunter account.

Views:
- `version`
- `get_program`, `list_programs`
- `get_submission`, `list_submissions`
- `list_pending(program_id, from_index, limit)`
- `get_sealed`
- `get_hunter` (global, display only), `get_hunter_in_program` (used for the bond)
- `required_bond`
- `get_vault`

Page size is capped at 50. Events are NEP-297 (`EVENT_JSON:`), standard `replaycourt`, version
`2.0.0`.

## Try the showcase contract (no account needed)

```sh
C=contract.replaycourt.testnet
near contract call-function as-read-only $C version json-args '{}' network-config testnet now
near contract call-function as-read-only $C list_programs json-args '{"from_index":0,"limit":10}' network-config testnet now
near contract call-function as-read-only $C list_pending json-args '{"program_id":0,"from_index":0,"limit":10}' network-config testnet now
near contract call-function as-read-only $C get_vault json-args '{"account_id":"agent.replaycourt.testnet"}' network-config testnet now
```

## Third-party code and AI disclosure

- Libraries: `near-sdk` 5.30 (contract), `near-workspaces` 0.24 and `tokio` (tests only).
- Tools: `cargo-near` 0.22.0, near-cli-rs 0.30.1.
- This contract, its tests and its scripts were written by an AI coding agent (Claude) during
  the hackathon window, from the human-authored `SPEC.md`.
