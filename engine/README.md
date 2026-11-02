# ReplayCourt engine - replay verifier for smart-contract bug reports

The engine takes a bug report (Markdown with a Foundry proof of concept), replays the PoC on a
fork of the real chain at the stated block, and decides from the **execution trace** - not from
what the PoC prints - whether the report proves real damage:

**valid** / **invalid** / **needs_human**, plus a **duplicate** check against earlier reports,
a severity hint (critical / high / medium / low) and an evidence file (`verdict.json`).

It is the off-chain verifier behind ReplayCourt: the worker in `../agent/` decrypts sealed reports
from the NEAR contract, runs this engine, and posts the verdict on-chain.

Python 3.8+ standard library only, plus Foundry's `forge`. Ported from a prototype written at
the start of the hackathon; this port adds the `--report-id` and `--dest` options and plain codes
in `verdict.json`. The decision rules are the prototype's, with these additions:
- three hardening rules in 0.3.0, after the attack demos (see "Security model");
- in 0.4.0, only a **valid** earlier report can be the original of a duplicate (see "Duplicate
  check"), and every timestamp is UTC;
- in 0.5.0, cheatcodes fail closed (only an allow-list is neutral, anything else counts as state
  manipulation) and an identity takeover is also detected from the trace itself: a call whose
  caller is not the frame that made it. `vm.broadcast` counts like `vm.prank`.

The demo outcomes did not change.

## Quick start

Requirements: Python >= 3.8, Foundry (`forge`, tested with 1.8.7; install with
`curl -L https://foundry.paradigm.xyz | bash && foundryup`), internet access (a free public
Ethereum archive RPC for the fork, and a one-time `solc` download by forge).

All commands run from the repository root.

```bash
# 1. check one report (English summary on stdout, the exit code is the verdict)
python3 -I engine/replay.py check engine/reports/01_templedao_stax.md
#    -> "**Verdict: VALID** · severity hint: **critical** · exit code 0"
#    -> files in engine/verdicts/01-templedao-stax/ (verdict.json, summary.md, forge logs)

# 2. reproduce the whole demo table below (registry cleared first, reports in order)
python3 -I engine/replay.py registry clear
for r in 01_templedao_stax 02_seneca_chamber 03_stax_duplicate 04_seneca_bogus 05_fake_profit 06_local_reentrancy; do
  python3 -I engine/replay.py check engine/reports/$r.md --quiet > /dev/null; echo "$r exit=$?"
done
#    -> exit codes 0 0 3 1 1 2

# 3. machine-readable, as the worker calls it
#    (runs/demo/ is git-ignored; "outcome" is "invalid", exit code 1)
python3 -I engine/replay.py check engine/reports/04_seneca_bogus.md --json --quiet \
  --registry runs/demo/registry.jsonl --report-id sub-4 --dest runs/demo/sub-4
```

`forge` is found via `$REPLAYCOURT_FORGE`, then `PATH`, then `~/.foundry/bin/forge`. `-I` runs
Python isolated, so no module planted in the current directory can hijack the run.

## Demo results (real run)

`../demo/engine-replay.sh` reproduces this table (and checks the attack reports). Engines 0.3.0,
0.4.0 and 0.5.0 gave the same outcomes on 2026-11-02 for the 14 reports they share (01-06, attacks
a/b and six probes). Engine 0.5.0 adds three identity-takeover probes, 17 reports in all. The
0.5.0 run is in
[`../demo/attacks/logs/engine-replay-all.txt`](../demo/attacks/logs/engine-replay-all.txt).

First run on 2026-11-02 on the author's Mac (macOS x86_64, Python 3.8.7, forge 1.8.7), registry
cleared, reports 01..06 in order, every run wrapped in a memory/time cap (4 GB, 30 min). Fork RPC:
`https://eth.drpc.org` (publicnode refuses archive queries without a token and is skipped
automatically).

| # | Report | Expected | Verdict (`outcome`) | Exit | Evidence from the trace | Time |
|---|---|---|---|---|---|---|
| 01 | TempleDAO/STAX `migrateStake()` (ETH, block 15,725,066) | valid | **valid**, critical | 0 | attacker +321,154.87 xFraxTempleLP, StaxLPStaking -100 % of its holdings; no cheatcode except fork/label | 12 s |
| 02 | Seneca `Chamber.performOperations()` (ETH, block 19,325,936) | valid | **valid**, critical | 0 | attacker +1,385.24 PT-rsETH-27JUN2024, the named victim -100 %; one `transferFrom` in the Chamber's name | 15 s |
| 03 | STAX drain, **reworded + PoC rebuilt** (own helper contract) | duplicate of 01 | **duplicate** of `01-templedao-stax` | 3 | fingerprint 1.00 (same target, same selectors, same loser) although text 0.02 / code 0.39 | 12 s |
| 04 | Seneca "direct `transferFrom` without approval" | invalid | **invalid** | 1 | PoC test fails on the fork: `ERC20: insufficient allowance` | 11 s |
| 05 | "Attacker holds 1M USDC" (with `deal` + `vm.prank`) | invalid | **invalid** | 1 | test passes, but the "damage" exists only because the PoC pranks as the victim; the `deal` balance emits no Transfer and does not count | 15 s |
| 06 | Reentrancy, **local contract without a fork** | needs human | **needs_human**, provisional high | 2 | attacker +10 ETH, vault -10 ETH in the trace, but the code is not proven against a deployment | 9 s |

These are the same six outcomes the prototype produced on these reports (01 valid, 02 valid, 03
duplicate of 01, 04 invalid, 05 invalid, 06 needs human), with the same severity hints.

Demo reports: two real public exploits (01 TempleDAO, 2022-10-11; 02 Seneca, 2024-02-28)
reproduced at their fork blocks, PoCs from [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs)
(see `THIRD_PARTY.md`); 03 shows duplicate detection by behaviour fingerprint; 04 and 05 are the
negative cases (PoC fails / passes only through faked preconditions); 06 is the local fallback.
Report 01 now carries the DeFiHackLabs PoC inline (byte-identical) instead of a `poc:` file
reference, so it stays self-contained when it is sealed and submitted on-chain.

## What the engine does

Each report goes through seven steps:

1. **Read the report.** Markdown with optional front matter (`---` block: `title`, `chain`,
   `fork_block`, `test`, `target`, `victim`, `attacker`, `severity`, `author`, `poc`). The PoC is
   a ```` ```solidity ```` block or a `poc: <path>` reference. No executable PoC -> **invalid**.
2. **Chain and fork block** from front matter, CLI or the PoC's `createSelectFork(...)`;
   resolved through `config/chains.json` (aliases, chain id, RPCs).
3. **Static check** of the PoC (read, not run): `vm.ffi`, file/env/HTTP/RPC cheatcodes, own fork
   URLs. Literal own URLs are blocked unless `--allow-external-urls` -> **needs_human**. The check
   is advisory (code can hide a call); step 7 sees every cheatcode call in the trace.
4. **Prepare the fork.** Public RPCs are probed in order for **archive access at the fork
   block**; the first that answers is used. No archive reachable -> **exit 69** (infrastructure),
   no verdict. Alternatively local mode (`chain: local`) without a fork.
5. **Compile** (`forge build`) in an **isolated throw-away workspace** with an engine-generated
   `foundry.toml` (`ffi = false`, `fs_permissions = []`). Compile error -> **invalid**.
6. **Run the PoC** (`forge test --json -vvvv`).
7. **Analyse the trace.** Balance changes from raw `Transfer`/`Deposit`/`Withdrawal` events and
   call values (in fork mode, events emitted by contracts the PoC deployed itself are ignored);
   cheatcode use; `vm.prank` identities; every fork the PoC opened, with the URL or alias decoded
   from the call data; an **attack fingerprint**. Then the verdict and the duplicate check.

### Decision rules (short)

The burden of proof is on the report. **valid** only if

- the PoC **passes** on the fork, AND
- the trace shows a real **outflow of value from third parties to the attacker**, AND
- **no identity was taken over** with `vm.prank` and **no state was faked** with cheatcodes.

**invalid**: PoC does not build / does not pass; no measurable value movement; or the "damage"
only exists because the PoC pranks as the victim.
**needs_human**: everything doubtful - local mode, starting capital or state via cheatcodes,
acting as a foreign (privileged) address, block mismatch, target without code at the fork,
gain without an identifiable victim, possible duplicate, a fork from an RPC the engine did not
choose.

### Severity hint

From the damage (USD where priceable: stablecoins and the native coin via the Chainlink feed **at
the fork block**) and the share of the victim's holdings: critical from 1M USD or 50 %, high from
100,000 USD or 10 %, medium from 1,000 USD or 1 %, otherwise low. Pure griefing (no gain for the
attacker) is capped at medium. For needs_human the level is marked `"provisional": true`.

### Duplicate check

Three independent measures against every earlier registry entry:
- **text:** Jaccard over word 3-grams, code blocks removed;
- **code:** `difflib` ratio over the normalized PoC tokens;
- **fingerprint:** Jaccard over the attack calls that actually executed (`target:selector`) and
  the addresses that lost value.

Above a duplicate threshold (fingerprint 0.75, text 0.70, code 0.90) the report is a
**duplicate** of the earliest matching original. Above a lower "possible" threshold, a valid
verdict becomes needs_human.

**Only a valid report can be an original** (SPEC v2). Every report is recorded in the registry,
but an invalid or needs-human entry never makes a later report a duplicate or a possible
duplicate. It is still compared and listed in `duplicate.candidates`, with `"eligible": false`
and its id in `duplicate.not_original`. Without this rule, a hunter whose first try failed (a
typo in the PoC) could not resubmit the fixed report: it was closed as a duplicate of their own
invalid report (text 1.00, code 0.98). A match with a recorded duplicate points to that
duplicate's original, if the original is still valid. The original named is the earliest one,
by triage time (UTC, so mixed offsets of older registries compare correctly).

The worker passes the on-chain statuses with `--onchain-status <file>` (`{"sub-3": "paid", …}`).
The contract's rule then decides: an original must be `valid`, `paid` or `disputed` on-chain.
This covers a needs-human report that the owner resolved as valid, and a valid verdict the owner
overruled. The overlay is used in memory only; the registry file keeps the engine's own record.

## Output

`check` writes into `--dest DIR`, or `--out OUT` / `<report-id>/` (default `engine/verdicts/`):

| File | Content |
|---|---|
| `verdict.json` | full verdict, schema `replaycourt.verdict/v1` |
| `summary.md` | human summary |
| `PoC.t.sol` | the PoC that was checked (copy) |
| `foundry.toml` | the engine-generated configuration of the run |
| `forge-build.log`, `forge-test.json`, `forge-test.stderr.txt` | raw forge output |

Key fields of `verdict.json` (language-independent codes):

```jsonc
{
  "schema": "replaycourt.verdict/v1",
  "outcome": "duplicate",           // valid | invalid | needs_human | duplicate | null (exit 69/70)
  "verdict": "valid",               // technical verdict: valid | invalid | needs_human
  "exit_code": 3,
  "severity_hint": { "level": "critical", "provisional": false, "basis": ["..."] },
                                    // level: critical | high | medium | low | none | unclear
  "duplicate": { "status": "duplicate", "of": "sub-1", "candidates": [ ... ] },
  "fork": { "chain": "ethereum", "chain_id": 1, "local": false, "poc_fork_block": 15725066, ... },
  "fingerprint": { "chain": "ethereum", "calls": ["0xd286...:0x..."], "losers": [...] },
  "reasons": ["..."], "warnings": ["..."], "evidence": { "balance_changes": [...], ... }
}
```

### Exit codes (for scripts and agents)

| Code | Meaning |
|---|---|
| 0 | valid |
| 1 | invalid |
| 2 | needs human |
| 3 | duplicate (the technical verdict is also in the JSON) |
| 64 | usage error |
| 65 | report not readable |
| 69 | infrastructure missing (no archive RPC, forge/compiler unavailable) - no verdict, retry later |
| 70 | internal error - no verdict |

### Options of `check`

`--chain`, `--block`, `--rpc <archive-url>` (redacted to `scheme://host/…` in the evidence),
`--test <function>`, `--evm-version`, `--json`, `--quiet`, `--registry <file>`,
`--report-id <id>` (register and file the report under this id; the worker passes `sub-<id>` so
that a duplicate block names an on-chain submission), `--onchain-status <file>` (on-chain statuses
for the duplicate check, see above), `--out <dir>`, `--dest <dir>`, `--no-register`,
`--keep-workspace`, `--allow-external-urls`, `--allow-path <dir>`, `--build-timeout` /
`--test-timeout` (seconds, default 900).

All timestamps in the output (`pipeline.started_at`/`finished_at`, the registry's `triaged_at`,
`summary.md`) are UTC with a `Z` suffix, whatever the machine's time zone.

Other commands:

```bash
python3 -I engine/replay.py rpc --chain ethereum --block 15725066   # probe archive access
python3 -I engine/replay.py registry list                           # show the duplicate registry ("original": may it be one)
python3 -I engine/replay.py registry remove --id 03-stax-staking-drain
python3 -I engine/replay.py registry clear
```

## Security model (submitted code is hostile)

- PoCs only run inside `forge test` (EVM), always with an engine-generated `foundry.toml`
  (`ffi = false`, `fs_permissions = []`), never the submitter's.
- Empty environment: only `PATH`, an own `HOME` (`engine/.sandbox-home/`), `FOUNDRY_FFI=false`.
  No environment variables or secrets are passed on.
- Each run in its own throw-away workspace under `engine/work/`, deleted afterwards.
- Hard time limit; on timeout the whole process group is killed.
- Static warnings for `vm.ffi`, file/env/HTTP/RPC cheatcodes; literal own fork URLs blocked.
- The RPC client uses read-only methods only. No transactions, no keys, no money.

Added in 0.3.0, after the attack demos in [`../demo/ATTACKS.md`](../demo/ATTACKS.md) found three
holes (probes in `../demo/attacks/engine-probes/`):

- **Forks the engine did not choose.** Every `createFork`/`createSelectFork` call is decoded from
  the raw trace (by selector, so low-level calls and URLs built at run time are seen). Only the
  aliases of the generated `foundry.toml` and the URLs behind them are trusted. A passing PoC that
  moved value on another fork -> **needs_human** (its state could be fabricated by an
  attacker-run RPC); every fork is listed in `evidence.fork_cheatcodes`.
- **Fake value events.** In fork mode, `Transfer`/`Deposit`/`Withdrawal` events emitted by any
  contract created during the run (the test contract included) are not value. Before, a PoC that
  emitted `Transfer(victim, itself, …)` from its own contract was technically valid.
- **No infrastructure verdict from PoC text.** A failing test whose message looks like an RPC
  error (`429`, `rate limit`, `could not instantiate forked environment`, …) is only treated as
  exit 69 if a failed cheatcode call produced it and the fork target is the engine's own. A
  `revert("429 Too Many Requests")` or a fork from a dead URL of the PoC's choosing is a failing
  PoC (invalid). Before, it made the worker retry forever and stall the program's queue.
- **Evidence scrubbing.** Every file written to the evidence folder has the workspace path, the
  repository path and the home directory replaced (`<workspace>`, `<repo>`, `~`), and a `--rpc`
  URL redacted. A PoC can log `vm.projectRoot()` or `vm.rpcUrl(...)`, and the evidence is
  published.

## Limits (honest)

- **Archive access.** Free public RPCs are flaky; `eth.drpc.org` and `blastapi.io` served old
  state reliably in the demos. Production needs a paid archive endpoint via `--rpc` or
  `config/chains.json`.
- **"valid" is a technical statement, not an audit**: "this PoC moves real value from the victim
  to the attacker at this block". Whether the fork block is fair or a precondition (e.g. an
  existing approval) is realistic stays with a human - hence needs_human.
- **Attacker/victim attribution is heuristic** (test contract + declared attackers + contracts
  created during execution). Unusual PoCs can fool it.
- **Valuation is rough**: USD only for stablecoins and the native coin.
- **Local mode proves nothing about a deployment** - always needs_human.
- **Solidity/Foundry PoCs only**; process/env/file-system hardening, no kernel-level sandbox. The
  PoC has network access (it can open forks; the engine detects them afterwards), and
  `vm.rpcUrl` returns the configured RPC URLs: use keyless or IP-restricted archive endpoints, and
  in production run the engine in a container without access to the verifier's keys.

## Tests

```bash
python3 -I -m unittest discover -s engine/tests -v    # from the repository root; 44 tests, about 1 s
```

They need no network and no forge, and CI runs them:
- the registry file (round trip, re-check, broken lines, the on-chain overlay);
- the duplicate check, including the S1 regression: an invalid first try followed by the same
  report is not a duplicate;
- needs-human and overruled originals, redirects to originals, the earliest original across UTC
  offsets, and the similarity measures;
- the check pipeline on paths that need no fork: UTC timestamps in `verdict.json`,
  `summary.md` and the registry; registration; `--onchain-status`.

## Layout

```
engine/
├── replay.py             CLI + pipeline
├── replaylib/
│   ├── report.py         read report + PoC, static flags
│   ├── rpc.py            JSON-RPC (read-only): archive probe, balances, token meta, Chainlink
│   ├── forge.py          isolated workspace, build/test, selectors, solc version
│   ├── trace.py          trace analysis: flows, cheatcodes, prank roles, fingerprint
│   ├── dedup.py          duplicate check (text/code/fingerprint) + registry
│   ├── verdict.py        decision rules, severity, exit codes
│   ├── render.py         summary.md
│   └── i18n.py           message catalog
├── config/chains.json    chains, aliases, RPCs, stablecoins, Chainlink feeds
├── reports/              the six demo reports (01-06)
├── register/             default duplicate registry (registry.jsonl, not committed)
├── tests/                unit tests (stdlib unittest, no network, no forge): registry, duplicate check, UTC
├── tools/vendor.py       verify / re-fetch the vendored files at their pinned commits
├── vendor/               forge-std + DeFiHackLabs interface.sol (pinned, see THIRD_PARTY.md)
├── verdicts/             default output (not committed)
├── work/                 throw-away workspaces (deleted per run)
└── .sandbox-home/        own HOME for forge (solc cache)
```
