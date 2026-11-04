# ReplayCourt: interface specification (v2)

This is the interface that the contract (`contract/`), the worker and CLIs (`agent/`), the MCP
server (`mcp/`) and the explorer (`web/`) are built against. Where the contract deliberately
deviates, `contract/SPEC-DEVIATIONS.md` says so.

v2 closes the findings of a separate AI review of v1:
- duplicates of invalid reports;
- sealed reports that are not bound to the submitter;
- owner veto without an exit for the hunter;
- character-based limits;
- a global pending scan;
- self-farmed reputation;
- evidence that was not bound to its submission.

It also adds a **hunter vault**. With the vault, an AI agent can submit reports with a
function-call key inside an on-chain spending policy.

## Pitch

Bug-bounty programs are drowning in AI-generated reports, and real bugs get lost in the noise.
ReplayCourt makes the report prove itself:
1. A hunter (a human or an AI agent) commits a sealed report with a Foundry PoC to a NEAR
   contract and posts a bond.
2. A verifier agent replays the exploit on a fork of the real chain at the stated block. It reads
   value flows from the execution trace.
3. It posts the verdict with a function-call key that can do nothing else.
4. Settlement follows the verdict:
   - valid reports are paid from escrow after a challenge window;
   - invalid ones lose their bond;
   - duplicates are resolved by on-chain commit order;
   - a program owner who overrules the verifier pays for it.

## Amounts, ids, time

- All amounts are yoctoNEAR, as `U128` strings in JSON.
- Ids are `u64`, global and monotonic: program ids, and submission ids across all programs.
- Timestamps are nanoseconds (`env::block_timestamp()`), as `U64` strings in JSON.
- Durations in arguments are seconds.
- All text limits are **bytes** of UTF-8, not characters.

## Types (JSON)

```jsonc
// Severity
"critical" | "high" | "medium" | "low"

// Outcome posted by the verifier
"valid" | "invalid" | "duplicate" | "needs_human"

// Submission status
"pending"      // waiting for the verifier
"valid"        // verifier said valid; challenge window running, finalize() after it
"paid"         // hunter paid (final)
"invalid"      // verifier said invalid, bond slashed (final)
"duplicate"    // duplicate of an earlier valid submission, bond refunded minus fee (final)
"needs_human"  // verifier escalated; owner must resolve() before resolve_until
"disputed"     // owner disputed a valid verdict (with dispute bond); must resolve() before resolve_until
"rejected"     // owner resolved as invalid (final)
"expired"      // needs_human not resolved in time: full bond back (final)
"withdrawn"    // hunter withdrew while pending after the pending timeout (final)

// ScopeTarget
{ "chain_id": 1, "address": "0x..." }                // address <= 64 bytes

// Payouts
{ "critical": "U128", "high": "U128", "medium": "U128", "low": "U128" }

// VerdictInput (posted by the verifier)
{
  "outcome": "valid",
  "severity": "critical" | null,        // required for valid
  "duplicate_of": 3 | null,             // required for duplicate
  "fingerprint": "...",                 // <= 128 bytes, may be ""
  "evidence_sha256": "64 lowercase hex",
  "evidence_uri": "runs/...",           // <= 256 bytes, may be ""
  "chain_id": 1,                        // fork chain (0 = local, no fork)
  "fork_block": "U64",
  "reason": "short text"                // <= 280 bytes
}
```

## Programs

```
create_program(
  name: String,                 // 1..=80 bytes
  scope: Vec<ScopeTarget>,      // 0..=32; the contract only stores it, the verifier enforces it
  verifier_id: AccountId,       // the only account that may post verdicts for this program
  verifier_pubkey: String,      // base64 of the raw 32-byte X25519 key; hunters seal to it
  payouts: Payouts,             // at least one > 0
  bond: U128,                   // base bond per report
  verifier_fee: U128,           // per verdict, to verifier_id
  dispute_bond: U128,           // owner must attach this to dispute(); >= bond
  challenge_period_sec: u64,    // 60 ..= 30 days
  pending_timeout_sec: u64,     // 60 ..= 365 days: after it a pending report may be withdrawn
  resolve_timeout_sec: u64      // 60 ..= 30 days: deadline for the owner to resolve
                                //   needs_human and disputed submissions
) -> u64                        // #[payable], deposit >= 1 NEAR; pool = deposit - program storage
top_up(program_id)              // #[payable], anyone
set_active(program_id, active)  // owner; inactive = no new submissions, open ones still settle
withdraw_pool(program_id, amount: U128)   // owner; at most pool - reserved
```

`reserved` grows by `max_payout + verifier_fee` per open submission and is released when the
submission becomes final. `withdraw_pool` can never touch reserved funds.

## Commitments and sealed reports

**Commitment (v2, bound to the submitter):**

```
commitment = sha256( "replaycourt/commit/v2" || 0x00 || hunter_account_id || 0x00 || report_bytes )
```

The hash is lowercase hex. `hunter_account_id` is the account that calls `submit_report` /
`submit_report_from_vault`. Anyone who copies a sealed blob and its commitment from a failed or
pending transaction cannot reuse it from another account: the worker recomputes the commitment
with the submitting account and posts `invalid` ("sealed report does not match commitment") on a
mismatch. The contract only enforces that a commitment is used once.

**Sealed report (unchanged from v1):**
- ECIES with X25519, HKDF-SHA256 and AES-256-GCM, using Node's built-in crypto.
- Key derivation: `salt = epk_raw || recipient_pk_raw`, `info = "replaycourt/v1"`.
- The sealed string is base64 of the JSON
  `{"v":1,"alg":"x25519-hkdf-sha256-aes256gcm","epk","iv","ct","tag"}`.
- The sealed blob is at most 64 KiB.

## Submissions

```
submit_report(program_id, title, commitment, sealed) -> u64          // #[payable]
submit_report_from_vault(program_id, title, commitment, sealed) -> u64   // NOT payable, see vault
```

**Rules (both methods):**
- The program exists and is active. The title is 1..=120 bytes and public. The commitment is 64
  lowercase hex and unused.
- **Storage:** `storage_cost = (measured bytes + LATER_WRITES_STORAGE_BYTES) * storage_byte_cost`.
  The extra bytes pre-pay the verdict, dispute and resolution writes at their byte limits.
- **Bond:** `bond = deposit - storage_cost`, and it must be at least
  `required_bond(program_id, hunter)`. In the vault variant, exactly
  `required_bond + storage_cost` is drawn from the vault.
- **Program funds:** the program must be able to reserve `max_payout + verifier_fee` from
  `pool - reserved`.
- **Commit order:** the submission id. `submitted_block` and `submitted_at` are recorded.

**`required_bond(program_id, hunter_id)`** uses the hunter's stats **in this program only**, so
reputation farmed in a self-run program buys nothing elsewhere:
- `invalid > valid`: `bond * 2`
- `valid >= 3 && invalid == 0`: `bond / 4`
- `valid >= 1`: `bond / 2`
- otherwise: `bond`

## Verifier

```
post_verdict(submission_id, verdict: VerdictInput)    // NOT payable; works from a function-call key
```

- The caller is the program's `verifier_id`, and the status is `pending`.
- **valid:** severity is required. The status becomes `valid` and
  `valid_until = now + challenge_period`.
- **invalid:** `min(fee, bond)` goes to the verifier and the rest of the bond to the pool. The
  hunter's program and global stats count it as `invalid`.
- **duplicate:** `duplicate_of` must be an **earlier submission of the same program whose status
  is `valid`, `paid` or `disputed`**. An invalid, rejected, withdrawn, expired, pending or
  needs_human report can never be the original. `min(fee, bond)` goes to the verifier and the
  rest is refunded.
- **needs_human:** the status becomes `needs_human` and `resolve_until = now + resolve_timeout`.

## Settlement

```
finalize(submission_id)      // anyone
```

| status | condition | effect |
|---|---|---|
| `valid` | `now >= valid_until` | pay `min(payouts[severity], pool)`, refund bond, fee to verifier, `paid` |
| `disputed` | `now >= resolve_until` (owner did not resolve) | as `valid`, **plus the owner's dispute bond to the hunter**, `paid` |
| `needs_human` | `now >= resolve_until` (owner did not resolve) | full bond refund, no fee, `expired` |

```
dispute(submission_id, reason)   // #[payable]; program owner; status valid; now < valid_until;
                                 // attached deposit >= program.dispute_bond (excess refunded);
                                 // status disputed, resolve_until = now + resolve_timeout
resolve(submission_id, outcome, severity: Option<Severity>, note)
                                 // program owner; status needs_human | disputed; now < resolve_until
withdraw_pending(submission_id)  // hunter; status pending; now >= submitted_at + pending_timeout:
                                 // full bond refund, withdrawn
```

**`resolve` outcomes:**

| from | outcome | effect |
|---|---|---|
| `needs_human` | `valid` (severity required) | pay as finalize, `paid` |
| `needs_human` | `invalid` | slash as an invalid verdict, `rejected` |
| `needs_human` | `duplicate` | refund minus fee, `duplicate` |
| `disputed` | `valid` (severity optional, default the verifier's) | pay as finalize, `paid`; the dispute bond goes back to the owner, **unless the chosen severity pays less than the verifier's: then it goes to the hunter** and counts as overruled |
| `disputed` | `invalid` | **hunter gets the full bond plus the owner's dispute bond**, no fee, no strike on the hunter, `rejected` |
| `disputed` | `duplicate` | refused: a disputed report resolves as `valid` or `invalid` |

Every dispute counts in the program's public `stats.disputes`, and every overruled one in
`stats.overruled`. An owner can still refuse to pay a valid report, but it costs them the dispute
bond, which goes to the hunter, and it is visible on-chain. An owner who does nothing gets paid
out automatically after `resolve_until`.

## Hunter vault (agent spending policy on-chain)

A hunter account can pre-fund a vault inside the contract. It can then submit with a
**function-call access key** that may call only `submit_report_from_vault`, `finalize` and
`withdraw_pending`. Function-call keys cannot attach deposits, so they can neither change the
policy nor withdraw. Both of those need exactly 1 yoctoNEAR, which only a full-access key can
attach.

```
vault_deposit()                                    // #[payable] (> 0); creates the vault on first
                                                   //   use, its storage is taken from the deposit
vault_set_policy(max_bond_per_report: U128,        // #[payable], exactly 1 yoctoNEAR
                 max_spend_per_day: U128,          // rolling window of 24 h from window_start
                 allowed_programs: Option<Vec<u64>>)   // None = any program; <= 32 ids
vault_withdraw(amount: U128)                       // #[payable], exactly 1 yoctoNEAR
get_vault(account_id) -> Option<VaultView>
```

**`submit_report_from_vault`** follows these rules:
- It refuses if there is no vault or no policy has been set.
- It refuses if the program is not in `allowed_programs`.
- It refuses if `required_bond > max_bond_per_report`.
- It refuses if `spent_in_window + required_bond + storage_cost > max_spend_per_day`. The window
  restarts when `now >= window_start + 24 h`.
- It refuses if the balance is too low.
- **Bond refunds** of vault-funded submissions go back into the vault. These are refunds on
  `finalize`/`paid`, `duplicate`, `rejected` after an overruled dispute, `expired` and
  `withdrawn`.
- **Payouts** and **dispute bonds** go to the hunter account.

**VaultView:**

```jsonc
{ "account_id", "balance", "max_bond_per_report", "max_spend_per_day",
  "allowed_programs": [..] | null, "spent_in_window", "window_start", "policy_set": true }
```

## Views

```
version() -> String
get_program(program_id) -> Option<ProgramView>
list_programs(from_index, limit) -> Vec<ProgramView>
get_submission(submission_id) -> Option<SubmissionView>
list_submissions(program_id, from_index, limit) -> Vec<SubmissionView>
list_pending(program_id, from_index, limit) -> Vec<SubmissionView>     // per program (v2)
get_sealed(submission_id) -> Option<String>
get_hunter(account_id) -> HunterView                                     // global, display only
get_hunter_in_program(program_id, account_id) -> HunterView             // used for the bond
required_bond(program_id, hunter_id) -> U128
get_vault(account_id) -> Option<VaultView>
```

`limit` is capped at 50.

**ProgramView** adds `dispute_bond`, `resolve_timeout_sec` and `stats.overruled` to v1.

**SubmissionView** adds the following to v1:
- `valid_until`, `resolve_until`
- `dispute_bond` (held from the owner)
- `funded_by_vault`
- `storage_cost`

**HunterView:** `{ submissions, valid, invalid, duplicate, needs_human, earned }`.

## Events (NEP-297)

- `standard`: `"replaycourt"`, `version`: `"2.0.0"`.
- Events: `program_created`, `pool_topped_up`, `pool_withdrawn`, `report_submitted`,
  `verdict_posted`, `report_paid`, `bond_slashed`, `bond_refunded`, `report_disputed`,
  `report_resolved`, `report_expired`, `report_withdrawn`, `vault_deposited`, `vault_policy_set`,
  `vault_withdrawn`.
- `data` is a one-element array with ids, accounts and amounts.

## Init and trust

- `new(owner_id)`: the contract owner has no power over programs, vaults or funds.
- A production deployment removes the contract account's full-access keys, or hands upgrades to a
  DAO, so the code cannot be swapped.

## Evidence (worker)

The worker publishes `evidence.json` and posts `evidence_sha256 = sha256(evidence.json bytes)`
with `evidence_uri = "runs/<network>/<contract_id>/<submission_id>/evidence.json"`. The file binds
the engine's verdict to the submission:

```jsonc
{ "schema": "replaycourt.evidence/v1", "network": "testnet", "contract_id": "...",
  "program_id": 0, "submission_id": 7, "hunter_id": "...", "commitment": "...",
  "engine": { ...the engine's verdict.json... } }
```

A checker:
1. recomputes the hash;
2. compares `contract_id`, `program_id`, `submission_id`, `hunter_id` and `commitment` with the
   on-chain submission;
3. accepts only evidence URIs below `runs/`.

**Disclosure.** By default the worker keeps evidence of unsettled submissions private and
publishes it once the submission is final. Until then only the hash is on-chain, so the exploit
details of a live bug are not disclosed before the owner could react. The demo publishes
everything, because its reports re-enact historical incidents.

## Engine (replay verifier)

```
python3 -I engine/replay.py check <report.md> --json --registry <file> --report-id sub-<id> --dest <dir>
```

| exit | meaning |
|---|---|
| 0 | valid |
| 1 | invalid |
| 2 | needs human |
| 3 | duplicate |
| 64 | usage |
| 65 | unreadable report |
| 69 | infrastructure missing: no verdict, retry later |
| 70 | internal error: no verdict |

- **Duplicates (v2):** the registry only offers **valid** earlier reports as originals. Invalid
  and needs-human reports are recorded but never make a later report a duplicate.
- **Severity:** critical, high, medium, low.
