# Deviations from SPEC.md (contract v2.0.0)

The contract implements the interface of `../SPEC.md` (v2) as written: every method, argument,
view, status and event name. This file lists only what goes beyond the text or where the text
leaves a choice. Each point is covered by a unit test in `src/tests.rs`.

## Interpretations (SPEC.md leaves room)

1. **Pre-paid later writes.** `LATER_WRITES_STORAGE_BYTES = 1359`, the exact Borsh maximum of
   everything written after submission without a storage deposit:
   - a verdict with every optional field set and every text at its byte limit: 780 bytes;
   - a dispute reason of 280 bytes: 284 bytes;
   - a resolution note of 280 bytes with a severity: 295 bytes.

   Every other later write overwrites a fixed-size field or frees storage. This covers the
   status, `valid_until`, `resolve_until`, the dispute bond, the payout, the hunter stats, the
   vault balance and the pending index.
   - `later_writes_*` submit a minimal report and run the maximal sequence (verdict, dispute,
     resolution) with ASCII text, 4-byte UTF-8 text and a vault-funded bond. After every step,
     the storage used stays within what the hunter pre-paid.
   - `later_writes_constant_is_tight` shows that the record grows by exactly 1359 bytes.
2. **Vault storage.** The first `vault_deposit` pays the measured vault record plus 260 bytes, so
   a later `vault_set_policy`, which carries exactly 1 yoctoNEAR, can store 32
   `allowed_programs` ids. The 260 bytes are a 4-byte length plus 32 × 8 bytes. The test
   `vault_storage_prepay_covers_a_full_policy` shows that this prepay is exact. Storage fees,
   like all storage fees in the contract, are not refunded.
3. **The 1 yoctoNEAR** attached to `vault_set_policy` and `vault_withdraw` is credited to the
   caller's vault balance, so a full withdrawal can include it. This keeps the money audit
   exact.
4. **Spend window.**
   - The window opens with the first vault submission. Before that, `window_start` is 0.
   - It restarts on the next vault submission once `now >= window_start + 24 h`.
   - `spent_in_window` counts the gross amount drawn (bond + storage). Refunds into the vault
     do not lower it.
   - `vault_set_policy` does not reset the window.
   - `get_vault` returns the stored values. A window that has run out still shows its old
     `spent_in_window` until the next vault submission.
5. **Order of the vault refusals** in `submit_report_from_vault`:
   1. the generic submission checks (title, commitment, sealed blob, program exists);
   2. no vault;
   3. no policy;
   4. `allowed_programs`;
   5. `max_bond_per_report`;
   6. program active and funded;
   7. daily limit;
   8. balance.

   An unknown program id therefore fails with `program not found`, before the
   `allowed_programs` check.
6. **`list_pending(program_id, ...)`** reads a per-program index in O(1) per entry. The order is
   insertion order, except that removing an entry moves the last one into its position (no
   global sort). `from_index` counts positions in this index.
7. **Statistics.**
   - `required_bond` and `get_hunter_in_program` count `valid` = paid reports, including a
     dispute that timed out and `resolve valid`.
   - They count `invalid` = invalid verdicts and `needs_human` reports resolved invalid. An
     overruled dispute (disputed → invalid) is no strike.
   - Program `stats.invalid` counts invalid verdicts and both kinds of `rejected`.
   - `stats.overruled` counts only disputed → invalid. A dispute that runs out is not
     overruled: the verifier's verdict stands and the report is paid.
   - `stats.needs_human` counts escalations when the verifier posts them.
   - Expiries have no counter.
8. **Payment details.**
   - `finalize` and `resolve valid` send the payout, the bond (unless it goes back to the vault)
     and, if due, the dispute bond to the hunter as one transfer.
   - The verifier fee is `min(verifier_fee, pool - payout)`. The pool always covers it, because
     the full fee is part of the reservation.
   - When a disputed report is resolved valid without a severity, the verifier's severity is
     used and stored in the resolution.
9. **`resolve`** accepts `"valid" | "invalid" | "duplicate"`. A resolved duplicate has no
   `duplicate_of`, because `resolve` takes none. Deadlines are exclusive for `resolve`
   (`now < resolve_until`) and inclusive for `finalize` (`now >= resolve_until`), so there is no
   gap or overlap.
10. **Verdict fields.** `severity` and `duplicate_of` are stored as given for any outcome. They
    are only required where SPEC.md says so.

## Additions (backwards compatible)

11. **View fields.**
    - `SubmissionView.valid_until` and `resolve_until` are `null` until they are set.
    - `dispute_bond` is `"0"` for a report that was never disputed. After settlement it still
      shows the amount that was held.
12. **Event fields.** Events carry more fields than SPEC.md lists:
    - `bond_refunded` has `to` (`"vault"` or `"hunter"`) and `reason` (`paid`, `duplicate`,
      `withdrawn`, `expired`, `dispute_overruled`). For an overruled dispute it also has
      `dispute_bond` and `dispute_bond_to`.
    - `report_paid` has `dispute_bond` and `dispute_bond_to` (`"owner"`, `"hunter"` or `null`).
    - `report_disputed` has `dispute_bond`, `refunded_excess` and `resolve_until`.
    - `report_submitted` has `storage_cost` and `funded_by_vault`.
    - `program_created` has `storage_cost`.
    - `vault_deposited` has `storage_cost`.
    - `bond_refunded` is also emitted next to `report_paid`, `report_withdrawn` and
      `report_expired`, so every movement of a bond is logged.
13. **Extra input checks.**
    - `verifier_pubkey` must decode from base64 to exactly 32 bytes.
    - At least one payout must be > 0.
    - `sealed` must not be empty.
    - `evidence_sha256` must be 64 lowercase hex characters.
    - The dispute `reason` and the resolution `note` are at most 280 bytes.
14. **Optional verdict fields.** In `VerdictInput`, `severity`, `duplicate_of`, `fingerprint`
    and `evidence_uri` may be omitted. They default to `null` / `""`.
15. **Ids.** Submission and program ids are indexes of `near_sdk::store::Vector`, so they are
    below 2^32.

## Severity downgrade counts as an overrule

When the owner resolves a disputed report as `valid` with a severity whose payout is **lower**
than the payout for the verifier's severity, it is a partial overrule: the dispute bond goes to
the hunter (not back to the owner) and `stats.overruled` grows. With an equal or higher payout
the dispute bond goes back to the owner. Test:
`resolve_disputed_as_valid_with_lower_severity_costs_the_dispute_bond`.

## Known limits (not changed)

- **Commitment binding.** The binding of a commitment to its submitter is checked off-chain by
  the worker. The contract only enforces that a commitment is used once, as SPEC.md says. The
  test `s2_replayed_commitment_is_recorded_under_the_copier_and_cannot_match` documents both
  halves.
- **Failed transfers.** When a transfer fails (for example, the recipient account was
  deleted), the amount returns to the contract account but is not credited to any pool or
  vault.
- **Storage is never refunded.** Sealed blobs are never deleted.
- **Owner roles.** The program owner both funds the pool and resolves escalations. The dispute
  bond, `stats.disputes` and `stats.overruled` are the public counterweight.
