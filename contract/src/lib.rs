//! ReplayCourt: escrowed bug-bounty programs on NEAR (interface v2, see SPEC.md).
//!
//! A program owner escrows a pool. Hunters commit sealed (encrypted) reports and post a bond,
//! either with an attached deposit or from a pre-funded vault with an on-chain spending policy.
//! The program's verifier posts a verdict (valid / invalid / duplicate / needs_human) with a
//! function-call access key that can call nothing but `post_verdict`. Valid reports are paid
//! from the pool after a challenge window; invalid reports lose their bond to the pool. An owner
//! who disputes a valid verdict posts a dispute bond and must resolve before a deadline;
//! otherwise anyone can `finalize` and the hunter is paid plus the dispute bond.
//!
//! The contract owner has no power over programs, vaults or funds. Only the program owner can
//! withdraw the part of a pool that is not reserved for open submissions.

use near_sdk::json_types::{U64, U128};
use near_sdk::serde_json::{self, json};
use near_sdk::store::{LookupMap, Vector};
use near_sdk::{
    AccountId, BorshStorageKey, NearToken, PanicOnDefault, Promise, env, near, require,
};

pub mod types;
pub use types::*;

#[cfg(test)]
mod tests;

/// NEP-297 event standard name.
pub const EVENT_STANDARD: &str = "replaycourt";
pub const EVENT_VERSION: &str = "2.0.0";

pub const ONE_NEAR: u128 = 1_000_000_000_000_000_000_000_000;
pub const ONE_YOCTO: u128 = 1;
pub const MIN_INITIAL_POOL: u128 = ONE_NEAR;
pub const NANOS_PER_SEC: u64 = 1_000_000_000;
const DAY_SEC: u64 = 24 * 60 * 60;
/// Lower bound of every window and timeout (challenge, pending, resolve).
pub const MIN_WINDOW_SEC: u64 = 60;
pub const MAX_CHALLENGE_PERIOD_SEC: u64 = 30 * DAY_SEC;
pub const MAX_PENDING_TIMEOUT_SEC: u64 = 365 * DAY_SEC;
pub const MAX_RESOLVE_TIMEOUT_SEC: u64 = 30 * DAY_SEC;
/// Length of the vault's rolling spend window.
pub const VAULT_WINDOW_SEC: u64 = DAY_SEC;

// All text limits are bytes of UTF-8.
pub const MAX_NAME_BYTES: usize = 80;
pub const MAX_SCOPE_TARGETS: usize = 32;
pub const MAX_ADDRESS_BYTES: usize = 64;
pub const MAX_TITLE_BYTES: usize = 120;
pub const MAX_SEALED_BYTES: usize = 64 * 1024;
pub const MAX_FINGERPRINT_BYTES: usize = 128;
pub const MAX_EVIDENCE_URI_BYTES: usize = 256;
pub const MAX_REASON_BYTES: usize = 280;
pub const MAX_NOTE_BYTES: usize = 280;
pub const MAX_ALLOWED_PROGRAMS: usize = 32;
pub const MAX_PAGE: u64 = 50;

/// Borsh bytes a `Some(Verdict)` adds over `None` with every field at its limit: outcome 1,
/// `Some(severity)` 2, `Some(duplicate_of)` 9, fingerprint 4+128, evidence_sha256 4+64,
/// evidence_uri 4+256, chain_id 8, fork_block 8, reason 4+280, posted_at 8.
pub const VERDICT_MAX_BYTES: u64 =
    1 + 2 + 9 + (4 + 128) + (4 + 64) + (4 + 256) + 8 + 8 + (4 + 280) + 8;
/// `Some(dispute_reason)` over `None`: 4-byte length + 280 bytes.
pub const DISPUTE_REASON_MAX_BYTES: u64 = 4 + MAX_NOTE_BYTES as u64;
/// `Some(Resolution)` over `None`: outcome 1, `Some(severity)` 2, note 4+280, at 8.
pub const RESOLUTION_MAX_BYTES: u64 = 1 + 2 + (4 + MAX_NOTE_BYTES as u64) + 8;
/// Storage bytes pre-paid at submission for everything written later without a storage
/// deposit: the verdict, a dispute reason and a resolution note, each at its byte limit. All
/// other later writes (status, `valid_until`, `resolve_until`, `dispute_bond`, payout, stats,
/// vault balance, pending index) overwrite fixed-size fields or free storage. `post_verdict`
/// must work from a function-call key, so it cannot charge for its own storage.
pub const LATER_WRITES_STORAGE_BYTES: u64 =
    VERDICT_MAX_BYTES + DISPUTE_REASON_MAX_BYTES + RESOLUTION_MAX_BYTES;
/// Storage bytes pre-paid when a vault is created, so `vault_set_policy` (exactly 1 yoctoNEAR)
/// can store up to 32 allowed program ids: 4-byte length + 32 * 8 bytes.
pub const VAULT_POLICY_STORAGE_BYTES: u64 = 4 + 8 * MAX_ALLOWED_PROGRAMS as u64;

#[near(serializers = [borsh])]
#[derive(BorshStorageKey)]
enum StorageKey {
    Programs,
    Submissions,
    Sealed,
    Commitments,
    Hunters,
    ProgramHunters,
    ProgramSubmissions,
    PendingItems,
    PendingIndex,
    Vaults,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    /// Deployer-chosen owner. Has no power over programs, vaults or funds (by design).
    owner_id: AccountId,
    programs: Vector<Program>,
    submissions: Vector<Submission>,
    sealed: LookupMap<u64, String>,
    /// commitment (sha256 hex) -> submission id; makes every commitment single-use.
    commitments: LookupMap<String, u64>,
    /// Global hunter stats (display only).
    hunters: LookupMap<AccountId, HunterStats>,
    /// Hunter stats per program; `required_bond` uses only these.
    program_hunters: LookupMap<(u64, AccountId), HunterStats>,
    /// (program_id, n-th submission of that program) -> submission id.
    program_submissions: LookupMap<(u64, u64), u64>,
    /// Per-program pending index: (program_id, position) -> submission id, positions
    /// `0..program.pending_count`. Removal moves the last entry into the freed position.
    pending_items: LookupMap<(u64, u64), u64>,
    /// submission id -> its position in `pending_items` (only while pending).
    pending_index: LookupMap<u64, u64>,
    vaults: LookupMap<AccountId, Vault>,
}

fn emit(event: &str, data: serde_json::Value) {
    let ev = json!({
        "standard": EVENT_STANDARD,
        "version": EVENT_VERSION,
        "event": event,
        "data": [data],
    });
    env::log_str(&format!("EVENT_JSON:{}", ev));
}

fn transfer(to: &AccountId, amount: u128) {
    if amount > 0 {
        Promise::new(to.clone())
            .transfer(NearToken::from_yoctonear(amount))
            .detach();
    }
}

fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn idx(id: u64) -> Option<u32> {
    u32::try_from(id).ok()
}

fn secs_to_nanos(secs: u64) -> u64 {
    secs.saturating_mul(NANOS_PER_SEC)
}

fn parse_outcome(outcome: &str) -> Outcome {
    match outcome {
        "valid" => Outcome::Valid,
        "invalid" => Outcome::Invalid,
        "duplicate" => Outcome::Duplicate,
        _ => env::panic_str("outcome must be one of: valid, invalid, duplicate"),
    }
}

fn severity_str(s: Option<Severity>) -> Option<&'static str> {
    s.map(|s| s.as_str())
}

fn require_one_yocto() {
    require!(
        env::attached_deposit().as_yoctonear() == ONE_YOCTO,
        "requires an attached deposit of exactly 1 yoctoNEAR (full-access key)"
    );
}

fn storage_cost_of(bytes: u64) -> u128 {
    env::storage_byte_cost().as_yoctonear() * bytes as u128
}

/// How a submission's bond and storage are paid.
enum Funding {
    /// Attached deposit (`submit_report`).
    Deposit(u128),
    /// Drawn from the hunter's vault (`submit_report_from_vault`).
    Vault,
}

/// Where a held dispute bond goes when a disputed submission is paid.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DisputeBondTo {
    Owner,
    Hunter,
}

#[near]
impl Contract {
    #[init]
    pub fn new(owner_id: AccountId) -> Self {
        Self {
            owner_id,
            programs: Vector::new(StorageKey::Programs),
            submissions: Vector::new(StorageKey::Submissions),
            sealed: LookupMap::new(StorageKey::Sealed),
            commitments: LookupMap::new(StorageKey::Commitments),
            hunters: LookupMap::new(StorageKey::Hunters),
            program_hunters: LookupMap::new(StorageKey::ProgramHunters),
            program_submissions: LookupMap::new(StorageKey::ProgramSubmissions),
            pending_items: LookupMap::new(StorageKey::PendingItems),
            pending_index: LookupMap::new(StorageKey::PendingIndex),
            vaults: LookupMap::new(StorageKey::Vaults),
        }
    }

    // ------------------------------------------------------------------ programs

    /// Creates a bounty program. The attached deposit (>= 1 NEAR) funds the pool; the storage
    /// used by the program record is deducted from it. Returns the program id.
    #[payable]
    #[allow(clippy::too_many_arguments)]
    pub fn create_program(
        &mut self,
        name: String,
        scope: Vec<ScopeTarget>,
        verifier_id: AccountId,
        verifier_pubkey: String,
        payouts: Payouts,
        bond: U128,
        verifier_fee: U128,
        dispute_bond: U128,
        challenge_period_sec: u64,
        pending_timeout_sec: u64,
        resolve_timeout_sec: u64,
    ) -> u64 {
        let deposit = env::attached_deposit().as_yoctonear();
        require!(
            deposit >= MIN_INITIAL_POOL,
            "attached deposit must be at least 1 NEAR (initial pool)"
        );
        require!(
            (1..=MAX_NAME_BYTES).contains(&name.len()),
            "name must be 1..=80 bytes"
        );
        require!(
            scope.len() <= MAX_SCOPE_TARGETS,
            "scope must have at most 32 targets"
        );
        for t in &scope {
            require!(
                t.address.len() <= MAX_ADDRESS_BYTES,
                "scope address must be at most 64 bytes"
            );
        }
        Self::check_pubkey(&verifier_pubkey);
        require!(
            (MIN_WINDOW_SEC..=MAX_CHALLENGE_PERIOD_SEC).contains(&challenge_period_sec),
            "challenge_period_sec must be between 60 s and 30 days"
        );
        require!(
            (MIN_WINDOW_SEC..=MAX_PENDING_TIMEOUT_SEC).contains(&pending_timeout_sec),
            "pending_timeout_sec must be between 60 s and 365 days"
        );
        require!(
            (MIN_WINDOW_SEC..=MAX_RESOLVE_TIMEOUT_SEC).contains(&resolve_timeout_sec),
            "resolve_timeout_sec must be between 60 s and 30 days"
        );
        require!(
            payouts.max() > 0,
            "at least one payout must be greater than zero"
        );
        require!(
            dispute_bond.0 >= bond.0,
            "dispute_bond must be at least the bond"
        );

        self.flush_all();
        let before = env::storage_usage();

        let id = self.programs.len() as u64;
        let owner_id = env::predecessor_account_id();
        self.programs.push(Program {
            id,
            owner_id: owner_id.clone(),
            name,
            scope,
            verifier_id: verifier_id.clone(),
            verifier_pubkey,
            payouts,
            bond: bond.0,
            verifier_fee: verifier_fee.0,
            dispute_bond: dispute_bond.0,
            challenge_period_sec,
            pending_timeout_sec,
            resolve_timeout_sec,
            pool: 0,
            reserved: 0,
            active: true,
            stats: ProgramStats::default(),
            created_at: env::block_timestamp(),
            pending_count: 0,
        });
        self.flush_all();
        let used = env::storage_usage().saturating_sub(before);
        let storage_cost = storage_cost_of(used);
        require!(
            deposit > storage_cost,
            "attached deposit does not cover the program storage"
        );
        let pool = deposit - storage_cost;
        self.program_mut(id).pool = pool;

        emit(
            "program_created",
            json!({
                "program_id": id,
                "owner_id": owner_id,
                "verifier_id": verifier_id,
                "pool": U128(pool),
                "storage_cost": U128(storage_cost),
                "bond": bond,
                "verifier_fee": verifier_fee,
                "dispute_bond": dispute_bond,
                "challenge_period_sec": challenge_period_sec,
                "pending_timeout_sec": pending_timeout_sec,
                "resolve_timeout_sec": resolve_timeout_sec,
            }),
        );
        id
    }

    /// Adds the attached deposit to the program pool. Anyone may top up.
    #[payable]
    pub fn top_up(&mut self, program_id: u64) {
        let amount = env::attached_deposit().as_yoctonear();
        require!(amount > 0, "attach a deposit to top up the pool");
        let p = self.program_mut(program_id);
        p.pool = p.pool.checked_add(amount).expect("pool overflow");
        let pool = p.pool;
        emit(
            "pool_topped_up",
            json!({
                "program_id": program_id,
                "account_id": env::predecessor_account_id(),
                "amount": U128(amount),
                "pool": U128(pool),
            }),
        );
    }

    /// Program owner only. Inactive programs accept no new submissions; open ones still settle.
    pub fn set_active(&mut self, program_id: u64, active: bool) {
        let caller = env::predecessor_account_id();
        let p = self.program_mut(program_id);
        require!(caller == p.owner_id, "only the program owner can do this");
        p.active = active;
    }

    /// Program owner only. Withdraws at most `pool - reserved`; funds reserved for open
    /// submissions can never be withdrawn.
    pub fn withdraw_pool(&mut self, program_id: u64, amount: U128) {
        let caller = env::predecessor_account_id();
        let p = self.program_mut(program_id);
        require!(caller == p.owner_id, "only the program owner can do this");
        require!(amount.0 > 0, "amount must be greater than zero");
        require!(
            amount.0 <= p.available(),
            "amount exceeds the unreserved part of the pool"
        );
        p.pool -= amount.0;
        let (pool, reserved, owner) = (p.pool, p.reserved, p.owner_id.clone());
        transfer(&owner, amount.0);
        emit(
            "pool_withdrawn",
            json!({
                "program_id": program_id,
                "owner_id": owner,
                "amount": amount,
                "pool": U128(pool),
                "reserved": U128(reserved),
            }),
        );
    }

    // --------------------------------------------------------------- submissions

    /// Commits a sealed report. The attached deposit pays the storage used (plus the
    /// pre-paid later writes); the rest is the bond and must be at least
    /// `required_bond(program_id, hunter)`. Returns the submission id.
    #[payable]
    pub fn submit_report(
        &mut self,
        program_id: u64,
        title: String,
        commitment: String,
        sealed: String,
    ) -> u64 {
        let deposit = env::attached_deposit().as_yoctonear();
        self.submit_internal(
            program_id,
            title,
            commitment,
            sealed,
            Funding::Deposit(deposit),
        )
    }

    /// Like `submit_report`, but exactly `required_bond + storage_cost` is drawn from the
    /// caller's vault, inside its spending policy. Not payable: works from a function-call key.
    pub fn submit_report_from_vault(
        &mut self,
        program_id: u64,
        title: String,
        commitment: String,
        sealed: String,
    ) -> u64 {
        self.submit_internal(program_id, title, commitment, sealed, Funding::Vault)
    }

    // ------------------------------------------------------------------ verifier

    /// Verifier only. Not payable, needs no deposit: works from a function-call access key.
    pub fn post_verdict(&mut self, submission_id: u64, verdict: VerdictInput) {
        let caller = env::predecessor_account_id();
        let s = self.submission(submission_id).clone();
        let p = self.program(s.program_id).clone();
        require!(
            caller == p.verifier_id,
            "only the program verifier can post verdicts"
        );
        require!(s.status == Status::Pending, "submission is not pending");
        require!(
            is_lower_hex_64(&verdict.evidence_sha256),
            "evidence_sha256 must be 64 lowercase hex characters"
        );
        require!(
            verdict.fingerprint.len() <= MAX_FINGERPRINT_BYTES,
            "fingerprint must be at most 128 bytes"
        );
        require!(
            verdict.evidence_uri.len() <= MAX_EVIDENCE_URI_BYTES,
            "evidence_uri must be at most 256 bytes"
        );
        require!(
            verdict.reason.len() <= MAX_REASON_BYTES,
            "reason must be at most 280 bytes"
        );
        match verdict.outcome {
            Outcome::Valid => require!(
                verdict.severity.is_some(),
                "severity is required for a valid verdict"
            ),
            Outcome::Duplicate => {
                let orig_id = verdict
                    .duplicate_of
                    .unwrap_or_else(|| env::panic_str("duplicate_of is required for a duplicate"));
                require!(
                    orig_id < submission_id,
                    "duplicate_of must be an earlier submission"
                );
                let (orig_program, orig_status) = idx(orig_id)
                    .and_then(|i| self.submissions.get(i))
                    .map(|o| (o.program_id, o.status))
                    .unwrap_or_else(|| env::panic_str("duplicate_of does not exist"));
                require!(
                    orig_program == s.program_id,
                    "duplicate_of must belong to the same program"
                );
                require!(
                    matches!(orig_status, Status::Valid | Status::Paid | Status::Disputed),
                    "duplicate_of must be a valid, paid or disputed submission"
                );
            }
            _ => {}
        }

        let now = env::block_timestamp();
        self.pending_remove(s.program_id, submission_id);
        {
            let sm = self.submission_mut(submission_id);
            sm.verdict = Some(Verdict {
                outcome: verdict.outcome,
                severity: verdict.severity,
                duplicate_of: verdict.duplicate_of,
                fingerprint: verdict.fingerprint.clone(),
                evidence_sha256: verdict.evidence_sha256.clone(),
                evidence_uri: verdict.evidence_uri.clone(),
                chain_id: verdict.chain_id,
                fork_block: verdict.fork_block.0,
                reason: verdict.reason.clone(),
                posted_at: now,
            });
        }
        emit(
            "verdict_posted",
            json!({
                "submission_id": submission_id,
                "program_id": s.program_id,
                "verifier_id": caller,
                "outcome": verdict.outcome.as_str(),
                "severity": severity_str(verdict.severity),
                "duplicate_of": verdict.duplicate_of,
                "evidence_sha256": verdict.evidence_sha256,
                "evidence_uri": verdict.evidence_uri,
            }),
        );

        match verdict.outcome {
            Outcome::Valid => {
                let sm = self.submission_mut(submission_id);
                sm.status = Status::Valid;
                sm.valid_until = now.saturating_add(secs_to_nanos(p.challenge_period_sec));
            }
            Outcome::NeedsHuman => {
                {
                    let sm = self.submission_mut(submission_id);
                    sm.status = Status::NeedsHuman;
                    sm.resolve_until = now.saturating_add(secs_to_nanos(p.resolve_timeout_sec));
                }
                self.program_mut(s.program_id).stats.needs_human += 1;
                self.hunter_update(s.program_id, &s.hunter_id, |h| h.needs_human += 1);
            }
            Outcome::Invalid => {
                self.slash(submission_id, true, Status::Invalid);
            }
            Outcome::Duplicate => {
                self.refund_duplicate(submission_id);
            }
        }
    }

    // ---------------------------------------------------------------- settlement

    /// Anyone. Settles a submission whose deadline has passed:
    /// - `valid` after the challenge window: pays the hunter, status `paid`;
    /// - `disputed` after `resolve_until`: pays as valid plus the owner's dispute bond to the
    ///   hunter, status `paid`;
    /// - `needs_human` after `resolve_until`: full bond refund, no fee, status `expired`.
    pub fn finalize(&mut self, submission_id: u64) {
        let s = self.submission(submission_id).clone();
        let now = env::block_timestamp();
        match s.status {
            Status::Valid => {
                require!(now >= s.valid_until, "challenge window has not ended yet");
                self.pay(submission_id, Self::verdict_severity(&s), None);
            }
            Status::Disputed => {
                require!(
                    now >= s.resolve_until,
                    "resolve deadline has not passed yet"
                );
                self.pay(
                    submission_id,
                    Self::verdict_severity(&s),
                    Some(DisputeBondTo::Hunter),
                );
            }
            Status::NeedsHuman => {
                require!(
                    now >= s.resolve_until,
                    "resolve deadline has not passed yet"
                );
                self.expire(submission_id);
            }
            _ => env::panic_str("only valid, disputed or needs_human submissions can be finalized"),
        }
    }

    /// Program owner only, while the submission is `valid` and inside its challenge window.
    /// The attached deposit must cover the program's `dispute_bond` (the excess is refunded);
    /// the bond is held until the dispute is settled. The owner must `resolve` before
    /// `resolve_until`, otherwise anyone can `finalize` and the hunter is paid plus the bond.
    #[payable]
    pub fn dispute(&mut self, submission_id: u64, reason: String) {
        let caller = env::predecessor_account_id();
        let deposit = env::attached_deposit().as_yoctonear();
        let s = self.submission(submission_id).clone();
        let program_id = s.program_id;
        let (owner_id, dispute_bond, resolve_timeout_sec) = {
            let p = self.program(program_id);
            (p.owner_id.clone(), p.dispute_bond, p.resolve_timeout_sec)
        };
        require!(caller == owner_id, "only the program owner can do this");
        require!(
            s.status == Status::Valid,
            "only a valid verdict can be disputed"
        );
        let now = env::block_timestamp();
        require!(now < s.valid_until, "challenge window has ended");
        require!(
            reason.len() <= MAX_NOTE_BYTES,
            "reason must be at most 280 bytes"
        );
        if deposit < dispute_bond {
            env::panic_str(&format!(
                "attached deposit {} is below the program's dispute bond {}",
                deposit, dispute_bond
            ));
        }
        let resolve_until = now.saturating_add(secs_to_nanos(resolve_timeout_sec));
        {
            let sm = self.submission_mut(submission_id);
            sm.status = Status::Disputed;
            sm.dispute_reason = Some(reason.clone());
            sm.dispute_bond = dispute_bond;
            sm.resolve_until = resolve_until;
        }
        self.program_mut(program_id).stats.disputes += 1;
        let excess = deposit - dispute_bond;
        transfer(&caller, excess);
        emit(
            "report_disputed",
            json!({
                "submission_id": submission_id,
                "program_id": program_id,
                "owner_id": caller,
                "hunter_id": s.hunter_id,
                "reason": reason,
                "dispute_bond": U128(dispute_bond),
                "refunded_excess": U128(excess),
                "resolve_until": U64(resolve_until),
            }),
        );
    }

    /// Program owner only, for `needs_human` or `disputed` submissions, before
    /// `resolve_until`.
    /// - `needs_human`: "valid" (pays now, needs `severity`), "invalid" (slash, `rejected`),
    ///   "duplicate" (refund minus verifier fee).
    /// - `disputed`: "valid" (pays now, severity defaults to the verifier's, dispute bond back
    ///   to the owner) or "invalid" (`rejected`: the hunter gets the bond plus the dispute bond,
    ///   no fee, no strike). "duplicate" is refused.
    pub fn resolve(
        &mut self,
        submission_id: u64,
        outcome: String,
        severity: Option<Severity>,
        note: String,
    ) {
        let caller = env::predecessor_account_id();
        let s = self.submission(submission_id).clone();
        let program_id = s.program_id;
        require!(
            caller == self.program(program_id).owner_id,
            "only the program owner can do this"
        );
        require!(
            matches!(s.status, Status::NeedsHuman | Status::Disputed),
            "only needs_human or disputed submissions can be resolved"
        );
        require!(
            env::block_timestamp() < s.resolve_until,
            "resolve deadline has passed; use finalize"
        );
        require!(
            note.len() <= MAX_NOTE_BYTES,
            "note must be at most 280 bytes"
        );
        let outcome = parse_outcome(&outcome);
        let disputed = s.status == Status::Disputed;
        let severity = match outcome {
            Outcome::Valid if disputed => Some(severity.unwrap_or(Self::verdict_severity(&s))),
            Outcome::Valid => {
                require!(
                    severity.is_some(),
                    "severity is required to resolve as valid"
                );
                severity
            }
            Outcome::Duplicate if disputed => {
                env::panic_str("a disputed report resolves as valid or invalid")
            }
            _ => severity,
        };
        self.submission_mut(submission_id).resolution = Some(Resolution {
            outcome,
            severity,
            note: note.clone(),
            at: env::block_timestamp(),
        });
        emit(
            "report_resolved",
            json!({
                "submission_id": submission_id,
                "program_id": program_id,
                "owner_id": caller,
                "previous_status": s.status,
                "outcome": outcome.as_str(),
                "severity": severity_str(severity),
                "note": note,
            }),
        );
        match outcome {
            Outcome::Valid if disputed => {
                // Resolving with a severity that pays less than the verifier's is a partial
                // overrule: it costs the owner the dispute bond, like a full one.
                let new = severity.unwrap();
                let lowered = {
                    let p = self.program(program_id);
                    p.payouts.for_severity(new) < p.payouts.for_severity(Self::verdict_severity(&s))
                };
                let to = if lowered {
                    self.program_mut(program_id).stats.overruled += 1;
                    DisputeBondTo::Hunter
                } else {
                    DisputeBondTo::Owner
                };
                self.pay(submission_id, new, Some(to))
            }
            Outcome::Valid => self.pay(submission_id, severity.unwrap(), None),
            Outcome::Invalid if disputed => self.reject_disputed(submission_id),
            Outcome::Invalid => self.slash(submission_id, true, Status::Rejected),
            Outcome::Duplicate => self.refund_duplicate(submission_id),
            Outcome::NeedsHuman => unreachable!(),
        }
    }

    /// Hunter only. A report still `pending` after the program's pending timeout can be
    /// withdrawn; the full bond is refunded (into the vault if it came from there).
    pub fn withdraw_pending(&mut self, submission_id: u64) {
        let caller = env::predecessor_account_id();
        let s = self.submission(submission_id).clone();
        require!(caller == s.hunter_id, "only the hunter can withdraw");
        require!(s.status == Status::Pending, "submission is not pending");
        let timeout = secs_to_nanos(self.program(s.program_id).pending_timeout_sec);
        require!(
            env::block_timestamp() >= s.submitted_at.saturating_add(timeout),
            "pending timeout has not passed yet"
        );
        self.pending_remove(s.program_id, submission_id);
        self.release(s.program_id, s.reserved);
        self.submission_mut(submission_id).status = Status::Withdrawn;
        let (to_hunter, to) = self.refund_target(&s, s.bond);
        transfer(&s.hunter_id, to_hunter);
        emit(
            "report_withdrawn",
            json!({
                "submission_id": submission_id,
                "program_id": s.program_id,
                "hunter_id": s.hunter_id,
                "bond": U128(s.bond),
            }),
        );
        emit(
            "bond_refunded",
            json!({
                "submission_id": submission_id,
                "program_id": s.program_id,
                "hunter_id": s.hunter_id,
                "amount": U128(s.bond),
                "to": to,
                "verifier_fee": U128(0),
                "reason": "withdrawn",
            }),
        );
    }

    // --------------------------------------------------------------------- vault

    /// Funds the caller's vault. The first deposit creates the vault; its storage (including
    /// room for a full `allowed_programs` list) is taken from that deposit.
    #[payable]
    pub fn vault_deposit(&mut self) {
        let amount = env::attached_deposit().as_yoctonear();
        require!(amount > 0, "attach a deposit to fund the vault");
        let account_id = env::predecessor_account_id();
        let mut storage_cost = 0;
        let balance = if let Some(v) = self.vaults.get_mut(&account_id) {
            v.balance = v.balance.checked_add(amount).expect("vault overflow");
            v.balance
        } else {
            self.flush_all();
            let before = env::storage_usage();
            self.vaults.insert(account_id.clone(), Vault::default());
            self.flush_all();
            let used = env::storage_usage().saturating_sub(before) + VAULT_POLICY_STORAGE_BYTES;
            storage_cost = storage_cost_of(used);
            if amount <= storage_cost {
                env::panic_str(&format!(
                    "attached deposit {} does not cover the vault storage {}",
                    amount, storage_cost
                ));
            }
            let v = self.vaults.get_mut(&account_id).unwrap();
            v.balance = amount - storage_cost;
            v.balance
        };
        emit(
            "vault_deposited",
            json!({
                "account_id": account_id,
                "amount": U128(amount),
                "storage_cost": U128(storage_cost),
                "balance": U128(balance),
            }),
        );
    }

    /// Sets the spending policy of the caller's vault. Needs exactly 1 yoctoNEAR, so only a
    /// full-access key can call it (the yoctoNEAR is credited to the vault). The spend window
    /// is not reset.
    #[payable]
    pub fn vault_set_policy(
        &mut self,
        max_bond_per_report: U128,
        max_spend_per_day: U128,
        allowed_programs: Option<Vec<u64>>,
    ) {
        require_one_yocto();
        if let Some(list) = &allowed_programs {
            require!(
                list.len() <= MAX_ALLOWED_PROGRAMS,
                "allowed_programs must have at most 32 ids"
            );
        }
        let account_id = env::predecessor_account_id();
        let v = self
            .vaults
            .get_mut(&account_id)
            .unwrap_or_else(|| env::panic_str("no vault for this account; call vault_deposit"));
        v.balance += ONE_YOCTO;
        v.max_bond_per_report = max_bond_per_report.0;
        v.max_spend_per_day = max_spend_per_day.0;
        v.allowed_programs = allowed_programs.clone();
        v.policy_set = true;
        emit(
            "vault_policy_set",
            json!({
                "account_id": account_id,
                "max_bond_per_report": max_bond_per_report,
                "max_spend_per_day": max_spend_per_day,
                "allowed_programs": allowed_programs,
            }),
        );
    }

    /// Withdraws from the caller's vault. Needs exactly 1 yoctoNEAR (full-access key only);
    /// the yoctoNEAR is credited to the vault first.
    #[payable]
    pub fn vault_withdraw(&mut self, amount: U128) {
        require_one_yocto();
        require!(amount.0 > 0, "amount must be greater than zero");
        let account_id = env::predecessor_account_id();
        let v = self
            .vaults
            .get_mut(&account_id)
            .unwrap_or_else(|| env::panic_str("no vault for this account; call vault_deposit"));
        v.balance += ONE_YOCTO;
        require!(amount.0 <= v.balance, "amount exceeds the vault balance");
        v.balance -= amount.0;
        let balance = v.balance;
        transfer(&account_id, amount.0);
        emit(
            "vault_withdrawn",
            json!({
                "account_id": account_id,
                "amount": amount,
                "balance": U128(balance),
            }),
        );
    }

    // --------------------------------------------------------------------- views

    pub fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    pub fn get_program(&self, program_id: u64) -> Option<ProgramView> {
        idx(program_id)
            .and_then(|i| self.programs.get(i))
            .map(|p| p.view())
    }

    pub fn list_programs(&self, from_index: u64, limit: u64) -> Vec<ProgramView> {
        let len = self.programs.len() as u64;
        let limit = limit.min(MAX_PAGE);
        (from_index..len.min(from_index.saturating_add(limit)))
            .filter_map(|i| self.programs.get(i as u32).map(|p| p.view()))
            .collect()
    }

    pub fn get_submission(&self, submission_id: u64) -> Option<SubmissionView> {
        idx(submission_id)
            .and_then(|i| self.submissions.get(i))
            .map(|s| s.view())
    }

    pub fn list_submissions(
        &self,
        program_id: u64,
        from_index: u64,
        limit: u64,
    ) -> Vec<SubmissionView> {
        let count = match idx(program_id).and_then(|i| self.programs.get(i)) {
            Some(p) => p.stats.submissions,
            None => return vec![],
        };
        let limit = limit.min(MAX_PAGE);
        (from_index..count.min(from_index.saturating_add(limit)))
            .filter_map(|n| self.program_submissions.get(&(program_id, n)))
            .filter_map(|id| self.submissions.get(*id as u32).map(|s| s.view()))
            .collect()
    }

    /// Pending submissions of one program, read from the program's own pending index: the cost
    /// does not depend on other programs. Positions are insertion order, except that a
    /// submission leaving the index moves the last one into its position.
    pub fn list_pending(
        &self,
        program_id: u64,
        from_index: u64,
        limit: u64,
    ) -> Vec<SubmissionView> {
        let count = match idx(program_id).and_then(|i| self.programs.get(i)) {
            Some(p) => p.pending_count,
            None => return vec![],
        };
        let limit = limit.min(MAX_PAGE);
        (from_index..count.min(from_index.saturating_add(limit)))
            .filter_map(|pos| self.pending_items.get(&(program_id, pos)))
            .filter_map(|id| self.submissions.get(*id as u32).map(|s| s.view()))
            .collect()
    }

    pub fn get_sealed(&self, submission_id: u64) -> Option<String> {
        self.sealed.get(&submission_id).cloned()
    }

    /// Global stats across all programs (display only; the bond uses per-program stats).
    pub fn get_hunter(&self, account_id: AccountId) -> HunterView {
        self.hunters
            .get(&account_id)
            .cloned()
            .unwrap_or_default()
            .view()
    }

    /// The hunter's stats in one program; `required_bond` uses these.
    pub fn get_hunter_in_program(&self, program_id: u64, account_id: AccountId) -> HunterView {
        self.program_hunters
            .get(&(program_id, account_id))
            .cloned()
            .unwrap_or_default()
            .view()
    }

    pub fn required_bond(&self, program_id: u64, hunter_id: AccountId) -> U128 {
        U128(self.required_bond_internal(program_id, &hunter_id))
    }

    pub fn get_vault(&self, account_id: AccountId) -> Option<VaultView> {
        self.vaults
            .get(&account_id)
            .map(|v| v.view(account_id.clone()))
    }
}

// ------------------------------------------------------------------- internals

impl Contract {
    fn check_pubkey(pk: &str) {
        use near_sdk::base64::Engine;
        use near_sdk::base64::engine::general_purpose::STANDARD;
        let ok = pk.len() == 44
            && STANDARD
                .decode(pk.as_bytes())
                .map(|b| b.len() == 32)
                .unwrap_or(false);
        require!(
            ok,
            "verifier_pubkey must be base64 of a raw 32-byte X25519 public key"
        );
    }

    fn program(&self, program_id: u64) -> &Program {
        idx(program_id)
            .and_then(|i| self.programs.get(i))
            .unwrap_or_else(|| env::panic_str("program not found"))
    }

    fn program_mut(&mut self, program_id: u64) -> &mut Program {
        idx(program_id)
            .and_then(|i| self.programs.get_mut(i))
            .unwrap_or_else(|| env::panic_str("program not found"))
    }

    fn submission(&self, submission_id: u64) -> &Submission {
        idx(submission_id)
            .and_then(|i| self.submissions.get(i))
            .unwrap_or_else(|| env::panic_str("submission not found"))
    }

    fn submission_mut(&mut self, submission_id: u64) -> &mut Submission {
        idx(submission_id)
            .and_then(|i| self.submissions.get_mut(i))
            .unwrap_or_else(|| env::panic_str("submission not found"))
    }

    fn verdict_severity(s: &Submission) -> Severity {
        s.verdict
            .as_ref()
            .and_then(|v| v.severity)
            .unwrap_or_else(|| env::panic_str("valid verdict without severity"))
    }

    fn required_bond_internal(&self, program_id: u64, hunter_id: &AccountId) -> u128 {
        let bond = self.program(program_id).bond;
        let h = self
            .program_hunters
            .get(&(program_id, hunter_id.clone()))
            .cloned()
            .unwrap_or_default();
        if h.invalid > h.valid {
            bond.saturating_mul(2)
        } else if h.valid >= 3 && h.invalid == 0 {
            bond / 4
        } else if h.valid >= 1 {
            bond / 2
        } else {
            bond
        }
    }

    /// Applies `f` to the hunter's stats in `program_id` and to the global stats.
    fn hunter_update(
        &mut self,
        program_id: u64,
        hunter_id: &AccountId,
        f: impl Fn(&mut HunterStats),
    ) {
        let key = (program_id, hunter_id.clone());
        let mut h = self.program_hunters.get(&key).cloned().unwrap_or_default();
        f(&mut h);
        self.program_hunters.insert(key, h);
        let mut g = self.hunters.get(hunter_id).cloned().unwrap_or_default();
        f(&mut g);
        self.hunters.insert(hunter_id.clone(), g);
    }

    fn submit_internal(
        &mut self,
        program_id: u64,
        title: String,
        commitment: String,
        sealed: String,
        funding: Funding,
    ) -> u64 {
        let hunter_id = env::predecessor_account_id();
        require!(
            (1..=MAX_TITLE_BYTES).contains(&title.len()),
            "title must be 1..=120 bytes"
        );
        require!(
            is_lower_hex_64(&commitment),
            "commitment must be 64 lowercase hex characters (sha256)"
        );
        require!(!sealed.is_empty(), "sealed report must not be empty");
        require!(
            sealed.len() <= MAX_SEALED_BYTES,
            "sealed report must be at most 64 KiB"
        );
        require!(
            !self.commitments.contains_key(&commitment),
            "commitment already used"
        );
        let required = self.required_bond_internal(program_id, &hunter_id);
        let from_vault = match funding {
            Funding::Deposit(deposit) => {
                if deposit < required {
                    env::panic_str(&format!(
                        "attached deposit {} is too small: required bond {} plus storage",
                        deposit, required
                    ));
                }
                false
            }
            Funding::Vault => {
                let v = self
                    .vaults
                    .get(&hunter_id)
                    .unwrap_or_else(|| env::panic_str("no vault for this account"));
                require!(v.policy_set, "vault policy is not set");
                if let Some(list) = &v.allowed_programs {
                    require!(
                        list.contains(&program_id),
                        "program is not in the vault's allowed_programs"
                    );
                }
                if required > v.max_bond_per_report {
                    env::panic_str(&format!(
                        "required bond {} exceeds the vault's max_bond_per_report {}",
                        required, v.max_bond_per_report
                    ));
                }
                true
            }
        };

        let (reservation, nth) = {
            let p = self.program(program_id);
            require!(p.active, "program is not active");
            let reservation = p.reservation();
            require!(
                p.available() >= reservation,
                "program pool is underfunded for a new submission"
            );
            (reservation, p.stats.submissions)
        };

        self.flush_all();
        let before = env::storage_usage();

        let now = env::block_timestamp();
        let id = self.submissions.len() as u64;
        self.submissions.push(Submission {
            id,
            program_id,
            hunter_id: hunter_id.clone(),
            title,
            commitment: commitment.clone(),
            bond: 0,
            status: Status::Pending,
            submitted_at: now,
            submitted_block: env::block_height(),
            verdict: None,
            valid_until: 0,
            resolve_until: 0,
            payout: 0,
            resolution: None,
            dispute_reason: None,
            dispute_bond: 0,
            reserved: reservation,
            storage_cost: 0,
            funded_by_vault: from_vault,
        });
        self.sealed.insert(id, sealed);
        self.commitments.insert(commitment.clone(), id);
        self.program_submissions.insert((program_id, nth), id);
        self.pending_add(program_id, id);
        self.hunter_update(program_id, &hunter_id, |h| h.submissions += 1);
        {
            let p = self.program_mut(program_id);
            p.reserved += reservation;
            p.stats.submissions += 1;
        }
        self.flush_all();
        let used = env::storage_usage().saturating_sub(before) + LATER_WRITES_STORAGE_BYTES;
        let storage_cost = storage_cost_of(used);

        let bond = match funding {
            Funding::Deposit(deposit) => {
                let needed = storage_cost.saturating_add(required);
                if deposit < needed {
                    env::panic_str(&format!(
                        "attached deposit {} is too small: storage {} + required bond {} = {} yoctoNEAR",
                        deposit, storage_cost, required, needed
                    ));
                }
                deposit - storage_cost
            }
            Funding::Vault => {
                let draw = required.saturating_add(storage_cost);
                let v = self.vaults.get_mut(&hunter_id).unwrap();
                // the first vault submission opens the window; it restarts after 24 h
                if v.window_start == 0
                    || now
                        >= v.window_start
                            .saturating_add(secs_to_nanos(VAULT_WINDOW_SEC))
                {
                    v.window_start = now;
                    v.spent_in_window = 0;
                }
                if v.spent_in_window.saturating_add(draw) > v.max_spend_per_day {
                    env::panic_str(&format!(
                        "vault max_spend_per_day exceeded: spent {} + bond {} + storage {} > {}",
                        v.spent_in_window, required, storage_cost, v.max_spend_per_day
                    ));
                }
                if v.balance < draw {
                    env::panic_str(&format!(
                        "vault balance {} is too low: bond {} + storage {} = {} yoctoNEAR",
                        v.balance, required, storage_cost, draw
                    ));
                }
                v.balance -= draw;
                v.spent_in_window += draw;
                required
            }
        };
        {
            let s = self.submission_mut(id);
            s.bond = bond;
            s.storage_cost = storage_cost;
        }
        emit(
            "report_submitted",
            json!({
                "submission_id": id,
                "program_id": program_id,
                "hunter_id": hunter_id,
                "commitment": commitment,
                "bond": U128(bond),
                "storage_cost": U128(storage_cost),
                "reserved": U128(reservation),
                "submitted_block": U64(env::block_height()),
                "funded_by_vault": from_vault,
            }),
        );
        id
    }

    fn pending_add(&mut self, program_id: u64, submission_id: u64) {
        let pos = {
            let p = self.program_mut(program_id);
            p.pending_count += 1;
            p.pending_count - 1
        };
        self.pending_items.insert((program_id, pos), submission_id);
        self.pending_index.insert(submission_id, pos);
    }

    /// O(1) removal: the last entry of the program's index moves into the freed position.
    fn pending_remove(&mut self, program_id: u64, submission_id: u64) {
        let Some(pos) = self.pending_index.remove(&submission_id) else {
            return;
        };
        let last = {
            let p = self.program_mut(program_id);
            p.pending_count -= 1;
            p.pending_count
        };
        if pos != last {
            let moved = *self
                .pending_items
                .get(&(program_id, last))
                .unwrap_or_else(|| env::panic_str("pending index corrupted"));
            self.pending_items.insert((program_id, pos), moved);
            self.pending_index.insert(moved, pos);
        }
        self.pending_items.remove(&(program_id, last));
    }

    /// Releases a submission's reservation on the program pool.
    fn release(&mut self, program_id: u64, amount: u128) {
        let p = self.program_mut(program_id);
        p.reserved = p.reserved.saturating_sub(amount);
    }

    /// Routes a bond refund: vault-funded submissions are credited back to the hunter's vault.
    /// Returns the amount still to transfer to the hunter account and where the refund went.
    fn refund_target(&mut self, s: &Submission, amount: u128) -> (u128, &'static str) {
        if s.funded_by_vault
            && let Some(v) = self.vaults.get_mut(&s.hunter_id)
        {
            v.balance = v.balance.saturating_add(amount);
            return (0, "vault");
        }
        (amount, "hunter")
    }

    /// Pays a valid submission: `min(payout, pool)` to the hunter, the bond back (to the vault
    /// if it came from there), the verifier fee from what is left of the pool. For a disputed
    /// submission, the held dispute bond goes to `dispute_bond_to`. Status becomes `paid`.
    fn pay(
        &mut self,
        submission_id: u64,
        severity: Severity,
        dispute_bond_to: Option<DisputeBondTo>,
    ) {
        let s = self.submission(submission_id).clone();
        let (payout, fee, verifier_id, owner_id) = {
            let p = self.program_mut(s.program_id);
            let payout = p.payouts.for_severity(severity).min(p.pool);
            let fee = p.verifier_fee.min(p.pool - payout);
            p.pool -= payout + fee;
            p.reserved = p.reserved.saturating_sub(s.reserved);
            p.stats.paid += 1;
            p.stats.total_paid = p.stats.total_paid.saturating_add(payout);
            (payout, fee, p.verifier_id.clone(), p.owner_id.clone())
        };
        {
            let sm = self.submission_mut(submission_id);
            sm.status = Status::Paid;
            sm.payout = payout;
        }
        self.hunter_update(s.program_id, &s.hunter_id, |h| {
            h.valid += 1;
            h.earned = h.earned.saturating_add(payout);
        });
        let (bond_to_hunter, bond_to) = self.refund_target(&s, s.bond);
        let dispute_bond = match dispute_bond_to {
            Some(_) => s.dispute_bond,
            None => 0,
        };
        let (db_hunter, db_owner) = match dispute_bond_to {
            Some(DisputeBondTo::Hunter) => (dispute_bond, 0),
            Some(DisputeBondTo::Owner) => (0, dispute_bond),
            None => (0, 0),
        };
        transfer(&s.hunter_id, payout + bond_to_hunter + db_hunter);
        transfer(&verifier_id, fee);
        transfer(&owner_id, db_owner);
        emit(
            "report_paid",
            json!({
                "submission_id": submission_id,
                "program_id": s.program_id,
                "hunter_id": s.hunter_id,
                "severity": severity.as_str(),
                "payout": U128(payout),
                "verifier_id": verifier_id,
                "verifier_fee": U128(fee),
                "dispute_bond": U128(dispute_bond),
                "dispute_bond_to": dispute_bond_to.map(|t| match t {
                    DisputeBondTo::Owner => "owner",
                    DisputeBondTo::Hunter => "hunter",
                }),
            }),
        );
        emit(
            "bond_refunded",
            json!({
                "submission_id": submission_id,
                "program_id": s.program_id,
                "hunter_id": s.hunter_id,
                "amount": U128(s.bond),
                "to": bond_to,
                "verifier_fee": U128(0),
                "reason": "paid",
            }),
        );
    }

    /// Slashes the bond: `min(verifier_fee, bond)` to the verifier (only if `pay_verifier`),
    /// the rest into the program pool.
    fn slash(&mut self, submission_id: u64, pay_verifier: bool, final_status: Status) {
        let s = self.submission(submission_id).clone();
        let (fee, to_pool, verifier_id) = {
            let p = self.program_mut(s.program_id);
            let fee = if pay_verifier {
                p.verifier_fee.min(s.bond)
            } else {
                0
            };
            let to_pool = s.bond - fee;
            p.pool = p.pool.saturating_add(to_pool);
            p.reserved = p.reserved.saturating_sub(s.reserved);
            p.stats.invalid += 1;
            (fee, to_pool, p.verifier_id.clone())
        };
        self.submission_mut(submission_id).status = final_status;
        self.hunter_update(s.program_id, &s.hunter_id, |h| h.invalid += 1);
        transfer(&verifier_id, fee);
        emit(
            "bond_slashed",
            json!({
                "submission_id": submission_id,
                "program_id": s.program_id,
                "hunter_id": s.hunter_id,
                "bond": U128(s.bond),
                "to_pool": U128(to_pool),
                "verifier_id": verifier_id,
                "verifier_fee": U128(fee),
            }),
        );
    }

    /// A disputed valid verdict, overruled by the owner (resolved invalid): the hunter gets the
    /// whole bond back plus the owner's dispute bond, the verifier gets no fee, and the hunter's
    /// reputation is not touched. Counted in `stats.disputes` and `stats.overruled`.
    fn reject_disputed(&mut self, submission_id: u64) {
        let s = self.submission(submission_id).clone();
        {
            let p = self.program_mut(s.program_id);
            p.reserved = p.reserved.saturating_sub(s.reserved);
            p.stats.invalid += 1;
            p.stats.overruled += 1;
        }
        self.submission_mut(submission_id).status = Status::Rejected;
        let (bond_to_hunter, to) = self.refund_target(&s, s.bond);
        transfer(&s.hunter_id, bond_to_hunter + s.dispute_bond);
        emit(
            "bond_refunded",
            json!({
                "submission_id": submission_id,
                "program_id": s.program_id,
                "hunter_id": s.hunter_id,
                "amount": U128(s.bond),
                "to": to,
                "verifier_fee": U128(0),
                "reason": "dispute_overruled",
                "dispute_bond": U128(s.dispute_bond),
                "dispute_bond_to": "hunter",
            }),
        );
    }

    /// Duplicate: `min(verifier_fee, bond)` to the verifier, the rest back to the hunter.
    fn refund_duplicate(&mut self, submission_id: u64) {
        let s = self.submission(submission_id).clone();
        let (fee, verifier_id) = {
            let p = self.program_mut(s.program_id);
            let fee = p.verifier_fee.min(s.bond);
            p.reserved = p.reserved.saturating_sub(s.reserved);
            p.stats.duplicate += 1;
            (fee, p.verifier_id.clone())
        };
        let refund = s.bond - fee;
        self.submission_mut(submission_id).status = Status::Duplicate;
        self.hunter_update(s.program_id, &s.hunter_id, |h| h.duplicate += 1);
        let (to_hunter, to) = self.refund_target(&s, refund);
        transfer(&verifier_id, fee);
        transfer(&s.hunter_id, to_hunter);
        emit(
            "bond_refunded",
            json!({
                "submission_id": submission_id,
                "program_id": s.program_id,
                "hunter_id": s.hunter_id,
                "amount": U128(refund),
                "to": to,
                "verifier_id": verifier_id,
                "verifier_fee": U128(fee),
                "reason": "duplicate",
            }),
        );
    }

    /// `needs_human` not resolved before `resolve_until`: full bond back, no fee, `expired`.
    fn expire(&mut self, submission_id: u64) {
        let s = self.submission(submission_id).clone();
        self.release(s.program_id, s.reserved);
        self.submission_mut(submission_id).status = Status::Expired;
        let (to_hunter, to) = self.refund_target(&s, s.bond);
        transfer(&s.hunter_id, to_hunter);
        emit(
            "report_expired",
            json!({
                "submission_id": submission_id,
                "program_id": s.program_id,
                "hunter_id": s.hunter_id,
                "bond": U128(s.bond),
                "resolve_until": U64(s.resolve_until),
            }),
        );
        emit(
            "bond_refunded",
            json!({
                "submission_id": submission_id,
                "program_id": s.program_id,
                "hunter_id": s.hunter_id,
                "amount": U128(s.bond),
                "to": to,
                "verifier_fee": U128(0),
                "reason": "expired",
            }),
        );
    }

    /// Writes all cached collection entries so `env::storage_usage()` reflects them.
    fn flush_all(&mut self) {
        self.programs.flush();
        self.submissions.flush();
        self.sealed.flush();
        self.commitments.flush();
        self.hunters.flush();
        self.program_hunters.flush();
        self.program_submissions.flush();
        self.pending_items.flush();
        self.pending_index.flush();
        self.vaults.flush();
    }
}
