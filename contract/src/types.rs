//! Stored types (Borsh) and their JSON views.
//!
//! Amounts are kept as `u128` (yoctoNEAR) and timestamps as `u64` (nanoseconds) in state; the
//! views convert them to `U128` / `U64` strings so JSON clients never lose precision.

use near_sdk::json_types::{U64, U128};
use near_sdk::{AccountId, near};

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
}

/// Outcome posted by the verifier.
#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Valid,
    Invalid,
    Duplicate,
    NeedsHuman,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Valid => "valid",
            Outcome::Invalid => "invalid",
            Outcome::Duplicate => "duplicate",
            Outcome::NeedsHuman => "needs_human",
        }
    }
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pending,
    Valid,
    Paid,
    Invalid,
    Duplicate,
    NeedsHuman,
    Disputed,
    Rejected,
    Withdrawn,
    Expired,
}

impl Status {
    /// Open submissions hold a reservation on the program pool.
    pub fn is_open(&self) -> bool {
        matches!(
            self,
            Status::Pending | Status::Valid | Status::NeedsHuman | Status::Disputed
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Pending => "pending",
            Status::Valid => "valid",
            Status::Paid => "paid",
            Status::Invalid => "invalid",
            Status::Duplicate => "duplicate",
            Status::NeedsHuman => "needs_human",
            Status::Disputed => "disputed",
            Status::Rejected => "rejected",
            Status::Withdrawn => "withdrawn",
            Status::Expired => "expired",
        }
    }
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeTarget {
    pub chain_id: u64,
    pub address: String,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payouts {
    pub critical: U128,
    pub high: U128,
    pub medium: U128,
    pub low: U128,
}

impl Payouts {
    pub fn for_severity(&self, s: Severity) -> u128 {
        match s {
            Severity::Critical => self.critical.0,
            Severity::High => self.high.0,
            Severity::Medium => self.medium.0,
            Severity::Low => self.low.0,
        }
    }

    pub fn max(&self) -> u128 {
        self.critical
            .0
            .max(self.high.0)
            .max(self.medium.0)
            .max(self.low.0)
    }
}

#[near(serializers = [borsh])]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProgramStats {
    pub submissions: u64,
    pub paid: u64,
    pub invalid: u64,
    pub duplicate: u64,
    pub needs_human: u64,
    pub disputes: u64,
    /// Disputes the owner won against a `valid` verdict (resolved as invalid).
    pub overruled: u64,
    pub total_paid: u128,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramStatsView {
    pub submissions: u64,
    pub paid: u64,
    pub invalid: u64,
    pub duplicate: u64,
    pub needs_human: u64,
    pub disputes: u64,
    pub overruled: u64,
    pub total_paid: U128,
}

#[near(serializers = [borsh])]
#[derive(Clone, Debug)]
pub struct Program {
    pub id: u64,
    pub owner_id: AccountId,
    pub name: String,
    pub scope: Vec<ScopeTarget>,
    pub verifier_id: AccountId,
    pub verifier_pubkey: String,
    pub payouts: Payouts,
    pub bond: u128,
    pub verifier_fee: u128,
    /// Deposit the owner must attach to `dispute`; held until the dispute is settled.
    pub dispute_bond: u128,
    pub challenge_period_sec: u64,
    pub pending_timeout_sec: u64,
    /// Deadline for the owner to resolve `needs_human` and `disputed` submissions.
    pub resolve_timeout_sec: u64,
    /// Escrowed funds of this program (includes the `reserved` part).
    pub pool: u128,
    /// Part of `pool` held back for open submissions (max payout + verifier fee each).
    pub reserved: u128,
    pub active: bool,
    pub stats: ProgramStats,
    pub created_at: u64,
    /// Number of entries in this program's pending index (see `Contract::pending_items`).
    pub pending_count: u64,
}

impl Program {
    /// Amount reserved per open submission.
    pub fn reservation(&self) -> u128 {
        self.payouts.max().saturating_add(self.verifier_fee)
    }

    pub fn available(&self) -> u128 {
        self.pool.saturating_sub(self.reserved)
    }

    pub fn view(&self) -> ProgramView {
        ProgramView {
            id: self.id,
            owner_id: self.owner_id.clone(),
            name: self.name.clone(),
            scope: self.scope.clone(),
            verifier_id: self.verifier_id.clone(),
            verifier_pubkey: self.verifier_pubkey.clone(),
            payouts: self.payouts.clone(),
            bond: U128(self.bond),
            verifier_fee: U128(self.verifier_fee),
            dispute_bond: U128(self.dispute_bond),
            challenge_period_sec: self.challenge_period_sec,
            pending_timeout_sec: self.pending_timeout_sec,
            resolve_timeout_sec: self.resolve_timeout_sec,
            pool: U128(self.pool),
            reserved: U128(self.reserved),
            active: self.active,
            stats: ProgramStatsView {
                submissions: self.stats.submissions,
                paid: self.stats.paid,
                invalid: self.stats.invalid,
                duplicate: self.stats.duplicate,
                needs_human: self.stats.needs_human,
                disputes: self.stats.disputes,
                overruled: self.stats.overruled,
                total_paid: U128(self.stats.total_paid),
            },
            created_at: U64(self.created_at),
        }
    }
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct ProgramView {
    pub id: u64,
    pub owner_id: AccountId,
    pub name: String,
    pub scope: Vec<ScopeTarget>,
    pub verifier_id: AccountId,
    pub verifier_pubkey: String,
    pub payouts: Payouts,
    pub bond: U128,
    pub verifier_fee: U128,
    pub dispute_bond: U128,
    pub challenge_period_sec: u64,
    pub pending_timeout_sec: u64,
    pub resolve_timeout_sec: u64,
    pub pool: U128,
    pub reserved: U128,
    pub active: bool,
    pub stats: ProgramStatsView,
    pub created_at: U64,
}

/// Verdict as posted by the verifier (`post_verdict` argument).
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct VerdictInput {
    pub outcome: Outcome,
    #[serde(default)]
    pub severity: Option<Severity>,
    #[serde(default)]
    pub duplicate_of: Option<u64>,
    #[serde(default)]
    pub fingerprint: String,
    pub evidence_sha256: String,
    #[serde(default)]
    pub evidence_uri: String,
    pub chain_id: u64,
    pub fork_block: U64,
    pub reason: String,
}

#[near(serializers = [borsh])]
#[derive(Clone, Debug)]
pub struct Verdict {
    pub outcome: Outcome,
    pub severity: Option<Severity>,
    pub duplicate_of: Option<u64>,
    pub fingerprint: String,
    pub evidence_sha256: String,
    pub evidence_uri: String,
    pub chain_id: u64,
    pub fork_block: u64,
    pub reason: String,
    pub posted_at: u64,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct VerdictView {
    pub outcome: Outcome,
    pub severity: Option<Severity>,
    pub duplicate_of: Option<u64>,
    pub fingerprint: String,
    pub evidence_sha256: String,
    pub evidence_uri: String,
    pub chain_id: u64,
    pub fork_block: U64,
    pub reason: String,
    pub posted_at: U64,
}

#[near(serializers = [borsh])]
#[derive(Clone, Debug)]
pub struct Resolution {
    pub outcome: Outcome,
    pub severity: Option<Severity>,
    pub note: String,
    pub at: u64,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct ResolutionView {
    pub by: String,
    pub outcome: String,
    pub severity: Option<Severity>,
    pub note: String,
    pub at: U64,
}

#[near(serializers = [borsh])]
#[derive(Clone, Debug)]
pub struct Submission {
    pub id: u64,
    pub program_id: u64,
    pub hunter_id: AccountId,
    pub title: String,
    pub commitment: String,
    /// Bond posted by the hunter (attached deposit minus storage cost, or drawn from the vault).
    pub bond: u128,
    pub status: Status,
    pub submitted_at: u64,
    pub submitted_block: u64,
    pub verdict: Option<Verdict>,
    /// End of the challenge window (0 until the verdict is `valid`).
    pub valid_until: u64,
    /// Deadline for the owner's `resolve` (0 until `needs_human` or `disputed`).
    pub resolve_until: u64,
    pub payout: u128,
    pub resolution: Option<Resolution>,
    pub dispute_reason: Option<String>,
    /// Dispute bond held from the program owner while `disputed` (kept for the record after).
    pub dispute_bond: u128,
    /// Amount this submission reserved on the program pool while open.
    pub reserved: u128,
    /// Storage fee charged at submission (kept by the contract for storage staking).
    pub storage_cost: u128,
    /// Bond and storage were drawn from the hunter's vault; bond refunds go back there.
    pub funded_by_vault: bool,
}

fn nonzero(t: u64) -> Option<U64> {
    if t > 0 { Some(U64(t)) } else { None }
}

impl Submission {
    pub fn view(&self) -> SubmissionView {
        SubmissionView {
            id: self.id,
            program_id: self.program_id,
            hunter_id: self.hunter_id.clone(),
            title: self.title.clone(),
            commitment: self.commitment.clone(),
            bond: U128(self.bond),
            status: self.status,
            submitted_at: U64(self.submitted_at),
            submitted_block: U64(self.submitted_block),
            verdict: self.verdict.as_ref().map(|v| VerdictView {
                outcome: v.outcome,
                severity: v.severity,
                duplicate_of: v.duplicate_of,
                fingerprint: v.fingerprint.clone(),
                evidence_sha256: v.evidence_sha256.clone(),
                evidence_uri: v.evidence_uri.clone(),
                chain_id: v.chain_id,
                fork_block: U64(v.fork_block),
                reason: v.reason.clone(),
                posted_at: U64(v.posted_at),
            }),
            payout: U128(self.payout),
            resolution: self.resolution.as_ref().map(|r| ResolutionView {
                by: "owner".to_string(),
                outcome: r.outcome.as_str().to_string(),
                severity: r.severity,
                note: r.note.clone(),
                at: U64(r.at),
            }),
            dispute_reason: self.dispute_reason.clone(),
            valid_until: nonzero(self.valid_until),
            resolve_until: nonzero(self.resolve_until),
            dispute_bond: U128(self.dispute_bond),
            funded_by_vault: self.funded_by_vault,
            storage_cost: U128(self.storage_cost),
        }
    }
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct SubmissionView {
    pub id: u64,
    pub program_id: u64,
    pub hunter_id: AccountId,
    pub title: String,
    pub commitment: String,
    pub bond: U128,
    pub status: Status,
    pub submitted_at: U64,
    pub submitted_block: U64,
    pub verdict: Option<VerdictView>,
    pub payout: U128,
    pub resolution: Option<ResolutionView>,
    pub dispute_reason: Option<String>,
    /// End of the challenge window once the verdict is `valid` (`null` before).
    pub valid_until: Option<U64>,
    /// Owner's resolve deadline once `needs_human` or `disputed` (`null` before).
    pub resolve_until: Option<U64>,
    /// Dispute bond held from (or settled for) the program owner; "0" if never disputed.
    pub dispute_bond: U128,
    pub funded_by_vault: bool,
    /// Storage fee charged at submission.
    pub storage_cost: U128,
}

#[near(serializers = [borsh])]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HunterStats {
    pub submissions: u64,
    pub valid: u64,
    pub invalid: u64,
    pub duplicate: u64,
    pub needs_human: u64,
    pub earned: u128,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HunterView {
    pub submissions: u64,
    pub valid: u64,
    pub invalid: u64,
    pub duplicate: u64,
    pub needs_human: u64,
    pub earned: U128,
}

impl HunterStats {
    pub fn view(&self) -> HunterView {
        HunterView {
            submissions: self.submissions,
            valid: self.valid,
            invalid: self.invalid,
            duplicate: self.duplicate,
            needs_human: self.needs_human,
            earned: U128(self.earned),
        }
    }
}

/// A hunter's pre-funded vault with an on-chain spending policy for agent submissions.
#[near(serializers = [borsh])]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Vault {
    pub balance: u128,
    pub max_bond_per_report: u128,
    pub max_spend_per_day: u128,
    /// `None` = any program.
    pub allowed_programs: Option<Vec<u64>>,
    /// Bond + storage drawn since `window_start`.
    pub spent_in_window: u128,
    pub window_start: u64,
    pub policy_set: bool,
}

impl Vault {
    pub fn view(&self, account_id: AccountId) -> VaultView {
        VaultView {
            account_id,
            balance: U128(self.balance),
            max_bond_per_report: U128(self.max_bond_per_report),
            max_spend_per_day: U128(self.max_spend_per_day),
            allowed_programs: self.allowed_programs.clone(),
            spent_in_window: U128(self.spent_in_window),
            window_start: U64(self.window_start),
            policy_set: self.policy_set,
        }
    }
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultView {
    pub account_id: AccountId,
    pub balance: U128,
    pub max_bond_per_report: U128,
    pub max_spend_per_day: U128,
    pub allowed_programs: Option<Vec<u64>>,
    pub spent_in_window: U128,
    pub window_start: U64,
    pub policy_set: bool,
}
