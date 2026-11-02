//! Unit tests: every rule, refusal and money path of SPEC.md v2, the vault, and regression tests
//! for the findings of the separate AI review of v1 (S1..S8, see the `regression` section).

use super::*;
use near_sdk::base64::Engine;
use near_sdk::base64::engine::general_purpose::STANDARD;
use near_sdk::borsh;
use near_sdk::mock::MockAction;
use near_sdk::test_utils::{VMContextBuilder, get_created_receipts, get_logs};
use near_sdk::testing_env;

const NEAR: u128 = ONE_NEAR;
const MILLI: u128 = NEAR / 1000;
const BYTE: u128 = 10_000_000_000_000_000_000; // storage byte cost

fn acc(s: &str) -> AccountId {
    s.parse().unwrap()
}
fn deployer() -> AccountId {
    acc("deployer.testnet")
}
fn owner() -> AccountId {
    acc("owner.testnet")
}
fn verifier() -> AccountId {
    acc("verifier.testnet")
}
fn hunter1() -> AccountId {
    acc("hunter1.testnet")
}
fn hunter2() -> AccountId {
    acc("hunter2.testnet")
}
fn stranger() -> AccountId {
    acc("stranger.testnet")
}

/// New mocked context. Storage persists across contexts in near-sdk's mock; `storage_usage`
/// is carried over explicitly so storage deltas can be measured across several calls.
fn set_ctx(who: &AccountId, deposit: u128, now_sec: u64) {
    let usage = env::storage_usage();
    let mut b = VMContextBuilder::new();
    b.current_account_id(acc("contract.testnet"))
        .signer_account_id(who.clone())
        .predecessor_account_id(who.clone())
        .attached_deposit(NearToken::from_yoctonear(deposit))
        .account_balance(NearToken::from_near(100_000))
        .storage_usage(usage)
        .block_timestamp(now_sec * NANOS_PER_SEC)
        .block_height(1_000 + now_sec);
    testing_env!(b.build());
}

fn pubkey() -> String {
    STANDARD.encode([7u8; 32])
}

fn payouts() -> Payouts {
    Payouts {
        critical: U128(10 * NEAR),
        high: U128(5 * NEAR),
        medium: U128(2 * NEAR),
        low: U128(NEAR),
    }
}

const BOND: u128 = NEAR;
const FEE: u128 = 100 * MILLI;
const DISPUTE_BOND: u128 = 2 * NEAR;
const RESERVATION: u128 = 10 * NEAR + FEE;
const CHALLENGE: u64 = 60;
const TIMEOUT: u64 = 3_600;
const RESOLVE: u64 = 600;
const DAY: u64 = 24 * 3_600;
/// A 4-byte UTF-8 character (U+1D54F).
const WIDE: &str = "\u{1D54F}";

fn commit(n: u64) -> String {
    format!("{:064x}", n)
}

fn verdict(outcome: Outcome) -> VerdictInput {
    VerdictInput {
        outcome,
        severity: if outcome == Outcome::Valid {
            Some(Severity::High)
        } else {
            None
        },
        duplicate_of: None,
        fingerprint: "reentrancy:withdraw".into(),
        evidence_sha256: "ab".repeat(32),
        evidence_uri: "runs/testnet/replaycourt/0/evidence.json".into(),
        chain_id: 1,
        fork_block: U64(19_000_000),
        reason: "drained 10 ETH from the vault".into(),
    }
}

fn dup_of(id: u64) -> VerdictInput {
    VerdictInput {
        duplicate_of: Some(id),
        ..verdict(Outcome::Duplicate)
    }
}

/// Program parameters with defaults; override fields per test.
#[derive(Clone)]
struct P {
    name: String,
    scope: Vec<ScopeTarget>,
    verifier: AccountId,
    payouts: Payouts,
    bond: u128,
    fee: u128,
    dispute_bond: u128,
    challenge: u64,
    pending: u64,
    resolve: u64,
}

impl Default for P {
    fn default() -> Self {
        P {
            name: "Vault program".into(),
            scope: vec![ScopeTarget {
                chain_id: 1,
                address: "0x1111111111111111111111111111111111111111".into(),
            }],
            verifier: verifier(),
            payouts: payouts(),
            bond: BOND,
            fee: FEE,
            dispute_bond: DISPUTE_BOND,
            challenge: CHALLENGE,
            pending: TIMEOUT,
            resolve: RESOLVE,
        }
    }
}

/// Test harness: one contract instance, a clock in seconds, and a ledger of every yoctoNEAR
/// attached (`inflow`), transferred out (`outflow`) and kept for storage (`kept`).
struct T {
    c: Contract,
    now: u64,
    inflow: u128,
    outflow: u128,
    kept: u128,
}

impl T {
    fn new() -> Self {
        set_ctx(&deployer(), 0, 1_000);
        T {
            c: Contract::new(deployer()),
            now: 1_000,
            inflow: 0,
            outflow: 0,
            kept: 0,
        }
    }
    /// Books the transfers of the previous call, then opens a new context.
    fn switch(&mut self, who: &AccountId, deposit: u128) {
        self.outflow += transfers().iter().map(|(_, a)| *a).sum::<u128>();
        self.inflow += deposit;
        set_ctx(who, deposit, self.now);
    }
    fn call(&mut self, who: &AccountId, deposit: u128) -> &mut Contract {
        self.switch(who, deposit);
        &mut self.c
    }
    fn view(&mut self) -> &Contract {
        self.switch(&stranger(), 0);
        &self.c
    }
    fn advance(&mut self, secs: u64) {
        self.now += secs;
    }
    fn create(&mut self, who: &AccountId, deposit: u128, a: P) -> u64 {
        let id = self.call(who, deposit).create_program(
            a.name,
            a.scope,
            a.verifier,
            pubkey(),
            a.payouts,
            U128(a.bond),
            U128(a.fee),
            U128(a.dispute_bond),
            a.challenge,
            a.pending,
            a.resolve,
        );
        self.kept += event_amount("program_created", "storage_cost");
        id
    }
    fn create_program(&mut self, deposit: u128) -> u64 {
        self.create(&owner(), deposit, P::default())
    }
    fn create_program_with(&mut self, deposit: u128, bond: u128, fee: u128) -> u64 {
        self.create(
            &owner(),
            deposit,
            P {
                bond,
                fee,
                ..P::default()
            },
        )
    }
    fn submit(&mut self, hunter: &AccountId, program_id: u64, n: u64, deposit: u128) -> u64 {
        let id = self.call(hunter, deposit).submit_report(
            program_id,
            format!("Report {}", n),
            commit(n),
            "c2VhbGVk".repeat(16),
        );
        self.kept += self.c.submission(id).storage_cost;
        id
    }
    fn submit_vault(&mut self, hunter: &AccountId, program_id: u64, n: u64) -> u64 {
        let id = self.call(hunter, 0).submit_report_from_vault(
            program_id,
            format!("Vault report {}", n),
            commit(n),
            "c2VhbGVk".repeat(16),
        );
        self.kept += self.c.submission(id).storage_cost;
        id
    }
    fn vault_deposit(&mut self, who: &AccountId, amount: u128) {
        self.call(who, amount).vault_deposit();
        self.kept += event_amount("vault_deposited", "storage_cost");
    }
    fn set_policy(
        &mut self,
        who: &AccountId,
        max_bond: u128,
        max_day: u128,
        allowed: Option<Vec<u64>>,
    ) {
        self.call(who, 1)
            .vault_set_policy(U128(max_bond), U128(max_day), allowed);
    }
    fn vault(&mut self, who: &AccountId) -> VaultView {
        self.view().get_vault(who.clone()).unwrap()
    }
    fn program(&mut self, id: u64) -> ProgramView {
        self.view().get_program(id).unwrap()
    }
    fn sub(&mut self, id: u64) -> SubmissionView {
        self.view().get_submission(id).unwrap()
    }
    fn post(&mut self, id: u64, v: VerdictInput) {
        self.call(&verifier(), 0).post_verdict(id, v);
    }
    fn dispute(&mut self, id: u64, deposit: u128) {
        self.call(&owner(), deposit)
            .dispute(id, "out of scope".into());
    }
    fn resolve(&mut self, id: u64, outcome: &str, severity: Option<Severity>) {
        self.call(&owner(), 0)
            .resolve(id, outcome.into(), severity, "checked by hand".into());
    }
    fn finalize(&mut self, id: u64) {
        self.call(&stranger(), 0).finalize(id);
    }
    fn flush_usage(&mut self) -> u64 {
        self.c.flush_all();
        env::storage_usage()
    }
}

fn transfers() -> Vec<(String, u128)> {
    get_created_receipts()
        .into_iter()
        .flat_map(|r| {
            let to = r.receiver_id.to_string();
            r.actions.into_iter().filter_map(move |a| match a {
                MockAction::Transfer { deposit, .. } => Some((to.clone(), deposit.as_yoctonear())),
                _ => None,
            })
        })
        .collect()
}

fn paid_to(who: &AccountId) -> u128 {
    transfers()
        .iter()
        .filter(|(to, _)| to == who.as_str())
        .map(|(_, a)| *a)
        .sum()
}

fn events() -> Vec<serde_json::Value> {
    get_logs()
        .iter()
        .filter_map(|l| l.strip_prefix("EVENT_JSON:"))
        .map(|j| serde_json::from_str(j).unwrap())
        .collect()
}

fn event_names() -> Vec<String> {
    events()
        .iter()
        .map(|e| e["event"].as_str().unwrap().to_string())
        .collect()
}

fn event_data(name: &str) -> serde_json::Value {
    events()
        .into_iter()
        .find(|e| e["event"] == name)
        .unwrap_or_else(|| panic!("no event {}", name))["data"][0]
        .clone()
}

fn event_amount(name: &str, field: &str) -> u128 {
    event_data(name)[field].as_str().unwrap().parse().unwrap()
}

/// - `reserved` equals the sum of reservations of open submissions and never exceeds the pool;
/// - every program's pending index holds exactly its pending submissions, consistently.
fn check_invariants(t: &mut T) {
    let c = t.view();
    for i in 0..c.programs.len() {
        let p = c.programs.get(i).unwrap();
        assert!(p.reserved <= p.pool, "reserved exceeds pool");
        let mut open = 0u128;
        let mut pending = vec![];
        for j in 0..c.submissions.len() {
            let s = c.submissions.get(j).unwrap();
            if s.program_id == p.id && s.status.is_open() {
                open += s.reserved;
            }
            if s.program_id == p.id && s.status == Status::Pending {
                pending.push(s.id);
            }
        }
        assert_eq!(p.reserved, open, "reserved != sum of open reservations");
        assert_eq!(p.pending_count, pending.len() as u64, "pending_count");
        let mut listed: Vec<u64> = (0..p.pending_count)
            .map(|pos| *c.pending_items.get(&(p.id, pos)).unwrap())
            .collect();
        for (pos, id) in listed.iter().enumerate() {
            assert_eq!(
                *c.pending_index.get(id).unwrap(),
                pos as u64,
                "pending_index"
            );
        }
        assert!(c.pending_items.get(&(p.id, p.pending_count)).is_none());
        listed.sort_unstable();
        assert_eq!(listed, pending, "pending index != pending submissions");
    }
}

/// Every yoctoNEAR that entered (attached deposits) was transferred out, kept for storage, or
/// is still held: in a pool, as an open bond, as a held dispute bond, or in a vault.
fn assert_conserved(t: &mut T, vault_accounts: &[AccountId]) {
    t.switch(&stranger(), 0);
    let c = &t.c;
    let mut held = 0u128;
    for i in 0..c.programs.len() {
        held += c.programs.get(i).unwrap().pool;
    }
    for j in 0..c.submissions.len() {
        let s = c.submissions.get(j).unwrap();
        if s.status.is_open() {
            held += s.bond;
        }
        if s.status == Status::Disputed {
            held += s.dispute_bond;
        }
    }
    for a in vault_accounts {
        held += c.vaults.get(a).map(|v| v.balance).unwrap_or(0);
    }
    // t.kept = program, vault and submission storage (booked by the helpers)
    assert_eq!(t.inflow, t.outflow + t.kept + held, "money not conserved");
}

/// Program with 100 NEAR, one submission by hunter1 with 2 NEAR attached.
fn setup_one() -> (T, u64, u64) {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    let sid = t.submit(&hunter1(), pid, 1, 2 * NEAR);
    (t, pid, sid)
}

/// setup_one + valid verdict + dispute with exactly the dispute bond.
fn setup_disputed() -> (T, u64, u64) {
    let (mut t, pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::Valid));
    t.dispute(sid, DISPUTE_BOND);
    (t, pid, sid)
}

/// hunter1 has a vault with 10 NEAR and a policy (max bond 1 NEAR, 5 NEAR per day, any program).
fn setup_vault() -> (T, u64) {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    t.vault_deposit(&hunter1(), 10 * NEAR);
    t.set_policy(&hunter1(), BOND, 5 * NEAR, None);
    (t, pid)
}

// ----------------------------------------------------------------- init / views

#[test]
fn init_and_empty_views() {
    let mut t = T::new();
    let c = t.view();
    assert_eq!(c.version(), "2.0.0");
    assert!(c.get_program(0).is_none());
    assert!(c.get_submission(0).is_none());
    assert!(c.get_sealed(0).is_none());
    assert!(c.list_programs(0, 10).is_empty());
    assert!(c.list_submissions(0, 0, 10).is_empty());
    assert!(c.list_pending(0, 0, 10).is_empty());
    assert!(c.get_vault(hunter1()).is_none());
    assert_eq!(c.get_hunter(hunter1()), HunterStats::default().view());
    assert_eq!(
        c.get_hunter_in_program(0, hunter1()),
        HunterStats::default().view()
    );
}

#[test]
fn version_matches_cargo_and_events() {
    assert_eq!(env!("CARGO_PKG_VERSION"), "2.0.0");
    assert_eq!(EVENT_VERSION, "2.0.0");
    assert_eq!(EVENT_STANDARD, "replaycourt");
}

// ------------------------------------------------------------------ programs

#[test]
fn create_program_escrows_deposit_minus_storage() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    assert_eq!(pid, 0);
    let ev = events();
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["standard"], "replaycourt");
    assert_eq!(ev[0]["version"], "2.0.0");
    assert_eq!(ev[0]["event"], "program_created");
    assert!(ev[0]["data"].is_array() && ev[0]["data"].as_array().unwrap().len() == 1);
    let d = &ev[0]["data"][0];
    assert_eq!(d["dispute_bond"], DISPUTE_BOND.to_string());
    assert_eq!(d["resolve_timeout_sec"], RESOLVE);
    let storage: u128 = d["storage_cost"].as_str().unwrap().parse().unwrap();
    assert!(storage > 0 && storage < NEAR / 10);
    let p = t.program(pid);
    assert_eq!(p.owner_id, owner());
    assert_eq!(p.verifier_id, verifier());
    assert_eq!(p.pool.0, 100 * NEAR - storage);
    assert_eq!(p.reserved.0, 0);
    assert!(p.active);
    assert_eq!(p.challenge_period_sec, CHALLENGE);
    assert_eq!(p.pending_timeout_sec, TIMEOUT);
    assert_eq!(p.resolve_timeout_sec, RESOLVE);
    assert_eq!(p.dispute_bond.0, DISPUTE_BOND);
    assert_eq!(p.stats.overruled, 0);
    assert_eq!(p.created_at.0, 1_000 * NANOS_PER_SEC);
    assert_eq!(t.create_program(5 * NEAR), 1);
    assert_eq!(t.view().list_programs(0, 10).len(), 2);
    assert_eq!(t.view().list_programs(1, 10)[0].id, 1);
}

#[test]
#[should_panic(expected = "attached deposit must be at least 1 NEAR")]
fn create_program_needs_one_near() {
    let mut t = T::new();
    t.create_program(NEAR - 1);
}

#[test]
#[should_panic(expected = "name must be 1..=80 bytes")]
fn create_program_rejects_empty_name() {
    let mut t = T::new();
    t.create(
        &owner(),
        NEAR,
        P {
            name: "".into(),
            ..P::default()
        },
    );
}

#[test]
#[should_panic(expected = "name must be 1..=80 bytes")]
fn create_program_rejects_long_name() {
    let mut t = T::new();
    t.create(
        &owner(),
        NEAR,
        P {
            name: "x".repeat(81),
            ..P::default()
        },
    );
}

#[test]
fn create_program_name_limit_counts_bytes() {
    let mut t = T::new();
    // 20 four-byte characters = 80 bytes: accepted
    let pid = t.create(
        &owner(),
        NEAR,
        P {
            name: WIDE.repeat(20),
            ..P::default()
        },
    );
    assert_eq!(t.program(pid).name.len(), 80);
}

#[test]
#[should_panic(expected = "name must be 1..=80 bytes")]
fn create_program_rejects_81_bytes_of_wide_chars() {
    // 21 characters, 84 bytes: a character-based limit (v1) would have accepted it
    let mut t = T::new();
    t.create(
        &owner(),
        NEAR,
        P {
            name: WIDE.repeat(21),
            ..P::default()
        },
    );
}

#[test]
#[should_panic(expected = "scope must have at most 32 targets")]
fn create_program_rejects_large_scope() {
    let mut t = T::new();
    let scope = (0..33)
        .map(|_| ScopeTarget {
            chain_id: 1,
            address: "0x1".into(),
        })
        .collect();
    t.create(
        &owner(),
        NEAR,
        P {
            scope,
            ..P::default()
        },
    );
}

#[test]
#[should_panic(expected = "scope address must be at most 64 bytes")]
fn create_program_rejects_long_address() {
    let mut t = T::new();
    t.create(
        &owner(),
        NEAR,
        P {
            scope: vec![ScopeTarget {
                chain_id: 1,
                address: "a".repeat(65),
            }],
            ..P::default()
        },
    );
}

#[test]
#[should_panic(expected = "scope address must be at most 64 bytes")]
fn create_program_rejects_wide_address() {
    let mut t = T::new();
    t.create(
        &owner(),
        NEAR,
        P {
            scope: vec![ScopeTarget {
                chain_id: 1,
                address: WIDE.repeat(17), // 17 characters, 68 bytes
            }],
            ..P::default()
        },
    );
}

#[test]
#[should_panic(expected = "verifier_pubkey must be base64 of a raw 32-byte X25519 public key")]
fn create_program_rejects_bad_pubkey() {
    let mut t = T::new();
    t.call(&owner(), NEAR).create_program(
        "p".into(),
        vec![],
        verifier(),
        STANDARD.encode([1u8; 31]),
        payouts(),
        U128(BOND),
        U128(FEE),
        U128(DISPUTE_BOND),
        60,
        60,
        60,
    );
}

#[test]
#[should_panic(expected = "at least one payout must be greater than zero")]
fn create_program_rejects_zero_payouts() {
    let mut t = T::new();
    t.create(
        &owner(),
        NEAR,
        P {
            payouts: Payouts {
                critical: U128(0),
                high: U128(0),
                medium: U128(0),
                low: U128(0),
            },
            ..P::default()
        },
    );
}

#[test]
#[should_panic(expected = "challenge_period_sec must be between 60 s and 30 days")]
fn create_program_rejects_long_challenge_period() {
    let mut t = T::new();
    t.create(
        &owner(),
        NEAR,
        P {
            challenge: MAX_CHALLENGE_PERIOD_SEC + 1,
            ..P::default()
        },
    );
}

#[test]
#[should_panic(expected = "pending_timeout_sec must be between 60 s and 365 days")]
fn create_program_rejects_long_pending_timeout() {
    let mut t = T::new();
    t.create(
        &owner(),
        NEAR,
        P {
            pending: MAX_PENDING_TIMEOUT_SEC + 1,
            ..P::default()
        },
    );
}

#[test]
#[should_panic(expected = "resolve_timeout_sec must be between 60 s and 30 days")]
fn create_program_rejects_long_resolve_timeout() {
    let mut t = T::new();
    t.create(
        &owner(),
        NEAR,
        P {
            resolve: MAX_RESOLVE_TIMEOUT_SEC + 1,
            ..P::default()
        },
    );
}

#[test]
fn create_program_accepts_bounds() {
    let mut t = T::new();
    let a = t.create(
        &owner(),
        NEAR,
        P {
            challenge: MAX_CHALLENGE_PERIOD_SEC,
            pending: MAX_PENDING_TIMEOUT_SEC,
            resolve: MAX_RESOLVE_TIMEOUT_SEC,
            ..P::default()
        },
    );
    let b = t.create(
        &owner(),
        NEAR,
        P {
            challenge: MIN_WINDOW_SEC,
            pending: MIN_WINDOW_SEC,
            resolve: MIN_WINDOW_SEC,
            ..P::default()
        },
    );
    assert_eq!(t.program(a).resolve_timeout_sec, 30 * DAY);
    assert_eq!(t.program(b).challenge_period_sec, 60);
}

#[test]
#[should_panic(expected = "dispute_bond must be at least the bond")]
fn create_program_rejects_dispute_bond_below_bond() {
    let mut t = T::new();
    t.create(
        &owner(),
        NEAR,
        P {
            bond: BOND,
            dispute_bond: BOND - 1,
            ..P::default()
        },
    );
}

#[test]
fn create_program_accepts_dispute_bond_equal_to_bond() {
    let mut t = T::new();
    let pid = t.create(
        &owner(),
        NEAR,
        P {
            dispute_bond: BOND,
            ..P::default()
        },
    );
    assert_eq!(t.program(pid).dispute_bond.0, BOND);
}

#[test]
fn top_up_by_anyone_increases_pool() {
    let mut t = T::new();
    let pid = t.create_program(10 * NEAR);
    let before = t.program(pid).pool.0;
    t.call(&stranger(), 3 * NEAR).top_up(pid);
    assert_eq!(event_names(), vec!["pool_topped_up"]);
    assert_eq!(t.program(pid).pool.0, before + 3 * NEAR);
}

#[test]
#[should_panic(expected = "attach a deposit to top up the pool")]
fn top_up_needs_deposit() {
    let mut t = T::new();
    let pid = t.create_program(10 * NEAR);
    t.call(&stranger(), 0).top_up(pid);
}

#[test]
#[should_panic(expected = "program not found")]
fn top_up_unknown_program() {
    let mut t = T::new();
    t.call(&stranger(), NEAR).top_up(7);
}

#[test]
fn set_active_by_owner() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    t.call(&owner(), 0).set_active(pid, false);
    assert!(!t.program(pid).active);
    t.call(&owner(), 0).set_active(pid, true);
    assert!(t.program(pid).active);
}

#[test]
#[should_panic(expected = "only the program owner can do this")]
fn set_active_only_owner() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    t.call(&stranger(), 0).set_active(pid, false);
}

#[test]
#[should_panic(expected = "program is not active")]
fn inactive_program_rejects_submissions() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    t.call(&owner(), 0).set_active(pid, false);
    t.submit(&hunter1(), pid, 1, 2 * NEAR);
}

#[test]
fn inactive_program_still_settles() {
    let (mut t, pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::Valid));
    t.call(&owner(), 0).set_active(pid, false);
    t.advance(CHALLENGE);
    t.finalize(sid);
    assert_eq!(t.sub(sid).status, Status::Paid);
}

// ----------------------------------------------------------------- withdraw_pool

#[test]
fn withdraw_pool_cannot_touch_reserved_funds() {
    let (mut t, pid, _sid) = setup_one();
    let p = t.program(pid);
    assert_eq!(p.reserved.0, RESERVATION);
    let available = p.pool.0 - p.reserved.0;
    t.call(&owner(), 0).withdraw_pool(pid, U128(available));
    assert_eq!(paid_to(&owner()), available);
    assert_eq!(event_names(), vec!["pool_withdrawn"]);
    let p = t.program(pid);
    assert_eq!(p.pool.0, RESERVATION);
    assert_eq!(p.reserved.0, RESERVATION);
    check_invariants(&mut t);
}

#[test]
#[should_panic(expected = "amount exceeds the unreserved part of the pool")]
fn withdraw_pool_over_unreserved_fails() {
    let (mut t, pid, _sid) = setup_one();
    let p = t.program(pid);
    let available = p.pool.0 - p.reserved.0;
    t.call(&owner(), 0).withdraw_pool(pid, U128(available + 1));
}

#[test]
#[should_panic(expected = "amount exceeds the unreserved part of the pool")]
fn withdraw_pool_blocked_while_valid_in_window() {
    let (mut t, pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::Valid));
    let p = t.program(pid);
    t.call(&owner(), 0)
        .withdraw_pool(pid, U128(p.pool.0 - p.reserved.0));
    t.call(&owner(), 0).withdraw_pool(pid, U128(1));
}

#[test]
#[should_panic(expected = "amount exceeds the unreserved part of the pool")]
fn withdraw_pool_blocked_while_disputed() {
    let (mut t, pid, _sid) = setup_disputed();
    let p = t.program(pid);
    t.call(&owner(), 0)
        .withdraw_pool(pid, U128(p.pool.0 - p.reserved.0));
    t.call(&owner(), 0).withdraw_pool(pid, U128(1));
}

#[test]
#[should_panic(expected = "only the program owner can do this")]
fn withdraw_pool_only_program_owner() {
    let (mut t, pid, _sid) = setup_one();
    t.call(&stranger(), 0).withdraw_pool(pid, U128(1));
}

#[test]
#[should_panic(expected = "only the program owner can do this")]
fn contract_owner_cannot_withdraw_program_funds() {
    let (mut t, pid, _sid) = setup_one();
    t.call(&deployer(), 0).withdraw_pool(pid, U128(1));
}

#[test]
#[should_panic(expected = "only the program owner can do this")]
fn contract_owner_cannot_resolve() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::NeedsHuman));
    t.call(&deployer(), 0)
        .resolve(sid, "invalid".into(), None, "".into());
}

#[test]
#[should_panic(expected = "only the program owner can do this")]
fn contract_owner_cannot_dispute() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::Valid));
    t.call(&deployer(), DISPUTE_BOND).dispute(sid, "x".into());
}

#[test]
#[should_panic(expected = "amount must be greater than zero")]
fn withdraw_pool_zero_fails() {
    let (mut t, pid, _sid) = setup_one();
    t.call(&owner(), 0).withdraw_pool(pid, U128(0));
}

#[test]
fn withdraw_pool_frees_after_settlement() {
    let (mut t, pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::Invalid));
    let p = t.program(pid);
    assert_eq!(p.reserved.0, 0);
    t.call(&owner(), 0).withdraw_pool(pid, p.pool);
    assert_eq!(t.program(pid).pool.0, 0);
    check_invariants(&mut t);
}

// ---------------------------------------------------------------- submissions

#[test]
fn submit_charges_storage_and_records_bond() {
    let (mut t, pid, sid) = setup_one();
    let ev = events(); // logs of the submit call (views reset the mocked context)
    let s = t.sub(sid);
    assert_eq!(s.id, 0);
    assert_eq!(s.program_id, pid);
    assert_eq!(s.hunter_id, hunter1());
    assert_eq!(s.status, Status::Pending);
    assert_eq!(s.commitment, commit(1));
    assert_eq!(s.submitted_at.0, 1_000 * NANOS_PER_SEC);
    assert_eq!(s.submitted_block.0, 2_000);
    assert!(s.verdict.is_none() && s.resolution.is_none() && s.dispute_reason.is_none());
    assert!(s.valid_until.is_none() && s.resolve_until.is_none());
    assert_eq!(s.dispute_bond.0, 0);
    assert!(!s.funded_by_vault);
    assert_eq!(s.payout.0, 0);
    let storage = s.storage_cost.0;
    assert_eq!(storage % BYTE, 0);
    let sealed_len = "c2VhbGVk".repeat(16).len() as u128;
    assert!(storage >= (sealed_len + LATER_WRITES_STORAGE_BYTES as u128) * BYTE);
    assert_eq!(s.bond.0, 2 * NEAR - storage);
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["event"], "report_submitted");
    assert_eq!(ev[0]["version"], "2.0.0");
    assert_eq!(ev[0]["data"][0]["bond"], s.bond.0.to_string());
    assert_eq!(ev[0]["data"][0]["storage_cost"], storage.to_string());
    assert_eq!(ev[0]["data"][0]["funded_by_vault"], false);
    assert_eq!(t.view().get_sealed(sid).unwrap(), "c2VhbGVk".repeat(16));
    let p = t.program(pid);
    assert_eq!(p.reserved.0, RESERVATION);
    assert_eq!(p.stats.submissions, 1);
    assert_eq!(t.view().get_hunter(hunter1()).submissions, 1);
    assert_eq!(
        t.view().get_hunter_in_program(pid, hunter1()).submissions,
        1
    );
    check_invariants(&mut t);
}

#[test]
fn storage_cost_tracks_sealed_size_exactly() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    // warm up the hunter records so both submissions create the same kind of entries
    t.submit(&hunter1(), pid, 1, 2 * NEAR);
    let a =
        t.call(&hunter1(), 2 * NEAR)
            .submit_report(pid, "A".into(), commit(2), "x".repeat(1_000));
    let b =
        t.call(&hunter1(), 2 * NEAR)
            .submit_report(pid, "B".into(), commit(3), "x".repeat(11_000));
    let (sa, sb) = (t.sub(a).storage_cost.0, t.sub(b).storage_cost.0);
    assert_eq!(sb - sa, 10_000 * BYTE);
}

#[test]
fn submit_with_max_sealed_size() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    let sid = t.call(&hunter1(), 3 * NEAR).submit_report(
        pid,
        "big".into(),
        commit(9),
        "s".repeat(MAX_SEALED_BYTES),
    );
    assert_eq!(t.view().get_sealed(sid).unwrap().len(), MAX_SEALED_BYTES);
}

#[test]
#[should_panic(expected = "sealed report must be at most 64 KiB")]
fn submit_rejects_oversized_sealed() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    t.call(&hunter1(), 3 * NEAR).submit_report(
        pid,
        "big".into(),
        commit(9),
        "s".repeat(MAX_SEALED_BYTES + 1),
    );
}

#[test]
#[should_panic(expected = "sealed report must not be empty")]
fn submit_rejects_empty_sealed() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    t.call(&hunter1(), 3 * NEAR)
        .submit_report(pid, "t".into(), commit(9), "".into());
}

#[test]
#[should_panic(expected = "title must be 1..=120 bytes")]
fn submit_rejects_long_title() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    t.call(&hunter1(), 3 * NEAR)
        .submit_report(pid, "t".repeat(121), commit(9), "s".into());
}

#[test]
#[should_panic(expected = "title must be 1..=120 bytes")]
fn submit_rejects_wide_title_over_120_bytes() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    // 31 characters, 124 bytes
    t.call(&hunter1(), 3 * NEAR)
        .submit_report(pid, WIDE.repeat(31), commit(9), "s".into());
}

#[test]
fn submit_accepts_wide_title_of_120_bytes() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    let sid =
        t.call(&hunter1(), 3 * NEAR)
            .submit_report(pid, WIDE.repeat(30), commit(9), "s".into());
    assert_eq!(t.sub(sid).title.len(), 120);
}

#[test]
#[should_panic(expected = "title must be 1..=120 bytes")]
fn submit_rejects_empty_title() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    t.call(&hunter1(), 3 * NEAR)
        .submit_report(pid, "".into(), commit(9), "s".into());
}

#[test]
#[should_panic(expected = "commitment must be 64 lowercase hex characters")]
fn submit_rejects_uppercase_commitment() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    t.call(&hunter1(), 3 * NEAR)
        .submit_report(pid, "t".into(), "AB".repeat(32), "s".into());
}

#[test]
#[should_panic(expected = "commitment must be 64 lowercase hex characters")]
fn submit_rejects_short_commitment() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    t.call(&hunter1(), 3 * NEAR)
        .submit_report(pid, "t".into(), "ab".repeat(31), "s".into());
}

#[test]
#[should_panic(expected = "commitment already used")]
fn commitment_is_single_use() {
    let (mut t, pid, _sid) = setup_one();
    t.submit(&hunter2(), pid, 1, 2 * NEAR);
}

#[test]
#[should_panic(expected = "commitment already used")]
fn commitment_single_use_across_programs_and_after_settlement() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::Invalid));
    let other = t.create_program(100 * NEAR);
    t.submit(&hunter1(), other, 1, 2 * NEAR);
}

#[test]
#[should_panic(expected = "is too small")]
fn submit_rejects_bond_below_required() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    // storage alone is ~0.02 NEAR, the bond is 1 NEAR
    t.submit(&hunter1(), pid, 1, NEAR);
}

#[test]
#[should_panic(expected = "is too small: storage")]
fn submit_rejects_deposit_below_storage() {
    let mut t = T::new();
    let pid = t.create_program_with(100 * NEAR, 0, FEE);
    t.submit(&hunter1(), pid, 1, 1_000 * BYTE);
}

#[test]
fn submit_with_zero_bond_program_only_pays_storage() {
    let mut t = T::new();
    let pid = t.create_program_with(100 * NEAR, 0, FEE);
    let sid = t.submit(&hunter1(), pid, 1, NEAR / 10);
    let s = t.sub(sid);
    assert_eq!(s.bond.0, NEAR / 10 - s.storage_cost.0);
}

#[test]
#[should_panic(expected = "program pool is underfunded for a new submission")]
fn submit_rejects_when_pool_underfunded() {
    let mut t = T::new();
    // pool ~= 10 NEAR - storage < reservation (10 NEAR + fee)
    let pid = t.create_program(10 * NEAR);
    t.submit(&hunter1(), pid, 1, 2 * NEAR);
}

#[test]
#[should_panic(expected = "program not found")]
fn submit_to_unknown_program() {
    let mut t = T::new();
    t.submit(&hunter1(), 3, 1, 2 * NEAR);
}

#[test]
fn reserved_never_exceeds_pool() {
    let mut t = T::new();
    // room for exactly 4 reservations
    let pid = t.create_program(4 * RESERVATION + NEAR / 10);
    for n in 1..=4 {
        t.submit(&hunter1(), pid, n, 2 * NEAR);
        check_invariants(&mut t);
    }
    let p = t.program(pid);
    assert_eq!(p.reserved.0, 4 * RESERVATION);
    assert!(p.pool.0 - p.reserved.0 < RESERVATION);
    // the 5th must fail (before any write)
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        t.submit(&hunter1(), pid, 5, 2 * NEAR);
    }));
    assert!(r.is_err());
    // topping up makes room again
    t.call(&stranger(), RESERVATION).top_up(pid);
    t.submit(&hunter2(), pid, 6, 2 * NEAR);
    check_invariants(&mut t);
}

// ------------------------------------------------- storage pre-paid for later writes

#[test]
fn later_writes_constant_is_the_borsh_maximum() {
    assert_eq!(VERDICT_MAX_BYTES, 780);
    assert_eq!(DISPUTE_REASON_MAX_BYTES, 284);
    assert_eq!(RESOLUTION_MAX_BYTES, 295);
    assert_eq!(LATER_WRITES_STORAGE_BYTES, 1_359);
    assert_eq!(VAULT_POLICY_STORAGE_BYTES, 260);
}

/// Maximal later writes on one submission: a valid verdict with every optional field set and
/// every text at its byte limit, a dispute with a maximal reason, then a resolution with a
/// maximal note. `fill` is the character the texts are made of.
fn max_verdict(fill: &str, duplicate_of: u64) -> VerdictInput {
    let rep = |limit: usize| fill.repeat(limit / fill.len());
    VerdictInput {
        outcome: Outcome::Valid,
        severity: Some(Severity::Critical),
        duplicate_of: Some(duplicate_of),
        fingerprint: rep(MAX_FINGERPRINT_BYTES),
        evidence_sha256: "ab".repeat(32),
        evidence_uri: rep(MAX_EVIDENCE_URI_BYTES),
        chain_id: u64::MAX,
        fork_block: U64(u64::MAX),
        reason: rep(MAX_REASON_BYTES),
    }
}

/// Runs `f`; true if it did not panic. Every refusal used with it happens before any write.
fn attempt(f: impl FnOnce()) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_ok()
}

/// Runs a minimal submission and the maximal sequence of later writes; after every step, the
/// storage this submission caused stays within the bytes the hunter pre-paid. Every text is
/// first tried at v1's limit (that many *characters* of `fill`); a contract that counts bytes
/// refuses it before writing anything, and the byte maximum is used instead. Under v1
/// semantics the first try is accepted and the storage check fails. Returns
/// (prepaid bytes, peak bytes used).
fn later_writes_scenario(fill: &str, from_vault: bool) -> (u64, u64) {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    if from_vault {
        t.vault_deposit(&hunter1(), 10 * NEAR);
        t.set_policy(&hunter1(), BOND, 10 * NEAR, Some((0..32).collect()));
    }
    // an earlier submission, so the verdict can carry Some(duplicate_of)
    t.submit(&hunter2(), pid, 99, 2 * NEAR);
    t.switch(&hunter1(), if from_vault { 0 } else { 2 * NEAR });
    let base = t.flush_usage();
    // minimal report: 1-byte title, 1-byte sealed blob
    let sid = if from_vault {
        t.c.submit_report_from_vault(pid, "t".into(), commit(1), "s".into())
    } else {
        t.c.submit_report(pid, "t".into(), commit(1), "s".into())
    };
    let prepaid = (t.c.submission(sid).storage_cost / BYTE) as u64;
    let mut peak = 0u64;
    let mut check = |t: &mut T, step: &str| {
        let used = t.flush_usage() - base;
        assert!(
            used <= prepaid,
            "{}: used {} bytes > prepaid {} bytes",
            step,
            used,
            prepaid
        );
        peak = peak.max(used);
    };
    check(&mut t, "submit");
    let v1_verdict = VerdictInput {
        fingerprint: fill.repeat(MAX_FINGERPRINT_BYTES),
        evidence_uri: fill.repeat(MAX_EVIDENCE_URI_BYTES),
        reason: fill.repeat(MAX_REASON_BYTES),
        ..max_verdict(fill, 0)
    };
    if !attempt(|| t.post(sid, v1_verdict)) {
        t.post(sid, max_verdict(fill, 0));
    }
    check(&mut t, "verdict");
    let v1_text = fill.repeat(MAX_NOTE_BYTES);
    let text = fill.repeat(MAX_NOTE_BYTES / fill.len());
    if !attempt(|| t.call(&owner(), DISPUTE_BOND).dispute(sid, v1_text.clone())) {
        t.call(&owner(), DISPUTE_BOND).dispute(sid, text.clone());
    }
    check(&mut t, "dispute");
    let resolve = |t: &mut T, note: String| {
        t.call(&owner(), 0)
            .resolve(sid, "invalid".into(), Some(Severity::Critical), note)
    };
    if !attempt(|| resolve(&mut t, v1_text)) {
        resolve(&mut t, text);
    }
    check(&mut t, "resolve");
    // settlement only overwrites fixed-size fields
    assert_eq!(t.sub(sid).status, Status::Rejected);
    check(&mut t, "settled");
    (prepaid, peak)
}

#[test]
fn later_writes_never_exceed_prepaid_storage_ascii() {
    let (prepaid, peak) = later_writes_scenario("x", false);
    assert!(peak <= prepaid);
}

#[test]
fn later_writes_never_exceed_prepaid_storage_four_byte_chars() {
    // regression S4: v1 limited characters, so 4-byte text could write 4x the pre-paid bytes
    let (prepaid, peak) = later_writes_scenario(WIDE, false);
    assert!(peak <= prepaid);
}

#[test]
fn later_writes_never_exceed_prepaid_storage_vault_funded() {
    let (prepaid, peak) = later_writes_scenario(WIDE, true);
    assert!(peak <= prepaid);
}

#[test]
fn later_writes_constant_is_tight() {
    // the submission record grows by exactly LATER_WRITES_STORAGE_BYTES in the maximal case
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    t.submit(&hunter2(), pid, 99, 2 * NEAR);
    let sid = t.submit(&hunter1(), pid, 1, 2 * NEAR);
    let len = |t: &mut T| borsh::to_vec(t.c.submission(sid)).unwrap().len() as u64;
    let before = len(&mut t);
    t.post(sid, max_verdict(WIDE, 0));
    t.call(&owner(), DISPUTE_BOND)
        .dispute(sid, WIDE.repeat(MAX_NOTE_BYTES / 4));
    t.call(&owner(), 0).resolve(
        sid,
        "valid".into(),
        Some(Severity::Low),
        WIDE.repeat(MAX_NOTE_BYTES / 4),
    );
    assert_eq!(len(&mut t) - before, LATER_WRITES_STORAGE_BYTES);
}

#[test]
fn later_writes_other_paths_stay_within_prepaid() {
    // needs_human -> resolve, and valid -> dispute -> finalize after the deadline
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    t.submit(&hunter2(), pid, 99, 2 * NEAR);
    t.switch(&hunter1(), 2 * NEAR);
    let base = t.flush_usage();
    let a = t.c.submit_report(pid, "a".into(), commit(1), "s".into());
    let b = t.submit(&hunter1(), pid, 2, 2 * NEAR);
    let prepaid = ((t.c.submission(a).storage_cost + t.c.submission(b).storage_cost) / BYTE) as u64;
    let mut nh = max_verdict(WIDE, 0);
    nh.outcome = Outcome::NeedsHuman;
    t.post(a, nh);
    t.post(b, max_verdict(WIDE, 0));
    t.call(&owner(), 0).resolve(
        a,
        "valid".into(),
        Some(Severity::Low),
        WIDE.repeat(MAX_NOTE_BYTES / 4),
    );
    t.call(&owner(), DISPUTE_BOND)
        .dispute(b, WIDE.repeat(MAX_NOTE_BYTES / 4));
    t.advance(RESOLVE);
    t.finalize(b);
    assert!(t.flush_usage() - base <= prepaid);
}

// --------------------------------------------------------------- required_bond

fn set_hunter(t: &mut T, pid: u64, valid: u64, invalid: u64) {
    t.c.program_hunters.insert(
        (pid, hunter1()),
        HunterStats {
            valid,
            invalid,
            ..Default::default()
        },
    );
}

#[test]
fn required_bond_tiers() {
    let mut t = T::new();
    let pid = t.create(
        &owner(),
        100 * NEAR,
        P {
            bond: 4 * NEAR,
            dispute_bond: 4 * NEAR,
            ..P::default()
        },
    );
    assert_eq!(t.view().required_bond(pid, hunter1()).0, 4 * NEAR);
    set_hunter(&mut t, pid, 1, 0);
    assert_eq!(t.view().required_bond(pid, hunter1()).0, 2 * NEAR);
    set_hunter(&mut t, pid, 2, 1);
    assert_eq!(t.view().required_bond(pid, hunter1()).0, 2 * NEAR);
    set_hunter(&mut t, pid, 3, 0);
    assert_eq!(t.view().required_bond(pid, hunter1()).0, NEAR);
    set_hunter(&mut t, pid, 3, 1);
    assert_eq!(t.view().required_bond(pid, hunter1()).0, 2 * NEAR);
    set_hunter(&mut t, pid, 1, 2);
    assert_eq!(t.view().required_bond(pid, hunter1()).0, 8 * NEAR);
    set_hunter(&mut t, pid, 0, 1);
    assert_eq!(t.view().required_bond(pid, hunter1()).0, 8 * NEAR);
    set_hunter(&mut t, pid, 2, 2);
    assert_eq!(t.view().required_bond(pid, hunter1()).0, 2 * NEAR);
}

#[test]
fn required_bond_ignores_global_stats() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    t.c.hunters.insert(
        hunter1(),
        HunterStats {
            valid: 10,
            ..Default::default()
        },
    );
    assert_eq!(t.view().required_bond(pid, hunter1()).0, BOND);
}

#[test]
fn required_bond_follows_real_outcomes_per_program() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    let other = t.create_program(100 * NEAR);
    let sid = t.submit(&hunter1(), pid, 1, 2 * NEAR);
    t.post(sid, verdict(Outcome::Invalid));
    assert_eq!(t.view().required_bond(pid, hunter1()).0, 2 * BOND);
    // the strike counts in this program only
    assert_eq!(t.view().required_bond(other, hunter1()).0, BOND);
    assert_eq!(t.view().required_bond(pid, hunter2()).0, BOND);
    // 1.5 NEAR still covers bond + storage for a fresh hunter
    t.submit(&hunter2(), pid, 3, 3 * NEAR / 2);
}

#[test]
fn required_bond_halves_after_a_paid_report_in_the_same_program() {
    let (mut t, pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::Valid));
    t.advance(CHALLENGE);
    t.finalize(sid);
    assert_eq!(t.view().required_bond(pid, hunter1()).0, BOND / 2);
    let h = t.view().get_hunter_in_program(pid, hunter1());
    assert_eq!((h.submissions, h.valid, h.earned.0), (1, 1, 5 * NEAR));
}

#[test]
#[should_panic(expected = "is too small")]
fn slashed_hunter_needs_double_bond() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    let sid = t.submit(&hunter1(), pid, 1, 2 * NEAR);
    t.post(sid, verdict(Outcome::Invalid));
    t.submit(&hunter1(), pid, 2, 3 * NEAR / 2);
}

// --------------------------------------------------------------- post_verdict

#[test]
#[should_panic(expected = "only the program verifier can post verdicts")]
fn only_verifier_posts_verdicts() {
    let (mut t, _pid, sid) = setup_one();
    t.call(&stranger(), 0)
        .post_verdict(sid, verdict(Outcome::Valid));
}

#[test]
#[should_panic(expected = "only the program verifier can post verdicts")]
fn program_owner_cannot_post_verdicts() {
    let (mut t, _pid, sid) = setup_one();
    t.call(&owner(), 0)
        .post_verdict(sid, verdict(Outcome::Valid));
}

#[test]
#[should_panic(expected = "only the program verifier can post verdicts")]
fn hunter_cannot_post_verdicts() {
    let (mut t, _pid, sid) = setup_one();
    t.call(&hunter1(), 0)
        .post_verdict(sid, verdict(Outcome::Valid));
}

#[test]
#[should_panic(expected = "submission is not pending")]
fn verdict_only_once() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::NeedsHuman));
    t.post(sid, verdict(Outcome::Valid));
}

#[test]
#[should_panic(expected = "severity is required for a valid verdict")]
fn valid_verdict_needs_severity() {
    let (mut t, _pid, sid) = setup_one();
    let mut v = verdict(Outcome::Valid);
    v.severity = None;
    t.post(sid, v);
}

#[test]
#[should_panic(expected = "evidence_sha256 must be 64 lowercase hex characters")]
fn verdict_checks_evidence_hash() {
    let (mut t, _pid, sid) = setup_one();
    let mut v = verdict(Outcome::Invalid);
    v.evidence_sha256 = "XY".repeat(32);
    t.post(sid, v);
}

#[test]
#[should_panic(expected = "reason must be at most 280 bytes")]
fn verdict_checks_reason_length() {
    let (mut t, _pid, sid) = setup_one();
    let mut v = verdict(Outcome::Invalid);
    v.reason = "r".repeat(281);
    t.post(sid, v);
}

#[test]
#[should_panic(expected = "reason must be at most 280 bytes")]
fn verdict_checks_reason_bytes_not_chars() {
    let (mut t, _pid, sid) = setup_one();
    let mut v = verdict(Outcome::Invalid);
    v.reason = WIDE.repeat(71); // 71 characters, 284 bytes
    t.post(sid, v);
}

#[test]
#[should_panic(expected = "fingerprint must be at most 128 bytes")]
fn verdict_checks_fingerprint_length() {
    let (mut t, _pid, sid) = setup_one();
    let mut v = verdict(Outcome::Invalid);
    v.fingerprint = "f".repeat(129);
    t.post(sid, v);
}

#[test]
#[should_panic(expected = "fingerprint must be at most 128 bytes")]
fn verdict_checks_fingerprint_bytes_not_chars() {
    let (mut t, _pid, sid) = setup_one();
    let mut v = verdict(Outcome::Invalid);
    v.fingerprint = WIDE.repeat(33);
    t.post(sid, v);
}

#[test]
#[should_panic(expected = "evidence_uri must be at most 256 bytes")]
fn verdict_checks_uri_length() {
    let (mut t, _pid, sid) = setup_one();
    let mut v = verdict(Outcome::Invalid);
    v.evidence_uri = "u".repeat(257);
    t.post(sid, v);
}

#[test]
#[should_panic(expected = "evidence_uri must be at most 256 bytes")]
fn verdict_checks_uri_bytes_not_chars() {
    let (mut t, _pid, sid) = setup_one();
    let mut v = verdict(Outcome::Invalid);
    v.evidence_uri = WIDE.repeat(65);
    t.post(sid, v);
}

#[test]
fn verdict_accepts_texts_exactly_at_byte_limits() {
    let (mut t, _pid, sid) = setup_one();
    let mut v = verdict(Outcome::NeedsHuman);
    v.fingerprint = WIDE.repeat(32);
    v.evidence_uri = WIDE.repeat(64);
    v.reason = WIDE.repeat(70);
    t.post(sid, v);
    let s = t.sub(sid);
    let v = s.verdict.unwrap();
    assert_eq!(
        (v.fingerprint.len(), v.evidence_uri.len(), v.reason.len()),
        (128, 256, 280)
    );
}

#[test]
#[should_panic(expected = "submission not found")]
fn verdict_on_unknown_submission() {
    let mut t = T::new();
    t.post(5, verdict(Outcome::Invalid));
}

#[test]
fn verdict_json_shape_and_defaults() {
    // the worker may omit optional fields
    let v: VerdictInput = serde_json::from_str(
        r#"{"outcome":"needs_human","evidence_sha256":"00","chain_id":0,"fork_block":"5","reason":"x"}"#,
    )
    .unwrap();
    assert_eq!(v.outcome, Outcome::NeedsHuman);
    assert!(v.severity.is_none() && v.duplicate_of.is_none());
    assert_eq!(v.fingerprint, "");
    let v: VerdictInput = serde_json::from_str(
        r#"{"outcome":"duplicate","severity":null,"duplicate_of":3,"fingerprint":"f","evidence_sha256":"00","evidence_uri":"","chain_id":1,"fork_block":"19000000","reason":"x"}"#,
    )
    .unwrap();
    assert_eq!(v.duplicate_of, Some(3));
    assert_eq!(v.fork_block.0, 19_000_000);
}

#[test]
fn invalid_verdict_slashes_bond() {
    let (mut t, pid, sid) = setup_one();
    let pool_before = t.program(pid).pool.0;
    let bond = t.sub(sid).bond.0;
    t.post(sid, verdict(Outcome::Invalid));
    // fee from the bond to the verifier, the rest into the pool, nothing to the hunter
    assert_eq!(paid_to(&verifier()), FEE);
    assert_eq!(paid_to(&hunter1()), 0);
    assert_eq!(event_names(), vec!["verdict_posted", "bond_slashed"]);
    let ev = events();
    assert_eq!(ev[1]["data"][0]["to_pool"], (bond - FEE).to_string());
    let p = t.program(pid);
    assert_eq!(p.pool.0, pool_before + bond - FEE);
    assert_eq!(p.reserved.0, 0);
    assert_eq!(p.stats.invalid, 1);
    let s = t.sub(sid);
    assert_eq!(s.status, Status::Invalid);
    assert_eq!(s.verdict.unwrap().outcome, Outcome::Invalid);
    let h = t.view().get_hunter(hunter1());
    assert_eq!((h.submissions, h.invalid, h.valid), (1, 1, 0));
    let h = t.view().get_hunter_in_program(pid, hunter1());
    assert_eq!((h.submissions, h.invalid, h.valid), (1, 1, 0));
    check_invariants(&mut t);
}

#[test]
fn invalid_verdict_fee_capped_by_bond() {
    let mut t = T::new();
    // verifier fee (0.5 NEAR) larger than the posted bond
    let pid = t.create_program_with(100 * NEAR, 0, NEAR / 2);
    let sid = t.submit(&hunter1(), pid, 1, NEAR / 10);
    let bond = t.sub(sid).bond.0;
    assert!(bond < NEAR / 2);
    let pool_before = t.program(pid).pool.0;
    t.post(sid, verdict(Outcome::Invalid));
    assert_eq!(paid_to(&verifier()), bond);
    assert_eq!(t.program(pid).pool.0, pool_before);
    check_invariants(&mut t);
}

#[test]
fn duplicate_of_valid_refunds_bond_minus_fee() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    let first = t.submit(&hunter1(), pid, 1, 2 * NEAR);
    let dup = t.submit(&hunter2(), pid, 2, 2 * NEAR);
    t.post(first, verdict(Outcome::Valid));
    let pool_before = t.program(pid).pool.0;
    let bond = t.sub(dup).bond.0;
    t.post(dup, dup_of(first));
    assert_eq!(paid_to(&verifier()), FEE);
    assert_eq!(paid_to(&hunter2()), bond - FEE);
    assert_eq!(event_names(), vec!["verdict_posted", "bond_refunded"]);
    assert_eq!(event_data("bond_refunded")["to"], "hunter");
    let p = t.program(pid);
    assert_eq!(p.pool.0, pool_before);
    assert_eq!(p.reserved.0, RESERVATION); // only the first is still open
    assert_eq!(p.stats.duplicate, 1);
    let s = t.sub(dup);
    assert_eq!(s.status, Status::Duplicate);
    assert_eq!(s.verdict.unwrap().duplicate_of, Some(first));
    assert_eq!(t.view().get_hunter(hunter2()).duplicate, 1);
    check_invariants(&mut t);
}

#[test]
fn duplicate_of_paid_original_is_accepted() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    let first = t.submit(&hunter1(), pid, 1, 2 * NEAR);
    let dup = t.submit(&hunter2(), pid, 2, 2 * NEAR);
    t.post(first, verdict(Outcome::Valid));
    t.advance(CHALLENGE);
    t.finalize(first);
    t.post(dup, dup_of(first));
    assert_eq!(t.sub(dup).status, Status::Duplicate);
}

#[test]
fn duplicate_of_disputed_original_is_accepted() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    let first = t.submit(&hunter1(), pid, 1, 2 * NEAR);
    let dup = t.submit(&hunter2(), pid, 2, 2 * NEAR);
    t.post(first, verdict(Outcome::Valid));
    t.dispute(first, DISPUTE_BOND);
    t.post(dup, dup_of(first));
    assert_eq!(t.sub(dup).status, Status::Duplicate);
}

#[test]
#[should_panic(expected = "duplicate_of is required for a duplicate")]
fn duplicate_needs_duplicate_of() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::Duplicate));
}

#[test]
#[should_panic(expected = "duplicate_of must be an earlier submission")]
fn duplicate_of_self_rejected() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, dup_of(sid));
}

#[test]
#[should_panic(expected = "duplicate_of must be an earlier submission")]
fn duplicate_of_later_rejected() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    let a = t.submit(&hunter1(), pid, 1, 2 * NEAR);
    let b = t.submit(&hunter2(), pid, 2, 2 * NEAR);
    t.post(a, dup_of(b));
}

#[test]
#[should_panic(expected = "duplicate_of must belong to the same program")]
fn duplicate_of_other_program_rejected() {
    let mut t = T::new();
    let p0 = t.create_program(100 * NEAR);
    let p1 = t.create_program(100 * NEAR);
    let a = t.submit(&hunter1(), p0, 1, 2 * NEAR);
    let b = t.submit(&hunter2(), p1, 2, 2 * NEAR);
    t.post(a, verdict(Outcome::Valid));
    t.post(b, dup_of(a));
}

#[test]
fn needs_human_moves_no_money_and_sets_resolve_deadline() {
    let (mut t, pid, sid) = setup_one();
    let pool = t.program(pid).pool.0;
    t.post(sid, verdict(Outcome::NeedsHuman));
    assert!(transfers().is_empty());
    let p = t.program(pid);
    assert_eq!(p.pool.0, pool);
    assert_eq!(p.reserved.0, RESERVATION);
    assert_eq!(p.stats.needs_human, 1);
    let s = t.sub(sid);
    assert_eq!(s.status, Status::NeedsHuman);
    assert_eq!(
        s.resolve_until.unwrap().0,
        (1_000 + RESOLVE) * NANOS_PER_SEC
    );
    assert!(s.valid_until.is_none());
    assert_eq!(t.view().get_hunter(hunter1()).needs_human, 1);
    assert_eq!(
        t.view().get_hunter_in_program(pid, hunter1()).needs_human,
        1
    );
    check_invariants(&mut t);
}

// ---------------------------------------------------------- valid + finalize

#[test]
fn valid_then_finalize_after_window_pays() {
    let (mut t, pid, sid) = setup_one();
    let pool_before = t.program(pid).pool.0;
    let bond = t.sub(sid).bond.0;
    t.post(sid, verdict(Outcome::Valid));
    assert!(transfers().is_empty());
    let s = t.sub(sid);
    assert_eq!(s.status, Status::Valid);
    assert_eq!(
        s.valid_until.unwrap().0,
        (1_000 + CHALLENGE) * NANOS_PER_SEC
    );
    t.advance(CHALLENGE);
    t.finalize(sid);
    // payout (high = 5 NEAR) + bond to the hunter, fee to the verifier, both from the pool
    assert_eq!(paid_to(&hunter1()), 5 * NEAR + bond);
    assert_eq!(paid_to(&verifier()), FEE);
    assert_eq!(paid_to(&owner()), 0);
    assert_eq!(event_names(), vec!["report_paid", "bond_refunded"]);
    let d = event_data("report_paid");
    assert_eq!(d["dispute_bond"], "0");
    assert!(d["dispute_bond_to"].is_null());
    let p = t.program(pid);
    assert_eq!(p.pool.0, pool_before - 5 * NEAR - FEE);
    assert_eq!(p.reserved.0, 0);
    assert_eq!(p.stats.paid, 1);
    assert_eq!(p.stats.total_paid.0, 5 * NEAR);
    let s = t.sub(sid);
    assert_eq!(s.status, Status::Paid);
    assert_eq!(s.payout.0, 5 * NEAR);
    let h = t.view().get_hunter(hunter1());
    assert_eq!((h.valid, h.earned.0), (1, 5 * NEAR));
    check_invariants(&mut t);
}

#[test]
#[should_panic(expected = "challenge window has not ended yet")]
fn finalize_before_window_fails() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::Valid));
    t.advance(CHALLENGE - 1);
    t.finalize(sid);
}

#[test]
#[should_panic(expected = "only valid, disputed or needs_human submissions can be finalized")]
fn finalize_twice_fails() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::Valid));
    t.advance(CHALLENGE);
    t.finalize(sid);
    t.finalize(sid);
}

#[test]
#[should_panic(expected = "only valid, disputed or needs_human submissions can be finalized")]
fn finalize_pending_fails() {
    let (mut t, _pid, sid) = setup_one();
    t.finalize(sid);
}

#[test]
#[should_panic(expected = "only valid, disputed or needs_human submissions can be finalized")]
fn finalize_invalid_fails() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::Invalid));
    t.finalize(sid);
}

#[test]
fn payout_capped_by_pool() {
    let (mut t, pid, sid) = setup_one();
    let bond = t.sub(sid).bond.0;
    t.post(sid, verdict(Outcome::Valid));
    // Force a pool below the payout (unreachable through the public API, which keeps
    // pool >= reserved) to prove the cap: payout = pool, verifier fee = what is left (0).
    t.c.programs.get_mut(pid as u32).unwrap().pool = 3 * NEAR;
    t.advance(CHALLENGE);
    t.finalize(sid);
    assert_eq!(paid_to(&hunter1()), 3 * NEAR + bond);
    assert_eq!(paid_to(&verifier()), 0);
    let p = t.program(pid);
    assert_eq!(p.pool.0, 0);
    assert_eq!(t.sub(sid).payout.0, 3 * NEAR);
}

#[test]
fn critical_payout_through_public_api_is_always_covered() {
    let mut t = T::new();
    let pid = t.create_program(RESERVATION + NEAR / 10);
    let sid = t.submit(&hunter1(), pid, 1, 2 * NEAR);
    let mut v = verdict(Outcome::Valid);
    v.severity = Some(Severity::Critical);
    t.post(sid, v);
    let p = t.program(pid);
    t.call(&owner(), 0)
        .withdraw_pool(pid, U128(p.pool.0 - p.reserved.0));
    t.advance(CHALLENGE);
    let bond = t.sub(sid).bond.0;
    t.finalize(sid);
    assert_eq!(paid_to(&hunter1()), 10 * NEAR + bond);
    assert_eq!(paid_to(&verifier()), FEE);
    assert_eq!(t.program(pid).pool.0, 0);
    check_invariants(&mut t);
}

// ------------------------------------------------------------------- dispute

#[test]
fn dispute_in_window_holds_the_dispute_bond() {
    let (mut t, pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::Valid));
    t.advance(CHALLENGE - 1);
    t.call(&owner(), DISPUTE_BOND)
        .dispute(sid, "out of scope".into());
    assert_eq!(event_names(), vec!["report_disputed"]);
    let d = event_data("report_disputed");
    assert_eq!(d["dispute_bond"], DISPUTE_BOND.to_string());
    assert_eq!(d["refunded_excess"], "0");
    assert!(transfers().is_empty());
    let s = t.sub(sid);
    assert_eq!(s.status, Status::Disputed);
    assert_eq!(s.dispute_reason.as_deref(), Some("out of scope"));
    assert_eq!(s.dispute_bond.0, DISPUTE_BOND);
    assert_eq!(
        s.resolve_until.unwrap().0,
        (1_000 + CHALLENGE - 1 + RESOLVE) * NANOS_PER_SEC
    );
    let p = t.program(pid);
    assert_eq!(p.stats.disputes, 1);
    assert_eq!(p.reserved.0, RESERVATION);
    check_invariants(&mut t);
}

#[test]
fn dispute_refunds_excess_deposit() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::Valid));
    t.call(&owner(), DISPUTE_BOND + 7 * MILLI)
        .dispute(sid, "x".into());
    assert_eq!(paid_to(&owner()), 7 * MILLI);
    assert_eq!(
        event_data("report_disputed")["refunded_excess"],
        (7 * MILLI).to_string()
    );
    assert_eq!(t.sub(sid).dispute_bond.0, DISPUTE_BOND);
}

#[test]
#[should_panic(expected = "is below the program's dispute bond")]
fn dispute_needs_the_dispute_bond() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::Valid));
    t.call(&owner(), DISPUTE_BOND - 1).dispute(sid, "x".into());
}

#[test]
#[should_panic(expected = "is below the program's dispute bond")]
fn dispute_without_deposit_fails() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::Valid));
    t.call(&owner(), 0).dispute(sid, "x".into());
}

#[test]
#[should_panic(expected = "challenge window has ended")]
fn dispute_after_window_fails() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::Valid));
    t.advance(CHALLENGE);
    t.dispute(sid, DISPUTE_BOND);
}

#[test]
#[should_panic(expected = "only the program owner can do this")]
fn dispute_only_owner() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::Valid));
    t.call(&stranger(), DISPUTE_BOND).dispute(sid, "x".into());
}

#[test]
#[should_panic(expected = "only a valid verdict can be disputed")]
fn dispute_only_valid() {
    let (mut t, _pid, sid) = setup_one();
    t.dispute(sid, DISPUTE_BOND);
}

#[test]
#[should_panic(expected = "only a valid verdict can be disputed")]
fn dispute_twice_fails() {
    let (mut t, _pid, sid) = setup_disputed();
    t.dispute(sid, DISPUTE_BOND);
}

#[test]
#[should_panic(expected = "reason must be at most 280 bytes")]
fn dispute_reason_counts_bytes() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::Valid));
    t.call(&owner(), DISPUTE_BOND).dispute(sid, WIDE.repeat(71));
}

#[test]
#[should_panic(expected = "resolve deadline has not passed yet")]
fn disputed_cannot_be_finalized_before_resolve_deadline() {
    let (mut t, _pid, sid) = setup_disputed();
    t.advance(RESOLVE - 1);
    t.finalize(sid);
}

#[test]
fn disputed_unresolved_finalize_pays_hunter_plus_dispute_bond() {
    let (mut t, pid, sid) = setup_disputed();
    let bond = t.sub(sid).bond.0;
    let pool = t.program(pid).pool.0;
    t.advance(RESOLVE);
    t.finalize(sid);
    // payout (high) + bond + the owner's dispute bond to the hunter; fee to the verifier
    assert_eq!(paid_to(&hunter1()), 5 * NEAR + bond + DISPUTE_BOND);
    assert_eq!(paid_to(&verifier()), FEE);
    assert_eq!(paid_to(&owner()), 0);
    assert_eq!(event_names(), vec!["report_paid", "bond_refunded"]);
    let d = event_data("report_paid");
    assert_eq!(d["dispute_bond"], DISPUTE_BOND.to_string());
    assert_eq!(d["dispute_bond_to"], "hunter");
    let p = t.program(pid);
    assert_eq!(p.pool.0, pool - 5 * NEAR - FEE);
    assert_eq!(p.reserved.0, 0);
    assert_eq!(
        (p.stats.disputes, p.stats.overruled, p.stats.paid),
        (1, 0, 1)
    );
    assert_eq!(t.sub(sid).status, Status::Paid);
    assert_eq!(t.view().get_hunter_in_program(pid, hunter1()).valid, 1);
    check_invariants(&mut t);
}

// ------------------------------------------------------------------- resolve

#[test]
fn resolve_needs_human_as_valid_pays_now() {
    let (mut t, pid, sid) = setup_one();
    let bond = t.sub(sid).bond.0;
    t.post(sid, verdict(Outcome::NeedsHuman));
    t.call(&owner(), 0).resolve(
        sid,
        "valid".into(),
        Some(Severity::Medium),
        "confirmed by hand".into(),
    );
    assert_eq!(paid_to(&hunter1()), 2 * NEAR + bond);
    assert_eq!(paid_to(&verifier()), FEE);
    assert_eq!(
        event_names(),
        vec!["report_resolved", "report_paid", "bond_refunded"]
    );
    let s = t.sub(sid);
    assert_eq!(s.status, Status::Paid);
    let r = s.resolution.unwrap();
    assert_eq!(
        (r.by.as_str(), r.outcome.as_str(), r.severity),
        ("owner", "valid", Some(Severity::Medium))
    );
    assert_eq!(t.program(pid).reserved.0, 0);
    check_invariants(&mut t);
}

#[test]
fn resolve_needs_human_as_invalid_slashes() {
    let (mut t, pid, sid) = setup_one();
    let bond = t.sub(sid).bond.0;
    t.post(sid, verdict(Outcome::NeedsHuman));
    let pool = t.program(pid).pool.0;
    t.resolve(sid, "invalid", None);
    // the verifier escalated and posted a verdict, so it gets its fee from the bond
    assert_eq!(paid_to(&verifier()), FEE);
    assert_eq!(paid_to(&hunter1()), 0);
    let p = t.program(pid);
    assert_eq!(p.pool.0, pool + bond - FEE);
    assert_eq!(p.reserved.0, 0);
    assert_eq!(p.stats.overruled, 0);
    assert_eq!(t.sub(sid).status, Status::Rejected);
    assert_eq!(t.view().get_hunter(hunter1()).invalid, 1);
    assert_eq!(t.view().get_hunter_in_program(pid, hunter1()).invalid, 1);
    check_invariants(&mut t);
}

#[test]
fn resolve_needs_human_as_duplicate() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    let _first = t.submit(&hunter1(), pid, 1, 2 * NEAR);
    let sid = t.submit(&hunter2(), pid, 2, 2 * NEAR);
    let bond = t.sub(sid).bond.0;
    t.post(sid, verdict(Outcome::NeedsHuman));
    t.resolve(sid, "duplicate", None);
    assert_eq!(paid_to(&hunter2()), bond - FEE);
    assert_eq!(paid_to(&verifier()), FEE);
    assert_eq!(t.sub(sid).status, Status::Duplicate);
    check_invariants(&mut t);
}

#[test]
fn resolve_disputed_as_valid_returns_dispute_bond_to_owner() {
    let (mut t, pid, sid) = setup_disputed();
    let bond = t.sub(sid).bond.0;
    // severity omitted: the verifier's (high) is used
    t.resolve(sid, "valid", None);
    assert_eq!(paid_to(&hunter1()), 5 * NEAR + bond);
    assert_eq!(paid_to(&verifier()), FEE);
    assert_eq!(paid_to(&owner()), DISPUTE_BOND);
    let d = event_data("report_paid");
    assert_eq!(d["severity"], "high");
    assert_eq!(d["dispute_bond_to"], "owner");
    let s = t.sub(sid);
    assert_eq!(s.status, Status::Paid);
    assert_eq!(s.resolution.unwrap().severity, Some(Severity::High));
    let p = t.program(pid);
    assert_eq!((p.stats.disputes, p.stats.overruled), (1, 0));
    check_invariants(&mut t);
}

#[test]
fn resolve_disputed_as_valid_with_explicit_severity() {
    let (mut t, _pid, sid) = setup_disputed();
    let bond = t.sub(sid).bond.0;
    t.resolve(sid, "valid", Some(Severity::Critical));
    assert_eq!(paid_to(&hunter1()), 10 * NEAR + bond);
    assert_eq!(paid_to(&owner()), DISPUTE_BOND);
}

#[test]
fn resolve_disputed_as_valid_with_lower_severity_costs_the_dispute_bond() {
    let (mut t, pid, sid) = setup_disputed();
    let bond = t.sub(sid).bond.0;
    // the verifier said high (5 NEAR); the owner pays only medium (2 NEAR): a partial overrule
    t.resolve(sid, "valid", Some(Severity::Medium));
    assert_eq!(paid_to(&hunter1()), 2 * NEAR + bond + DISPUTE_BOND);
    assert_eq!(paid_to(&owner()), 0);
    assert_eq!(event_data("report_paid")["dispute_bond_to"], "hunter");
    let p = t.program(pid);
    assert_eq!((p.stats.disputes, p.stats.overruled), (1, 1));
    assert_eq!(t.sub(sid).status, Status::Paid);
    check_invariants(&mut t);
}

#[test]
fn resolve_disputed_as_invalid_pays_hunter_bond_plus_dispute_bond() {
    let (mut t, pid, sid) = setup_disputed();
    let bond = t.sub(sid).bond.0;
    let pool = t.program(pid).pool.0;
    t.resolve(sid, "invalid", None);
    // the owner overrules a valid verdict: no payout, but it costs the dispute bond
    assert_eq!(event_names(), vec!["report_resolved", "bond_refunded"]);
    let d = event_data("bond_refunded");
    assert_eq!(d["reason"], "dispute_overruled");
    assert_eq!(d["dispute_bond_to"], "hunter");
    assert_eq!(paid_to(&hunter1()), bond + DISPUTE_BOND);
    assert_eq!(paid_to(&verifier()), 0);
    assert_eq!(paid_to(&owner()), 0);
    let p = t.program(pid);
    assert_eq!(p.pool.0, pool);
    assert_eq!(p.reserved.0, 0);
    assert_eq!((p.stats.disputes, p.stats.overruled), (1, 1));
    assert_eq!(t.sub(sid).status, Status::Rejected);
    // no strike on the hunter
    assert_eq!(t.view().get_hunter(hunter1()).invalid, 0);
    assert_eq!(t.view().get_hunter_in_program(pid, hunter1()).invalid, 0);
    assert_eq!(t.view().required_bond(pid, hunter1()).0, BOND);
    check_invariants(&mut t);
}

#[test]
#[should_panic(expected = "a disputed report resolves as valid or invalid")]
fn resolve_disputed_as_duplicate_is_refused() {
    let (mut t, _pid, sid) = setup_disputed();
    t.resolve(sid, "duplicate", None);
}

#[test]
#[should_panic(expected = "resolve deadline has passed; use finalize")]
fn resolve_disputed_after_deadline_fails() {
    let (mut t, _pid, sid) = setup_disputed();
    t.advance(RESOLVE);
    t.resolve(sid, "invalid", None);
}

#[test]
#[should_panic(expected = "resolve deadline has passed; use finalize")]
fn resolve_needs_human_after_deadline_fails() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::NeedsHuman));
    t.advance(RESOLVE);
    t.resolve(sid, "invalid", None);
}

#[test]
fn resolve_just_before_deadline_works() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::NeedsHuman));
    t.advance(RESOLVE - 1);
    t.resolve(sid, "invalid", None);
    assert_eq!(t.sub(sid).status, Status::Rejected);
}

#[test]
fn slash_without_verdict_pays_no_fee() {
    // resolve() only accepts needs_human/disputed (both have a verdict); this exercises the
    // internal rule "fee only if the verifier had posted a verdict" directly.
    let (mut t, pid, sid) = setup_one();
    let bond = t.sub(sid).bond.0;
    let pool = t.program(pid).pool.0;
    set_ctx(&owner(), 0, t.now);
    t.c.slash(sid, false, Status::Rejected);
    assert_eq!(paid_to(&verifier()), 0);
    assert_eq!(t.program(pid).pool.0, pool + bond);
}

#[test]
#[should_panic(expected = "severity is required to resolve as valid")]
fn resolve_valid_needs_severity() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::NeedsHuman));
    t.resolve(sid, "valid", None);
}

#[test]
#[should_panic(expected = "outcome must be one of: valid, invalid, duplicate")]
fn resolve_rejects_unknown_outcome() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::NeedsHuman));
    t.resolve(sid, "needs_human", None);
}

#[test]
#[should_panic(expected = "note must be at most 280 bytes")]
fn resolve_note_counts_bytes() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::NeedsHuman));
    t.call(&owner(), 0)
        .resolve(sid, "invalid".into(), None, WIDE.repeat(71));
}

#[test]
#[should_panic(expected = "only needs_human or disputed submissions can be resolved")]
fn resolve_pending_fails() {
    let (mut t, _pid, sid) = setup_one();
    t.resolve(sid, "invalid", None);
}

#[test]
#[should_panic(expected = "only needs_human or disputed submissions can be resolved")]
fn resolve_valid_in_window_fails() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::Valid));
    t.resolve(sid, "invalid", None);
}

#[test]
#[should_panic(expected = "only the program owner can do this")]
fn resolve_only_owner() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::NeedsHuman));
    t.call(&verifier(), 0)
        .resolve(sid, "valid".into(), Some(Severity::Low), "".into());
}

// ------------------------------------------------------- needs_human expiry

#[test]
#[should_panic(expected = "resolve deadline has not passed yet")]
fn needs_human_cannot_expire_before_deadline() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::NeedsHuman));
    t.advance(RESOLVE - 1);
    t.finalize(sid);
}

#[test]
fn needs_human_unresolved_expires_with_full_bond_refund() {
    let (mut t, pid, sid) = setup_one();
    let bond = t.sub(sid).bond.0;
    t.post(sid, verdict(Outcome::NeedsHuman));
    let pool = t.program(pid).pool.0;
    t.advance(RESOLVE);
    t.finalize(sid);
    assert_eq!(paid_to(&hunter1()), bond);
    assert_eq!(paid_to(&verifier()), 0);
    assert_eq!(event_names(), vec!["report_expired", "bond_refunded"]);
    assert_eq!(event_data("bond_refunded")["reason"], "expired");
    let p = t.program(pid);
    assert_eq!(p.pool.0, pool);
    assert_eq!(p.reserved.0, 0);
    assert_eq!(t.sub(sid).status, Status::Expired);
    assert!(!Status::Expired.is_open());
    check_invariants(&mut t);
}

#[test]
#[should_panic(expected = "only needs_human or disputed submissions can be resolved")]
fn expired_is_final() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::NeedsHuman));
    t.advance(RESOLVE);
    t.finalize(sid);
    t.resolve(sid, "valid", Some(Severity::Low));
}

// ------------------------------------------------------------ withdraw_pending

#[test]
fn withdraw_pending_after_timeout_refunds_full_bond() {
    let (mut t, pid, sid) = setup_one();
    let bond = t.sub(sid).bond.0;
    t.advance(TIMEOUT);
    t.call(&hunter1(), 0).withdraw_pending(sid);
    assert_eq!(paid_to(&hunter1()), bond);
    assert_eq!(paid_to(&verifier()), 0);
    assert_eq!(event_names(), vec!["report_withdrawn", "bond_refunded"]);
    assert_eq!(t.sub(sid).status, Status::Withdrawn);
    assert_eq!(t.program(pid).reserved.0, 0);
    assert!(t.view().list_pending(pid, 0, 50).is_empty());
    check_invariants(&mut t);
}

#[test]
#[should_panic(expected = "pending timeout has not passed yet")]
fn withdraw_pending_before_timeout_fails() {
    let (mut t, _pid, sid) = setup_one();
    t.advance(TIMEOUT - 1);
    t.call(&hunter1(), 0).withdraw_pending(sid);
}

#[test]
#[should_panic(expected = "only the hunter can withdraw")]
fn withdraw_pending_only_hunter() {
    let (mut t, _pid, sid) = setup_one();
    t.advance(TIMEOUT);
    t.call(&owner(), 0).withdraw_pending(sid);
}

#[test]
#[should_panic(expected = "submission is not pending")]
fn withdraw_after_verdict_fails() {
    let (mut t, _pid, sid) = setup_one();
    t.post(sid, verdict(Outcome::NeedsHuman));
    t.advance(TIMEOUT);
    t.call(&hunter1(), 0).withdraw_pending(sid);
}

#[test]
#[should_panic(expected = "submission is not pending")]
fn verdict_after_withdraw_fails() {
    let (mut t, _pid, sid) = setup_one();
    t.advance(TIMEOUT);
    t.call(&hunter1(), 0).withdraw_pending(sid);
    t.post(sid, verdict(Outcome::Valid));
}

// --------------------------------------------------------------------- listing

fn ids(v: Vec<SubmissionView>) -> Vec<u64> {
    v.into_iter().map(|s| s.id).collect()
}

#[test]
fn list_pending_is_per_program() {
    let mut t = T::new();
    let p0 = t.create_program(100 * NEAR);
    let p1 = t.create(
        &owner(),
        100 * NEAR,
        P {
            verifier: stranger(),
            ..P::default()
        },
    );
    let a = t.submit(&hunter1(), p0, 1, 2 * NEAR);
    let b = t.submit(&hunter1(), p1, 2, 2 * NEAR);
    let c = t.submit(&hunter2(), p0, 3, 2 * NEAR);
    let d = t.submit(&hunter2(), p0, 4, 2 * NEAR);
    assert_eq!(ids(t.view().list_pending(p0, 0, 50)), vec![a, c, d]);
    assert_eq!(ids(t.view().list_pending(p0, 1, 1)), vec![c]);
    assert_eq!(ids(t.view().list_pending(p1, 0, 50)), vec![b]);
    assert!(t.view().list_pending(9, 0, 50).is_empty());
    assert!(t.view().list_pending(p0, 3, 50).is_empty());
    // removing the first entry moves the last one into its position
    t.post(a, verdict(Outcome::Invalid));
    assert_eq!(ids(t.view().list_pending(p0, 0, 50)), vec![d, c]);
    t.post(c, verdict(Outcome::Invalid));
    assert_eq!(ids(t.view().list_pending(p0, 0, 50)), vec![d]);
    assert_eq!(ids(t.view().list_submissions(p0, 0, 50)), vec![a, c, d]);
    assert_eq!(ids(t.view().list_submissions(p0, 2, 50)), vec![d]);
    assert_eq!(ids(t.view().list_submissions(p1, 0, 50)), vec![b]);
    assert!(t.view().list_submissions(9, 0, 50).is_empty());
    check_invariants(&mut t);
}

#[test]
fn pending_index_stays_consistent_under_mixed_settlement() {
    let mut t = T::new();
    let pid = t.create_program(100 * RESERVATION);
    let mut subs = vec![];
    for n in 0..12 {
        let h = if n % 2 == 0 { hunter1() } else { hunter2() };
        subs.push(t.submit(&h, pid, n, 3 * NEAR));
    }
    check_invariants(&mut t);
    // settle in an order that hits first, middle and last positions
    for (i, &k) in [5usize, 0, 11, 3, 7].iter().enumerate() {
        let v = if i % 2 == 0 {
            verdict(Outcome::Invalid)
        } else {
            verdict(Outcome::NeedsHuman)
        };
        t.post(subs[k], v);
        check_invariants(&mut t);
    }
    t.advance(TIMEOUT);
    t.call(&hunter2(), 0).withdraw_pending(subs[9]);
    check_invariants(&mut t);
    let pending = ids(t.view().list_pending(pid, 0, 50));
    assert_eq!(pending.len(), 6);
    for k in [1usize, 2, 4, 6, 8, 10] {
        assert!(pending.contains(&subs[k]));
    }
}

#[test]
fn list_limit_capped_at_50() {
    let mut t = T::new();
    for _ in 0..55 {
        t.create_program(NEAR);
    }
    assert_eq!(t.view().list_programs(0, 1_000).len(), 50);
    assert_eq!(t.view().list_programs(50, 1_000).len(), 5);
    assert!(t.view().list_programs(60, 10).is_empty());
    let pid = t.create_program(100 * RESERVATION);
    for n in 0..55 {
        t.submit(&hunter1(), pid, n, 2 * NEAR);
    }
    assert_eq!(t.view().list_submissions(pid, 0, 999).len(), 50);
    assert_eq!(t.view().list_pending(pid, 0, 999).len(), 50);
    assert_eq!(t.view().list_pending(pid, 50, 999).len(), 5);
}

#[test]
fn submission_view_json_shape() {
    let (mut t, _pid, sid) = setup_one();
    let json = serde_json::to_value(t.sub(sid)).unwrap();
    assert!(json.get("sealed").is_none());
    for k in [
        "id",
        "program_id",
        "hunter_id",
        "title",
        "commitment",
        "bond",
        "status",
        "submitted_at",
        "submitted_block",
        "verdict",
        "payout",
        "resolution",
        "dispute_reason",
        "valid_until",
        "resolve_until",
        "dispute_bond",
        "funded_by_vault",
        "storage_cost",
    ] {
        assert!(json.get(k).is_some(), "missing {}", k);
    }
    assert_eq!(json["status"], "pending");
    assert!(json["valid_until"].is_null() && json["resolve_until"].is_null());
    assert!(json["bond"].is_string() && json["submitted_at"].is_string());
    assert_eq!(json["dispute_bond"], "0");
    assert_eq!(json["funded_by_vault"], false);
    // every status serializes as in SPEC.md
    for (s, name) in [
        (Status::Pending, "pending"),
        (Status::NeedsHuman, "needs_human"),
        (Status::Expired, "expired"),
        (Status::Withdrawn, "withdrawn"),
    ] {
        assert_eq!(serde_json::to_value(s).unwrap(), name);
        assert_eq!(s.as_str(), name);
    }
}

#[test]
fn program_view_json_shape() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    let json = serde_json::to_value(t.program(pid)).unwrap();
    for k in [
        "id",
        "owner_id",
        "name",
        "scope",
        "verifier_id",
        "verifier_pubkey",
        "payouts",
        "bond",
        "verifier_fee",
        "dispute_bond",
        "challenge_period_sec",
        "pending_timeout_sec",
        "resolve_timeout_sec",
        "pool",
        "reserved",
        "active",
        "stats",
        "created_at",
    ] {
        assert!(json.get(k).is_some(), "missing {}", k);
    }
    assert!(json.get("pending_count").is_none());
    assert_eq!(json["payouts"]["critical"], (10 * NEAR).to_string());
    assert_eq!(json["stats"]["total_paid"], "0");
    assert_eq!(json["stats"]["overruled"], 0);
    assert_eq!(json["challenge_period_sec"], 60);
    assert_eq!(json["dispute_bond"], DISPUTE_BOND.to_string());
}

// ------------------------------------------------------------------- vault

#[test]
fn vault_deposit_creates_vault_and_charges_storage() {
    let mut t = T::new();
    t.call(&hunter1(), 3 * NEAR).vault_deposit();
    assert_eq!(event_names(), vec!["vault_deposited"]);
    let storage = event_amount("vault_deposited", "storage_cost");
    assert!(storage > VAULT_POLICY_STORAGE_BYTES as u128 * BYTE);
    assert!(storage < NEAR / 100);
    let v = t.vault(&hunter1());
    assert_eq!(v.account_id, hunter1());
    assert_eq!(v.balance.0, 3 * NEAR - storage);
    assert!(!v.policy_set);
    assert!(v.allowed_programs.is_none());
    assert_eq!((v.spent_in_window.0, v.window_start.0), (0, 0));
    // a second deposit only adds, no storage
    t.call(&hunter1(), NEAR).vault_deposit();
    assert_eq!(event_amount("vault_deposited", "storage_cost"), 0);
    assert_eq!(t.vault(&hunter1()).balance.0, 4 * NEAR - storage);
    assert!(t.view().get_vault(hunter2()).is_none());
}

#[test]
#[should_panic(expected = "attach a deposit to fund the vault")]
fn vault_deposit_needs_deposit() {
    let mut t = T::new();
    t.call(&hunter1(), 0).vault_deposit();
}

#[test]
#[should_panic(expected = "does not cover the vault storage")]
fn vault_deposit_must_cover_storage() {
    let mut t = T::new();
    t.call(&hunter1(), 100 * BYTE).vault_deposit();
}

#[test]
fn vault_storage_prepay_covers_a_full_policy() {
    let mut t = T::new();
    t.switch(&hunter1(), NEAR);
    let base = t.flush_usage();
    t.c.vault_deposit();
    let prepaid = (event_amount("vault_deposited", "storage_cost") / BYTE) as u64;
    t.set_policy(&hunter1(), NEAR, NEAR, Some((0..32).collect()));
    let used = t.flush_usage() - base;
    assert!(used <= prepaid, "used {} > prepaid {}", used, prepaid);
    assert_eq!(used, prepaid, "the prepay is exact for a 32-id list");
}

#[test]
fn vault_set_policy_with_one_yocto() {
    let mut t = T::new();
    t.vault_deposit(&hunter1(), NEAR);
    let before = t.vault(&hunter1()).balance.0;
    t.call(&hunter1(), 1)
        .vault_set_policy(U128(BOND), U128(3 * NEAR), Some(vec![0, 4]));
    assert_eq!(event_names(), vec!["vault_policy_set"]);
    let d = event_data("vault_policy_set");
    assert_eq!(d["allowed_programs"], serde_json::json!([0, 4]));
    let v = t.vault(&hunter1());
    assert!(v.policy_set);
    assert_eq!(v.max_bond_per_report.0, BOND);
    assert_eq!(v.max_spend_per_day.0, 3 * NEAR);
    assert_eq!(v.allowed_programs, Some(vec![0, 4]));
    // the yoctoNEAR is credited to the vault
    assert_eq!(v.balance.0, before + 1);
    // None = any program
    t.set_policy(&hunter1(), BOND, 3 * NEAR, None);
    assert!(t.vault(&hunter1()).allowed_programs.is_none());
}

#[test]
#[should_panic(expected = "requires an attached deposit of exactly 1 yoctoNEAR")]
fn vault_set_policy_refuses_zero_deposit() {
    // what a function-call key would send
    let mut t = T::new();
    t.vault_deposit(&hunter1(), NEAR);
    t.call(&hunter1(), 0)
        .vault_set_policy(U128(BOND), U128(NEAR), None);
}

#[test]
#[should_panic(expected = "requires an attached deposit of exactly 1 yoctoNEAR")]
fn vault_set_policy_refuses_two_yocto() {
    let mut t = T::new();
    t.vault_deposit(&hunter1(), NEAR);
    t.call(&hunter1(), 2)
        .vault_set_policy(U128(BOND), U128(NEAR), None);
}

#[test]
#[should_panic(expected = "no vault for this account")]
fn vault_set_policy_needs_a_vault() {
    let mut t = T::new();
    t.set_policy(&hunter1(), BOND, NEAR, None);
}

#[test]
#[should_panic(expected = "allowed_programs must have at most 32 ids")]
fn vault_set_policy_limits_allowed_programs() {
    let mut t = T::new();
    t.vault_deposit(&hunter1(), NEAR);
    t.set_policy(&hunter1(), BOND, NEAR, Some((0..33).collect()));
}

#[test]
fn vault_withdraw_with_one_yocto() {
    let mut t = T::new();
    t.vault_deposit(&hunter1(), 3 * NEAR);
    let bal = t.vault(&hunter1()).balance.0;
    t.call(&hunter1(), 1).vault_withdraw(U128(NEAR));
    assert_eq!(paid_to(&hunter1()), NEAR);
    assert_eq!(event_names(), vec!["vault_withdrawn"]);
    assert_eq!(t.vault(&hunter1()).balance.0, bal + 1 - NEAR);
    // everything, including the credited yoctoNEARs
    let rest = t.vault(&hunter1()).balance.0 + 1;
    t.call(&hunter1(), 1).vault_withdraw(U128(rest));
    assert_eq!(paid_to(&hunter1()), rest);
    assert_eq!(t.vault(&hunter1()).balance.0, 0);
}

#[test]
#[should_panic(expected = "requires an attached deposit of exactly 1 yoctoNEAR")]
fn vault_withdraw_refuses_zero_deposit() {
    let mut t = T::new();
    t.vault_deposit(&hunter1(), 3 * NEAR);
    t.call(&hunter1(), 0).vault_withdraw(U128(NEAR));
}

#[test]
#[should_panic(expected = "requires an attached deposit of exactly 1 yoctoNEAR")]
fn vault_withdraw_refuses_larger_deposit() {
    let mut t = T::new();
    t.vault_deposit(&hunter1(), 3 * NEAR);
    t.call(&hunter1(), NEAR).vault_withdraw(U128(NEAR));
}

#[test]
#[should_panic(expected = "amount exceeds the vault balance")]
fn vault_withdraw_over_balance_fails() {
    let mut t = T::new();
    t.vault_deposit(&hunter1(), 3 * NEAR);
    let bal = t.vault(&hunter1()).balance.0;
    t.call(&hunter1(), 1).vault_withdraw(U128(bal + 2));
}

#[test]
#[should_panic(expected = "amount must be greater than zero")]
fn vault_withdraw_zero_fails() {
    let mut t = T::new();
    t.vault_deposit(&hunter1(), 3 * NEAR);
    t.call(&hunter1(), 1).vault_withdraw(U128(0));
}

#[test]
#[should_panic(expected = "no vault for this account")]
fn vault_withdraw_needs_a_vault() {
    let mut t = T::new();
    t.call(&hunter1(), 1).vault_withdraw(U128(1));
}

#[test]
fn vault_withdraw_only_touches_own_vault() {
    let mut t = T::new();
    t.vault_deposit(&hunter1(), 3 * NEAR);
    t.vault_deposit(&hunter2(), 3 * NEAR);
    let b1 = t.vault(&hunter1()).balance.0;
    t.call(&hunter2(), 1).vault_withdraw(U128(NEAR));
    assert_eq!(paid_to(&hunter2()), NEAR);
    assert_eq!(paid_to(&hunter1()), 0);
    assert_eq!(t.vault(&hunter1()).balance.0, b1);
}

#[test]
fn submit_from_vault_draws_exactly_bond_plus_storage() {
    let (mut t, pid) = setup_vault();
    let before = t.vault(&hunter1()).balance.0;
    let sid = t.submit_vault(&hunter1(), pid, 1);
    let ev = events();
    assert_eq!(ev[0]["event"], "report_submitted");
    assert_eq!(ev[0]["data"][0]["funded_by_vault"], true);
    assert!(transfers().is_empty());
    let s = t.sub(sid);
    assert!(s.funded_by_vault);
    assert_eq!(s.bond.0, BOND);
    assert_eq!(s.status, Status::Pending);
    let draw = BOND + s.storage_cost.0;
    let v = t.vault(&hunter1());
    assert_eq!(v.balance.0, before - draw);
    assert_eq!(v.spent_in_window.0, draw);
    assert_eq!(v.window_start.0, t.now * NANOS_PER_SEC);
    assert_eq!(t.program(pid).reserved.0, RESERVATION);
    assert_eq!(ids(t.view().list_pending(pid, 0, 50)), vec![sid]);
    check_invariants(&mut t);
}

#[test]
fn submit_from_vault_uses_the_per_program_required_bond() {
    let (mut t, pid) = setup_vault();
    set_hunter(&mut t, pid, 1, 0);
    let sid = t.submit_vault(&hunter1(), pid, 1);
    assert_eq!(t.sub(sid).bond.0, BOND / 2);
}

#[test]
#[should_panic(expected = "no vault for this account")]
fn submit_from_vault_needs_a_vault() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    t.submit_vault(&hunter1(), pid, 1);
}

#[test]
#[should_panic(expected = "vault policy is not set")]
fn submit_from_vault_needs_a_policy() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    t.vault_deposit(&hunter1(), 10 * NEAR);
    t.submit_vault(&hunter1(), pid, 1);
}

#[test]
#[should_panic(expected = "program is not in the vault's allowed_programs")]
fn submit_from_vault_respects_allowed_programs() {
    let (mut t, pid) = setup_vault();
    let other = t.create_program(100 * NEAR);
    t.set_policy(&hunter1(), BOND, 5 * NEAR, Some(vec![other]));
    t.submit_vault(&hunter1(), pid, 1);
}

#[test]
fn submit_from_vault_allowed_program_passes() {
    let (mut t, pid) = setup_vault();
    let other = t.create_program(100 * NEAR);
    t.set_policy(&hunter1(), BOND, 5 * NEAR, Some(vec![7, other]));
    let sid = t.submit_vault(&hunter1(), other, 1);
    assert_eq!(t.sub(sid).program_id, other);
    // an empty list allows nothing
    t.set_policy(&hunter1(), BOND, 5 * NEAR, Some(vec![]));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        t.submit_vault(&hunter1(), pid, 2);
    }));
    assert!(r.is_err());
}

#[test]
#[should_panic(expected = "exceeds the vault's max_bond_per_report")]
fn submit_from_vault_respects_max_bond() {
    let (mut t, pid) = setup_vault();
    t.set_policy(&hunter1(), BOND - 1, 5 * NEAR, None);
    t.submit_vault(&hunter1(), pid, 1);
}

#[test]
#[should_panic(expected = "exceeds the vault's max_bond_per_report")]
fn submit_from_vault_refuses_doubled_bond_after_strike() {
    // a slashed hunter's bond doubles; the policy caps what the agent may risk
    let (mut t, pid) = setup_vault();
    let sid = t.submit_vault(&hunter1(), pid, 1);
    t.post(sid, verdict(Outcome::Invalid));
    t.submit_vault(&hunter1(), pid, 2);
}

#[test]
#[should_panic(expected = "vault max_spend_per_day exceeded")]
fn submit_from_vault_respects_daily_limit() {
    let (mut t, pid) = setup_vault();
    // one report draws bond + ~0.02 NEAR storage; 2 NEAR per day allows only one
    t.set_policy(&hunter1(), BOND, 2 * NEAR, None);
    t.submit_vault(&hunter1(), pid, 1);
    t.submit_vault(&hunter1(), pid, 2);
}

#[test]
#[should_panic(expected = "vault max_spend_per_day exceeded")]
fn vault_window_still_runs_one_second_before_24_hours() {
    let (mut t, pid) = setup_vault();
    t.set_policy(&hunter1(), BOND, 2 * NEAR, None);
    t.submit_vault(&hunter1(), pid, 1);
    t.advance(DAY - 1);
    t.submit_vault(&hunter1(), pid, 2);
}

#[test]
fn vault_window_resets_after_24_hours() {
    let (mut t, pid) = setup_vault();
    t.set_policy(&hunter1(), BOND, 2 * NEAR, None);
    t.submit_vault(&hunter1(), pid, 1);
    let start = t.vault(&hunter1()).window_start.0;
    // at window_start + 24 h the window restarts and the second report fits again
    t.advance(DAY);
    let b = t.submit_vault(&hunter1(), pid, 2);
    let v = t.vault(&hunter1());
    assert_eq!(v.window_start.0, start + DAY * NANOS_PER_SEC);
    assert_eq!(v.spent_in_window.0, BOND + t.sub(b).storage_cost.0);
}

#[test]
fn policy_change_does_not_reset_the_window() {
    let (mut t, pid) = setup_vault();
    let a = t.submit_vault(&hunter1(), pid, 1);
    let spent = t.vault(&hunter1()).spent_in_window.0;
    t.set_policy(&hunter1(), BOND, 10 * NEAR, None);
    let v = t.vault(&hunter1());
    assert_eq!(v.spent_in_window.0, spent);
    assert_eq!(spent, BOND + t.sub(a).storage_cost.0);
}

#[test]
#[should_panic(expected = "is too low")]
fn submit_from_vault_needs_enough_balance() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    t.vault_deposit(&hunter1(), NEAR); // < bond + storage after the vault's own storage
    t.set_policy(&hunter1(), BOND, 5 * NEAR, None);
    t.submit_vault(&hunter1(), pid, 1);
}

#[test]
#[should_panic(expected = "commitment already used")]
fn submit_from_vault_commitment_single_use() {
    let (mut t, pid) = setup_vault();
    t.submit_vault(&hunter1(), pid, 1);
    t.submit_vault(&hunter1(), pid, 1);
}

// ------------------------------------------------- vault refund routing

#[test]
fn vault_funded_paid_bond_to_vault_payout_to_account() {
    let (mut t, pid) = setup_vault();
    let sid = t.submit_vault(&hunter1(), pid, 1);
    let bal = t.vault(&hunter1()).balance.0;
    t.post(sid, verdict(Outcome::Valid));
    t.advance(CHALLENGE);
    t.finalize(sid);
    assert_eq!(paid_to(&hunter1()), 5 * NEAR);
    assert_eq!(event_data("bond_refunded")["to"], "vault");
    assert_eq!(t.vault(&hunter1()).balance.0, bal + BOND);
    check_invariants(&mut t);
}

#[test]
fn vault_funded_duplicate_refund_to_vault() {
    let (mut t, pid) = setup_vault();
    let first = t.submit(&hunter2(), pid, 1, 2 * NEAR);
    t.post(first, verdict(Outcome::Valid));
    let sid = t.submit_vault(&hunter1(), pid, 2);
    let bal = t.vault(&hunter1()).balance.0;
    t.post(sid, dup_of(first));
    assert_eq!(paid_to(&hunter1()), 0);
    assert_eq!(paid_to(&verifier()), FEE);
    assert_eq!(t.vault(&hunter1()).balance.0, bal + BOND - FEE);
}

#[test]
fn vault_funded_withdrawn_refund_to_vault() {
    let (mut t, pid) = setup_vault();
    let sid = t.submit_vault(&hunter1(), pid, 1);
    let bal = t.vault(&hunter1()).balance.0;
    t.advance(TIMEOUT);
    t.call(&hunter1(), 0).withdraw_pending(sid);
    assert_eq!(paid_to(&hunter1()), 0);
    assert_eq!(event_data("bond_refunded")["to"], "vault");
    assert_eq!(t.vault(&hunter1()).balance.0, bal + BOND);
}

#[test]
fn vault_funded_expired_refund_to_vault() {
    let (mut t, pid) = setup_vault();
    let sid = t.submit_vault(&hunter1(), pid, 1);
    t.post(sid, verdict(Outcome::NeedsHuman));
    let bal = t.vault(&hunter1()).balance.0;
    t.advance(RESOLVE);
    t.finalize(sid);
    assert_eq!(paid_to(&hunter1()), 0);
    assert_eq!(t.vault(&hunter1()).balance.0, bal + BOND);
    assert_eq!(t.sub(sid).status, Status::Expired);
}

#[test]
fn vault_funded_overruled_dispute_bond_to_vault_dispute_bond_to_account() {
    let (mut t, pid) = setup_vault();
    let sid = t.submit_vault(&hunter1(), pid, 1);
    t.post(sid, verdict(Outcome::Valid));
    t.dispute(sid, DISPUTE_BOND);
    let bal = t.vault(&hunter1()).balance.0;
    t.resolve(sid, "invalid", None);
    assert_eq!(paid_to(&hunter1()), DISPUTE_BOND);
    assert_eq!(event_data("bond_refunded")["to"], "vault");
    assert_eq!(t.vault(&hunter1()).balance.0, bal + BOND);
}

#[test]
fn vault_funded_dispute_timeout_payout_and_dispute_bond_to_account() {
    let (mut t, pid) = setup_vault();
    let sid = t.submit_vault(&hunter1(), pid, 1);
    t.post(sid, verdict(Outcome::Valid));
    t.dispute(sid, DISPUTE_BOND);
    let bal = t.vault(&hunter1()).balance.0;
    t.advance(RESOLVE);
    t.finalize(sid);
    assert_eq!(paid_to(&hunter1()), 5 * NEAR + DISPUTE_BOND);
    assert_eq!(t.vault(&hunter1()).balance.0, bal + BOND);
}

#[test]
fn vault_funded_invalid_slashes_nothing_back() {
    let (mut t, pid) = setup_vault();
    let sid = t.submit_vault(&hunter1(), pid, 1);
    let bal = t.vault(&hunter1()).balance.0;
    let pool = t.program(pid).pool.0;
    t.post(sid, verdict(Outcome::Invalid));
    assert_eq!(paid_to(&hunter1()), 0);
    assert_eq!(t.vault(&hunter1()).balance.0, bal);
    assert_eq!(t.program(pid).pool.0, pool + BOND - FEE);
}

#[test]
fn vault_view_json_shape() {
    let (mut t, _pid) = setup_vault();
    let json = serde_json::to_value(t.vault(&hunter1())).unwrap();
    for k in [
        "account_id",
        "balance",
        "max_bond_per_report",
        "max_spend_per_day",
        "allowed_programs",
        "spent_in_window",
        "window_start",
        "policy_set",
    ] {
        assert!(json.get(k).is_some(), "missing {}", k);
    }
    assert!(json["balance"].is_string() && json["window_start"].is_string());
    assert!(json["allowed_programs"].is_null());
    assert_eq!(json["policy_set"], true);
}

// ----------------------------------------------- regression tests (review of v1)

/// S1: v1 accepted any earlier submission of the program as the original of a duplicate, so
/// a verifier could refund (instead of slash) a report "duplicating" an invalid one.
#[test]
#[should_panic(expected = "duplicate_of must be a valid, paid or disputed submission")]
fn s1_duplicate_of_invalid_original_is_refused() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    let junk = t.submit(&hunter1(), pid, 1, 2 * NEAR);
    let copy = t.submit(&hunter2(), pid, 2, 2 * NEAR);
    t.post(junk, verdict(Outcome::Invalid));
    t.post(copy, dup_of(junk));
}

#[test]
fn s1_only_valid_paid_or_disputed_originals() {
    // every non-qualifying status is refused; checked on fresh clones of the same state
    let mut t = T::new();
    let pid = t.create_program(100 * RESERVATION);
    let valid = t.submit(&hunter2(), pid, 8, 2 * NEAR);
    let pending = t.submit(&hunter1(), pid, 1, 2 * NEAR);
    let invalid = t.submit(&hunter1(), pid, 2, 2 * NEAR);
    let needs_human = t.submit(&hunter1(), pid, 3, 2 * NEAR);
    let rejected = t.submit(&hunter1(), pid, 4, 3 * NEAR);
    let expired = t.submit(&hunter1(), pid, 5, 3 * NEAR);
    let withdrawn = t.submit(&hunter1(), pid, 6, 3 * NEAR);
    let duplicate = t.submit(&hunter1(), pid, 7, 3 * NEAR);
    t.post(valid, verdict(Outcome::Valid));
    t.post(invalid, verdict(Outcome::Invalid));
    t.post(needs_human, verdict(Outcome::NeedsHuman));
    t.post(rejected, verdict(Outcome::NeedsHuman));
    t.resolve(rejected, "invalid", None);
    t.post(expired, verdict(Outcome::NeedsHuman));
    t.post(duplicate, dup_of(valid));
    t.advance(TIMEOUT);
    t.call(&hunter1(), 0).withdraw_pending(withdrawn);
    t.finalize(expired);
    let probe = t.submit(&hunter2(), pid, 9, 2 * NEAR);
    t.switch(&verifier(), 0);
    // clones read the shared mocked storage, so flush the caches first
    t.c.flush_all();
    let snapshot = borsh::to_vec(&t.c).unwrap();
    for orig in [
        pending,
        invalid,
        needs_human,
        rejected,
        expired,
        withdrawn,
        duplicate,
    ] {
        let mut c: Contract = borsh::from_slice(&snapshot).unwrap();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            c.post_verdict(probe, dup_of(orig));
        }));
        assert!(r.is_err(), "original {} must be refused", orig);
    }
    let mut c: Contract = borsh::from_slice(&snapshot).unwrap();
    c.post_verdict(probe, dup_of(valid));
    assert_eq!(c.submission(probe).status, Status::Duplicate);
}

/// S2: a failed submission's arguments are public. The contract only enforces that a
/// commitment is used once; the binding to the submitter is checked off-chain by the worker
/// (commitment v2 = sha256("replaycourt/commit/v2" 0x00 hunter 0x00 report)). This test
/// documents both halves.
#[test]
fn s2_replayed_commitment_is_recorded_under_the_copier_and_cannot_match() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    let report = b"# Reentrancy in Vault.withdraw\n...PoC...";
    let commit_v2 = |hunter: &AccountId| -> String {
        let mut pre = b"replaycourt/commit/v2".to_vec();
        pre.push(0);
        pre.extend_from_slice(hunter.as_bytes());
        pre.push(0);
        pre.extend_from_slice(report);
        hex(&env::sha256(&pre))
    };
    let original = commit_v2(&hunter1());
    let sealed = "c2VhbGVk".repeat(16);
    // hunter1's first try fails on chain (deposit too small): nothing is stored
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        t.call(&hunter1(), NEAR / 2).submit_report(
            pid,
            "my finding".into(),
            original.clone(),
            sealed.clone(),
        );
    }));
    assert!(r.is_err());
    assert!(!t.c.commitments.contains_key(&original));
    // hunter2 replays the public arguments: the contract accepts (uniqueness only) ...
    let sid =
        t.call(&hunter2(), 2 * NEAR)
            .submit_report(pid, "copied".into(), original.clone(), sealed);
    let s = t.sub(sid);
    // ... but records the copier, so the worker's recomputation cannot match
    assert_eq!(s.hunter_id, hunter2());
    assert_ne!(commit_v2(&s.hunter_id), s.commitment);
    assert_eq!(commit_v2(&hunter1()), s.commitment);
    // and the commitment is now burnt for everyone
    let again = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        t.call(&hunter1(), 2 * NEAR).submit_report(
            pid,
            "mine".into(),
            original.clone(),
            "eA==".into(),
        );
    }));
    assert!(again.is_err());
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// S3: in v1 a disputed report had no exit: ten years later neither the hunter nor anyone else
/// could settle it. In v2 `finalize` pays after `resolve_until`.
#[test]
fn s3_disputed_report_has_an_exit() {
    let (mut t, _pid, sid) = setup_disputed();
    let bond = t.sub(sid).bond.0;
    t.advance(10 * 365 * DAY); // the owner never resolves
    t.call(&hunter1(), 0).finalize(sid);
    assert_eq!(paid_to(&hunter1()), 5 * NEAR + bond + DISPUTE_BOND);
    assert_eq!(t.sub(sid).status, Status::Paid);
}

/// S3: v1 also had no exit for `needs_human`; v2 expires it with a full refund.
#[test]
fn s3_needs_human_has_an_exit() {
    let (mut t, _pid, sid) = setup_one();
    let bond = t.sub(sid).bond.0;
    t.post(sid, verdict(Outcome::NeedsHuman));
    t.advance(10 * 365 * DAY);
    t.call(&hunter1(), 0).finalize(sid);
    assert_eq!(paid_to(&hunter1()), bond);
    assert_eq!(t.sub(sid).status, Status::Expired);
}

/// S4: v1 limits counted characters; 4-byte text overran LATER_WRITES_STORAGE_BYTES and the
/// contract paid the difference. In v2 every limit counts bytes.
#[test]
fn s4_multibyte_text_cannot_drain_storage() {
    let (prepaid, peak) = later_writes_scenario(WIDE, false);
    assert!(peak <= prepaid, "peak {} > prepaid {}", peak, prepaid);
}

/// S4: the v1 attack payload (280 four-byte characters in a 280 limit) is refused outright.
#[test]
#[should_panic(expected = "reason must be at most 280 bytes")]
fn s4_v1_multibyte_payload_is_refused() {
    let (mut t, _pid, sid) = setup_one();
    let mut v = verdict(Outcome::Valid);
    v.reason = WIDE.repeat(MAX_REASON_BYTES);
    t.post(sid, v);
}

/// S5: v1's `list_pending(verifier_id)` scanned the global pending set, so anyone could make
/// it unusable with cheap pending entries in their own program. In v2 the cost of listing a
/// program does not depend on other programs' pending entries.
#[test]
fn s5_list_pending_cost_is_independent_of_foreign_programs() {
    let mut t = T::new();
    let victim = t.create_program(100 * NEAR);
    let victim_sub = t.submit(&hunter1(), victim, 1, 2 * NEAR);
    let attacker = stranger();
    let own = t.create(
        &attacker,
        NEAR,
        P {
            verifier: attacker.clone(),
            payouts: Payouts {
                critical: U128(1),
                high: U128(0),
                medium: U128(0),
                low: U128(0),
            },
            bond: 0,
            fee: 0,
            dispute_bond: 0,
            pending: MAX_PENDING_TIMEOUT_SEC,
            ..P::default()
        },
    );
    let measure = |t: &mut T| -> (u64, Vec<u64>) {
        t.c.flush_all();
        let fresh: Contract = borsh::from_slice(&borsh::to_vec(&t.c).unwrap()).unwrap();
        set_ctx(&stranger(), 0, t.now);
        let g0 = env::used_gas().as_gas();
        let page = ids(fresh.list_pending(victim, 0, 50));
        (env::used_gas().as_gas() - g0, page)
    };
    let (g_before, page_before) = measure(&mut t);
    for n in 0..200u64 {
        t.submit(&attacker, own, 50_000 + n, NEAR / 20);
    }
    let (g_after, page_after) = measure(&mut t);
    assert_eq!(page_before, vec![victim_sub]);
    assert_eq!(page_after, vec![victim_sub]);
    assert_eq!(g_before, g_after, "listing cost must not grow");
    assert_eq!(t.view().list_pending(own, 0, 50).len(), 50);
}

/// S6: v1 used global stats for the bond, so reputation farmed in a self-run program
/// (owner = verifier = hunter, 1-yocto payouts) cut the bond everywhere. In v2 the bond uses
/// the hunter's stats in the program at hand only.
#[test]
fn s6_self_farmed_reputation_buys_nothing_elsewhere() {
    let mut t = T::new();
    let victim = t.create_program(100 * NEAR);
    let attacker = stranger();
    let own = t.create(
        &attacker,
        NEAR,
        P {
            verifier: attacker.clone(),
            payouts: Payouts {
                critical: U128(1),
                high: U128(0),
                medium: U128(0),
                low: U128(0),
            },
            bond: 0,
            fee: 0,
            dispute_bond: 0,
            ..P::default()
        },
    );
    for n in 0..3u64 {
        let sid = t.submit(&attacker, own, 9_000 + n, NEAR / 10);
        t.call(&attacker, 0).post_verdict(
            sid,
            VerdictInput {
                severity: Some(Severity::Critical),
                ..verdict(Outcome::Valid)
            },
        );
        t.advance(CHALLENGE);
        t.call(&attacker, 0).finalize(sid);
    }
    assert_eq!(t.view().get_hunter(attacker.clone()).valid, 3);
    assert_eq!(
        t.view().get_hunter_in_program(own, attacker.clone()).valid,
        3
    );
    assert_eq!(
        t.view()
            .get_hunter_in_program(victim, attacker.clone())
            .valid,
        0
    );
    assert_eq!(t.view().required_bond(own, attacker.clone()).0, 0);
    assert_eq!(t.view().required_bond(victim, attacker.clone()).0, BOND);
}

/// S8: v1 accepted zero windows: a zero pending timeout let a hunter pull the bond back in
/// the same block, before any verdict; a zero challenge window made disputes impossible.
#[test]
#[should_panic(expected = "pending_timeout_sec must be between 60 s and 365 days")]
fn s8_zero_pending_timeout_is_refused() {
    let mut t = T::new();
    t.create(
        &owner(),
        100 * NEAR,
        P {
            pending: 0,
            ..P::default()
        },
    );
}

#[test]
#[should_panic(expected = "challenge_period_sec must be between 60 s and 30 days")]
fn s8_zero_challenge_period_is_refused() {
    let mut t = T::new();
    t.create(
        &owner(),
        100 * NEAR,
        P {
            challenge: 0,
            ..P::default()
        },
    );
}

#[test]
#[should_panic(expected = "resolve_timeout_sec must be between 60 s and 30 days")]
fn s8_zero_resolve_timeout_is_refused() {
    let mut t = T::new();
    t.create(
        &owner(),
        100 * NEAR,
        P {
            resolve: 0,
            ..P::default()
        },
    );
}

#[test]
#[should_panic(expected = "challenge_period_sec must be between 60 s and 30 days")]
fn s8_59_second_window_is_refused() {
    let mut t = T::new();
    t.create(
        &owner(),
        100 * NEAR,
        P {
            challenge: 59,
            ..P::default()
        },
    );
}

#[test]
#[should_panic(expected = "pending timeout has not passed yet")]
fn s8_no_same_block_withdrawal() {
    let mut t = T::new();
    let pid = t.create(
        &owner(),
        100 * NEAR,
        P {
            pending: MIN_WINDOW_SEC,
            ..P::default()
        },
    );
    let sid = t.submit(&hunter1(), pid, 1, 2 * NEAR);
    t.call(&hunter1(), 0).withdraw_pending(sid);
}

#[test]
#[should_panic(expected = "challenge window has not ended yet")]
fn s8_no_same_block_finalize() {
    // a program at the minimum window (v1's minimum was 0, which paid in the verdict's block)
    let mut t = T::new();
    let pid = t.create(
        &owner(),
        100 * NEAR,
        P {
            challenge: MIN_WINDOW_SEC,
            ..P::default()
        },
    );
    let sid = t.submit(&hunter1(), pid, 1, 2 * NEAR);
    t.post(sid, verdict(Outcome::Valid));
    t.finalize(sid);
}

// ----------------------------------------------------------- full money audit

/// Every yoctoNEAR that enters (pool deposits, top ups, bonds, vault deposits, dispute
/// deposits, 1-yocto attachments) is either still held (pool, open bond, held dispute bond,
/// vault balance), kept for storage, or was transferred out. Covers every settlement path.
#[test]
fn money_is_conserved_across_all_paths() {
    let mut t = T::new();
    let pid = t.create_program(100 * NEAR);
    let vaults = [hunter1(), hunter2()];
    t.call(&stranger(), 5 * NEAR).top_up(pid);
    t.vault_deposit(&hunter2(), 20 * NEAR);
    t.set_policy(&hunter2(), 2 * BOND, 20 * NEAR, Some(vec![pid]));
    let mut subs = vec![];
    for n in 0..10 {
        let sid = if n % 3 == 2 {
            t.submit_vault(&hunter2(), pid, n)
        } else {
            let h = if n % 2 == 0 { hunter1() } else { stranger() };
            t.submit(&h, pid, n, 3 * NEAR)
        };
        subs.push(sid);
        assert_conserved(&mut t, &vaults);
    }
    // 0: valid -> finalize
    t.post(subs[0], verdict(Outcome::Valid));
    // 1: invalid
    t.post(subs[1], verdict(Outcome::Invalid));
    // 2 (vault): duplicate of 0
    t.post(subs[2], dup_of(subs[0]));
    // 3: needs_human -> resolve invalid
    t.post(subs[3], verdict(Outcome::NeedsHuman));
    t.resolve(subs[3], "invalid", None);
    assert_conserved(&mut t, &vaults);
    // 4: valid -> dispute (with excess) -> resolve invalid (overruled)
    t.post(subs[4], verdict(Outcome::Valid));
    t.dispute(subs[4], DISPUTE_BOND + 3 * MILLI);
    assert_conserved(&mut t, &vaults);
    t.resolve(subs[4], "invalid", None);
    // 5 (vault): valid -> dispute -> resolve valid with a lower severity (partial overrule)
    t.post(subs[5], verdict(Outcome::Valid));
    t.dispute(subs[5], DISPUTE_BOND);
    t.resolve(subs[5], "valid", Some(Severity::Low));
    // 6: valid -> dispute -> finalize after the deadline
    t.post(subs[6], verdict(Outcome::Valid));
    t.dispute(subs[6], DISPUTE_BOND);
    // 7: needs_human -> expires
    t.post(subs[7], verdict(Outcome::NeedsHuman));
    // 8 (vault): needs_human -> resolve valid
    t.post(subs[8], verdict(Outcome::NeedsHuman));
    t.resolve(subs[8], "valid", Some(Severity::Medium));
    assert_conserved(&mut t, &vaults);
    check_invariants(&mut t);
    // 9: left pending, withdrawn after the timeout
    t.advance(TIMEOUT);
    t.call(&stranger(), 0).withdraw_pending(subs[9]);
    t.finalize(subs[0]);
    t.finalize(subs[6]);
    t.finalize(subs[7]);
    assert_conserved(&mut t, &vaults);
    check_invariants(&mut t);
    let statuses: Vec<Status> = subs.iter().map(|&s| t.sub(s).status).collect();
    assert_eq!(
        statuses,
        vec![
            Status::Paid,
            Status::Invalid,
            Status::Duplicate,
            Status::Rejected,
            Status::Rejected,
            Status::Paid,
            Status::Paid,
            Status::Expired,
            Status::Paid,
            Status::Withdrawn,
        ]
    );
    // drain the pool and the vault: everything left the contract except storage
    let p = t.program(pid);
    assert_eq!(p.reserved.0, 0);
    assert_eq!((p.stats.disputes, p.stats.overruled), (3, 2));
    t.call(&owner(), 0).withdraw_pool(pid, p.pool);
    let rest = t.vault(&hunter2()).balance.0 + 1;
    t.call(&hunter2(), 1).vault_withdraw(U128(rest));
    assert_conserved(&mut t, &vaults);
    assert_eq!(t.program(pid).pool.0, 0);
    assert_eq!(t.vault(&hunter2()).balance.0, 0);
    assert_eq!(t.inflow, t.outflow + t.kept);
}

#[test]
fn events_use_version_2_and_cover_the_new_names() {
    let (mut t, pid) = setup_vault();
    let mut seen = std::collections::BTreeSet::new();
    let grab = |seen: &mut std::collections::BTreeSet<String>| {
        for e in events() {
            assert_eq!(e["standard"], "replaycourt");
            assert_eq!(e["version"], "2.0.0");
            assert_eq!(e["data"].as_array().unwrap().len(), 1);
            seen.insert(e["event"].as_str().unwrap().to_string());
        }
    };
    let a = t.submit_vault(&hunter1(), pid, 1);
    grab(&mut seen);
    t.post(a, verdict(Outcome::NeedsHuman));
    grab(&mut seen);
    t.advance(RESOLVE);
    t.finalize(a);
    grab(&mut seen);
    t.call(&hunter1(), 1).vault_withdraw(U128(NEAR));
    grab(&mut seen);
    t.call(&hunter1(), NEAR).vault_deposit();
    grab(&mut seen);
    t.set_policy(&hunter1(), BOND, NEAR, None);
    grab(&mut seen);
    for name in [
        "report_submitted",
        "verdict_posted",
        "report_expired",
        "bond_refunded",
        "vault_withdrawn",
        "vault_deposited",
        "vault_policy_set",
    ] {
        assert!(seen.contains(name), "missing event {}", name);
    }
}
