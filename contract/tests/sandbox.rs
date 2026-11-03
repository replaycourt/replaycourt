//! Sandbox integration test of contract v2 (near-workspaces + a local NEAR sandbox node).
//!
//! Build the wasm first:   ./build.sh
//! Then run:               cargo test --test sandbox -- --nocapture
//!
//! near-workspaces downloads the sandbox node for Linux x86_64/aarch64 and macOS arm64. On
//! macOS x86_64 point NEAR_SANDBOX_BIN_PATH at a near-sandbox binary (see README.md).

use near_sdk::serde_json::{Value, json};
use near_workspaces::types::{AccessKey, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, Contract, Worker, network::Sandbox};

type R<T> = Result<T, Box<dyn std::error::Error>>;

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const MILLI: u128 = NEAR / 1000;
const FEE: u128 = 10 * MILLI;
const BOND: u128 = 100 * MILLI;
const DISPUTE_BOND: u128 = 150 * MILLI;
const WINDOW: u64 = 60;

fn wasm_path() -> std::path::PathBuf {
    match std::env::var_os("REPLAYCOURT_WASM") {
        Some(p) => p.into(),
        None => {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/near/replaycourt.wasm")
        }
    }
}

fn verdict(outcome: &str, severity: Option<&str>, duplicate_of: Option<u64>) -> Value {
    json!({
        "outcome": outcome,
        "severity": severity,
        "duplicate_of": duplicate_of,
        "fingerprint": "sandbox",
        "evidence_sha256": "ab".repeat(32),
        "evidence_uri": "runs/sandbox/verdict.json",
        "chain_id": 0,
        "fork_block": "0",
        "reason": format!("sandbox {}", outcome),
    })
}

fn amount(v: &Value) -> u128 {
    v.as_str().unwrap().parse().unwrap()
}

async fn balance(a: &Account) -> R<u128> {
    Ok(a.view_account().await?.balance.as_yoctonear())
}

async fn submission(c: &Contract, id: u64) -> R<Value> {
    Ok(c.view("get_submission")
        .args_json(json!({ "submission_id": id }))
        .await?
        .json()?)
}

async fn program(c: &Contract, id: u64) -> R<Value> {
    Ok(c.view("get_program")
        .args_json(json!({ "program_id": id }))
        .await?
        .json()?)
}

async fn submit(c: &Contract, hunter: &Account, pid: u64, n: u64) -> R<u64> {
    let res = hunter
        .call(c.id(), "submit_report")
        .args_json(json!({
            "program_id": pid,
            "title": format!("sandbox report {}", n),
            "commitment": format!("{:064x}", n),
            "sealed": "c2VhbGVk".repeat(32),
        }))
        .deposit(NearToken::from_millinear(200))
        .max_gas()
        .transact()
        .await?
        .into_result()?;
    Ok(res.json()?)
}

async fn create_program(c: &Contract, owner: &Account, verifier: &Account, timeout: u64) -> R<u64> {
    let res = owner
        .call(c.id(), "create_program")
        .args_json(json!({
            "name": "sandbox program",
            "scope": [{ "chain_id": 1, "address": "0x00000000000000000000000000000000000000aa" }],
            "verifier_id": verifier.id(),
            "verifier_pubkey": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
            "payouts": { "critical": "1000000000000000000000000", "high": "500000000000000000000000",
                         "medium": "200000000000000000000000", "low": "100000000000000000000000" },
            "bond": BOND.to_string(),
            "verifier_fee": FEE.to_string(),
            "dispute_bond": DISPUTE_BOND.to_string(),
            "challenge_period_sec": WINDOW,
            "pending_timeout_sec": timeout,
            "resolve_timeout_sec": WINDOW,
        }))
        .deposit(NearToken::from_near(10))
        .max_gas()
        .transact()
        .await?
        .into_result()?;
    Ok(res.json()?)
}

async fn sub_account(worker: &Worker<Sandbox>, name: &str, near: u128) -> R<Account> {
    let root = worker.root_account()?;
    Ok(root
        .create_subaccount(name)
        .initial_balance(NearToken::from_near(near))
        .transact()
        .await?
        .into_result()?)
}

#[tokio::test]
async fn sandbox_end_to_end() -> R<()> {
    let wasm = std::fs::read(wasm_path())
        .map_err(|e| format!("{}: {} (run `./build.sh` first)", wasm_path().display(), e))?;
    let worker = near_workspaces::sandbox().await?;
    let contract = worker.dev_deploy(&wasm).await?;
    contract
        .call("new")
        .args_json(json!({ "owner_id": contract.id() }))
        .transact()
        .await?
        .into_result()?;
    let version: String = contract.view("version").await?.json()?;
    assert_eq!(version, "2.0.0");

    let owner = sub_account(&worker, "owner", 50).await?;
    let verifier = sub_account(&worker, "verifier", 5).await?;
    let hunter1 = sub_account(&worker, "hunter1", 10).await?;
    let hunter2 = sub_account(&worker, "hunter2", 10).await?;
    let anyone = sub_account(&worker, "anyone", 5).await?;

    // --- function-call key for the verifier: only post_verdict on this contract
    let fc_sk = SecretKey::from_random(KeyType::ED25519);
    verifier
        .batch(verifier.id())
        .add_key(
            fc_sk.public_key(),
            AccessKey::function_call_access(
                contract.id(),
                &["post_verdict"],
                Some(NearToken::from_millinear(250)),
            ),
        )
        .transact()
        .await?
        .into_result()?;
    let verifier_fc = Account::from_secret_key(verifier.id().clone(), fc_sk, &worker);

    let pid = create_program(&contract, &owner, &verifier, 3_600).await?;
    let p = program(&contract, pid).await?;
    assert_eq!(p["owner_id"], owner.id().as_str());
    assert!(amount(&p["pool"]) > 9 * NEAR && amount(&p["pool"]) < 10 * NEAR);

    let a = submit(&contract, &hunter1, pid, 1).await?; // valid -> finalize
    let b = submit(&contract, &hunter2, pid, 2).await?; // invalid
    let c = submit(&contract, &hunter2, pid, 3).await?; // duplicate of a
    let d = submit(&contract, &hunter1, pid, 4).await?; // needs_human -> resolve
    let e = submit(&contract, &hunter1, pid, 5).await?; // valid -> dispute -> resolve
    assert_eq!((a, b, c, d, e), (0, 1, 2, 3, 4));
    let reservation = 1_000 * MILLI + FEE;
    assert_eq!(
        amount(&program(&contract, pid).await?["reserved"]),
        5 * reservation
    );

    // same commitment twice is rejected
    let dup_commit = hunter2
        .call(contract.id(), "submit_report")
        .args_json(json!({ "program_id": pid, "title": "again",
                           "commitment": format!("{:064x}", 1), "sealed": "eA==" }))
        .deposit(NearToken::from_millinear(200))
        .max_gas()
        .transact()
        .await?;
    assert!(
        format!("{:?}", dup_commit.into_result().unwrap_err()).contains("commitment already used")
    );

    let pending: Vec<Value> = contract
        .view("list_pending")
        .args_json(json!({ "program_id": pid, "from_index": 0, "limit": 50 }))
        .await?
        .json()?;
    assert_eq!(pending.len(), 5);

    // --- only the verifier may post, and post_verdict takes no deposit
    let wrong = hunter1
        .call(contract.id(), "post_verdict")
        .args_json(json!({ "submission_id": a, "verdict": verdict("valid", Some("high"), None) }))
        .max_gas()
        .transact()
        .await?;
    assert!(
        format!("{:?}", wrong.into_result().unwrap_err()).contains("only the program verifier")
    );
    let with_deposit = verifier
        .call(contract.id(), "post_verdict")
        .args_json(json!({ "submission_id": a, "verdict": verdict("valid", Some("high"), None) }))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact()
        .await?;
    assert!(
        format!("{:?}", with_deposit.into_result().unwrap_err()).contains("doesn't accept deposit")
    );

    // --- verdicts, all signed with the function-call key
    let v_balance0 = balance(&verifier).await?;
    let h2_balance0 = balance(&hunter2).await?;
    let pool0 = amount(&program(&contract, pid).await?["pool"]);
    let bond_b = amount(&submission(&contract, b).await?["bond"]);
    let bond_c = amount(&submission(&contract, c).await?["bond"]);
    let mut verdict_logs: Vec<String> = Vec::new();
    for (id, v) in [
        (a, verdict("valid", Some("high"), None)),
        (b, verdict("invalid", None, None)),
        (c, verdict("duplicate", None, Some(a))),
        (d, verdict("needs_human", None, None)),
        (e, verdict("valid", Some("critical"), None)),
    ] {
        let r = verifier_fc
            .call(contract.id(), "post_verdict")
            .args_json(json!({ "submission_id": id, "verdict": v }))
            .gas(near_workspaces::types::Gas::from_tgas(50))
            .transact()
            .await?
            .into_result()?;
        assert!(
            r.logs()
                .iter()
                .any(|l| l.contains("\"event\":\"verdict_posted\""))
        );
        verdict_logs.extend(r.logs().iter().map(|l| l.to_string()));
    }
    // the verifier earned two fees (invalid + duplicate). Its balance also pays the gas of the
    // function-call key, and gas is expensive on the sandbox, so count the fees in the events;
    // the exact arrival of a fee is checked at `finalize` below, where the verifier pays no gas
    let v_balance1 = balance(&verifier).await?;
    assert!(v_balance1 <= v_balance0 + 2 * FEE);
    let fee_field = format!("\"verifier_fee\":\"{}\"", FEE);
    assert_eq!(
        verdict_logs
            .iter()
            .filter(|l| l.contains(&fee_field))
            .count(),
        2,
        "verifier fees"
    );
    assert_eq!(
        balance(&hunter2).await? - h2_balance0,
        bond_c - FEE,
        "duplicate refund"
    );
    assert_eq!(
        amount(&program(&contract, pid).await?["pool"]),
        pool0 + bond_b - FEE,
        "slashed bond went to the pool"
    );
    assert_eq!(submission(&contract, b).await?["status"], "invalid");
    assert_eq!(submission(&contract, c).await?["status"], "duplicate");
    assert_eq!(submission(&contract, d).await?["status"], "needs_human");

    // the function-call key can do nothing else
    let fc_transfer = verifier_fc
        .transfer_near(hunter1.id(), NearToken::from_near(1))
        .await;
    assert!(
        match &fc_transfer {
            Err(_) => true,
            Ok(r) => r.is_failure(),
        },
        "function-call key must not transfer NEAR"
    );
    let fc_other_method = verifier_fc
        .call(contract.id(), "finalize")
        .args_json(json!({ "submission_id": a }))
        .transact()
        .await;
    assert!(match &fc_other_method {
        Err(_) => true,
        Ok(r) => r.is_failure(),
    });
    let fc_deposit = verifier_fc
        .call(contract.id(), "post_verdict")
        .args_json(json!({ "submission_id": a, "verdict": verdict("valid", Some("high"), None) }))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await;
    assert!(match &fc_deposit {
        Err(_) => true,
        Ok(r) => r.is_failure(),
    });
    assert_eq!(balance(&verifier).await?, v_balance1);

    // --- dispute e inside the window
    let no_bond = owner
        .call(contract.id(), "dispute")
        .args_json(json!({ "submission_id": e, "reason": "known issue" }))
        .transact()
        .await?;
    assert!(
        format!("{:?}", no_bond.into_result().unwrap_err())
            .contains("below the program's dispute bond")
    );
    owner
        .call(contract.id(), "dispute")
        .args_json(json!({ "submission_id": e, "reason": "known issue" }))
        .deposit(NearToken::from_yoctonear(DISPUTE_BOND))
        .transact()
        .await?
        .into_result()?;
    assert_eq!(submission(&contract, e).await?["status"], "disputed");
    assert_eq!(program(&contract, pid).await?["stats"]["disputes"], 1);

    // finalize before the window fails
    let early = anyone
        .call(contract.id(), "finalize")
        .args_json(json!({ "submission_id": a }))
        .transact()
        .await?;
    assert!(
        format!("{:?}", early.into_result().unwrap_err())
            .contains("challenge window has not ended")
    );

    // withdraw_pool cannot touch reserved funds
    let p = program(&contract, pid).await?;
    let free = amount(&p["pool"]) - amount(&p["reserved"]);
    let too_much = owner
        .call(contract.id(), "withdraw_pool")
        .args_json(json!({ "program_id": pid, "amount": (free + 1).to_string() }))
        .transact()
        .await?;
    assert!(
        format!("{:?}", too_much.into_result().unwrap_err()).contains("exceeds the unreserved")
    );
    // the contract account owner has no power over the pool either
    let rug = contract
        .call("withdraw_pool")
        .args_json(json!({ "program_id": pid, "amount": "1" }))
        .transact()
        .await?;
    assert!(format!("{:?}", rug.into_result().unwrap_err()).contains("only the program owner"));

    // --- owner resolves the escalations, before fast-forwarding past their deadlines
    owner
        .call(contract.id(), "resolve")
        .args_json(
            json!({ "submission_id": d, "outcome": "valid", "severity": "low", "note": "ok" }),
        )
        .transact()
        .await?
        .into_result()?;
    assert_eq!(submission(&contract, d).await?["status"], "paid");
    let bond_e = amount(&submission(&contract, e).await?["bond"]);
    let h1_before = balance(&hunter1).await?;
    owner
        .call(contract.id(), "resolve")
        .args_json(json!({ "submission_id": e, "outcome": "invalid", "severity": null, "note": "dup of internal" }))
        .transact()
        .await?
        .into_result()?;
    assert_eq!(submission(&contract, e).await?["status"], "rejected");
    assert_eq!(
        balance(&hunter1).await? - h1_before,
        bond_e + DISPUTE_BOND,
        "overruled dispute: bond + dispute bond to the hunter"
    );
    assert_eq!(program(&contract, pid).await?["stats"]["overruled"], 1);

    // --- advance past the challenge window (sandbox blocks are ~1 s apart; fast-forward)
    let t0: u64 = submission(&contract, a).await?["verdict"]["posted_at"]
        .as_str()
        .unwrap()
        .parse()?;
    loop {
        worker.fast_forward(100).await?;
        let now = worker.view_block().await?.timestamp();
        if now >= t0 + 61 * 1_000_000_000 {
            break;
        }
    }
    let h1_before = balance(&hunter1).await?;
    let v_before = balance(&verifier).await?;
    let bond_a = amount(&submission(&contract, a).await?["bond"]);
    anyone
        .call(contract.id(), "finalize")
        .args_json(json!({ "submission_id": a }))
        .transact()
        .await?
        .into_result()?;
    assert_eq!(
        balance(&hunter1).await? - h1_before,
        500 * MILLI + bond_a,
        "payout + bond"
    );
    assert_eq!(balance(&verifier).await? - v_before, FEE);
    let sa = submission(&contract, a).await?;
    assert_eq!(sa["status"], "paid");
    assert_eq!(amount(&sa["payout"]), 500 * MILLI);

    // --- withdraw_pending after the (minimum, 60 s) pending timeout
    let pid2 = create_program(&contract, &owner, &verifier, WINDOW).await?;
    let f = submit(&contract, &hunter2, pid2, 6).await?;
    let early = hunter2
        .call(contract.id(), "withdraw_pending")
        .args_json(json!({ "submission_id": f }))
        .transact()
        .await?;
    assert!(format!("{:?}", early.into_result().unwrap_err()).contains("pending timeout"));
    let t_f: u64 = submission(&contract, f).await?["submitted_at"]
        .as_str()
        .unwrap()
        .parse()?;
    loop {
        worker.fast_forward(100).await?;
        if worker.view_block().await?.timestamp() >= t_f + (WINDOW + 1) * 1_000_000_000 {
            break;
        }
    }
    let bond_f = amount(&submission(&contract, f).await?["bond"]);
    let h2_before = balance(&hunter2).await?;
    let wd = hunter2
        .call(contract.id(), "withdraw_pending")
        .args_json(json!({ "submission_id": f }))
        .transact()
        .await?
        .into_result()?;
    assert!(wd.logs().iter().any(|l| l.contains("report_withdrawn")));
    // the sandbox charges up to 1 milliNEAR per Tgas, and the default call attaches 30 Tgas
    let gas_cost = 40 * MILLI;
    let got = balance(&hunter2).await? - h2_before;
    assert!(
        got <= bond_f && got + gas_cost >= bond_f,
        "refund {} vs bond {}",
        got,
        bond_f
    );
    assert_eq!(submission(&contract, f).await?["status"], "withdrawn");

    // --- hunter vault: full-access key sets it up, a function-call key submits from it
    hunter2
        .call(contract.id(), "vault_deposit")
        .deposit(NearToken::from_near(1))
        .transact()
        .await?
        .into_result()?;
    hunter2
        .call(contract.id(), "vault_set_policy")
        .args_json(json!({ "max_bond_per_report": BOND.to_string(),
                           "max_spend_per_day": (300 * MILLI).to_string(),
                           "allowed_programs": [pid2] }))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?
        .into_result()?;
    let agent_sk = SecretKey::from_random(KeyType::ED25519);
    hunter2
        .batch(hunter2.id())
        .add_key(
            agent_sk.public_key(),
            AccessKey::function_call_access(
                contract.id(),
                &["submit_report_from_vault", "finalize", "withdraw_pending"],
                // max_gas at the sandbox's gas price needs far more allowance than on testnet
                Some(NearToken::from_near(3)),
            ),
        )
        .transact()
        .await?
        .into_result()?;
    let agent = Account::from_secret_key(hunter2.id().clone(), agent_sk, &worker);
    let g: u64 = agent
        .call(contract.id(), "submit_report_from_vault")
        .args_json(json!({ "program_id": pid2, "title": "from the vault",
                           "commitment": format!("{:064x}", 7), "sealed": "eA==" }))
        .max_gas()
        .transact()
        .await?
        .into_result()?
        .json()?;
    let sg = submission(&contract, g).await?;
    assert_eq!(sg["funded_by_vault"], true);
    assert_eq!(amount(&sg["bond"]), BOND);
    // the agent key can neither withdraw nor change the policy
    let steal = agent
        .call(contract.id(), "vault_withdraw")
        .args_json(json!({ "amount": "1" }))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await;
    assert!(match &steal {
        Err(_) => true,
        Ok(r) => r.is_failure(),
    });
    let relax = agent
        .call(contract.id(), "vault_set_policy")
        .args_json(
            json!({ "max_bond_per_report": "1", "max_spend_per_day": "1",
                           "allowed_programs": null }),
        )
        .transact()
        .await;
    assert!(match &relax {
        Err(_) => true,
        Ok(r) => r.is_failure(),
    });
    // a third vault report would exceed the daily limit after a second one
    agent
        .call(contract.id(), "submit_report_from_vault")
        .args_json(json!({ "program_id": pid2, "title": "second",
                           "commitment": format!("{:064x}", 8), "sealed": "eA==" }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;
    let over = agent
        .call(contract.id(), "submit_report_from_vault")
        .args_json(json!({ "program_id": pid2, "title": "third",
                           "commitment": format!("{:064x}", 9), "sealed": "eA==" }))
        .max_gas()
        .transact()
        .await?;
    assert!(format!("{:?}", over.into_result().unwrap_err()).contains("max_spend_per_day"));
    // needs_human, not resolved: the agent finalizes after resolve_until, the bond returns
    verifier
        .call(contract.id(), "post_verdict")
        .args_json(json!({ "submission_id": g, "verdict": verdict("needs_human", None, None) }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;
    let vault_before: Value = contract
        .view("get_vault")
        .args_json(json!({ "account_id": hunter2.id() }))
        .await?
        .json()?;
    let until: u64 = submission(&contract, g).await?["resolve_until"]
        .as_str()
        .unwrap()
        .parse()?;
    loop {
        worker.fast_forward(100).await?;
        if worker.view_block().await?.timestamp() >= until + 1_000_000_000 {
            break;
        }
    }
    agent
        .call(contract.id(), "finalize")
        .args_json(json!({ "submission_id": g }))
        .transact()
        .await?
        .into_result()?;
    assert_eq!(submission(&contract, g).await?["status"], "expired");
    let vault_after: Value = contract
        .view("get_vault")
        .args_json(json!({ "account_id": hunter2.id() }))
        .await?
        .json()?;
    assert_eq!(
        amount(&vault_after["balance"]),
        amount(&vault_before["balance"]) + BOND,
        "expired bond back into the vault"
    );

    // --- reputation and accounting
    let h1: Value = contract
        .view("get_hunter")
        .args_json(json!({ "account_id": hunter1.id() }))
        .await?
        .json()?;
    assert_eq!(h1["valid"], 2);
    assert_eq!(h1["invalid"], 0);
    let h1p: Value = contract
        .view("get_hunter_in_program")
        .args_json(json!({ "program_id": pid, "account_id": hunter1.id() }))
        .await?
        .json()?;
    assert_eq!(h1p, h1);
    let req: String = contract
        .view("required_bond")
        .args_json(json!({ "program_id": pid, "hunter_id": hunter1.id() }))
        .await?
        .json()?;
    assert_eq!(req.parse::<u128>()?, BOND / 2);

    // program 0 is settled; program 1 still holds the second vault report
    let mut pools = 0u128;
    for id in [pid, pid2] {
        let p = program(&contract, id).await?;
        let open = if id == pid { 0 } else { 1_000 * MILLI + FEE };
        assert_eq!(amount(&p["reserved"]), open);
        pools += amount(&p["pool"]);
    }
    let acct = contract.view_account().await?;
    let storage_stake = acct.storage_usage as u128 * 10_000_000_000_000_000_000;
    assert!(
        acct.balance.as_yoctonear() >= pools + storage_stake,
        "contract is solvent"
    );

    // drain program 0 completely: the owner gets exactly the pool back
    let p = program(&contract, pid).await?;
    let o_before = balance(&owner).await?;
    let w = owner
        .call(contract.id(), "withdraw_pool")
        .args_json(json!({ "program_id": pid, "amount": p["pool"] }))
        .transact()
        .await?
        .into_result()?;
    assert!(w.logs().iter().any(|l| l.contains("pool_withdrawn")));
    assert!(balance(&owner).await? > o_before);
    assert_eq!(amount(&program(&contract, pid).await?["pool"]), 0);
    Ok(())
}
