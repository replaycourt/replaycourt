import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { formatNear, parseNear } from "../src/amounts.ts";
import { DAY_MS, decide, HOUR_MS, parsePolicy, PolicyError } from "../src/policy.ts";
import type { SpendHistory, SpendRequest } from "../src/policy.ts";
import { BASE_POLICY, N } from "./helpers.ts";

const NOW = Date.parse("2026-11-02T12:00:00Z");
const policy = parsePolicy(BASE_POLICY);
const empty: SpendHistory = { deposits: [], reportAttempts: [] };
const submit = (over: Partial<SpendRequest> = {}): SpendRequest => ({
  op: "submit_report",
  programId: 7,
  bond: N("0.1"),
  deposit: N("0.2"),
  gasReserve: N("0.02"),
  ...over,
});

describe("amounts", () => {
  it("parses and formats exactly", () => {
    assert.equal(parseNear("0.15", "x"), 150000000000000000000000n);
    assert.equal(parseNear("1", "x"), 10n ** 24n);
    assert.equal(formatNear(150000000000000000000000n), "0.15");
    assert.equal(formatNear(1n), "0.000000000000000000000001");
    assert.equal(formatNear(-N("0.5")), "-0.5");
    for (const bad of ["-1", "1e3", "0.1234567890123456789012345", "", " ", "abc", null]) {
      assert.throws(() => parseNear(bad, "x"), /NEAR amount/);
    }
  });
});

describe("policy file validation", () => {
  it("accepts the base policy and keeps the program list sorted and unique", () => {
    const p = parsePolicy({ ...BASE_POLICY, allowed_program_ids: [9, 7, 9] });
    assert.deepEqual(p.allowedProgramIds, [7, 9]);
    assert.equal(p.maxBondPerReport, N("0.15"));
    assert.equal(p.maxDepositPerReport, N("0.4"));
  });

  it("rejects unknown fields (a typo must not switch a limit off)", () => {
    assert.throws(() => parsePolicy({ ...BASE_POLICY, max_bond: "5" }), /unknown field "max_bond"/);
  });

  it("allows comment fields", () => {
    assert.doesNotThrow(() => parsePolicy({ ...BASE_POLICY, _comment: "demo", $schema: "x" }));
  });

  it("requires every limit", () => {
    for (const k of ["allowed_program_ids", "max_bond_per_report_near", "max_total_deposit_24h_near", "max_total_deposit_lifetime_near", "min_account_balance_near", "max_reports_per_hour", "version"]) {
      const o: Record<string, unknown> = { ...BASE_POLICY };
      delete o[k];
      assert.throws(() => parsePolicy(o), new RegExp(`missing field "${k}"`), k);
    }
  });

  it("max_deposit_per_report is optional", () => {
    const o: Record<string, unknown> = { ...BASE_POLICY };
    delete o.max_deposit_per_report_near;
    assert.equal(parsePolicy(o).maxDepositPerReport, null);
  });

  it("rejects bad values and reports all problems at once", () => {
    try {
      parsePolicy({ ...BASE_POLICY, allowed_program_ids: "*", max_bond_per_report_near: 0.1e30, max_reports_per_hour: -1, version: 2 });
      assert.fail("no error");
    } catch (e) {
      assert.ok(e instanceof PolicyError);
      const m = (e as Error).message;
      assert.match(m, /allowed_program_ids/);
      assert.match(m, /max_bond_per_report_near/);
      assert.match(m, /max_reports_per_hour/);
      assert.match(m, /version/);
    }
  });

  it("rejects a 24 h cap above the lifetime cap", () => {
    assert.throws(() => parsePolicy({ ...BASE_POLICY, max_total_deposit_24h_near: "2" }), /larger than/);
  });
});

describe("policy decisions", () => {
  it("allows a request inside every limit and lists the checks", () => {
    const d = decide(policy, submit(), empty, N("1"), NOW);
    assert.equal(d.allowed, true);
    assert.deepEqual(d.checks.map((c) => c.rule), [
      "program_allowed",
      "bond_within_max",
      "deposit_within_max_per_report",
      "hourly_report_limit",
      "daily_deposit_cap",
      "lifetime_deposit_cap",
      "min_balance",
    ]);
  });

  const refusedBy = (d: ReturnType<typeof decide>) => (d.allowed ? null : d.refusal);

  it("refuses programs that are not on the allow-list", () => {
    const r = refusedBy(decide(policy, submit({ programId: 0 }), empty, N("1"), NOW));
    assert.equal(r?.rule, "program_not_allowed");
    assert.equal(r?.retry_after, null);
  });

  it("refuses a bond above the maximum", () => {
    const r = refusedBy(decide(policy, submit({ bond: N("0.16"), deposit: N("0.2") }), empty, N("1"), NOW));
    assert.equal(r?.rule, "bond_above_max");
    assert.deepEqual(r?.limit, { near: "0.15", yocto: N("0.15").toString() });
  });

  it("refuses a deposit above the per-report maximum", () => {
    const r = refusedBy(decide(policy, submit({ deposit: N("0.41") }), empty, N("5"), NOW));
    assert.equal(r?.rule, "deposit_above_max_per_report");
  });

  it("refuses more reports per hour than allowed and says when the next slot opens", () => {
    const h: SpendHistory = { deposits: [], reportAttempts: [NOW - 50 * 60_000, NOW - 20 * 60_000, NOW - 5 * 60_000, NOW - 2 * HOUR_MS] };
    const r = refusedBy(decide(policy, submit(), h, N("1"), NOW));
    assert.equal(r?.rule, "hourly_report_limit");
    assert.equal(r?.already_used, 3);
    assert.equal(r?.retry_after, new Date(NOW - 50 * 60_000 + HOUR_MS).toISOString());
  });

  it("max_reports_per_hour 0 disables submissions", () => {
    const p = parsePolicy({ ...BASE_POLICY, max_reports_per_hour: 0 });
    const r = refusedBy(decide(p, submit(), empty, N("1"), NOW));
    assert.equal(r?.rule, "hourly_report_limit");
    assert.equal(r?.retry_after, null);
  });

  it("refuses above the rolling 24 h cap and computes when enough falls out of the window", () => {
    const h: SpendHistory = {
      deposits: [
        { at: NOW - 23 * HOUR_MS, amount: N("0.1") },
        { at: NOW - 2 * HOUR_MS, amount: N("0.1") },
        { at: NOW - 25 * HOUR_MS, amount: N("0.5") }, // outside the window
      ],
      reportAttempts: [],
    };
    const r = refusedBy(decide(policy, submit({ deposit: N("0.15") }), h, N("2"), NOW));
    assert.equal(r?.rule, "daily_deposit_cap");
    assert.deepEqual(r?.already_used, { near: "0.2", yocto: N("0.2").toString() });
    // 0.2 + 0.15 > 0.3; once the deposit from 23 h ago leaves the window: 0.1 + 0.15 <= 0.3
    assert.equal(r?.retry_after, new Date(NOW - 23 * HOUR_MS + DAY_MS).toISOString());
  });

  it("a deposit larger than the 24 h cap on its own never fits", () => {
    const p = parsePolicy({ ...BASE_POLICY, max_deposit_per_report_near: "1" });
    const r = refusedBy(decide(p, submit({ deposit: N("0.31") }), empty, N("2"), NOW));
    assert.equal(r?.rule, "daily_deposit_cap");
    assert.equal(r?.retry_after, null);
  });

  it("refuses above the lifetime cap even when the 24 h window is empty", () => {
    const h: SpendHistory = { deposits: [{ at: NOW - 30 * DAY_MS, amount: N("0.9") }], reportAttempts: [] };
    const r = refusedBy(decide(policy, submit({ deposit: N("0.2") }), h, N("2"), NOW));
    assert.equal(r?.rule, "lifetime_deposit_cap");
    assert.equal(r?.retry_after, null);
  });

  it("allows exactly reaching a cap", () => {
    const h: SpendHistory = { deposits: [{ at: NOW - HOUR_MS, amount: N("0.1") }], reportAttempts: [] };
    assert.equal(decide(policy, submit({ deposit: N("0.2") }), h, N("2"), NOW).allowed, true);
  });

  it("refuses when the balance after deposit and gas would fall below the minimum", () => {
    const r = refusedBy(decide(policy, submit(), empty, N("0.5"), NOW));
    assert.equal(r?.rule, "min_balance");
    // 0.5 - 0.2 - 0.02 = 0.28 < 0.3
    assert.match(r!.reason, /0\.28 NEAR/);
    assert.equal(decide(policy, submit(), empty, N("0.52"), NOW).allowed, true);
  });

  it("fails closed when the balance is unknown", () => {
    assert.equal(refusedBy(decide(policy, submit(), empty, null, NOW))?.rule, "balance_unknown");
    assert.equal(refusedBy(decide(policy, { op: "finalize", programId: 7, bond: 0n, deposit: 0n, gasReserve: N("0.02") }, empty, null, NOW))?.rule, "balance_unknown");
  });

  it("gas-only operations skip the deposit rules but keep the allow-list and the minimum balance", () => {
    const h: SpendHistory = { deposits: [{ at: NOW, amount: N("1") }], reportAttempts: [NOW, NOW, NOW, NOW] };
    const fin: SpendRequest = { op: "finalize", programId: 7, bond: 0n, deposit: 0n, gasReserve: N("0.02") };
    assert.equal(decide(policy, fin, h, N("1"), NOW).allowed, true);
    assert.equal(refusedBy(decide(policy, { ...fin, programId: 3 }, h, N("1"), NOW))?.rule, "program_not_allowed");
    assert.equal(refusedBy(decide(policy, { ...fin, op: "withdraw_pending" }, h, N("0.31"), NOW))?.rule, "min_balance");
  });
});
