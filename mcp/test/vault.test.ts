// Vault mode (SPEC v2 "Hunter vault"): the server signs submit_report_from_vault with the hunter's
// function-call key; the mocked contract draws bond + storage from the vault inside its policy,
// exactly in the contract's order. Covers the submission, every vault refusal before signing,
// both layers refusing together, the contract as the backstop, and what budget_status shows.

import assert from "node:assert/strict";
import { after, afterEach, describe, it } from "node:test";
import { DAY_NS } from "../../agent/src/actions.ts";
import { commitmentFor, openAndCheck } from "../../agent/src/seal.ts";
import { formatNear } from "../src/amounts.ts";
import { vaultDecide, vaultKeyCheck, vaultRule } from "../src/vault.ts";
import { cleanup, CONTRACT, fcPermission, harness, HUNTER, mockChain, N, program, SAMPLE_REPORT, vault, VERIFIER } from "./helpers.ts";
import type { Harness } from "./helpers.ts";

const open: Harness[] = [];
async function start(opts: Parameters<typeof harness>[0] = {}): Promise<Harness> {
  const clock = opts.clock ?? { t: Date.parse("2026-11-02T12:00:00Z") };
  const chain = opts.chain ?? mockChain({ now: () => clock.t, vault: vault(), permission: fcPermission() });
  const h = await harness({ mode: "vault", ...opts, clock, chain, policy: { max_total_deposit_24h_near: "0.6", ...(opts.policy ?? {}) } });
  open.push(h);
  return h;
}
afterEach(async () => {
  for (const h of open.splice(0)) await h.close();
});
after(cleanup);

const submit = (h: Harness, over: Record<string, unknown> = {}) =>
  h.call("submit_report", { program_id: 7, title: "Accounting bug in vault", report_markdown: SAMPLE_REPORT, ...over });

type Amt = { near: string; yocto: string };

describe("vault mode: submit_report", () => {
  it("signs submit_report_from_vault with no deposit; the vault pays bond + storage", async () => {
    const h = await start();
    const { doc, isError } = await submit(h);
    assert.equal(isError, false);
    assert.equal(doc.outcome, "submitted");
    assert.equal(doc.method, "submit_report_from_vault");
    assert.equal(doc.tx_hash, "TX0vault");
    assert.deepEqual(h.chain.calls.map((c) => [c.method, c.deposit]), [["submit_report_from_vault", 0n]]);
    assert.deepEqual(doc.attached, { near: "0", yocto: "0" });

    // v2 commitment, bound to the hunter account
    const args = h.chain.calls[0].args as { sealed: string; commitment: string };
    assert.equal(args.commitment, commitmentFor(HUNTER, Buffer.from(SAMPLE_REPORT)));
    assert.ok(openAndCheck(args.sealed, VERIFIER.privateKey, args.commitment, HUNTER).ok);

    // what the contract charged, and the vault afterwards
    const charged = doc.charged_on_chain as { bond: Amt; storage_cost: Amt; funded_by_vault: boolean };
    assert.equal(charged.funded_by_vault, true);
    assert.equal(charged.bond.near, "0.1");
    const est = doc.drawn_from_vault_estimate as { storage_estimate: Amt; total: Amt };
    assert.ok(BigInt(charged.storage_cost.yocto) <= BigInt(est.storage_estimate.yocto), "the estimate covers the measured storage");
    const after = doc.vault_after as { balance: Amt; spent_in_current_window: Amt };
    const draw = N("0.1") + BigInt(charged.storage_cost.yocto);
    assert.equal(BigInt(after.balance.yocto), N("1") - draw);
    assert.equal(BigInt(after.spent_in_current_window.yocto), draw);
    assert.deepEqual((doc.vault_checks as { ok: boolean }[]).map((c) => c.ok), [true, true, true, true, true, true]);
    assert.equal(h.chain.balance, N("1"), "the account itself attached nothing");

    // the ledger records the draw (counted against the local caps) as vault-funded
    const intent = h.ledger.read().records.find((r) => r.type === "intent") as { funding?: string; deposit_yocto: string };
    assert.equal(intent.funding, "vault");
    assert.equal(BigInt(intent.deposit_yocto), BigInt(est.total.yocto));

    const sub = await h.call("get_submission", { submission_id: 0 });
    const view = sub.doc.submission as { funded_by_vault: boolean; bond_refunds_to: string; storage_cost: Amt };
    assert.equal(view.funded_by_vault, true);
    assert.equal(view.bond_refunds_to, "vault");
  });

  it("dry_run shows the vault draw and both layers' checks, signs nothing", async () => {
    const h = await start();
    const { doc } = await submit(h, { dry_run: true });
    assert.equal(doc.outcome, "dry_run");
    assert.ok(doc.would_draw_from_vault);
    assert.deepEqual(doc.would_attach, { near: "0", yocto: "0" });
    assert.ok(Array.isArray(doc.vault_checks) && Array.isArray(doc.checks));
    assert.equal(h.chain.calls.length, 0);
  });

  it("refuses a program outside the vault's allow-list before fetching anything (refused_by vault_policy)", async () => {
    const h = await start({ policy: { allowed_program_ids: [0, 7] } }); // the local policy would allow it
    const { doc, isError } = await submit(h, { program_id: 0 });
    assert.equal(isError, false);
    assert.equal(doc.outcome, "refused");
    assert.equal(doc.refused_by, "vault_policy");
    assert.equal(doc.rule, "program_not_allowed");
    assert.equal(doc.signed, false);
    assert.match(doc.reason as string, /program 0 is not in the vault's allowed programs \[7\]/);
    assert.match(doc.reason as string, /full-access key/);
    assert.deepEqual(doc.also_refused_by, []);
    assert.equal(h.chain.calls.length, 0);
    const rec = h.ledger.read().records.at(-1) as { type: string; refused_by?: string; rule: string };
    assert.deepEqual([rec.type, rec.refused_by, rec.rule], ["refusal", "vault_policy", "program_not_allowed"]);
  });

  it("a program off both allow-lists: both layers are reported", async () => {
    const h = await start();
    const { doc } = await submit(h, { program_id: 0 });
    assert.equal(doc.refused_by, "vault_policy");
    assert.equal(doc.rule, "program_not_allowed");
    const also = doc.also_refused_by as { refused_by: string; rule: string }[];
    assert.deepEqual(also.map((x) => [x.refused_by, x.rule]), [["policy", "program_not_allowed"]]);
  });

  it("refuses without a vault or without a vault policy", async () => {
    let h = await start({ chain: mockChain({ vault: null, permission: fcPermission() }) });
    let r = await submit(h);
    assert.equal(r.doc.refused_by, "vault_policy");
    assert.equal(r.doc.rule, "vault_missing");
    h = await start({ chain: mockChain({ vault: vault({ policy_set: false }), permission: fcPermission() }) });
    r = await submit(h);
    assert.equal(r.doc.rule, "vault_policy_not_set");
    assert.equal(h.chain.calls.length, 0);
  });

  it("refuses a bond above the vault's max bond (while the local policy allows it)", async () => {
    const chain = mockChain({ vault: vault({ max_bond_per_report: N("0.05").toString() }), permission: fcPermission() });
    const h = await start({ chain });
    const { doc } = await submit(h);
    assert.equal(doc.refused_by, "vault_policy");
    assert.equal(doc.rule, "bond_above_max");
    assert.equal((doc.limit as Amt).near, "0.05");
    assert.equal((doc.requested as Amt).near, "0.1");
    assert.equal(chain.calls.length, 0);
  });

  it("refuses above the vault's 24 h cap with the storage counted, and says when the window resets", async () => {
    const clock = { t: Date.parse("2026-11-02T12:00:00Z") };
    const startNs = BigInt(clock.t - 3_600_000) * 1_000_000n; // window opened an hour ago
    const chain = mockChain({
      now: () => clock.t,
      vault: vault({ spent_in_window: N("0.38").toString(), window_start: startNs.toString() }),
      permission: fcPermission(),
    });
    const h = await start({ chain, clock });
    // bond 0.1 alone fits under 0.5 - 0.38 (the agent library's check passes); bond + storage (~0.03) does not
    const { doc } = await submit(h);
    assert.equal(doc.refused_by, "vault_policy");
    assert.equal(doc.rule, "daily_spend_cap");
    assert.match(doc.reason as string, /storage estimate/);
    assert.equal((doc.already_used as Amt).near, "0.38");
    assert.equal(doc.retry_after, new Date(Number((startNs + DAY_NS) / 1_000_000n)).toISOString());
    const v = doc.vault as { remaining_in_window: Amt; window_resets_at: string };
    assert.equal(v.remaining_in_window.near, "0.12");
    assert.equal(v.window_resets_at, doc.retry_after);
    assert.equal(chain.calls.length, 0);

    // after the window the same report passes
    clock.t += 24 * 3_600_000;
    assert.equal((await submit(h)).doc.outcome, "submitted");
  });

  it("the daily cap holds across reports: the second one in the window is refused before signing", async () => {
    const chain = mockChain({ vault: vault({ max_spend_per_day: N("0.25").toString() }), permission: fcPermission() });
    const h = await start({ chain });
    assert.equal((await submit(h, { report_markdown: SAMPLE_REPORT + "1" })).doc.outcome, "submitted");
    const second = await submit(h, { report_markdown: SAMPLE_REPORT + "2" });
    assert.equal(second.doc.refused_by, "vault_policy");
    assert.equal(second.doc.rule, "daily_spend_cap");
    assert.ok(second.doc.retry_after, "it fits again when the window restarts");
    assert.equal(chain.calls.length, 1);
  });

  it("refuses when the vault balance cannot cover bond + storage", async () => {
    const chain = mockChain({ vault: vault({ balance: N("0.12").toString() }), permission: fcPermission() });
    const h = await start({ chain });
    const { doc } = await submit(h);
    assert.equal(doc.rule, "vault_balance_too_low");
    assert.equal(doc.retry_after, null);
    assert.equal(chain.calls.length, 0);
  });

  it("the local policy stays the second layer: its 24 h cap refuses what the vault would allow", async () => {
    const h = await start({ policy: { max_total_deposit_24h_near: "0.15" } });
    assert.equal((await submit(h, { report_markdown: SAMPLE_REPORT + "1" })).doc.outcome, "submitted");
    const r = await submit(h, { report_markdown: SAMPLE_REPORT + "2" });
    assert.equal(r.doc.refused_by, "policy");
    assert.equal(r.doc.rule, "daily_deposit_cap");
    assert.match(r.doc.reason as string, /vault draw/);
    assert.ok((r.doc.vault_checks as { ok: boolean }[]).every((c) => c.ok), "the vault itself would have allowed it");
  });

  it("the minimum balance only keeps the gas reserve free: the vault, not the account, pays the bond", async () => {
    const h = await start();
    h.chain.balance = N("0.35"); // above min 0.3 + gas 0.02, below min + bond + storage
    assert.equal((await submit(h)).doc.outcome, "submitted");
  });

  it("if the pre-check is bypassed (vault changed in between), the contract refuses and nothing is drawn", async () => {
    const h = await start();
    const real = h.chain.getVault.bind(h.chain);
    let calls = 0;
    // the first look (allow-lists) and the look under the lock see the old policy; then it shrinks
    h.chain.getVault = async (id) => {
      calls++;
      const v = await real(id);
      if (calls === 2) h.chain.vault = { ...h.chain.vault!, max_spend_per_day: N("0.05").toString() };
      return v;
    };
    const { doc, isError } = await submit(h);
    assert.equal(isError, true);
    assert.equal(doc.outcome, "failed");
    assert.equal(doc.tx_status, "failed_onchain");
    assert.equal(doc.deposit_counted_against_budget, false);
    assert.match((doc.error as { message: string }).message, /vault max_spend_per_day exceeded/);
    assert.match(doc.explanation as string, /nothing was drawn from the vault/);
    assert.equal(h.chain.vault!.balance, N("1").toString());
  });

  it("fails closed when the vault cannot be read", async () => {
    const h = await start();
    h.chain.getVault = async () => {
      throw new Error("rpc down");
    };
    const { doc, isError } = await submit(h);
    assert.equal(isError, true);
    assert.equal(doc.outcome, "error");
    assert.equal(h.chain.calls.length, 0);
  });
});

describe("vault mode: read tools", () => {
  it("budget_status shows the on-chain vault, its policy, spent_in_window and the key's permission", async () => {
    const h = await start();
    await submit(h);
    const { doc } = await h.call("budget_status");
    const signing = doc.signing as { mode: string; public_key: string; permission: { kind: string; method_names: string[]; allowance_remaining: Amt; receiver_id: string } };
    assert.equal(signing.mode, "vault");
    assert.equal(signing.public_key, "ed25519:MockPublicKey");
    assert.equal(signing.permission.kind, "FunctionCall");
    assert.equal(signing.permission.receiver_id, CONTRACT);
    assert.deepEqual(signing.permission.method_names, ["submit_report_from_vault", "finalize", "withdraw_pending"]);
    assert.equal(signing.permission.allowance_remaining.near, "0.5");
    const v = doc.vault as {
      exists: boolean; balance: Amt; policy: { max_bond_per_report: Amt; max_spend_per_day: Amt; allowed_programs: number[] };
      spent_in_window: Amt; spent_in_current_window: Amt; remaining_in_window: Amt; window_resets_at: string;
    };
    assert.equal(v.exists, true);
    assert.deepEqual(v.policy.allowed_programs, [7]);
    assert.equal(v.policy.max_bond_per_report.near, "0.15");
    assert.equal(v.policy.max_spend_per_day.near, "0.5");
    const spent = BigInt(h.chain.vault!.spent_in_window);
    assert.equal(v.spent_in_window.yocto, spent.toString());
    assert.equal(v.remaining_in_window.near, formatNear(N("0.5") - spent));
    assert.equal(v.balance.yocto, h.chain.vault!.balance);
    assert.equal(v.window_resets_at, new Date(h.clock.t + 24 * 3_600_000).toISOString());
    assert.match((doc.balance as { used_for: string }).used_for, /gas only/);
  });

  it("list_programs and required_bond show the vault's allow-list next to the local one", async () => {
    const h = await start({ policy: { allowed_program_ids: [0, 7] } });
    const list = await h.call("list_programs");
    const progs = list.doc.programs as { id: number; allowed_by_policy: boolean; allowed_by_vault: boolean; dispute_bond: Amt; resolve_timeout_sec: number }[];
    assert.deepEqual(progs.map((p) => [p.id, p.allowed_by_policy, p.allowed_by_vault]), [[0, true, false], [7, true, true]]);
    assert.deepEqual(list.doc.vault_allowed_program_ids, [7]);
    const only = await h.call("list_programs", { allowed_only: true });
    assert.deepEqual((only.doc.programs as { id: number }[]).map((p) => p.id), [7]);
    const rb = await h.call("required_bond", { program_id: 0 });
    assert.deepEqual(rb.doc.vault_policy, {
      program_allowed: false, bond_within_max: true, max_bond_per_report: { near: "0.15", yocto: N("0.15").toString() },
      remaining_in_window: { near: "0.5", yocto: N("0.5").toString() },
    });
    assert.ok(rb.doc.hunter_stats_in_program);
  });

  it("finalize and withdraw_pending work with the function-call key (no deposit)", async () => {
    const h = await start();
    await submit(h);
    Object.assign(h.chain.submissions[0], { status: "valid", valid_until: "1" });
    const r = await h.call("finalize", { submission_id: 0 });
    assert.equal(r.doc.outcome, "finalized");
    assert.equal(r.doc.bond_refunded_to, "vault");
    assert.deepEqual(h.chain.calls.map((c) => [c.method, c.deposit]), [["submit_report_from_vault", 0n], ["finalize", 0n]]);
  });
});

describe("vault mode: pure checks", () => {
  it("vaultKeyCheck accepts exactly the hunter function-call key and refuses a full-access key unless allowed", () => {
    assert.equal(vaultKeyCheck(fcPermission(), CONTRACT, HUNTER, false).ok, true);
    const fa = vaultKeyCheck("FullAccess", CONTRACT, HUNTER, false);
    assert.equal(fa.ok, false);
    assert.match(!fa.ok ? fa.problem : "", /refuses a full-access key.*REPLAYCOURT_MCP_ALLOW_FULL_ACCESS=1/);
    const allowed = vaultKeyCheck("FullAccess", CONTRACT, HUNTER, true);
    assert.ok(allowed.ok && /FULL-ACCESS/.test(allowed.warning ?? ""));
    for (const bad of [
      fcPermission({ receiver_id: "other.testnet" }),
      fcPermission({ method_names: ["submit_report_from_vault"] }),
      fcPermission({ method_names: [] }), // any method of the contract
      fcPermission({ method_names: ["submit_report_from_vault", "finalize", "withdraw_pending", "vault_withdraw"] }),
      null,
    ]) {
      assert.equal(vaultKeyCheck(bad, CONTRACT, HUNTER, true).ok, false, JSON.stringify(bad));
    }
  });

  it("maps every refusal reason of the agent library to a rule", () => {
    const nowNs = 10n ** 18n;
    const cases: [ReturnType<typeof vault> | null, number, bigint, string][] = [
      [null, 7, 1n, "vault_missing"],
      [vault({ policy_set: false }), 7, 1n, "vault_policy_not_set"],
      [vault(), 3, 1n, "program_not_allowed"],
      [vault(), 7, N("0.2"), "bond_above_max"],
      [vault({ spent_in_window: N("0.45").toString(), window_start: (nowNs - 1n).toString() }), 7, N("0.1"), "daily_spend_cap"],
      [vault({ balance: N("0.05").toString() }), 7, N("0.1"), "vault_balance_too_low"],
    ];
    for (const [v, pid, bond, rule] of cases) {
      const d = vaultDecide(v, pid, bond, 0n, nowNs);
      assert.equal(d.allowed, false, rule);
      assert.equal(!d.allowed && d.refusal.rule, rule);
      assert.deepEqual(d.checks.at(-1), { rule, ok: false });
    }
    assert.equal(vaultRule("something new"), "vault_policy");
    assert.equal(vaultDecide(vault(), 7, N("0.1"), N("0.05"), nowNs).allowed, true);
  });
});

describe("direct mode next to a vault", () => {
  it("a direct-mode server ignores the vault and attaches the deposit", async () => {
    const chain = mockChain({ vault: vault(), programs: [program(7)] });
    const h = await harness({ chain });
    open.push(h);
    const { doc } = await submit(h);
    assert.equal(doc.method, "submit_report");
    assert.equal(chain.calls[0].method, "submit_report");
    assert.ok(chain.calls[0].deposit > 0n);
    const st = await h.call("budget_status");
    assert.equal(st.doc.vault, undefined);
    assert.equal((st.doc.signing as { mode: string }).mode, "direct");
  });
});
