import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { after, describe, it } from "node:test";
import { commitmentUsed, knownSubmissionIds, Ledger, LedgerBusyError, spendHistory } from "../src/ledger.ts";
import type { OutcomeStatus } from "../src/ledger.ts";
import { cleanup, N, tmpDir } from "./helpers.ts";

after(cleanup);

const T0 = Date.parse("2026-11-02T12:00:00Z");

function intent(ledger: Ledger, opId: string, deposit: string, op: "submit_report" | "finalize" = "submit_report", commitment: string | null = null) {
  return ledger.append({
    type: "intent",
    op,
    op_id: opId,
    network: "testnet",
    contract_id: "c.testnet",
    account_id: "h.testnet",
    program_id: 7,
    submission_id: null,
    deposit_yocto: N(deposit).toString(),
    bond_yocto: "0",
    storage_yocto: "0",
    commitment,
  });
}
function outcome(ledger: Ledger, opId: string, status: OutcomeStatus, submissionId: number | null = null) {
  return ledger.append({ type: "outcome", op_id: opId, status, tx_hash: status === "ok" ? "TX" : null, submission_id: submissionId, error: null });
}

describe("ledger", () => {
  it("creates the state dir and file with private permissions", () => {
    const dir = path.join(tmpDir(), "state");
    const l = new Ledger(dir);
    assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
    assert.equal(fs.statSync(l.file).mode & 0o777, 0o600);
  });

  it("persists across instances (limits survive a restart)", async () => {
    const dir = tmpDir();
    const clock = { t: T0 };
    const a = new Ledger(dir, { clock: () => clock.t });
    await a.withLock(async () => {
      intent(a, "op1", "0.2", "submit_report", "c1");
      outcome(a, "op1", "ok", 4);
    });
    const b = new Ledger(dir);
    const snap = b.read();
    assert.equal(snap.integrity.ok, true);
    assert.equal(snap.records.length, 2);
    const h = spendHistory(snap.records);
    assert.deepEqual(h.deposits, [{ at: T0, amount: N("0.2") }]);
    assert.deepEqual(h.reportAttempts, [T0]);
    assert.deepEqual(knownSubmissionIds(snap.records), [4]);
    assert.equal(commitmentUsed(snap.records, "c1"), true);
    assert.equal(commitmentUsed(snap.records, "c2"), false);
  });

  it("counts deposits unless the outcome proves they never left the account", () => {
    const l = new Ledger(tmpDir());
    intent(l, "ok", "0.1");
    outcome(l, "ok", "ok", 1);
    intent(l, "panic", "0.2");
    outcome(l, "panic", "failed_onchain");
    intent(l, "rejected", "0.3");
    outcome(l, "rejected", "not_executed");
    intent(l, "timeout", "0.4");
    outcome(l, "timeout", "unknown");
    intent(l, "crash", "0.5"); // no outcome: the process died while sending
    intent(l, "gas", "0", "finalize");
    outcome(l, "gas", "ok");
    const h = spendHistory(l.read().records);
    assert.deepEqual(h.deposits.map((d) => d.amount), [N("0.1"), N("0.4"), N("0.5")]);
    // every signed submit counts as an attempt for the hourly limit, whatever happened to it
    assert.equal(h.reportAttempts.length, 5);
  });

  it("a failed commitment may be retried, a sent one may not", () => {
    const l = new Ledger(tmpDir());
    intent(l, "a", "0.1", "submit_report", "c-failed");
    outcome(l, "a", "failed_onchain");
    intent(l, "b", "0.1", "submit_report", "c-unknown");
    const recs = l.read().records;
    assert.equal(commitmentUsed(recs, "c-failed"), false);
    assert.equal(commitmentUsed(recs, "c-unknown"), true);
  });

  it("cuts off a torn last line (crash during a write) and keeps working", () => {
    const l = new Ledger(tmpDir());
    intent(l, "a", "0.1");
    fs.appendFileSync(l.file, '{"v":1,"seq":2,"type":"inte');
    const snap = l.read();
    assert.equal(snap.integrity.ok, true);
    assert.equal(snap.records.length, 1);
    outcome(l, "a", "ok");
    assert.equal(l.read().records.length, 2);
    assert.equal(l.read().integrity.ok, true);
  });

  it("detects an edited record in the middle (hash chain)", () => {
    const l = new Ledger(tmpDir());
    intent(l, "a", "0.25");
    outcome(l, "a", "ok");
    intent(l, "b", "0.1");
    const lines = fs.readFileSync(l.file, "utf8").split("\n");
    lines[0] = lines[0].replace(N("0.25").toString(), N("0.01").toString());
    fs.writeFileSync(l.file, lines.join("\n"));
    const snap = l.read();
    assert.equal(snap.integrity.ok, false);
    assert.match((snap.integrity as { problem: string }).problem, /hash chain broken at line 2/);
    assert.throws(() => intent(l, "c", "0.1"), /ledger integrity/);
  });

  it("detects a deleted record", () => {
    const l = new Ledger(tmpDir());
    intent(l, "a", "0.1");
    intent(l, "b", "0.1");
    intent(l, "c", "0.1");
    const lines = fs.readFileSync(l.file, "utf8").split("\n").filter(Boolean);
    fs.writeFileSync(l.file, [lines[0], lines[2]].join("\n") + "\n");
    assert.equal(l.read().integrity.ok, false);
  });

  it("serializes withLock callers inside one process", async () => {
    const l = new Ledger(tmpDir());
    const order: string[] = [];
    const slow = (name: string, ms: number) =>
      l.withLock(async () => {
        order.push(`${name}:start`);
        await new Promise((r) => setTimeout(r, ms));
        order.push(`${name}:end`);
      });
    await Promise.all([slow("a", 30), slow("b", 1), slow("c", 1)]);
    assert.deepEqual(order, ["a:start", "a:end", "b:start", "b:end", "c:start", "c:end"]);
  });

  it("a failing callback releases the lock", async () => {
    const l = new Ledger(tmpDir());
    await assert.rejects(l.withLock(async () => { throw new Error("boom"); }), /boom/);
    assert.equal(await l.withLock(async () => 42), 42);
  });

  it("takes over a stale lock of a dead process and waits for a live one", async () => {
    const dir = tmpDir();
    const l = new Ledger(dir);
    const dead = spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"]).stdout.toString();
    fs.writeFileSync(path.join(dir, "ledger.lock"), dead);
    assert.equal(await l.withLock(async () => "ok", 2_000), "ok");
    // a live holder (this test process's parent) blocks until the timeout
    fs.writeFileSync(path.join(dir, "ledger.lock"), String(process.ppid));
    await assert.rejects(l.withLock(async () => "never", 300), LedgerBusyError);
    fs.unlinkSync(path.join(dir, "ledger.lock"));
  });
});
