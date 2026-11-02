// Append-only spending ledger (JSON Lines) in the state directory, so the limits survive restarts.
//
// Protocol for every signing tool:
//   1. under the lock, read the ledger and ask the policy;
//   2. append an "intent" record and fsync it BEFORE the transaction is signed;
//   3. sign and send;
//   4. append an "outcome" record (ok / failed_onchain / not_executed / unknown).
// A deposit counts against the limits unless its outcome proves it never left the account
// (failed_onchain: the protocol refunds the attached deposit of a failed function call;
// not_executed: the RPC rejected the transaction). An intent without an outcome (crash, timeout)
// counts: the ledger errs on the side of "spent".
//
// Each record carries `prev`, the sha256 of the previous line. A line edited or removed in the
// middle breaks the chain and the server refuses to sign until a human looks at it. This detects
// careless edits; it is not a defence against someone who can rewrite the whole file (see the
// threat model in README.md: the hard cap is the hunter account's balance).

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { u128 } from "./amounts.ts";
import type { SpendHistory, SpendOp } from "./policy.ts";

export const LEDGER_FILE = "ledger.jsonl";
const LOCK_FILE = "ledger.lock";
const GENESIS = "0".repeat(64);

export type OutcomeStatus = "ok" | "failed_onchain" | "not_executed" | "unknown";

interface Base {
  v: 1;
  seq: number;
  ts: string;
  prev: string;
}

export interface IntentRecord extends Base {
  type: "intent";
  op: SpendOp;
  op_id: string;
  network: string;
  contract_id: string;
  account_id: string;
  program_id: number;
  submission_id: number | null;
  deposit_yocto: string;
  bond_yocto: string;
  storage_yocto: string;
  commitment: string | null;
  /** v2: where the deposit comes from: attached by the account, or drawn from the on-chain vault
   *  (submit_report_from_vault). Absent in records written before vault mode. Either way it
   *  counts against the policy's caps. */
  funding?: "deposit" | "vault";
}

export interface OutcomeRecord extends Base {
  type: "outcome";
  op_id: string;
  status: OutcomeStatus;
  tx_hash: string | null;
  submission_id: number | null;
  error: string | null;
}

export interface RefusalRecord extends Base {
  type: "refusal";
  op: SpendOp;
  program_id: number | null;
  rule: string;
  /** The guard that refused ("policy" when absent, as in records written before vault mode). */
  refused_by?: "policy" | "vault_policy";
}

export type LedgerRecord = IntentRecord | OutcomeRecord | RefusalRecord;

type NewRecord =
  | Omit<IntentRecord, keyof Base>
  | Omit<OutcomeRecord, keyof Base>
  | Omit<RefusalRecord, keyof Base>;

export interface LedgerSnapshot {
  records: LedgerRecord[];
  integrity: { ok: true } | { ok: false; problem: string };
}

export class LedgerBusyError extends Error {}

const sha256 = (s: string) => crypto.createHash("sha256").update(s, "utf8").digest("hex");

export class Ledger {
  readonly dir: string;
  readonly file: string;
  private readonly lockFile: string;
  private readonly clock: () => number;
  private chain: Promise<unknown> = Promise.resolve();

  constructor(dir: string, opts: { clock?: () => number } = {}) {
    this.dir = path.resolve(dir);
    this.file = path.join(this.dir, LEDGER_FILE);
    this.lockFile = path.join(this.dir, LOCK_FILE);
    this.clock = opts.clock ?? Date.now;
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    if (!fs.existsSync(this.file)) fs.writeFileSync(this.file, "", { mode: 0o600 });
  }

  /** Read and verify the whole ledger. A torn last line (crash during a write) is cut off. */
  read(): LedgerSnapshot {
    let text = fs.readFileSync(this.file, "utf8");
    if (text.length && !text.endsWith("\n")) {
      // An incomplete write: the record was never fsynced, so nothing was signed after it.
      const keep = text.lastIndexOf("\n") + 1;
      fs.truncateSync(this.file, Buffer.byteLength(text.slice(0, keep), "utf8"));
      text = text.slice(0, keep);
    }
    const records: LedgerRecord[] = [];
    let prev = GENESIS;
    let seq = 0;
    const lines = text.split("\n").filter((l) => l.length > 0);
    for (let i = 0; i < lines.length; i++) {
      let rec: LedgerRecord;
      try {
        rec = JSON.parse(lines[i]) as LedgerRecord;
      } catch {
        return { records, integrity: { ok: false, problem: `line ${i + 1} is not valid JSON` } };
      }
      if (rec.prev !== prev) return { records, integrity: { ok: false, problem: `hash chain broken at line ${i + 1}` } };
      if (rec.seq !== seq + 1) return { records, integrity: { ok: false, problem: `sequence gap at line ${i + 1}` } };
      records.push(rec);
      prev = sha256(lines[i]);
      seq = rec.seq;
    }
    return { records, integrity: { ok: true } };
  }

  /** Append one record and fsync. Call only while holding the lock (withLock). */
  append(rec: NewRecord): LedgerRecord {
    const snap = this.read();
    if (!snap.integrity.ok) throw new Error(`ledger integrity: ${snap.integrity.problem}`);
    const text = fs.readFileSync(this.file, "utf8");
    const lines = text.split("\n").filter((l) => l.length > 0);
    const full = {
      v: 1,
      seq: snap.records.length ? snap.records[snap.records.length - 1].seq + 1 : 1,
      ts: new Date(this.clock()).toISOString(),
      prev: lines.length ? sha256(lines[lines.length - 1]) : GENESIS,
      ...rec,
    } as LedgerRecord;
    const fd = fs.openSync(this.file, "a", 0o600);
    try {
      fs.writeSync(fd, JSON.stringify(full) + "\n");
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    return full;
  }

  /**
   * Run fn exclusively: one at a time inside this process (promise chain) and across processes
   * sharing the state directory (lock file with the owner's pid; a lock of a dead pid is stale).
   */
  withLock<T>(fn: () => Promise<T>, timeoutMs = 60_000): Promise<T> {
    const run = async () => {
      await this.acquire(timeoutMs);
      try {
        return await fn();
      } finally {
        this.release();
      }
    };
    const next = this.chain.then(run, run);
    this.chain = next.catch(() => undefined);
    return next;
  }

  private async acquire(timeoutMs: number): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      try {
        const fd = fs.openSync(this.lockFile, "wx", 0o600);
        fs.writeSync(fd, String(process.pid));
        fs.closeSync(fd);
        return;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      }
      let holder = NaN;
      let ageMs = 0;
      try {
        holder = Number(fs.readFileSync(this.lockFile, "utf8").trim() || "0");
        ageMs = Date.now() - fs.statSync(this.lockFile).mtimeMs;
      } catch {
        // removed in between: retry at once
        continue;
      }
      // An empty lock file is one another process is still writing its pid into.
      const beingWritten = holder === 0 && ageMs < 5_000;
      if (!beingWritten && (!Number.isInteger(holder) || holder <= 0 || !pidAlive(holder))) {
        try {
          fs.unlinkSync(this.lockFile);
        } catch {
          // someone else removed it
        }
        continue;
      }
      if (Date.now() > deadline) throw new LedgerBusyError(`the ledger is locked by another replaycourt-mcp process (pid ${holder})`);
      await new Promise((r) => setTimeout(r, 200));
    }
  }

  private release(): void {
    try {
      if (fs.readFileSync(this.lockFile, "utf8").trim() === String(process.pid)) fs.unlinkSync(this.lockFile);
    } catch {
      // already gone
    }
  }
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

// ---------------------------------------------------------------------------------------------
// Derived views

export interface OpState {
  intent: IntentRecord;
  outcome: OutcomeRecord | null;
}

export function operations(records: LedgerRecord[]): OpState[] {
  const ops = new Map<string, OpState>();
  for (const r of records) {
    if (r.type === "intent") ops.set(r.op_id, { intent: r, outcome: null });
    else if (r.type === "outcome") {
      const o = ops.get(r.op_id);
      if (o) o.outcome = r;
    }
  }
  return [...ops.values()];
}

/** Does this operation's deposit count against the limits? */
export function depositCounts(op: OpState): boolean {
  const s = op.outcome?.status;
  return !(s === "failed_onchain" || s === "not_executed");
}

/** The history the policy needs. */
export function spendHistory(records: LedgerRecord[]): SpendHistory {
  const h: SpendHistory = { deposits: [], reportAttempts: [] };
  for (const op of operations(records)) {
    const at = Date.parse(op.intent.ts);
    if (op.intent.op === "submit_report") h.reportAttempts.push(at);
    const dep = u128(op.intent.deposit_yocto) ?? 0n;
    if (dep > 0n && depositCounts(op)) h.deposits.push({ at, amount: dep });
  }
  return h;
}

/** Submission ids this server created (from successful submit_report outcomes). */
export function knownSubmissionIds(records: LedgerRecord[]): number[] {
  const ids = new Set<number>();
  for (const op of operations(records)) {
    if (op.intent.op === "submit_report" && op.outcome?.status === "ok" && op.outcome.submission_id !== null) {
      ids.add(op.outcome.submission_id);
    }
  }
  return [...ids].sort((a, b) => a - b);
}

/** Was this commitment already sent (and not proven to have failed)? */
export function commitmentUsed(records: LedgerRecord[], commitment: string): boolean {
  return operations(records).some(
    (op) => op.intent.op === "submit_report" && op.intent.commitment === commitment && depositCounts(op),
  );
}
