// Verifier worker (v2): for each program it serves, list_pending(program_id) -> unseal ->
// commitment v2 check -> engine -> evidence.json envelope -> post_verdict.
// All chain and engine access goes through WorkerDeps so the decision logic is testable offline.

import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { EVIDENCE_FILE, ORIGINAL_STATUSES, envelopeBytes, evidenceUri, makeEnvelope, sha256Hex, statusAfterVerdict } from "./evidence.ts";
import {
  COMMITMENT_MISMATCH_REASON,
  EXIT,
  actionForExit,
  buildVerdict,
  commitmentMismatchVerdict,
  escalateToHuman,
} from "./mapping.ts";
import type { EngineVerdict, VerdictInput } from "./mapping.ts";
import { openAndCheck } from "./seal.ts";

export { sha256Hex } from "./evidence.ts";

export interface SubmissionView {
  id: number;
  program_id: number;
  hunter_id: string;
  title: string;
  commitment: string;
  bond: string;
  status: string;
  submitted_at?: string;
  submitted_block?: string;
  verdict?: { outcome?: string; duplicate_of?: number | null } | null;
  payout?: string;
  funded_by_vault?: boolean;
}

export interface ProgramView {
  id: number;
  name: string;
  verifier_id: string;
  active?: boolean;
  scope?: { chain_id: number; address: string }[];
}

export interface EngineRunArgs {
  reportPath: string;
  registryPath: string;
  /** JSON {"sub-<id>": on-chain status} of the program's submissions (engine --onchain-status). */
  statusPath?: string | null;
  reportId: string;
  destDir: string;
  /** Engine --scope: <chain_id>:<address>,... from the program. Absent: the program names no scope. */
  scope?: string | null;
  /** Engine --min-block: the operator's first accepted fork block. */
  minBlock?: number | null;
}

export interface EngineRunResult {
  exitCode: number | null;
  command: string[];
  durationMs: number;
}

export interface WorkerDeps {
  /** Every program on the contract (all pages). Used when no allow-list is configured. */
  listPrograms(): Promise<ProgramView[]>;
  getProgram(id: number): Promise<ProgramView | null>;
  /** list_pending(program_id, …), all pages. */
  listPending(programId: number): Promise<SubmissionView[]>;
  /** list_submissions(program_id, …), all pages: on-chain statuses for the duplicate registry. */
  listSubmissions(programId: number): Promise<SubmissionView[]>;
  getSubmission(id: number): Promise<SubmissionView | null>;
  getSealed(id: number): Promise<string | null>;
  postVerdict(id: number, verdict: VerdictInput): Promise<string>; // returns the tx hash
  runEngine(args: EngineRunArgs): Promise<EngineRunResult>;
  log(line: string): void;
}

/** after-settlement (default): evidence of a submission stays in runs-private/ until it is final and
 *  `publish` moves it to runs/. immediately: straight into runs/ (demos of historical incidents). */
export type Disclosure = "after-settlement" | "immediately";
export const DISCLOSURE_MODES: readonly Disclosure[] = ["after-settlement", "immediately"];

export interface WorkerContext {
  network: string;
  contractId: string;
  verifierId: string;
  x25519PrivateKey: string; // base64 raw 32 bytes
  repoRoot: string; // evidence_uri is relative to this
  runsRoot: string; // public evidence: <repo>/runs/<network>/<contract>
  privateRoot: string; // private evidence and worker state: <repo>/runs-private/<network>/<contract>
  disclose: Disclosure;
  /** Allow-list of program ids; null = every program whose verifier_id is this verifier. */
  programs: number[] | null;
  /** Reports forking from an older block are invalid; a program's first accepted block. */
  minForkBlock?: number | null;
}

export type WorkerResult =
  | { id: number; action: "posted"; verdict: VerdictInput; txHash: string; engineExit: number | null }
  | { id: number; action: "retry"; why: string; engineExit: number | null }
  | { id: number; action: "deferred"; why: string }
  | { id: number; action: "skipped"; why: string };

/** Where the worker writes a submission's files (and its registry) in this disclosure mode. */
export function workRoot(ctx: WorkerContext): string {
  return ctx.disclose === "immediately" ? ctx.runsRoot : ctx.privateRoot;
}

function writeJson(file: string, data: unknown): Buffer {
  const bytes = Buffer.from(JSON.stringify(data, null, 2) + "\n", "utf8");
  fs.writeFileSync(file, bytes);
  return bytes;
}

function appendLog(ctx: WorkerContext, entry: Record<string, unknown>) {
  const root = workRoot(ctx);
  fs.mkdirSync(root, { recursive: true });
  fs.appendFileSync(path.join(root, "worker.log.jsonl"), JSON.stringify({ at: new Date().toISOString(), ...entry }) + "\n");
}

/** Write the envelope next to the engine files; returns its sha256 (the on-chain evidence_sha256). */
function writeEvidence(ctx: WorkerContext, sub: SubmissionView, dir: string, engine: unknown): string {
  const env = makeEnvelope({
    network: ctx.network,
    contract_id: ctx.contractId,
    program_id: Number(sub.program_id),
    submission_id: Number(sub.id),
    hunter_id: String(sub.hunter_id ?? ""),
    commitment: String(sub.commitment ?? ""),
  }, engine);
  const bytes = envelopeBytes(env);
  fs.writeFileSync(path.join(dir, EVIDENCE_FILE), bytes);
  return sha256Hex(bytes);
}

/** A duplicate must point to an earlier submission of the same program that is valid, paid or
 *  disputed on-chain (SPEC v2). If the original changed since the engine ran (the owner overruled
 *  it, …), the contract would refuse the verdict and the program's queue would stall: a human decides. */
async function checkOriginal(deps: WorkerDeps, sub: SubmissionView, verdict: VerdictInput): Promise<VerdictInput> {
  if (verdict.outcome !== "duplicate" || verdict.duplicate_of === null) return verdict;
  const orig = await deps.getSubmission(verdict.duplicate_of);
  if (orig && Number(orig.program_id) === Number(sub.program_id) && ORIGINAL_STATUSES.includes(orig.status)) return verdict;
  const state = !orig ? "not found" : Number(orig.program_id) !== Number(sub.program_id) ? `in program ${orig.program_id}` : `'${orig.status}'`;
  return escalateToHuman(verdict, `engine reports a duplicate of submission ${verdict.duplicate_of}, which is ${state} on-chain; ` +
    "only a valid, paid or disputed report of the same program can be the original; a human must decide");
}

/** Judge one pending submission. Posts at most one verdict. */
export async function processSubmission(
  ctx: WorkerContext,
  deps: WorkerDeps,
  sub: SubmissionView,
  statusPath: string | null = null,
  scope: string | null = null,
): Promise<WorkerResult> {
  const id = Number(sub.id);
  const dir = path.join(workRoot(ctx), String(id));
  fs.mkdirSync(dir, { recursive: true });
  const verdictPath = path.join(dir, "verdict.json");
  const uri = evidenceUri(ctx.network, ctx.contractId, id);

  const sealed = await deps.getSealed(id);
  if (sealed === null || sealed === undefined) {
    return { id, action: "retry", why: "get_sealed returned nothing", engineExit: null };
  }
  fs.writeFileSync(path.join(dir, "sealed.b64"), sealed);
  fs.rmSync(path.join(dir, EVIDENCE_FILE), { force: true }); // never post stale evidence of an earlier attempt

  let verdict: VerdictInput;
  let engineExit: number | null = null;
  // Commitment v2: recomputed with the account that submitted. A blob and commitment copied from
  // someone else's transaction do not match when they come from another account.
  const hunterId = typeof sub.hunter_id === "string" ? sub.hunter_id : "";
  const opened = hunterId
    ? openAndCheck(sealed, ctx.x25519PrivateKey, sub.commitment, hunterId)
    : { ok: false as const, error: "the submission names no hunter account" };
  if (!opened.ok) {
    const worker = {
      schema: "replaycourt.worker-verdict/v1",
      submission_id: id,
      outcome: "invalid",
      reason: COMMITMENT_MISMATCH_REASON,
      detail: opened.error,
      commitment: sub.commitment,
      hunter_id: hunterId,
      checked_at: new Date().toISOString(),
    };
    writeJson(verdictPath, worker);
    verdict = commitmentMismatchVerdict(writeEvidence(ctx, sub, dir, worker), uri);
    deps.log(`#${id}: ${COMMITMENT_MISMATCH_REASON} (${opened.error})`);
  } else {
    const reportPath = path.join(dir, "report.md");
    fs.writeFileSync(reportPath, opened.plaintext);
    fs.rmSync(verdictPath, { force: true });
    const registryPath = path.join(workRoot(ctx), "registry", `program-${sub.program_id}.jsonl`);
    fs.mkdirSync(path.dirname(registryPath), { recursive: true });
    deps.log(`#${id}: commitment ok, running the engine (program ${sub.program_id}) …`);
    const run = await deps.runEngine({ reportPath, registryPath, statusPath, reportId: `sub-${id}`, destDir: dir, scope, minBlock: ctx.minForkBlock ?? null });
    engineExit = run.exitCode;
    const action = actionForExit(run.exitCode);
    if (action.kind === "retry") {
      appendLog(ctx, { submission_id: id, action: "retry", engine_exit: run.exitCode, why: action.why });
      deps.log(`#${id}: no verdict posted - ${action.why}; will retry`);
      return { id, action: "retry", why: action.why, engineExit };
    }
    let engine: EngineVerdict | Record<string, unknown>;
    let parsed: EngineVerdict | null = null;
    if (fs.existsSync(verdictPath)) {
      try {
        parsed = JSON.parse(fs.readFileSync(verdictPath, "utf8")) as EngineVerdict;
      } catch {
        return { id, action: "retry", why: "engine wrote an unreadable verdict.json", engineExit };
      }
      engine = parsed;
    } else if (run.exitCode === EXIT.wrapperTimeout || run.exitCode === EXIT.wrapperMemory) {
      engine = {
        schema: "replaycourt.worker-verdict/v1",
        submission_id: id,
        outcome: "needs_human",
        reason: run.exitCode === EXIT.wrapperTimeout ? "engine time limit exceeded" : "engine memory limit exceeded",
        engine_exit: run.exitCode,
        checked_at: new Date().toISOString(),
      };
      writeJson(verdictPath, engine);
    } else {
      return { id, action: "retry", why: `engine exit ${String(run.exitCode)} but no verdict.json`, engineExit };
    }
    const evidenceSha256 = writeEvidence(ctx, sub, dir, engine);
    verdict = buildVerdict({ submissionId: id, exitCode: run.exitCode as number, verdict: parsed, evidenceSha256, evidenceUri: uri },
      action.outcome);
    verdict = await checkOriginal(deps, sub, verdict);
  }

  const current = await deps.getSubmission(id);
  if (!current || current.status !== "pending") {
    deps.log(`#${id}: status is ${current?.status ?? "unknown"} now - nothing posted`);
    return { id, action: "skipped", why: `status ${current?.status ?? "unknown"}` };
  }
  const txHash = await deps.postVerdict(id, verdict);
  writeJson(path.join(dir, "worker.json"), {
    submission_id: id,
    program_id: sub.program_id,
    hunter_id: sub.hunter_id,
    engine_exit: engineExit,
    disclose: ctx.disclose,
    posted: verdict,
    tx_hash: txHash,
    posted_at: new Date().toISOString(),
  });
  appendLog(ctx, { submission_id: id, action: "posted", outcome: verdict.outcome, tx_hash: txHash, engine_exit: engineExit });
  deps.log(`#${id}: posted ${verdict.outcome}${verdict.severity ? " (" + verdict.severity + ")" : ""}` +
    `${verdict.duplicate_of !== null ? " of #" + verdict.duplicate_of : ""} - tx ${txHash}`);
  return { id, action: "posted", verdict, txHash, engineExit };
}

/** The programs this worker serves, ascending: the allow-list (each must name this verifier), or
 *  every program whose verifier_id is this verifier. */
export async function servedPrograms(ctx: WorkerContext, deps: WorkerDeps): Promise<ProgramView[]> {
  const out: ProgramView[] = [];
  if (ctx.programs) {
    for (const id of [...new Set(ctx.programs)].sort((a, b) => a - b)) {
      const p = await deps.getProgram(id);
      if (!p) deps.log(`program ${id} (allow-list): not found on ${ctx.contractId} - skipped`);
      else if (p.verifier_id !== ctx.verifierId) deps.log(`program ${id} (allow-list): its verifier is ${p.verifier_id}, not ${ctx.verifierId} - skipped`);
      else out.push(p);
    }
    return out;
  }
  return (await deps.listPrograms()).filter((p) => p.verifier_id === ctx.verifierId).sort((a, b) => Number(a.id) - Number(b.id));
}

/** A program's on-chain scope as the engine's --scope value; null when it names none. */
export function scopeArg(program: ProgramView): string | null {
  const targets = program.scope ?? [];
  return targets.length ? targets.map((t) => `${Number(t.chain_id)}:${t.address}`).join(",") : null;
}

/** On-chain statuses of a program's submissions as the engine's --onchain-status file. */
async function loadStatuses(ctx: WorkerContext, deps: WorkerDeps, programId: number): Promise<Record<string, string> | null> {
  try {
    const subs = await deps.listSubmissions(programId);
    return Object.fromEntries(subs.map((s) => [`sub-${Number(s.id)}`, String(s.status)]));
  } catch (err) {
    deps.log(`program ${programId}: cannot read on-chain statuses (${(err as Error).message}); the engine uses its own verdicts`);
    return null;
  }
}

function writeStatuses(ctx: WorkerContext, programId: number, statuses: Record<string, string> | null): string | null {
  if (!statuses) return null;
  const file = path.join(workRoot(ctx), "registry", `program-${programId}.status.json`);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  writeJson(file, statuses);
  return file;
}

/** One pass over the pending submissions of every served program, oldest first per program.
 *  If a submission must be retried (engine exit 69/70/...), the later submissions of the same
 *  program wait too, so that duplicates keep being judged in on-chain commit order. */
export async function processPending(ctx: WorkerContext, deps: WorkerDeps): Promise<WorkerResult[]> {
  const results: WorkerResult[] = [];
  for (const program of await servedPrograms(ctx, deps)) {
    const pid = Number(program.id);
    const pending = [...(await deps.listPending(pid))]
      .filter((s) => Number(s.program_id) === pid)
      .sort((a, b) => Number(a.id) - Number(b.id));
    if (pending.length === 0) continue;
    const scope = scopeArg(program);
    if (!scope) deps.log(`program ${pid} names no scope: reports against any contract can be judged valid`);
    const statuses = await loadStatuses(ctx, deps, pid);
    let blocked = false;
    for (const sub of pending) {
      if (blocked) {
        results.push({ id: Number(sub.id), action: "deferred", why: "an earlier submission of this program waits for a retry" });
        continue;
      }
      let r: WorkerResult;
      try {
        r = await processSubmission(ctx, deps, sub, writeStatuses(ctx, pid, statuses), scope);
      } catch (err) {
        const why = `error: ${(err as Error).message}`;
        deps.log(`#${sub.id}: ${why}; will retry`);
        appendLog(ctx, { submission_id: Number(sub.id), action: "retry", why });
        r = { id: Number(sub.id), action: "retry", why, engineExit: null };
      }
      // The next report of this round must see this verdict as on-chain state (a valid report is
      // an original from now on).
      if (r.action === "posted" && statuses) statuses[`sub-${r.id}`] = statusAfterVerdict(r.verdict.outcome);
      if (r.action === "retry") blocked = true;
      results.push(r);
    }
  }
  return results;
}

// ------------------------------------------------------------------ real engine runner

/** Re-run the engine after exit 69 (flaky free archive RPCs) up to `retries` times within a round. */
export function withInfraRetries(
  run: (a: EngineRunArgs) => Promise<EngineRunResult>,
  retries: number,
  delayMs: number,
  log: (line: string) => void,
): (a: EngineRunArgs) => Promise<EngineRunResult> {
  return async (a) => {
    let res = await run(a);
    for (let i = 1; i <= retries && res.exitCode === EXIT.unavailable; i++) {
      log(`${a.reportId}: engine exit 69 (infrastructure), retry ${i}/${retries} in ${Math.round(delayMs / 1000)} s`);
      await new Promise((r) => setTimeout(r, delayMs));
      res = await run(a);
    }
    return res;
  };
}

export interface EngineRunnerOptions {
  repoRoot: string;
  python?: string;
  /** Command prefix for every engine run (e.g. a memory/time cap); default REPLAYCOURT_ENGINE_WRAPPER, else none. */
  wrapper?: string[] | null;
  /** Hard time limit for the whole process group, "30m", "90s", "1h" (default 30m). */
  timeout?: string;
}

/** REPLAYCOURT_ENGINE_WRAPPER: a command prefix split at whitespace (no shell quoting); empty = none. */
export function parseWrapper(value: string | undefined): string[] | null {
  const parts = (value ?? "").trim().split(/\s+/).filter(Boolean);
  return parts.length ? parts : null;
}

export function parseDuration(s: string): number {
  const m = /^(\d+(?:\.\d+)?)([smh]?)$/.exec(s.trim());
  if (!m) return 1800;
  return Number(m[1]) * ({ s: 1, m: 60, h: 3600, "": 1 } as Record<string, number>)[m[2]];
}

/** The engine command line (without a wrapper). */
export function engineCommand(python: string, repoRoot: string, a: EngineRunArgs): string[] {
  return [python, "-I", path.join(repoRoot, "engine", "replay.py"), "check", a.reportPath,
    "--quiet", "--registry", a.registryPath, "--report-id", a.reportId, "--dest", a.destDir,
    ...(a.statusPath ? ["--onchain-status", a.statusPath] : []),
    ...(a.scope ? ["--scope", a.scope] : []),
    ...(a.minBlock !== null && a.minBlock !== undefined ? ["--min-block", String(a.minBlock)] : [])];
}

const running = new Set<ChildProcess>();
let cleanupInstalled = false;

/** Kill every engine run that is still going (its whole process group). */
export function killEngineRuns() {
  for (const child of running) {
    try { process.kill(-(child.pid as number), "SIGKILL"); } catch { /* already gone */ }
  }
  running.clear();
}

/** Runs `[wrapper…] python3 -I engine/replay.py check …` in its own process group, with TZ=UTC
 *  and a hard time limit for the whole group (exit 124, as timeout(1)). */
export function makeEngineRunner(opts: EngineRunnerOptions): (a: EngineRunArgs) => Promise<EngineRunResult> {
  const python = opts.python ?? process.env.REPLAYCOURT_PYTHON ?? "python3";
  const wrapper = opts.wrapper === undefined ? parseWrapper(process.env.REPLAYCOURT_ENGINE_WRAPPER) : opts.wrapper;
  // With a wrapper, the worker's own limit comes 2 minutes later, so a time limit of the wrapper
  // (a memory/time cap, timeout(1), …) ends the run first and reports its own exit code.
  const limitS = parseDuration(opts.timeout ?? "30m") + (wrapper ? 120 : 0);
  if (!cleanupInstalled) {
    cleanupInstalled = true;
    process.on("exit", killEngineRuns); // no engine run outlives the worker
  }
  return (a) =>
    new Promise((resolve) => {
      const command = [...(wrapper ?? []), ...engineCommand(python, opts.repoRoot, a)];
      const started = Date.now();
      const out = fs.openSync(path.join(a.destDir, "engine.stdout.txt"), "w");
      const err = fs.openSync(path.join(a.destDir, "engine.stderr.txt"), "w");
      const child = spawn(command[0], command.slice(1), {
        cwd: opts.repoRoot,
        stdio: ["ignore", out, err],
        detached: true, // own process group, so the time limit ends everything it started
        env: { ...process.env, TZ: "UTC" },
      });
      running.add(child);
      let timedOut = false;
      let done = false;
      const timer = setTimeout(() => {
        timedOut = true;
        try { process.kill(-(child.pid as number), "SIGTERM"); } catch { /* already gone */ }
        setTimeout(() => { try { process.kill(-(child.pid as number), "SIGKILL"); } catch { /* gone */ } }, 5000).unref();
      }, limitS * 1000);
      const finish = (code: number | null) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        running.delete(child);
        fs.closeSync(out);
        fs.closeSync(err);
        resolve({ exitCode: code, command, durationMs: Date.now() - started });
      };
      child.on("error", () => finish(null));
      child.on("exit", (code) => finish(timedOut ? EXIT.wrapperTimeout : code));
    });
}
