// verify-onchain: for every submission, read the on-chain verdict, load the evidence file named by
// evidence_uri (only below runs/), recompute its sha256, compare it with the on-chain
// evidence_sha256 and check that the evidence envelope is bound to this submission (SPEC v2
// "Evidence"). Read-only, needs no keys. The chain access is injected (`view`), so tests run with
// the RPC mocked.
//
// Evidence modes:
//   v2 (replaycourt.evidence/v1 envelope): hash + contract_id, program_id, submission_id, hunter_id,
//     commitment and network must equal the on-chain submission.
//   v1 (verdict.json without an envelope): hash only. Accepted only from contracts older than v2
//     (version() < 2), e.g. the v1 showcase; a v2 contract must post envelopes.

import fs from "node:fs";
import path from "node:path";
import { BINDING_FIELDS, EVIDENCE_SCHEMA, isFinal, resolveRunsPath, sha256Hex } from "./evidence.ts";
import { DISCLOSURE_FILE, DISCLOSURE_SCHEMA } from "./disclosure.ts";
import { fmtNear } from "./near.ts";

export { sha256Hex } from "./evidence.ts";

export type EvidenceState =
  | "ok" // hash matches and (v2) the envelope is bound to the submission
  | "mismatch" // the file's sha256 differs from the on-chain evidence_sha256
  | "unbound" // the hash matches, but the envelope names another submission, or a v2 contract posted no envelope
  | "refused" // evidence_uri is not a path below runs/
  | "missing" // the file is not there, and it should be (the submission is final)
  | "undisclosed" // the file is not there yet: the submission (or a related one) is not final
  | "no-verdict";

export interface OnchainVerdict {
  outcome: string;
  severity: string | null;
  duplicate_of: number | null;
  evidence_sha256: string;
  evidence_uri: string;
}

export interface OnchainSubmission {
  id: number;
  program_id: number;
  hunter_id: string;
  title: string;
  commitment?: string;
  status: string;
  payout: string;
  verdict: OnchainVerdict | null;
  resolution: { outcome: string; severity: string | null } | null;
}

export interface OnchainProgram {
  id: number;
  name: string;
}

export type EvidenceRead = { ok: true; bytes: Uint8Array; source: string } | { ok: false; error: string; source?: string; notFound?: boolean };
export type EvidenceReader = (uri: string) => Promise<EvidenceRead>;
export type ViewFn = <T>(method: string, args: Record<string, unknown>) => Promise<T>;

export interface VerifyRow {
  id: number;
  programId: number;
  status: string;
  outcome: string;
  severity: string;
  payout: string; // yoctoNEAR
  evidence: EvidenceState;
  mode: "v2" | "v1" | null; // which evidence rule was applied
  detail: string;
  uri: string | null;
  expected: string | null; // on-chain evidence_sha256
  actual: string | null; // sha256 of the file
}

export interface CheckContext {
  network: string;
  contractId: string;
  /** Major version of the contract (version()); v1 evidence is accepted only below 2. */
  contractMajor: number;
  /** Final submissions held back by `publish` -> the ids they wait for (runs/<net>/<contract>/disclosure.json). */
  held: Map<number, number[]>;
  /** On-chain status by submission id, for "waits for" checks. */
  statusOf: (id: number) => Promise<string | null>;
}

/** Evidence reader: paths below <repoRoot>/runs/ only (also after resolving symlinks). */
export function makeEvidenceReader(repoRoot: string): EvidenceReader {
  return async (uri) => {
    const file = resolveRunsPath(repoRoot, uri);
    if (!file) return { ok: false, error: "evidence_uri is not a path below runs/" };
    const source = path.relative(repoRoot, file).split(path.sep).join("/");
    try {
      const real = fs.realpathSync(file);
      const runsReal = fs.realpathSync(path.join(repoRoot, "runs"));
      if (!(real + path.sep).startsWith(runsReal + path.sep)) return { ok: false, error: "evidence file leaves runs/ (symlink)", source };
      return { ok: true, bytes: fs.readFileSync(real), source };
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      return code === "ENOENT"
        ? { ok: false, error: "file not found", source, notFound: true }
        : { ok: false, error: `cannot read: ${(e as Error).message}`, source };
    }
  };
}

function outcomeLabel(s: OnchainSubmission): string {
  const v = s.verdict;
  if (!v) return "-";
  let label = v.outcome === "duplicate" && v.duplicate_of !== null && v.duplicate_of !== undefined ? `duplicate of #${v.duplicate_of}` : v.outcome;
  if (s.resolution) label += ` -> ${s.resolution.outcome} (owner)`;
  return label;
}

function severityLabel(s: OnchainSubmission): string {
  if (s.verdict?.severity) return s.verdict.severity;
  if (s.resolution?.severity) return `${s.resolution.severity} (owner)`;
  return "-";
}

/** Compare the envelope's binding fields with the on-chain submission; returns the differences. */
export function bindingErrors(env: Record<string, unknown>, s: OnchainSubmission, ctx: Pick<CheckContext, "network" | "contractId">): string[] {
  const want: Record<(typeof BINDING_FIELDS)[number], unknown> = {
    network: ctx.network,
    contract_id: ctx.contractId,
    program_id: Number(s.program_id),
    submission_id: Number(s.id),
    hunter_id: s.hunter_id,
    commitment: s.commitment,
  };
  const errs: string[] = [];
  for (const f of BINDING_FIELDS) {
    if (env[f] !== want[f]) errs.push(`${f} ${JSON.stringify(env[f])} != on-chain ${JSON.stringify(want[f])}`);
  }
  return errs;
}

/** Why evidence that is not there yet is fine (not final, or held back by publish), or null. */
async function undisclosedReason(s: OnchainSubmission, ctx: CheckContext): Promise<string | null> {
  if (!isFinal(s.status)) return `not disclosed yet: the submission is ${s.status}, not final`;
  const waits = ctx.held.get(Number(s.id));
  if (!waits) return null;
  const open: string[] = [];
  for (const w of waits) {
    const st = await ctx.statusOf(w);
    if (st && !isFinal(st)) open.push(`#${w} (${st})`);
  }
  return open.length ? `held back: related to ${open.join(", ")}, which is not final yet` : null;
}

/** Check one submission's evidence: hash, place (below runs/) and binding. */
export async function checkSubmission(s: OnchainSubmission, read: EvidenceReader, ctx: CheckContext): Promise<VerifyRow> {
  const row: VerifyRow = {
    id: s.id,
    programId: s.program_id,
    status: s.status,
    outcome: outcomeLabel(s),
    severity: severityLabel(s),
    payout: String(s.payout ?? "0"),
    evidence: "no-verdict",
    mode: null,
    detail: "no verdict posted yet",
    uri: null,
    expected: null,
    actual: null,
  };
  const v = s.verdict;
  if (!v) return row;
  row.uri = v.evidence_uri || null;
  row.expected = typeof v.evidence_sha256 === "string" ? v.evidence_sha256 : null;
  if (!v.evidence_uri) return { ...row, evidence: "missing", detail: "the verdict has no evidence_uri" };
  const r = await read(v.evidence_uri);
  if (!r.ok) {
    if (!r.source) return { ...row, evidence: "refused", detail: `${r.error} (${v.evidence_uri})` };
    if (r.notFound) {
      const why = await undisclosedReason(s, ctx);
      if (why) return { ...row, evidence: "undisclosed", detail: `${why} (${r.source})` };
    }
    return { ...row, evidence: "missing", detail: `${r.error} (${r.source})` };
  }
  row.actual = sha256Hex(r.bytes);
  const expected = (row.expected ?? "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expected)) {
    return { ...row, evidence: "mismatch", detail: `on-chain evidence_sha256 is not 64 hex characters (${r.source})` };
  }
  if (row.actual !== expected) {
    return { ...row, evidence: "mismatch", detail: `on-chain ${expected}, file ${row.actual} (${r.source})` };
  }
  let doc: unknown = null;
  try {
    doc = JSON.parse(Buffer.from(r.bytes).toString("utf8"));
  } catch {
    doc = null;
  }
  const env = doc && typeof doc === "object" && !Array.isArray(doc) ? (doc as Record<string, unknown>) : null;
  if (env && env.schema === EVIDENCE_SCHEMA) {
    const errs = bindingErrors(env, s, ctx);
    if (errs.length) return { ...row, mode: "v2", evidence: "unbound", detail: `evidence names another submission: ${errs.join("; ")} (${r.source})` };
    return { ...row, mode: "v2", evidence: "ok", detail: r.source };
  }
  if (ctx.contractMajor < 2) return { ...row, mode: "v1", evidence: "ok", detail: `${r.source} (v1 evidence: hash only, no envelope)` };
  return { ...row, mode: "v1", evidence: "unbound", detail: `not a ${EVIDENCE_SCHEMA} envelope; a v2 contract must bind its evidence (${r.source})` };
}

const PASSING: readonly EvidenceState[] = ["ok", "undisclosed", "no-verdict"];

/** 0 only if every checked submission with a posted verdict has matching, bound (or not yet disclosed) evidence. */
export function exitCodeFor(rows: VerifyRow[]): number {
  return rows.every((r) => PASSING.includes(r.evidence)) ? 0 : 1;
}

async function listAll<T>(view: ViewFn, method: string, args: Record<string, unknown>): Promise<T[]> {
  const all: T[] = [];
  for (let from = 0; ; from += 50) {
    const page = await view<T[]>(method, { ...args, from_index: from, limit: 50 });
    all.push(...page);
    if (page.length < 50) break;
  }
  return all;
}

export interface VerifyOptions {
  network: string;
  contractId: string;
  /** Check only this program (explicit; pinning does not apply). */
  programId?: number;
  /** Check every program on the contract. */
  allPrograms?: boolean;
  /** The pinned showcase programs of this contract; null or [] = none pinned (then every program is checked). */
  pinned?: number[] | null;
}

export interface VerifyResult {
  programs: { program: OnchainProgram; rows: VerifyRow[] }[];
  /** Programs on the contract that are not part of the showcase: listed, not checked. */
  skipped: OnchainProgram[];
  rows: VerifyRow[];
  contractVersion: string | null;
  contractMajor: number;
  selection: "program" | "all" | "pinned";
  exitCode: number;
}

/** Major version from version() ("1.0.1" -> 1); unknown -> 2 (the strict rule). */
export function majorOf(version: string | null): number {
  const m = /^(\d+)\./.exec(String(version ?? ""));
  return m ? Number(m[1]) : 2;
}

/** Read held-back submissions from runs/<network>/<contract>/disclosure.json (written by `publish`). */
async function readHeld(read: EvidenceReader, network: string, contractId: string): Promise<Map<number, number[]>> {
  const held = new Map<number, number[]>();
  const r = await read(["runs", network, contractId, DISCLOSURE_FILE].join("/"));
  if (!r.ok) return held;
  try {
    const doc = JSON.parse(Buffer.from(r.bytes).toString("utf8")) as { schema?: string; held?: { submission_id?: unknown; waits_for?: unknown }[] };
    if (doc.schema !== DISCLOSURE_SCHEMA || !Array.isArray(doc.held)) return held;
    for (const h of doc.held) {
      if (Number.isInteger(h.submission_id) && Array.isArray(h.waits_for)) {
        held.set(Number(h.submission_id), h.waits_for.filter((w): w is number => Number.isInteger(w)));
      }
    }
  } catch {
    // a broken disclosure file holds nothing back
  }
  return held;
}

/** Read the programs and check every submission's evidence. */
export async function verifyOnchain(view: ViewFn, read: EvidenceReader, opts: VerifyOptions): Promise<VerifyResult> {
  let contractVersion: string | null = null;
  try {
    contractVersion = String(await view<string>("version", {}));
  } catch {
    contractVersion = null;
  }
  const contractMajor = majorOf(contractVersion);
  let programs: OnchainProgram[];
  let skipped: OnchainProgram[] = [];
  let selection: VerifyResult["selection"];
  if (opts.programId !== undefined) {
    const p = await view<OnchainProgram | null>("get_program", { program_id: opts.programId });
    if (!p) throw new Error(`program ${opts.programId} not found`);
    programs = [p];
    selection = "program";
  } else {
    const all = await listAll<OnchainProgram>(view, "list_programs", {});
    const pinned = opts.pinned ?? [];
    if (opts.allPrograms || pinned.length === 0) {
      programs = all;
      selection = "all";
    } else {
      programs = all.filter((p) => pinned.includes(Number(p.id)));
      skipped = all.filter((p) => !pinned.includes(Number(p.id)));
      selection = "pinned";
    }
  }
  const known = new Map<number, string>();
  const ctx: CheckContext = {
    network: opts.network,
    contractId: opts.contractId,
    contractMajor,
    held: await readHeld(read, opts.network, opts.contractId),
    async statusOf(id) {
      if (known.has(id)) return known.get(id)!;
      const s = await view<OnchainSubmission | null>("get_submission", { submission_id: id });
      const st = s ? String(s.status) : null;
      if (st) known.set(id, st);
      return st;
    },
  };
  const out: VerifyResult["programs"] = [];
  for (const program of programs) {
    const subs = await listAll<OnchainSubmission>(view, "list_submissions", { program_id: program.id });
    for (const s of subs) known.set(Number(s.id), String(s.status));
    const rows: VerifyRow[] = [];
    for (const s of subs.sort((a, b) => a.id - b.id)) rows.push(await checkSubmission(s, read, ctx));
    out.push({ program, rows });
  }
  const rows = out.flatMap((p) => p.rows);
  return { programs: out, skipped, rows, contractVersion, contractMajor, selection, exitCode: exitCodeFor(rows) };
}

/** On-chain text (program names, titles, reasons) for a terminal: control characters, ANSI escapes,
 *  line breaks and bidi overrides become spaces; at most `max` characters. */
export function printable(text: unknown, max = 120): string {
  const t = String(text ?? "").replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, " ");
  const cps = Array.from(t);
  return cps.length > max ? cps.slice(0, max - 1).join("") + "…" : t;
}

function evidenceLabel(r: VerifyRow): string {
  switch (r.evidence) {
    case "no-verdict":
      return "- (no verdict)";
    case "ok":
      return r.mode === "v1" ? "ok (v1 evidence)" : "ok";
    case "undisclosed":
      return isFinal(r.status) ? "private (held back)" : "private (not final)";
    default:
      return r.evidence;
  }
}

/** Plain-text table: id, status, outcome, severity, payout, evidence. */
export function formatTable(rows: VerifyRow[]): string[] {
  const head = ["id", "status", "outcome", "severity", "payout (NEAR)", "evidence"];
  const body = rows.map((r) => [
    `#${r.id}`,
    r.status,
    r.outcome,
    r.severity,
    r.status === "paid" || r.payout !== "0" ? fmtNear(r.payout) : "-",
    evidenceLabel(r),
  ]);
  const widths = head.map((h, i) => Math.max(h.length, ...body.map((b) => b[i].length)));
  const line = (cells: string[]) => cells.map((c, i) => (i === cells.length - 1 ? c : c.padEnd(widths[i]))).join("  ");
  return [line(head), line(widths.map((w) => "-".repeat(w))), ...body.map(line)];
}

/** The last line of verify-onchain. */
export function resultLine(rows: VerifyRow[]): string {
  if (exitCodeFor(rows) !== 0) return "result: FAILED - at least one posted verdict does not match its evidence";
  const hidden = rows.filter((r) => r.evidence === "undisclosed").length;
  return hidden === 0
    ? "result: every posted verdict matches its evidence file"
    : `result: no mismatch; ${hidden} verdict(s) not checkable yet (evidence stays private until the submission is settled)`;
}

export function summaryLine(rows: VerifyRow[]): string {
  const n = (s: EvidenceState) => rows.filter((r) => r.evidence === s).length;
  const posted = rows.length - n("no-verdict");
  const v1 = rows.filter((r) => r.evidence === "ok" && r.mode === "v1").length;
  const bad = (["mismatch", "unbound", "refused", "missing"] as const).map((s) => `${n(s)} ${s}`).join(", ");
  return `${posted} posted verdict(s) checked: ${n("ok")} ok${v1 ? ` (${v1} v1 evidence)` : ""}, ${bad}, ` +
    `${n("undisclosed")} not disclosed yet; ${n("no-verdict")} submission(s) without a verdict`;
}
