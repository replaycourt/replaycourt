// Pure mapping from an engine run (exit code + verdict.json) to the on-chain VerdictInput.
// SPEC.md "Engine contract": 0 valid, 1 invalid, 2 needs human, 3 duplicate, 64 usage,
// 65 unreadable report, 69 infrastructure missing (no verdict, retry), 70 internal error (no verdict).

import crypto from "node:crypto";

export type Outcome = "valid" | "invalid" | "duplicate" | "needs_human";
export type Severity = "critical" | "high" | "medium" | "low";

export interface VerdictInput {
  outcome: Outcome;
  severity: Severity | null;
  duplicate_of: number | null;
  fingerprint: string;
  evidence_sha256: string;
  evidence_uri: string;
  chain_id: number;
  fork_block: string; // U64
  reason: string;
}

export const MAX_REASON_BYTES = 280;
export const MAX_FINGERPRINT_BYTES = 128;
export const MAX_EVIDENCE_URI_BYTES = 256;
export const COMMITMENT_MISMATCH_REASON = "sealed report does not match commitment";

// Exit codes of the engine, and of an optional wrapper (REPLAYCOURT_ENGINE_WRAPPER) or the worker's own
// time limit: 124 time limit, 137 memory limit (the usual timeout(1) / "Killed: 9" codes).
export const EXIT = {
  valid: 0,
  invalid: 1,
  needsHuman: 2,
  duplicate: 3,
  usage: 64,
  badReport: 65,
  unavailable: 69,
  internal: 70,
  wrapperTimeout: 124,
  wrapperMemory: 137,
} as const;

/** Engine severity level (optionally "provisional") -> on-chain severity:
 *  critical -> critical, high -> high, medium -> medium, anything lower -> low. */
export function mapSeverity(level: string | null | undefined): Severity {
  const l = String(level ?? "").trim().toLowerCase().replace(/^provisional\s+/, "");
  if (l === "critical") return "critical";
  if (l === "high") return "high";
  if (l === "medium") return "medium";
  return "low";
}

export type EngineAction =
  | { kind: "post"; outcome: Outcome }
  | { kind: "retry"; why: string }; // post nothing, log, retry later

/** What to do with an engine exit code (before looking at verdict.json details). */
export function actionForExit(code: number | null): EngineAction {
  switch (code) {
    case EXIT.valid:
      return { kind: "post", outcome: "valid" };
    case EXIT.invalid:
      return { kind: "post", outcome: "invalid" };
    case EXIT.needsHuman:
      return { kind: "post", outcome: "needs_human" };
    case EXIT.duplicate:
      return { kind: "post", outcome: "duplicate" };
    case EXIT.unavailable:
      return { kind: "retry", why: "engine exit 69: infrastructure missing (archive RPC / forge / solc)" };
    case EXIT.internal:
      return { kind: "retry", why: "engine exit 70: internal error" };
    case EXIT.usage:
      return { kind: "retry", why: "engine exit 64: usage error (worker bug)" };
    case EXIT.badReport:
      // The worker writes the report file itself and the engine reads it leniently, so 65
      // means a local I/O problem, not a bad report: never slash a hunter for it.
      return { kind: "retry", why: "engine exit 65: report file not readable (local I/O)" };
    case EXIT.wrapperTimeout:
      return { kind: "post", outcome: "needs_human" };
    case EXIT.wrapperMemory:
      return { kind: "post", outcome: "needs_human" };
    default:
      return { kind: "retry", why: `engine ended with unexpected code ${String(code)}` };
  }
}

/** Cut to at most `max` UTF-8 bytes without splitting a character (the contract counts bytes). */
export function truncateBytes(s: string, max: number): string {
  if (Buffer.byteLength(s) <= max) return s;
  const ellipsis = "…";
  let out = "";
  let used = Buffer.byteLength(ellipsis);
  for (const ch of s) {
    used += Buffer.byteLength(ch);
    if (used > max) break;
    out += ch;
  }
  return out + ellipsis;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    return "{" + Object.keys(obj).sort().map((k) => JSON.stringify(k) + ":" + canonicalJson(obj[k])).join(",") + "}";
  }
  return JSON.stringify(value);
}

/** sha256 of the canonical JSON of the engine's behaviour fingerprint ("" if there is none). */
export function fingerprintId(fp: unknown): string {
  if (!fp || typeof fp !== "object") return "";
  return crypto.createHash("sha256").update(canonicalJson(fp)).digest("hex");
}

/** "sub-12" -> 12; anything else -> null. */
export function parseSubmissionRef(ref: unknown): number | null {
  const m = /^sub-(\d+)$/.exec(String(ref ?? ""));
  return m ? Number(m[1]) : null;
}

// Subset of the engine's verdict.json that the worker reads.
export interface EngineVerdict {
  outcome?: string | null;
  verdict?: string | null;
  exit_code?: number;
  severity_hint?: { level?: string | null; provisional?: boolean } | null;
  duplicate?: { status?: string; of?: string | null } | null;
  fork?: { chain_id?: number; local?: boolean; poc_fork_block?: number | null; declared_block?: number | null } | null;
  fingerprint?: unknown;
  reasons?: string[];
}

export interface BuildArgs {
  submissionId: number;
  exitCode: number;
  verdict: EngineVerdict | null; // parsed verdict.json (null if the engine wrote none)
  evidenceSha256: string; // sha256 of the verdict.json bytes
  evidenceUri: string;
}

/** Build the VerdictInput for an engine run whose exit code says "post". */
export function buildVerdict(a: BuildArgs, outcome: Outcome): VerdictInput {
  const v = a.verdict ?? {};
  const fork = v.fork ?? {};
  const reasons = (v.reasons ?? []).filter((r) => typeof r === "string");
  let severity: Severity | null = null;
  let duplicateOf: number | null = null;
  let reasonHead = "";
  let finalOutcome: Outcome = outcome;

  if (a.exitCode === EXIT.wrapperTimeout || a.exitCode === EXIT.wrapperMemory) {
    reasonHead = a.exitCode === EXIT.wrapperTimeout
      ? "verifier time limit exceeded while replaying the PoC; a human must check"
      : "verifier memory limit exceeded while replaying the PoC; a human must check";
  } else if (outcome === "valid") {
    severity = mapSeverity(v.severity_hint?.level);
  } else if (outcome === "duplicate") {
    const ref = v.duplicate?.of ?? null;
    duplicateOf = parseSubmissionRef(ref);
    if (duplicateOf === null || duplicateOf >= a.submissionId) {
      // The contract only accepts an earlier submission of the same program; anything else
      // (e.g. the original was judged later after a retry) goes to a human.
      finalOutcome = "needs_human";
      reasonHead = `engine reports a duplicate of ${String(ref)}, which is not an earlier submission; a human must decide`;
      duplicateOf = null;
    } else {
      reasonHead = `duplicate of submission ${duplicateOf}`;
    }
  }

  const reason = truncateBytes([reasonHead ? reasonHead + "." : "", ...reasons].filter(Boolean).join(" "), MAX_REASON_BYTES)
    || `engine outcome ${finalOutcome}`;
  const local = fork.local === true;
  const block = fork.poc_fork_block ?? fork.declared_block ?? 0;
  return {
    outcome: finalOutcome,
    severity: finalOutcome === "valid" ? severity : null,
    duplicate_of: finalOutcome === "duplicate" ? duplicateOf : null,
    fingerprint: truncateBytes(fingerprintId(v.fingerprint), MAX_FINGERPRINT_BYTES),
    evidence_sha256: a.evidenceSha256,
    evidence_uri: truncateBytes(a.evidenceUri, MAX_EVIDENCE_URI_BYTES),
    chain_id: local ? 0 : Number(fork.chain_id ?? 0),
    fork_block: String(local ? 0 : Number(block ?? 0)),
    reason,
  };
}

/** Turn a verdict into needs_human (no severity, no duplicate_of) with `why` in front of the reason. */
export function escalateToHuman(v: VerdictInput, why: string): VerdictInput {
  return { ...v, outcome: "needs_human", severity: null, duplicate_of: null, reason: truncateBytes(why, MAX_REASON_BYTES) };
}

/** Verdict for a sealed blob that cannot be opened or does not match its commitment. */
export function commitmentMismatchVerdict(evidenceSha256: string, evidenceUri: string): VerdictInput {
  return {
    outcome: "invalid",
    severity: null,
    duplicate_of: null,
    fingerprint: "",
    evidence_sha256: evidenceSha256,
    evidence_uri: truncateBytes(evidenceUri, MAX_EVIDENCE_URI_BYTES),
    chain_id: 0,
    fork_block: "0",
    reason: COMMITMENT_MISMATCH_REASON,
  };
}
