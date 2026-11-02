// Evidence envelope (SPEC v2 "Evidence"), submission status sets and evidence paths, shared by the
// worker (writes evidence.json), `publish` (moves settled evidence into runs/) and `verify-onchain`.

import crypto from "node:crypto";
import path from "node:path";

export const EVIDENCE_SCHEMA = "replaycourt.evidence/v1";
export const EVIDENCE_FILE = "evidence.json";

/** evidence.json: binds the engine's verdict to one submission on one contract. Its sha256 is the
 *  on-chain evidence_sha256. */
export interface EvidenceEnvelope {
  schema: typeof EVIDENCE_SCHEMA;
  network: string;
  contract_id: string;
  program_id: number;
  submission_id: number;
  hunter_id: string;
  commitment: string;
  /** The engine's verdict.json (schema replaycourt.verdict/v1), or the worker's own verdict
   *  (replaycourt.worker-verdict/v1) when the engine did not run (commitment mismatch, memory/time cap). */
  engine: unknown;
}

/** Fields of the envelope that must equal the on-chain submission. */
export const BINDING_FIELDS = ["network", "contract_id", "program_id", "submission_id", "hunter_id", "commitment"] as const;

export function makeEnvelope(b: Omit<EvidenceEnvelope, "schema" | "engine">, engine: unknown): EvidenceEnvelope {
  return {
    schema: EVIDENCE_SCHEMA,
    network: b.network,
    contract_id: b.contract_id,
    program_id: Number(b.program_id),
    submission_id: Number(b.submission_id),
    hunter_id: b.hunter_id,
    commitment: b.commitment,
    engine,
  };
}

/** The exact bytes the worker writes and hashes (pretty JSON + newline). */
export function envelopeBytes(env: EvidenceEnvelope): Buffer {
  return Buffer.from(JSON.stringify(env, null, 2) + "\n", "utf8");
}

export function sha256Hex(data: Uint8Array): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

/** Statuses after which nothing changes any more (SPEC v2 "Types"). */
export const FINAL_STATUSES: readonly string[] = ["paid", "invalid", "duplicate", "rejected", "expired", "withdrawn"];
/** Statuses a duplicate_of may point to (SPEC v2 post_verdict "duplicate"). */
export const ORIGINAL_STATUSES: readonly string[] = ["valid", "paid", "disputed"];

export function isFinal(status: string | null | undefined): boolean {
  return typeof status === "string" && FINAL_STATUSES.includes(status);
}

/** On-chain status right after post_verdict with this outcome. */
export function statusAfterVerdict(outcome: string): string {
  return outcome; // valid -> valid, invalid -> invalid, duplicate -> duplicate, needs_human -> needs_human
}

/** runs/<network>/<contract>/<id>/evidence.json: the public place of a submission's evidence, also
 *  while it is still private (the URI is posted on-chain before the file is published). */
export function evidenceUri(network: string, contractId: string, submissionId: number): string {
  return ["runs", network, contractId, String(submissionId), EVIDENCE_FILE].join("/");
}

/**
 * Map an evidence_uri to a file below <repoRoot>/runs/. Absolute paths, URL schemes, NUL bytes,
 * backslashes and anything that leaves runs/ are refused (null), so a verdict can neither make a
 * checker read other files nor point at evidence outside the published tree.
 */
export function resolveRunsPath(repoRoot: string, uri: string): string | null {
  if (!uri || uri.includes("\0") || uri.includes("\\") || path.isAbsolute(uri) || /^[a-z][a-z0-9+.-]*:/i.test(uri)) return null;
  const runs = path.resolve(repoRoot, "runs");
  const file = path.resolve(path.resolve(repoRoot), uri);
  const rel = path.relative(runs, file);
  if (rel === "" || rel === ".." || rel.startsWith(".." + path.sep) || path.isAbsolute(rel)) return null;
  return file;
}
