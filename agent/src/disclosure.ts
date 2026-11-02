// Disclosure (SPEC v2 "Evidence"): with `worker --disclose after-settlement` (the default) the
// evidence of a submission stays in runs-private/<network>/<contract>/<id>/ until the submission is
// final; `publish` then moves it to runs/<network>/<contract>/<id>/, where its evidence_uri points.
//
// A final submission can still disclose a live bug: a duplicate repeats its original, and an invalid
// first try describes the same bug as a later valid report. So a submission is also held back while a
// related submission of the program is not final. Related = duplicate_of in either direction, or the
// engine listed the other report as a similar earlier report (duplicate check, level duplicate or
// possible). Held submissions are listed in runs/<network>/<contract>/disclosure.json (ids only), so
// that verify-onchain can tell "held back" from "missing".

import fs from "node:fs";
import path from "node:path";
import { EVIDENCE_FILE, isFinal } from "./evidence.ts";
import { parseSubmissionRef } from "./mapping.ts";

export const DISCLOSURE_SCHEMA = "replaycourt.disclosure/v1";
export const DISCLOSURE_FILE = "disclosure.json";

export interface ChainState {
  id: number;
  program_id: number;
  status: string;
  duplicate_of: number | null;
}

export interface PrivateRun {
  id: number;
  /** Submission ids the engine found similar (duplicate check), or that this one duplicates. */
  related: number[];
}

export interface PublishPlan {
  publish: number[];
  held: { id: number; status: string; waitsFor: number[]; why: string }[];
  unknown: number[]; // private runs without an on-chain submission (another contract?)
}

/** Submission ids an engine verdict.json relates to: its duplicate original and every candidate of
 *  level duplicate/possible ("sub-<id>" report ids only). */
export function relatedFromVerdict(verdict: unknown): number[] {
  const d = (verdict as { duplicate?: { of?: unknown; candidates?: { id?: unknown; level?: unknown }[] } } | null)?.duplicate;
  const ids = new Set<number>();
  const of = parseSubmissionRef(d?.of);
  if (of !== null) ids.add(of);
  for (const c of Array.isArray(d?.candidates) ? d.candidates : []) {
    if (c && (c.level === "duplicate" || c.level === "possible")) {
      const n = parseSubmissionRef(c.id);
      if (n !== null) ids.add(n);
    }
  }
  return [...ids].sort((a, b) => a - b);
}

/** Decide which private runs may be published now. Pure; `chain` holds the on-chain state of every
 *  run and of every submission a run is related to. */
export function planPublish(runs: PrivateRun[], chain: Map<number, ChainState>): PublishPlan {
  const rel = new Map<number, Set<number>>();
  const link = (a: number, b: number) => {
    if (a === b) return;
    if (!rel.has(a)) rel.set(a, new Set());
    if (!rel.has(b)) rel.set(b, new Set());
    rel.get(a)!.add(b);
    rel.get(b)!.add(a);
  };
  for (const r of runs) for (const o of r.related) link(r.id, o);
  for (const s of chain.values()) if (s.duplicate_of !== null && s.duplicate_of !== undefined) link(s.id, s.duplicate_of);

  const plan: PublishPlan = { publish: [], held: [], unknown: [] };
  for (const r of [...runs].sort((a, b) => a.id - b.id)) {
    const s = chain.get(r.id);
    if (!s) {
      plan.unknown.push(r.id);
      continue;
    }
    if (!isFinal(s.status)) {
      plan.held.push({ id: r.id, status: s.status, waitsFor: [r.id], why: `not final yet (${s.status})` });
      continue;
    }
    const waits = [...(rel.get(r.id) ?? [])]
      .filter((o) => {
        const os = chain.get(o);
        return os && Number(os.program_id) === Number(s.program_id) && !isFinal(os.status);
      })
      .sort((a, b) => a - b);
    if (waits.length) {
      plan.held.push({ id: r.id, status: s.status, waitsFor: waits,
        why: `final (${s.status}), but related to ${waits.map((w) => `#${w} (${chain.get(w)!.status})`).join(", ")}, which is not final yet` });
      continue;
    }
    plan.publish.push(r.id);
  }
  return plan;
}

function readJson(file: string): unknown {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

/** The submission directories in runs-private/<network>/<contract>/ (numeric names). */
export function listPrivateRuns(privateRoot: string): PrivateRun[] {
  if (!fs.existsSync(privateRoot)) return [];
  return fs.readdirSync(privateRoot, { withFileTypes: true })
    .filter((d) => d.isDirectory() && /^\d+$/.test(d.name))
    .map((d) => ({ id: Number(d.name), related: relatedFromVerdict(readJson(path.join(privateRoot, d.name, "verdict.json"))) }));
}

export interface PublishOptions {
  network: string;
  contractId: string;
  runsRoot: string; // <repo>/runs/<network>/<contract>
  privateRoot: string; // <repo>/runs-private/<network>/<contract>
  dryRun?: boolean;
}

export interface PublishResult {
  plan: PublishPlan;
  moved: number[];
  conflicts: { id: number; why: string }[];
  disclosureFile: string | null;
}

/** Move the evidence of every settled submission from runs-private/ to runs/ and record the held ones. */
export async function publishEvidence(
  o: PublishOptions,
  getSubmission: (id: number) => Promise<{ id: number; program_id: number; status: string; verdict?: { duplicate_of?: number | null } | null } | null>,
): Promise<PublishResult> {
  const runs = listPrivateRuns(o.privateRoot);
  const chain = new Map<number, ChainState>();
  const want = new Set<number>([...runs.map((r) => r.id), ...runs.flatMap((r) => r.related)]);
  for (const id of [...want].sort((a, b) => a - b)) {
    const s = await getSubmission(id);
    if (s) chain.set(id, { id, program_id: Number(s.program_id), status: String(s.status), duplicate_of: s.verdict?.duplicate_of ?? null });
  }
  const plan = planPublish(runs, chain);
  const result: PublishResult = { plan, moved: [], conflicts: [], disclosureFile: null };
  if (o.dryRun) return result;
  fs.mkdirSync(o.runsRoot, { recursive: true });
  for (const id of plan.publish) {
    const src = path.join(o.privateRoot, String(id));
    const dst = path.join(o.runsRoot, String(id));
    if (fs.existsSync(dst)) {
      const a = fs.existsSync(path.join(src, EVIDENCE_FILE)) ? fs.readFileSync(path.join(src, EVIDENCE_FILE)) : null;
      const b = fs.existsSync(path.join(dst, EVIDENCE_FILE)) ? fs.readFileSync(path.join(dst, EVIDENCE_FILE)) : null;
      if (a && b && a.equals(b)) {
        fs.rmSync(src, { recursive: true, force: true }); // published before (same evidence)
        result.moved.push(id);
      } else {
        result.conflicts.push({ id, why: `${path.join("runs", o.network, o.contractId, String(id))} exists with other evidence; not overwritten` });
      }
      continue;
    }
    fs.renameSync(src, dst);
    result.moved.push(id);
  }
  // Held-back final submissions, so that verify-onchain can tell them from missing evidence.
  const heldFinal = plan.held.filter((h) => !(h.waitsFor.length === 1 && h.waitsFor[0] === h.id));
  const file = path.join(o.runsRoot, DISCLOSURE_FILE);
  const doc = {
    schema: DISCLOSURE_SCHEMA,
    network: o.network,
    contract_id: o.contractId,
    held: heldFinal.map((h) => ({ submission_id: h.id, waits_for: h.waitsFor })),
  };
  if (heldFinal.length || fs.existsSync(file)) {
    fs.writeFileSync(file, JSON.stringify(doc, null, 2) + "\n");
    result.disclosureFile = file;
  }
  return result;
}
