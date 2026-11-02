// verify-onchain: evidence hash and binding checks with the RPC (view calls) and the evidence files mocked.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import { evidenceUri, resolveRunsPath } from "../src/evidence.ts";
import {
  checkSubmission,
  exitCodeFor,
  formatTable,
  majorOf,
  makeEvidenceReader,
  printable,
  resultLine,
  summaryLine,
  verifyOnchain,
} from "../src/verify.ts";
import type { CheckContext, EvidenceReader, OnchainSubmission, ViewFn, VerifyRow } from "../src/verify.ts";

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "replaycourt-verify-test-"));
after(() => fs.rmSync(tmpRoot, { recursive: true, force: true }));

const NET = "testnet";
const C = "c.testnet";
const sha = (s: string | Uint8Array) => crypto.createHash("sha256").update(s).digest("hex");
const commitOf = (id: number) => sha(`commitment ${id}`);

/** v2 evidence of submission `id` (program 0, hunter.testnet). */
const envOf = (id: number, over: Record<string, unknown> = {}) => JSON.stringify({
  schema: "replaycourt.evidence/v1", network: NET, contract_id: C, program_id: 0, submission_id: id,
  hunter_id: "hunter.testnet", commitment: commitOf(id), engine: { schema: "replaycourt.verdict/v1", outcome: "invalid" }, ...over,
}, null, 2) + "\n";
/** v1 evidence (the engine's verdict.json, no envelope). */
const v1Of = (id: number) => `{"schema":"replaycourt.verdict/v1","report":{"id":"sub-${id}"}}\n`;
const v1Uri = (id: number) => `runs/testnet/${C}/${id}/verdict.json`;

function sub(id: number, over: Partial<OnchainSubmission> = {}, verdict: Partial<NonNullable<OnchainSubmission["verdict"]>> | null = {},
  body = envOf(id)): OnchainSubmission {
  return {
    id,
    program_id: 0,
    hunter_id: "hunter.testnet",
    commitment: commitOf(id),
    title: `report ${id}`,
    status: "invalid",
    payout: "0",
    resolution: null,
    verdict: verdict === null ? null : {
      outcome: "invalid",
      severity: null,
      duplicate_of: null,
      evidence_sha256: sha(body),
      evidence_uri: evidenceUri(NET, C, id),
      ...verdict,
    },
    ...over,
  };
}

/** In-memory evidence files keyed by evidence_uri; only runs/ paths are readable (like the real reader). */
function memReader(files: Record<string, string>): EvidenceReader & { reads: string[] } {
  const reads: string[] = [];
  const fn = (async (uri: string) => {
    reads.push(uri);
    if (!resolveRunsPath("/repo", uri)) return { ok: false as const, error: "evidence_uri is not a path below runs/" };
    return uri in files
      ? { ok: true as const, bytes: Buffer.from(files[uri]), source: uri }
      : { ok: false as const, error: "file not found", source: uri, notFound: true };
  }) as EvidenceReader & { reads: string[] };
  fn.reads = reads;
  return fn;
}

const v2ctx = (over: Partial<CheckContext> = {}): CheckContext => ({
  network: NET, contractId: C, contractMajor: 2, held: new Map(), statusOf: async () => null, ...over,
});

/** Mocked contract views: version, programs and their submissions, paged like the contract (limit <= 50). */
function mockChain(programs: { id: number; name: string }[], subs: OnchainSubmission[], version = "2.0.0") {
  const calls: { method: string; args: Record<string, unknown> }[] = [];
  const view = (async (method: string, args: Record<string, unknown>) => {
    calls.push({ method, args });
    const from = Number(args.from_index ?? 0);
    const limit = Math.min(Number(args.limit ?? 50), 50);
    switch (method) {
      case "version":
        return version;
      case "get_program":
        return programs.find((p) => p.id === args.program_id) ?? null;
      case "list_programs":
        return programs.slice(from, from + limit);
      case "list_submissions":
        return subs.filter((s) => s.program_id === args.program_id).slice(from, from + limit);
      case "get_submission":
        return subs.find((s) => s.id === args.submission_id) ?? null;
      default:
        throw new Error(`unexpected view ${method}`);
    }
  }) as ViewFn;
  return { view, calls };
}

const P0 = { id: 0, name: "demo" };
const opts = { network: NET, contractId: C };
const filesFor = (ids: number[]) => Object.fromEntries(ids.map((id) => [evidenceUri(NET, C, id), envOf(id)]));

test("v2: hash matches and the envelope is bound to the submission -> ok, exit 0", async () => {
  const subs = [sub(0, { status: "paid", payout: "400000000000000000000000" }, { outcome: "valid", severity: "critical" }), sub(1), sub(2)];
  const { view } = mockChain([P0], subs);
  const res = await verifyOnchain(view, memReader(filesFor([0, 1, 2])), { ...opts, programId: 0 });
  assert.deepEqual(res.rows.map((r) => [r.evidence, r.mode]), [["ok", "v2"], ["ok", "v2"], ["ok", "v2"]]);
  assert.equal(res.exitCode, 0);
  assert.equal(resultLine(res.rows), "result: every posted verdict matches its evidence file");
  assert.equal(res.contractMajor, 2);
  assert.equal(res.rows[0].actual, sha(envOf(0)));
});

test("v2: evidence of another submission with a matching hash is 'unbound' (copied or re-pointed evidence)", async () => {
  // The verifier posts #1's hash and file for #5: the hash matches, the binding does not.
  const s = sub(5, {}, { evidence_sha256: sha(envOf(1)), evidence_uri: evidenceUri(NET, C, 1) });
  const r = await checkSubmission(s, memReader(filesFor([1])), v2ctx());
  assert.equal(r.evidence, "unbound");
  assert.match(r.detail, /submission_id 1 != on-chain 5/);
  assert.match(r.detail, /commitment/);
  assert.equal(exitCodeFor([r]), 1);
});

test("v2: every binding field is compared (contract, program, hunter, commitment, network)", async () => {
  for (const [field, value] of [["contract_id", "other.testnet"], ["program_id", 3], ["hunter_id", "copycat.testnet"],
    ["commitment", sha("x")], ["network", "mainnet"]] as const) {
    const body = envOf(4, { [field]: value });
    const r = await checkSubmission(sub(4, {}, {}, body), memReader({ [evidenceUri(NET, C, 4)]: body }), v2ctx());
    assert.equal(r.evidence, "unbound", field);
    assert.match(r.detail, new RegExp(field), field);
  }
});

test("v1 evidence (no envelope) is accepted from a v1 contract only: hash only, shown as v1", async () => {
  const s = sub(0, {}, { evidence_sha256: sha(v1Of(0)), evidence_uri: v1Uri(0) });
  const files = { [v1Uri(0)]: v1Of(0) };
  const v1 = await checkSubmission(s, memReader(files), v2ctx({ contractMajor: 1 }));
  assert.deepEqual([v1.evidence, v1.mode], ["ok", "v1"]);
  assert.match(v1.detail, /v1 evidence: hash only/);
  const v2 = await checkSubmission(s, memReader(files), v2ctx({ contractMajor: 2 }));
  assert.equal(v2.evidence, "unbound");
  assert.match(v2.detail, /not a replaycourt\.evidence\/v1 envelope/);
});

test("the showcase (contract version 1.x) keeps working in v1 evidence mode", async () => {
  const subs = [0, 1].map((id) => sub(id, {}, { evidence_sha256: sha(v1Of(id)), evidence_uri: v1Uri(id) }));
  const { view } = mockChain([P0], subs, "1.0.1");
  const res = await verifyOnchain(view, memReader({ [v1Uri(0)]: v1Of(0), [v1Uri(1)]: v1Of(1) }), opts);
  assert.equal(res.contractVersion, "1.0.1");
  assert.equal(res.contractMajor, 1);
  assert.deepEqual(res.rows.map((r) => [r.evidence, r.mode]), [["ok", "v1"], ["ok", "v1"]]);
  assert.equal(res.exitCode, 0);
  assert.match(formatTable(res.rows)[2], /ok \(v1 evidence\)$/);
  assert.match(summaryLine(res.rows), /2 ok \(2 v1 evidence\)/);
});

test("majorOf: version string -> major; unknown is treated as v2 (strict)", () => {
  assert.equal(majorOf("1.0.1"), 1);
  assert.equal(majorOf("2.0.0"), 2);
  assert.equal(majorOf(null), 2);
  assert.equal(majorOf("dev"), 2);
});

test("a changed evidence file -> mismatch with both hashes, exit 1", async () => {
  const files = { ...filesFor([0]), [evidenceUri(NET, C, 1)]: envOf(1).replace("invalid", "valid") };
  const { view } = mockChain([P0], [sub(0), sub(1)]);
  const res = await verifyOnchain(view, memReader(files), opts);
  assert.deepEqual(res.rows.map((r) => r.evidence), ["ok", "mismatch"]);
  assert.equal(res.exitCode, 1);
  assert.match(res.rows[1].detail, new RegExp(`on-chain ${sha(envOf(1))}, file ${sha(envOf(1).replace("invalid", "valid"))}`));
});

test("a single changed byte (trailing newline) is a mismatch", async () => {
  const r = await checkSubmission(sub(0), memReader({ [evidenceUri(NET, C, 0)]: envOf(0).trimEnd() }), v2ctx());
  assert.equal(r.evidence, "mismatch");
});

test("evidence of a final submission not found -> missing, exit 1", async () => {
  const { view } = mockChain([P0], [sub(0), sub(1)]);
  const res = await verifyOnchain(view, memReader(filesFor([0])), opts);
  assert.deepEqual(res.rows.map((r) => r.evidence), ["ok", "missing"]);
  assert.match(res.rows[1].detail, /file not found/);
  assert.equal(res.exitCode, 1);
});

test("evidence of a submission that is not final yet may be private (after-settlement disclosure)", async () => {
  const subs = [sub(0, { status: "valid" }, { outcome: "valid", severity: "high" }), sub(1, { status: "needs_human" }, { outcome: "needs_human" }),
    sub(2, { status: "disputed" }, { outcome: "valid", severity: "low" })];
  const { view } = mockChain([P0], subs);
  const res = await verifyOnchain(view, memReader({}), opts);
  assert.deepEqual(res.rows.map((r) => r.evidence), ["undisclosed", "undisclosed", "undisclosed"]);
  assert.match(res.rows[0].detail, /not disclosed yet: the submission is valid, not final/);
  assert.equal(res.exitCode, 0);
  assert.match(formatTable(res.rows)[2], /private \(not final\)$/);
  // ... but once the file is there, it is checked like any other.
  const bad = await verifyOnchain(view, memReader({ [evidenceUri(NET, C, 0)]: envOf(0) + " " }), opts);
  assert.equal(bad.rows[0].evidence, "mismatch");
});

test("a final submission held back by publish (disclosure.json) is fine while the related one is open", async () => {
  const subs = [sub(1, { status: "invalid" }), sub(2, { status: "valid" }, { outcome: "valid", severity: "critical" })];
  const disclosure = JSON.stringify({ schema: "replaycourt.disclosure/v1", network: NET, contract_id: C, held: [{ submission_id: 1, waits_for: [2] }] });
  const dUri = `runs/${NET}/${C}/disclosure.json`;
  const { view } = mockChain([P0], subs);
  const res = await verifyOnchain(view, memReader({ [dUri]: disclosure }), opts);
  assert.deepEqual(res.rows.map((r) => r.evidence), ["undisclosed", "undisclosed"]);
  assert.match(res.rows[0].detail, /held back: related to #2 \(valid\)/);
  assert.equal(res.exitCode, 0);
  const table = formatTable(res.rows);
  assert.match(table[2], /private \(held back\)$/);
  assert.match(table[3], /private \(not final\)$/);
  assert.equal(resultLine(res.rows), "result: no mismatch; 2 verdict(s) not checkable yet (evidence stays private until the submission is settled)");
  // A stale hold (the related submission is final now) does not excuse missing evidence.
  subs[1].status = "paid";
  const stale = await verifyOnchain(view, memReader({ [dUri]: disclosure }), opts);
  assert.deepEqual(stale.rows.map((r) => r.evidence), ["missing", "missing"]);
  assert.equal(stale.exitCode, 1);
  assert.match(resultLine(stale.rows), /^result: FAILED/);
});

test("only evidence below runs/ is read: other paths and https URLs are refused", async () => {
  for (const uri of ["engine/verdicts/x/verdict.json", "../outside.json", "runs/../.secrets/testnet.json", "/etc/passwd",
    "https://evidence.example/ok.json", "file:///etc/passwd", "runs\\x\\evidence.json", ""]) {
    const read = memReader({ [uri]: envOf(0) });
    const r = await checkSubmission(sub(0, {}, { evidence_uri: uri }), read, v2ctx());
    assert.ok(r.evidence === "refused" || (uri === "" && r.evidence === "missing"), `${uri}: ${r.evidence}`);
    assert.equal(exitCodeFor([r]), 1, uri);
  }
});

test("verdict without evidence_uri -> missing, the reader is not called", async () => {
  const read = memReader({});
  const r = await checkSubmission(sub(3, {}, { evidence_uri: "" }), read, v2ctx());
  assert.equal(r.evidence, "missing");
  assert.match(r.detail, /no evidence_uri/);
  assert.deepEqual(read.reads, []);
});

test("submissions without a verdict are listed but do not fail the run", async () => {
  const subs = [sub(0), sub(1, { status: "pending" }, null), sub(2, { status: "withdrawn" }, null)];
  const { view } = mockChain([P0], subs);
  const res = await verifyOnchain(view, memReader(filesFor([0])), opts);
  assert.deepEqual(res.rows.map((r) => r.evidence), ["ok", "no-verdict", "no-verdict"]);
  assert.equal(res.exitCode, 0);
  assert.equal(summaryLine(res.rows),
    "1 posted verdict(s) checked: 1 ok, 0 mismatch, 0 unbound, 0 refused, 0 missing, 0 not disclosed yet; 2 submission(s) without a verdict");
});

test("on-chain hash that is not 64 hex chars -> mismatch; upper-case hex is accepted", async () => {
  const files = filesFor([0]);
  const bad = await checkSubmission(sub(0, {}, { evidence_sha256: "abc" }), memReader(files), v2ctx());
  assert.equal(bad.evidence, "mismatch");
  assert.match(bad.detail, /not 64 hex/);
  const upper = await checkSubmission(sub(0, {}, { evidence_sha256: sha(envOf(0)).toUpperCase() }), memReader(files), v2ctx());
  assert.equal(upper.evidence, "ok");
});

test("exitCodeFor: 0 only if every posted verdict is ok or not disclosed yet", () => {
  const row = (evidence: VerifyRow["evidence"]): VerifyRow => ({
    id: 0, programId: 0, status: "", outcome: "", severity: "", payout: "0", evidence, mode: null, detail: "", uri: null, expected: null, actual: null,
  });
  assert.equal(exitCodeFor([]), 0);
  assert.equal(exitCodeFor([row("ok"), row("no-verdict"), row("undisclosed")]), 0);
  for (const bad of ["mismatch", "missing", "unbound", "refused"] as const) assert.equal(exitCodeFor([row("ok"), row(bad)]), 1, bad);
});

test("pinned showcase programs: other programs are listed as not part of the showcase and do not fail the run", async () => {
  const programs = [P0, { id: 1, name: "showcase 2" }, { id: 2, name: "a stranger's program" }];
  const body1 = envOf(1, { program_id: 1 });
  const subs = [sub(0), sub(1, { program_id: 1 }, {}, body1), { ...sub(2), program_id: 2, verdict: { ...sub(2).verdict!, evidence_sha256: "f".repeat(64) } }];
  const files = { ...filesFor([0, 2]), [evidenceUri(NET, C, 1)]: body1 };
  const { view, calls } = mockChain(programs, subs);
  const res = await verifyOnchain(view, memReader(files), { ...opts, pinned: [0, 1] });
  assert.equal(res.selection, "pinned");
  assert.deepEqual(res.programs.map((p) => p.program.id), [0, 1]);
  assert.deepEqual(res.skipped.map((p) => p.id), [2]);
  assert.equal(res.exitCode, 0);
  assert.ok(calls.every((c) => c.method !== "list_submissions" || c.args.program_id !== 2));
  // --all-programs checks the stranger's program too (and fails on its bad hash)
  const all = await verifyOnchain(view, memReader(files), { ...opts, pinned: [0, 1], allPrograms: true });
  assert.equal(all.selection, "all");
  assert.deepEqual(all.skipped, []);
  assert.equal(all.exitCode, 1);
  // a contract with nothing pinned: every program is checked
  const unpinned = await verifyOnchain(view, memReader(files), { ...opts, pinned: null });
  assert.equal(unpinned.selection, "all");
  assert.equal(unpinned.programs.length, 3);
});

test("--program reads only that program (pinning does not apply); an unknown program is an error", async () => {
  const subs = [sub(0), { ...sub(1), program_id: 1 }];
  const { view, calls } = mockChain([P0, { id: 1, name: "other" }], subs);
  const res = await verifyOnchain(view, memReader(filesFor([0])), { ...opts, programId: 0, pinned: [1] });
  assert.equal(res.selection, "program");
  assert.deepEqual(res.rows.map((r) => r.id), [0]);
  assert.ok(!calls.some((c) => c.method === "list_programs"));
  assert.ok(calls.every((c) => c.method !== "list_submissions" || c.args.program_id === 0));
  await assert.rejects(verifyOnchain(view, memReader({}), { ...opts, programId: 7 }), /program 7 not found/);
});

test("all programs and all pages of submissions are read (contract limit 50)", async () => {
  const subs: OnchainSubmission[] = [];
  for (let id = 0; id < 120; id++) subs.push(id === 119 ? sub(id) : sub(id, { status: "pending" }, null));
  subs.push({ ...sub(120), program_id: 1 });
  const files = { ...filesFor([119]), [evidenceUri(NET, C, 120)]: envOf(120, { program_id: 1 }) };
  subs[120].verdict!.evidence_sha256 = sha(envOf(120, { program_id: 1 }));
  const { view, calls } = mockChain([P0, { id: 1, name: "second" }], subs);
  const res = await verifyOnchain(view, memReader(files), opts);
  assert.equal(res.programs.length, 2);
  assert.equal(res.programs[0].rows.length, 120);
  assert.equal(calls.filter((c) => c.method === "list_submissions" && c.args.program_id === 0).length, 3);
  assert.deepEqual(res.rows.filter((r) => r.evidence !== "no-verdict").map((r) => [r.id, r.evidence]), [[119, "ok"], [120, "ok"]]);
  assert.equal(res.exitCode, 0);
});

test("table: outcome with duplicate_of and owner resolution, payout in NEAR", async () => {
  const subs = [
    sub(0, { status: "paid", payout: "400000000000000000000000" }, { outcome: "valid", severity: "critical" }),
    sub(2, { status: "paid", payout: "250000000000000000000000", resolution: { outcome: "valid", severity: "high" } }, { outcome: "needs_human" }),
    sub(3, { status: "duplicate" }, { outcome: "duplicate", duplicate_of: 0 }),
  ];
  const rows = await Promise.all(subs.map((s) => checkSubmission(s, memReader(filesFor([0, 2, 3])), v2ctx())));
  const lines = formatTable(rows);
  assert.match(lines[0], /^id\s+status\s+outcome\s+severity\s+payout \(NEAR\)\s+evidence$/);
  assert.match(lines[2], /^#0\s+paid\s+valid\s+critical\s+0\.4\s+ok$/);
  assert.match(lines[3], /^#2\s+paid\s+needs_human -> valid \(owner\)\s+high \(owner\)\s+0\.25\s+ok$/);
  assert.match(lines[4], /^#3\s+duplicate\s+duplicate of #0\s+-\s+-\s+ok$/);
});

test("resolveRunsPath keeps evidence below runs/", () => {
  const root = path.join(tmpRoot, "repo");
  assert.equal(resolveRunsPath(root, "runs/a/evidence.json"), path.join(root, "runs", "a", "evidence.json"));
  assert.equal(resolveRunsPath(root, "./runs/../runs/b.json"), path.join(root, "runs", "b.json"));
  for (const bad of ["", "runs", "runs/", "engine/x.json", "../outside.json", "runs/../../outside.json", "runs/../.secrets/k.json",
    "/etc/passwd", "file:///etc/passwd", "https://x/y.json", ".", "a\0b", "runs\\a.json"]) {
    assert.equal(resolveRunsPath(root, bad), null, bad);
  }
});

test("makeEvidenceReader reads files below runs/ and refuses everything else, also through a symlink", async () => {
  const root = path.join(tmpRoot, "repo2");
  fs.mkdirSync(path.join(root, "runs", "x"), { recursive: true });
  fs.writeFileSync(path.join(root, "runs", "x", "evidence.json"), envOf(5));
  fs.writeFileSync(path.join(root, "secret.json"), "outside");
  fs.symlinkSync(path.join(root, "secret.json"), path.join(root, "runs", "x", "link.json"));
  const read = makeEvidenceReader(root);
  const ok = await read("runs/x/evidence.json");
  assert.equal(ok.ok, true);
  if (ok.ok) assert.equal(ok.source, "runs/x/evidence.json");
  const missing = await read("runs/x/nope.json");
  assert.equal(missing.ok, false);
  if (!missing.ok) assert.equal(missing.notFound, true);
  const outside = await read("secret.json");
  assert.equal(outside.ok, false);
  if (!outside.ok) assert.match(outside.error, /not a path below runs/);
  const link = await read("runs/x/link.json");
  assert.equal(link.ok, false);
  if (!link.ok) assert.match(link.error, /symlink/);
});

test("printable: on-chain names cannot inject terminal escapes or fake output lines", () => {
  assert.equal(printable("demo"), "demo");
  assert.equal(printable("a\u001b[2Jb\nresult: every posted verdict matches\r"), "a [2Jb result: every posted verdict matches ");
  assert.equal(printable("x\u202edcba"), "x dcba");
  assert.equal(printable("é".repeat(200), 10), "é".repeat(9) + "…");
  assert.equal(printable(null), "");
});
