// Disclosure after settlement: which private evidence `publish` moves into runs/, and which it holds back.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import { planPublish, publishEvidence, relatedFromVerdict } from "../src/disclosure.ts";
import type { ChainState } from "../src/disclosure.ts";

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "replaycourt-disclosure-test-"));
after(() => fs.rmSync(tmpRoot, { recursive: true, force: true }));

const st = (id: number, status: string, duplicate_of: number | null = null, program_id = 0): ChainState => ({ id, program_id, status, duplicate_of });
const chainOf = (...s: ChainState[]) => new Map(s.map((x) => [x.id, x]));

test("relatedFromVerdict: the duplicate original and every similar candidate (sub-<id> only)", () => {
  assert.deepEqual(relatedFromVerdict({
    duplicate: {
      status: "duplicate", of: "sub-1",
      candidates: [{ id: "sub-1", level: "duplicate" }, { id: "sub-4", level: "possible" }, { id: "sub-9", level: "none" }, { id: "01-x", level: "duplicate" }],
    },
  }), [1, 4]);
  assert.deepEqual(relatedFromVerdict(null), []);
  assert.deepEqual(relatedFromVerdict({ schema: "replaycourt.worker-verdict/v1" }), []);
});

test("only final submissions are published", () => {
  const plan = planPublish([1, 2, 3, 4, 5, 6].map((id) => ({ id, related: [] })),
    chainOf(st(1, "paid"), st(2, "invalid"), st(3, "valid"), st(4, "needs_human"), st(5, "disputed"), st(6, "pending")));
  assert.deepEqual(plan.publish, [1, 2]);
  assert.deepEqual(plan.held.map((h) => [h.id, h.why]), [
    [3, "not final yet (valid)"], [4, "not final yet (needs_human)"], [5, "not final yet (disputed)"], [6, "not final yet (pending)"]]);
});

test("a duplicate waits for its original; an invalid first try waits for the similar later report", () => {
  // #1: the hunter's first try (invalid, a typo). #2: the fixed report (valid, challenge window open).
  // #3: a duplicate of #2. Publishing #1 or #3 now would disclose #2's live bug.
  const runs = [{ id: 1, related: [] }, { id: 2, related: [1] }, { id: 3, related: [2] }];
  const open = planPublish(runs, chainOf(st(1, "invalid"), st(2, "valid"), st(3, "duplicate", 2)));
  assert.deepEqual(open.publish, []);
  assert.deepEqual(open.held.map((h) => [h.id, h.waitsFor]), [[1, [2]], [2, [2]], [3, [2]]]);
  assert.match(open.held[0].why, /final \(invalid\), but related to #2 \(valid\)/);
  const settled = planPublish(runs, chainOf(st(1, "invalid"), st(2, "paid"), st(3, "duplicate", 2)));
  assert.deepEqual(settled.publish, [1, 2, 3]);
  assert.deepEqual(settled.held, []);
});

test("the duplicate_of link counts even when the engine verdict lists nothing", () => {
  const plan = planPublish([{ id: 5, related: [] }], chainOf(st(5, "duplicate", 2), st(2, "disputed")));
  assert.deepEqual(plan.held.map((h) => [h.id, h.waitsFor]), [[5, [2]]]);
});

test("relations to other programs and unknown submissions do not hold anything back", () => {
  const plan = planPublish([{ id: 1, related: [7, 8] }, { id: 9, related: [] }], chainOf(st(1, "invalid"), st(7, "valid", null, 3)));
  assert.deepEqual(plan.publish, [1]);
  assert.deepEqual(plan.unknown, [9]);
});

function privateRun(root: string, id: number, verdict: unknown, evidence = `{"submission_id":${id}}\n`) {
  const dir = path.join(root, String(id));
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "evidence.json"), evidence);
  fs.writeFileSync(path.join(dir, "report.md"), `# report ${id}\n`);
  if (verdict) fs.writeFileSync(path.join(dir, "verdict.json"), JSON.stringify(verdict));
}

test("publish moves final evidence to runs/, keeps the rest private and records held-back final ones", async () => {
  const repo = fs.mkdtempSync(path.join(tmpRoot, "repo-"));
  const privateRoot = path.join(repo, "runs-private", "testnet", "c.testnet");
  const runsRoot = path.join(repo, "runs", "testnet", "c.testnet");
  privateRun(privateRoot, 1, { duplicate: { status: "none", candidates: [] } });
  privateRun(privateRoot, 2, { duplicate: { status: "none", candidates: [{ id: "sub-1", level: "duplicate" }] } });
  privateRun(privateRoot, 3, { duplicate: { status: "duplicate", of: "sub-2", candidates: [{ id: "sub-2", level: "duplicate" }] } });
  privateRun(privateRoot, 4, null); // commitment mismatch: worker verdict, no candidates
  fs.mkdirSync(path.join(privateRoot, "registry"), { recursive: true });
  fs.writeFileSync(path.join(privateRoot, "registry", "program-0.jsonl"), "{}\n");
  const chain: Record<number, { id: number; program_id: number; status: string; verdict: { duplicate_of: number | null } | null }> = {
    1: { id: 1, program_id: 0, status: "invalid", verdict: { duplicate_of: null } },
    2: { id: 2, program_id: 0, status: "valid", verdict: { duplicate_of: null } },
    3: { id: 3, program_id: 0, status: "duplicate", verdict: { duplicate_of: 2 } },
    4: { id: 4, program_id: 0, status: "invalid", verdict: { duplicate_of: null } },
  };
  const get = async (id: number) => chain[id] ?? null;
  const o = { network: "testnet", contractId: "c.testnet", runsRoot, privateRoot };

  const dry = await publishEvidence({ ...o, dryRun: true }, get);
  assert.deepEqual(dry.plan.publish, [4]);
  assert.equal(fs.existsSync(runsRoot), false, "a dry run moves nothing");

  const first = await publishEvidence(o, get);
  assert.deepEqual(first.moved, [4]);
  assert.ok(fs.existsSync(path.join(runsRoot, "4", "evidence.json")));
  assert.ok(fs.existsSync(path.join(runsRoot, "4", "report.md")));
  assert.equal(fs.existsSync(path.join(privateRoot, "4")), false);
  for (const id of [1, 2, 3]) assert.ok(fs.existsSync(path.join(privateRoot, String(id))));
  const doc = JSON.parse(fs.readFileSync(path.join(runsRoot, "disclosure.json"), "utf8"));
  assert.equal(doc.schema, "replaycourt.disclosure/v1");
  assert.deepEqual(doc.held, [{ submission_id: 1, waits_for: [2] }, { submission_id: 3, waits_for: [2] }]);
  assert.ok(!fs.existsSync(path.join(runsRoot, "registry")), "the duplicate registry is never published");

  chain[2].status = "paid";
  const second = await publishEvidence(o, get);
  assert.deepEqual(second.moved, [1, 2, 3]);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(runsRoot, "disclosure.json"), "utf8")).held, []);
  assert.deepEqual(fs.readdirSync(privateRoot).sort(), ["registry"]);
});

test("publish never overwrites other evidence that is already public", async () => {
  const repo = fs.mkdtempSync(path.join(tmpRoot, "repo-"));
  const privateRoot = path.join(repo, "runs-private", "testnet", "c.testnet");
  const runsRoot = path.join(repo, "runs", "testnet", "c.testnet");
  privateRun(privateRoot, 1, null, "A\n");
  privateRun(privateRoot, 2, null, "B\n");
  privateRun(runsRoot, 1, null, "A\n"); // the same evidence, published before
  privateRun(runsRoot, 2, null, "other\n");
  const get = async (id: number) => ({ id, program_id: 0, status: "invalid", verdict: null });
  const res = await publishEvidence({ network: "testnet", contractId: "c.testnet", runsRoot, privateRoot }, get);
  assert.deepEqual(res.moved, [1]);
  assert.deepEqual(res.conflicts.map((c) => c.id), [2]);
  assert.equal(fs.readFileSync(path.join(runsRoot, "2", "evidence.json"), "utf8"), "other\n");
  assert.ok(fs.existsSync(path.join(privateRoot, "2")));
});
