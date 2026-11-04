// Worker decisions for each engine outcome, with the chain and the engine mocked.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import type { VerdictInput } from "../src/mapping.ts";
import { commitmentFor, commitmentOf, generateVerifierKeypair, seal } from "../src/seal.ts";
import {
  engineCommand,
  makeEngineRunner,
  parseDuration,
  parseWrapper,
  processPending,
  processSubmission,
  scopeArg,
  withInfraRetries,
  workRoot,
} from "../src/worker.ts";
import type { Disclosure, EngineRunArgs, EngineRunResult, ProgramView, SubmissionView, WorkerContext, WorkerDeps } from "../src/worker.ts";

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "replaycourt-worker-test-"));
after(() => fs.rmSync(tmpRoot, { recursive: true, force: true }));

const kp = generateVerifierKeypair();
const VERIFIER = "verifier.testnet";
const HUNTER = "hunter.testnet";

interface EngineScript {
  exit: number | null;
  verdict?: Record<string, unknown> | null; // written as verdict.json unless null/undefined
}

interface SubSpec {
  id: number;
  program: number;
  report?: string;
  sealed?: string;
  commitment?: string;
  hunter?: string; // the account that submitted (on-chain hunter_id)
  status?: string;
}

function setup(subs: SubSpec[], engine: Record<number, EngineScript>, opts: {
  disclose?: Disclosure; programs?: number[] | null; programList?: ProgramView[];
} = {}) {
  const repoRoot = fs.mkdtempSync(path.join(tmpRoot, "repo-"));
  const ctx: WorkerContext = {
    network: "testnet",
    contractId: "contract.example.testnet",
    verifierId: VERIFIER,
    x25519PrivateKey: kp.privateKey,
    repoRoot,
    runsRoot: path.join(repoRoot, "runs", "testnet", "contract.example.testnet"),
    privateRoot: path.join(repoRoot, "runs-private", "testnet", "contract.example.testnet"),
    disclose: opts.disclose ?? "after-settlement",
    programs: opts.programs === undefined ? null : opts.programs,
  };
  const programIds = [...new Set(subs.map((s) => s.program))];
  const programs: ProgramView[] = opts.programList ?? programIds.map((id) => ({ id, name: `p${id}`, verifier_id: VERIFIER }));
  const views = new Map<number, SubmissionView>();
  const sealedMap = new Map<number, string>();
  for (const s of subs) {
    const report = Buffer.from(s.report ?? `# report ${s.id}\n`);
    const hunter = s.hunter ?? HUNTER;
    views.set(s.id, {
      id: s.id, program_id: s.program, hunter_id: hunter, title: `r${s.id}`,
      commitment: s.commitment ?? commitmentFor(hunter, report), bond: "100", status: s.status ?? "pending",
    });
    sealedMap.set(s.id, s.sealed ?? seal(report, kp.publicKey));
  }
  const posted: { id: number; verdict: VerdictInput }[] = [];
  const engineCalls: (EngineRunArgs & { statuses: Record<string, string> | null })[] = [];
  const calls: string[] = [];
  const deps: WorkerDeps = {
    listPrograms: async () => { calls.push("listPrograms"); return programs; },
    getProgram: async (id) => { calls.push(`getProgram:${id}`); return programs.find((p) => p.id === id) ?? null; },
    // the contract returns pending submissions of one program; the mock returns them unordered
    listPending: async (pid) => {
      calls.push(`listPending:${pid}`);
      return [...views.values()].filter((s) => s.status === "pending" && s.program_id === pid).reverse();
    },
    listSubmissions: async (pid) => [...views.values()].filter((s) => s.program_id === pid),
    getSubmission: async (id) => views.get(id) ?? null,
    getSealed: async (id) => sealedMap.get(id) ?? null,
    postVerdict: async (id, verdict) => {
      posted.push({ id, verdict });
      views.get(id)!.status = verdict.outcome;
      return `tx-${id}`;
    },
    runEngine: async (a): Promise<EngineRunResult> => {
      engineCalls.push({ ...a, statuses: a.statusPath ? JSON.parse(fs.readFileSync(a.statusPath, "utf8")) : null });
      const id = Number(a.reportId.replace("sub-", ""));
      const script = engine[id] ?? { exit: 70 };
      if (script.verdict) fs.writeFileSync(path.join(a.destDir, "verdict.json"), JSON.stringify(script.verdict, null, 2));
      return { exitCode: script.exit, command: ["mock"], durationMs: 1 };
    },
    log: () => {},
  };
  return { ctx, deps, posted, engineCalls, views, calls };
}

const fork = { chain_id: 1, local: false, poc_fork_block: 15725066, declared_block: 15725066 };

function evidencePath(ctx: WorkerContext, id: number): string {
  return path.join(workRoot(ctx), String(id), "evidence.json");
}

function evidenceHash(ctx: WorkerContext, id: number): string {
  return crypto.createHash("sha256").update(fs.readFileSync(evidencePath(ctx, id))).digest("hex");
}

function envelope(ctx: WorkerContext, id: number): Record<string, any> {
  return JSON.parse(fs.readFileSync(evidencePath(ctx, id), "utf8"));
}

test("engine exit 0 -> post valid; evidence.json binds the engine verdict to the submission", async () => {
  const { ctx, deps, posted, engineCalls } = setup([{ id: 1, program: 0 }], {
    1: { exit: 0, verdict: { schema: "replaycourt.verdict/v1", outcome: "valid", severity_hint: { level: "critical" }, fork, fingerprint: { calls: ["a"] }, reasons: ["ok"] } },
  });
  const res = await processPending(ctx, deps);
  assert.equal(res[0].action, "posted");
  assert.equal(posted.length, 1);
  const v = posted[0].verdict;
  assert.equal(v.outcome, "valid");
  assert.equal(v.severity, "critical");
  assert.equal(v.chain_id, 1);
  assert.equal(v.fork_block, "15725066");
  assert.equal(v.evidence_sha256, evidenceHash(ctx, 1));
  assert.equal(v.evidence_uri, "runs/testnet/contract.example.testnet/1/evidence.json");
  const env = envelope(ctx, 1);
  assert.deepEqual(Object.keys(env), ["schema", "network", "contract_id", "program_id", "submission_id", "hunter_id", "commitment", "engine"]);
  assert.equal(env.schema, "replaycourt.evidence/v1");
  assert.deepEqual([env.network, env.contract_id, env.program_id, env.submission_id, env.hunter_id],
    ["testnet", "contract.example.testnet", 0, 1, HUNTER]);
  assert.equal(env.commitment, commitmentFor(HUNTER, Buffer.from("# report 1\n")));
  assert.equal(env.engine.schema, "replaycourt.verdict/v1");
  assert.equal(env.engine.outcome, "valid");
  // engine got the plaintext report, a per-program registry, the on-chain id and the on-chain statuses
  assert.equal(engineCalls[0].reportId, "sub-1");
  assert.match(engineCalls[0].registryPath, /runs-private[\\/]testnet[\\/]contract\.example\.testnet[\\/]registry[\\/]program-0\.jsonl$/);
  assert.deepEqual(engineCalls[0].statuses, { "sub-1": "pending" });
  assert.equal(fs.readFileSync(engineCalls[0].reportPath, "utf8"), "# report 1\n");
  assert.ok(fs.existsSync(path.join(ctx.privateRoot, "1", "worker.json")));
});

test("default disclosure after-settlement: nothing of an unsettled submission lands in runs/", async () => {
  const { ctx, deps } = setup([{ id: 1, program: 0 }], { 1: { exit: 0, verdict: { severity_hint: { level: "high" }, fork } } });
  await processPending(ctx, deps);
  assert.ok(fs.existsSync(path.join(ctx.privateRoot, "1", "evidence.json")));
  assert.ok(fs.existsSync(path.join(ctx.privateRoot, "1", "report.md")));
  assert.ok(fs.existsSync(path.join(ctx.privateRoot, "worker.log.jsonl")));
  assert.equal(fs.existsSync(ctx.runsRoot), false);
});

test("--disclose immediately writes evidence straight into runs/ (demos)", async () => {
  const { ctx, deps, posted } = setup([{ id: 3, program: 0 }], { 3: { exit: 1, verdict: { fork } } }, { disclose: "immediately" });
  await processPending(ctx, deps);
  assert.ok(fs.existsSync(path.join(ctx.runsRoot, "3", "evidence.json")));
  assert.equal(fs.existsSync(ctx.privateRoot), false);
  assert.equal(posted[0].verdict.evidence_uri, "runs/testnet/contract.example.testnet/3/evidence.json");
  assert.equal(posted[0].verdict.evidence_sha256, evidenceHash(ctx, 3));
});

test("engine exit 1 -> post invalid; exit 2 -> post needs_human without severity", async () => {
  const { ctx, deps, posted } = setup([{ id: 1, program: 0 }, { id: 2, program: 0 }], {
    1: { exit: 1, verdict: { outcome: "invalid", severity_hint: { level: "none" }, fork, reasons: ["The PoC test fails on the fork: ERC20: insufficient allowance"] } },
    2: { exit: 2, verdict: { outcome: "needs_human", severity_hint: { level: "high", provisional: true }, fork: { chain_id: 31337, local: true }, reasons: ["Local mode"] } },
  });
  await processPending(ctx, deps);
  assert.deepEqual(posted.map((p) => [p.id, p.verdict.outcome, p.verdict.severity]), [[1, "invalid", null], [2, "needs_human", null]]);
  assert.match(posted[0].verdict.reason, /insufficient allowance/);
  assert.equal(posted[1].verdict.chain_id, 0);
});

test("engine exit 3 -> post duplicate with the numeric id of the earlier, valid submission", async () => {
  const { ctx, deps, posted, engineCalls } = setup([{ id: 1, program: 0 }, { id: 4, program: 0 }], {
    1: { exit: 0, verdict: { severity_hint: { level: "critical" }, fork } },
    4: { exit: 3, verdict: { outcome: "duplicate", verdict: "valid", duplicate: { status: "duplicate", of: "sub-1" }, fork } },
  });
  await processPending(ctx, deps);
  assert.equal(posted[1].id, 4);
  assert.equal(posted[1].verdict.outcome, "duplicate");
  assert.equal(posted[1].verdict.duplicate_of, 1);
  assert.equal(posted[1].verdict.severity, null);
  // The engine run for #4 saw #1 as valid on-chain (updated within the round), so it may be an original.
  assert.deepEqual(engineCalls[1].statuses, { "sub-1": "valid", "sub-4": "pending" });
});

test("duplicate of a later submission is escalated to needs_human", async () => {
  const { ctx, deps, posted } = setup([{ id: 2, program: 0 }], {
    2: { exit: 3, verdict: { duplicate: { status: "duplicate", of: "sub-5" }, fork } },
  });
  await processPending(ctx, deps);
  assert.equal(posted[0].verdict.outcome, "needs_human");
});

test("duplicate of an original that is not valid/paid/disputed on-chain is escalated to needs_human", async () => {
  // #1 was valid when the engine registered it, but the owner overruled it (rejected); the contract
  // would refuse duplicate_of = 1 and the program's queue would stall.
  const { ctx, deps, posted } = setup([{ id: 1, program: 0, status: "rejected" }, { id: 2, program: 0 }], {
    2: { exit: 3, verdict: { outcome: "duplicate", verdict: "valid", duplicate: { status: "duplicate", of: "sub-1" }, fork } },
  });
  await processPending(ctx, deps);
  assert.equal(posted.length, 1);
  assert.equal(posted[0].verdict.outcome, "needs_human");
  assert.equal(posted[0].verdict.duplicate_of, null);
  assert.match(posted[0].verdict.reason, /duplicate of submission 1, which is 'rejected' on-chain/);
  for (const ok of ["valid", "paid", "disputed"]) {
    const s = setup([{ id: 1, program: 0, status: ok }, { id: 2, program: 0 }], {
      2: { exit: 3, verdict: { duplicate: { status: "duplicate", of: "sub-1" }, fork } },
    });
    await processPending(s.ctx, s.deps);
    assert.equal(s.posted[0].verdict.outcome, "duplicate", ok);
  }
});

test("engine exit 69 -> nothing posted, later submissions of the same program wait, other programs go on", async () => {
  const { ctx, deps, posted, engineCalls } = setup(
    [{ id: 1, program: 0 }, { id: 2, program: 0 }, { id: 3, program: 1 }],
    { 1: { exit: 69, verdict: { outcome: null } }, 2: { exit: 0, verdict: { severity_hint: { level: "low" }, fork } }, 3: { exit: 1, verdict: { fork } } },
  );
  const res = await processPending(ctx, deps);
  assert.deepEqual(res.map((r) => [r.id, r.action]), [[1, "retry"], [2, "deferred"], [3, "posted"]]);
  assert.deepEqual(posted.map((p) => p.id), [3]);
  assert.deepEqual(engineCalls.map((c) => c.reportId), ["sub-1", "sub-3"]);
  const log = fs.readFileSync(path.join(ctx.privateRoot, "worker.log.jsonl"), "utf8");
  assert.match(log, /"action":"retry"/);
});

test("engine exit 70 (and 64/65) -> nothing posted", async () => {
  for (const code of [70, 64, 65]) {
    const { ctx, deps, posted } = setup([{ id: 1, program: 0 }], { 1: { exit: code, verdict: { outcome: null } } });
    const res = await processPending(ctx, deps);
    assert.equal(res[0].action, "retry", `exit ${code}`);
    assert.equal(posted.length, 0, `exit ${code}`);
  }
});

test("memory/time cap (137/124) without verdict.json -> needs_human with a worker verdict inside the envelope", async () => {
  const { ctx, deps, posted } = setup([{ id: 1, program: 0 }], { 1: { exit: 137 } });
  await processPending(ctx, deps);
  assert.equal(posted[0].verdict.outcome, "needs_human");
  assert.equal(posted[0].verdict.evidence_sha256, evidenceHash(ctx, 1));
  assert.match(posted[0].verdict.reason, /memory limit/);
  assert.equal(envelope(ctx, 1).engine.schema, "replaycourt.worker-verdict/v1");
});

test("commitment mismatch -> invalid 'sealed report does not match commitment', engine not run", async () => {
  const wrong = commitmentFor(HUNTER, Buffer.from("something else"));
  const { ctx, deps, posted, engineCalls } = setup([{ id: 1, program: 0, commitment: wrong }], {});
  await processPending(ctx, deps);
  assert.equal(engineCalls.length, 0);
  assert.equal(posted[0].verdict.outcome, "invalid");
  assert.equal(posted[0].verdict.reason, "sealed report does not match commitment");
  assert.equal(posted[0].verdict.evidence_sha256, evidenceHash(ctx, 1));
  const env = envelope(ctx, 1);
  assert.equal(env.schema, "replaycourt.evidence/v1");
  assert.equal(env.commitment, wrong);
  assert.equal(env.engine.schema, "replaycourt.worker-verdict/v1");
  assert.match(env.engine.detail, /commitment mismatch/);
});

test("S2: a sealed blob and commitment copied to another account are judged invalid", async () => {
  // The victim's submission (or a failed transaction) shows `sealed` and `commitment` publicly.
  // A copycat submits both from their own account, hoping to take the victim's place in line.
  const report = Buffer.from("# the victim's real finding\n");
  const commitment = commitmentFor("victim.testnet", report);
  const sealed = seal(report, kp.publicKey);
  const { ctx, deps, posted, engineCalls } = setup([
    { id: 7, program: 0, hunter: "copycat.testnet", commitment, sealed },
  ], {});
  await processPending(ctx, deps);
  assert.equal(engineCalls.length, 0, "the copied report is never run");
  assert.equal(posted.length, 1);
  assert.equal(posted[0].verdict.outcome, "invalid");
  assert.equal(posted[0].verdict.reason, "sealed report does not match commitment");
  const env = envelope(ctx, 7);
  assert.equal(env.hunter_id, "copycat.testnet");
  assert.match(env.engine.detail, /commitment v2 for copycat\.testnet/);
  // The same blob from the account it was committed for is accepted.
  const own = setup([{ id: 8, program: 0, hunter: "victim.testnet", commitment, sealed }], { 8: { exit: 1, verdict: { fork } } });
  await processPending(own.ctx, own.deps);
  assert.equal(own.engineCalls.length, 1);
});

test("a v1 commitment (sha256 of the report) is not accepted by the v2 worker", async () => {
  const report = Buffer.from("# report\n");
  const { ctx, deps, posted, engineCalls } = setup([{ id: 1, program: 0, report: "# report\n", commitment: commitmentOf(report) }], {});
  await processPending(ctx, deps);
  assert.equal(engineCalls.length, 0);
  assert.equal(posted[0].verdict.reason, "sealed report does not match commitment");
});

test("report sealed to another key -> invalid with the same reason", async () => {
  const other = generateVerifierKeypair();
  const report = Buffer.from("# report\n");
  const { ctx, deps, posted, engineCalls } = setup(
    [{ id: 1, program: 0, report: "# report\n", sealed: seal(report, other.publicKey) }], {});
  await processPending(ctx, deps);
  assert.equal(engineCalls.length, 0);
  assert.equal(posted[0].verdict.outcome, "invalid");
  assert.equal(posted[0].verdict.reason, "sealed report does not match commitment");
});

test("a submission that is no longer pending is not posted twice", async () => {
  const { ctx, deps, posted, views } = setup([{ id: 1, program: 0 }], { 1: { exit: 1, verdict: { fork } } });
  const sub = views.get(1)!;
  const realGet = deps.getSubmission;
  deps.getSubmission = async (id) => ({ ...(await realGet(id))!, status: "invalid" });
  const r = await processSubmission(ctx, deps, sub);
  assert.equal(r.action, "skipped");
  assert.equal(posted.length, 0);
});

test("allow-list: only the listed programs, each must name this verifier; list_programs is not read", async () => {
  const programList: ProgramView[] = [
    { id: 0, name: "mine", verifier_id: VERIFIER },
    { id: 1, name: "mine too, not listed", verifier_id: VERIFIER },
    { id: 2, name: "someone else's", verifier_id: "other.testnet" },
  ];
  const { ctx, deps, posted, calls } = setup(
    [{ id: 1, program: 0 }, { id: 2, program: 1 }, { id: 3, program: 2 }],
    { 1: { exit: 1, verdict: { fork } }, 2: { exit: 1, verdict: { fork } }, 3: { exit: 1, verdict: { fork } } },
    { programs: [2, 0, 9], programList },
  );
  const lines: string[] = [];
  deps.log = (l) => lines.push(l);
  await processPending(ctx, deps);
  assert.deepEqual(posted.map((p) => p.id), [1]);
  assert.ok(!calls.includes("listPrograms"));
  assert.deepEqual(calls.filter((c) => c.startsWith("listPending")), ["listPending:0"]);
  assert.ok(lines.some((l) => /program 2 \(allow-list\): its verifier is other\.testnet/.test(l)));
  assert.ok(lines.some((l) => /program 9 \(allow-list\): not found/.test(l)));
});

test("no allow-list: every program whose verifier_id is this verifier, list_pending per program", async () => {
  const programList: ProgramView[] = [
    { id: 0, name: "a", verifier_id: VERIFIER },
    { id: 1, name: "b", verifier_id: "other.testnet" },
    { id: 2, name: "c", verifier_id: VERIFIER },
  ];
  const { ctx, deps, posted, calls } = setup(
    [{ id: 5, program: 2 }, { id: 1, program: 0 }, { id: 3, program: 1 }],
    { 1: { exit: 1, verdict: { fork } }, 3: { exit: 1, verdict: { fork } }, 5: { exit: 1, verdict: { fork } } },
    { programList },
  );
  await processPending(ctx, deps);
  assert.deepEqual(posted.map((p) => p.id), [1, 5]);
  assert.deepEqual(calls.filter((c) => c.startsWith("listPending")), ["listPending:0", "listPending:2"]);
});

test("withInfraRetries re-runs the engine only after exit 69, up to the limit", async () => {
  const args: EngineRunArgs = { reportPath: "r", registryPath: "g", reportId: "sub-1", destDir: "d" };
  let calls = 0;
  const flaky = withInfraRetries(async () => ({ exitCode: ++calls < 3 ? 69 : 0, command: [], durationMs: 0 }), 2, 1, () => {});
  assert.equal((await flaky(args)).exitCode, 0);
  assert.equal(calls, 3);
  calls = 0;
  const down = withInfraRetries(async () => ({ exitCode: (++calls, 69), command: [], durationMs: 0 }), 2, 1, () => {});
  assert.equal((await down(args)).exitCode, 69);
  assert.equal(calls, 3);
  calls = 0;
  const invalid = withInfraRetries(async () => ({ exitCode: (++calls, 1), command: [], durationMs: 0 }), 2, 1, () => {});
  assert.equal((await invalid(args)).exitCode, 1);
  assert.equal(calls, 1);
});

test("function-call key allowance used up -> nothing posted, retried later, later submissions of the program wait", async () => {
  const { ctx, deps, posted } = setup(
    [{ id: 1, program: 0 }, { id: 2, program: 0 }, { id: 3, program: 1 }],
    { 1: { exit: 1, verdict: { fork } }, 2: { exit: 1, verdict: { fork } }, 3: { exit: 1, verdict: { fork } } },
  );
  class AccessKeyNotEnoughAllowanceActionError extends Error {}
  const realPost = deps.postVerdict;
  deps.postVerdict = async (id, verdict) => {
    if (id === 1) {
      throw new AccessKeyNotEnoughAllowanceActionError("Not enough allowance for access key ed25519:x (allowance: 1, cost: 100920854672762000000000)");
    }
    return realPost(id, verdict);
  };
  const res = await processPending(ctx, deps);
  assert.deepEqual(res.map((r) => [r.id, r.action]), [[1, "retry"], [2, "deferred"], [3, "posted"]]);
  assert.deepEqual(posted.map((p) => p.id), [3]);
  const log = fs.readFileSync(path.join(ctx.privateRoot, "worker.log.jsonl"), "utf8");
  assert.match(log, /Not enough allowance/);
});

test("REPLAYCOURT_ENGINE_WRAPPER parsing and the engine command line", () => {
  assert.equal(parseWrapper(undefined), null);
  assert.equal(parseWrapper("   "), null);
  assert.deepEqual(parseWrapper(" python3 /opt/cap.py --limit 4G --timeout 30m -- "), ["python3", "/opt/cap.py", "--limit", "4G", "--timeout", "30m", "--"]);
  const a: EngineRunArgs = { reportPath: "/r/report.md", registryPath: "/r/reg.jsonl", statusPath: "/r/st.json", reportId: "sub-4", destDir: "/r/4" };
  const cmd = engineCommand("python3", "/repo", a);
  assert.deepEqual(cmd.slice(0, 5), ["python3", "-I", path.join("/repo", "engine", "replay.py"), "check", "/r/report.md"]);
  assert.deepEqual(cmd.slice(cmd.indexOf("--onchain-status"), cmd.indexOf("--onchain-status") + 2), ["--onchain-status", "/r/st.json"]);
  assert.ok(!engineCommand("python3", "/repo", { ...a, statusPath: null }).includes("--onchain-status"));
  assert.equal(parseDuration("30m"), 1800);
  assert.equal(parseDuration("2h"), 7200);
  assert.equal(parseDuration("45"), 45);
});

test("the engine runs with TZ=UTC, behind the configured wrapper", async () => {
  const dir = fs.mkdtempSync(path.join(tmpRoot, "runner-"));
  const fake = path.join(dir, "wrapper.mjs");
  fs.writeFileSync(fake, `import fs from "node:fs";
const argv = process.argv.slice(2);
fs.writeFileSync(${JSON.stringify(path.join(dir, "seen.json"))}, JSON.stringify({ argv, tz: process.env.TZ }));
process.exit(3);\n`);
  const run = makeEngineRunner({ repoRoot: dir, python: "python3", wrapper: [process.execPath, fake], timeout: "60s" });
  const res = await run({ reportPath: "/x/report.md", registryPath: "/x/reg.jsonl", reportId: "sub-9", destDir: dir });
  assert.equal(res.exitCode, 3);
  const seen = JSON.parse(fs.readFileSync(path.join(dir, "seen.json"), "utf8"));
  assert.equal(seen.tz, "UTC");
  assert.deepEqual(seen.argv.slice(0, 4), ["python3", "-I", path.join(dir, "engine", "replay.py"), "check"]);
  assert.deepEqual(res.command.slice(0, 2), [process.execPath, fake]);
});

test("without a wrapper the worker's own time limit ends the run (exit 124)", { skip: process.platform === "win32" }, async () => {
  const dir = fs.mkdtempSync(path.join(tmpRoot, "slow-"));
  const slow = path.join(dir, "slow.sh");
  fs.writeFileSync(slow, "#!/bin/sh\nsleep 30\n", { mode: 0o755 });
  const run = makeEngineRunner({ repoRoot: dir, python: slow, wrapper: null, timeout: "1s" });
  const started = Date.now();
  const res = await run({ reportPath: "r", registryPath: "g", reportId: "sub-1", destDir: dir });
  assert.equal(res.exitCode, 124);
  assert.ok(Date.now() - started < 10_000);
});

test("the program's scope and the first accepted block reach the engine", () => {
  const scope = scopeArg({ id: 0, name: "p", verifier_id: "v", scope: [{ chain_id: 1, address: "0xaa" }, { chain_id: 8453, address: "0xbb" }] });
  assert.equal(scope, "1:0xaa,8453:0xbb");
  assert.equal(scopeArg({ id: 0, name: "p", verifier_id: "v", scope: [] }), null);
  assert.equal(scopeArg({ id: 0, name: "p", verifier_id: "v" }), null);
  const base = { reportPath: "r.md", registryPath: "reg", reportId: "sub-1", destDir: "d" };
  const cmd = engineCommand("python3", "/repo", { ...base, scope, minBlock: 0 });
  assert.deepEqual(cmd.slice(cmd.indexOf("--scope")), ["--scope", scope, "--min-block", "0"]);
  const plain = engineCommand("python3", "/repo", base);
  assert.ok(!plain.includes("--scope") && !plain.includes("--min-block"));
});
