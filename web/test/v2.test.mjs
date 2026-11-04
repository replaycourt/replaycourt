// Protocol v2 helpers of the explorer: version detection, the evidence envelope binding check, the
// runs/ path restriction and the "private until settlement" state. The rules mirror
// `verify-onchain` (agent/src/verify.ts). Run from the repository root: node --test web/test/*.test.mjs
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  EVIDENCE_FAILURES,
  assessEvidence,
  bindingCheck,
  commitmentOf,
  evidenceFiles,
  evidenceUrl,
  statusMeaning,
  fmtLeft,
  heldWaitsFor,
  isFinal,
  protocolMajor,
  sha256Hex,
  vaultWindow,
} from "../lib.js";

const enc = (o) => new TextEncoder().encode(JSON.stringify(o, null, 2) + "\n");
const CONTRACT = "contract.example.testnet";
const CTX2 = { network: "testnet", contractId: CONTRACT, major: 2 };
const CTX1 = { network: "testnet", contractId: "contract.v1-example.testnet", major: 1 };
const COMMIT = "b224d23adfc3cafc2040041466d39a86b4d77ecb417bce1a13d3ee1623a4db11";

/** An on-chain submission as get_submission returns it, with a verdict whose hash is that of `bytes`. */
async function submission(bytes, over = {}) {
  return {
    id: 1,
    program_id: 0,
    hunter_id: "hunter1.example.testnet",
    commitment: COMMIT,
    status: "paid",
    verdict: { outcome: "valid", severity: "critical", evidence_sha256: bytes ? await sha256Hex(bytes) : "ab".repeat(32), evidence_uri: `runs/testnet/${CONTRACT}/1/evidence.json` },
    ...over,
  };
}
const envelope = (over = {}) => ({
  schema: "replaycourt.evidence/v1",
  network: "testnet",
  contract_id: CONTRACT,
  program_id: 0,
  submission_id: 1,
  hunter_id: "hunter1.example.testnet",
  commitment: COMMIT,
  engine: { schema: "replaycourt.verdict/v1", outcome: "valid", poc: { copy: "PoC.t.sol" } },
  ...over,
});

test("version(): 1.0.x is protocol v1, 2.0.0 is v2, anything unknown gets the strict v2 rules", () => {
  assert.equal(protocolMajor("1.0.0"), 1);
  assert.equal(protocolMajor("1.0.1"), 1);
  assert.equal(protocolMajor("2.0.0"), 2);
  for (const unknown of [null, undefined, "", "?", "v1", "1", "1.0", "<b>1.0.1</b>", 2]) assert.equal(protocolMajor(unknown), 2, String(unknown));
});

test("evidence URIs: only paths below runs/, nothing that a URL parser could lift out of it", () => {
  const page = "http://127.0.0.1:8000/web/index.html";
  assert.equal(evidenceUrl(`runs/testnet/${CONTRACT}/1/evidence.json`, "../", page).href, `http://127.0.0.1:8000/runs/testnet/${CONTRACT}/1/evidence.json`);
  assert.equal(evidenceUrl("runs/testnet/c/1/evidence.json", "https://raw.example/o/r/main/", page).href, "https://raw.example/o/r/main/runs/testnet/c/1/evidence.json");
  const refused = [
    "https://evidence.example/runs/x/evidence.json", "//evil.example/runs/x", "runs", "runs/", "runsx/a.json", "docs/x.json",
    "./runs/a.json", "runs/./a.json", "runs/../web/app.js", "runs/a/../../x", "runs/%2e%2e/%2e%2e/secret", "runs/%2E%2E/x",
    "runs//x.json", "runs/.git/config", "runs/a\\..\\..\\x", "runs/a b.json", "runs/a.json?x=1", "runs/a.json#f",
    "runs/a\u0000.json", "/runs/a.json", "RUNS/a.json", `runs/${"a".repeat(260)}`,
  ];
  for (const bad of refused) assert.equal(evidenceUrl(bad, "../", page), null, JSON.stringify(bad));
  assert.equal(evidenceUrl("runs/a.json", "data:text/plain,", page), null, "a non-http base is refused");
});

test("v2 envelope: hash and every binding field are checked against the on-chain submission", async () => {
  const bytes = enc(envelope());
  const ok = await assessEvidence(await submission(bytes), CTX2, { bytes });
  assert.equal(ok.state, "ok");
  assert.equal(ok.mode, "v2");
  assert.deepEqual(ok.checks.map((c) => [c.field, c.ok]), [["sha256", true], ["network", true], ["contract_id", true], ["program_id", true], ["submission_id", true], ["hunter_id", true], ["commitment", true]]);

  // The same, correctly hashed envelope shown for another submission (copied evidence) is unbound.
  const other = await assessEvidence(await submission(bytes, { id: 2, hunter_id: "hunter2.example.testnet" }), CTX2, { bytes });
  assert.equal(other.state, "unbound");
  assert.deepEqual(other.checks.filter((c) => !c.ok).map((c) => c.field), ["submission_id", "hunter_id"]);
  assert.ok(EVIDENCE_FAILURES.includes(other.state));

  // Types count: "0" is not 0, and a missing field is not equal to anything.
  const s = await submission(null);
  const typed = bindingCheck({ ...envelope(), program_id: "0", commitment: undefined }, s, CTX2);
  assert.deepEqual(typed.filter((c) => !c.ok).map((c) => c.field), ["program_id", "commitment"]);
  // Another deployment or network is unbound too.
  assert.equal(bindingCheck(envelope(), s, { ...CTX2, contractId: "contract.v1-example.testnet" }).find((c) => c.field === "contract_id").ok, false);
  assert.equal(bindingCheck(envelope(), s, { ...CTX2, network: "mainnet" }).find((c) => c.field === "network").ok, false);
});

test("hash mismatch, and the v1 mode: hash only from a v1 contract, refused from a v2 contract", async () => {
  const bytes = enc(envelope());
  const tampered = await assessEvidence(await submission(enc(envelope({ submission_id: 9 }))), CTX2, { bytes });
  assert.equal(tampered.state, "mismatch");
  assert.equal(tampered.checks[0].ok, false);

  const verdict = enc({ schema: "replaycourt.verdict/v1", outcome: "valid", poc: { copy: "PoC.t.sol" } });
  const v1sub = await submission(verdict, { verdict: { outcome: "valid", evidence_sha256: await sha256Hex(verdict), evidence_uri: "runs/testnet/contract.v1-example.testnet/0/verdict.json" } });
  const v1 = await assessEvidence(v1sub, CTX1, { bytes: verdict });
  assert.deepEqual([v1.state, v1.mode], ["ok", "v1"]);
  const strict = await assessEvidence(v1sub, CTX2, { bytes: verdict });
  assert.deepEqual([strict.state, strict.mode], ["unbound", "v1"]);
  // An envelope is checked for its binding whatever the contract version.
  const env1 = await assessEvidence(await submission(bytes, { id: 7 }), CTX1, { bytes });
  assert.deepEqual([env1.state, env1.mode], ["unbound", "v2"]);
  // On-chain hash that is not 64 hex characters never matches.
  const badHash = await assessEvidence(await submission(bytes, { verdict: { evidence_sha256: "", evidence_uri: "runs/a/evidence.json" } }), CTX2, { bytes });
  assert.equal(badHash.state, "mismatch");
});

test("private until settlement: a missing file is fine while the submission is not final", async () => {
  const s = await submission(null);
  for (const status of ["pending", "valid", "needs_human", "disputed"]) {
    const r = await assessEvidence({ ...s, status }, CTX2, { notFound: true });
    assert.equal(r.state, "undisclosed", status);
    assert.ok(!EVIDENCE_FAILURES.includes(r.state));
    assert.equal(isFinal(status), false);
  }
  for (const status of ["paid", "invalid", "duplicate", "rejected", "expired", "withdrawn"]) {
    assert.equal(isFinal(status), true);
    const r = await assessEvidence({ ...s, status }, CTX2, { notFound: true });
    assert.equal(r.state, "missing", status);
    assert.ok(EVIDENCE_FAILURES.includes(r.state));
  }
  // Final, but held back by `publish` for a related submission that is not final yet.
  const held = await assessEvidence({ ...s, status: "duplicate" }, CTX2, { notFound: true, heldBy: ["#1 (valid)"] });
  assert.deepEqual([held.state, held.held], ["undisclosed", true]);
  assert.match(held.detail, /#1 \(valid\)/);
  // A load error is not "private", nor is a refused location; no verdict means nothing to check.
  assert.equal((await assessEvidence({ ...s, status: "valid" }, CTX2, { error: "HTTP 500" })).state, "missing");
  assert.equal((await assessEvidence(s, CTX2, { refused: true })).state, "refused");
  assert.equal((await assessEvidence({ ...s, verdict: null }, CTX2, {})).state, "no-verdict");
});

test("disclosure.json: which ids a held-back submission waits for", () => {
  const doc = { schema: "replaycourt.disclosure/v1", held: [{ submission_id: 2, waits_for: [1, "x", 0] }] };
  assert.deepEqual(heldWaitsFor(doc, 2), [1, 0]);
  assert.equal(heldWaitsFor(doc, 3), null);
  assert.equal(heldWaitsFor({ ...doc, schema: "other" }, 2), null);
  assert.equal(heldWaitsFor(null, 2), null);
});

test("raw file links work for the envelope layout and the v1 layout", () => {
  const page = "http://127.0.0.1:8000/web/";
  const u2 = evidenceUrl("runs/testnet/c/1/evidence.json", "../", page);
  assert.deepEqual(evidenceFiles(u2, envelope()).map(([n, u]) => [n, u.href]), [
    ["evidence.json", "http://127.0.0.1:8000/runs/testnet/c/1/evidence.json"],
    ["summary.md", "http://127.0.0.1:8000/runs/testnet/c/1/summary.md"],
    ["report.md", "http://127.0.0.1:8000/runs/testnet/c/1/report.md"],
    ["PoC.t.sol", "http://127.0.0.1:8000/runs/testnet/c/1/PoC.t.sol"],
    ["verdict.json", "http://127.0.0.1:8000/runs/testnet/c/1/verdict.json"],
  ]);
  const u1 = evidenceUrl("runs/testnet/c/0/verdict.json", "../", page);
  assert.deepEqual(evidenceFiles(u1, { schema: "replaycourt.verdict/v1", poc: { copy: "PoC.t.sol" } }).map(([n]) => n), ["verdict.json", "summary.md", "report.md", "PoC.t.sol"]);
  // The engine did not run (worker verdict): only the evidence file. A hostile PoC name is dropped.
  assert.deepEqual(evidenceFiles(u2, envelope({ engine: { schema: "replaycourt.worker-verdict/v1" } })).map(([n]) => n), ["evidence.json"]);
  assert.deepEqual(evidenceFiles(u2, envelope({ engine: { schema: "replaycourt.verdict/v1", poc: { copy: "../../web/app.js" } } })).map(([n]) => n), ["evidence.json", "summary.md", "report.md", "verdict.json"]);
});

test("commitment: v2 is bound to the hunter account, v1 is the plain sha256 of the report", async () => {
  const report = new TextEncoder().encode("hello report\n");
  assert.equal(await commitmentOf(report, "alice.testnet", 2), "91d3f6877fcfed42755de50d2c4cf0a4436ea9c789356206fb9eb59f1477f072");
  assert.equal(await commitmentOf(report, "alice.testnet", 1), "60554760d6fc3857aedf174a08e106125383b42c1143b67405f1f99e146986d7");
  assert.notEqual(await commitmentOf(report, "mallory.testnet", 2), await commitmentOf(report, "alice.testnet", 2));
});

test("deadlines and the vault's 24 h window", () => {
  const now = 1_793_635_000_000; // ms
  const ns = (ms) => (BigInt(ms) * 1_000_000n).toString();
  assert.equal(fmtLeft(ns(now + 45_000), now), "in 45 s");
  assert.equal(fmtLeft(ns(now + 185_000), now), "in 3 min 05 s");
  assert.equal(fmtLeft(ns(now + 2 * 3600_000 + 600_000), now), "in 2 h 10 min");
  assert.equal(fmtLeft(ns(now), now), "passed");
  assert.equal(fmtLeft(ns(now - 1), now), "passed");
  assert.equal(fmtLeft("garbage", now), "?");
  const vault = { window_start: ns(now - 3600_000), spent_in_window: "182050000000000000000000" };
  assert.deepEqual(vaultWindow(vault, now), { running: true, end: ns(now + 23 * 3600_000), spent: "182050000000000000000000", lastSpent: "182050000000000000000000" });
  const old = vaultWindow({ ...vault, window_start: ns(now - 25 * 3600_000) }, now);
  assert.deepEqual([old.running, old.spent, old.lastSpent], [false, "0", "182050000000000000000000"]);
  assert.equal(vaultWindow({ window_start: "0", spent_in_window: "0" }, now).running, false);
});

test("statusMeaning explains every status in plain words, and a rejection by how it came about", () => {
  for (const status of ["pending", "valid", "paid", "invalid", "duplicate", "needs_human", "disputed", "expired", "withdrawn"]) {
    assert.ok(statusMeaning({ status }).length > 20, status);
  }
  assert.match(statusMeaning({ status: "rejected", dispute_bond: "100" }), /got the deposit back plus/);
  assert.match(statusMeaning({ status: "rejected", dispute_bond: "0" }), /lost the deposit/);
  assert.match(statusMeaning({ status: "rejected", dispute_bond: "not a number" }), /lost the deposit/);
  assert.equal(statusMeaning({ status: "constructor" }), "");
  assert.equal(statusMeaning({ status: 7 }), "");
  assert.equal(statusMeaning(null), "");
});
