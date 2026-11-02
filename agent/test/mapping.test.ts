import assert from "node:assert/strict";
import { test } from "node:test";
import {
  COMMITMENT_MISMATCH_REASON,
  actionForExit,
  buildVerdict,
  commitmentMismatchVerdict,
  fingerprintId,
  mapSeverity,
  parseSubmissionRef,
  truncateBytes,
} from "../src/mapping.ts";

test("severity mapping per SPEC: critical->critical, high->high, medium->medium, anything lower->low", () => {
  const table: [string | null | undefined, string][] = [
    ["critical", "critical"], ["provisional critical", "critical"],
    ["high", "high"], ["provisional high", "high"], ["HIGH", "high"],
    ["medium", "medium"],
    ["low", "low"], ["none", "low"], ["unclear", "low"],
    [null, "low"], [undefined, "low"], ["", "low"],
  ];
  for (const [input, want] of table) assert.equal(mapSeverity(input), want, `mapSeverity(${String(input)})`);
});

test("exit code mapping per SPEC", () => {
  assert.deepEqual(actionForExit(0), { kind: "post", outcome: "valid" });
  assert.deepEqual(actionForExit(1), { kind: "post", outcome: "invalid" });
  assert.deepEqual(actionForExit(2), { kind: "post", outcome: "needs_human" });
  assert.deepEqual(actionForExit(3), { kind: "post", outcome: "duplicate" });
  for (const code of [64, 65, 69, 70, 5, 255, null]) {
    assert.equal(actionForExit(code).kind, "retry", `exit ${String(code)} must not post`);
  }
  assert.deepEqual(actionForExit(124), { kind: "post", outcome: "needs_human" });
  assert.deepEqual(actionForExit(137), { kind: "post", outcome: "needs_human" });
});

test("helpers: submission refs, char truncation, fingerprint id", () => {
  assert.equal(parseSubmissionRef("sub-12"), 12);
  assert.equal(parseSubmissionRef("sub-0"), 0);
  assert.equal(parseSubmissionRef("01-templedao-stax"), null);
  assert.equal(parseSubmissionRef(null), null);
  const long = "é".repeat(400);
  // 2-byte characters: 139 of them plus the 3-byte ellipsis = 281 bytes would be too many, so 138.
  assert.equal(Buffer.byteLength(truncateBytes(long, 280)), 279);
  assert.equal(Array.from(truncateBytes(long, 280)).length, 139);
  // ASCII text that needs cutting: exactly the limit, with the 3-byte ellipsis counted.
  assert.equal(Buffer.byteLength(truncateBytes("x".repeat(400), 280)), 280);
  assert.equal(truncateBytes("x".repeat(280), 280), "x".repeat(280));
  assert.equal(truncateBytes("short", 280), "short");
  const fp = { chain: "ethereum", calls: ["0xa:0x1"], losers: ["0xb"], gain_assets: [] };
  assert.match(fingerprintId(fp), /^[0-9a-f]{64}$/);
  assert.equal(fingerprintId(fp), fingerprintId({ losers: ["0xb"], gain_assets: [], calls: ["0xa:0x1"], chain: "ethereum" }));
  assert.equal(fingerprintId(null), "");
});

const SHA = "a".repeat(64);
const base = { evidenceSha256: SHA, evidenceUri: "runs/testnet/c/7/verdict.json" };

test("buildVerdict: valid carries severity, chain and fork block", () => {
  const v = buildVerdict({
    ...base, submissionId: 7, exitCode: 0,
    verdict: {
      severity_hint: { level: "critical", provisional: false },
      fork: { chain_id: 1, local: false, poc_fork_block: 15725066, declared_block: 15725066 },
      fingerprint: { chain: "ethereum", calls: ["x"], losers: ["y"] },
      reasons: ["PoC test passes on the fork.", "Real outflow of value."],
    },
  }, "valid");
  assert.equal(v.outcome, "valid");
  assert.equal(v.severity, "critical");
  assert.equal(v.duplicate_of, null);
  assert.equal(v.chain_id, 1);
  assert.equal(v.fork_block, "15725066");
  assert.equal(v.evidence_sha256, SHA);
  assert.match(v.fingerprint, /^[0-9a-f]{64}$/);
  assert.ok(Buffer.byteLength(v.reason) <= 280);
  const noLevel = buildVerdict({ ...base, submissionId: 7, exitCode: 0, verdict: {} }, "valid");
  assert.equal(noLevel.severity, "low");
});

test("buildVerdict: local runs report chain 0 / block 0; non-valid outcomes carry no severity", () => {
  const v = buildVerdict({
    ...base, submissionId: 3, exitCode: 2,
    verdict: { severity_hint: { level: "high", provisional: true }, fork: { chain_id: 31337, local: true }, reasons: ["r".repeat(500)] },
  }, "needs_human");
  assert.equal(v.outcome, "needs_human");
  assert.equal(v.severity, null);
  assert.equal(v.chain_id, 0);
  assert.equal(v.fork_block, "0");
  assert.equal(Buffer.byteLength(v.reason), 280);
});

test("buildVerdict: duplicate maps sub-<n> to duplicate_of and refuses later or unknown originals", () => {
  const dup = buildVerdict({ ...base, submissionId: 4, exitCode: 3, verdict: { duplicate: { status: "duplicate", of: "sub-1" } } }, "duplicate");
  assert.equal(dup.outcome, "duplicate");
  assert.equal(dup.duplicate_of, 1);
  assert.match(dup.reason, /duplicate of submission 1/);
  const later = buildVerdict({ ...base, submissionId: 2, exitCode: 3, verdict: { duplicate: { status: "duplicate", of: "sub-5" } } }, "duplicate");
  assert.equal(later.outcome, "needs_human");
  assert.equal(later.duplicate_of, null);
  const foreign = buildVerdict({ ...base, submissionId: 9, exitCode: 3, verdict: { duplicate: { status: "duplicate", of: "01-templedao-stax" } } }, "duplicate");
  assert.equal(foreign.outcome, "needs_human");
});

test("commitment mismatch verdict is invalid with the SPEC reason", () => {
  const v = commitmentMismatchVerdict(SHA, "runs/x/verdict.json");
  assert.equal(v.outcome, "invalid");
  assert.equal(v.reason, COMMITMENT_MISMATCH_REASON);
  assert.equal(v.reason, "sealed report does not match commitment");
  assert.equal(v.severity, null);
});
