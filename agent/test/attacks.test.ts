// Helpers of the attack demos (demo/attacks/): tampered seal, error normalization.
import assert from "node:assert/strict";
import { test } from "node:test";
import { describeTxError, panicText, tamperedSubmission } from "../src/attacks.ts";
import { COMMITMENT_MISMATCH_REASON, commitmentMismatchVerdict } from "../src/mapping.ts";
import { commitmentFor, generateVerifierKeypair, openAndCheck, unseal } from "../src/seal.ts";

test("tamperedSubmission commits to one file and seals another; the worker check refuses it", () => {
  const kp = generateVerifierKeypair();
  const hunter = "hunter2.example.testnet";
  const committed = Buffer.from("# placeholder\n");
  const real = Buffer.from("# someone else's valid report\n```solidity\n...\n```\n");
  const t = tamperedSubmission(committed, real, kp.publicKey, hunter);
  assert.equal(t.commitment, commitmentFor(hunter, committed));
  assert.equal(t.sealedPlaintextCommitment, commitmentFor(hunter, real));
  assert.notEqual(t.commitment, t.sealedPlaintextCommitment);
  // The blob itself is a valid seal of the other file ...
  assert.deepEqual(unseal(t.sealed, kp.privateKey), real);
  // ... but it does not match the on-chain commitment, so the worker posts invalid.
  const r = openAndCheck(t.sealed, kp.privateKey, t.commitment, hunter);
  assert.equal(r.ok, false);
  if (!r.ok) assert.match(r.error, /commitment mismatch/);
  assert.equal(commitmentMismatchVerdict("ab".repeat(32), "x").reason, COMMITMENT_MISMATCH_REASON);
});

test("describeTxError: access-key refusals are 'before inclusion', contract panics are not", () => {
  class RequiresFullAccessActionError extends Error {}
  const refused = describeTxError(new RequiresFullAccessActionError("The transaction contains an action that requires a full access key"));
  assert.equal(refused.kind, "RequiresFullAccessActionError");
  assert.equal(refused.rejectedBeforeInclusion, true);
  assert.equal(refused.txHash, null);

  const typed = describeTxError({ type: "MethodNameMismatch", message: "Method name withdraw_pool isn't allowed" });
  assert.equal(typed.kind, "MethodNameMismatch");

  const hash = "11111111111111111111111111111111111111111111";
  const panic = describeTxError({ message: "Smart contract panicked: only the program verifier can post verdicts", txHash: hash });
  assert.equal(panic.txHash, hash);
  assert.equal(panic.rejectedBeforeInclusion, false);

  assert.equal(refused.transport, false);
  // network trouble is not a refusal by the protocol
  for (const e of [new TypeError("fetch failed"), Object.assign(new Error("Exceeded 2 providers to execute request"), { type: "RetriesExceeded" }),
    Object.assign(new Error("Internal server error"), { name: "ProviderError" })]) {
    const info = describeTxError(e);
    assert.equal(info.transport, true, info.message);
    assert.equal(info.rejectedBeforeInclusion, false, info.message);
  }
  class AccessKeyNotEnoughAllowanceActionError extends Error {}
  const allowance = describeTxError(new AccessKeyNotEnoughAllowanceActionError("Not enough allowance … (allowance: 1, cost: 2)"));
  assert.equal(allowance.transport, false);
  assert.equal(allowance.rejectedBeforeInclusion, true);

  const plain = describeTxError("boom");
  assert.equal(plain.message, "boom");
  const long = describeTxError(new Error("x".repeat(1000)));
  assert.ok(long.message.length <= 400);
});

test("panicText extracts the contract's panic message", () => {
  assert.equal(panicText('{"ActionError":{"kind":{"FunctionCallError":{"ExecutionError":"Smart contract panicked: submission is not pending"}}}}'),
    "submission is not pending");
  assert.equal(panicText("no panic here"), null);
});
