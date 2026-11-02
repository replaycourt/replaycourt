// CLI actions for v2 (create-program, dispute, vault, hunter function-call key, submit, submit --from-vault)
// with the contract mocked: which method is called, with which arguments, deposit and signer.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ActionError,
  DAY_NS,
  HUNTER_KEY_METHODS,
  NEAR,
  ONE_YOCTO,
  clipBytes,
  createProgram,
  createProgramArgs,
  disputeSubmission,
  formatVault,
  functionCallKeyProblem,
  hunterKeyFile,
  prepareSubmission,
  setupHunterKey,
  spentNow,
  storageEstimate,
  submitFromVault,
  submitReport,
  vaultDeposit,
  vaultRefusal,
  vaultSetPolicy,
  vaultWithdraw,
} from "../src/actions.ts";
import type { ChainClient, CreateProgramOptions, Signer, VaultView } from "../src/actions.ts";
import { fmtNear } from "../src/near.ts";
import { commitmentFor, generateVerifierKeypair, openAndCheck } from "../src/seal.ts";

const CONTRACT = "contract.example.testnet";
const kp = generateVerifierKeypair();
const owner: Signer = { accountId: "owner.example.testnet", privateKey: "ed25519:owner-full-access" };
const hunter: Signer = { accountId: "hunter1.example.testnet", privateKey: "ed25519:hunter-full-access" };
const hunterFc: Signer = { accountId: "hunter1.example.testnet", privateKey: "ed25519:hunter-function-call" };

interface Call { signer: string; key: string; method: string; args: Record<string, unknown>; deposit: bigint }

function mockChain(state: { submissions?: Record<number, unknown>; programs?: Record<number, unknown>; vaults?: Record<string, VaultView | null>; required?: string } = {}) {
  const calls: Call[] = [];
  const keys: { signer: string; publicKey: string; methodNames: string[]; allowance: bigint }[] = [];
  const views: string[] = [];
  const chain: ChainClient = {
    contractId: CONTRACT,
    async view<T>(method: string, args: Record<string, unknown> = {}) {
      views.push(method);
      switch (method) {
        case "get_submission":
          return (state.submissions?.[Number(args.submission_id)] ?? null) as T;
        case "get_program":
          return (state.programs?.[Number(args.program_id)] ?? null) as T;
        case "get_vault":
          return (state.vaults?.[String(args.account_id)] ?? null) as T;
        case "required_bond":
          return (state.required ?? "100000000000000000000000") as T;
        default:
          throw new Error(`unexpected view ${method}`);
      }
    },
    async call<T>(signer: Signer, method: string, args: Record<string, unknown>, opts: { deposit: bigint }) {
      calls.push({ signer: signer.accountId, key: signer.privateKey, method, args, deposit: opts.deposit });
      return { result: (method.startsWith("submit") ? 42 : method === "create_program" ? 7 : null) as T, txHash: `tx-${method}` };
    },
    async addFunctionCallKey(signer, key) {
      keys.push({ signer: signer.privateKey, ...key });
      return "tx-add-key";
    },
    async accessKeyPermission() {
      return null;
    },
    async storageBytePrice() {
      return 10n ** 19n;
    },
  };
  return { chain, calls, keys, views };
}

const PROGRAM = { id: 0, name: "Demo", owner_id: owner.accountId, verifier_pubkey: kp.publicKey, active: true, bond: String(NEAR / 10n), dispute_bond: String(NEAR / 2n) };

function programOpts(over: Partial<CreateProgramOptions> = {}): CreateProgramOptions {
  return {
    name: "Demo", scope: [{ chain_id: 1, address: "0xd2869042E12a3506100af1D192b5b04D65137941" }], verifierId: "verifier.example.testnet",
    verifierPubkey: kp.publicKey, payouts: [NEAR / 2n, NEAR / 4n, NEAR / 10n, 0n], bond: NEAR / 10n, verifierFee: NEAR / 100n,
    disputeBond: NEAR / 2n, challengeSec: 60, pendingTimeoutSec: 86400, resolveTimeoutSec: 120, pool: 2n * NEAR, ...over,
  };
}

test("create-program sends dispute_bond and resolve_timeout_sec (SPEC v2) with the pool as deposit", async () => {
  const { chain, calls } = mockChain();
  const res = await createProgram(chain, owner, programOpts());
  assert.equal(res.programId, 7);
  assert.equal(calls.length, 1);
  const c = calls[0];
  assert.deepEqual([c.method, c.signer, c.deposit], ["create_program", owner.accountId, 2n * NEAR]);
  assert.equal(c.args.dispute_bond, String(NEAR / 2n));
  assert.equal(c.args.resolve_timeout_sec, 120);
  assert.equal(c.args.challenge_period_sec, 60);
  assert.equal(c.args.pending_timeout_sec, 86400);
  assert.deepEqual(c.args.payouts, { critical: String(NEAR / 2n), high: String(NEAR / 4n), medium: String(NEAR / 10n), low: "0" });
  assert.deepEqual(Object.keys(c.args).sort(), ["bond", "challenge_period_sec", "dispute_bond", "name", "payouts", "pending_timeout_sec",
    "resolve_timeout_sec", "scope", "verifier_fee", "verifier_id", "verifier_pubkey"]);
});

test("create-program refuses what the contract would refuse", () => {
  assert.throws(() => createProgramArgs(programOpts({ disputeBond: NEAR / 20n })), /dispute bond must be at least the bond/);
  assert.throws(() => createProgramArgs(programOpts({ resolveTimeoutSec: 59 })), /resolve timeout/);
  assert.throws(() => createProgramArgs(programOpts({ resolveTimeoutSec: 31 * 86400 })), /resolve timeout/);
  assert.throws(() => createProgramArgs(programOpts({ challengeSec: 30 })), /challenge period/);
  assert.throws(() => createProgramArgs(programOpts({ payouts: [0n, 0n, 0n, 0n] })), /payout/);
  assert.throws(() => createProgramArgs(programOpts({ name: "é".repeat(41) })), /1\.\.80 bytes/); // 82 bytes, 41 characters
  assert.throws(() => createProgramArgs(programOpts({ pool: NEAR / 2n })), /at least 1 NEAR/);
});

test("dispute attaches the program's dispute bond; a larger --deposit is allowed, a smaller one is refused", async () => {
  const state = { submissions: { 3: { id: 3, program_id: 0, status: "valid", hunter_id: hunter.accountId } }, programs: { 0: PROGRAM } };
  const { chain, calls } = mockChain(state);
  const res = await disputeSubmission(chain, owner, 3, "the PoC needs a privileged role");
  assert.equal(res.deposit, NEAR / 2n);
  assert.deepEqual([calls[0].method, calls[0].deposit, calls[0].args], ["dispute", NEAR / 2n, { submission_id: 3, reason: "the PoC needs a privileged role" }]);
  await disputeSubmission(chain, owner, 3, "x", NEAR);
  assert.equal(calls[1].deposit, NEAR);
  await assert.rejects(disputeSubmission(chain, owner, 3, "x", NEAR / 4n), /at least the program's dispute bond/);
  assert.equal(calls.length, 2);
});

test("dispute is refused before signing for a non-valid submission, a non-owner or a v1 program", async () => {
  const { chain, calls } = mockChain({
    submissions: { 1: { id: 1, program_id: 0, status: "paid" }, 2: { id: 2, program_id: 0, status: "valid" }, 3: { id: 3, program_id: 1, status: "valid" } },
    programs: { 0: PROGRAM, 1: { ...PROGRAM, id: 1, dispute_bond: undefined } },
  });
  await assert.rejects(disputeSubmission(chain, owner, 1, "x"), /is paid; only a valid verdict can be disputed/);
  await assert.rejects(disputeSubmission(chain, hunter, 2, "x"), /only the program owner/);
  await assert.rejects(disputeSubmission(chain, owner, 3, "x"), /no dispute_bond/);
  await assert.rejects(disputeSubmission(chain, owner, 9, "x"), /not found/);
  await assert.rejects(disputeSubmission(chain, owner, 2, "r".repeat(281)), /1\.\.280 bytes/);
  assert.equal(calls.length, 0);
});

test("vault-deposit attaches the amount; vault-set-policy and vault-withdraw attach exactly 1 yoctoNEAR", async () => {
  const vault: VaultView = { account_id: hunter.accountId, balance: String(3n * NEAR), max_bond_per_report: "0", max_spend_per_day: "0",
    allowed_programs: null, spent_in_window: "0", window_start: "0", policy_set: false };
  const { chain, calls } = mockChain({ vaults: { [hunter.accountId]: vault } });
  await vaultDeposit(chain, hunter, 3n * NEAR);
  await vaultSetPolicy(chain, hunter, { maxBondPerReport: NEAR / 5n, maxSpendPerDay: NEAR, allowedPrograms: [0, 2, 2] });
  await vaultSetPolicy(chain, hunter, { maxBondPerReport: NEAR / 5n, maxSpendPerDay: NEAR, allowedPrograms: null });
  await vaultWithdraw(chain, hunter, NEAR);
  const all = await vaultWithdraw(chain, hunter, "all");
  assert.deepEqual(calls.map((c) => [c.method, c.deposit, c.key]), [
    ["vault_deposit", 3n * NEAR, hunter.privateKey],
    ["vault_set_policy", ONE_YOCTO, hunter.privateKey],
    ["vault_set_policy", ONE_YOCTO, hunter.privateKey],
    ["vault_withdraw", ONE_YOCTO, hunter.privateKey],
    ["vault_withdraw", ONE_YOCTO, hunter.privateKey],
  ]);
  assert.deepEqual(calls[0].args, {});
  assert.deepEqual(calls[1].args, { max_bond_per_report: String(NEAR / 5n), max_spend_per_day: String(NEAR), allowed_programs: [0, 2] });
  assert.equal(calls[2].args.allowed_programs, null);
  assert.deepEqual(calls[3].args, { amount: String(NEAR) });
  assert.equal(all.amount, 3n * NEAR);
  assert.deepEqual(calls[4].args, { amount: String(3n * NEAR) });
});

test("vault commands refuse bad input before signing", async () => {
  const { chain, calls } = mockChain();
  await assert.rejects(vaultDeposit(chain, hunter, 0n), /must be > 0/);
  await assert.rejects(vaultSetPolicy(chain, hunter, { maxBondPerReport: 0n, maxSpendPerDay: NEAR, allowedPrograms: null }), /must be > 0/);
  await assert.rejects(vaultSetPolicy(chain, hunter, { maxBondPerReport: NEAR, maxSpendPerDay: NEAR, allowedPrograms: [...Array(33).keys()] }), /at most 32/);
  await assert.rejects(vaultWithdraw(chain, hunter, "all"), /has no vault/);
  await assert.rejects(vaultWithdraw(chain, hunter, 0n), /nothing to withdraw/);
  assert.equal(calls.length, 0);
});

test("vault-status formats balance, policy and the current window", () => {
  const now = 1_800_000_000n * 1_000_000_000n;
  const v: VaultView = { account_id: hunter.accountId, balance: String(2n * NEAR), max_bond_per_report: String(NEAR / 5n),
    max_spend_per_day: String(NEAR), allowed_programs: [0], spent_in_window: String(NEAR / 5n), window_start: String(now - 3600n * 1_000_000_000n), policy_set: true };
  const fmt = (y: bigint | string) => fmtNear(y);
  const lines = formatVault(hunter.accountId, v, fmt, now);
  assert.match(lines[0], /balance 2 NEAR/);
  assert.match(lines[1], /max bond per report 0\.2 NEAR, max spend per 24 h 1 NEAR, programs \[0\]/);
  assert.match(lines[2], /spent in the current window: 0\.2 NEAR/);
  assert.deepEqual(formatVault("x.testnet", null, fmt, now), ["x.testnet: no vault"]);
  assert.match(formatVault(hunter.accountId, { ...v, policy_set: false }, fmt, now)[1], /not set/);
  // the window restarts 24 h after window_start
  assert.equal(spentNow(v, now), NEAR / 5n);
  assert.equal(spentNow(v, BigInt(v.window_start) + DAY_NS), 0n);
});

test("setup-hunter-key adds a function-call key for exactly submit_report_from_vault, finalize, withdraw_pending", async () => {
  const { chain, keys, calls } = mockChain();
  const { record, txHash } = await setupHunterKey(chain, hunter, NEAR / 4n, { publicKey: "ed25519:PUB", secretKey: "ed25519:SECRET" });
  assert.equal(txHash, "tx-add-key");
  assert.deepEqual(keys, [{ signer: hunter.privateKey, publicKey: "ed25519:PUB", methodNames: ["submit_report_from_vault", "finalize", "withdraw_pending"], allowance: NEAR / 4n }]);
  assert.equal(calls.length, 0);
  assert.deepEqual([record.account_id, record.contract_id, record.public_key, record.private_key], [hunter.accountId, CONTRACT, "ed25519:PUB", "ed25519:SECRET"]);
  assert.deepEqual(record.method_names, [...HUNTER_KEY_METHODS]);
  assert.equal(record.allowance, String(NEAR / 4n));
  assert.equal(hunterKeyFile(hunter.accountId), "hunter-fc-key.hunter1.example.testnet.json");
  await assert.rejects(setupHunterKey(chain, hunter, 0n, { publicKey: "a", secretKey: "b" }), /allowance must be > 0/);
});

test("functionCallKeyProblem accepts only a function-call key for this contract with exactly the expected methods", () => {
  const fc = (receiver_id: string, method_names: string[]) => ({ FunctionCall: { receiver_id, method_names, allowance: "1" } });
  assert.equal(functionCallKeyProblem(fc(CONTRACT, ["finalize", "withdraw_pending", "submit_report_from_vault"]), CONTRACT, HUNTER_KEY_METHODS), null);
  assert.match(functionCallKeyProblem("FullAccess", CONTRACT, HUNTER_KEY_METHODS)!, /not a function-call key/);
  assert.match(functionCallKeyProblem(fc("other.testnet", [...HUNTER_KEY_METHODS]), CONTRACT, HUNTER_KEY_METHODS)!, /receiver is other\.testnet/);
  assert.match(functionCallKeyProblem(fc(CONTRACT, ["finalize"]), CONTRACT, HUNTER_KEY_METHODS)!, /expected exactly/);
  assert.match(functionCallKeyProblem(fc(CONTRACT, []), CONTRACT, HUNTER_KEY_METHODS)!, /expected exactly/); // [] = any method
  assert.equal(functionCallKeyProblem(fc(CONTRACT, ["post_verdict"]), CONTRACT, ["post_verdict"]), null);
});

const REPORT = Buffer.from("---\ntitle: Missing access control in migrateStake()\n---\n\n# Bug\n```solidity\npragma solidity ^0.8.0;\n```\n");

test("submit seals to the program's verifier key with the v2 commitment of the submitting account", async () => {
  const { chain, calls } = mockChain({ programs: { 0: PROGRAM }, required: String(NEAR / 10n) });
  const prep = await prepareSubmission(chain, { programId: 0, hunterId: hunter.accountId, report: REPORT });
  assert.equal(prep.commitment, commitmentFor(hunter.accountId, REPORT));
  assert.equal(prep.title, "Missing access control in migrateStake()");
  assert.equal(prep.required, NEAR / 10n);
  assert.equal(prep.storage, storageEstimate(prep.sealed.length, Buffer.byteLength(prep.title), hunter.accountId, 10n ** 19n));
  assert.equal(prep.deposit, prep.bond + prep.storage);
  assert.equal(openAndCheck(prep.sealed, kp.privateKey, prep.commitment, hunter.accountId).ok, true);
  const res = await submitReport(chain, hunter, prep);
  assert.equal(res.submissionId, 42);
  assert.deepEqual([calls[0].method, calls[0].deposit, calls[0].key], ["submit_report", prep.deposit, hunter.privateKey]);
  assert.deepEqual(calls[0].args, { program_id: 0, title: prep.title, commitment: prep.commitment, sealed: prep.sealed });
  // the commitment is bound to the account: it cannot be signed by another one
  await assert.rejects(submitReport(chain, owner, prep), /another account/);
  await assert.rejects(prepareSubmission(chain, { programId: 0, hunterId: hunter.accountId, report: REPORT, bond: NEAR / 20n }), /below the required bond/);
  await assert.rejects(prepareSubmission(chain, { programId: 5, hunterId: hunter.accountId, report: REPORT }), /program 5 not found/);
});

function policyVault(over: Partial<VaultView> = {}): VaultView {
  return { account_id: hunter.accountId, balance: String(NEAR), max_bond_per_report: String(NEAR / 5n), max_spend_per_day: String(NEAR / 2n),
    allowed_programs: [0], spent_in_window: "0", window_start: "0", policy_set: true, ...over };
}

test("submit --from-vault signs submit_report_from_vault with the function-call key and attaches nothing", async () => {
  const { chain, calls } = mockChain({ programs: { 0: PROGRAM }, vaults: { [hunter.accountId]: policyVault() }, required: String(NEAR / 10n) });
  const prep = await prepareSubmission(chain, { programId: 0, hunterId: hunter.accountId, report: REPORT });
  const res = await submitFromVault(chain, hunterFc, prep, 1n);
  assert.equal(res.submissionId, 42);
  assert.deepEqual([calls[0].method, calls[0].deposit, calls[0].key], ["submit_report_from_vault", 0n, hunterFc.privateKey]);
  assert.deepEqual(calls[0].args, { program_id: 0, title: prep.title, commitment: commitmentFor(hunter.accountId, REPORT), sealed: prep.sealed });
});

test("submit --from-vault is refused before signing when the vault policy would refuse", async () => {
  const req = NEAR / 10n;
  const now = 10n * DAY_NS;
  assert.equal(vaultRefusal(policyVault(), 0, req, now), null);
  assert.match(vaultRefusal(null, 0, req, now)!, /no vault/);
  assert.match(vaultRefusal(policyVault({ policy_set: false }), 0, req, now)!, /no policy/);
  assert.match(vaultRefusal(policyVault({ allowed_programs: [1, 2] }), 0, req, now)!, /not in the vault's allowed programs \[1, 2\]/);
  assert.equal(vaultRefusal(policyVault({ allowed_programs: null }), 9, req, now), null);
  assert.match(vaultRefusal(policyVault({ max_bond_per_report: String(NEAR / 20n) }), 0, req, now)!, /exceeds the vault's max bond/);
  // daily cap: spent in the current window counts, an old window does not
  const spent = policyVault({ spent_in_window: String(NEAR / 2n - NEAR / 20n), window_start: String(now - 3600n * 1_000_000_000n) });
  assert.match(vaultRefusal(spent, 0, req, now)!, /daily spending cap/);
  assert.equal(vaultRefusal({ ...spent, window_start: String(now - DAY_NS) }, 0, req, now), null);
  assert.match(vaultRefusal(policyVault({ balance: String(NEAR / 20n) }), 0, req, now)!, /balance/);

  const { chain, calls } = mockChain({ programs: { 0: PROGRAM }, vaults: { [hunter.accountId]: policyVault({ allowed_programs: [3] }) }, required: String(req) });
  const prep = await prepareSubmission(chain, { programId: 0, hunterId: hunter.accountId, report: REPORT });
  await assert.rejects(submitFromVault(chain, hunterFc, prep, now), (e: Error) => e instanceof ActionError && /refused before signing/.test(e.message));
  assert.equal(calls.length, 0);
});

test("titles are cut to 120 bytes without splitting a character", () => {
  assert.equal(clipBytes("short", 120), "short");
  const cut = clipBytes("é".repeat(100), 120);
  assert.ok(Buffer.byteLength(cut) <= 120);
  assert.ok(cut.endsWith("…"));
  assert.ok(!cut.includes("�"));
});
