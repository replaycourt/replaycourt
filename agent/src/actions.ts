// Chain-facing actions of the CLI (program owner, hunter, hunter vault). The chain access is
// injected (ChainClient), so tests run with the contract mocked; cli.ts wires the real client
// (near.ts makeChainClient).

import { commitmentFor, seal } from "./seal.ts";

export interface Signer {
  accountId: string;
  privateKey: string; // "ed25519:..."
}

export interface ChainClient {
  contractId: string;
  view<T>(method: string, args?: Record<string, unknown>): Promise<T>;
  call<T>(signer: Signer, method: string, args: Record<string, unknown>, opts: { deposit: bigint; gas?: bigint }): Promise<{ result: T; txHash: string }>;
  /** Add a function-call access key (receiver = this contract), signed with the account's full-access key. */
  addFunctionCallKey(signer: Signer, key: { publicKey: string; methodNames: string[]; allowance: bigint }): Promise<string>;
  /** On-chain permission of an access key (near-api-js viewAccessKey().permission). */
  accessKeyPermission(accountId: string, publicKey: string): Promise<unknown>;
  storageBytePrice(): Promise<bigint>;
}

export const ONE_YOCTO = 1n;
export const NEAR = 10n ** 24n;
export const DAY_NS = 24n * 3600n * 1_000_000_000n;
/** What a hunter's function-call key may call (SPEC v2 "Hunter vault"). It cannot attach deposits,
 *  so it can neither change the vault policy nor withdraw from the vault. */
export const HUNTER_KEY_METHODS = ["submit_report_from_vault", "finalize", "withdraw_pending"] as const;
export const VERIFIER_KEY_METHODS = ["post_verdict"] as const;
export const MAX_ALLOWED_PROGRAMS = 32;

export class ActionError extends Error {}

const utf8Len = (s: string) => Buffer.byteLength(s, "utf8");

// ------------------------------------------------------------------ programs

export interface CreateProgramOptions {
  name: string;
  scope: { chain_id: number; address: string }[];
  verifierId: string;
  verifierPubkey: string;
  payouts: [bigint, bigint, bigint, bigint]; // critical, high, medium, low
  bond: bigint;
  verifierFee: bigint;
  disputeBond: bigint;
  challengeSec: number;
  pendingTimeoutSec: number;
  resolveTimeoutSec: number;
  pool: bigint; // attached deposit
}

/** create_program arguments (SPEC v2); refuses what the contract would refuse. */
export function createProgramArgs(o: CreateProgramOptions): Record<string, unknown> {
  const n = utf8Len(o.name);
  if (n < 1 || n > 80) throw new ActionError(`program name must be 1..80 bytes (has ${n})`);
  if (o.scope.length > 32) throw new ActionError("at most 32 scope targets");
  if (o.payouts.every((p) => p === 0n)) throw new ActionError("at least one payout must be > 0");
  if (o.disputeBond < o.bond) throw new ActionError("the dispute bond must be at least the bond");
  const range = (v: number, lo: number, hi: number, what: string) => {
    if (!Number.isInteger(v) || v < lo || v > hi) throw new ActionError(`${what} must be ${lo}..${hi} seconds`);
  };
  range(o.challengeSec, 60, 30 * 86400, "the challenge period");
  range(o.pendingTimeoutSec, 60, 365 * 86400, "the pending timeout");
  range(o.resolveTimeoutSec, 60, 30 * 86400, "the resolve timeout");
  if (o.pool < NEAR) throw new ActionError("create_program needs a deposit (pool) of at least 1 NEAR");
  return {
    name: o.name,
    scope: o.scope,
    verifier_id: o.verifierId,
    verifier_pubkey: o.verifierPubkey,
    payouts: { critical: o.payouts[0].toString(), high: o.payouts[1].toString(), medium: o.payouts[2].toString(), low: o.payouts[3].toString() },
    bond: o.bond.toString(),
    verifier_fee: o.verifierFee.toString(),
    dispute_bond: o.disputeBond.toString(),
    challenge_period_sec: o.challengeSec,
    pending_timeout_sec: o.pendingTimeoutSec,
    resolve_timeout_sec: o.resolveTimeoutSec,
  };
}

export async function createProgram(chain: ChainClient, owner: Signer, o: CreateProgramOptions) {
  const args = createProgramArgs(o);
  const r = await chain.call<number>(owner, "create_program", args, { deposit: o.pool });
  return { programId: Number(r.result), txHash: r.txHash, args };
}

// ------------------------------------------------------------------ dispute

interface SubmissionLite {
  id: number;
  program_id: number;
  status: string;
  hunter_id: string;
  valid_until?: string | null;
}
interface ProgramLite {
  id: number;
  name: string;
  owner_id: string;
  verifier_pubkey: string;
  active?: boolean;
  bond?: string;
  dispute_bond?: string;
}

/** dispute(): the program owner attaches the program's dispute bond (SPEC v2). */
export async function disputeSubmission(chain: ChainClient, owner: Signer, submissionId: number, reason: string, deposit?: bigint) {
  if (!reason || utf8Len(reason) > 280) throw new ActionError("the dispute reason must be 1..280 bytes");
  const sub = await chain.view<SubmissionLite | null>("get_submission", { submission_id: submissionId });
  if (!sub) throw new ActionError(`submission ${submissionId} not found`);
  if (sub.status !== "valid") throw new ActionError(`submission ${submissionId} is ${sub.status}; only a valid verdict can be disputed`);
  const program = await chain.view<ProgramLite | null>("get_program", { program_id: sub.program_id });
  if (!program) throw new ActionError(`program ${sub.program_id} not found`);
  if (program.owner_id !== owner.accountId) throw new ActionError(`only the program owner ${program.owner_id} can dispute`);
  if (typeof program.dispute_bond !== "string") throw new ActionError(`program ${program.id} has no dispute_bond (a v1 contract?)`);
  const bond = BigInt(program.dispute_bond);
  const attach = deposit ?? bond;
  if (attach < bond) throw new ActionError(`the deposit must be at least the program's dispute bond (${bond} yocto)`);
  const r = await chain.call<null>(owner, "dispute", { submission_id: submissionId, reason }, { deposit: attach });
  return { txHash: r.txHash, deposit: attach, disputeBond: bond };
}

// ------------------------------------------------------------------ vault

export interface VaultView {
  account_id: string;
  balance: string;
  max_bond_per_report: string;
  max_spend_per_day: string;
  allowed_programs: number[] | null;
  spent_in_window: string;
  window_start: string;
  policy_set: boolean;
}

export interface VaultPolicy {
  maxBondPerReport: bigint;
  maxSpendPerDay: bigint;
  allowedPrograms: number[] | null; // null = any program
}

export async function getVault(chain: ChainClient, accountId: string): Promise<VaultView | null> {
  return chain.view<VaultView | null>("get_vault", { account_id: accountId });
}

export async function vaultDeposit(chain: ChainClient, hunter: Signer, amount: bigint) {
  if (amount <= 0n) throw new ActionError("the vault deposit must be > 0");
  const r = await chain.call<null>(hunter, "vault_deposit", {}, { deposit: amount });
  return { txHash: r.txHash };
}

export function vaultPolicyArgs(p: VaultPolicy): Record<string, unknown> {
  if (p.maxBondPerReport <= 0n || p.maxSpendPerDay <= 0n) throw new ActionError("max bond per report and max spend per day must be > 0");
  if (p.allowedPrograms && p.allowedPrograms.length > MAX_ALLOWED_PROGRAMS) throw new ActionError(`at most ${MAX_ALLOWED_PROGRAMS} allowed programs`);
  if (p.allowedPrograms?.some((id) => !Number.isInteger(id) || id < 0)) throw new ActionError("program ids must be non-negative integers");
  return {
    max_bond_per_report: p.maxBondPerReport.toString(),
    max_spend_per_day: p.maxSpendPerDay.toString(),
    allowed_programs: p.allowedPrograms ? [...new Set(p.allowedPrograms)] : null,
  };
}

/** vault_set_policy: exactly 1 yoctoNEAR, which only a full-access key can attach. */
export async function vaultSetPolicy(chain: ChainClient, hunter: Signer, p: VaultPolicy) {
  const args = vaultPolicyArgs(p);
  const r = await chain.call<null>(hunter, "vault_set_policy", args, { deposit: ONE_YOCTO });
  return { txHash: r.txHash, args };
}

/** vault_withdraw: exactly 1 yoctoNEAR (full-access key). "all" withdraws the whole balance. */
export async function vaultWithdraw(chain: ChainClient, hunter: Signer, amount: bigint | "all") {
  let value: bigint;
  if (amount === "all") {
    const v = await getVault(chain, hunter.accountId);
    if (!v) throw new ActionError(`${hunter.accountId} has no vault`);
    value = BigInt(v.balance);
  } else {
    value = amount;
  }
  if (value <= 0n) throw new ActionError("nothing to withdraw");
  const r = await chain.call<null>(hunter, "vault_withdraw", { amount: value.toString() }, { deposit: ONE_YOCTO });
  return { txHash: r.txHash, amount: value };
}

/** spent_in_window as the contract will see it now (the window restarts after 24 h). */
export function spentNow(v: VaultView, nowNs: bigint): bigint {
  return nowNs >= BigInt(v.window_start) + DAY_NS ? 0n : BigInt(v.spent_in_window);
}

/** Why the contract would refuse submit_report_from_vault, checked before signing; null if it may pass.
 *  `required` is required_bond; the storage cost comes on top on-chain, so balance and daily cap are
 *  only refused here when the bond alone already exceeds them. */
export function vaultRefusal(v: VaultView | null, programId: number, required: bigint, nowNs: bigint): string | null {
  if (!v) return "no vault: deposit first (vault-deposit)";
  if (!v.policy_set) return "the vault has no policy yet (vault-set-policy)";
  if (v.allowed_programs && !v.allowed_programs.map(Number).includes(programId)) {
    return `program ${programId} is not in the vault's allowed programs [${v.allowed_programs.join(", ")}]`;
  }
  if (required > BigInt(v.max_bond_per_report)) return `the required bond ${required} exceeds the vault's max bond per report ${v.max_bond_per_report}`;
  const spent = spentNow(v, nowNs);
  if (spent + required > BigInt(v.max_spend_per_day)) {
    return `the daily spending cap ${v.max_spend_per_day} would be exceeded (spent ${spent} in the current 24 h window)`;
  }
  if (required > BigInt(v.balance)) return `the vault balance ${v.balance} is below the required bond ${required}`;
  return null;
}

export function formatVault(accountId: string, v: VaultView | null, fmt: (y: bigint | string) => string, nowNs: bigint): string[] {
  if (!v) return [`${accountId}: no vault`];
  const lines = [
    `vault of ${v.account_id}: balance ${fmt(v.balance)} NEAR`,
    v.policy_set
      ? `  policy: max bond per report ${fmt(v.max_bond_per_report)} NEAR, max spend per 24 h ${fmt(v.max_spend_per_day)} NEAR, ` +
        `programs ${v.allowed_programs ? "[" + v.allowed_programs.join(", ") + "]" : "any"}`
      : "  policy: not set (submit_report_from_vault refuses until vault-set-policy)",
    `  spent in the current window: ${fmt(spentNow(v, nowNs))} NEAR (window started ${new Date(Number(BigInt(v.window_start) / 1_000_000n)).toISOString()})`,
  ];
  return lines;
}

// ------------------------------------------------------------------ function-call keys

/** null if `permission` is a function-call key for `contractId` limited to exactly `methods`; else why not. */
export function functionCallKeyProblem(permission: unknown, contractId: string, methods: readonly string[]): string | null {
  const fc = (permission && typeof permission === "object" ? (permission as Record<string, unknown>).FunctionCall : null) as
    | { receiver_id?: string; method_names?: string[] } | null;
  if (!fc) return `not a function-call key (permission: ${JSON.stringify(permission)})`;
  if (fc.receiver_id !== contractId) return `the key's receiver is ${fc.receiver_id}, not ${contractId}`;
  const have = [...(fc.method_names ?? [])].sort();
  const want = [...methods].sort();
  if (JSON.stringify(have) !== JSON.stringify(want)) return `the key may call [${have.join(", ")}], expected exactly [${want.join(", ")}]`;
  return null;
}

export interface HunterKeyRecord {
  account_id: string;
  contract_id: string;
  public_key: string;
  private_key: string;
  method_names: string[];
  allowance: string;
  added_tx: string;
  created_at: string;
}

/** Add a function-call key to a hunter account: receiver = the contract, methods =
 *  submit_report_from_vault, finalize, withdraw_pending; signed once with the full-access key. */
export async function setupHunterKey(chain: ChainClient, hunter: Signer, allowance: bigint, key: { publicKey: string; secretKey: string }) {
  if (allowance <= 0n) throw new ActionError("the allowance must be > 0");
  const txHash = await chain.addFunctionCallKey(hunter, { publicKey: key.publicKey, methodNames: [...HUNTER_KEY_METHODS], allowance });
  const record: HunterKeyRecord = {
    account_id: hunter.accountId,
    contract_id: chain.contractId,
    public_key: key.publicKey,
    private_key: key.secretKey,
    method_names: [...HUNTER_KEY_METHODS],
    allowance: allowance.toString(),
    added_tx: txHash,
    created_at: new Date().toISOString(),
  };
  return { record, txHash };
}

/** The file in .secrets/ that holds a hunter's function-call key. */
export function hunterKeyFile(accountId: string): string {
  return `hunter-fc-key.${accountId}.json`;
}

// ------------------------------------------------------------------ submit

export interface PreparedSubmission {
  programId: number;
  programName: string;
  hunterId: string;
  title: string;
  commitment: string;
  sealed: string;
  required: bigint;
  bond: bigint;
  storage: bigint;
  deposit: bigint;
}

/** Storage the contract charges for a submission, estimated (the contract keeps deposit - storage as
 *  bond): stored bytes measured on testnet + 1,500 bytes pre-paid for later writes + 300 bytes margin. */
export function storageEstimate(sealedLength: number, titleBytes: number, hunterId: string, perByte: bigint): bigint {
  return BigInt(sealedLength + titleBytes + 2 * 64 + 2 * hunterId.length + 600 + 1500 + 300) * perByte;
}

export function readTitle(text: string): string {
  const fm = /^---\n([\s\S]*?)\n---/.exec(text);
  if (fm) {
    const m = /^title\s*:\s*(.+)$/im.exec(fm[1]);
    if (m) return m[1].trim().replace(/^["']|["']$/g, "");
  }
  const h = /^#\s+(.+)$/m.exec(text);
  return h ? h[1].trim() : "untitled report";
}

/** Cut to at most `max` UTF-8 bytes without splitting a character (the contract counts bytes). */
export function clipBytes(s: string, max: number): string {
  if (utf8Len(s) <= max) return s;
  let out = "";
  for (const ch of s) {
    if (utf8Len(out + ch + "…") > max) break;
    out += ch;
  }
  return out + "…";
}

/** Seal a report to the program's verifier key and compute the v2 commitment for `hunterId`. */
export async function prepareSubmission(chain: ChainClient, o: {
  programId: number; hunterId: string; report: Uint8Array; title?: string; bond?: bigint; storage?: bigint;
}): Promise<PreparedSubmission> {
  const program = await chain.view<ProgramLite | null>("get_program", { program_id: o.programId });
  if (!program) throw new ActionError(`program ${o.programId} not found on ${chain.contractId}`);
  if (program.active === false) throw new ActionError(`program ${o.programId} does not accept new reports`);
  const required = BigInt(await chain.view<string>("required_bond", { program_id: o.programId, hunter_id: o.hunterId }));
  const bond = o.bond ?? required;
  if (bond < required) throw new ActionError(`the bond ${bond} is below the required bond ${required}`);
  const commitment = commitmentFor(o.hunterId, o.report);
  const sealed = seal(o.report, program.verifier_pubkey);
  if (sealed.length > 64 * 1024) throw new ActionError(`the sealed report has ${sealed.length} bytes; the contract accepts at most 65536`);
  const title = clipBytes(o.title ?? readTitle(Buffer.from(o.report).toString("utf8")), 120);
  const storage = o.storage ?? storageEstimate(sealed.length, utf8Len(title), o.hunterId, await chain.storageBytePrice());
  return { programId: o.programId, programName: program.name, hunterId: o.hunterId, title, commitment, sealed, required, bond, storage, deposit: bond + storage };
}

/** submit_report with bond + storage, signed with the hunter's full-access key. */
export async function submitReport(chain: ChainClient, hunter: Signer, p: PreparedSubmission) {
  if (hunter.accountId !== p.hunterId) throw new ActionError("the commitment was computed for another account");
  const r = await chain.call<number>(hunter, "submit_report",
    { program_id: p.programId, title: p.title, commitment: p.commitment, sealed: p.sealed }, { deposit: p.deposit });
  return { submissionId: Number(r.result), txHash: r.txHash };
}

/** submit_report_from_vault, signed with the hunter's function-call key: no deposit, the contract
 *  draws required_bond + storage from the vault inside the vault's policy. */
export async function submitFromVault(chain: ChainClient, hunterKey: Signer, p: PreparedSubmission, nowNs: bigint) {
  if (hunterKey.accountId !== p.hunterId) throw new ActionError("the commitment was computed for another account");
  const refusal = vaultRefusal(await getVault(chain, p.hunterId), p.programId, p.required, nowNs);
  if (refusal) throw new ActionError(`refused before signing: ${refusal}`);
  const r = await chain.call<number>(hunterKey, "submit_report_from_vault",
    { program_id: p.programId, title: p.title, commitment: p.commitment, sealed: p.sealed }, { deposit: 0n });
  return { submissionId: Number(r.result), txHash: r.txHash };
}
