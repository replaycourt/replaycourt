// Test harness: an in-memory ReplayCourt contract behind the Chain interface, and a real MCP
// client connected to the real server over an in-memory transport.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { DAY_NS, HUNTER_KEY_METHODS, storageEstimate } from "../../agent/src/actions.ts";
import type { VaultView } from "../../agent/src/actions.ts";
import { newEd25519 } from "../../agent/src/near.ts";
import { generateVerifierKeypair } from "../../agent/src/seal.ts";
import { parseNear } from "../src/amounts.ts";
import type { Chain, RawView, SubmitArgs } from "../src/chain.ts";
import { Ledger } from "../src/ledger.ts";
import { parsePolicy } from "../src/policy.ts";
import type { Policy } from "../src/policy.ts";
import { makeRedactor, secretForms } from "../src/redact.ts";
import { createReplayCourtServer } from "../src/tools.ts";
import type { SigningMode } from "../src/vault.ts";

export const HUNTER = "hunter.mock.testnet";
export const CONTRACT = "contract.mock.testnet";
export const N = (s: string) => parseNear(s, "test amount");
/** The mock programs' verifier: tests can unseal what the server sealed. */
export const VERIFIER = generateVerifierKeypair();

/** A fresh temp dir (tests run with TMPDIR pointed at the scratchpad); removed by cleanup(). */
const tmpDirs: string[] = [];
export function tmpDir(prefix = "fpmcp-"): string {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tmpDirs.push(d);
  return d;
}
export function cleanup(): void {
  for (const d of tmpDirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
}

export function program(id: number, over: RawView = {}): RawView {
  return {
    id,
    owner_id: "owner.mock.testnet",
    name: `Program ${id}`,
    scope: [{ chain_id: 1, address: "0x1111111111111111111111111111111111111111" }],
    verifier_id: "verifier.mock.testnet",
    verifier_pubkey: VERIFIER.publicKey,
    payouts: { critical: N("0.2").toString(), high: N("0.1").toString(), medium: N("0.05").toString(), low: N("0.02").toString() },
    bond: N("0.1").toString(),
    verifier_fee: N("0.01").toString(),
    dispute_bond: N("0.2").toString(),
    challenge_period_sec: 60,
    pending_timeout_sec: 300,
    resolve_timeout_sec: 600,
    pool: N("1").toString(),
    reserved: "0",
    active: true,
    stats: { submissions: 0, paid: 0, invalid: 0, duplicate: 0, needs_human: 0, disputes: 0, overruled: 0, total_paid: "0" },
    created_at: "1762000000000000000",
    ...over,
  };
}

/** A hunter vault as get_vault returns it. Defaults: 1 NEAR, max bond 0.15, 0.5 per 24 h, program 7. */
export function vault(over: Partial<VaultView> = {}): VaultView {
  return {
    account_id: HUNTER,
    balance: N("1").toString(),
    max_bond_per_report: N("0.15").toString(),
    max_spend_per_day: N("0.5").toString(),
    allowed_programs: [7],
    spent_in_window: "0",
    window_start: "0",
    policy_set: true,
    ...over,
  };
}

/** The on-chain permission of a hunter function-call key (agent setup-hunter-key). */
export function fcPermission(over: { receiver_id?: string; method_names?: string[]; allowance?: string | null } = {}) {
  return {
    FunctionCall: {
      allowance: over.allowance === undefined ? N("0.5").toString() : over.allowance,
      receiver_id: over.receiver_id ?? CONTRACT,
      method_names: over.method_names ?? [...HUNTER_KEY_METHODS],
    },
  };
}

/** A contract panic as near-api-js throws it: executed on-chain, with a transaction hash. */
export function panic(message: string, txHash = "TXpanic"): Error {
  return Object.assign(new Error(`Smart contract panicked: ${message}`), { transactionResult: { transaction_outcome: { id: txHash } } });
}

export interface MockChain extends Chain {
  programs: Map<number, RawView>;
  submissions: RawView[];
  balance: bigint | null;
  /** The hunter's vault; null = none. Behaves like the contract on submit_report_from_vault. */
  vault: VaultView | null;
  /** Raw permission of the loaded key (null = not an access key of the account). */
  permission: unknown;
  calls: { method: string; deposit: bigint; args: unknown }[];
  /** Make the next transaction throw this. */
  failNext: unknown;
  nowNs: () => bigint;
}

export function mockChain(opts: { programs?: RawView[]; balance?: string; now?: () => number; vault?: VaultView | null; permission?: unknown } = {}): MockChain {
  const now = opts.now ?? Date.now;
  const takeFailure = () => {
    if (!m.failNext) return;
    const e = m.failNext;
    m.failNext = null;
    throw e;
  };
  const record = (args: SubmitArgs, extra: RawView): number => {
    const id = m.submissions.length;
    m.submissions.push({
      id,
      program_id: args.program_id,
      hunter_id: HUNTER,
      title: args.title,
      commitment: args.commitment,
      status: "pending",
      submitted_at: m.nowNs().toString(),
      submitted_block: "1000",
      verdict: null,
      payout: "0",
      resolution: null,
      dispute_reason: null,
      valid_until: null,
      resolve_until: null,
      dispute_bond: "0",
      ...extra,
    });
    return id;
  };
  const m: MockChain = {
    programs: new Map((opts.programs ?? [program(7), program(0)]).map((p) => [p.id as number, p])),
    submissions: [],
    balance: N(opts.balance ?? "1"),
    vault: opts.vault === undefined ? null : opts.vault,
    permission: opts.permission === undefined ? "FullAccess" : opts.permission,
    calls: [],
    failNext: null,
    nowNs: () => BigInt(now()) * 1_000_000n,
    async listPrograms(from, limit) {
      return [...m.programs.values()].sort((a, b) => (a.id as number) - (b.id as number)).slice(from, from + limit);
    },
    async getProgram(id) {
      return m.programs.get(id) ?? null;
    },
    async listSubmissions(pid, from, limit) {
      return m.submissions.filter((s) => s.program_id === pid).slice(from, from + limit);
    },
    async getSubmission(id) {
      return m.submissions.find((s) => s.id === id) ?? null;
    },
    async requiredBond(pid) {
      const p = m.programs.get(pid);
      if (!p) throw new Error("no program");
      return BigInt(p.bond as string);
    },
    async getHunter() {
      return { submissions: m.submissions.length, valid: 0, invalid: 0, duplicate: 0, needs_human: 0, earned: "0" };
    },
    async getHunterInProgram(pid) {
      return { submissions: m.submissions.filter((s) => s.program_id === pid).length, valid: 0, invalid: 0, duplicate: 0, needs_human: 0, earned: "0" };
    },
    async getVault() {
      return m.vault === null ? null : { ...m.vault };
    },
    async availableBalance() {
      if (m.balance === null) throw new Error("rpc down");
      return m.balance;
    },
    async storageBytePrice() {
      return 10n ** 19n;
    },
    async submitReport(args: SubmitArgs, deposit: bigint) {
      m.calls.push({ method: "submit_report", deposit, args });
      takeFailure();
      const id = record(args, { bond: (deposit - 10n ** 22n).toString(), storage_cost: (10n ** 22n).toString(), funded_by_vault: false });
      if (m.balance !== null) m.balance -= deposit;
      return { result: id, txHash: `TX${id}submit` };
    },
    // The contract's submit_internal with Funding::Vault, in its order (SPEC v2 "Hunter vault").
    async submitReportFromVault(args: SubmitArgs) {
      m.calls.push({ method: "submit_report_from_vault", deposit: 0n, args });
      takeFailure();
      const v = m.vault;
      if (!v) throw panic("no vault for this account");
      if (!v.policy_set) throw panic("vault policy is not set");
      if (v.allowed_programs && !v.allowed_programs.includes(args.program_id)) throw panic("program is not in the vault's allowed_programs");
      const required = await m.requiredBond(args.program_id, HUNTER);
      if (required > BigInt(v.max_bond_per_report)) throw panic(`required bond ${required} exceeds the vault's max_bond_per_report ${v.max_bond_per_report}`);
      // measured storage: the estimate without its 300-byte margin
      const storage = storageEstimate(args.sealed.length, Buffer.byteLength(args.title), HUNTER, 10n ** 19n) - 300n * 10n ** 19n;
      const draw = required + storage;
      const t = m.nowNs();
      let start = BigInt(v.window_start);
      let spent = BigInt(v.spent_in_window);
      if (start === 0n || t >= start + DAY_NS) {
        start = t;
        spent = 0n;
      }
      if (spent + draw > BigInt(v.max_spend_per_day)) {
        throw panic(`vault max_spend_per_day exceeded: spent ${spent} + bond ${required} + storage ${storage} > ${v.max_spend_per_day}`);
      }
      if (BigInt(v.balance) < draw) throw panic(`vault balance ${v.balance} is too low: bond ${required} + storage ${storage} = ${draw} yoctoNEAR`);
      m.vault = { ...v, balance: (BigInt(v.balance) - draw).toString(), spent_in_window: (spent + draw).toString(), window_start: start.toString() };
      const id = record(args, { bond: required.toString(), storage_cost: storage.toString(), funded_by_vault: true });
      return { result: id, txHash: `TX${id}vault` };
    },
    async finalize(id) {
      m.calls.push({ method: "finalize", deposit: 0n, args: { id } });
      const s = m.submissions.find((x) => x.id === id)!;
      s.status = "paid";
      s.payout = N("0.2").toString();
      return { result: null, txHash: `TX${id}finalize` };
    },
    async withdrawPending(id) {
      m.calls.push({ method: "withdraw_pending", deposit: 0n, args: { id } });
      const s = m.submissions.find((x) => x.id === id)!;
      s.status = "withdrawn";
      return { result: null, txHash: `TX${id}withdraw` };
    },
    async accessKeyPermission() {
      return m.permission;
    },
  };
  return m;
}

export const BASE_POLICY = {
  version: 1,
  network: "testnet",
  contract_id: CONTRACT,
  allowed_program_ids: [7],
  max_bond_per_report_near: "0.15",
  max_deposit_per_report_near: "0.4",
  max_total_deposit_24h_near: "0.3",
  max_total_deposit_lifetime_near: "1",
  min_account_balance_near: "0.3",
  max_reports_per_hour: 3,
};

export interface Harness {
  client: Client;
  chain: MockChain;
  ledger: Ledger;
  policy: Policy;
  stateDir: string;
  reportDir: string;
  secretKey: string;
  logs: string[];
  outputs: string[];
  clock: { t: number };
  call(name: string, args?: Record<string, unknown>): Promise<{ isError: boolean; doc: Record<string, unknown>; text: string }>;
  close(): Promise<void>;
}

export async function harness(
  opts: {
    policy?: Record<string, unknown>;
    chain?: MockChain;
    stateDir?: string;
    reportDir?: string;
    secretKey?: string;
    clock?: { t: number };
    mode?: SigningMode;
  } = {},
): Promise<Harness> {
  const clock = opts.clock ?? { t: Date.parse("2026-11-02T12:00:00Z") };
  const chain = opts.chain ?? mockChain({ now: () => clock.t });
  const stateDir = opts.stateDir ?? tmpDir("fpmcp-state-");
  const reportDir = opts.reportDir ?? tmpDir("fpmcp-reports-");
  const secretKey = opts.secretKey ?? newEd25519().secretKey;
  const policy = parsePolicy({ ...BASE_POLICY, ...(opts.policy ?? {}) });
  const ledger = new Ledger(stateDir, { clock: () => clock.t });
  const redact = makeRedactor(secretForms(secretKey));
  const logs: string[] = [];
  const outputs: string[] = [];
  const server = createReplayCourtServer({
    chain,
    policy,
    ledger,
    hunterId: HUNTER,
    contractId: CONTRACT,
    network: "testnet",
    reportDirs: [fs.realpathSync(reportDir)],
    redact,
    log: (l) => logs.push(redact(l)),
    now: () => clock.t,
    txUrl: (h) => `https://testnet.nearblocks.io/txns/${h}`,
    mode: opts.mode,
    publicKey: "ed25519:MockPublicKey",
  });
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "1.0.0" });
  await server.connect(serverT);
  await client.connect(clientT);
  return {
    client,
    chain,
    ledger,
    policy,
    stateDir,
    reportDir,
    secretKey,
    logs,
    outputs,
    clock,
    async call(name, args = {}) {
      const res = await client.callTool({ name, arguments: args });
      const text = (res.content as { type: string; text?: string }[]).map((c) => c.text ?? "").join("\n");
      outputs.push(text, JSON.stringify(res.structuredContent ?? null));
      return { isError: res.isError === true, doc: JSON.parse(text) as Record<string, unknown>, text };
    },
    async close() {
      await client.close();
      await server.close();
    },
  };
}

export const SAMPLE_REPORT = "# Reentrancy in Vault.withdraw\n\nPoC:\n```solidity\ncontract Exploit {}\n```\n";
