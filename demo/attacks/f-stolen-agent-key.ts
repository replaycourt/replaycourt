#!/usr/bin/env node
// Attack demo f: the AI hunter's key is stolen. The agent (for example the MCP server in vault
// mode) signs with a function-call access key of the hunter account: receiver = the ReplayCourt
// contract, methods = submit_report_from_vault, finalize, withdraw_pending. The hunter's money sits
// in a vault inside the contract, under an on-chain spending policy that only the account's
// full-access key can change. This script holds ONLY that function-call key (read from
// <secrets dir>/hunter-fc-key.<account>.json) and tries what a thief would try: withdraw the vault,
// raise the policy, transfer NEAR, add or replace keys, delete the account, call another contract,
// and submit reports the policy forbids. Every attempt must fail; the script prints the exact
// errors and, for transactions that reached the chain, their hashes. Exit 0 only if every attempt
// failed; 1 if one succeeded; 2 if network errors left one undecided.
//
//   node demo/attacks/f-stolen-agent-key.ts --as agent [--other-contract <id>] [--json <file>]
//
// Configuration as for the agent CLI (REPLAYCOURT_CONFIG, ...). Testnet only.

import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { HUNTER_KEY_METHODS, hunterKeyFile, storageEstimate } from "../../agent/src/actions.ts";
import type { HunterKeyRecord, VaultView } from "../../agent/src/actions.ts";
import { Account, JsonRpcProvider, KeyPair, describeTxError, nearActions, panicText } from "../../agent/src/attacks.ts";
import type { TxErrorInfo } from "../../agent/src/attacks.ts";
import { DEMO_CONTRACT, REPO_ROOT, loadConfig, readSecret, requireContract, resolveAccount } from "../../agent/src/config.ts";
import { fmtNear, makeProvider, near, storageBytePrice, txUrl, view } from "../../agent/src/near.ts";
import { commitmentFor, seal } from "../../agent/src/seal.ts";

const { values } = parseArgs({
  options: {
    as: { type: "string", default: "agent" },
    "other-contract": { type: "string" },
    json: { type: "string" },
  },
});

interface Prog { id: number; verifier_pubkey: string; name: string }

const cfg = loadConfig();
if (cfg.network !== "testnet") throw new Error("attack demos run on testnet only");
const provider = makeProvider(cfg);
const contractId = requireContract(cfg);
const agentId = resolveAccount(cfg, values.as, "agent");
const key = readSecret<HunterKeyRecord>(cfg, hunterKeyFile(agentId));
if (!key?.private_key || key.account_id !== agentId) throw new Error(`no function-call key for ${agentId} in ${cfg.secretsDir}`);
const thiefTarget = cfg.accounts.thief ?? cfg.accounts.owner ?? contractId; // where a thief would send money

const log = (s = "") => console.log(s);
const permissionOf = async () => {
  try {
    const ak = await provider.viewAccessKey({ accountId: agentId, publicKey: key.public_key, finalityQuery: { finality: "final" } });
    return ak.permission as unknown;
  } catch {
    return null;
  }
};
const vaultOf = () => view<VaultView | null>(provider, contractId, "get_vault", { account_id: agentId });
const balanceOf = async () => (await provider.viewAccount({ accountId: agentId, blockQuery: { finality: "final" } })).amount;

const permission = await permissionOf();
const vaultBefore = await vaultOf();
const balanceBefore = await balanceOf();
log(`attack f: stolen AI-hunter key on ${contractId}`);
log(`  signer ${agentId}, key ${key.public_key}`);
log(`  on-chain permission of this key: ${JSON.stringify(permission)}`);
if (!permission || typeof permission !== "object") throw new Error("the key is not on chain or is a full-access key; refusing to run");
log(`  vault before: balance ${fmtNear(vaultBefore?.balance, 5)} NEAR, policy max_bond_per_report ${fmtNear(vaultBefore?.max_bond_per_report, 5)}, ` +
  `max_spend_per_day ${fmtNear(vaultBefore?.max_spend_per_day, 5)}, allowed_programs ${JSON.stringify(vaultBefore?.allowed_programs ?? null)}, ` +
  `spent_in_window ${fmtNear(vaultBefore?.spent_in_window, 5)}`);
log(`  account balance before: ${fmtNear(balanceBefore, 5)} NEAR`);
log();

// The thief's transactions go to one RPC endpoint without failover, so that the protocol's own
// error for each refused transaction reaches this script.
const txProvider = new JsonRpcProvider({ url: cfg.rpcUrls[0] }, { retries: 2, backoff: 1.5, wait: 1000 });
const thief = new Account(agentId, txProvider, key.private_key as `ed25519:${string}`);
const GAS = 100_000_000_000_000n;

interface Row { n: number; attempt: string; outcome: string; kind: string; message: string; tx: string | null }
const rows: Row[] = [];
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function attempt(attemptName: string, receiverId: string, actions: ReturnType<typeof nearActions.transfer>[]): Promise<Row> {
  const n = rows.length + 1;
  log(`[${n}] ${attemptName}`);
  let row: Row = { n, attempt: attemptName, outcome: "", kind: "", message: "", tx: null };
  for (let i = 1; i <= 5; i++) {
    row = await tryOnce(n, attemptName, receiverId, actions);
    if (!row.outcome.startsWith("INCONCLUSIVE")) break;
    if (i < 5) {
      log(`    (network error: ${row.kind}; retry ${i} of 4)`);
      await sleep(3000 * i);
    }
  }
  log(`    -> ${row.outcome}: ${row.kind}: ${row.message}${row.tx ? `\n       tx ${row.tx} ${txUrl(cfg.network, row.tx)}` : ""}`);
  rows.push(row);
  return row;
}

async function tryOnce(n: number, attemptName: string, receiverId: string, actions: ReturnType<typeof nearActions.transfer>[]): Promise<Row> {
  try {
    const res = await thief.signAndSendTransaction({ receiverId, actions, waitUntil: "FINAL", throwOnFailure: false });
    const hash = res.transaction_outcome?.id ?? null;
    const status = res.status as Record<string, unknown>;
    if (status && "Failure" in status) {
      const raw = JSON.stringify(status.Failure);
      const failure = status.Failure as Record<string, unknown>;
      const kind = Object.keys((failure.ActionError as Record<string, unknown>)?.kind as object ?? failure)[0] ?? "Failure";
      return { n, attempt: attemptName, outcome: "failed on chain", kind, message: panicText(raw) ?? raw.slice(0, 300), tx: hash };
    }
    return { n, attempt: attemptName, outcome: "SUCCEEDED (bad!)", kind: "-", message: JSON.stringify(status).slice(0, 200), tx: hash };
  } catch (e) {
    const info: TxErrorInfo = describeTxError(e);
    const outcome = info.transport ? "INCONCLUSIVE (network error, not an answer of the protocol)"
      : info.txHash ? "failed on chain" : "refused by the RPC (never included)";
    return { n, attempt: attemptName, outcome, kind: info.kind, message: panicText(info.message) ?? info.message, tx: info.txHash };
  }
}

const fn = (method: string, args: Record<string, unknown>, deposit: bigint) => nearActions.functionCall(method, args, GAS, deposit);
const newKey = KeyPair.fromRandom("ed25519").getPublicKey();
const raised = { max_bond_per_report: near("10").toString(), max_spend_per_day: near("10").toString(), allowed_programs: null };

await attempt("vault_withdraw 0.1 NEAR with the 1 yoctoNEAR it requires", contractId, [fn("vault_withdraw", { amount: near("0.1").toString() }, 1n)]);
await attempt("vault_withdraw 0.1 NEAR without a deposit", contractId, [fn("vault_withdraw", { amount: near("0.1").toString() }, 0n)]);
await attempt("vault_set_policy: 10 NEAR per report and per day, any program (1 yoctoNEAR)", contractId, [fn("vault_set_policy", raised, 1n)]);
await attempt("vault_set_policy: the same without a deposit", contractId, [fn("vault_set_policy", raised, 0n)]);
await attempt(`transfer 0.1 NEAR to ${thiefTarget}`, thiefTarget, [nearActions.transfer(near("0.1"))]);
await attempt("add a new full-access key to the agent account", agentId, [nearActions.addFullAccessKey(newKey)]);
await attempt("add a function-call key that may call vault_withdraw", agentId,
  [nearActions.addFunctionCallAccessKey(newKey, contractId, [...HUNTER_KEY_METHODS, "vault_withdraw", "vault_set_policy"])]);
await attempt(`delete the agent account (beneficiary ${thiefTarget})`, agentId, [nearActions.deleteAccount(thiefTarget)]);
const otherContract = values["other-contract"] ?? (DEMO_CONTRACT[cfg.network] !== contractId ? DEMO_CONTRACT[cfg.network] : null);
if (otherContract) {
  await attempt(`finalize on another contract (${otherContract})`, otherContract, [fn("finalize", { submission_id: 0 }, 0n)]);
}

// Submissions the vault policy forbids. They pass the key's checks (right receiver, allowed method,
// no deposit), so they execute and the CONTRACT refuses them; they cost gas from the key's allowance.
const programs = await view<Prog[]>(provider, contractId, "list_programs", { from_index: 0, limit: 50 });
const allowed = vaultBefore?.allowed_programs ?? null;
const offList = allowed ? programs.find((p) => !allowed.includes(p.id)) : undefined;
const inList = programs.find((p) => allowed === null || allowed.includes(p.id));
const stamp = new Date().toISOString();
if (offList) {
  const report = Buffer.from(`# stolen-key probe\n\nsubmitted with the agent's stolen function-call key, ${stamp}\n`);
  await attempt(`submit_report_from_vault to program ${offList.id}, which is not in the vault's allowed programs`, contractId,
    [fn("submit_report_from_vault", { program_id: offList.id, title: "stolen-key probe: program outside the policy",
      commitment: commitmentFor(agentId, report), sealed: seal(report, offList.verifier_pubkey) }, 0n)]);
}
if (inList && vaultBefore) {
  // A report whose bond + storage does not fit into what is left of the vault's 24 h window.
  const required = BigInt(await view<string>(provider, contractId, "required_bond", { program_id: inList.id, hunter_id: agentId }));
  const perByte = await storageBytePrice(provider);
  const windowOpen = BigInt(vaultBefore.window_start) > 0n && BigInt(Date.now()) * 1_000_000n < BigInt(vaultBefore.window_start) + 86_400n * 1_000_000_000n;
  const left = BigInt(vaultBefore.max_spend_per_day) - (windowOpen ? BigInt(vaultBefore.spent_in_window) : 0n);
  const base = fs.readFileSync(path.join(REPO_ROOT, "engine", "reports", "02_seneca_chamber.md"), "utf8");
  let text = `${base}\n\n<!-- stolen-key probe ${stamp} -->\n`;
  const title = "stolen-key probe: over the daily spending cap";
  let sealed = seal(Buffer.from(text), inList.verifier_pubkey);
  while (required + storageEstimate(sealed.length, title.length, agentId, perByte) <= left + near("0.02") && sealed.length < 60_000) {
    text += `\n${base}`;
    sealed = seal(Buffer.from(text), inList.verifier_pubkey);
  }
  const cost = required + storageEstimate(sealed.length, title.length, agentId, perByte);
  log(`  (left in the vault's 24 h window: ${fmtNear(left, 5)} NEAR; the probe report needs about ${fmtNear(cost, 5)} NEAR: bond ${fmtNear(required, 5)} + storage)`);
  await attempt(`submit_report_from_vault to program ${inList.id} with a report over the daily cap (${Buffer.byteLength(text)} bytes)`, contractId,
    [fn("submit_report_from_vault", { program_id: inList.id, title, commitment: commitmentFor(agentId, Buffer.from(text)), sealed }, 0n)]);
}

const vaultAfter = await vaultOf();
const balanceAfter = await balanceOf();
const permissionAfter = await permissionOf();
const allowanceOf = (p: unknown) => (p as { FunctionCall?: { allowance?: string | null } })?.FunctionCall?.allowance ?? null;
log();
log(`vault after: balance ${fmtNear(vaultAfter?.balance, 5)} NEAR (before ${fmtNear(vaultBefore?.balance, 5)}), ` +
  `max_bond_per_report ${fmtNear(vaultAfter?.max_bond_per_report, 5)}, max_spend_per_day ${fmtNear(vaultAfter?.max_spend_per_day, 5)}, ` +
  `allowed_programs ${JSON.stringify(vaultAfter?.allowed_programs ?? null)}`);
log(`account balance after: ${fmtNear(balanceAfter, 5)} NEAR (before ${fmtNear(balanceBefore, 5)}; the difference is gas of the two executed probes)`);
log(`key allowance: ${fmtNear(allowanceOf(permission), 5)} NEAR before, ${fmtNear(allowanceOf(permissionAfter), 5)} NEAR after`);
log();
log("| # | attempt with the stolen function-call key | result | error | tx |");
log("|---|---|---|---|---|");
for (const r of rows) {
  log(`| ${r.n} | ${r.attempt} | ${r.outcome} | \`${r.kind}\`: ${r.message.replace(/\|/g, "\\|")} | ${r.tx ? `[\`${r.tx.slice(0, 8)}…\`](${txUrl(cfg.network, r.tx)})` : "-"} |`);
}
const bad = rows.filter((r) => r.outcome.startsWith("SUCCEEDED"));
const unclear = rows.filter((r) => r.outcome.startsWith("INCONCLUSIVE"));
log();
if (bad.length > 0) log(`${bad.length} ATTEMPT(S) SUCCEEDED - THE KEY IS NOT LIMITED`);
else if (unclear.length > 0) log(`${unclear.length} ATTEMPT(S) INCONCLUSIVE because of network errors - run the script again`);
else log(`ALL ${rows.length} ATTEMPTS FAILED, as they must.`);
if (values.json) {
  fs.writeFileSync(values.json, JSON.stringify({
    contract: contractId, signer: agentId, public_key: key.public_key, permission, permission_after: permissionAfter,
    vault_before: vaultBefore, vault_after: vaultAfter, balance_before: balanceBefore.toString(), balance_after: balanceAfter.toString(),
    attempts: rows, at: new Date().toISOString(),
  }, null, 2) + "\n");
}
process.exit(bad.length > 0 ? 1 : unclear.length > 0 ? 2 : 0);
