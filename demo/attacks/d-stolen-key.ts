#!/usr/bin/env node
// Attack demo d: the verifier worker's key is stolen. The worker signs with a function-call
// access key (receiver = the ReplayCourt contract, methods = [post_verdict], gas allowance). This
// script holds ONLY that key (read from .secrets/<deployment>/verifier-fc-key.json) and tries
// everything a thief would try. Every attempt must fail; the script prints the exact errors and,
// for transactions that reached the chain, their hashes. Exit 0 only if every attempt was refused
// by the protocol or the contract; 1 if one succeeded; 2 if network errors left one undecided.
//
//   node demo/attacks/d-stolen-key.ts [--judged <id>] [--foreign <id>] [--other-contract <id>]
//                                     [--allowance-demo] [--json <file>]
//
// --judged    a submission that already has a verdict (default: the first one found)
// --foreign   a submission of a program whose verifier is another account (default: the first pending
//             one in that program's list_pending view, else its first submission)
// --other-contract  another contract to call post_verdict on (default: the showcase deployment,
//             unless this is the showcase; then the attempt runs only with this option)
// --allowance-demo  additionally shows a function-call key whose gas allowance is used up. Its
//             setup (adding a key with a 0.001 NEAR allowance, deleting it afterwards) is signed
//             with the verifier's FULL-ACCESS key, i.e. by the operator, not by the thief.
// Configuration as for the agent CLI (REPLAYCOURT_CONFIG, ...). Testnet only.

import fs from "node:fs";
import { parseArgs } from "node:util";
import { Account, JsonRpcProvider, KeyPair, PublicKey, describeTxError, nearActions, panicText } from "../../agent/src/attacks.ts";
import type { TxErrorInfo } from "../../agent/src/attacks.ts";
import { DEMO_CONTRACT, loadConfig, readSecret, requireContract, resolveAccount } from "../../agent/src/config.ts";
import { accountFromCredentials, fmtNear, makeProvider, near, txUrl, view } from "../../agent/src/near.ts";

const { values } = parseArgs({
  options: {
    judged: { type: "string" },
    foreign: { type: "string" },
    "other-contract": { type: "string" },
    "allowance-demo": { type: "boolean", default: false },
    json: { type: "string" },
  },
});

interface FcKeySecret { account_id: string; contract_id: string; public_key: string; private_key: string; allowance?: string }
interface Sub { id: number; program_id: number; status: string; verdict: unknown }
interface Prog { id: number; verifier_id: string; name: string }

const cfg = loadConfig();
if (cfg.network !== "testnet") throw new Error("attack demos run on testnet only");
const provider = makeProvider(cfg);
const contractId = requireContract(cfg);
const verifierId = resolveAccount(cfg, undefined, "verifier");
const fc = readSecret<FcKeySecret>(cfg, "verifier-fc-key.json");
if (!fc?.private_key || fc.account_id !== verifierId) throw new Error(`no function-call key for ${verifierId} in ${cfg.secretsDir}`);
const victimTarget = resolveAccount(cfg, undefined, "hunter1"); // where a thief would send money

const log = (s = "") => console.log(s);
async function accessKey(pk: string): Promise<Record<string, unknown> | null> {
  try {
    return (await provider.viewAccessKey({ accountId: verifierId, publicKey: pk, finalityQuery: { finality: "final" } })) as unknown as Record<string, unknown>;
  } catch {
    return null;
  }
}

const ak = await accessKey(fc.public_key);
log(`attack d: stolen verifier key on ${contractId}`);
log(`  signer ${verifierId}, key ${fc.public_key}`);
log(`  on-chain permission of this key: ${JSON.stringify(ak?.permission)}`);
if (!ak || typeof ak.permission !== "object") throw new Error("the key is not on chain or is a full-access key; refusing to run");

// Targets on the contract.
const programs: Prog[] = await view<Prog[]>(provider, contractId, "list_programs", { from_index: 0, limit: 50 });
const subsOf = (p: number) => view<Sub[]>(provider, contractId, "list_submissions", { program_id: p, from_index: 0, limit: 50 });
const pendingOf = (p: number) => view<Sub[]>(provider, contractId, "list_pending", { program_id: p, from_index: 0, limit: 50 });
let judged = values.judged !== undefined ? Number(values.judged) : null;
let foreign = values.foreign !== undefined ? Number(values.foreign) : null;
let ownProgram: number | null = null;
// The per-program pending view (v2: list_pending(program_id, ...)): what is waiting for a verdict in
// each program, and whose verifier may judge it. The stolen key belongs to verifierId only.
const pendingView: { program_id: number; verifier_id: string; own: boolean; pending: number[] }[] = [];
log("  per-program pending view (list_pending(program_id)):");
for (const p of programs) {
  const pending = (await pendingOf(p.id)).map((s) => s.id);
  const own = p.verifier_id === verifierId;
  pendingView.push({ program_id: p.id, verifier_id: p.verifier_id, own, pending });
  log(`    program ${p.id}: verifier ${p.verifier_id}${own ? " (the stolen key's account)" : " (another verifier)"}, pending [${pending.join(", ")}]`);
  if (own) {
    ownProgram ??= p.id;
    if (judged === null) judged = (await subsOf(p.id)).find((s) => s.verdict)?.id ?? null;
  } else if (foreign === null) {
    // Prefer a report that is still pending, so the contract's refusal can only be the verifier check.
    foreign = pending[0] ?? (await subsOf(p.id))[0]?.id ?? null;
  }
}
const otherContract = values["other-contract"] ?? (DEMO_CONTRACT[cfg.network] !== contractId ? DEMO_CONTRACT[cfg.network] : null);
log(`  judged submission: ${judged ?? "-"}, submission of a program with another verifier: ${foreign ?? "-"}, other contract: ${otherContract ?? "-"}`);
log();

// The thief's transactions go to one RPC endpoint without failover, so that the protocol's own
// error for each refused transaction reaches this script (a failover provider would replace it
// with "Exceeded 2 providers"). Reads above use the normal failover provider.
const txProvider = new JsonRpcProvider({ url: cfg.rpcUrls[0] }, { retries: 2, backoff: 1.5, wait: 1000 });
const thief = new Account(verifierId, txProvider, fc.private_key as `ed25519:${string}`);
const verdict = (reason: string) => ({
  outcome: "valid", severity: "critical", duplicate_of: null, fingerprint: "stolen-key",
  evidence_sha256: "00".repeat(32), evidence_uri: "", chain_id: 1, fork_block: "1", reason,
});
const GAS = 30_000_000_000_000n;

interface Row { n: number; attempt: string; outcome: string; kind: string; message: string; tx: string | null }
const rows: Row[] = [];

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Operator steps (full-access key) are retried on network trouble. */
async function withRetries<T>(what: string, fn: () => Promise<T>): Promise<T> {
  for (let i = 1; ; i++) {
    try {
      return await fn();
    } catch (e) {
      if (i >= 5 || !describeTxError(e).transport) throw e;
      log(`    (${what}: network error, retry ${i} of 4)`);
      await sleep(3000 * i);
    }
  }
}

async function attempt(attemptName: string, receiverId: string, actions: ReturnType<typeof nearActions.transfer>[],
  signer: Account = thief): Promise<Row> {
  const n = rows.length + 1;
  log(`[${n}] ${attemptName}`);
  let row: Row = { n, attempt: attemptName, outcome: "", kind: "", message: "", tx: null };
  // A network error says nothing about the key: retry it; only the protocol's answer counts.
  for (let i = 1; i <= 5; i++) {
    row = await tryOnce(n, attemptName, receiverId, actions, signer);
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

async function tryOnce(n: number, attemptName: string, receiverId: string, actions: ReturnType<typeof nearActions.transfer>[],
  signer: Account): Promise<Row> {
  let row: Row;
  try {
    const res = await signer.signAndSendTransaction({ receiverId, actions, waitUntil: "FINAL", throwOnFailure: false });
    const hash = res.transaction_outcome?.id ?? null;
    const status = res.status as Record<string, unknown>;
    if (status && "Failure" in status) {
      const raw = JSON.stringify(status.Failure);
      const failure = status.Failure as Record<string, unknown>;
      const kind = Object.keys((failure.ActionError as Record<string, unknown>)?.kind as object ?? failure)[0] ?? "Failure";
      row = { n, attempt: attemptName, outcome: "failed on chain", kind, message: panicText(raw) ?? raw.slice(0, 300), tx: hash };
    } else {
      row = { n, attempt: attemptName, outcome: "SUCCEEDED (bad!)", kind: "-", message: JSON.stringify(status).slice(0, 200), tx: hash };
    }
  } catch (e) {
    const info: TxErrorInfo = describeTxError(e);
    const outcome = info.transport ? "INCONCLUSIVE (network error, not an answer of the protocol)"
      : info.txHash ? "failed on chain" : "refused by the RPC (never included)";
    row = { n, attempt: attemptName, outcome, kind: info.kind, message: panicText(info.message) ?? info.message, tx: info.txHash };
  }
  return row;
}

const newKey = KeyPair.fromRandom("ed25519").getPublicKey();
await attempt(`transfer 0.01 NEAR to ${victimTarget}`, victimTarget, [nearActions.transfer(near("0.01"))]);
await attempt("add a new full-access key to the verifier account", verifierId, [nearActions.addFullAccessKey(newKey)]);
await attempt("add a new function-call key without allowance limit", verifierId,
  [nearActions.addFunctionCallAccessKey(newKey, contractId, ["post_verdict", "withdraw_pool"])]);
await attempt(`delete the verifier account (beneficiary ${victimTarget})`, verifierId, [nearActions.deleteAccount(victimTarget)]);
await attempt(`call withdraw_pool(${ownProgram ?? 0}) on the contract`, contractId,
  [nearActions.functionCall("withdraw_pool", { program_id: ownProgram ?? 0, amount: "1" }, GAS, 0n)]);
await attempt("call finalize (another method of the same contract)", contractId,
  [nearActions.functionCall("finalize", { submission_id: judged ?? 0 }, GAS, 0n)]);
await attempt("post_verdict with 1 yoctoNEAR attached", contractId,
  [nearActions.functionCall("post_verdict", { submission_id: judged ?? 0, verdict: verdict("deposit") }, GAS, 1n)]);
if (otherContract) {
  await attempt(`post_verdict on another contract (${otherContract})`, otherContract,
    [nearActions.functionCall("post_verdict", { submission_id: 0, verdict: verdict("receiver") }, GAS, 0n)]);
}
if (foreign !== null) {
  await attempt(`post_verdict on submission #${foreign} of a program with another verifier`, contractId,
    [nearActions.functionCall("post_verdict", { submission_id: foreign, verdict: verdict("not my program") }, GAS, 0n)]);
}
if (judged !== null) {
  await attempt(`post a second verdict on the already judged submission #${judged}`, contractId,
    [nearActions.functionCall("post_verdict", { submission_id: judged, verdict: verdict("overwrite") }, GAS, 0n)]);
}

// Gas allowance: what the key has left, and what happens when it is used up.
const allowanceNow = (ak.permission as { FunctionCall?: { allowance?: string | null } }).FunctionCall?.allowance ?? null;
log();
log(`allowance of the worker key: ${allowanceNow === null ? "unlimited" : fmtNear(allowanceNow, 6) + " NEAR left"}` +
  (fc.allowance ? ` of ${fmtNear(fc.allowance, 6)} NEAR granted` : ""));
const allowanceDemo: Record<string, unknown> = {};
if (values["allowance-demo"]) {
  const operator = accountFromCredentials(cfg, provider, verifierId); // full-access key: operator setup only
  const tiny = KeyPair.fromRandom("ed25519");
  const tinyPk = tiny.getPublicKey().toString();
  const add = await withRetries("add key", () =>
    operator.addFunctionCallAccessKey({ publicKey: tinyPk, contractId, methodNames: ["post_verdict"], allowance: near("0.001") }));
  allowanceDemo.add_key_tx = add.transaction_outcome?.id;
  log(`setup (operator, full-access key): added function-call key ${tinyPk} with allowance 0.001 NEAR - tx ${String(allowanceDemo.add_key_tx)}`);
  const small = new Account(verifierId, txProvider, tiny.toString() as `ed25519:${string}`);
  await attempt("post_verdict with a key whose allowance (0.001 NEAR) is below the cost of the call", contractId,
    [nearActions.functionCall("post_verdict", { submission_id: judged ?? 0, verdict: verdict("allowance") }, 100_000_000_000_000n, 0n)], small);
  const del = await withRetries("delete key", () => operator.deleteKey(PublicKey.fromString(tinyPk)));
  allowanceDemo.delete_key_tx = del.transaction_outcome?.id;
  log(`cleanup (operator, full-access key): deleted that key - tx ${String(allowanceDemo.delete_key_tx)}`);
}

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
    contract: contractId, signer: verifierId, public_key: fc.public_key, permission: ak.permission, pending_view: pendingView,
    allowance_left: allowanceNow, allowance_granted: fc.allowance ?? null, allowance_demo: allowanceDemo, attempts: rows,
    at: new Date().toISOString(),
  }, null, 2) + "\n");
}
process.exit(bad.length > 0 ? 1 : unclear.length > 0 ? 2 : 0);
