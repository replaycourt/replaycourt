#!/usr/bin/env node
// Attack demo e: a copied sealed report. Everything a submission puts on-chain is public: its
// commitment and sealed blob (`get_submission`, `get_sealed`), and also the arguments of a
// `submit_report` transaction that failed. A thief copies them and submits them from its own
// account, hoping to take the victim's place in the commit order (and later its payout) without
// ever reading the report. Two variants:
//
//   1. --copy <id>     copy of a submission that landed: the contract refuses it, because each
//                      commitment can be used once ("commitment already used").
//   2. --from-failed   copy of a transaction that failed. The victim's `submit_report` fails (here
//                      on purpose: the attached deposit is below the required bond), so its
//                      commitment stays unused while its arguments are public. The thief reads
//                      them from the chain and submits them with a correct bond. The contract
//                      accepts the copy: it only enforces that a commitment is used once. The
//                      worker then recomputes the v2 commitment,
//                      sha256("replaycourt/commit/v2" || 0 || hunter || 0 || report), with the
//                      THIEF's account, finds no match and posts `invalid` ("sealed report does
//                      not match commitment"); the thief's bond is slashed.
//
//   node demo/attacks/e-copied-seal.ts --program 0 --victim hunter1 --as thief [--copy <id>] [--from-failed]
//        [--report engine/reports/02_seneca_chamber.md] [--json <file>]
//
// The victim's failing transaction is signed with the victim's own full-access key (the victim
// acting, not the thief). The thief signs only its own transactions. Configuration as for the
// agent CLI (REPLAYCOURT_CONFIG, ...). Testnet only.

import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { storageEstimate } from "../../agent/src/actions.ts";
import { describeTxError, nearActions, panicText } from "../../agent/src/attacks.ts";
import { REPO_ROOT, VERIFIER_X25519_FILE, loadConfig, readSecret, requireContract, resolveAccount } from "../../agent/src/config.ts";
import { accountFromCredentials, fmtNear, makeProvider, near, storageBytePrice, txUrl, view } from "../../agent/src/near.ts";
import { commitmentFor, openAndCheck, seal } from "../../agent/src/seal.ts";

const { values } = parseArgs({
  options: {
    program: { type: "string", default: "0" },
    victim: { type: "string", default: "hunter1" },
    as: { type: "string", default: "thief" },
    copy: { type: "string" },
    "from-failed": { type: "boolean", default: false },
    report: { type: "string", default: path.join(REPO_ROOT, "engine", "reports", "02_seneca_chamber.md") },
    title: { type: "string" },
    json: { type: "string" },
  },
});

interface Sub { id: number; program_id: number; hunter_id: string; title: string; commitment: string; status: string }
interface Step { step: string; signer: string; outcome: string; message: string; tx: string | null; submission_id?: number }

const cfg = loadConfig();
if (cfg.network !== "testnet") throw new Error("attack demos run on testnet only");
const provider = makeProvider(cfg);
const contractId = requireContract(cfg);
const programId = Number(values.program);
const victim = resolveAccount(cfg, values.victim, "hunter1");
const thiefId = resolveAccount(cfg, values.as, "thief");
if (thiefId === victim) throw new Error("the thief must be another account than the victim");
const program = await view<{ verifier_pubkey: string; name: string } | null>(provider, contractId, "get_program", { program_id: programId });
if (!program) throw new Error(`program ${programId} not found on ${contractId}`);
const perByte = await storageBytePrice(provider);
const thief = accountFromCredentials(cfg, provider, thiefId);
const verifierKey = readSecret<{ private_key: string }>(cfg, VERIFIER_X25519_FILE);
const steps: Step[] = [];
const log = (s = "") => console.log(s);

log(`attack e: copied sealed report on ${contractId}, program ${programId} "${program.name}"`);
log(`  victim ${victim}, thief ${thiefId}`);

/** Sends one function call and returns how it ended, with the tx hash if it reached the chain. */
async function send(signer: typeof thief, step: string, method: string, args: Record<string, unknown>, deposit: bigint): Promise<Step> {
  let row: Step;
  try {
    const res = await signer.signAndSendTransaction({
      receiverId: contractId,
      actions: [nearActions.functionCall(method, args, 100_000_000_000_000n, deposit)],
      waitUntil: "FINAL",
      throwOnFailure: false,
    });
    const hash = res.transaction_outcome?.id ?? null;
    const status = res.status as Record<string, unknown>;
    if (status && "Failure" in status) {
      const raw = JSON.stringify(status.Failure);
      row = { step, signer: signer.accountId, outcome: "failed on chain", message: panicText(raw) ?? raw.slice(0, 300), tx: hash };
    } else {
      const b64 = (status as { SuccessValue?: string }).SuccessValue ?? "";
      const value = b64 ? JSON.parse(Buffer.from(b64, "base64").toString("utf8")) : null;
      row = { step, signer: signer.accountId, outcome: "succeeded", message: `returned ${JSON.stringify(value)}`, tx: hash };
      if (typeof value === "number") row.submission_id = value;
    }
  } catch (e) {
    const info = describeTxError(e);
    row = { step, signer: signer.accountId, outcome: info.transport ? "INCONCLUSIVE (network error)" : "refused", message: panicText(info.message) ?? info.message, tx: info.txHash };
  }
  log(`    -> ${row.outcome}: ${row.message}${row.tx ? `\n       tx ${row.tx} ${txUrl(cfg.network, row.tx)}` : ""}`);
  steps.push(row);
  return row;
}

/** The arguments of a transaction, read back from the chain (any RPC node serves them). */
async function txArgs(hash: string, sender: string): Promise<Record<string, unknown>> {
  let lastErr: unknown = null;
  for (const url of cfg.rpcUrls) {
    for (let i = 1; i <= 4; i++) {
      try {
        const r = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tx", params: { tx_hash: hash, sender_account_id: sender, wait_until: "FINAL" } }),
        });
        const j = (await r.json()) as { result?: { transaction: { actions: { FunctionCall?: { args: string } }[] } }; error?: unknown };
        const fc = j.result?.transaction.actions[0]?.FunctionCall;
        if (fc) return JSON.parse(Buffer.from(fc.args, "base64").toString("utf8")) as Record<string, unknown>;
        lastErr = j.error;
      } catch (e) {
        lastErr = e;
      }
      await new Promise((res) => setTimeout(res, 2000 * i));
    }
  }
  throw new Error(`could not read the arguments of tx ${hash}: ${JSON.stringify(lastErr)}`);
}

/** The thief submits a copied commitment + sealed blob with a bond that covers its own required bond. */
async function thiefSubmits(step: string, args: { title: string; commitment: string; sealed: string }): Promise<Step> {
  const required = BigInt(await view<string>(provider, contractId, "required_bond", { program_id: programId, hunter_id: thiefId }));
  const deposit = required + storageEstimate(args.sealed.length, Buffer.byteLength(args.title), thiefId, perByte);
  log(`    thief attaches ${fmtNear(deposit)} NEAR (its required bond ${fmtNear(required)} + storage estimate)`);
  return send(thief, step, "submit_report", { program_id: programId, title: args.title, commitment: args.commitment, sealed: args.sealed }, deposit);
}

function bindingCheck(sealed: string, commitment: string): void {
  if (!verifierKey) {
    log("  (no verifier key on this machine: the binding check is left to the worker)");
    return;
  }
  const asThief = openAndCheck(sealed, verifierKey.private_key, commitment, thiefId);
  const asVictim = openAndCheck(sealed, verifierKey.private_key, commitment, victim);
  log(`  as the verifier: the blob opens; v2 commitment for ${victim}: ${asVictim.ok ? "matches" : "no match"}; ` +
    `for ${thiefId}: ${asThief.ok ? "MATCHES (unexpected)" : "no match -> \"sealed report does not match commitment\""}`);
}

// ---------------------------------------------------------------- variant 1: a landed submission
if (values.copy !== undefined) {
  const id = Number(values.copy);
  const s = await view<Sub | null>(provider, contractId, "get_submission", { submission_id: id });
  const sealed = await view<string | null>(provider, contractId, "get_sealed", { submission_id: id });
  if (!s || !sealed) throw new Error(`submission ${id} not found`);
  log();
  log(`[e.1] copy of submission #${id} (hunter ${s.hunter_id}, status ${s.status}), read with get_submission + get_sealed`);
  log(`  commitment ${s.commitment}, sealed blob ${sealed.length} bytes, title "${s.title}"`);
  await thiefSubmits(`thief resubmits the commitment + sealed blob of #${id}`, { title: s.title, commitment: s.commitment, sealed });
}

// ---------------------------------------------------------------- variant 2: a failed transaction
if (values["from-failed"]) {
  const report = fs.readFileSync(values.report);
  const title = values.title ?? "Unchecked operation in Chamber.performOperations() lets anyone move approved tokens";
  const commitment = commitmentFor(victim, report);
  const sealed = seal(report, program.verifier_pubkey);
  log();
  log(`[e.2] the victim ${victim} sends ${path.relative(REPO_ROOT, values.report)}; the transaction fails (deposit below the required bond)`);
  log(`  commitment v2 of (${victim}, report) = ${commitment}, sealed blob ${sealed.length} bytes`);
  const failed = await send(accountFromCredentials(cfg, provider, victim), "victim's submit_report with 0.01 NEAR attached",
    "submit_report", { program_id: programId, title, commitment, sealed }, near("0.01"));
  if (!failed.tx || failed.outcome !== "failed on chain") throw new Error("the victim's transaction did not fail on chain as planned");

  log(`  the thief reads the failed transaction ${failed.tx} from the chain (RPC "tx")`);
  const copied = await txArgs(failed.tx, victim);
  const c = { title: String(copied.title), commitment: String(copied.commitment), sealed: String(copied.sealed) };
  if (c.commitment !== commitment || c.sealed !== sealed) throw new Error("internal: copied arguments differ from the sent ones");
  log(`  copied: commitment ${c.commitment}, sealed blob ${c.sealed.length} bytes, title "${c.title}"`);
  const landed = await thiefSubmits("thief submits the copied commitment + sealed blob", c);
  if (landed.submission_id !== undefined) log(`  submission id ${landed.submission_id}: now the worker judges it`);
  bindingCheck(c.sealed, c.commitment);
}

log();
log("| step | signer | result | message | tx |");
log("|---|---|---|---|---|");
for (const r of steps) {
  log(`| ${r.step} | ${r.signer} | ${r.outcome}${r.submission_id !== undefined ? ` (#${r.submission_id})` : ""} | ${r.message.replace(/\|/g, "\\|")} | ${r.tx ? `[\`${r.tx.slice(0, 8)}…\`](${txUrl(cfg.network, r.tx)})` : "-"} |`);
}
if (values.json) {
  fs.writeFileSync(values.json, JSON.stringify({ contract: contractId, program: programId, victim, thief: thiefId, steps, at: new Date().toISOString() }, null, 2) + "\n");
}
log();
log("next: run the worker (node src/cli.ts worker --once in agent/); for the copy that landed it must post");
log("      `invalid` with the reason \"sealed report does not match commitment\", and the contract slashes the bond.");
process.exit(steps.some((r) => r.outcome.startsWith("INCONCLUSIVE")) ? 2 : 0);
