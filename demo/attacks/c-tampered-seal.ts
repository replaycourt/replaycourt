#!/usr/bin/env node
// Attack demo c: a tampered sealed report. The hunter commits to one file (a cheap placeholder)
// but seals another one (a copy of somebody else's valid report), hoping that the verifier
// judges the sealed text while the placeholder holds an early commit time. The worker must post
// `invalid` with the reason "sealed report does not match commitment", without running the
// sealed text, and the contract slashes the bond. The commitment is the v2 commitment
// (agent/src/seal.ts commitmentFor), bound to the submitting hunter account.
//
// This is a separate script on purpose: the hunter CLI (agent/src/cli.ts) has no way to seal a
// different file than the one it commits to.
//
//   node demo/attacks/c-tampered-seal.ts --program 0 --as hunter2 \
//     [--committed demo/attacks/c-committed.md] [--sealed engine/reports/01_templedao_stax.md]
//
// Configuration as for the agent CLI (REPLAYCOURT_CONFIG, ...). Testnet only.

import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { storageEstimate } from "../../agent/src/actions.ts";
import { tamperedSubmission } from "../../agent/src/attacks.ts";
import { REPO_ROOT, loadConfig, requireContract, resolveAccount } from "../../agent/src/config.ts";
import { GAS, accountFromCredentials, call, fmtNear, makeProvider, storageBytePrice, txUrl, view } from "../../agent/src/near.ts";
import { commitmentFor, openAndCheck } from "../../agent/src/seal.ts";

const { values } = parseArgs({
  options: {
    program: { type: "string", default: "0" },
    as: { type: "string", default: "hunter2" },
    committed: { type: "string", default: path.join(REPO_ROOT, "demo", "attacks", "c-committed.md") },
    sealed: { type: "string", default: path.join(REPO_ROOT, "engine", "reports", "01_templedao_stax.md") },
    title: { type: "string", default: "Reentrancy in a lending pool (details follow)" },
  },
});

const cfg = loadConfig();
if (cfg.network !== "testnet") throw new Error("attack demos run on testnet only");
const provider = makeProvider(cfg);
const contractId = requireContract(cfg);
const programId = Number(values.program);
const hunter = resolveAccount(cfg, values.as, "hunter2");
const program = await view<{ verifier_pubkey: string; name: string } | null>(provider, contractId, "get_program", { program_id: programId });
if (!program) throw new Error(`program ${programId} not found on ${contractId}`);

const committed = fs.readFileSync(values.committed);
const sealedFrom = fs.readFileSync(values.sealed);
const t = tamperedSubmission(committed, sealedFrom, program.verifier_pubkey, hunter);
if (t.commitment !== commitmentFor(hunter, committed)) throw new Error("internal: commitment mismatch");
console.log(`attack c: tampered sealed report on ${contractId}, program ${programId} "${program.name}", hunter ${hunter}`);
console.log(`  commitment       = commitment v2 of (${hunter}, ${path.relative(REPO_ROOT, values.committed)}) = ${t.commitment}`);
console.log(`  sealed blob      = seal(${path.relative(REPO_ROOT, values.sealed)}) to the verifier key, ${t.sealed.length} bytes`);
console.log(`  commitment of the sealed plaintext = ${t.sealedPlaintextCommitment} (differs from the committed one)`);

// Same deposit rule as `cli.ts submit`: required bond + storage estimate (the contract keeps
// deposit - storage as bond).
const required = BigInt(await view<string>(provider, contractId, "required_bond", { program_id: programId, hunter_id: hunter }));
const deposit = required + storageEstimate(t.sealed.length, Buffer.byteLength(values.title), hunter, await storageBytePrice(provider));
console.log(`  deposit ${fmtNear(deposit)} NEAR (required bond ${fmtNear(required)} + storage estimate)`);

const res = await call<number>(accountFromCredentials(cfg, provider, hunter), contractId, "submit_report",
  { program_id: programId, title: values.title, commitment: t.commitment, sealed: t.sealed }, { deposit, gas: GAS.call });
console.log(`submission id: ${res.result}`);
console.log(`submit_report: tx ${res.txHash}`);
console.log(`  ${txUrl(cfg.network, res.txHash)}`);

// What the worker will see (only checkable here if this machine holds the verifier key).
const keyFile = path.join(cfg.secretsDir, "verifier-x25519.json");
if (fs.existsSync(keyFile)) {
  const key = JSON.parse(fs.readFileSync(keyFile, "utf8")) as { private_key: string };
  const check = openAndCheck(t.sealed, key.private_key, t.commitment, hunter);
  console.log(`local check with the verifier key: ${check.ok ? "opens and matches (unexpected)" : check.error}`);
}
console.log("next: run the worker (node src/cli.ts worker --once in agent/); it must post `invalid` with the reason");
console.log("      \"sealed report does not match commitment\" and the contract slashes the bond.");
