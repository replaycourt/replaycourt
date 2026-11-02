#!/usr/bin/env node
// ReplayCourt agent CLI: hunter commands, verifier worker, demo wrappers. Run: node src/cli.ts <command> --help

import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import type { ParseArgsConfig } from "node:util";
import {
  ActionError,
  HUNTER_KEY_METHODS,
  VERIFIER_KEY_METHODS,
  createProgram,
  disputeSubmission,
  formatVault,
  functionCallKeyProblem,
  getVault,
  hunterKeyFile,
  prepareSubmission,
  setupHunterKey,
  submitFromVault,
  submitReport,
  vaultDeposit,
  vaultSetPolicy,
  vaultWithdraw,
} from "./actions.ts";
import type { ChainClient, HunterKeyRecord, Signer } from "./actions.ts";
import {
  DEFAULT_RPC,
  DEMO_CONTRACT,
  REPO_ROOT,
  VERIFIER_FC_KEY_FILE,
  VERIFIER_X25519_FILE,
  loadConfig,
  loadFullAccessKey,
  pinnedPrograms,
  privateRunsDir,
  readSecret,
  requireContract,
  resolveAccount,
  runsDir,
  workerPrograms,
  writeSecret,
} from "./config.ts";
import type { Config } from "./config.ts";
import { publishEvidence } from "./disclosure.ts";
import { mapSeverity } from "./mapping.ts";
import type { VerdictInput } from "./mapping.ts";
import {
  GAS,
  accountFromCredentials,
  accountUrl,
  accountWithKey,
  call,
  describeError,
  fmtNear,
  makeChainClient,
  makeProvider,
  near,
  newEd25519,
  publicKeyOfSecret,
  txUrl,
  view,
} from "./near.ts";
import { commitmentFor, commitmentOf, generateVerifierKeypair, openAndCheck, publicKeyOf, seal, unseal } from "./seal.ts";
import { formatTable, majorOf, makeEvidenceReader, printable, resultLine, summaryLine, verifyOnchain } from "./verify.ts";
import { DISCLOSURE_MODES, killEngineRuns, makeEngineRunner, parseWrapper, processPending, withInfraRetries } from "./worker.ts";
import type { Disclosure, ProgramView, SubmissionView, WorkerContext, WorkerDeps } from "./worker.ts";

type Options = NonNullable<ParseArgsConfig["options"]>;

interface Command {
  usage: string;
  summary: string;
  options: Options;
  positionals?: boolean;
  run(values: Record<string, string | boolean | undefined>, positionals: string[]): Promise<number>;
}

interface X25519Secret {
  public_key: string;
  private_key: string;
}
interface FcKeySecret {
  account_id: string;
  contract_id: string;
  public_key: string;
  private_key: string;
  method_names: string[];
}

const err = (s: string) => process.stderr.write(s + "\n");
const out = (s: string) => process.stdout.write(s + "\n");

function str(v: string | boolean | undefined): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function needInt(v: string | undefined, what: string): number {
  if (v === undefined || !/^\d+$/.test(v)) throw new UsageError(`${what} must be a non-negative integer`);
  return Number(v);
}

function intList(v: string, what: string): number[] {
  return v.split(",").map((s) => s.trim()).filter(Boolean).map((s) => needInt(s, what));
}

class UsageError extends Error {}

function ctx() {
  const cfg = loadConfig();
  return { cfg, provider: makeProvider(cfg) };
}

function chainOf(): { cfg: Config; chain: ChainClient } {
  const { cfg, provider } = ctx();
  return { cfg, chain: makeChainClient(provider, requireContract(cfg)) };
}

/** Full-access signer of a role or account (key from the credentials directory). */
function fullAccess(cfg: Config, accountId: string): Signer {
  return { accountId, privateKey: loadFullAccessKey(cfg, accountId) };
}

function defaultHunter(cfg: Config): string {
  return cfg.accounts.hunter ? "hunter" : "hunter1";
}

function printTx(cfg: Config, label: string, hash: string) {
  out(`${label}: tx ${hash}`);
  out(`  ${txUrl(cfg.network, hash)}`);
}

function loadX25519(cfg: Config): X25519Secret {
  const s = readSecret<X25519Secret>(cfg, VERIFIER_X25519_FILE);
  if (!s?.private_key) throw new Error(`no verifier key in ${path.join(cfg.secretsDir, VERIFIER_X25519_FILE)} - run: node src/cli.ts keygen`);
  return s;
}

/** The hunter's function-call key from .secrets/, checked on-chain before it signs anything. */
async function loadHunterKey(cfg: Config, chain: ChainClient, hunterId: string): Promise<Signer> {
  const file = hunterKeyFile(hunterId);
  const rec = readSecret<HunterKeyRecord>(cfg, file);
  if (!rec?.private_key) throw new Error(`no function-call key in ${path.join(cfg.secretsDir, file)} - run: node src/cli.ts setup-hunter-key --as ${hunterId}`);
  if (rec.account_id !== hunterId || rec.contract_id !== chain.contractId) {
    throw new Error(`${file} is for ${rec.account_id} on ${rec.contract_id}, expected ${hunterId} on ${chain.contractId}`);
  }
  const problem = functionCallKeyProblem(await chain.accessKeyPermission(hunterId, rec.public_key), chain.contractId, HUNTER_KEY_METHODS);
  if (problem) throw new Error(`refusing to sign with ${rec.public_key}: ${problem}`);
  return { accountId: hunterId, privateKey: rec.private_key };
}

const nowNs = () => BigInt(Date.now()) * 1_000_000n;

async function listAllPages<T>(fetch: (from: number) => Promise<T[]>): Promise<T[]> {
  const all: T[] = [];
  for (let from = 0; ; from += 50) {
    const page = await fetch(from);
    all.push(...page);
    if (page.length < 50) break;
  }
  return all;
}

// ------------------------------------------------------------------------ commands

const commands: Record<string, Command> = {
  keygen: {
    usage: "keygen [--force]",
    summary: "create the verifier's X25519 keypair in .secrets/ and print the base64 public key",
    options: { force: { type: "boolean" } },
    async run(v) {
      const cfg = loadConfig();
      const kp = generateVerifierKeypair();
      const file = writeSecret(cfg, VERIFIER_X25519_FILE, {
        alg: "x25519",
        public_key: kp.publicKey,
        private_key: kp.privateKey,
        created_at: new Date().toISOString(),
      }, Boolean(v.force));
      err(`wrote ${file} (mode 600). Public key (use as verifier_pubkey):`);
      out(kp.publicKey);
      return 0;
    },
  },

  seal: {
    usage: "seal --report <file.md> (--pubkey <base64> | --program <id>) [--as <hunter role|account>] [--out <file>]",
    summary: "encrypt a report to the verifier key; prints the v2 commitment for the hunter account (--as)",
    options: {
      report: { type: "string" }, pubkey: { type: "string" }, program: { type: "string" }, out: { type: "string" }, as: { type: "string" },
    },
    async run(v) {
      const report = str(v.report);
      if (!report) throw new UsageError("--report is required");
      const cfg = loadConfig();
      let pubkey = str(v.pubkey);
      if (!pubkey) {
        if (!v.program) throw new UsageError("--pubkey or --program is required");
        const provider = makeProvider(cfg);
        const p = await view<{ verifier_pubkey: string } | null>(provider, requireContract(cfg), "get_program", { program_id: needInt(str(v.program), "--program") });
        if (!p) throw new Error(`program ${String(v.program)} not found`);
        pubkey = p.verifier_pubkey;
      }
      const plaintext = fs.readFileSync(report);
      const sealed = seal(plaintext, pubkey);
      let commitment = "(pass --as <hunter account>: the v2 commitment is bound to the submitting account)";
      try {
        const hunter = resolveAccount(cfg, str(v.as), defaultHunter(cfg));
        commitment = `${commitmentFor(hunter, plaintext)} (for ${hunter})`;
      } catch {
        // no hunter known: print the sealed text without a commitment
      }
      if (v.out) {
        fs.writeFileSync(String(v.out), sealed);
        out(`commitment ${commitment}`);
        err(`sealed ${plaintext.length} bytes -> ${sealed.length} bytes in ${String(v.out)}`);
      } else {
        out(sealed);
        err(`commitment ${commitment}`);
      }
      return 0;
    },
  },

  unseal: {
    usage: "unseal (--in <sealed-file> [--commitment <hex> --hunter <account>] | --submission <id>) [--out <file>]",
    summary: "decrypt a sealed report with the verifier key from .secrets/ and check its commitment",
    options: {
      in: { type: "string" }, commitment: { type: "string" }, hunter: { type: "string" }, submission: { type: "string" }, out: { type: "string" },
    },
    async run(v) {
      const cfg = loadConfig();
      const key = loadX25519(cfg);
      let sealed: string;
      let commitment = str(v.commitment);
      let hunter = str(v.hunter);
      if (v.submission !== undefined) {
        const provider = makeProvider(cfg);
        const id = needInt(str(v.submission), "--submission");
        const sub = await view<SubmissionView | null>(provider, requireContract(cfg), "get_submission", { submission_id: id });
        const s = await view<string | null>(provider, requireContract(cfg), "get_sealed", { submission_id: id });
        if (!sub || !s) throw new Error(`submission ${id} not found`);
        sealed = s;
        commitment = sub.commitment;
        hunter = sub.hunter_id;
      } else if (v.in) {
        sealed = fs.readFileSync(String(v.in), "utf8").trim();
      } else {
        throw new UsageError("--in or --submission is required");
      }
      let plaintext: Buffer;
      if (commitment !== undefined) {
        if (hunter === undefined) err("note: no --hunter given, checking the v1 commitment sha256(report)");
        const res = openAndCheck(sealed, key.private_key, commitment, hunter);
        if (!res.ok) {
          err(`cannot open: ${res.error}`);
          return 1;
        }
        plaintext = res.plaintext;
        err(`decrypted; commitment ${commitment} matches${hunter ? ` (v2, ${hunter})` : " (v1)"}`);
      } else {
        try {
          plaintext = unseal(sealed, key.private_key);
        } catch (e) {
          err(`cannot open: ${(e as Error).message}`);
          return 1;
        }
        err(`decrypted; sha256 ${commitmentOf(plaintext)} (no --commitment given to compare)`);
      }
      if (v.out) fs.writeFileSync(String(v.out), plaintext); else process.stdout.write(plaintext);
      return 0;
    },
  },

  submit: {
    usage: "submit --program <id> --report <file.md> [--bond <NEAR>] [--title <text>] [--storage <NEAR>] [--as <role|account>]\n" +
      "       submit --from-vault --program <id> --report <file.md> [--title <text>] [--as <role|account>]",
    summary: "seal a report and commit it (v2 commitment) with bond + storage, or from the hunter vault with the function-call key",
    options: {
      program: { type: "string" }, report: { type: "string" }, bond: { type: "string" }, title: { type: "string" },
      storage: { type: "string" }, as: { type: "string" }, "from-vault": { type: "boolean" },
    },
    async run(v) {
      const { cfg, chain } = chainOf();
      const programId = needInt(str(v.program), "--program");
      const reportFile = str(v.report);
      if (!reportFile) throw new UsageError("--report is required");
      const hunter = resolveAccount(cfg, str(v.as), defaultHunter(cfg));
      const fromVault = Boolean(v["from-vault"]);
      if (fromVault && (v.bond || v.storage)) throw new UsageError("--bond and --storage do not apply to --from-vault (the contract draws bond + storage from the vault)");
      const prep = await prepareSubmission(chain, {
        programId, hunterId: hunter, report: fs.readFileSync(reportFile), title: str(v.title),
        bond: v.bond ? near(String(v.bond)) : undefined, storage: v.storage ? near(String(v.storage)) : undefined,
      });
      let res: { submissionId: number; txHash: string };
      if (fromVault) {
        const key = await loadHunterKey(cfg, chain, hunter);
        err(`program ${programId} "${prep.programName}": required bond ${fmtNear(prep.required)} NEAR + storage, drawn from the vault of ${hunter}; ` +
          `signing submit_report_from_vault with the function-call key; sealed ${prep.sealed.length} bytes; commitment ${prep.commitment}`);
        res = await submitFromVault(chain, key, prep, nowNs());
      } else {
        err(`program ${programId} "${prep.programName}": required bond ${fmtNear(prep.required)} NEAR, attaching ${fmtNear(prep.deposit)} NEAR ` +
          `(bond ${fmtNear(prep.bond)} + storage estimate ${fmtNear(prep.storage)}); sealed ${prep.sealed.length} bytes; commitment ${prep.commitment}`);
        res = await submitReport(chain, fullAccess(cfg, hunter), prep);
      }
      out(`submission id: ${res.submissionId}`);
      out(`hunter: ${hunter}`);
      out(`commitment: ${prep.commitment}`);
      printTx(cfg, fromVault ? "submit_report_from_vault" : "submit_report", res.txHash);
      return 0;
    },
  },

  worker: {
    usage: "worker [--once] [--interval <seconds>] [--disclose after-settlement|immediately] [--engine-timeout <30m>] [--infra-retries <2>]",
    summary: "judge pending submissions of the served programs with the engine; post verdicts with the function-call key",
    options: {
      once: { type: "boolean" }, interval: { type: "string" }, "engine-timeout": { type: "string" }, "infra-retries": { type: "string" },
      disclose: { type: "string" },
    },
    async run(v) {
      const { cfg, provider } = ctx();
      const contractId = requireContract(cfg);
      const verifierId = resolveAccount(cfg, undefined, "verifier");
      const disclose = (str(v.disclose) ?? "after-settlement") as Disclosure;
      if (!DISCLOSURE_MODES.includes(disclose)) throw new UsageError(`--disclose must be one of ${DISCLOSURE_MODES.join(", ")}`);
      const programs = workerPrograms(cfg);
      const x = loadX25519(cfg);
      const fc = readSecret<FcKeySecret>(cfg, VERIFIER_FC_KEY_FILE);
      if (!fc?.private_key) throw new Error(`no function-call key in ${path.join(cfg.secretsDir, VERIFIER_FC_KEY_FILE)} - run: node src/cli.ts setup-verifier-key`);
      if (fc.account_id !== verifierId || fc.contract_id !== contractId) {
        throw new Error(`function-call key is for ${fc.account_id} on ${fc.contract_id}, expected ${verifierId} on ${contractId}`);
      }
      // Refuse to run unless the signing key is a function-call key limited to post_verdict on this contract.
      const ak = await provider.viewAccessKey({ accountId: verifierId, publicKey: fc.public_key, finalityQuery: { finality: "final" } });
      const problem = functionCallKeyProblem(ak.permission as unknown, contractId, VERIFIER_KEY_METHODS);
      if (problem) throw new Error(`refusing to sign with ${fc.public_key}: ${problem}`);
      if (publicKeyOf(x.private_key) !== x.public_key) throw new Error("verifier X25519 key file is inconsistent");
      const wrapper = parseWrapper(process.env.REPLAYCOURT_ENGINE_WRAPPER);
      err(`worker: verifier ${verifierId}, contract ${contractId} (${cfg.network}), signing with function-call key ${fc.public_key} (post_verdict only)`);
      err(`worker: disclosure ${disclose}${disclose === "after-settlement" ? " (evidence stays in runs-private/ until final; then: npm run cli -- publish)" : " (evidence goes straight to runs/)"}; ` +
        `engine ${wrapper ? "wrapped in: " + wrapper.join(" ") : "without a wrapper"}, time limit ${str(v["engine-timeout"]) ?? "30m"}`);
      if (programs) {
        err(`worker: serving programs ${programs.join(", ")} (allow-list)`);
      } else {
        err(`worker: WARNING no program allow-list (REPLAYCOURT_WORKER_PROGRAMS or "programs" in ${cfg.configFile ?? "the deployment file"}): ` +
          `serving every program whose verifier is ${verifierId}. Anyone can create a program that names this verifier.`);
      }
      const verifier = accountWithKey(provider, verifierId, fc.private_key);
      const log = (line: string) => err(`[worker ${new Date().toISOString().slice(11, 19)}Z] ${line}`);
      const pages = <T>(method: string, args: Record<string, unknown>) =>
        listAllPages<T>((from) => view<T[]>(provider, contractId, method, { ...args, from_index: from, limit: 50 }));
      // A v1 contract has only the global list_pending(verifier_id): read it and keep one program.
      const version = await view<string>(provider, contractId, "version", {}).catch(() => null);
      const v1 = majorOf(version) < 2;
      if (v1) err(`worker: contract version ${version} (v1): list_pending(verifier_id), filtered per program`);
      const deps: WorkerDeps = {
        listPrograms: () => pages<ProgramView>("list_programs", {}),
        getProgram: (id) => view<ProgramView | null>(provider, contractId, "get_program", { program_id: id }),
        listPending: (programId) => v1
          ? pages<SubmissionView>("list_pending", { verifier_id: verifierId }).then((all) => all.filter((s) => Number(s.program_id) === programId))
          : pages<SubmissionView>("list_pending", { program_id: programId }),
        listSubmissions: (programId) => pages<SubmissionView>("list_submissions", { program_id: programId }),
        getSubmission: (id) => view<SubmissionView | null>(provider, contractId, "get_submission", { submission_id: id }),
        getSealed: (id) => view<string | null>(provider, contractId, "get_sealed", { submission_id: id }),
        async postVerdict(id, verdict: VerdictInput) {
          const r = await call<null>(verifier, contractId, "post_verdict", { submission_id: id, verdict }, { deposit: 0n, gas: GAS.call });
          out(`posted #${id} ${verdict.outcome}: tx ${r.txHash}  ${txUrl(cfg.network, r.txHash)}`);
          return r.txHash;
        },
        runEngine: withInfraRetries(makeEngineRunner({ repoRoot: REPO_ROOT, wrapper, timeout: str(v["engine-timeout"]) ?? "30m" }),
          needInt(str(v["infra-retries"]) ?? "2", "--infra-retries"), 20_000, log),
        log,
      };
      const wctx: WorkerContext = {
        network: cfg.network, contractId, verifierId, x25519PrivateKey: x.private_key, repoRoot: REPO_ROOT,
        runsRoot: runsDir(cfg, contractId), privateRoot: privateRunsDir(cfg, contractId), disclose, programs,
      };
      const interval = Number(str(v.interval) ?? "30");
      let stop = false;
      process.once("SIGINT", () => { stop = true; err("worker: stopping after this round"); });
      process.once("SIGTERM", () => { stop = true; killEngineRuns(); });
      let retries = 0;
      do {
        const results = await processPending(wctx, deps);
        retries = results.filter((r) => r.action === "retry" || r.action === "deferred").length;
        err(`worker: round done - ${results.length} pending, ` +
          `${results.filter((r) => r.action === "posted").length} posted, ${retries} waiting for retry`);
        if (v.once || stop) break;
        await new Promise((r) => setTimeout(r, interval * 1000));
      } while (!stop);
      return v.once && retries > 0 ? 75 : 0;
    },
  },

  publish: {
    usage: "publish [--dry-run]",
    summary: "move the evidence of final submissions from runs-private/ to runs/ (worker --disclose after-settlement)",
    options: { "dry-run": { type: "boolean" } },
    async run(v) {
      const { cfg, provider } = ctx();
      const contractId = requireContract(cfg);
      const res = await publishEvidence(
        { network: cfg.network, contractId, runsRoot: runsDir(cfg, contractId), privateRoot: privateRunsDir(cfg, contractId), dryRun: Boolean(v["dry-run"]) },
        (id) => view(provider, contractId, "get_submission", { submission_id: id }),
      );
      const rel = (p: string) => path.relative(REPO_ROOT, p).split(path.sep).join("/");
      out(`publish: ${contractId} (${cfg.network}), ${rel(privateRunsDir(cfg, contractId))}/ -> ${rel(runsDir(cfg, contractId))}/${v["dry-run"] ? " (dry run)" : ""}`);
      for (const id of res.plan.publish) out(`  #${id}: final -> ${v["dry-run"] ? "would publish" : res.moved.includes(id) ? "published" : "not moved"}`);
      for (const h of res.plan.held) out(`  #${h.id}: kept private - ${h.why}`);
      for (const id of res.plan.unknown) out(`  #${id}: not found on ${contractId} - left alone`);
      for (const c of res.conflicts) out(`  #${c.id}: CONFLICT - ${c.why}`);
      if (res.disclosureFile) out(`held-back list: ${rel(res.disclosureFile)}`);
      out(`${v["dry-run"] ? res.plan.publish.length + " to publish" : res.moved.length + " published"}, ${res.plan.held.length} kept private`);
      return res.conflicts.length ? 1 : 0;
    },
  },

  "setup-verifier-key": {
    usage: "setup-verifier-key [--allowance <NEAR>] [--force] [--as <role|account>]",
    summary: "add a function-call key (post_verdict only) to the verifier account; store it in .secrets/",
    options: { allowance: { type: "string" }, force: { type: "boolean" }, as: { type: "string" } },
    async run(v) {
      const { cfg, provider } = ctx();
      const contractId = requireContract(cfg);
      const verifierId = resolveAccount(cfg, str(v.as), "verifier");
      const existing = readSecret<FcKeySecret>(cfg, VERIFIER_FC_KEY_FILE);
      if (existing && !v.force) throw new Error(`${path.join(cfg.secretsDir, VERIFIER_FC_KEY_FILE)} exists (use --force to add a new key)`);
      const allowance = near(str(v.allowance) ?? "1");
      const key = newEd25519();
      const owner = accountFromCredentials(cfg, provider, verifierId); // full-access key signs this once
      const res = await owner.addFunctionCallAccessKey({ publicKey: key.publicKey, contractId, methodNames: [...VERIFIER_KEY_METHODS], allowance });
      const txHash = res.transaction_outcome?.id ?? "?";
      const file = writeSecret(cfg, VERIFIER_FC_KEY_FILE, {
        account_id: verifierId,
        contract_id: contractId,
        public_key: key.publicKey,
        private_key: key.secretKey,
        method_names: [...VERIFIER_KEY_METHODS],
        allowance: allowance.toString(),
        added_tx: txHash,
        created_at: new Date().toISOString(),
      }, true);
      if (publicKeyOfSecret(key.secretKey) !== key.publicKey) throw new Error("key mismatch");
      out(`function-call key ${key.publicKey} added to ${verifierId}: receiver ${contractId}, methods [post_verdict], allowance ${fmtNear(allowance)} NEAR`);
      out(`private key stored in ${file} (mode 600)`);
      printTx(cfg, "add_key", txHash);
      return 0;
    },
  },

  "setup-hunter-key": {
    usage: "setup-hunter-key [--allowance <NEAR, default 0.5>] [--force] [--as <role|account>]",
    summary: "add a function-call key (submit_report_from_vault, finalize, withdraw_pending) to a hunter account; store it in .secrets/",
    options: { allowance: { type: "string" }, force: { type: "boolean" }, as: { type: "string" } },
    async run(v) {
      const { cfg, chain } = chainOf();
      const hunterId = resolveAccount(cfg, str(v.as), defaultHunter(cfg));
      const name = hunterKeyFile(hunterId);
      if (readSecret(cfg, name) && !v.force) throw new Error(`${path.join(cfg.secretsDir, name)} exists (use --force to add a new key)`);
      // A submit_report_from_vault (100 TGas, ~6 KB of arguments) reserves ~0.101 NEAR of allowance
      // while it is checked (measured on testnet), although it burns far less.
      const allowance = near(str(v.allowance) ?? "0.5");
      if (allowance < near("0.2")) err("warning: an allowance below 0.2 NEAR may not cover the ~0.1 NEAR a vault submission reserves");
      const key = newEd25519();
      if (publicKeyOfSecret(key.secretKey) !== key.publicKey) throw new Error("key mismatch");
      const { record, txHash } = await setupHunterKey(chain, fullAccess(cfg, hunterId), allowance, key);
      const file = writeSecret(cfg, name, record, true);
      out(`function-call key ${key.publicKey} added to ${hunterId}: receiver ${chain.contractId}, ` +
        `methods [${HUNTER_KEY_METHODS.join(", ")}], allowance ${fmtNear(allowance)} NEAR`);
      out("it cannot attach deposits, so it can neither change the vault policy nor withdraw from the vault");
      out(`private key stored in ${file} (mode 600)`);
      printTx(cfg, "add_key", txHash);
      return 0;
    },
  },

  "create-program": {
    usage: "create-program --name <text> [--pool <NEAR>] [--bond <NEAR>] [--verifier-fee <NEAR>] [--dispute-bond <NEAR>] [--payouts <c,h,m,l NEAR>]\n" +
      "                 [--challenge <sec>] [--pending-timeout <sec>] [--resolve-timeout <sec>] [--scope <chainId:0xaddr,...>]\n" +
      "                 [--verifier <role|account>] [--pubkey <base64>] [--as <role|account>]",
    summary: "create a bounty program (defaults: pool 3, bond 0.1, fee 0.01, dispute bond = bond, payouts 0.5,0.3,0.2,0.1, " +
      "challenge 60 s, pending timeout 1 d, resolve timeout 1 d)",
    options: {
      name: { type: "string" }, pool: { type: "string" }, bond: { type: "string" }, "verifier-fee": { type: "string" },
      "dispute-bond": { type: "string" }, payouts: { type: "string" }, challenge: { type: "string" }, "pending-timeout": { type: "string" },
      "resolve-timeout": { type: "string" }, scope: { type: "string" }, verifier: { type: "string" }, pubkey: { type: "string" }, as: { type: "string" },
    },
    async run(v) {
      const { cfg, chain } = chainOf();
      const name = str(v.name);
      if (!name) throw new UsageError("--name is required");
      const owner = resolveAccount(cfg, str(v.as), "owner");
      const verifierId = resolveAccount(cfg, str(v.verifier), "verifier");
      const pubkey = str(v.pubkey) ?? loadX25519(cfg).public_key;
      const p = (str(v.payouts) ?? "0.5,0.3,0.2,0.1").split(",").map((s) => near(s));
      if (p.length !== 4) throw new UsageError("--payouts needs 4 values: critical,high,medium,low");
      const scope = (str(v.scope) ?? "").split(",").filter(Boolean).map((s) => {
        const [chainId, address] = s.split(":");
        return { chain_id: Number(chainId), address };
      });
      const bond = near(str(v.bond) ?? "0.1");
      const res = await createProgram(chain, fullAccess(cfg, owner), {
        name, scope, verifierId, verifierPubkey: pubkey, payouts: [p[0], p[1], p[2], p[3]], bond,
        verifierFee: near(str(v["verifier-fee"]) ?? "0.01"),
        disputeBond: v["dispute-bond"] ? near(String(v["dispute-bond"])) : bond,
        challengeSec: needInt(str(v.challenge) ?? "60", "--challenge"),
        pendingTimeoutSec: needInt(str(v["pending-timeout"]) ?? "86400", "--pending-timeout"),
        resolveTimeoutSec: needInt(str(v["resolve-timeout"]) ?? "86400", "--resolve-timeout"),
        pool: near(str(v.pool) ?? "3"),
      });
      out(`program id: ${res.programId}`);
      out(`owner: ${owner}, verifier: ${verifierId}, verifier_pubkey: ${pubkey}`);
      out(`bond ${fmtNear(String(res.args.bond))} NEAR, dispute bond ${fmtNear(String(res.args.dispute_bond))} NEAR, ` +
        `challenge ${String(res.args.challenge_period_sec)} s, pending timeout ${String(res.args.pending_timeout_sec)} s, resolve timeout ${String(res.args.resolve_timeout_sec)} s`);
      printTx(cfg, "create_program", res.txHash);
      return 0;
    },
  },

  finalize: {
    usage: "finalize <submission-id> [--as <role|account>] [--hunter-key]",
    summary: "pay a valid submission after its challenge window (anyone may call; --hunter-key: sign with the hunter's function-call key)",
    options: { as: { type: "string" }, "hunter-key": { type: "boolean" } },
    positionals: true,
    async run(v, pos) {
      const { cfg, chain } = chainOf();
      const id = needInt(pos[0], "submission id");
      const who = resolveAccount(cfg, str(v.as), v["hunter-key"] ? defaultHunter(cfg) : "owner");
      const signer = v["hunter-key"] ? await loadHunterKey(cfg, chain, who) : fullAccess(cfg, who);
      const res = await chain.call<null>(signer, "finalize", { submission_id: id }, { deposit: 0n });
      printTx(cfg, `finalize #${id} (by ${who}${v["hunter-key"] ? ", function-call key" : ""})`, res.txHash);
      return 0;
    },
  },

  dispute: {
    usage: "dispute <submission-id> --reason <text> [--deposit <NEAR>] [--as <role|account>]",
    summary: "program owner disputes a valid verdict inside the challenge window, attaching the program's dispute bond",
    options: { reason: { type: "string" }, deposit: { type: "string" }, as: { type: "string" } },
    positionals: true,
    async run(v, pos) {
      const { cfg, chain } = chainOf();
      const id = needInt(pos[0], "submission id");
      const reason = str(v.reason);
      if (!reason) throw new UsageError("--reason is required");
      const who = resolveAccount(cfg, str(v.as), "owner");
      const res = await disputeSubmission(chain, fullAccess(cfg, who), id, reason, v.deposit ? near(String(v.deposit)) : undefined);
      out(`dispute bond ${fmtNear(res.disputeBond)} NEAR, attached ${fmtNear(res.deposit)} NEAR; resolve before resolve_until, ` +
        "or the hunter is paid and gets the dispute bond");
      printTx(cfg, `dispute #${id}`, res.txHash);
      return 0;
    },
  },

  resolve: {
    usage: "resolve <submission-id> --outcome <valid|invalid|duplicate> [--severity <critical|high|medium|low>] --note <text> [--as <role|account>]",
    summary: "program owner resolves a needs_human or disputed submission",
    options: { outcome: { type: "string" }, severity: { type: "string" }, note: { type: "string" }, as: { type: "string" } },
    positionals: true,
    async run(v, pos) {
      const { cfg, provider } = ctx();
      const id = needInt(pos[0], "submission id");
      const outcome = str(v.outcome);
      if (!outcome || !["valid", "invalid", "duplicate"].includes(outcome)) throw new UsageError("--outcome must be valid, invalid or duplicate");
      const severity = v.severity ? mapSeverity(str(v.severity)) : null;
      const who = resolveAccount(cfg, str(v.as), "owner");
      const res = await call<null>(accountFromCredentials(cfg, provider, who), requireContract(cfg), "resolve",
        { submission_id: id, outcome, severity, note: str(v.note) ?? "" });
      printTx(cfg, `resolve #${id} as ${outcome}${severity ? " (" + severity + ")" : ""}`, res.txHash);
      return 0;
    },
  },

  "withdraw-pending": {
    usage: "withdraw-pending <submission-id> [--as <role|account>] [--hunter-key]",
    summary: "hunter takes the full bond back from a submission still pending after the program's pending timeout",
    options: { as: { type: "string" }, "hunter-key": { type: "boolean" } },
    positionals: true,
    async run(v, pos) {
      const { cfg, chain } = chainOf();
      const id = needInt(pos[0], "submission id");
      const who = resolveAccount(cfg, str(v.as), defaultHunter(cfg));
      const signer = v["hunter-key"] ? await loadHunterKey(cfg, chain, who) : fullAccess(cfg, who);
      const res = await chain.call<null>(signer, "withdraw_pending", { submission_id: id }, { deposit: 0n });
      printTx(cfg, `withdraw_pending #${id} (by ${who}${v["hunter-key"] ? ", function-call key" : ""})`, res.txHash);
      return 0;
    },
  },

  "withdraw-pool": {
    usage: "withdraw-pool --program <id> (--amount <NEAR> | --all) [--as <role|account>]",
    summary: "program owner withdraws the unreserved part of the pool (--all: pool - reserved)",
    options: { program: { type: "string" }, amount: { type: "string" }, all: { type: "boolean" }, as: { type: "string" } },
    async run(v) {
      const { cfg, provider } = ctx();
      const contractId = requireContract(cfg);
      const programId = needInt(str(v.program), "--program");
      let amount: bigint;
      if (v.all) {
        const p = await view<{ pool: string; reserved: string } | null>(provider, contractId, "get_program", { program_id: programId });
        if (!p) throw new Error(`program ${programId} not found`);
        amount = BigInt(p.pool) - BigInt(p.reserved);
      } else if (str(v.amount)) {
        amount = near(String(v.amount));
      } else {
        throw new UsageError("--amount or --all is required");
      }
      if (amount <= 0n) throw new Error(`nothing to withdraw from program ${programId}`);
      const who = resolveAccount(cfg, str(v.as), "owner");
      const res = await call<null>(accountFromCredentials(cfg, provider, who), contractId, "withdraw_pool",
        { program_id: programId, amount: amount.toString() });
      printTx(cfg, `withdraw_pool program ${programId}: ${fmtNear(amount)} NEAR (by ${who})`, res.txHash);
      return 0;
    },
  },

  "vault-deposit": {
    usage: "vault-deposit --amount <NEAR> [--as <role|account>]",
    summary: "hunter funds their vault in the contract (creates it on first use; its storage is taken from the deposit)",
    options: { amount: { type: "string" }, as: { type: "string" } },
    async run(v) {
      const { cfg, chain } = chainOf();
      if (!str(v.amount)) throw new UsageError("--amount is required");
      const hunterId = resolveAccount(cfg, str(v.as), defaultHunter(cfg));
      const res = await vaultDeposit(chain, fullAccess(cfg, hunterId), near(String(v.amount)));
      printTx(cfg, `vault_deposit ${String(v.amount)} NEAR (by ${hunterId})`, res.txHash);
      for (const line of formatVault(hunterId, await getVault(chain, hunterId), fmtNear, nowNs())) out(line);
      return 0;
    },
  },

  "vault-set-policy": {
    usage: "vault-set-policy --max-bond <NEAR> --max-per-day <NEAR> (--programs <id,id,...> | --any-program) [--as <role|account>]",
    summary: "hunter sets the vault's spending policy (1 yoctoNEAR attached: needs the full-access key)",
    options: {
      "max-bond": { type: "string" }, "max-per-day": { type: "string" }, programs: { type: "string" }, "any-program": { type: "boolean" },
      as: { type: "string" },
    },
    async run(v) {
      const { cfg, chain } = chainOf();
      if (!str(v["max-bond"]) || !str(v["max-per-day"])) throw new UsageError("--max-bond and --max-per-day are required");
      if (Boolean(v["any-program"]) === Boolean(str(v.programs))) throw new UsageError("give either --programs <ids> or --any-program");
      const hunterId = resolveAccount(cfg, str(v.as), defaultHunter(cfg));
      const res = await vaultSetPolicy(chain, fullAccess(cfg, hunterId), {
        maxBondPerReport: near(String(v["max-bond"])),
        maxSpendPerDay: near(String(v["max-per-day"])),
        allowedPrograms: v["any-program"] ? null : intList(String(v.programs), "--programs"),
      });
      printTx(cfg, `vault_set_policy (by ${hunterId})`, res.txHash);
      for (const line of formatVault(hunterId, await getVault(chain, hunterId), fmtNear, nowNs())) out(line);
      return 0;
    },
  },

  "vault-withdraw": {
    usage: "vault-withdraw (--amount <NEAR> | --all) [--as <role|account>]",
    summary: "hunter withdraws from the vault (1 yoctoNEAR attached: needs the full-access key)",
    options: { amount: { type: "string" }, all: { type: "boolean" }, as: { type: "string" } },
    async run(v) {
      const { cfg, chain } = chainOf();
      if (Boolean(v.all) === Boolean(str(v.amount))) throw new UsageError("give either --amount <NEAR> or --all");
      const hunterId = resolveAccount(cfg, str(v.as), defaultHunter(cfg));
      const res = await vaultWithdraw(chain, fullAccess(cfg, hunterId), v.all ? "all" : near(String(v.amount)));
      printTx(cfg, `vault_withdraw ${fmtNear(res.amount)} NEAR (by ${hunterId})`, res.txHash);
      for (const line of formatVault(hunterId, await getVault(chain, hunterId), fmtNear, nowNs())) out(line);
      return 0;
    },
  },

  "vault-status": {
    usage: "vault-status [--account <role|account>] [--json]",
    summary: "read-only: a hunter's vault balance, policy and spending in the current 24 h window",
    options: { account: { type: "string" }, json: { type: "boolean" } },
    async run(v) {
      const { cfg, chain } = chainOf();
      const accountId = resolveAccount(cfg, str(v.account), defaultHunter(cfg));
      const vault = await getVault(chain, accountId);
      if (v.json) out(JSON.stringify(vault, null, 2));
      else for (const line of formatVault(accountId, vault, fmtNear, nowNs())) out(line);
      return 0;
    },
  },

  status: {
    usage: "status [--program <id>] [--json]",
    summary: "show programs, submissions (verdicts, payouts, slashes), hunter reputation and balances",
    options: { program: { type: "string" }, json: { type: "boolean" } },
    async run(v) {
      const { cfg, provider } = ctx();
      const contractId = requireContract(cfg);
      const programs = v.program !== undefined
        ? [await view<Record<string, unknown> | null>(provider, contractId, "get_program", { program_id: needInt(str(v.program), "--program") })].filter(Boolean)
        : await view<Record<string, unknown>[]>(provider, contractId, "list_programs", { from_index: 0, limit: 50 });
      const report: Record<string, unknown> = { network: cfg.network, contract: contractId, programs: [] as unknown[] };
      const hunters = new Set<string>(Object.entries(cfg.accounts).filter(([r]) => r.startsWith("hunter")).map(([, a]) => a));
      out(`contract ${contractId} (${cfg.network})  ${accountUrl(cfg.network, contractId)}`);
      for (const p of programs as Record<string, any>[]) {
        const subs = await listAllPages<Record<string, any>>((from) =>
          view<Record<string, any>[]>(provider, contractId, "list_submissions", { program_id: p.id, from_index: from, limit: 50 }));
        (report.programs as unknown[]).push({ ...p, submissions: subs });
        out("");
        out(`program ${p.id} "${printable(p.name)}"  owner ${p.owner_id}  verifier ${p.verifier_id}  ${p.active ? "active" : "inactive"}`);
        out(`  pool ${fmtNear(p.pool)} NEAR, reserved ${fmtNear(p.reserved)}, bond ${fmtNear(p.bond)}, fee ${fmtNear(p.verifier_fee)}` +
          `${p.dispute_bond !== undefined ? `, dispute bond ${fmtNear(p.dispute_bond)}` : ""}, challenge ${p.challenge_period_sec} s` +
          `${p.resolve_timeout_sec !== undefined ? `, resolve timeout ${p.resolve_timeout_sec} s` : ""}`);
        out(`  stats ${JSON.stringify(p.stats)}`);
        for (const s of subs) {
          hunters.add(s.hunter_id);
          const vd = s.verdict as Record<string, any> | null;
          const verdict = vd ? `${vd.outcome}${vd.severity ? "/" + vd.severity : ""}${vd.duplicate_of !== null && vd.duplicate_of !== undefined ? " of #" + vd.duplicate_of : ""}` : "-";
          const money = s.status === "paid" ? `paid ${fmtNear(s.payout)} NEAR + bond back`
            : s.status === "invalid" || s.status === "rejected" ? `bond ${fmtNear(s.bond)} NEAR slashed`
            : s.status === "duplicate" ? `bond ${fmtNear(s.bond)} NEAR refunded minus fee`
            : `bond ${fmtNear(s.bond)} NEAR held`;
          out(`  #${s.id} [${s.status}] verdict ${verdict}  ${money}  hunter ${s.hunter_id}${s.funded_by_vault ? " (vault)" : ""}`);
          out(`      "${printable(s.title)}"`);
          if (vd?.reason) out(`      reason: ${printable(vd.reason, 300)}`);
          if (s.resolution) out(`      resolution: ${printable(JSON.stringify(s.resolution), 400)}`);
        }
      }
      const rep: Record<string, unknown> = {};
      out("");
      out("hunter reputation:");
      for (const h of hunters) {
        const hv = await view<Record<string, any>>(provider, contractId, "get_hunter", { account_id: h });
        rep[h] = hv;
        out(`  ${h}: submissions ${hv.submissions}, valid ${hv.valid}, invalid ${hv.invalid}, duplicate ${hv.duplicate}, needs_human ${hv.needs_human}, earned ${fmtNear(hv.earned)} NEAR`);
      }
      report.hunters = rep;
      const balances: Record<string, string> = {};
      out("");
      out("account balances:");
      for (const [role, acct] of Object.entries(cfg.accounts)) {
        try {
          const a = await provider.viewAccount({ accountId: acct, blockQuery: { finality: "final" } });
          balances[acct] = String(a.amount);
          out(`  ${role.padEnd(9)} ${acct}: ${fmtNear(a.amount)} NEAR`);
        } catch (e) {
          out(`  ${role.padEnd(9)} ${acct}: ${describeError(e)}`);
        }
      }
      report.balances = balances;
      if (v.json) out(JSON.stringify(report, (_k, val) => (typeof val === "bigint" ? val.toString() : val), 2));
      return 0;
    },
  },

  "verify-onchain": {
    usage: "verify-onchain [--program <id> | --all-programs] [--contract <account>] [--rpc <url,url>] [--verbose]",
    summary: "read-only, no keys: check every verdict's evidence (sha256, place below runs/, binding to the submission)",
    options: {
      program: { type: "string" }, "all-programs": { type: "boolean" }, contract: { type: "string" }, rpc: { type: "string" },
      verbose: { type: "boolean" },
    },
    async run(v) {
      const cfg = loadConfig();
      if (v.program !== undefined && v["all-programs"]) throw new UsageError("--program and --all-programs exclude each other");
      // Works without .secrets/: falls back to the public demo deployment of this network.
      const contractId = str(v.contract) ?? cfg.contractId ?? DEMO_CONTRACT[cfg.network];
      if (!contractId) throw new UsageError(`no contract id for ${cfg.network}: pass --contract <account>`);
      // Fast public endpoints first; a configured rpc_url only as a later fallback (--rpc / REPLAYCOURT_RPC_URL override).
      const rpcList = str(v.rpc) ?? process.env.REPLAYCOURT_RPC_URL;
      cfg.rpcUrls = rpcList
        ? rpcList.split(",").map((s) => s.trim()).filter(Boolean)
        : [...new Set([...(DEFAULT_RPC[cfg.network] ?? []), ...cfg.rpcUrls])];
      const provider = makeProvider(cfg);
      const programId = v.program !== undefined ? needInt(str(v.program), "--program") : undefined;
      const pinned = pinnedPrograms(cfg.network, contractId);
      const result = await verifyOnchain(
        <T>(method: string, args: Record<string, unknown>) => view<T>(provider, contractId, method, args),
        makeEvidenceReader(REPO_ROOT),
        { network: cfg.network, contractId, programId, allPrograms: Boolean(v["all-programs"]), pinned },
      );
      out(`verify-onchain: contract ${contractId} (${cfg.network}), version ${result.contractVersion ?? "unknown"}: ` +
        (result.contractMajor < 2 ? "v1 evidence accepted (hash only)" : "evidence must be a replaycourt.evidence/v1 envelope bound to its submission"));
      out(`evidence files: below runs/ in the repository; ` + (result.selection === "program" ? `program ${programId}`
        : result.selection === "pinned" ? `pinned showcase programs ${pinned!.join(", ")} (--all-programs checks every program)`
        : `all programs${pinned && pinned.length ? "" : " (none pinned for this contract)"}`));
      for (const { program, rows } of result.programs) {
        out("");
        out(`program ${program.id} "${printable(program.name)}": ${rows.length} submission(s)`);
        if (rows.length === 0) continue;
        for (const line of formatTable(rows)) out(`  ${line}`);
        for (const r of rows) {
          if (["mismatch", "missing", "unbound", "refused"].includes(r.evidence)) out(`  #${r.id} ${r.evidence}: ${r.detail}`);
          else if (v.verbose && r.evidence === "ok") out(`  #${r.id} ok: sha256 ${r.actual} = on-chain evidence_sha256 (${r.detail})`);
          else if (v.verbose && r.evidence === "undisclosed") out(`  #${r.id} ${r.detail}`);
        }
      }
      if (result.skipped.length) {
        out("");
        for (const p of result.skipped) out(`program ${p.id} "${printable(p.name)}": not part of the showcase (not checked; --all-programs checks it)`);
      }
      out("");
      out(summaryLine(result.rows));
      out(resultLine(result.rows));
      return result.exitCode;
    },
  },
};

// ------------------------------------------------------------------------ main

function helpAll(): string {
  const lines = [
    "ReplayCourt agent - hunter CLI, verifier worker and demo commands (NEAR testnet)",
    "",
    "usage: node src/cli.ts <command> [options]      (node src/cli.ts <command> --help for details)",
    "",
    "commands:",
    ...Object.entries(commands).map(([name, c]) => `  ${name.padEnd(19)} ${c.summary}`),
    "",
    "configuration: env REPLAYCOURT_NETWORK, REPLAYCOURT_CONTRACT_ID, REPLAYCOURT_RPC_URL, REPLAYCOURT_<ROLE>_ID,",
    "REPLAYCOURT_SECRETS_DIR, REPLAYCOURT_CONFIG; otherwise .secrets/<network>.json. Full-access keys:",
    "~/.near-credentials/<network>/<account>.json. Roles for --as: owner, verifier, hunter1, hunter2, ...",
    "worker: REPLAYCOURT_WORKER_PROGRAMS (program allow-list), REPLAYCOURT_ENGINE_WRAPPER (command prefix for engine runs).",
  ];
  return lines.join("\n");
}

export async function main(argv: string[]): Promise<number> {
  const [name, ...rest] = argv;
  if (!name || name === "--help" || name === "-h" || name === "help") {
    out(helpAll());
    return name ? 0 : 64;
  }
  const cmd = commands[name];
  if (!cmd) {
    err(`unknown command: ${name}\n`);
    err(helpAll());
    return 64;
  }
  let parsed;
  try {
    parsed = parseArgs({
      args: rest,
      options: { ...cmd.options, help: { type: "boolean", short: "h" } },
      allowPositionals: Boolean(cmd.positionals),
      strict: true,
    });
  } catch (e) {
    err(`${(e as Error).message}\nusage: node src/cli.ts ${cmd.usage}`);
    return 64;
  }
  if (parsed.values.help) {
    out(`usage: node src/cli.ts ${cmd.usage}\n\n${cmd.summary}`);
    return 0;
  }
  try {
    return await cmd.run(parsed.values as Record<string, string | boolean | undefined>, parsed.positionals);
  } catch (e) {
    if (e instanceof UsageError) {
      err(`${e.message}\nusage: node src/cli.ts ${cmd.usage}`);
      return 64;
    }
    if (e instanceof ActionError) {
      err(`error: ${e.message}`);
      return 1;
    }
    err(`error: ${describeError(e)}`);
    return 1;
  }
}

if (import.meta.main) {
  main(process.argv.slice(2)).then((code) => process.exit(code));
}
