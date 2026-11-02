#!/usr/bin/env node
// Drives the ReplayCourt MCP server in VAULT MODE the way an AI agent would: an MCP client over stdio
// that only sees tool names, schemas and results; no key, no policy file, no chain access of its own.
// Afterwards, outside MCP, it shows what the server's function-call key cannot do even in the
// hands of an attacker who stole it from the host.
//
// Prerequisites (once, with the hunter's FULL-ACCESS key; see README "Vault mode: setup"):
//   agent CLI: vault-deposit, vault-set-policy, setup-hunter-key (writes the function-call key to
//   <secrets dir>/hunter-fc-key.<account>.json, where the server finds it in vault mode).
//
// Run from mcp/:
//   node demo/client-demo.ts [--config <file>] [--hunter <role|account>] [--state-dir <dir>]
//                            [--policy <file>] [--report <file>] [--title <text>] [--exact]
//                            [--withdraw] [--raw-key] [--verify-seal]
//
//   --config       deployment file (default .secrets/showcase-v2.json, the showcase)
//   --hunter       hunter role or account (default agent)
//   --state-dir    ledger directory (default .secrets/mcp-vault-showcase-state)
//   --policy       the server's local policy (default demo/policy.vault-showcase.json)
//   --report       the report to submit, a file in engine/reports/ (default 01_templedao_stax.md)
//   --title        its public title (default "MCP vault demo: sealed report A")
//   --exact        submit the report unchanged (default: a copy with one appended run-marker line,
//                  so that the demo can run again; the contract accepts each commitment once)
//   --withdraw     wait for the program's pending timeout, then withdraw_pending (bond back into the vault)
//   --raw-key      outside MCP: sign with the function-call key directly: vault_withdraw, vault_set_policy,
//                  a NEAR transfer, adding a full-access key, and two submissions the vault policy
//                  forbids (all must fail; the last two reach the contract and cost a little gas)
//   --verify-seal  afterwards, as the VERIFIER (not the agent): open the sealed blob from the chain with
//                  the verifier key and check the v2 commitment against the submitting account
//
// The contract accepts each commitment once, so by default the demo submits a working copy of the
// report with one appended line (a run marker); --exact submits the file as it is.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseArgs } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { hunterKeyFile } from "../../agent/src/actions.ts";
import type { HunterKeyRecord } from "../../agent/src/actions.ts";
import { loadConfig, readSecret, REPO_ROOT, resolveAccount, VERIFIER_X25519_FILE } from "../../agent/src/config.ts";
import { accountWithKey, call, fmtNear, GAS, makeProvider, near, newEd25519, view } from "../../agent/src/near.ts";
import { commitmentFor, openAndCheck, seal } from "../../agent/src/seal.ts";

const { values: v } = parseArgs({
  options: {
    config: { type: "string" },
    hunter: { type: "string" },
    "state-dir": { type: "string" },
    policy: { type: "string" },
    report: { type: "string" },
    title: { type: "string" },
    exact: { type: "boolean" },
    withdraw: { type: "boolean" },
    "raw-key": { type: "boolean" },
    "verify-seal": { type: "boolean" },
  },
});

const MCP_DIR = path.resolve(import.meta.dirname, "..");
const CONFIG = path.resolve(v.config ?? path.join(REPO_ROOT, ".secrets", "showcase-v2.json"));
const POLICY = path.resolve(v.policy ?? path.join(MCP_DIR, "demo", "policy.vault-showcase.json"));
const REPORTS = path.join(REPO_ROOT, "engine", "reports");
const STATE = path.resolve(v["state-dir"] ?? path.join(REPO_ROOT, ".secrets", "mcp-vault-showcase-state"));
const WORK = path.join(STATE, "reports");
const REPORT = path.basename(v.report ?? "01_templedao_stax.md");
const TITLE = v.title ?? "MCP vault demo: sealed report A";
const LONG_REPORT = "02_seneca_chamber_with_appendix.md";

const home = os.homedir();
const repoTilde = REPO_ROOT.startsWith(home) ? "~" + REPO_ROOT.slice(home.length) : REPO_ROOT;
/** Recorded output must not carry local paths: the repository becomes <repo>, home becomes ~. */
const tidy = (s: string) => s.split(REPO_ROOT).join("<repo>").split(repoTilde).join("<repo>").split(home).join("~");
const say = (s = "") => process.stdout.write(tidy(s) + "\n");
const stamp = () => new Date().toISOString().replace(/\.\d+Z$/, "Z");

let step = 0;
function heading(title: string) {
  step++;
  say(`\n=== ${step}. ${title}  [${stamp()}]`);
}

type Doc = Record<string, unknown>;
type Amt = { near: string; yocto: string };

/** A report of about `bytes` bytes: report 02 plus an appendix (the other sample reports, repeated). */
function longReport(bytes: number, marker: string): string {
  let text = fs.readFileSync(path.join(REPORTS, "02_seneca_chamber.md"), "utf8") + "\n\n## Appendix: related reports and traces\n\n";
  const filler = fs.readdirSync(REPORTS).filter((f) => f.endsWith(".md") && f !== "02_seneca_chamber.md").sort()
    .map((f) => `### ${f}\n\n` + fs.readFileSync(path.join(REPORTS, f), "utf8")).join("\n");
  while (Buffer.byteLength(text) < bytes) text += filler;
  return Buffer.from(text).subarray(0, bytes).toString("utf8").replace(/�+$/, "") + `\n${marker}\n`;
}

async function main(): Promise<void> {
  if (!fs.existsSync(CONFIG)) throw new Error(`no deployment file ${CONFIG}`);
  const cfg = loadConfig({ ...process.env, REPLAYCOURT_CONFIG: CONFIG });
  const hunterId = resolveAccount(cfg, v.hunter, "agent");
  const contractId = cfg.contractId!;
  const keyRec = readSecret<HunterKeyRecord>(cfg, hunterKeyFile(hunterId));
  if (!keyRec) throw new Error(`no function-call key for ${hunterId}: run the agent CLI setup-hunter-key --as ${hunterId} first`);
  const marker = `<!-- ReplayCourt MCP vault demo copy, run ${new Date().toISOString()} -->`;
  fs.mkdirSync(WORK, { recursive: true, mode: 0o700 });
  const original = fs.readFileSync(path.join(REPORTS, REPORT), "utf8");
  fs.writeFileSync(path.join(WORK, REPORT), v.exact ? original : original + `\n${marker}\n`);
  say(`contract ${contractId}, hunter ${hunterId}, vault mode, local policy ${path.basename(POLICY)}`);
  say(v.exact ? `report: engine/reports/${REPORT}, unchanged` : `working copy of engine/reports/${REPORT} with the line ${marker}`);

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [path.join(MCP_DIR, "src", "server.ts")],
    cwd: MCP_DIR,
    stderr: "pipe",
    env: {
      ...getDefaultEnvironment(),
      REPLAYCOURT_CONFIG: CONFIG,
      REPLAYCOURT_HUNTER_ID: hunterId,
      REPLAYCOURT_MCP_MODE: "vault",
      REPLAYCOURT_MCP_POLICY: POLICY,
      REPLAYCOURT_MCP_STATE_DIR: STATE,
      REPLAYCOURT_MCP_REPORT_DIRS: [WORK, REPORTS].join(path.delimiter),
      ...(process.env.REPLAYCOURT_RPC_URL ? { REPLAYCOURT_RPC_URL: process.env.REPLAYCOURT_RPC_URL } : {}),
    },
  });
  // Server log lines (stderr) are shown, minus near-api-js' failover noise.
  let pending = "";
  transport.stderr?.on("data", (b: Buffer) => {
    pending += b.toString();
    const lines = pending.split("\n");
    pending = lines.pop() ?? "";
    for (const l of lines) if (l.startsWith("[replaycourt-mcp]")) say(`  ${l}`);
  });

  const client = new Client({ name: "replaycourt-agent-demo", version: "1.0.0" });
  await client.connect(transport);
  const callTool = async (name: string, args: Doc = {}, show: (d: Doc) => unknown = (d) => d): Promise<Doc> => {
    say(`> ${name} ${JSON.stringify(args).replace(/"report_markdown":"[^"]{200,}"/, '"report_markdown":"…"')}`);
    const res = await client.callTool({ name, arguments: args });
    const text = (res.content as { type: string; text?: string }[]).map((c) => c.text ?? "").join("\n");
    const doc = JSON.parse(text) as Doc;
    say(`< isError=${res.isError === true}`);
    say(JSON.stringify(show(doc), null, 2));
    return doc;
  };

  let subId: number | undefined;
  let longText = "";
  try {
    heading("connect and list tools");
    const { tools } = await client.listTools();
    say(`server: ${JSON.stringify(client.getServerVersion())}; tools: ${tools.map((t) => t.name).join(", ")}`);

    heading("list programs (as the agent sees them)");
    const listed = await callTool("list_programs", { limit: 50 }, (d) => ({
      untrusted_data_notice: d.untrusted_data_notice,
      signing_mode: d.signing_mode,
      policy_allowed_program_ids: d.policy_allowed_program_ids,
      vault_allowed_program_ids: d.vault_allowed_program_ids,
      programs: (d.programs as Doc[]).map((p) =>
        `#${p.id} active=${p.active} allowed_by_policy=${p.allowed_by_policy} allowed_by_vault=${p.allowed_by_vault} ` +
        `bond=${(p.base_bond as Amt).near} dispute_bond=${(p.dispute_bond as Amt | null)?.near} pool_free=${(p.pool_free as Amt).near} name=${p.name}`),
    }));
    const programs = listed.programs as Doc[];
    const target = programs.find((p) => p.allowed_by_policy === true && p.allowed_by_vault === true && p.active === true);
    if (!target) throw new Error("no program on both allow-lists");
    const programId = target.id as number;
    const offList = programs.find((p) => p.allowed_by_vault === false)?.id as number | undefined;

    heading(`required bond for program ${programId}`);
    await callTool("required_bond", { program_id: programId });

    heading(`submit ${REPORT} through the vault${v.exact ? "" : " (fresh copy, new commitment)"}`);
    const first = await callTool("submit_report", { program_id: programId, title: TITLE, report_path: REPORT });
    subId = first.submission_id as number | undefined;

    if (offList !== undefined) {
      heading(`submit to program ${offList}, which is outside the allow-lists`);
      await callTool("submit_report", { program_id: offList, title: "MCP vault demo: off-list", report_path: REPORT });
    }

    heading("exceed the daily cap: a long report whose bond + storage does not fit into what is left of the 24 h window");
    const before = await callTool("budget_status", {}, (d) => ({ vault: d.vault, usage: d.usage }));
    const vault = before.vault as { remaining_in_window: Amt };
    const usage = before.usage as { remaining_24h: Amt };
    const left = [BigInt(vault.remaining_in_window.yocto), BigInt(usage.remaining_24h.yocto)].reduce((a, b) => (a < b ? a : b));
    // aim 0.05 NEAR above what is left: storage ~ (16/9 * bytes + ~2,900) * 1e19 yocto, plus the bond
    const bond = BigInt(((await callTool("required_bond", { program_id: programId }, (d) => d.required_bond)).required_bond as Amt).yocto);
    const storageWanted = left + near("0.05") - bond;
    const bytes = Math.min(30_000, Math.max(1_000, Math.floor(((Number(storageWanted / 10n ** 19n) - 2_900) * 9) / 16)));
    longText = longReport(bytes, marker);
    fs.writeFileSync(path.join(WORK, LONG_REPORT), longText);
    say(`(left in the window: ${fmtNear(left, 5)} NEAR; the long report has ${Buffer.byteLength(longText)} bytes)`);
    await callTool("submit_report", { program_id: programId, title: "MCP vault demo: sealed report B (long)", report_path: LONG_REPORT });

    heading("the hunter's own key file as a 'report' (prompt-injected exfiltration attempt)");
    await callTool("submit_report", {
      program_id: programId,
      title: "MCP vault demo: exfiltration attempt",
      report_path: path.join(cfg.secretsDir, hunterKeyFile(hunterId)),
    });

    heading("budget status");
    await callTool("budget_status");

    if (subId !== undefined) {
      heading(`follow submission ${subId}`);
      await callTool("get_submission", { submission_id: subId });

      if (v.withdraw) {
        heading(`withdraw_pending ${subId} with the function-call key (the bond goes back into the vault)`);
        let r = await callTool("withdraw_pending", { submission_id: subId });
        if (r.rule === "pending_timeout_not_reached" && typeof r.retry_after === "string") {
          const ms = Date.parse(r.retry_after) - Date.now() + 3_000;
          say(`(waiting ${Math.ceil(ms / 1000)} s for the pending timeout)`);
          await new Promise((res) => setTimeout(res, ms));
          r = await callTool("withdraw_pending", { submission_id: subId });
        }
        await callTool("budget_status", {}, (d) => ({ vault: d.vault, usage: d.usage, signing: d.signing }));
      }
    }
  } finally {
    await client.close();
  }

  const provider = makeProvider(cfg);

  if (v["raw-key"]) {
    heading("OUTSIDE MCP: an attacker with the stolen function-call key signs directly");
    const fc = accountWithKey(provider, hunterId, keyRec.private_key);
    const allowance = async () => {
      const ak = await provider.viewAccessKey({ accountId: hunterId, publicKey: keyRec.public_key, finalityQuery: { finality: "final" } });
      const p = ak.permission as unknown as { FunctionCall?: { allowance?: string | null } };
      return p.FunctionCall?.allowance ? `${fmtNear(p.FunctionCall.allowance, 5)} NEAR` : JSON.stringify(ak.permission);
    };
    say(`key ${keyRec.public_key}: allowance left ${await allowance()}`);
    const attempt = async (label: string, fn: () => Promise<unknown>) => {
      say(`\n--- ${label}`);
      try {
        const r = (await fn()) as { transaction_outcome?: { id?: string }; txHash?: string } | undefined;
        say(`UNEXPECTED SUCCESS ${JSON.stringify(r?.txHash ?? r?.transaction_outcome?.id ?? r)}`);
      } catch (e) {
        const err = e as Error & { txHash?: string; transactionResult?: { transaction_outcome?: { id?: string } }; type?: string; kind?: unknown };
        const hash = err.txHash ?? err.transactionResult?.transaction_outcome?.id ?? null;
        say(`refused: ${err.name}${err.type ? ` (${err.type})` : ""}: ${String(err.message).replace(/\s+/g, " ").slice(0, 600)}`);
        say(hash ? `  executed on-chain and failed, tx ${hash}` : "  rejected before execution (no transaction on-chain)");
      }
    };
    const vaultBalance = async () => fmtNear((await view<{ balance: string } | null>(provider, contractId, "get_vault", { account_id: hunterId }))?.balance ?? "0", 5);
    say(`vault balance before: ${await vaultBalance()} NEAR`);
    await attempt("vault_withdraw 0.1 NEAR (needs exactly 1 yoctoNEAR attached)", () =>
      fc.callFunctionRaw({ contractId, methodName: "vault_withdraw", args: { amount: near("0.1").toString() }, deposit: 1n, gas: GAS.call }));
    await attempt("vault_withdraw 0.1 NEAR without the yoctoNEAR", () =>
      fc.callFunctionRaw({ contractId, methodName: "vault_withdraw", args: { amount: near("0.1").toString() }, deposit: 0n, gas: GAS.call }));
    await attempt("vault_set_policy: raise the limits to 10 NEAR, any program (1 yoctoNEAR)", () =>
      fc.callFunctionRaw({ contractId, methodName: "vault_set_policy", args: { max_bond_per_report: near("10").toString(), max_spend_per_day: near("10").toString(), allowed_programs: null }, deposit: 1n, gas: GAS.call }));
    await attempt(`transfer 0.1 NEAR from ${hunterId} to ${cfg.accounts.owner ?? contractId}`, () =>
      fc.transfer({ receiverId: cfg.accounts.owner ?? contractId, amount: near("0.1") }));
    await attempt("add a new full-access key to the account", () => fc.addFullAccessKey(newEd25519().publicKey));

    const program0 = await view<{ verifier_pubkey: string }>(provider, contractId, "get_program", { program_id: 0 });
    const offList = (await view<{ id: number }[]>(provider, contractId, "list_programs", { from_index: 0, limit: 50 })).map((p) => p.id).find((id) => id !== 0);
    if (offList !== undefined) {
      const bytes = Buffer.from(`raw-key probe ${new Date().toISOString()}\n`);
      await attempt(`submit_report_from_vault to program ${offList} (not in the vault's allowed programs), no MCP pre-check`, () =>
        call(fc, contractId, "submit_report_from_vault",
          { program_id: offList, title: "raw-key probe: off-list program", commitment: commitmentFor(hunterId, bytes), sealed: seal(bytes, program0.verifier_pubkey) },
          { deposit: 0n, gas: GAS.call }));
    }
    if (longText) {
      const bytes = Buffer.from(longText.replace(marker, `${marker.slice(0, -4)} (raw key) -->`));
      await attempt("submit_report_from_vault with the long report (over the daily cap), no MCP pre-check", () =>
        call(fc, contractId, "submit_report_from_vault",
          { program_id: 0, title: "raw-key probe: over the daily cap", commitment: commitmentFor(hunterId, bytes), sealed: seal(bytes, program0.verifier_pubkey) },
          { deposit: 0n, gas: GAS.call }));
    }
    say(`\nvault balance after: ${await vaultBalance()} NEAR; key allowance left ${await allowance()}`);
  }

  if (v["verify-seal"] && subId !== undefined) {
    heading("out-of-band check, as the VERIFIER (not the agent): does the sealed blob open and match the v2 commitment?");
    const key = readSecret<{ private_key: string }>(cfg, VERIFIER_X25519_FILE);
    const s = await view<{ commitment: string; hunter_id: string; status: string } | null>(provider, contractId, "get_submission", { submission_id: subId });
    const sealed = await view<string | null>(provider, contractId, "get_sealed", { submission_id: subId });
    if (!key || !s || !sealed) {
      say("cannot check: verifier key, submission or sealed blob missing");
    } else {
      const own = openAndCheck(sealed, key.private_key, s.commitment, s.hunter_id);
      const other = openAndCheck(sealed, key.private_key, s.commitment, cfg.accounts.hunter2 ?? "someone-else.testnet");
      const file = fs.readFileSync(path.join(WORK, REPORT));
      say(`submission ${subId}: status ${s.status}; sealed ${sealed.length} bytes`);
      say(`  opened with the verifier key, v2 commitment for ${s.hunter_id}: ${own.ok ? "matches" : "MISMATCH: " + own.error}` +
        (own.ok ? `; plaintext ${own.plaintext.equals(file) ? "==" : "!="} the submitted file` : ""));
      say(`  the same blob and commitment claimed by ${cfg.accounts.hunter2 ?? "another account"}: ${other.ok ? "MATCHES (unexpected)" : "rejected (" + other.error.slice(0, 60) + "…)"}`);
    }
  }
  say(`\ndone [${stamp()}]`);
}

main().catch((e) => {
  process.stderr.write(`demo failed: ${(e as Error).stack ?? e}\n`);
  process.exit(1);
});
