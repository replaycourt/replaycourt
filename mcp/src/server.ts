#!/usr/bin/env node
// ReplayCourt MCP server (stdio). Started by an MCP host (Claude Code, Claude Desktop, ...):
//   node src/server.ts
// Configuration comes from the environment only (see README.md). stdout is the MCP channel;
// every log line goes to stderr, through the redactor.

import os from "node:os";
import path from "node:path";
import { format } from "node:util";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { loadConfig, requireContract } from "../../agent/src/config.ts";
import { txUrl } from "../../agent/src/near.ts";
import { makeNearChain, permissionKind } from "./chain.ts";
import { loadHunterKey } from "./keys.ts";
import { Ledger } from "./ledger.ts";
import { displayPath, resolveAllowedDirs } from "./paths.ts";
import { describePolicy, loadPolicy } from "./policy.ts";
import { makeRedactor } from "./redact.ts";
import { createReplayCourtServer, SERVER_VERSION } from "./tools.ts";
import { SIGNING_MODES, vaultKeyCheck, vaultSummary } from "./vault.ts";
import type { SigningMode } from "./vault.ts";

let redact = makeRedactor();
const log = (line: string) => process.stderr.write(redact(`[replaycourt-mcp] ${line}`) + "\n");

// stdout belongs to MCP. A library that calls console.log (near-api-js' failover provider logs
// RPC errors) must not corrupt the channel, and nothing it prints may carry key material.
for (const m of ["log", "info", "warn", "error", "debug"] as const) {
  console[m] = (...args: unknown[]) => void process.stderr.write(redact(format(...args)) + "\n");
}

function fail(msg: string): never {
  log(`cannot start: ${msg}`);
  process.exit(1);
}

async function main(): Promise<void> {
  const env = process.env;
  const mode = (env.REPLAYCOURT_MCP_MODE ?? "direct").trim() as SigningMode;
  if (!SIGNING_MODES.includes(mode)) fail(`REPLAYCOURT_MCP_MODE must be one of ${SIGNING_MODES.join(", ")} (got ${JSON.stringify(env.REPLAYCOURT_MCP_MODE)})`);
  const allowFullAccess = env.REPLAYCOURT_MCP_ALLOW_FULL_ACCESS === "1";
  let cfg;
  try {
    cfg = loadConfig(env);
  } catch (e) {
    fail((e as Error).message);
  }
  if (cfg.network !== "testnet") fail(`this build is testnet-only (network "${cfg.network}")`);
  let contractId: string;
  try {
    contractId = requireContract(cfg);
  } catch (e) {
    fail((e as Error).message);
  }
  const hunterId = cfg.accounts.hunter;
  if (!hunterId) fail(`no hunter account: set REPLAYCOURT_HUNTER_ID or "hunter_id" in the config file`);

  let policy;
  try {
    policy = loadPolicy(env.REPLAYCOURT_MCP_POLICY);
  } catch (e) {
    fail((e as Error).message);
  }
  if (policy.network && policy.network !== cfg.network) fail(`the policy is pinned to network ${policy.network}, the config says ${cfg.network}`);
  if (policy.contractId && policy.contractId !== contractId) fail(`the policy is pinned to contract ${policy.contractId}, the config says ${contractId}`);

  let key;
  try {
    const loaded = loadHunterKey(env, cfg, hunterId, { mode, contractId });
    key = loaded.key;
    loaded.warnings.forEach((w) => log(`warning: ${w}`));
  } catch (e) {
    fail((e as Error).message);
  }
  // From here on, the loaded key in any form is redacted from every output and log line.
  redact = makeRedactor(key.redactionForms());

  let reportDirs: string[] = [];
  try {
    reportDirs = resolveAllowedDirs((env.REPLAYCOURT_MCP_REPORT_DIRS ?? "").split(path.delimiter));
  } catch (e) {
    fail(`REPLAYCOURT_MCP_REPORT_DIRS: ${(e as Error).message}`);
  }

  const stateDir = path.resolve(env.REPLAYCOURT_MCP_STATE_DIR ?? path.join(os.homedir(), ".replaycourt-mcp", cfg.network, hunterId));
  let ledger: Ledger;
  try {
    ledger = new Ledger(stateDir);
  } catch (e) {
    fail(`state dir ${displayPath(stateDir)}: ${(e as Error).message}`);
  }
  const snap = ledger.read();

  const chain = makeNearChain(cfg, contractId, hunterId, key);
  const network = cfg.network;
  const p = describePolicy(policy);
  log(`v${SERVER_VERSION} mode=${mode} network=${network} contract=${contractId} hunter=${hunterId} key=${key.publicKey} (from ${key.source})`);
  log(
    `policy: programs [${p.allowed_program_ids.join(", ")}], max bond ${p.max_bond_per_report.near}, ` +
      `max deposit/report ${p.max_deposit_per_report?.near ?? "-"}, 24h ${p.max_total_deposit_24h.near}, ` +
      `lifetime ${p.max_total_deposit_lifetime.near}, keep ${p.min_account_balance.near} NEAR, ${p.max_reports_per_hour} reports/h`,
  );
  log(`ledger ${displayPath(ledger.file)}: ${snap.records.length} records, integrity ${snap.integrity.ok ? "ok" : "BROKEN (" + snap.integrity.problem + ")"}`);
  log(`report dirs: ${reportDirs.length ? reportDirs.map(displayPath).join(", ") : "none (report_path disabled)"}`);

  if (mode === "vault") {
    // Vault mode is only worth its name if the key cannot do more than the vault policy allows:
    // check on-chain, before serving, that it is the hunter function-call key (the worker does
    // the same for its post_verdict key). Fail closed if the RPC cannot answer.
    let permission: unknown;
    try {
      permission = await chain.accessKeyPermission();
    } catch (e) {
      fail(`vault mode: cannot read the key's permission on ${hunterId} from the RPC (${(e as Error)?.message ?? e}); refusing to start without that check`);
    }
    const check = vaultKeyCheck(permission, contractId, hunterId, allowFullAccess);
    if (!check.ok) fail(check.problem);
    log(`key permission on ${hunterId}: ${check.summary}`);
    if (check.warning) log(`WARNING: ${check.warning}`);
    try {
      const v = vaultSummary(await chain.getVault(hunterId), BigInt(Date.now()) * 1_000_000n);
      if (!v.exists) log(`warning: ${hunterId} has no vault yet; submit_report refuses until a full-access key deposits (vault_deposit) and sets a policy`);
      else if (!v.policy) log(`warning: the vault of ${hunterId} has no policy yet; submit_report refuses until vault_set_policy`);
      else {
        log(
          `vault: balance ${v.balance?.near} NEAR; policy: programs ${v.policy.allowed_programs ? "[" + v.policy.allowed_programs.join(", ") + "]" : "any"}, ` +
            `max bond ${v.policy.max_bond_per_report.near}, max ${v.policy.max_spend_per_day.near} NEAR per 24 h; ` +
            `spent ${v.spent_in_current_window?.near} in the current window`,
        );
      }
    } catch (e) {
      log(`warning: cannot read the vault of ${hunterId} (${(e as Error)?.message ?? e}); submit_report refuses until it can`);
    }
  } else {
    // Tell the human early if the key cannot sign deposits (function-call key) or is not on the account.
    chain.accessKeyPermission().then(
      (perm) => {
        const kind = permissionKind(perm);
        if (kind === "FunctionCall") {
          log("warning: the loaded key is a function-call key; NEAR rejects attached deposits from such keys, so submit_report will fail. " +
            "If it is the hunter's vault key, set REPLAYCOURT_MCP_MODE=vault (see README)");
        } else if (kind === "not_found") log(`warning: the loaded key is not an access key of ${hunterId}`);
        else log(`key permission on ${hunterId}: ${kind}`);
      },
      () => undefined,
    );
  }

  const handle = serveStdio(() =>
    createReplayCourtServer({
      chain,
      policy,
      ledger,
      hunterId,
      contractId,
      network,
      reportDirs,
      redact: (s) => redact(s),
      log,
      txUrl: (hash) => txUrl(network, hash),
      mode,
      publicKey: key.publicKey,
    }),
  );
  const stop = () => {
    void handle.close().finally(() => process.exit(0));
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
  log("listening on stdio");
}

main().catch((e) => fail((e as Error)?.message ?? String(e)));
