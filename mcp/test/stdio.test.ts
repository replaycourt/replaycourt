// The real entry point (src/server.ts) spawned over stdio, as an MCP host would: config and key
// file from the environment, the RPC pointed at a closed local port (no network in tests).

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { PassThrough } from "node:stream";
import { after, describe, it } from "node:test";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { hunterKeyFile } from "../../agent/src/actions.ts";
import { newEd25519 } from "../../agent/src/near.ts";
import { BASE_POLICY, cleanup, CONTRACT, fcPermission, tmpDir, vault } from "./helpers.ts";
import { startMockRpc } from "./rpc-mock.ts";

after(cleanup);

const SERVER = path.resolve(import.meta.dirname, "..", "src", "server.ts");

function setup(over: Record<string, string | undefined> = {}) {
  const dir = tmpDir("fpmcp-stdio-");
  const { secretKey, publicKey } = newEd25519();
  const keyFile = path.join(dir, "hunter-key.json");
  fs.writeFileSync(keyFile, JSON.stringify({ account_id: "hunter.mock.testnet", public_key: publicKey, private_key: secretKey }), { mode: 0o600 });
  const config = path.join(dir, "config.json");
  fs.writeFileSync(config, JSON.stringify({ network: "testnet", contract_id: CONTRACT, hunter_id: "hunter.mock.testnet" }));
  const policy = path.join(dir, "policy.json");
  fs.writeFileSync(policy, JSON.stringify(BASE_POLICY));
  const reports = path.join(dir, "reports");
  fs.mkdirSync(reports);
  fs.writeFileSync(path.join(reports, "r.md"), "# r\n");
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? "",
    HOME: process.env.HOME ?? dir,
    TMPDIR: process.env.TMPDIR ?? dir,
    REPLAYCOURT_CONFIG: config,
    REPLAYCOURT_RPC_URL: "http://127.0.0.1:9",
    REPLAYCOURT_HUNTER_KEY_FILE: keyFile,
    REPLAYCOURT_MCP_POLICY: policy,
    REPLAYCOURT_MCP_STATE_DIR: path.join(dir, "state"),
    REPLAYCOURT_MCP_REPORT_DIRS: reports,
  };
  for (const [k, v] of Object.entries(over)) {
    if (v === undefined) delete env[k];
    else env[k] = v;
  }
  return { dir, env, secretKey, publicKey, keyFile };
}

/** The server must exit 1 at startup with this message and print nothing on stdout. */
function startFails(over: Record<string, string | undefined>, pattern: RegExp) {
  const { env } = setup(over);
  const r = spawnSync(process.execPath, [SERVER], { env, input: "", timeout: 30_000 });
  assert.equal(r.status, 1, r.stderr.toString());
  assert.match(r.stderr.toString(), pattern);
  assert.equal(r.stdout.toString(), "", "nothing on the protocol channel");
}

/** Spawn the server, close its stdin, wait until it exits (async: the mock RPC runs in this process). */
function runToExit(env: Record<string, string>, timeoutMs = 30_000): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SERVER], { env, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (b: Buffer) => (stdout += b.toString()));
    child.stderr.on("data", (b: Buffer) => (stderr += b.toString()));
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`server did not exit: ${stderr}`));
    }, timeoutMs);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
    child.stdin.end();
  });
}

/** Connect an MCP client over stdio; returns the client, collected stderr and a close function. */
async function connect(env: Record<string, string>) {
  const transport = new StdioClientTransport({ command: process.execPath, args: [SERVER], env, stderr: "pipe" });
  const stderr: string[] = [];
  (transport.stderr as PassThrough | null)?.on("data", (b: Buffer) => stderr.push(b.toString()));
  const client = new Client({ name: "stdio-test", version: "1.0.0" });
  await client.connect(transport);
  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const r = await client.callTool({ name, arguments: args });
    return JSON.parse((r.content as { text: string }[])[0].text) as Record<string, unknown>;
  };
  return { client, call, log: () => stderr.join("") };
}

describe("stdio entry point", () => {
  it("serves the tools over stdio and never prints the key", { timeout: 60_000 }, async () => {
    const { env, secretKey, keyFile } = setup();
    const transport = new StdioClientTransport({ command: process.execPath, args: [SERVER], env, stderr: "pipe" });
    const stderr: string[] = [];
    const pipe = transport.stderr as PassThrough | null;
    pipe?.on("data", (b: Buffer) => stderr.push(b.toString()));
    const client = new Client({ name: "stdio-test", version: "1.0.0" });
    await client.connect(transport);
    const texts: string[] = [];
    try {
      const { tools } = await client.listTools();
      assert.equal(tools.length, 9);
      const call = async (name: string, args: Record<string, unknown>) => {
        const r = await client.callTool({ name, arguments: args });
        const t = (r.content as { text: string }[])[0].text;
        texts.push(t);
        return JSON.parse(t) as Record<string, unknown>;
      };
      // the key file itself, as a prompt-injected agent would try
      let doc = await call("submit_report", { program_id: 7, title: "t", report_path: keyFile });
      assert.equal(doc.rule, "path_not_allowed");
      doc = await call("submit_report", { program_id: 0, title: "t", report_markdown: "x" });
      assert.equal(doc.rule, "program_not_allowed");
      // RPC unreachable: read tools report an error result, spending fails closed
      doc = await call("budget_status", {});
      assert.equal((doc.balance as { available: unknown }).available, null);
      doc = await call("list_programs", {});
      assert.equal(doc.outcome, "error");
    } finally {
      await client.close();
    }
    const log = stderr.join("");
    assert.match(log, /listening on stdio/);
    assert.match(log, /hunter=hunter\.mock\.testnet key=ed25519:/);
    const body = secretKey.slice("ed25519:".length);
    for (const t of [...texts, log]) assert.ok(!t.includes(body), "key material in stdout or stderr");
  });

  it("does not start without a policy", () => startFails({ REPLAYCOURT_MCP_POLICY: undefined }, /REPLAYCOURT_MCP_POLICY is not set/));

  it("does not start with an invalid policy", () => {
    const { dir } = setup();
    const bad = path.join(dir, "bad.json");
    fs.writeFileSync(bad, JSON.stringify({ ...BASE_POLICY, max_bond: "9" }));
    startFails({ REPLAYCOURT_MCP_POLICY: bad }, /unknown field "max_bond"/);
  });

  it("does not start when the policy is pinned to another contract", () => {
    const { dir } = setup();
    const other = path.join(dir, "other.json");
    fs.writeFileSync(other, JSON.stringify({ ...BASE_POLICY, contract_id: "other.testnet" }));
    startFails({ REPLAYCOURT_MCP_POLICY: other }, /pinned to contract other\.testnet/);
  });

  it("does not start on mainnet", () => startFails({ REPLAYCOURT_NETWORK: "mainnet", REPLAYCOURT_ALLOW_MAINNET: "1" }, /testnet-only/));

  it("does not start with a key file of another account", () => {
    const { dir } = setup();
    const f = path.join(dir, "other-key.json");
    fs.writeFileSync(f, JSON.stringify({ account_id: "someone.testnet", private_key: newEd25519().secretKey }), { mode: 0o600 });
    startFails({ REPLAYCOURT_HUNTER_KEY_FILE: f }, /belongs to someone\.testnet/);
  });
});

describe("stdio entry point, vault mode: the on-chain key check at startup", () => {
  const vaultEnv = async (permission: unknown, over: Record<string, string | undefined> = {}) => {
    const base = setup();
    const rpc = await startMockRpc({ keys: permission === undefined ? {} : { [base.publicKey]: permission }, views: { get_vault: vault({ account_id: "hunter.mock.testnet" }) } });
    rpcs.push(rpc);
    const env = { ...base.env, REPLAYCOURT_MCP_MODE: "vault", REPLAYCOURT_RPC_URL: rpc.url };
    for (const [k, v] of Object.entries(over)) {
      if (v === undefined) delete (env as Record<string, string>)[k];
      else (env as Record<string, string>)[k] = v;
    }
    return { ...base, env, rpc };
  };
  const rpcs: { close: () => Promise<void> }[] = [];
  after(async () => {
    for (const r of rpcs.splice(0)) await r.close();
  });

  it("refuses to start with a full-access key", { timeout: 60_000 }, async () => {
    const { env, rpc } = await vaultEnv("FullAccess");
    const r = await runToExit(env);
    assert.equal(r.code, 1, r.stderr);
    assert.match(r.stderr, /cannot start: vault mode refuses a full-access key \(a full-access key can withdraw the vault, change its policy, transfer the account's NEAR and add keys\)/);
    assert.match(r.stderr, /REPLAYCOURT_MCP_ALLOW_FULL_ACCESS=1/);
    assert.equal(r.stdout, "", "nothing on the protocol channel");
    assert.deepEqual(rpc.state.seen, ["view_access_key"]);
  });

  it("starts with a full-access key only with REPLAYCOURT_MCP_ALLOW_FULL_ACCESS=1, and warns", { timeout: 60_000 }, async () => {
    const { env } = await vaultEnv("FullAccess", { REPLAYCOURT_MCP_ALLOW_FULL_ACCESS: "1" });
    const s = await connect(env);
    try {
      const doc = await s.call("budget_status");
      assert.equal((doc.signing as { mode: string }).mode, "vault");
      assert.deepEqual((doc.signing as { permission: unknown }).permission, { kind: "FullAccess" });
    } finally {
      await s.client.close();
    }
    assert.match(s.log(), /WARNING: vault mode is running with a FULL-ACCESS key/);
  });

  it("refuses a function-call key with other methods or another receiver", { timeout: 60_000 }, async () => {
    let { env } = await vaultEnv(fcPermission({ method_names: ["submit_report_from_vault"] }), { REPLAYCOURT_MCP_ALLOW_FULL_ACCESS: "1" });
    let r = await runToExit(env);
    assert.equal(r.code, 1, r.stderr);
    assert.match(r.stderr, /not a hunter function-call key: the key may call \[submit_report_from_vault\], expected exactly \[finalize, submit_report_from_vault, withdraw_pending\]/);
    ({ env } = await vaultEnv(fcPermission({ receiver_id: "other.testnet" })));
    r = await runToExit(env);
    assert.equal(r.code, 1, r.stderr);
    assert.match(r.stderr, /the key's receiver is other\.testnet/);
  });

  it("refuses a key that is not on the account, and fails closed when the RPC cannot answer", { timeout: 60_000 }, async () => {
    let { env } = await vaultEnv(undefined);
    let r = await runToExit(env);
    assert.equal(r.code, 1, r.stderr);
    assert.match(r.stderr, /the loaded key is not an access key of hunter\.mock\.testnet/);
    ({ env } = await vaultEnv(fcPermission(), { REPLAYCOURT_RPC_URL: "http://127.0.0.1:9" }));
    r = await runToExit(env);
    assert.equal(r.code, 1, r.stderr);
    assert.match(r.stderr, /vault mode: cannot read the key's permission .* refusing to start without that check/);
  });

  it("loads the hunter function-call key from the secrets directory (never the keychain) and shows the vault", { timeout: 60_000 }, async () => {
    const base = await vaultEnv(fcPermission());
    const secrets = path.join(base.dir, "secrets");
    fs.mkdirSync(secrets, { mode: 0o700 });
    // without the file: refused, and the keychain is not used as a fallback
    const env = { ...base.env, REPLAYCOURT_SECRETS_DIR: secrets };
    delete (env as Record<string, string>).REPLAYCOURT_HUNTER_KEY_FILE;
    let r = await runToExit(env);
    assert.equal(r.code, 1, r.stderr);
    assert.match(r.stderr, /vault mode: no function-call key for hunter\.mock\.testnet .*setup-hunter-key/);
    // a key file of another contract is refused
    const file = path.join(secrets, hunterKeyFile("hunter.mock.testnet"));
    const rec = { account_id: "hunter.mock.testnet", contract_id: "other.testnet", public_key: base.publicKey, private_key: base.secretKey };
    fs.writeFileSync(file, JSON.stringify(rec), { mode: 0o600 });
    r = await runToExit(env);
    assert.equal(r.code, 1, r.stderr);
    assert.match(r.stderr, /is a key for the contract other\.testnet, not for contract\.mock\.testnet/);
    // the right file: starts, and budget_status shows the on-chain vault
    fs.writeFileSync(file, JSON.stringify({ ...rec, contract_id: CONTRACT }), { mode: 0o600 });
    const s = await connect(env);
    let doc: Record<string, unknown>;
    try {
      doc = await s.call("budget_status");
    } finally {
      await s.client.close();
    }
    const log = s.log();
    assert.match(log, /mode=vault .*key=ed25519:\S+ \(from .*hunter-fc-key\.hunter\.mock\.testnet\.json\)/);
    assert.match(log, /key permission on hunter\.mock\.testnet: FunctionCall: receiver contract\.mock\.testnet, methods \[submit_report_from_vault, finalize, withdraw_pending\], allowance 0\.5 NEAR/);
    assert.match(log, /vault: balance 1 NEAR; policy: programs \[7\], max bond 0\.15, max 0\.5 NEAR per 24 h/);
    const v = doc.vault as { exists: boolean; policy: { allowed_programs: number[] } };
    assert.equal(v.exists, true);
    assert.deepEqual(v.policy.allowed_programs, [7]);
    assert.equal(((doc.signing as { permission: { kind: string } }).permission).kind, "FunctionCall");
    assert.ok(!log.includes(base.secretKey.slice("ed25519:".length)), "the key never reaches stderr");
  });

  it("refuses an unknown REPLAYCOURT_MCP_MODE", () => startFails({ REPLAYCOURT_MCP_MODE: "yolo" }, /REPLAYCOURT_MCP_MODE must be one of direct, vault/));
});
