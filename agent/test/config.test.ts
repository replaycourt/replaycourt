// Deployment files: secrets_dir, relative REPLAYCOURT_CONFIG, showcase defaults.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import {
  DEMO_CONTRACT,
  REPO_ROOT,
  SHOWCASE_PROGRAMS,
  collectAccounts,
  loadConfig,
  pinnedPrograms,
  resolveConfigPath,
  workerPrograms,
} from "../src/config.ts";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "replaycourt-config-test-"));
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

function writeDeployment(name: string, extra: Record<string, unknown>): string {
  const file = path.join(tmp, name);
  fs.writeFileSync(file, JSON.stringify({
    network: "testnet", contract_id: "contract.example.testnet", owner_id: "owner.example.testnet",
    verifier_id: "verifier.example.testnet", hunter1_id: "hunter1.example.testnet", hunter3_id: "hunter3.example.testnet",
    verifier2_id: "verifier2.example.testnet", rpc_url: "https://test.rpc.fastnear.com", ...extra,
  }));
  return file;
}

test("secrets_dir in the deployment file selects a separate secrets directory (relative to the file)", () => {
  const file = writeDeployment("showcase.json", { secrets_dir: "showcase" });
  const cfg = loadConfig({ REPLAYCOURT_CONFIG: file });
  assert.equal(cfg.secretsDir, path.join(tmp, "showcase"));
  assert.equal(cfg.contractId, "contract.example.testnet");
  assert.equal(cfg.accounts.hunter3, "hunter3.example.testnet");
  assert.equal(cfg.accounts.verifier2, "verifier2.example.testnet");
  assert.equal(cfg.accounts.secrets_dir, undefined);
});

test("credentials_dir in the deployment file selects where full-access keys are read", () => {
  const file = writeDeployment("judge.json", { secrets_dir: "judge", credentials_dir: "judge/credentials" });
  const cfg = loadConfig({ REPLAYCOURT_CONFIG: file });
  assert.equal(cfg.credentialsDir, path.join(tmp, "judge", "credentials"));
  assert.equal(loadConfig({ REPLAYCOURT_CONFIG: file, REPLAYCOURT_CREDENTIALS_DIR: path.join(tmp, "c") }).credentialsDir, path.join(tmp, "c"));
  assert.equal(loadConfig({ REPLAYCOURT_CONFIG: writeDeployment("nocred.json", {}) }).credentialsDir,
    path.join(os.homedir(), ".near-credentials", "testnet"));
  assert.equal(cfg.accounts.credentials_dir, undefined);
});

test("REPLAYCOURT_SECRETS_DIR wins over secrets_dir; without either the default is .secrets/", () => {
  const file = writeDeployment("showcase2.json", { secrets_dir: "showcase" });
  assert.equal(loadConfig({ REPLAYCOURT_CONFIG: file, REPLAYCOURT_SECRETS_DIR: path.join(tmp, "x") }).secretsDir, path.join(tmp, "x"));
  const plain = writeDeployment("plain.json", {});
  assert.equal(loadConfig({ REPLAYCOURT_CONFIG: plain }).secretsDir, path.join(REPO_ROOT, ".secrets"));
});

test("a relative REPLAYCOURT_CONFIG is found from INIT_CWD or the repository root", () => {
  writeDeployment("rel.json", {});
  assert.equal(resolveConfigPath("rel.json", { INIT_CWD: tmp }), path.join(tmp, "rel.json"));
  assert.equal(resolveConfigPath(path.join(tmp, "rel.json"), {}), path.join(tmp, "rel.json"));
  // "agent/package.json" exists only relative to the repository root, not to agent/ (the cwd of npm test).
  assert.equal(resolveConfigPath("agent/package.json", {}), path.join(REPO_ROOT, "agent", "package.json"));
});

test("read-only commands default to the showcase deployment and its pinned programs 0 and 1", () => {
  assert.equal(DEMO_CONTRACT.testnet, "contract.replaycourt.testnet");
  assert.deepEqual(SHOWCASE_PROGRAMS.testnet[DEMO_CONTRACT.testnet], [0, 1]);
  assert.deepEqual(Object.keys(SHOWCASE_PROGRAMS.testnet), [DEMO_CONTRACT.testnet]);
});

test("collectAccounts keeps every <role>_id, including extra hunters and verifiers", () => {
  const acc = collectAccounts({ hunter3_id: "h3.testnet", verifier2_id: "v2.testnet", contract_id: "c.testnet", secrets_dir: "x" });
  assert.deepEqual(acc, { hunter3: "h3.testnet", verifier2: "v2.testnet" });
});

test("worker allow-list: REPLAYCOURT_WORKER_PROGRAMS wins over \"programs\" in the deployment file; none = null", () => {
  assert.deepEqual(workerPrograms({ raw: {} }, { REPLAYCOURT_WORKER_PROGRAMS: "0, 2,5" }), [0, 2, 5]);
  assert.deepEqual(workerPrograms({ raw: { programs: [1, "3"] } }, {}), [1, 3]);
  assert.deepEqual(workerPrograms({ raw: { programs: [1] } }, { REPLAYCOURT_WORKER_PROGRAMS: "4" }), [4]);
  assert.equal(workerPrograms({ raw: {} }, {}), null);
  assert.equal(workerPrograms({ raw: {} }, { REPLAYCOURT_WORKER_PROGRAMS: " " }), null);
  assert.throws(() => workerPrograms({ raw: {} }, { REPLAYCOURT_WORKER_PROGRAMS: "0,x" }), /REPLAYCOURT_WORKER_PROGRAMS: "x" is not a program id/);
  assert.throws(() => workerPrograms({ raw: { programs: [-1] } }, {}), /config "programs"/);
});

test("pinned showcase programs: the showcase contract is pinned, other contracts are not", () => {
  assert.deepEqual(pinnedPrograms("testnet", DEMO_CONTRACT.testnet), SHOWCASE_PROGRAMS.testnet[DEMO_CONTRACT.testnet]);
  assert.ok(pinnedPrograms("testnet", DEMO_CONTRACT.testnet)!.includes(0));
  assert.equal(pinnedPrograms("testnet", "someone-else.testnet"), null);
  assert.equal(pinnedPrograms("mainnet", DEMO_CONTRACT.testnet), null);
});
