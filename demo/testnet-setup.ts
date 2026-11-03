#!/usr/bin/env node
// Creates a complete ReplayCourt deployment on NEAR testnet from nothing, without near-cli:
//   <master>.testnet through the testnet faucet (10 NEAR), the sub-accounts contract., owner.,
//   verifier., verifier2., hunter1., hunter2.<master>, and the contract (deploy + new()).
// Keys are stored only under .secrets/<master>/credentials/ (git-ignored, mode 600). The
// deployment file .secrets/<master>.json (account ids, no keys) is what the agent CLI reads with
// REPLAYCOURT_CONFIG. Idempotent: existing accounts and an existing deployment are reused.
//
//   node demo/testnet-setup.ts --master <name>.testnet [--wasm <file>]
//
// The wasm: --wasm, else contract/target/near/replaycourt.wasm if it exists, else the code of the
// public showcase contract (read over RPC). Its sha256 must equal the pinned build hash unless
// --allow-other-wasm is given. Testnet only.

import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { DEMO_CONTRACT, REPO_ROOT, loadConfig } from "../agent/src/config.ts";
import { accountWithKey, fmtNear, makeProvider, near, txUrl, view } from "../agent/src/near.ts";
import {
  REPLAYCOURT_WASM_SHA256,
  accountExists,
  createFaucetAccount,
  deployAndInit,
  deployedCodeSha256,
  fetchDeployedCode,
  isTopLevelTestnetName,
  keyPairOf,
  newCredential,
  readCredential,
  sha256Hex,
} from "../agent/src/testnet.ts";

const { values } = parseArgs({
  options: {
    master: { type: "string" },
    wasm: { type: "string" },
    "allow-other-wasm": { type: "boolean", default: false },
  },
});
const master = values.master ?? "";
if (!isTopLevelTestnetName(master)) {
  console.error("usage: node demo/testnet-setup.ts --master <name>.testnet   (lowercase letters, digits, - and _)");
  process.exit(64);
}
const base = master.replace(/\.testnet$/, "");
const secretsDir = path.join(REPO_ROOT, ".secrets", base);
const credDir = path.join(secretsDir, "credentials");
const deployFile = path.join(REPO_ROOT, ".secrets", `${base}.json`);

// Funding from the faucet's 10 NEAR. The contract holds the wasm's storage stake (~2.96 NEAR for
// 295 KB) and pays the gas of its own deploy.
const ACCOUNTS: [role: string, prefix: string, amount: string][] = [
  ["contract", "contract", "3.2"],
  ["owner", "owner", "2.8"],
  ["verifier", "verifier", "0.3"],
  ["verifier2", "verifier2", "0.15"],
  ["hunter1", "hunter1", "1"],
  ["hunter2", "hunter2", "1"],
];

const cfg = loadConfig({ ...process.env, REPLAYCOURT_CONFIG: deployFile });
if (cfg.network !== "testnet") throw new Error("testnet only");
const provider = makeProvider(cfg);
const log = (s: string) => console.log(s);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitForAccount(id: string, seconds: number) {
  for (let i = 0; i < seconds / 3; i++) {
    if (await accountExists(provider, id)) return;
    await sleep(3000);
  }
  throw new Error(`${id} did not appear on chain within ${seconds} s`);
}

// 1. master account through the faucet
if (await accountExists(provider, master)) {
  if (!readCredential(credDir, master)) {
    throw new Error(`${master} already exists, but its key is not in ${path.relative(REPO_ROOT, credDir)}; pick another name`);
  }
  log(`master ${master} exists (key in ${path.relative(REPO_ROOT, credDir)})`);
} else {
  const c = newCredential(credDir, master);
  log(`creating ${master} through the testnet faucet …`);
  await createFaucetAccount(master, c.public_key);
  await waitForAccount(master, 90);
  log(`master ${master} created`);
}
const masterAcc = accountWithKey(provider, master, keyPairOf(readCredential(credDir, master)!));
const bal = await provider.viewAccount({ accountId: master, blockQuery: { finality: "final" } });
log(`  balance ${fmtNear(bal.amount)} NEAR`);

// 2. sub-accounts
const ids: Record<string, string> = {};
for (const [role, prefix, amount] of ACCOUNTS) {
  const id = `${prefix}.${master}`;
  ids[role] = id;
  if (await accountExists(provider, id)) {
    if (!readCredential(credDir, id)) throw new Error(`${id} exists but its key is not in ${path.relative(REPO_ROOT, credDir)}`);
    log(`${id} exists`);
    continue;
  }
  const c = newCredential(credDir, id);
  const res = await masterAcc.createAccount({ newAccountId: id, publicKey: c.public_key, nearToTransfer: near(amount) });
  log(`created ${id} (${amount} NEAR): tx ${res.transaction_outcome?.id}  ${txUrl("testnet", res.transaction_outcome?.id ?? "")}`);
}

// 3. the wasm
let wasm: Uint8Array;
let wasmSource: string;
const built = path.join(REPO_ROOT, "contract", "target", "near", "replaycourt.wasm");
if (values.wasm) {
  wasm = fs.readFileSync(values.wasm);
  wasmSource = values.wasm;
} else if (fs.existsSync(built)) {
  wasm = fs.readFileSync(built);
  wasmSource = path.relative(REPO_ROOT, built);
  // Builds are not bit-identical across operating systems, so a judge's own build usually differs.
  if (sha256Hex(wasm) !== REPLAYCOURT_WASM_SHA256 && !values["allow-other-wasm"]) {
    log(`${wasmSource} differs from the pinned build (builds differ across systems); using the showcase contract's code instead`);
    wasm = await fetchDeployedCode(provider, DEMO_CONTRACT.testnet);
    wasmSource = `code of ${DEMO_CONTRACT.testnet} (read over RPC; the local build differs from the pin)`;
  }
} else {
  wasm = await fetchDeployedCode(provider, DEMO_CONTRACT.testnet);
  wasmSource = `code of ${DEMO_CONTRACT.testnet} (read over RPC; no local build found)`;
}
const wasmSha = sha256Hex(wasm);
log(`wasm: ${wasmSource}, ${wasm.length} bytes, sha256 ${wasmSha}`);
if (wasmSha !== REPLAYCOURT_WASM_SHA256) {
  const msg = `the wasm's sha256 differs from the pinned build ${REPLAYCOURT_WASM_SHA256}`;
  if (!values["allow-other-wasm"]) throw new Error(`${msg} (use --allow-other-wasm to deploy it anyway)`);
  log(`WARNING: ${msg}; deploying it because of --allow-other-wasm`);
}

// 4. deploy + new(owner_id = master), unless already done
const contractId = ids.contract;
const deployed = await deployedCodeSha256(provider, contractId);
if (deployed === null) {
  const contract = accountWithKey(provider, contractId, keyPairOf(readCredential(credDir, contractId)!));
  const tx = await deployAndInit(contract, wasm, master);
  log(`deployed and initialized ${contractId}: tx ${tx}  ${txUrl("testnet", tx)}`);
} else if (deployed === wasmSha) {
  log(`${contractId} already runs this wasm`);
} else {
  throw new Error(`${contractId} runs other code (sha256 ${deployed}); refusing to redeploy`);
}
const version = await view<string>(provider, contractId, "version", {});
log(`contract version ${version}`);

// 5. deployment file (account ids, no keys)
const deployment = {
  network: "testnet",
  contract_id: contractId,
  contract_owner_id: master,
  owner_id: ids.owner,
  verifier_id: ids.verifier,
  verifier2_id: ids.verifier2,
  hunter1_id: ids.hunter1,
  hunter2_id: ids.hunter2,
  rpc_url: "https://test.rpc.fastnear.com",
  explorer: "https://testnet.nearblocks.io",
  secrets_dir: base,
  credentials_dir: `${base}/credentials`,
  wasm_sha256: wasmSha,
};
fs.mkdirSync(path.dirname(deployFile), { recursive: true });
fs.writeFileSync(deployFile, JSON.stringify(deployment, null, 2) + "\n");
log(`wrote ${path.relative(REPO_ROOT, deployFile)} (account ids only; keys in ${path.relative(REPO_ROOT, credDir)}/)`);
