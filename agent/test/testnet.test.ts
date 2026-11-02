// Testnet setup helpers (demo/testnet-setup.ts): names, key files, faucet request; no network.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import { REPO_ROOT } from "../src/config.ts";
import {
  REPLAYCOURT_WASM_SHA256,
  createFaucetAccount,
  credentialPath,
  errorMatches,
  faucetRequestBody,
  isTopLevelTestnetName,
  newCredential,
  randomJudgeName,
  readCredential,
  sha256Hex,
} from "../src/testnet.ts";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "replaycourt-testnet-test-"));
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

test("only top-level <name>.testnet accounts are accepted for the faucet", () => {
  assert.ok(isTopLevelTestnetName("replaycourt.testnet"));
  assert.ok(isTopLevelTestnetName("rc-judge-1a2b3c4d.testnet"));
  assert.ok(isTopLevelTestnetName(randomJudgeName()));
  for (const bad of ["owner.replaycourt.testnet", "replaycourt.near", "Replaycourt.testnet", "a.testnet", ".testnet", "x y.testnet", "testnet"]) {
    assert.equal(isTopLevelTestnetName(bad), false, bad);
  }
});

test("newCredential writes a near-cli key file with mode 600 once and then reuses it", () => {
  const dir = path.join(tmp, "creds");
  const a = newCredential(dir, "hunter1.x.testnet");
  assert.match(a.public_key, /^ed25519:/);
  assert.match(a.private_key, /^ed25519:/);
  assert.equal(fs.statSync(credentialPath(dir, "hunter1.x.testnet")).mode & 0o777, 0o600);
  const b = newCredential(dir, "hunter1.x.testnet");
  assert.deepEqual(b, a);
  assert.deepEqual(readCredential(dir, "hunter1.x.testnet"), a);
  assert.equal(readCredential(dir, "nobody.testnet"), null);
});

test("the faucet request is near-cli's JSON body; errors carry the HTTP status", async () => {
  assert.deepEqual(JSON.parse(faucetRequestBody("a1.testnet", "ed25519:abc")), { newAccountId: "a1.testnet", newAccountPublicKey: "ed25519:abc" });
  let seen: { url: string; body: string } | null = null;
  const ok = (async (url: string, init: RequestInit) => {
    seen = { url, body: String(init.body) };
    return new Response("{\"status\":\"ok\"}", { status: 200 });
  }) as unknown as typeof fetch;
  assert.equal(await createFaucetAccount("judge-1.testnet", "ed25519:abc", ok, "https://faucet.example/account"), "{\"status\":\"ok\"}");
  assert.equal(seen!.url, "https://faucet.example/account");
  const fail = (async () => new Response("rate limited", { status: 429 })) as unknown as typeof fetch;
  await assert.rejects(createFaucetAccount("judge-1.testnet", "ed25519:abc", fail), /HTTP 429: rate limited/);
  await assert.rejects(createFaucetAccount("sub.judge.testnet", "ed25519:abc", ok), /not a top-level/);
});

test("the pinned wasm hash is the one contract/build.sh records", () => {
  assert.equal(sha256Hex(Buffer.from("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  const recorded = fs.readFileSync(path.join(REPO_ROOT, "contract", "WASM_SHA256"), "utf8").trim();
  assert.equal(REPLAYCOURT_WASM_SHA256, recorded);
});

test("errorMatches looks through a failover provider's per-endpoint errors", () => {
  class AccountDoesNotExistError extends Error {}
  const missing = new AccountDoesNotExistError("Account x.testnet does not exist at block height 1");
  const failover = Object.assign(new Error("Exceeded 2 providers to execute request"), { type: "RetriesExceeded", errors: [missing, missing] });
  assert.ok(errorMatches(missing, /AccountDoesNotExist/));
  assert.ok(errorMatches(failover, /AccountDoesNotExist/));
  // one endpoint down, the other says "missing": not proof that the account is missing
  const mixed = Object.assign(new Error("Exceeded 2 providers"), { errors: [missing, new TypeError("fetch failed")] });
  assert.equal(errorMatches(mixed, /AccountDoesNotExist/), false);
  assert.equal(errorMatches(new TypeError("fetch failed"), /AccountDoesNotExist/), false);
});
