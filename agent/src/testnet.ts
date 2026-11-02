// Testnet setup without near-cli: faucet account, sub-accounts, contract deployment. Used by
// demo/testnet-setup.ts (judge path C, demo/full-testnet.sh). Testnet only.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { KeyPair, actions } from "near-api-js";
import type { Account, KeyPairString, Provider } from "near-api-js";

/** sha256 of the wasm that contract/build.sh builds (rustc 1.95.0, cargo-near 0.22.0), the code of the
 *  showcase contract (demo/SHOWCASE.md). The same value is in contract/WASM_SHA256. */
export const REPLAYCOURT_WASM_SHA256 = "456631c55d04492c6f4143a19f82ebd66942af4333d05997db910d7a1608bd32";

/** near-cli-rs' testnet faucet ("sponsor-by-faucet-service"): creates <name>.testnet with 10 NEAR. */
export const TESTNET_FAUCET_URL = "https://helper.nearprotocol.com/account";

const ACCOUNT_RE = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;

/** A top-level testnet account the faucet can create: "<name>.testnet", lowercase, 2..64 chars. */
export function isTopLevelTestnetName(id: string): boolean {
  return ACCOUNT_RE.test(id) && id.length >= 2 && id.length <= 64 && /^[a-z\d_-]+\.testnet$/.test(id) && id.length > ".testnet".length + 1;
}

export function randomJudgeName(): string {
  return `rc-judge-${crypto.randomBytes(4).toString("hex")}.testnet`;
}

export function sha256Hex(data: Uint8Array): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

export interface Credential {
  account_id: string;
  public_key: string;
  private_key: string;
}

/** near-cli legacy keychain format: <dir>/<account>.json = {account_id, public_key, private_key}. */
export function credentialPath(dir: string, accountId: string): string {
  return path.join(dir, `${accountId}.json`);
}

export function readCredential(dir: string, accountId: string): Credential | null {
  try {
    const c = JSON.parse(fs.readFileSync(credentialPath(dir, accountId), "utf8")) as Credential;
    return c.private_key ? c : null;
  } catch {
    return null;
  }
}

/** Create a new ed25519 key for `accountId` and store it (mode 600) before it is used on chain,
 *  so that a crash between the two steps never loses the key of a funded account. */
export function newCredential(dir: string, accountId: string): Credential {
  const existing = readCredential(dir, accountId);
  if (existing) return existing;
  const kp = KeyPair.fromRandom("ed25519");
  const c: Credential = { account_id: accountId, public_key: kp.getPublicKey().toString(), private_key: kp.toString() };
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(credentialPath(dir, accountId), JSON.stringify(c, null, 2) + "\n", { mode: 0o600 });
  return c;
}

export function faucetRequestBody(accountId: string, publicKey: string): string {
  return JSON.stringify({ newAccountId: accountId, newAccountPublicKey: publicKey });
}

/** Ask the testnet faucet to create `accountId` with `publicKey` as its full-access key. */
export async function createFaucetAccount(accountId: string, publicKey: string,
  fetchImpl: typeof fetch = fetch, url = TESTNET_FAUCET_URL): Promise<string> {
  if (!isTopLevelTestnetName(accountId)) throw new Error(`not a top-level testnet account name: ${accountId}`);
  const res = await fetchImpl(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: faucetRequestBody(accountId, publicKey),
    signal: AbortSignal.timeout(60_000),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`faucet answered HTTP ${res.status}: ${text.slice(0, 300)}`);
  return text;
}

/** True if the error (or, for a failover provider, every endpoint's error) matches `re`. */
export function errorMatches(err: unknown, re: RegExp): boolean {
  const text = (x: unknown) => {
    const o = x as { constructor?: { name?: string }; type?: unknown; message?: unknown } | null;
    return `${o?.constructor?.name ?? ""} ${String(o?.type ?? "")} ${String(o?.message ?? x)}`;
  };
  const nested = (err as { errors?: unknown[] } | null)?.errors;
  return Array.isArray(nested) && nested.length > 0 ? nested.every((x) => re.test(text(x))) : re.test(text(err));
}

export async function accountExists(provider: Provider, accountId: string): Promise<boolean> {
  try {
    await provider.viewAccount({ accountId, blockQuery: { finality: "final" } });
    return true;
  } catch (e) {
    if (errorMatches(e, /does not exist|UNKNOWN_ACCOUNT|AccountDoesNotExist/i)) return false;
    throw e;
  }
}

/** sha256 (hex) of the code deployed on `accountId`, or null if it has none. */
export async function deployedCodeSha256(provider: Provider, accountId: string): Promise<string | null> {
  try {
    const code = await provider.viewContractCode({ contractId: accountId, blockQuery: { finality: "final" } });
    return sha256Hex(code.code);
  } catch (e) {
    if (errorMatches(e, /no contract code|CodeDoesNotExist|NO_CONTRACT_CODE|does not exist/i)) return null;
    throw e;
  }
}

export async function fetchDeployedCode(provider: Provider, accountId: string): Promise<Uint8Array> {
  const code = await provider.viewContractCode({ contractId: accountId, blockQuery: { finality: "final" } });
  return code.code;
}

/** Deploy the wasm and call new(owner_id) in one transaction (signed by the contract account). */
export async function deployAndInit(contract: Account, wasm: Uint8Array, ownerId: string): Promise<string> {
  const res = await contract.signAndSendTransaction({
    receiverId: contract.accountId,
    actions: [actions.deployContract(wasm), actions.functionCall("new", { owner_id: ownerId }, 30_000_000_000_000n, 0n)],
    waitUntil: "FINAL",
  });
  return res.transaction_outcome?.id ?? "?";
}

export function keyPairOf(c: Credential): KeyPairString {
  return c.private_key as KeyPairString;
}
