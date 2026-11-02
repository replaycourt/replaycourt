// Thin wrapper around near-api-js 7 (Account, JsonRpcProvider, KeyPair).

import {
  Account,
  FailoverRpcProvider,
  JsonRpcProvider,
  KeyPair,
  getTransactionLastResult,
  nearToYocto,
  teraToGas,
  yoctoToNear,
} from "near-api-js";
import type { KeyPairString, Provider } from "near-api-js";
import type { ChainClient } from "./actions.ts";
import { EXPLORER, loadFullAccessKey } from "./config.ts";
import type { Config } from "./config.ts";

export const GAS = {
  call: teraToGas("100"),
  light: teraToGas("50"),
};

export function makeProvider(cfg: Config): Provider {
  if (cfg.rpcUrls.length === 0) throw new Error(`no RPC URL for network ${cfg.network}`);
  const providers = cfg.rpcUrls.map((url) => new JsonRpcProvider({ url }, { retries: 4, backoff: 1.5, wait: 500 }));
  return providers.length === 1 ? providers[0] : new FailoverRpcProvider(providers);
}

export async function view<T>(provider: Provider, contractId: string, method: string, args: Record<string, unknown> = {}): Promise<T> {
  return (await provider.callFunction<never>({ contractId, method, args })) as unknown as T;
}

export function accountWithKey(provider: Provider, accountId: string, privateKey: string): Account {
  return new Account(accountId, provider, privateKey as KeyPairString);
}

export function accountFromCredentials(cfg: Config, provider: Provider, accountId: string): Account {
  return accountWithKey(provider, accountId, loadFullAccessKey(cfg, accountId));
}

export interface CallResult<T> {
  result: T;
  txHash: string;
}

export async function call<T>(
  account: Account,
  contractId: string,
  methodName: string,
  args: Record<string, unknown>,
  opts: { deposit?: bigint; gas?: bigint } = {},
): Promise<CallResult<T>> {
  const res = await account.callFunctionRaw({
    contractId,
    methodName,
    args,
    deposit: opts.deposit ?? 0n,
    gas: opts.gas ?? GAS.call,
    waitUntil: "FINAL",
  });
  const txHash = res.transaction_outcome?.id ?? (res.transaction as { hash?: string })?.hash ?? "?";
  return { result: getTransactionLastResult(res) as T, txHash };
}

export function txUrl(network: string, hash: string): string {
  return `${EXPLORER[network] ?? EXPLORER.testnet}/txns/${hash}`;
}

export function accountUrl(network: string, accountId: string): string {
  return `${EXPLORER[network] ?? EXPLORER.testnet}/address/${accountId}`;
}

/** "1.5" NEAR -> yocto bigint. */
export function near(amount: string | number): bigint {
  const s = String(amount).trim();
  if (!/^\d+(\.\d+)?$/.test(s)) throw new Error(`not a NEAR amount: ${s}`);
  return nearToYocto(s as `${number}`);
}

/** yocto (bigint or decimal string) -> "1.2345" NEAR. */
export function fmtNear(yocto: bigint | string | number | null | undefined, decimals = 4): string {
  if (yocto === null || yocto === undefined) return "-";
  return yoctoToNear(BigInt(yocto), decimals);
}

export function newEd25519(): { publicKey: string; secretKey: string } {
  const kp = KeyPair.fromRandom("ed25519");
  return { publicKey: kp.getPublicKey().toString(), secretKey: kp.toString() };
}

export function publicKeyOfSecret(secretKey: string): string {
  return KeyPair.fromString(secretKey as KeyPairString).getPublicKey().toString();
}

/** Storage price per byte in yocto from the protocol config (falls back to 1e19). */
export async function storageBytePrice(provider: Provider): Promise<bigint> {
  try {
    const pc = (await provider.experimental_protocolConfig({ finality: "final" })) as unknown as {
      runtime_config?: { storage_amount_per_byte?: string };
    };
    const v = pc.runtime_config?.storage_amount_per_byte;
    if (v) return BigInt(v);
  } catch {
    // fall through
  }
  return 10n ** 19n;
}

export function describeError(err: unknown): string {
  const e = err as { message?: string; type?: string; cause?: unknown };
  let msg = e?.message ?? String(err);
  // near-api-js puts the contract panic text into the message; keep it short.
  msg = msg.replace(/\s+/g, " ").trim();
  return msg.length > 600 ? msg.slice(0, 600) + "…" : msg;
}

/** The real ChainClient of src/actions.ts: views over `provider`, calls signed with the given key. */
export function makeChainClient(provider: Provider, contractId: string): ChainClient {
  return {
    contractId,
    view: <T>(method: string, args: Record<string, unknown> = {}) => view<T>(provider, contractId, method, args),
    call: <T>(signer: { accountId: string; privateKey: string }, method: string, args: Record<string, unknown>, opts: { deposit: bigint; gas?: bigint }) =>
      call<T>(accountWithKey(provider, signer.accountId, signer.privateKey), contractId, method, args, { deposit: opts.deposit, gas: opts.gas ?? GAS.call }),
    async addFunctionCallKey(signer, key) {
      const res = await accountWithKey(provider, signer.accountId, signer.privateKey)
        .addFunctionCallAccessKey({ publicKey: key.publicKey, contractId, methodNames: key.methodNames, allowance: key.allowance });
      return res.transaction_outcome?.id ?? "?";
    },
    async accessKeyPermission(accountId, publicKey) {
      const ak = await provider.viewAccessKey({ accountId, publicKey, finalityQuery: { finality: "final" } });
      return ak.permission as unknown;
    },
    storageBytePrice: () => storageBytePrice(provider),
  };
}
