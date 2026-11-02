// The only place that talks to NEAR. Tools see the Chain interface (so tests can mock it);
// the NEAR implementation reuses the agent's helpers (../agent/src) and keeps the key in a
// closure: no method returns it.

import type { VaultView } from "../../agent/src/actions.ts";
import { accountWithKey, call, GAS, makeProvider, storageBytePrice, view } from "../../agent/src/near.ts";
import type { Config } from "../../agent/src/config.ts";
import type { SecretKey } from "./keys.ts";
import type { OutcomeStatus } from "./ledger.ts";

export type RawView = Record<string, unknown>;

export interface TxResult<T> {
  result: T;
  txHash: string;
}

export interface SubmitArgs {
  program_id: number;
  title: string;
  commitment: string;
  sealed: string;
}

export type KeyPermission = "FullAccess" | "FunctionCall" | "not_found" | "unknown";

/** The kind of a raw on-chain permission (near-api-js viewAccessKey().permission; null = no such key). */
export function permissionKind(permission: unknown): KeyPermission {
  if (permission === null) return "not_found";
  if (permission === "FullAccess") return "FullAccess";
  if (permission && typeof permission === "object" && "FunctionCall" in permission) return "FunctionCall";
  return "unknown";
}

export interface Chain {
  listPrograms(fromIndex: number, limit: number): Promise<RawView[]>;
  getProgram(programId: number): Promise<RawView | null>;
  listSubmissions(programId: number, fromIndex: number, limit: number): Promise<RawView[]>;
  getSubmission(submissionId: number): Promise<RawView | null>;
  requiredBond(programId: number, hunterId: string): Promise<bigint>;
  getHunter(hunterId: string): Promise<RawView>;
  /** The hunter's stats in one program (v2): the bond depends on these, not on the global stats. */
  getHunterInProgram(programId: number, hunterId: string): Promise<RawView>;
  /** The hunter vault (SPEC v2 "Hunter vault"); null if the account has none. */
  getVault(accountId: string): Promise<VaultView | null>;
  /** Balance the account can spend (total minus storage-locked and staked). */
  availableBalance(accountId: string): Promise<bigint>;
  storageBytePrice(): Promise<bigint>;
  submitReport(args: SubmitArgs, deposit: bigint): Promise<TxResult<number>>;
  /** submit_report_from_vault: no deposit; the contract draws bond + storage from the vault. */
  submitReportFromVault(args: SubmitArgs): Promise<TxResult<number>>;
  finalize(submissionId: number): Promise<TxResult<unknown>>;
  withdrawPending(submissionId: number): Promise<TxResult<unknown>>;
  /** Raw on-chain permission of the loaded key on the hunter account ("FullAccess" or
   *  {FunctionCall: {receiver_id, method_names, allowance}}); null if the key is not on the account.
   *  Throws if the RPC cannot answer. */
  accessKeyPermission(): Promise<unknown>;
}

/** Worst-case cost of the 100 TGas the server attaches (gas price floor 1e8 yocto/gas, x2 margin). */
export const GAS_RESERVE = 2n * 10n ** 22n;

export function makeNearChain(cfg: Config, contractId: string, hunterId: string, key: SecretKey): Chain {
  const provider = makeProvider(cfg);
  let account: ReturnType<typeof accountWithKey> | null = null;
  const signer = () => (account ??= accountWithKey(provider, hunterId, key.reveal()));
  const v = <T>(method: string, args: Record<string, unknown>) => view<T>(provider, contractId, method, args);

  return {
    listPrograms: (fromIndex, limit) => v<RawView[]>("list_programs", { from_index: fromIndex, limit }),
    getProgram: (programId) => v<RawView | null>("get_program", { program_id: programId }),
    listSubmissions: (programId, fromIndex, limit) =>
      v<RawView[]>("list_submissions", { program_id: programId, from_index: fromIndex, limit }),
    getSubmission: (submissionId) => v<RawView | null>("get_submission", { submission_id: submissionId }),
    requiredBond: async (programId, hunter) => BigInt(await v<string>("required_bond", { program_id: programId, hunter_id: hunter })),
    getHunter: (hunter) => v<RawView>("get_hunter", { account_id: hunter }),
    getHunterInProgram: (programId, hunter) => v<RawView>("get_hunter_in_program", { program_id: programId, account_id: hunter }),
    getVault: (accountId) => v<VaultView | null>("get_vault", { account_id: accountId }),
    async availableBalance(accountId) {
      const a = await provider.viewAccount({ accountId, blockQuery: { finality: "final" } });
      // Same rule as near-api-js Account.getState(): storage is locked for the account's state.
      const perByte = await storageBytePrice(provider);
      const locked = a.locked > BigInt(a.storage_usage) * perByte ? a.locked : BigInt(a.storage_usage) * perByte;
      const avail = a.amount + a.locked - locked;
      return avail > 0n ? avail : 0n;
    },
    storageBytePrice: () => storageBytePrice(provider),
    async submitReport(args, deposit) {
      return call<number>(signer(), contractId, "submit_report", { ...args }, { deposit, gas: GAS.call });
    },
    async submitReportFromVault(args) {
      return call<number>(signer(), contractId, "submit_report_from_vault", { ...args }, { deposit: 0n, gas: GAS.call });
    },
    async finalize(submissionId) {
      return call<unknown>(signer(), contractId, "finalize", { submission_id: submissionId }, { deposit: 0n, gas: GAS.call });
    },
    async withdrawPending(submissionId) {
      return call<unknown>(signer(), contractId, "withdraw_pending", { submission_id: submissionId }, { deposit: 0n, gas: GAS.call });
    },
    async accessKeyPermission() {
      try {
        const k = await provider.viewAccessKey({ accountId: hunterId, publicKey: key.publicKey, finalityQuery: { finality: "final" } });
        return k.permission as unknown;
      } catch (e) {
        if (/does not exist|AccessKeyDoesNotExist|UNKNOWN_ACCESS_KEY/i.test(String((e as Error)?.message ?? e))) return null;
        throw e;
      }
    },
  };
}

/**
 * What happened to a transaction that threw. Decides whether its deposit still counts:
 *   failed_onchain: the transaction executed and failed (contract panic): the protocol refunds the
 *                   attached deposit of a failed function call;
 *   not_executed:   rejected before execution (invalid nonce, not enough balance, bad key);
 *   unknown:        timeout or network error: it may have gone through; the deposit counts.
 */
export function classifyTxError(err: unknown): { status: OutcomeStatus; txHash: string | null } {
  const e = (err ?? {}) as {
    txHash?: unknown;
    transactionResult?: { transaction_outcome?: { id?: unknown } };
    name?: unknown;
    message?: unknown;
  };
  const hash =
    typeof e.txHash === "string" ? e.txHash
    : typeof e.transactionResult?.transaction_outcome?.id === "string" ? e.transactionResult.transaction_outcome.id
    : null;
  if (hash) return { status: "failed_onchain", txHash: hash };
  const text = `${String(e.name ?? "")} ${String(e.message ?? "")}`;
  // A function-call key's limits (allowance, receiver, methods, no deposit) are checked by the
  // protocol before execution, like a bad nonce or signature.
  if (/InvalidTransaction|InvalidTxError|InvalidNonce|NotEnoughBalance|LackBalanceForState|Expired|AccessKeyDoesNotExist|InvalidSignature|InvalidAccessKey|NotEnoughAllowance|MethodNameMismatch|ReceiverMismatch|DepositWithFunctionCall|RequiresFullAccess/i.test(text)) {
    return { status: "not_executed", txHash: null };
  }
  return { status: "unknown", txHash: null };
}
