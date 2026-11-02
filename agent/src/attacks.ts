// Helpers for the attack demos in ../demo/attacks/ (security track). Nothing here is used by the
// hunter CLI or the worker: the demos import it so that their logic is unit-tested.

import { commitmentFor, seal } from "./seal.ts";

/** A tampered submission: the commitment is the hunter's commitment of one file, the sealed blob
 *  encrypts another. The worker must refuse it ("sealed report does not match commitment") without
 *  running it. `sealedPlaintextCommitment` is what the commitment of the sealed text would be. */
export function tamperedSubmission(committed: Uint8Array, sealedFrom: Uint8Array, verifierPubkeyB64: string, hunterId: string): {
  commitment: string;
  sealed: string;
  sealedPlaintextCommitment: string;
} {
  return {
    commitment: commitmentFor(hunterId, committed),
    sealed: seal(sealedFrom, verifierPubkeyB64),
    sealedPlaintextCommitment: commitmentFor(hunterId, sealedFrom),
  };
}

export interface TxErrorInfo {
  /** error class or RPC error name, e.g. RequiresFullAccessActionError, InvalidTxError */
  kind: string;
  /** one-line message (panic text for contract errors) */
  message: string;
  /** hash of the transaction if it was included on chain (and failed there) */
  txHash: string | null;
  /** true if the RPC refused the transaction before it was included in a block */
  rejectedBeforeInclusion: boolean;
  /** true for a transport problem (network, timeout, HTTP 5xx, all endpoints failed): the protocol
   *  has not judged the transaction, so the attempt proves nothing and should be retried */
  transport: boolean;
}

const TRANSPORT_RE = /fetch failed|ETIMEDOUT|ECONNRESET|ECONNREFUSED|ENOTFOUND|EHOSTUNREACH|EAI_AGAIN|UND_ERR|socket hang up|Internal server error|Exceeded \d+ providers|RetriesExceeded|timed? ?out|HTTP 5\d\d|\b50[234]\b/i;
const PROTOCOL_RE = /AccessKey|InvalidTx|ActionError|NotEnough|Mismatch|RequiresFullAccess|Deposit|InvalidNonce|InvalidSignature|panicked|FunctionCallError|ExecutionError/i;

const HASH_RE = /^[1-9A-HJ-NP-Za-km-z]{43,44}$/;

function findTxHash(e: Record<string, unknown>): string | null {
  for (const k of ["txHash", "transactionHash", "transaction_hash"]) {
    const v = e[k];
    if (typeof v === "string" && HASH_RE.test(v)) return v;
  }
  const ctx = e.context as Record<string, unknown> | undefined;
  if (ctx && typeof ctx.transactionHash === "string" && HASH_RE.test(ctx.transactionHash)) return ctx.transactionHash;
  return null;
}

/** Normalize an error thrown by near-api-js when a transaction is refused or fails. */
export function describeTxError(err: unknown): TxErrorInfo {
  const e = (err && typeof err === "object" ? err : { message: String(err) }) as Record<string, unknown>;
  const ctorName = (err as { constructor?: { name?: string } })?.constructor?.name;
  const kind = String(e.type ?? (ctorName && ctorName !== "Object" ? ctorName : undefined) ?? e.name ?? "Error");
  let message = String(e.message ?? err).replace(/\s+/g, " ").trim();
  if (message.length > 400) message = message.slice(0, 399) + "…";
  const txHash = findTxHash(e);
  // Contract panics and other execution failures happen after inclusion; everything an access key
  // forbids (wrong method, deposit, transfer, add key, receiver, allowance) is refused before.
  const executed = /ExecutionError|FunctionCallError|Smart contract panicked|panicked at|HostError|CodeDoesNotExist/i.test(`${kind} ${message}`);
  const transport = !PROTOCOL_RE.test(`${kind} ${message}`) && TRANSPORT_RE.test(`${kind} ${message}`);
  return { kind, message, txHash, rejectedBeforeInclusion: !executed && txHash === null && !transport, transport };
}

/** The contract's panic text from a failed execution outcome or error message, if any. */
export function panicText(text: string): string | null {
  const m = /Smart contract panicked: ([^"\n}]+)/.exec(text) ?? /panicked at [^:]*: ([^"\n}]+)/.exec(text);
  return m ? m[1].trim() : null;
}

// Re-exported for the demo scripts in ../demo/, which cannot resolve near-api-js themselves
// (it is installed in agent/node_modules).
export { Account, JsonRpcProvider, KeyPair, PublicKey, actions as nearActions } from "near-api-js";
