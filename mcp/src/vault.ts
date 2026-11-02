// Vault mode (SPEC v2 "Hunter vault"): the server signs with a function-call key of the hunter
// account that may call only submit_report_from_vault, finalize and withdraw_pending. Such a key
// cannot attach a deposit, so it cannot withdraw from the vault, change the vault policy or move
// the account's NEAR. The contract enforces the vault policy on every submission; this module
// pre-checks it before signing, so a refusal costs no gas and comes back as a structured result.
//
// The rules themselves come from the agent library (agent/src/actions.ts: vaultRefusal,
// functionCallKeyProblem, HUNTER_KEY_METHODS); this file maps them to the server's output.

import { DAY_NS, functionCallKeyProblem, HUNTER_KEY_METHODS, spentNow, vaultRefusal } from "../../agent/src/actions.ts";
import type { VaultView } from "../../agent/src/actions.ts";
import { amount, formatNear, u128 } from "./amounts.ts";
import { permissionKind } from "./chain.ts";
import type { Check, Refusal } from "./policy.ts";

export type SigningMode = "direct" | "vault";

export const SIGNING_MODES: readonly SigningMode[] = ["direct", "vault"];

// ---------------------------------------------------------------------------------------------
// Startup: is the loaded key really a hunter function-call key?

export type KeyCheck =
  | { ok: true; summary: string; warning: string | null }
  | { ok: false; problem: string };

/**
 * Vault mode accepts only a function-call key of the hunter account with receiver = the contract
 * and exactly the methods HUNTER_KEY_METHODS (the worker applies the same rule to its key).
 * A full-access key is refused unless `allowFullAccess` (REPLAYCOURT_MCP_ALLOW_FULL_ACCESS=1).
 */
export function vaultKeyCheck(permission: unknown, contractId: string, hunterId: string, allowFullAccess: boolean): KeyCheck {
  const kind = permissionKind(permission);
  if (kind === "not_found") return { ok: false, problem: `the loaded key is not an access key of ${hunterId}` };
  if (kind === "FullAccess") {
    const risk = "a full-access key can withdraw the vault, change its policy, transfer the account's NEAR and add keys";
    if (!allowFullAccess) {
      return {
        ok: false,
        problem: `vault mode refuses a full-access key (${risk}). Give the server the hunter's function-call key ` +
          `(agent CLI: setup-hunter-key), or set REPLAYCOURT_MCP_ALLOW_FULL_ACCESS=1 to run with this key anyway`,
      };
    }
    return {
      ok: true,
      summary: "FullAccess (allowed by REPLAYCOURT_MCP_ALLOW_FULL_ACCESS=1)",
      warning: `vault mode is running with a FULL-ACCESS key because REPLAYCOURT_MCP_ALLOW_FULL_ACCESS=1: ${risk}. ` +
        `The server itself only calls submit_report_from_vault, finalize and withdraw_pending, but the key protects nothing`,
    };
  }
  const problem = functionCallKeyProblem(permission, contractId, HUNTER_KEY_METHODS);
  if (problem) return { ok: false, problem: `the loaded key is not a hunter function-call key: ${problem}` };
  const fc = (permission as { FunctionCall: { allowance?: unknown } }).FunctionCall;
  const allowance = u128(fc.allowance);
  return {
    ok: true,
    summary: `FunctionCall: receiver ${contractId}, methods [${HUNTER_KEY_METHODS.join(", ")}], allowance ` +
      (allowance === null ? "unlimited" : `${formatNear(allowance)} NEAR`),
    warning: null,
  };
}

/** The key's permission as shown in budget_status. */
export function describePermission(permission: unknown): Record<string, unknown> {
  const kind = permissionKind(permission);
  if (kind !== "FunctionCall") return { kind };
  const fc = (permission as { FunctionCall: { receiver_id?: unknown; method_names?: unknown; allowance?: unknown } }).FunctionCall;
  const allowance = u128(fc.allowance);
  return {
    kind,
    receiver_id: typeof fc.receiver_id === "string" ? fc.receiver_id : null,
    method_names: Array.isArray(fc.method_names) ? fc.method_names.filter((m) => typeof m === "string" && /^[a-z0-9_]{1,64}$/.test(m)) : [],
    allowance_remaining: allowance === null ? null : amount(allowance),
    note: "a function-call key cannot attach a deposit: it cannot withdraw from the vault, change the vault policy, transfer NEAR or add keys",
  };
}

// ---------------------------------------------------------------------------------------------
// The vault as the agent sees it

const iso = (ns: bigint) => new Date(Number(ns / 1_000_000n)).toISOString();

/** Program ids the vault allows; null = any program (or no vault/policy: see vaultRefusal). */
export function vaultAllowedPrograms(v: VaultView | null): number[] | null {
  if (!v || !Array.isArray(v.allowed_programs)) return null;
  return v.allowed_programs.map(Number).filter((n) => Number.isSafeInteger(n) && n >= 0);
}

/** Would the vault accept a submission to this program at all (vault, policy, allow-list)? */
export function vaultAllowsProgram(v: VaultView | null, programId: number): boolean {
  if (!v || v.policy_set !== true) return false;
  const list = vaultAllowedPrograms(v);
  return list === null || list.includes(programId);
}

export function vaultSummary(v: VaultView | null, nowNs: bigint) {
  if (!v) return { exists: false, note: "the hunter account has no vault: a full-access key must vault_deposit first" };
  const balance = u128(v.balance) ?? 0n;
  const maxSpend = u128(v.max_spend_per_day) ?? 0n;
  const windowStart = u128(v.window_start) ?? 0n;
  const spent = spentNow(v, nowNs);
  const open = windowStart > 0n && nowNs < windowStart + DAY_NS;
  return {
    exists: true,
    balance: amount(balance),
    policy_set: v.policy_set === true,
    policy:
      v.policy_set === true
        ? {
            max_bond_per_report: amount(u128(v.max_bond_per_report) ?? 0n),
            max_spend_per_day: amount(maxSpend),
            allowed_programs: vaultAllowedPrograms(v),
          }
        : null,
    spent_in_window: amount(u128(v.spent_in_window) ?? 0n),
    spent_in_current_window: amount(spent),
    remaining_in_window: v.policy_set === true ? amount(maxSpend > spent ? maxSpend - spent : 0n) : null,
    window_start: windowStart > 0n ? iso(windowStart) : null,
    window_resets_at: open ? iso(windowStart + DAY_NS) : null,
    enforced_by: "the ReplayCourt contract, on every submit_report_from_vault; only a full-access key of the hunter account can change the policy or withdraw (both need 1 yoctoNEAR)",
  };
}

// ---------------------------------------------------------------------------------------------
// Pre-check before signing

/** Rule names for vaultRefusal's reasons. The same names as the local policy where the rule is the same. */
export function vaultRule(reason: string): string {
  if (/^no vault/.test(reason)) return "vault_missing";
  if (/has no policy/.test(reason)) return "vault_policy_not_set";
  if (/not in the vault's allowed programs/.test(reason)) return "program_not_allowed";
  if (/exceeds the vault's max bond per report/.test(reason)) return "bond_above_max";
  if (/daily spending cap/.test(reason)) return "daily_spend_cap";
  if (/vault balance/.test(reason)) return "vault_balance_too_low";
  return "vault_policy";
}

/** The vault checks in the contract's order, and the refusal rule each one produces. */
const VAULT_CHECKS: [check: string, rule: string][] = [
  ["vault_exists", "vault_missing"],
  ["vault_policy_set", "vault_policy_not_set"],
  ["program_allowed", "program_not_allowed"],
  ["bond_within_max", "bond_above_max"],
  ["daily_spend_cap", "daily_spend_cap"],
  ["vault_balance", "vault_balance_too_low"],
];
const FIX = "only the hunter account's full-access key can change the vault policy or fund the vault; the agent cannot";

export type VaultDecision = { allowed: true; checks: Check[] } | { allowed: false; refusal: Refusal; checks: Check[] };

/**
 * The on-chain vault policy, checked before signing. `bond` is required_bond; `storage` the
 * storage estimate (the contract draws bond + measured storage, which the estimate covers with a
 * margin). vaultRefusal (agent library) checks the bond alone; the daily cap and the balance are
 * checked again here with the storage estimate on top, so a report the contract would refuse for
 * its size is refused here too, without gas.
 */
export function vaultDecide(v: VaultView | null, programId: number, bond: bigint, storage: bigint, nowNs: bigint): VaultDecision {
  const refuse = (refusal: Refusal): VaultDecision => {
    const at = VAULT_CHECKS.findIndex(([, rule]) => rule === refusal.rule);
    const checks: Check[] = VAULT_CHECKS.slice(0, Math.max(0, at)).map(([check]) => ({ rule: check, ok: true }));
    checks.push({ rule: refusal.rule, ok: false });
    return { allowed: false, refusal, checks };
  };
  const windowRetry = (total: bigint, maxSpend: bigint): string | null => {
    if (!v || total > maxSpend) return null;
    const start = u128(v.window_start) ?? 0n;
    return start > 0n ? iso(start + DAY_NS) : null;
  };

  const reason = vaultRefusal(v, programId, bond, nowNs);
  if (reason) {
    const rule = vaultRule(reason);
    const r: Refusal = { rule, reason: `${reason} (on-chain vault policy; ${FIX})`, retry_after: null };
    if (v && rule === "bond_above_max") {
      r.limit = amount(u128(v.max_bond_per_report) ?? 0n);
      r.requested = amount(bond);
    }
    if (v && rule === "daily_spend_cap") {
      const maxSpend = u128(v.max_spend_per_day) ?? 0n;
      r.limit = amount(maxSpend);
      r.requested = amount(bond);
      r.already_used = amount(spentNow(v, nowNs));
      r.retry_after = windowRetry(bond, maxSpend);
    }
    if (v && rule === "vault_balance_too_low") {
      r.requested = amount(bond);
      r.available = amount(u128(v.balance) ?? 0n);
    }
    return refuse(r);
  }
  const vv = v!;
  const total = bond + storage;
  const maxSpend = u128(vv.max_spend_per_day) ?? 0n;
  const spent = spentNow(vv, nowNs);
  if (spent + total > maxSpend) {
    return refuse({
      rule: "daily_spend_cap",
      reason: `bond ${formatNear(bond)} + storage estimate ${formatNear(storage)} NEAR on top of ${formatNear(spent)} NEAR spent in the vault's ` +
        `current 24 h window exceeds the vault's max_spend_per_day of ${formatNear(maxSpend)} NEAR; the contract would refuse it ` +
        `(on-chain vault policy; ${FIX}; a shorter report needs less storage)`,
      limit: amount(maxSpend),
      requested: amount(total),
      already_used: amount(spent),
      retry_after: windowRetry(total, maxSpend),
    });
  }
  const balance = u128(vv.balance) ?? 0n;
  if (total > balance) {
    return refuse({
      rule: "vault_balance_too_low",
      reason: `the vault holds ${formatNear(balance)} NEAR, less than bond ${formatNear(bond)} + storage estimate ${formatNear(storage)} NEAR (${FIX})`,
      requested: amount(total),
      available: amount(balance),
      retry_after: null,
    });
  }
  return { allowed: true, checks: VAULT_CHECKS.map(([check]) => ({ rule: check, ok: true })) };
}
