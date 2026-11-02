// Spending policy: a JSON file read once at startup, then a pure decision function that every
// spending tool calls BEFORE anything is signed. Unknown fields are an error (a typo such as
// "max_bond" must not silently switch a limit off), and every limit is required.

import fs from "node:fs";
import { amount, formatNear, parseNear } from "./amounts.ts";
import type { Amount } from "./amounts.ts";

export const HOUR_MS = 60 * 60 * 1000;
export const DAY_MS = 24 * HOUR_MS;

export interface Policy {
  /** Optional pins: the server refuses to start if its config points elsewhere. */
  network: string | null;
  contractId: string | null;
  allowedProgramIds: number[];
  maxBondPerReport: bigint;
  /** bond + storage attached to one submit_report; null = only the bond limit applies. */
  maxDepositPerReport: bigint | null;
  maxDeposit24h: bigint;
  maxDepositLifetime: bigint;
  minAccountBalance: bigint;
  maxReportsPerHour: number;
}

export class PolicyError extends Error {}

const FIELDS: Record<string, true> = {
  version: true,
  network: true,
  contract_id: true,
  allowed_program_ids: true,
  max_bond_per_report_near: true,
  max_deposit_per_report_near: true,
  max_total_deposit_24h_near: true,
  max_total_deposit_lifetime_near: true,
  min_account_balance_near: true,
  max_reports_per_hour: true,
};

const REQUIRED = [
  "version",
  "allowed_program_ids",
  "max_bond_per_report_near",
  "max_total_deposit_24h_near",
  "max_total_deposit_lifetime_near",
  "min_account_balance_near",
  "max_reports_per_hour",
];

/** Parse and validate a policy object. Collects every problem and throws them together. */
export function parsePolicy(raw: unknown): Policy {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new PolicyError("policy must be a JSON object");
  const o = raw as Record<string, unknown>;
  const problems: string[] = [];
  for (const k of Object.keys(o)) {
    // "_comment" / "$schema" style keys are allowed for documentation.
    if (!FIELDS[k] && !k.startsWith("_") && !k.startsWith("$")) problems.push(`unknown field "${k}"`);
  }
  for (const k of REQUIRED) if (!(k in o)) problems.push(`missing field "${k}"`);
  if ("version" in o && o.version !== 1) problems.push(`"version" must be 1`);

  const near = (k: string): bigint => {
    try {
      return parseNear(o[k], `"${k}"`);
    } catch (e) {
      problems.push((e as Error).message);
      return 0n;
    }
  };

  let allowed: number[] = [];
  const ids = o.allowed_program_ids;
  if ("allowed_program_ids" in o) {
    if (!Array.isArray(ids) || ids.some((x) => !Number.isSafeInteger(x) || (x as number) < 0)) {
      problems.push(`"allowed_program_ids" must be an array of non-negative integers (an explicit list; there is no wildcard)`);
    } else {
      allowed = [...new Set(ids as number[])].sort((a, b) => a - b);
    }
  }
  const perHour = o.max_reports_per_hour;
  if ("max_reports_per_hour" in o && (!Number.isSafeInteger(perHour) || (perHour as number) < 0 || (perHour as number) > 1000)) {
    problems.push(`"max_reports_per_hour" must be an integer 0..1000`);
  }
  const str = (k: string): string | null => {
    if (!(k in o)) return null;
    if (typeof o[k] !== "string" || !(o[k] as string)) {
      problems.push(`"${k}" must be a non-empty string`);
      return null;
    }
    return o[k] as string;
  };

  const policy: Policy = {
    network: str("network"),
    contractId: str("contract_id"),
    allowedProgramIds: allowed,
    maxBondPerReport: "max_bond_per_report_near" in o ? near("max_bond_per_report_near") : 0n,
    maxDepositPerReport: "max_deposit_per_report_near" in o ? near("max_deposit_per_report_near") : null,
    maxDeposit24h: "max_total_deposit_24h_near" in o ? near("max_total_deposit_24h_near") : 0n,
    maxDepositLifetime: "max_total_deposit_lifetime_near" in o ? near("max_total_deposit_lifetime_near") : 0n,
    minAccountBalance: "min_account_balance_near" in o ? near("min_account_balance_near") : 0n,
    maxReportsPerHour: Number.isSafeInteger(perHour) ? (perHour as number) : 0,
  };
  if (policy.maxDeposit24h > policy.maxDepositLifetime) {
    problems.push(`"max_total_deposit_24h_near" is larger than "max_total_deposit_lifetime_near"`);
  }
  if (problems.length) throw new PolicyError(`invalid policy: ${problems.join("; ")}`);
  return policy;
}

export function loadPolicy(file: string | undefined): Policy {
  if (!file) throw new PolicyError("REPLAYCOURT_MCP_POLICY is not set: the server does not start without a spending policy");
  let text: string;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch (e) {
    throw new PolicyError(`cannot read policy file: ${(e as NodeJS.ErrnoException).code ?? (e as Error).message}`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    throw new PolicyError(`policy file is not valid JSON: ${(e as Error).message}`);
  }
  return parsePolicy(raw);
}

/** Policy as it is shown to the agent (amounts in NEAR and yocto). */
export function describePolicy(p: Policy) {
  return {
    allowed_program_ids: p.allowedProgramIds,
    max_bond_per_report: amount(p.maxBondPerReport),
    max_deposit_per_report: p.maxDepositPerReport === null ? null : amount(p.maxDepositPerReport),
    max_total_deposit_24h: amount(p.maxDeposit24h),
    max_total_deposit_lifetime: amount(p.maxDepositLifetime),
    min_account_balance: amount(p.minAccountBalance),
    max_reports_per_hour: p.maxReportsPerHour,
  };
}

// ---------------------------------------------------------------------------------------------
// Decisions

export type SpendOp = "submit_report" | "finalize" | "withdraw_pending";

export interface SpendRequest {
  op: SpendOp;
  programId: number;
  /** Bond part of the deposit (0 for gas-only calls). */
  bond: bigint;
  /** Everything the report costs (bond + storage; 0 for gas-only calls): attached to the
   *  transaction, or in vault mode drawn from the on-chain vault. Counts against the caps. */
  deposit: bigint;
  /** Vault mode: the deposit is drawn from the hunter's vault inside the contract, not from the
   *  account, so the minimum-balance rule only keeps the gas reserve free. */
  fromVault?: boolean;
  /** Worst-case gas cost of the transaction, kept free on top of the minimum balance. */
  gasReserve: bigint;
}

/** What the ledger says has already happened (see ledger.ts for what counts). */
export interface SpendHistory {
  /** Deposits that count against the limits, with their time (ms since epoch). */
  deposits: { at: number; amount: bigint }[];
  /** Times of submit_report signing attempts (ms since epoch). */
  reportAttempts: number[];
}

export interface Refusal {
  rule: string;
  reason: string;
  limit?: Amount | number;
  requested?: Amount | number;
  already_used?: Amount | number;
  available?: Amount;
  /** ISO time when the same request would pass this rule again; null = never under this policy. */
  retry_after?: string | null;
}

export interface Check {
  rule: string;
  ok: boolean;
}

export type Decision = { allowed: true; checks: Check[] } | { allowed: false; refusal: Refusal; checks: Check[] };

export function sumDeposits(h: SpendHistory, since: number): bigint {
  let s = 0n;
  for (const d of h.deposits) if (d.at > since) s += d.amount;
  return s;
}

/**
 * Earliest time at which `extra` more fits under `cap` in a rolling window of `windowMs`,
 * given the deposits so far. null if it never fits (extra alone exceeds the cap).
 */
function windowRetryAfter(h: SpendHistory, now: number, windowMs: number, cap: bigint, extra: bigint): number | null {
  if (extra > cap) return null;
  const inWindow = h.deposits.filter((d) => d.at > now - windowMs).sort((a, b) => a.at - b.at);
  let total = inWindow.reduce((s, d) => s + d.amount, 0n);
  for (const d of inWindow) {
    if (total + extra <= cap) break;
    total -= d.amount;
    if (total + extra <= cap) return d.at + windowMs;
  }
  return now;
}

const iso = (ms: number) => new Date(ms).toISOString();

/** The allow-list rule on its own (also used before anything is fetched from the chain). */
export function programRefusal(p: Policy, programId: number): Refusal | null {
  if (p.allowedProgramIds.includes(programId)) return null;
  return {
    rule: "program_not_allowed",
    reason: `program ${programId} is not in the policy's allowed_program_ids [${p.allowedProgramIds.join(", ")}]; ` +
      `only the human who runs this server can add programs`,
    retry_after: null,
  };
}

/**
 * The policy decision. Pure: the caller passes the ledger history, the current time and the
 * account's available balance (null when it could not be read: that refuses, fail closed).
 */
export function decide(p: Policy, req: SpendRequest, h: SpendHistory, availableBalance: bigint | null, now: number): Decision {
  const checks: Check[] = [];
  const what = req.fromVault ? "vault draw (bond + storage)" : "deposit";
  const refuse = (refusal: Refusal): Decision => {
    checks.push({ rule: refusal.rule, ok: false });
    return { allowed: false, refusal, checks };
  };
  const pass = (rule: string) => checks.push({ rule, ok: true });

  const notAllowed = programRefusal(p, req.programId);
  if (notAllowed) return refuse(notAllowed);
  pass("program_allowed");

  if (req.op === "submit_report") {
    if (req.bond > p.maxBondPerReport) {
      return refuse({
        rule: "bond_above_max",
        reason: `the required bond ${formatNear(req.bond)} NEAR is above the policy's max_bond_per_report ${formatNear(p.maxBondPerReport)} NEAR`,
        limit: amount(p.maxBondPerReport),
        requested: amount(req.bond),
        retry_after: null,
      });
    }
    pass("bond_within_max");

    if (p.maxDepositPerReport !== null && req.deposit > p.maxDepositPerReport) {
      return refuse({
        rule: "deposit_above_max_per_report",
        reason: `bond + storage ${formatNear(req.deposit)} NEAR is above the policy's max_deposit_per_report ${formatNear(p.maxDepositPerReport)} NEAR ` +
          `(a shorter report needs less storage)`,
        limit: amount(p.maxDepositPerReport),
        requested: amount(req.deposit),
        retry_after: null,
      });
    }
    pass("deposit_within_max_per_report");

    const recent = h.reportAttempts.filter((t) => t > now - HOUR_MS).sort((a, b) => a - b);
    if (recent.length >= p.maxReportsPerHour) {
      const oldest = recent[recent.length - p.maxReportsPerHour];
      return refuse({
        rule: "hourly_report_limit",
        reason: `${recent.length} report(s) were signed in the last hour; the policy allows ${p.maxReportsPerHour} per hour`,
        limit: p.maxReportsPerHour,
        already_used: recent.length,
        retry_after: p.maxReportsPerHour === 0 || oldest === undefined ? null : iso(oldest + HOUR_MS),
      });
    }
    pass("hourly_report_limit");

    const used24h = sumDeposits(h, now - DAY_MS);
    if (used24h + req.deposit > p.maxDeposit24h) {
      const at = windowRetryAfter(h, now, DAY_MS, p.maxDeposit24h, req.deposit);
      return refuse({
        rule: "daily_deposit_cap",
        reason: `this ${what} of ${formatNear(req.deposit)} NEAR on top of ${formatNear(used24h)} NEAR in the last 24 h ` +
          `exceeds the policy's max_total_deposit_24h of ${formatNear(p.maxDeposit24h)} NEAR`,
        limit: amount(p.maxDeposit24h),
        requested: amount(req.deposit),
        already_used: amount(used24h),
        retry_after: at === null ? null : iso(at),
      });
    }
    pass("daily_deposit_cap");

    const usedLifetime = sumDeposits(h, -Infinity);
    if (usedLifetime + req.deposit > p.maxDepositLifetime) {
      return refuse({
        rule: "lifetime_deposit_cap",
        reason: `this ${what} of ${formatNear(req.deposit)} NEAR on top of ${formatNear(usedLifetime)} NEAR already spent ` +
          `exceeds the policy's max_total_deposit_lifetime of ${formatNear(p.maxDepositLifetime)} NEAR`,
        limit: amount(p.maxDepositLifetime),
        requested: amount(req.deposit),
        already_used: amount(usedLifetime),
        retry_after: null,
      });
    }
    pass("lifetime_deposit_cap");
  }

  if (availableBalance === null) {
    return refuse({
      rule: "balance_unknown",
      reason: "the hunter account's balance could not be read, so the minimum-balance rule cannot be checked (fail closed); try again later",
    });
  }
  const fromAccount = req.fromVault ? 0n : req.deposit;
  const after = availableBalance - fromAccount - req.gasReserve;
  if (after < p.minAccountBalance) {
    return refuse({
      rule: "min_balance",
      reason: `after this transaction the account would hold about ${formatNear(after)} NEAR available ` +
        `(${formatNear(availableBalance)} - deposit ${formatNear(fromAccount)} - gas reserve ${formatNear(req.gasReserve)}), ` +
        `below the policy's min_account_balance of ${formatNear(p.minAccountBalance)} NEAR`,
      limit: amount(p.minAccountBalance),
      requested: amount(fromAccount + req.gasReserve),
      available: amount(availableBalance),
      retry_after: null,
    });
  }
  pass("min_balance");
  return { allowed: true, checks };
}
