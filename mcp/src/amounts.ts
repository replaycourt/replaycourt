// Exact yoctoNEAR <-> NEAR conversions. Budgets are compared in yocto (bigint), never in floats.

export const YOCTO_PER_NEAR = 10n ** 24n;

/** "0.15" -> 150000000000000000000000n. Throws on anything that is not a plain non-negative decimal. */
export function parseNear(value: unknown, what: string): bigint {
  const s = typeof value === "number" ? String(value) : value;
  if (typeof s !== "string" || !/^\d{1,12}(\.\d{1,24})?$/.test(s.trim())) {
    throw new Error(`${what} must be a NEAR amount as a decimal string such as "0.25", got ${JSON.stringify(value)}`);
  }
  const [whole, frac = ""] = s.trim().split(".");
  return BigInt(whole) * YOCTO_PER_NEAR + BigInt(frac.padEnd(24, "0"));
}

/** Exact decimal NEAR string without trailing zeros: 150000000000000000000000n -> "0.15". */
export function formatNear(yocto: bigint): string {
  const neg = yocto < 0n;
  const a = neg ? -yocto : yocto;
  const whole = a / YOCTO_PER_NEAR;
  const frac = (a % YOCTO_PER_NEAR).toString().padStart(24, "0").replace(/0+$/, "");
  return `${neg ? "-" : ""}${whole}${frac ? "." + frac : ""}`;
}

/** The shape every amount takes in tool output: exact NEAR for reading, yocto for arithmetic. */
export interface Amount {
  near: string;
  yocto: string;
}

export function amount(yocto: bigint): Amount {
  return { near: formatNear(yocto), yocto: yocto.toString() };
}

/** U128 JSON string from the contract -> bigint; anything malformed -> null (never trusted blindly). */
export function u128(value: unknown): bigint | null {
  if (typeof value === "string" && /^\d{1,39}$/.test(value)) return BigInt(value);
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  return null;
}

export const max = (a: bigint, b: bigint) => (a > b ? a : b);
