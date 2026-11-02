// Last line of defence for key isolation: every tool result and every log line passes through
// the redactor before it leaves the process. The server never puts key material into an output
// on purpose; this catches a library error message or a future bug that would.

const B58 = "[1-9A-HJ-NP-Za-km-z]";
// A NEAR private key is "ed25519:" + base58 of 64 bytes (about 87-88 chars). Public keys are
// 32 bytes (43-44 chars) and stay readable.
const PRIVATE_KEY_RE = new RegExp(`\\b(ed25519|secp256k1):${B58}{60,}`, "g");

export type Redactor = (text: string) => string;

/** secrets: exact strings that must never appear (the loaded private key, its base58 body). */
export function makeRedactor(secrets: string[] = []): Redactor {
  const literals = [...new Set(secrets.filter((s) => typeof s === "string" && s.length >= 16))].sort((a, b) => b.length - a.length);
  return (text: string) => {
    let out = text.replace(PRIVATE_KEY_RE, (_m, curve: string) => `${curve}:[redacted]`);
    for (const s of literals) if (out.includes(s)) out = out.split(s).join("[redacted]");
    return out;
  };
}

/** The forms of a "ed25519:<base58>" secret that a redactor must catch. */
export function secretForms(secretKey: string): string[] {
  const body = secretKey.includes(":") ? secretKey.slice(secretKey.indexOf(":") + 1) : secretKey;
  return [secretKey, body];
}
