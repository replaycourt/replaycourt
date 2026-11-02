// Loading the hunter's key. The private key lives in a SecretKey object whose string, JSON and
// inspect forms are all "[redacted]"; only the chain adapter calls reveal() to build the signer.
// There is deliberately no environment variable that holds the key itself: MCP host configs
// (claude_desktop_config.json, .mcp.json) are plain-text files that get copied and shared.

import fs from "node:fs";
import path from "node:path";
import { inspect } from "node:util";
import { hunterKeyFile } from "../../agent/src/actions.ts";
import { loadFullAccessKey } from "../../agent/src/config.ts";
import type { Config } from "../../agent/src/config.ts";
import { publicKeyOfSecret } from "../../agent/src/near.ts";
import { displayPath } from "./paths.ts";
import { secretForms } from "./redact.ts";

const KEY_RE = /^ed25519:[1-9A-HJ-NP-Za-km-z]{60,}$/;

export class SecretKey {
  readonly #value: string;
  readonly publicKey: string;
  readonly source: string;

  constructor(value: string, source: string) {
    const v = value.trim();
    if (!KEY_RE.test(v)) throw new Error(`the key from ${source} is not an "ed25519:<base58>" private key`);
    this.#value = v;
    this.publicKey = publicKeyOfSecret(v);
    this.source = source;
  }

  reveal(): string {
    return this.#value;
  }

  /** Strings the redactor must remove if they ever show up in an output. */
  redactionForms(): string[] {
    return secretForms(this.#value);
  }

  toString(): string {
    return "[redacted]";
  }

  toJSON(): string {
    return "[redacted]";
  }

  [inspect.custom](): string {
    return `SecretKey(${this.publicKey}, [redacted])`;
  }
}

export interface KeyLoadResult {
  key: SecretKey;
  warnings: string[];
}

/** A near-cli JSON key file ({"account_id", "private_key"}, also the agent's hunter-fc-key.<account>.json
 *  with "contract_id"), or a text file holding "ed25519:...". */
function readKeyFile(file: string, what: string, hunterId: string, contractId: string | null, warnings: string[]): SecretKey {
  let text: string;
  try {
    const st = fs.statSync(file);
    if ((st.mode & 0o077) !== 0) warnings.push(`key file ${displayPath(file)} is readable by group/others; chmod 600 it`);
    text = fs.readFileSync(file, "utf8");
  } catch (e) {
    throw new Error(`cannot read ${what} ${displayPath(file)}: ${(e as NodeJS.ErrnoException).code ?? "error"}`);
  }
  let value = text.trim();
  if (value.startsWith("{")) {
    let data: Record<string, unknown>;
    try {
      data = JSON.parse(value) as Record<string, unknown>;
    } catch {
      throw new Error(`${what} ${displayPath(file)} is neither JSON nor an "ed25519:..." line`);
    }
    const accountInFile = data.account_id;
    if (typeof accountInFile === "string" && accountInFile !== hunterId) {
      throw new Error(`${what} belongs to ${accountInFile}, not to the hunter account ${hunterId}`);
    }
    const contractInFile = data.contract_id;
    if (contractId && typeof contractInFile === "string" && contractInFile !== contractId) {
      throw new Error(`${what} is a key for the contract ${contractInFile}, not for ${contractId}`);
    }
    value = String(data.private_key ?? data.secret_key ?? "");
  }
  return new SecretKey(value, displayPath(file));
}

/**
 * REPLAYCOURT_HUNTER_KEY_FILE (a near-cli JSON file with "private_key", or a text file holding
 * "ed25519:...") wins. Otherwise:
 *   direct mode: the NEAR keychain ~/.near-credentials/<network>/<account>.json (full-access key);
 *   vault mode:  the hunter's function-call key that `setup-hunter-key` (agent CLI) wrote to
 *                <secrets dir>/hunter-fc-key.<account>.json. Never the keychain: vault mode exists
 *                so that the server does not hold the full-access key.
 */
export function loadHunterKey(
  env: NodeJS.ProcessEnv,
  cfg: Config,
  hunterId: string,
  opts: { mode?: "direct" | "vault"; contractId?: string | null } = {},
): KeyLoadResult {
  const warnings: string[] = [];
  const contractId = opts.contractId ?? null;
  const file = env.REPLAYCOURT_HUNTER_KEY_FILE;
  if (file) return { key: readKeyFile(file, "REPLAYCOURT_HUNTER_KEY_FILE", hunterId, contractId, warnings), warnings };
  if (opts.mode === "vault") {
    const fcFile = path.join(cfg.secretsDir, hunterKeyFile(hunterId));
    if (!fs.existsSync(fcFile)) {
      throw new Error(`vault mode: no function-call key for ${hunterId} in ${displayPath(fcFile)}; ` +
        `create one with the agent CLI (setup-hunter-key --as ${hunterId}) or set REPLAYCOURT_HUNTER_KEY_FILE`);
    }
    return { key: readKeyFile(fcFile, "the hunter function-call key file", hunterId, contractId, warnings), warnings };
  }
  const keychainFile = `${cfg.credentialsDir}/${hunterId}.json`;
  try {
    const st = fs.statSync(keychainFile);
    if ((st.mode & 0o077) !== 0) warnings.push(`keychain file ${displayPath(keychainFile)} is readable by group/others; chmod 600 it`);
  } catch {
    // loadFullAccessKey reports the missing file
  }
  let value: string;
  try {
    value = loadFullAccessKey(cfg, hunterId);
  } catch {
    throw new Error(`no key for ${hunterId} in the NEAR keychain (${displayPath(keychainFile)}); set REPLAYCOURT_HUNTER_KEY_FILE`);
  }
  return { key: new SecretKey(value, displayPath(keychainFile)), warnings };
}
