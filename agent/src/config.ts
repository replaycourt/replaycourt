// Configuration: environment variables override .secrets/<network>.json in the repository
// (written by the contract deployment), full-access keys come from ~/.near-credentials/<network>/.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const AGENT_DIR = path.resolve(import.meta.dirname, "..");
export const REPO_ROOT = path.resolve(AGENT_DIR, "..");

export interface Config {
  network: string;
  contractId: string | null;
  rpcUrls: string[];
  accounts: Record<string, string>; // role -> account id (owner, verifier, hunter1, ...)
  secretsDir: string;
  credentialsDir: string;
  configFile: string | null;
  raw: Record<string, unknown>;
}

export const DEFAULT_RPC: Record<string, string[]> = {
  testnet: ["https://test.rpc.fastnear.com", "https://near-testnet.drpc.org"],
  mainnet: ["https://free.rpc.fastnear.com"],
};

/** The public showcase deployment (demo/SHOWCASE.md); read-only commands fall back to it without .secrets/. */
export const DEMO_CONTRACT: Record<string, string> = {
  testnet: "contract.replaycourt.testnet",
};

/** Pinned showcase programs per network and contract. `verify-onchain` checks only these by default:
 *  anyone can create a program on a public contract, so programs of strangers are listed as "not part
 *  of the showcase" instead of failing the run (`--all-programs` checks everything). A contract
 *  without an entry here has every program checked. Update after a redeploy. */
export const SHOWCASE_PROGRAMS: Record<string, Record<string, number[]>> = {
  testnet: {
    "contract.replaycourt.testnet": [0, 1],
  },
};

export function pinnedPrograms(network: string, contractId: string): number[] | null {
  return SHOWCASE_PROGRAMS[network]?.[contractId] ?? null;
}

/** Program allow-list of the worker: REPLAYCOURT_WORKER_PROGRAMS ("0,2") or "programs": [0, 2] in the
 *  deployment file; null if neither is set (the worker then serves every program of its verifier). */
export function workerPrograms(cfg: Pick<Config, "raw">, env: NodeJS.ProcessEnv = process.env): number[] | null {
  const parse = (items: unknown[], where: string): number[] => items.map((x) => {
    const n = typeof x === "number" ? x : typeof x === "string" && /^\s*\d+\s*$/.test(x) ? Number(x) : NaN;
    if (!Number.isSafeInteger(n) || n < 0) throw new Error(`${where}: "${String(x)}" is not a program id`);
    return n;
  });
  const fromEnv = env.REPLAYCOURT_WORKER_PROGRAMS;
  if (fromEnv !== undefined && fromEnv.trim() !== "") {
    return parse(fromEnv.split(",").filter((x) => x.trim() !== ""), "REPLAYCOURT_WORKER_PROGRAMS");
  }
  if (Array.isArray(cfg.raw.programs)) return parse(cfg.raw.programs, 'config "programs"');
  return null;
}

export const EXPLORER: Record<string, string> = {
  testnet: "https://testnet.nearblocks.io",
  mainnet: "https://nearblocks.io",
};

function readJson(file: string): Record<string, unknown> | null {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, unknown>;
  } catch {
    return null;
  }
}

const ACCOUNT_RE = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;

/** Collect role -> account id from the deployment file, whatever its exact shape. */
export function collectAccounts(raw: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  const add = (role: string, value: unknown) => {
    if (typeof value === "string" && ACCOUNT_RE.test(value) && value.length >= 2 && value.length <= 64) {
      out[role] = value;
    }
  };
  for (const [k, v] of Object.entries(raw)) {
    if (k === "contract_id" || k === "contract" || k === "network") continue;
    const m = /^(.*?)(_id|_account|_account_id)$/.exec(k);
    if (m && typeof v === "string") add(m[1], v);
    else if (typeof v === "string" && /^(owner|verifier|hunter\d*|deployer)$/.test(k)) add(k, v);
  }
  for (const key of ["accounts", "roles"]) {
    const nested = raw[key];
    if (nested && typeof nested === "object" && !Array.isArray(nested)) {
      for (const [role, v] of Object.entries(nested as Record<string, unknown>)) {
        if (typeof v === "string") add(role.replace(/(_id|_account|_account_id)$/, ""), v);
        else if (v && typeof v === "object") {
          const o = v as Record<string, unknown>;
          add(role.replace(/(_id|_account|_account_id)$/, ""), o.account_id ?? o.id ?? o.accountId);
        }
      }
    }
  }
  // "hunters": ["a.testnet", "b.testnet"] -> hunter1, hunter2
  if (Array.isArray(raw.hunters)) {
    raw.hunters.forEach((h, i) => {
      const id = typeof h === "string" ? h : (h as Record<string, unknown>)?.account_id;
      if (!out[`hunter${i + 1}`]) add(`hunter${i + 1}`, id);
    });
  }
  return out;
}

/** A relative REPLAYCOURT_CONFIG is looked up from the current directory, then from the directory
 *  npm was started in (INIT_CWD), then from the repository root, so that
 *  `REPLAYCOURT_CONFIG=.secrets/showcase.json` works from the repository root and from agent/. */
export function resolveConfigPath(file: string, env: NodeJS.ProcessEnv = process.env): string {
  if (path.isAbsolute(file)) return file;
  const candidates = [process.cwd(), env.INIT_CWD, REPO_ROOT].filter((d): d is string => Boolean(d)).map((d) => path.resolve(d, file));
  return candidates.find((c) => fs.existsSync(c)) ?? candidates[0];
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const baseSecretsDir = path.resolve(env.REPLAYCOURT_SECRETS_DIR ?? path.join(REPO_ROOT, ".secrets"));
  const network = env.REPLAYCOURT_NETWORK ?? "testnet";
  const configFile = env.REPLAYCOURT_CONFIG ? resolveConfigPath(env.REPLAYCOURT_CONFIG, env) : path.join(baseSecretsDir, `${network}.json`);
  const raw = readJson(configFile) ?? {};
  // A deployment file may name its own secrets directory ("secrets_dir", relative to the file), so
  // that several deployments keep separate verifier keys. REPLAYCOURT_SECRETS_DIR still wins.
  const secretsDir = !env.REPLAYCOURT_SECRETS_DIR && typeof raw.secrets_dir === "string" && raw.secrets_dir.trim()
    ? path.resolve(path.dirname(path.resolve(configFile)), raw.secrets_dir.trim())
    : baseSecretsDir;
  const fileNetwork = typeof raw.network === "string" ? raw.network : null;
  const net = env.REPLAYCOURT_NETWORK ?? fileNetwork ?? "testnet";
  if (net === "mainnet" && env.REPLAYCOURT_ALLOW_MAINNET !== "1") {
    throw new Error("mainnet is disabled in this demo build (set REPLAYCOURT_ALLOW_MAINNET=1 to override)");
  }
  const accounts = collectAccounts(raw);
  for (const role of ["owner", "verifier", "hunter", "hunter1", "hunter2"]) {
    const v = env[`REPLAYCOURT_${role.toUpperCase()}_ID`];
    if (v) accounts[role] = v;
  }
  const contractId =
    env.REPLAYCOURT_CONTRACT_ID ??
    (typeof raw.contract_id === "string" ? raw.contract_id : typeof raw.contract === "string" ? raw.contract : null);
  const rpcFromFile = typeof raw.rpc_url === "string" ? [raw.rpc_url] : Array.isArray(raw.rpc_urls) ? (raw.rpc_urls as string[]) : [];
  // The configured RPC first, the public defaults behind it as failover.
  const rpcUrls = env.REPLAYCOURT_RPC_URL
    ? env.REPLAYCOURT_RPC_URL.split(",").map((s) => s.trim()).filter(Boolean)
    : [...new Set([...rpcFromFile, ...(DEFAULT_RPC[net] ?? [])])];
  return {
    network: net,
    contractId,
    rpcUrls,
    accounts,
    secretsDir,
    // "credentials_dir" in the deployment file (relative to it) keeps a deployment's full-access keys
    // next to its other secrets (demo/full-testnet.sh); REPLAYCOURT_CREDENTIALS_DIR still wins.
    credentialsDir: path.resolve(env.REPLAYCOURT_CREDENTIALS_DIR ??
      (typeof raw.credentials_dir === "string" && raw.credentials_dir.trim()
        ? path.resolve(path.dirname(path.resolve(configFile)), raw.credentials_dir.trim())
        : path.join(os.homedir(), ".near-credentials", net))),
    configFile: fs.existsSync(configFile) ? configFile : null,
    raw,
  };
}

/** Resolve "owner", "hunter1", ... to an account id; account ids pass through unchanged. */
export function resolveAccount(cfg: Config, nameOrId: string | undefined, fallbackRole: string): string {
  const key = nameOrId ?? fallbackRole;
  if (cfg.accounts[key]) return cfg.accounts[key];
  if (key.includes(".") || /^[0-9a-f]{64}$/.test(key)) return key;
  throw new Error(
    `unknown account or role "${key}" (known roles: ${Object.keys(cfg.accounts).join(", ") || "none"}; ` +
      `config: ${cfg.configFile ?? "no " + path.join(cfg.secretsDir, cfg.network + ".json")})`,
  );
}

export function requireContract(cfg: Config): string {
  if (!cfg.contractId) {
    throw new Error(`no contract id: set REPLAYCOURT_CONTRACT_ID or write ${path.join(cfg.secretsDir, cfg.network + ".json")}`);
  }
  return cfg.contractId;
}

/** Private key ("ed25519:...") of a full-access key from ~/.near-credentials/<network>/<account>.json. */
export function loadFullAccessKey(cfg: Config, accountId: string): string {
  const file = path.join(cfg.credentialsDir, `${accountId}.json`);
  const data = readJson(file);
  const key = data && (data.private_key ?? data.secret_key);
  if (typeof key !== "string") throw new Error(`no credentials for ${accountId} in ${file}`);
  return key;
}

export const VERIFIER_X25519_FILE = "verifier-x25519.json";
export const VERIFIER_FC_KEY_FILE = "verifier-fc-key.json";

export function secretPath(cfg: Config, name: string): string {
  return path.join(cfg.secretsDir, name);
}

export function readSecret<T>(cfg: Config, name: string): T | null {
  return readJson(secretPath(cfg, name)) as T | null;
}

/** Write a secret file with mode 0600 inside the git-ignored secrets directory. */
export function writeSecret(cfg: Config, name: string, data: unknown, overwrite: boolean): string {
  fs.mkdirSync(cfg.secretsDir, { recursive: true, mode: 0o700 });
  const file = secretPath(cfg, name);
  if (fs.existsSync(file) && !overwrite) throw new Error(`${file} exists (use --force to replace it)`);
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\n", { mode: 0o600 });
  fs.chmodSync(file, 0o600);
  return file;
}

export function runsDir(cfg: Config, contractId: string): string {
  return path.join(REPO_ROOT, "runs", cfg.network, contractId);
}

/** Evidence that is not disclosed yet, and the worker's registry (git-ignored). */
export function privateRunsDir(cfg: Config, contractId: string): string {
  return path.join(REPO_ROOT, "runs-private", cfg.network, contractId);
}
