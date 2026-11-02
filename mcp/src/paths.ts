// report_path allow-listing. Without it, a prompt-injected agent could "submit" a local secret
// (a key file, ~/.ssh/...) sealed to a verifier key the attacker controls: a quiet exfiltration
// channel that looks like an ordinary bounty report. Rules:
//   - the path must lie inside one of the allow-listed directories, both as written and after
//     resolving symlinks (realpath), so neither "../" nor a symlink can leave the directory;
//   - no path component may start with "." (.env, .git/, .secrets/ ...);
//   - only .md, .markdown and .txt files, regular files only, at most maxBytes.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const REPORT_EXTENSIONS = [".md", ".markdown", ".txt"];

export type PathResult =
  | { ok: true; realPath: string; bytes: Buffer }
  | { ok: false; rule: string; reason: string };

/** Resolve allow-listed directories once at startup: they must exist and be directories. */
export function resolveAllowedDirs(dirs: string[]): string[] {
  const out: string[] = [];
  for (const d of dirs.map((s) => s.trim()).filter(Boolean)) {
    const real = fs.realpathSync(path.resolve(expandHome(d)));
    if (!fs.statSync(real).isDirectory()) throw new Error(`report directory is not a directory: ${displayPath(real)}`);
    out.push(real);
  }
  return [...new Set(out)];
}

export function expandHome(p: string): string {
  return p === "~" || p.startsWith("~/") ? path.join(os.homedir(), p.slice(1)) : p;
}

/** Paths as shown to the agent and in logs: the home directory becomes "~". */
export function displayPath(p: string): string {
  const home = os.homedir();
  return p === home || p.startsWith(home + path.sep) ? "~" + p.slice(home.length) : p;
}

function inside(dir: string, p: string): boolean {
  const rel = path.relative(dir, p);
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

function hiddenComponent(dir: string, p: string): boolean {
  return path.relative(dir, p).split(path.sep).some((c) => c.startsWith("."));
}

export function readAllowedReport(input: string, allowedDirs: string[], maxBytes: number): PathResult {
  const notAllowed = (why: string): PathResult => ({
    ok: false,
    rule: "path_not_allowed",
    reason: `report_path ${JSON.stringify(displayPath(input))} is refused: ${why}. ` +
      (allowedDirs.length
        ? `Allowed report directories: ${allowedDirs.map(displayPath).join(", ")} (relative paths are resolved against the first one).`
        : `This server has no report directory configured (REPLAYCOURT_MCP_REPORT_DIRS); pass the report as report_markdown instead.`),
  });
  if (!allowedDirs.length) return notAllowed("report_path is disabled");
  if (typeof input !== "string" || !input.trim() || input.includes("\0")) return notAllowed("empty or malformed path");

  let lexical = path.resolve(allowedDirs[0], expandHome(input.trim()));
  // The allowed directories are stored as real paths. Anchor the parent the same way, so an
  // absolute path through a symlinked prefix (macOS: /var -> /private/var) is compared like
  // for like. The final realpath check below stays the authority.
  try {
    lexical = path.join(fs.realpathSync(path.dirname(lexical)), path.basename(lexical));
  } catch {
    // parent does not exist: keep the lexical path; the realpath check reports it missing
  }
  const lexDir = allowedDirs.find((d) => inside(d, lexical));
  if (!lexDir) return notAllowed("it is outside the allow-listed report directories");
  if (hiddenComponent(lexDir, lexical)) return notAllowed("hidden files and directories (starting with '.') are not allowed");
  if (!REPORT_EXTENSIONS.includes(path.extname(lexical).toLowerCase())) {
    return notAllowed(`only ${REPORT_EXTENSIONS.join(", ")} files are allowed`);
  }

  let real: string;
  try {
    real = fs.realpathSync(lexical);
  } catch {
    return { ok: false, rule: "report_not_found", reason: `report_path ${JSON.stringify(displayPath(input))} does not exist` };
  }
  const realDir = allowedDirs.find((d) => inside(d, real));
  if (!realDir) return notAllowed("it resolves (through a symlink) to a file outside the allow-listed report directories");
  if (hiddenComponent(realDir, real)) return notAllowed("it resolves to a hidden file or directory");
  if (!REPORT_EXTENSIONS.includes(path.extname(real).toLowerCase())) {
    return notAllowed(`it resolves to a file that is not ${REPORT_EXTENSIONS.join(", ")}`);
  }

  let st: fs.Stats;
  try {
    st = fs.statSync(real);
  } catch {
    return { ok: false, rule: "report_not_found", reason: `report_path ${JSON.stringify(displayPath(input))} cannot be read` };
  }
  if (!st.isFile()) return notAllowed("it is not a regular file");
  if (st.size > maxBytes) {
    return { ok: false, rule: "report_too_large", reason: `the report has ${st.size} bytes; the limit is ${maxBytes} bytes` };
  }
  return { ok: true, realPath: real, bytes: fs.readFileSync(real) };
}
