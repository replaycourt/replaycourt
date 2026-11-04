// Pure helpers without DOM access (also loaded by web/test/*.test.mjs under Node): HTML escaping via
// the html`` tag, formatting, sha256, evidence URLs, the v1/v2 evidence check, a minimal safe Markdown renderer.

const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" };

/** Escape text for HTML element content and quoted attribute values. */
export function esc(value) {
  return String(value).replace(/[&<>"'`]/g, (c) => ESC[c]);
}

/** Markup produced by html`` or renderMarkdown(); every other value is escaped when interpolated. */
class Html {
  constructor(s) {
    this.s = s;
  }
  toString() {
    return this.s;
  }
}

function piece(v) {
  if (v instanceof Html) return v.s;
  if (Array.isArray(v)) return v.map(piece).join("");
  if (v === null || v === undefined || v === false) return "";
  return esc(v);
}

/** Tagged template: interpolated values are HTML-escaped unless they are Html themselves. */
export function html(strings, ...values) {
  let out = strings[0];
  for (let i = 0; i < values.length; i++) out += piece(values[i]) + strings[i + 1];
  return new Html(out);
}

export function isHtml(v) {
  return v instanceof Html;
}

// ---------------------------------------------------------------- formatting

const YOCTO = 10n ** 24n;

/** yoctoNEAR (decimal string) -> "1.5126" (truncated to `decimals`). */
export function fmtNear(yocto, decimals = 4) {
  if (yocto === null || yocto === undefined || yocto === "") return "–";
  let v;
  try {
    v = BigInt(yocto);
  } catch {
    return "?";
  }
  const neg = v < 0n;
  if (neg) v = -v;
  const whole = v / YOCTO;
  const frac = (v % YOCTO).toString().padStart(24, "0").slice(0, decimals).replace(/0+$/, "");
  if (whole === 0n && !frac && v > 0n) return `${neg ? "-" : ""}<0.${"0".repeat(decimals - 1)}1`;
  return `${neg ? "-" : ""}${whole}${frac ? "." + frac : ""}`;
}

/** Nanosecond timestamp (string) -> "2026-11-02 09:37:52 UTC". */
export function fmtTime(ns) {
  if (ns === null || ns === undefined || ns === "") return "–";
  try {
    const d = new Date(Number(BigInt(ns) / 1000000n));
    if (Number.isNaN(d.getTime())) return "?";
    return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
  } catch {
    return "?";
  }
}

/** Seconds -> "60 s", "1 h", "1 d", "7 d 2 h". */
export function fmtDuration(sec) {
  const s = Number(sec);
  if (!Number.isFinite(s) || s < 0) return "?";
  if (s < 120) return `${s} s`;
  if (s < 7200) return `${Math.round(s / 60)} min`;
  const d = Math.floor(s / 86400);
  const h = Math.round((s % 86400) / 3600);
  if (d === 0) return `${h} h`;
  return h ? `${d} d ${h} h` : `${d} d`;
}

export function fmtInt(n) {
  const v = Number(n);
  return Number.isFinite(v) ? v.toLocaleString("en-US") : "?";
}

const CHAINS = { 0: "local (no fork)", 1: "Ethereum", 10: "Optimism", 56: "BNB Chain", 137: "Polygon", 8453: "Base", 42161: "Arbitrum One" };
export function chainName(id) {
  return Object.hasOwn(CHAINS, id) ? CHAINS[id] : `chain ${id}`;
}

// ---------------------------------------------------------------- hashing and URLs

export async function sha256Hex(bytes) {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

// One path segment below runs/: account ids, ids and file names. No "." / ".." / hidden names, no
// "%" (a URL parser reads "%2e%2e" as ".."), no "?", "#", "\", spaces or control characters.
const RUNS_SEGMENT = /^[A-Za-z0-9_][A-Za-z0-9._-]*$/;

/**
 * The URL to fetch an on-chain evidence_uri from. Only a relative path below runs/ is accepted
 * (SPEC v2 "Evidence": a checker accepts only evidence URIs below runs/), resolved against `base`
 * (itself relative to `pageUrl`). Absolute paths, URLs of any scheme, ".." and anything that would
 * leave <base>/runs/ are refused (null).
 */
export function evidenceUrl(uri, base, pageUrl) {
  if (typeof uri !== "string" || uri === "" || new TextEncoder().encode(uri).length > 256) return null;
  const segs = uri.split("/");
  if (segs.length < 2 || segs[0] !== "runs" || !segs.slice(1).every((s) => RUNS_SEGMENT.test(s))) return null;
  try {
    const root = new URL("runs/", new URL(base, pageUrl));
    if (root.protocol !== "https:" && root.protocol !== "http:") return null;
    const url = new URL(uri, new URL(base, pageUrl));
    if (url.search || url.hash || !url.href.startsWith(root.href) || url.href === root.href) return null;
    return url;
  } catch {
    return null;
  }
}

/** A file next to the evidence file (.../evidence.json of v2 or .../verdict.json of v1); null otherwise. */
export function siblingUrl(evidenceFileUrl, name) {
  if (!evidenceFileUrl || !/\/(evidence|verdict)\.json$/.test(evidenceFileUrl.pathname)) return null;
  return new URL(name, evidenceFileUrl);
}

// ---------------------------------------------------------------- protocol v1 / v2

/** Protocol major version from version(): "1.0.1" -> 1, "2.0.0" -> 2. Unknown -> 2, the strict rule
 *  (as `verify-onchain`): v1 evidence without an envelope is accepted only from a v1 contract. */
export function protocolMajor(version) {
  const m = /^(\d+)\.\d+\.\d+$/.exec(String(version ?? "").trim());
  return m ? Number(m[1]) : 2;
}

/** Statuses after which nothing changes any more (SPEC v2 "Types"). */
export const FINAL_STATUSES = ["paid", "invalid", "duplicate", "rejected", "expired", "withdrawn"];
export function isFinal(status) {
  return typeof status === "string" && FINAL_STATUSES.includes(status);
}

const MEANING = {
  pending: "Waiting for a verdict. The contract holds the hunter's deposit.",
  valid: "The replay confirmed the exploit. After the challenge window anyone can trigger the payment. If the owner objects first, the owner must decide.",
  paid: "Accepted. The hunter was paid and got the deposit back.",
  invalid: "Rejected. The hunter lost the deposit.",
  duplicate: "Judged a duplicate of an earlier report. The hunter got the deposit back, minus a fee.",
  needs_human: "The replay cannot decide this alone, so the program owner must decide before a deadline.",
  disputed: "The program owner objected and must decide before a deadline. If not, the hunter is paid and gets the owner's deposit too.",
  expired: "Nobody decided in time. The hunter got the deposit back.",
  withdrawn: "No verdict came in time. The hunter ended the report and got the deposit back.",
};

/** One sentence for a visitor who does not know the protocol: what this submission's status means. */
export function statusMeaning(s) {
  const status = s?.status;
  if (status === "rejected") {
    // dispute_reason, not the bond: a program may have a dispute bond of zero
    const disputed = typeof s.dispute_reason === "string";
    return disputed
      ? "The program owner overruled the verifier. The hunter got the deposit back plus the owner's deposit, but no payout."
      : "The replay could not decide, and the program owner rejected the report. The hunter lost the deposit.";
  }
  return typeof status === "string" && Object.hasOwn(MEANING, status) ? MEANING[status] : "";
}

const COMMIT_DOMAIN = "replaycourt/commit/v2";

/** The commitment of a report: v2 sha256("replaycourt/commit/v2" || 0x00 || hunter || 0x00 || report),
 *  bound to the submitting account; v1 sha256(report). */
export async function commitmentOf(reportBytes, hunterId, major) {
  const report = new Uint8Array(reportBytes);
  if (major < 2) return sha256Hex(report);
  const head = new TextEncoder().encode(`${COMMIT_DOMAIN}\u0000${hunterId}\u0000`);
  const all = new Uint8Array(head.length + report.length);
  all.set(head);
  all.set(report, head.length);
  return sha256Hex(all);
}

// ---------------------------------------------------------------- evidence check (SPEC v2 "Evidence")

export const EVIDENCE_SCHEMA = "replaycourt.evidence/v1";
export const BINDING_FIELDS = ["network", "contract_id", "program_id", "submission_id", "hunter_id", "commitment"];
const ENGINE_SCHEMA = "replaycourt.verdict/v1";

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const field = (o, k) => (isObject(o) && Object.hasOwn(o, k) ? o[k] : undefined);

/** Each binding field of an evidence envelope next to the value it must have (the on-chain
 *  submission, the network and contract this page reads). Strict equality, as `verify-onchain`. */
export function bindingCheck(env, s, ctx) {
  const want = {
    network: ctx.network,
    contract_id: ctx.contractId,
    program_id: Number(s.program_id),
    submission_id: Number(s.id),
    hunter_id: s.hunter_id,
    commitment: s.commitment,
  };
  return BINDING_FIELDS.map((f) => ({ field: f, actual: field(env, f), expected: want[f], ok: field(env, f) === want[f] }));
}

/** States that fail the check; "undisclosed" (private until settlement) and "no-verdict" do not. */
export const EVIDENCE_FAILURES = ["mismatch", "unbound", "refused", "missing"];

/**
 * The evidence check of one submission, with the rules of `verify-onchain` (agent/src/verify.ts):
 *   ok          hash matches; v2: the envelope is bound to the submission; v1 contract: hash only
 *   mismatch    sha256 of the file differs from the on-chain evidence_sha256
 *   unbound     hash matches, but the envelope names another submission, or a v2 contract posted no envelope
 *   refused     evidence_uri is not a path below runs/
 *   missing     no file although the submission is final (or it cannot be loaded)
 *   undisclosed no file yet: the submission is not final, or it is held back for a related one
 * `read` is what loading the file gave: { refused } | { notFound, heldBy?: string[] } | { error } | { bytes }.
 */
export async function assessEvidence(s, ctx, read) {
  const out = { state: "no-verdict", mode: null, held: false, checks: [], detail: "", doc: null, size: null };
  const v = s?.verdict;
  if (!v) return out;
  if (!v.evidence_uri) return { ...out, state: "missing", detail: "the verdict has no evidence_uri" };
  if (read.refused) return { ...out, state: "refused", detail: "evidence_uri is not a path below runs/" };
  if (read.notFound) {
    if (!isFinal(s.status)) return { ...out, state: "undisclosed", detail: `the submission is ${s.status}, not final` };
    if (read.heldBy?.length) return { ...out, state: "undisclosed", held: true, detail: `final, but related to ${read.heldBy.join(", ")}, which is not final yet` };
    return { ...out, state: "missing", detail: `the submission is final (${s.status}), but the file is not there` };
  }
  if (read.error || !read.bytes) return { ...out, state: "missing", detail: read.error || "the file could not be loaded" };
  const bytes = new Uint8Array(read.bytes);
  const expected = String(v.evidence_sha256 ?? "").toLowerCase();
  const actual = await sha256Hex(bytes);
  const hash = { field: "sha256", actual, expected, ok: /^[0-9a-f]{64}$/.test(expected) && actual === expected };
  const base = { ...out, size: bytes.byteLength, checks: [hash] };
  if (!hash.ok) return { ...base, state: "mismatch", detail: "the sha256 of the file differs from the on-chain evidence_sha256" };
  let doc = null;
  try {
    doc = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    doc = null;
  }
  if (isObject(doc) && doc.schema === EVIDENCE_SCHEMA) {
    const checks = [hash, ...bindingCheck(doc, s, ctx)];
    const bad = checks.filter((c) => !c.ok).map((c) => c.field);
    return bad.length
      ? { ...base, doc, checks, mode: "v2", state: "unbound", detail: `the envelope names another submission (${bad.join(", ")})` }
      : { ...base, doc, checks, mode: "v2", state: "ok" };
  }
  if (ctx.major < 2) return { ...base, doc, mode: "v1", state: "ok", detail: "v1 evidence: hash only, no envelope" };
  return { ...base, doc, mode: "v1", state: "unbound", detail: `not a ${EVIDENCE_SCHEMA} envelope; a v2 contract must bind its evidence` };
}

/** The engine's verdict inside the evidence (the envelope's `engine`, or a v1 verdict.json itself). */
export function engineVerdict(doc) {
  if (!isObject(doc)) return null;
  const e = doc.schema === EVIDENCE_SCHEMA ? doc.engine : doc;
  return isObject(e) ? e : null;
}

/** The raw files to link next to an evidence file. summary.md, report.md and the PoC exist only if
 *  the engine ran (not for a worker verdict such as "sealed report does not match commitment"). */
export function evidenceFiles(url, doc) {
  if (!url) return [];
  const files = [url.pathname.split("/").pop()];
  const e = engineVerdict(doc);
  if (e && e.schema === ENGINE_SCHEMA) {
    files.push("summary.md", "report.md");
    const poc = field(field(e, "poc"), "copy");
    if (typeof poc === "string" && poc.length <= 64 && RUNS_SEGMENT.test(poc)) files.push(poc);
    if (doc.schema === EVIDENCE_SCHEMA) files.push("verdict.json");
  }
  return [...new Set(files)].map((f) => [f, new URL(f, url)]);
}

/** Held-back submissions (runs/<network>/<contract>/disclosure.json, written by `publish`): the ids
 *  submission `id` waits for, or null if it is not held back. */
export function heldWaitsFor(doc, id) {
  if (!isObject(doc) || doc.schema !== "replaycourt.disclosure/v1" || !Array.isArray(doc.held)) return null;
  const h = doc.held.find((x) => isObject(x) && x.submission_id === Number(id));
  if (!h || !Array.isArray(h.waits_for)) return null;
  return h.waits_for.filter((w) => Number.isInteger(w));
}

// ---------------------------------------------------------------- deadlines and the vault window

const NS_PER_MS = 1000000n;

/** Time left until a nanosecond deadline: "in 45 s", "in 3 min 05 s", "in 2 h 10 min", "in 2 d 4 h";
 *  "passed" once it is reached (the contract's checks are `now >= deadline`). */
export function fmtLeft(deadlineNs, nowMs = Date.now()) {
  let ms;
  try {
    ms = Number(BigInt(deadlineNs) / NS_PER_MS) - nowMs;
  } catch {
    return "?";
  }
  if (!Number.isFinite(ms)) return "?";
  if (ms <= 0) return "passed";
  const s = Math.ceil(ms / 1000);
  const pad = (n) => String(n).padStart(2, "0");
  if (s < 60) return `in ${s} s`;
  if (s < 3600) return `in ${Math.floor(s / 60)} min ${pad(s % 60)} s`;
  if (s < 86400) return `in ${Math.floor(s / 3600)} h ${pad(Math.floor((s % 3600) / 60))} min`;
  return `in ${Math.floor(s / 86400)} d ${Math.floor((s % 86400) / 3600)} h`;
}

/** Nanosecond timestamp + seconds -> nanosecond timestamp (decimal string); null if malformed. */
export function addSeconds(ns, sec) {
  try {
    return (BigInt(ns) + BigInt(Math.trunc(Number(sec))) * 1000000000n).toString();
  } catch {
    return null;
  }
}

/** The vault's 24 h spend window (SPEC v2 vault): it restarts when now >= window_start + 24 h, so
 *  after that the effective spend is 0 until the next vault submission. */
export function vaultWindow(vault, nowMs = Date.now()) {
  const end = addSeconds(vault?.window_start ?? "0", 86400);
  let running = false;
  try {
    running = BigInt(vault.window_start) > 0n && BigInt(end) / NS_PER_MS > BigInt(Math.floor(nowMs));
  } catch {
    running = false;
  }
  return { running, end, spent: running ? String(vault.spent_in_window ?? "0") : "0", lastSpent: String(vault?.spent_in_window ?? "0") };
}

/** Only http(s) URLs may become links. */
export function safeHref(url) {
  try {
    const u = new URL(String(url));
    return u.protocol === "https:" || u.protocol === "http:" ? u.href : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- minimal Markdown

function inline(text) {
  // Code spans first; everything else is escaped before **bold** markers become <strong>.
  return text
    .split(/(`[^`\n]+`)/)
    .map((part) => {
      if (part.length >= 2 && part.startsWith("`") && part.endsWith("`")) return `<code>${esc(part.slice(1, -1))}</code>`;
      return esc(part).replace(/\*\*([^*]+?)\*\*/g, "<strong>$1</strong>");
    })
    .join("");
}

/** One line of untrusted text with `code` and **bold** rendered, everything else escaped. */
export function renderInline(text) {
  return new Html(inline(String(text ?? "")));
}

function splitRow(line) {
  let s = line.trim();
  if (s.startsWith("|")) s = s.slice(1);
  if (s.endsWith("|")) s = s.slice(0, -1);
  return s.split("|").map((c) => c.trim());
}

function renderList(items) {
  let h = "";
  let depth = -1;
  for (const it of items) {
    const d = Math.min(it.depth, depth + 1);
    if (d > depth) {
      h += "<ul><li>";
      depth = d;
    } else {
      while (depth > d) {
        h += "</li></ul>";
        depth--;
      }
      h += "</li><li>";
    }
    h += inline(it.text);
  }
  while (depth >= 0) {
    h += "</li></ul>";
    depth--;
  }
  return h;
}

/**
 * Markdown subset used by the engine's summary.md: headings, paragraphs, **bold**, `code`,
 * nested "-" lists, pipe tables, fenced code blocks and "---" rules. Links and raw HTML are shown as
 * text. Headings are shifted down two levels so "#" fits under the page's own headings.
 */
export function renderMarkdown(src, maxChars = 400_000) {
  let text = String(src).replace(/\r\n?/g, "\n");
  let note = "";
  if (text.length > maxChars) {
    text = text.slice(0, maxChars);
    note = `<p class="muted">(cut after ${maxChars.toLocaleString("en-US")} characters)</p>`;
  }
  const lines = text.split("\n");
  const out = [];
  let para = [];
  const flush = () => {
    if (para.length) out.push(`<p>${inline(para.join(" "))}</p>`);
    para = [];
  };
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    let m;
    if (/^```/.test(line)) {
      flush();
      const body = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) body.push(lines[i++]);
      i++;
      out.push(`<pre><code>${esc(body.join("\n"))}</code></pre>`);
      continue;
    }
    if ((m = /^(#{1,6})\s+(.*)$/.exec(line))) {
      flush();
      const level = Math.min(m[1].length + 2, 6);
      out.push(`<h${level}>${inline(m[2])}</h${level}>`);
      i++;
      continue;
    }
    if (/^\s*(-{3,}|\*{3,})\s*$/.test(line)) {
      flush();
      out.push("<hr>");
      i++;
      continue;
    }
    if (/^\s*\|/.test(line) && i + 1 < lines.length && /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(lines[i + 1])) {
      flush();
      const head = splitRow(line);
      i += 2;
      const rows = [];
      while (i < lines.length && /^\s*\|/.test(lines[i])) rows.push(splitRow(lines[i++]));
      out.push(
        `<div class="table-wrap"><table class="md"><thead><tr>${head.map((c) => `<th>${inline(c)}</th>`).join("")}</tr></thead>` +
          `<tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`,
      );
      continue;
    }
    if (/^\s*[-*+]\s+/.test(line)) {
      flush();
      const items = [];
      while (i < lines.length && (m = /^(\s*)[-*+]\s+(.*)$/.exec(lines[i]))) {
        items.push({ depth: Math.floor(m[1].replace(/\t/g, "  ").length / 2), text: m[2] });
        i++;
      }
      out.push(renderList(items));
      continue;
    }
    if (line.trim() === "") {
      flush();
      i++;
      continue;
    }
    para.push(line.trim());
    i++;
  }
  flush();
  return new Html(out.join("\n") + note);
}

const ACCOUNT_ID_RE = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;

/** `?contract=<account>` in the page URL selects another deployment (e.g. a judge's own copy); anything that is not a valid NEAR account id is ignored. */
export function contractFromQuery(search, fallback) {
  const q = new URLSearchParams(search || "").get("contract");
  return q && q.length >= 2 && q.length <= 64 && ACCOUNT_ID_RE.test(q) ? q : fallback;
}
