// ReplayCourt explorer: read-only views of the ReplayCourt contract (protocol v1 and v2). Every value from
// the chain or from an evidence file is untrusted (anyone can submit a report, own a program or fund a
// vault): it is rendered through html`` (escaped) or renderMarkdown / renderInline (escaped, tiny subset).
import cfg from "./config.js";
import {
  EVIDENCE_FAILURES,
  addSeconds,
  assessEvidence,
  chainName,
  commitmentOf,
  contractFromQuery,
  engineVerdict,
  evidenceFiles,
  evidenceUrl,
  fmtDuration,
  fmtInt,
  fmtLeft,
  fmtNear,
  fmtTime,
  heldWaitsFor,
  html,
  isFinal,
  protocolMajor,
  renderInline,
  renderMarkdown,
  safeHref,
  siblingUrl,
  statusMeaning,
  vaultWindow,
} from "./lib.js";
import { listAll, rpcState, view } from "./near.js";

cfg.contractId = contractFromQuery(location.search, cfg.contractId);

const main = document.getElementById("main");
let seq = 0; // render generation; late async work for an old route is dropped

// ---------------------------------------------------------------- contract version

let versionInfo = null;
/** version() of the contract: protocol 1 for "1.0.x", 2 for "2.0.0". Remembered once it answered;
 *  if it does not answer, v2 rules apply (strict) and the next view asks again. */
async function contractVersion() {
  if (versionInfo) return versionInfo;
  try {
    const v = await view("version");
    const version = typeof v === "string" ? v : String(v);
    versionInfo = { version, major: protocolMajor(version) };
    const tag = document.getElementById("proto");
    if (tag) {
      tag.textContent = `v${versionInfo.version}`;
      tag.title = `contract version() = ${versionInfo.version}: protocol v${versionInfo.major}`;
      tag.hidden = false;
    }
    return versionInfo;
  } catch {
    return { version: null, major: 2 };
  }
}

// ---------------------------------------------------------------- small building blocks

const STATUS = {
  pending: "pending",
  valid: "valid · in challenge window",
  paid: "paid",
  invalid: "invalid · bond slashed",
  duplicate: "duplicate",
  needs_human: "needs human",
  disputed: "disputed",
  rejected: "rejected",
  expired: "expired · bond refunded",
  withdrawn: "withdrawn",
};
const OUTCOME = { valid: "valid", invalid: "invalid", duplicate: "duplicate", needs_human: "needs human" };
const SEVERITY = ["critical", "high", "medium", "low"];

const own = (o, k) => typeof k === "string" && Object.hasOwn(o, k);

function badge(status) {
  const k = own(STATUS, status) ? status : "unknown";
  return html`<span class="badge st-${k}">${own(STATUS, status) ? STATUS[status] : String(status)}</span>`;
}

function sevTag(sev, by) {
  if (!sev) return html`<span class="muted">–</span>`;
  const k = SEVERITY.includes(sev) ? sev : "unknown";
  return html`<span class="sev sev-${k}">${sev}</span>${by ? html` <span class="muted small">(${by})</span>` : ""}`;
}

function acct(id) {
  if (typeof id !== "string" || !id) return html`<span class="muted">–</span>`;
  return html`<a class="acct" href="${cfg.explorer}/address/${encodeURIComponent(id)}" target="_blank" rel="noopener noreferrer">${id}</a>`;
}

const subLink = (id, label) => html`<a href="#/submission/${Number(id)}">${label ?? `#${Number(id)}`}</a>`;
const progLink = (id, label) => html`<a href="#/program/${Number(id)}">${label ?? `program #${Number(id)}`}</a>`;
const near = (yocto) => html`${fmtNear(yocto)} <span class="unit">NEAR</span>`;
const vaultTag = (title) => html`<span class="tag" title="${title}">vault</span>`;
const isZero = (yocto) => {
  try {
    return BigInt(yocto ?? 0) === 0n;
  } catch {
    return true;
  }
};

function outcomeCell(s) {
  const v = s.verdict;
  if (!v) return html`<span class="muted">awaiting verdict</span>`;
  const label = own(OUTCOME, v.outcome) ? OUTCOME[v.outcome] : String(v.outcome);
  const dup = v.outcome === "duplicate" && v.duplicate_of !== null && v.duplicate_of !== undefined
    ? html` of ${subLink(v.duplicate_of)}` : "";
  const res = s.resolution ? html`<div class="muted small">owner resolved: ${s.resolution.outcome}</div>` : "";
  return html`<span class="outcome oc-${own(OUTCOME, v.outcome) ? v.outcome : "unknown"}">${label}</span>${dup}${res}`;
}

function severityCell(s) {
  if (s.verdict?.severity) return sevTag(s.verdict.severity);
  if (s.resolution?.severity) return sevTag(s.resolution.severity, "owner");
  return sevTag(null);
}

function payoutCell(s) {
  return s.payout && s.payout !== "0" ? near(s.payout) : html`<span class="muted">–</span>`;
}

const activeBadge = (p) => html`<span class="badge ${p.active ? "st-paid" : "st-withdrawn"}">${p.active ? "active · accepts reports" : "inactive"}</span>`;

function tile(label, value, hint) {
  return html`<div class="tile"><div class="tile-label">${label}</div><div class="tile-value">${value}</div>${hint ? html`<div class="tile-hint">${hint}</div>` : ""}</div>`;
}

function crumbs(...parts) {
  return html`<nav class="crumbs" aria-label="breadcrumb">${parts.map((p, i) => html`${i ? html`<span class="sep">/</span>` : ""}${p}`)}</nav>`;
}

/** A deadline: its time, and while it matters a live countdown that turns into `passed` (what
 *  happens then). The countdown is updated every second by the ticker below. */
function deadline(ns, passed) {
  if (ns === null || ns === undefined || ns === "") return html`<span class="muted">–</span>`;
  if (!passed) return html`${fmtTime(ns)}${fmtLeft(ns) === "passed" ? html` <span class="muted">· passed</span>` : ""}`;
  return html`${fmtTime(ns)} · <span class="left" data-until="${String(ns)}" data-passed="${passed}">${leftText(String(ns), passed)}</span>`;
}
function leftText(ns, passed) {
  const t = fmtLeft(ns);
  return t === "passed" ? passed : t;
}

let ticker = null;
function startTicker() {
  if (ticker) clearInterval(ticker);
  ticker = null;
  const tick = () => {
    const els = main.querySelectorAll("[data-until]");
    for (const el of els) {
      const t = leftText(el.dataset.until, el.dataset.passed);
      if (el.textContent !== t) el.textContent = t;
      el.classList.toggle("passed", t === el.dataset.passed);
    }
    return els.length;
  };
  if (tick()) ticker = setInterval(tick, 1000);
}

// ---------------------------------------------------------------- views

const PITCH = html`
  <p class="lead"><strong>ReplayCourt</strong> makes a bug report prove itself. A hunter (a human or an
  AI agent) commits a sealed report with a Foundry proof of concept to this NEAR contract and posts a
  small bond. A verifier agent decrypts it, replays the exploit on a fork of the real chain at the
  stated block, and reads the value flows from the execution trace instead of trusting what the PoC
  prints. It posts the verdict (valid, invalid, duplicate or needs human, with severity, attack
  fingerprint and the sha256 of its evidence) on-chain with a function-call key that can call
  nothing else. Valid reports are paid from the program's escrow after a challenge window, invalid
  ones lose their bond (to the program's pool and the verifier's fee), and duplicates are settled by on-chain commit order. This
  page only reads: every number comes from a contract view call, and each evidence file is hashed
  in your browser and compared with the hash on-chain.</p>`;
const PITCH_V2 = html`
  <p class="lead small-lead">Protocol v2: the commitment is bound to the hunter's account, each evidence
  file names the submission it belongs to and stays private until the submission is settled, an
  owner who disputes a valid verdict attaches a dispute bond that goes to the hunter if the owner
  overrules the verifier or does not resolve in time, and a hunter's AI agent can submit from a
  vault within an on-chain spending policy.</p>`;

function programFacts(p, major) {
  const v2 = major >= 2;
  const available = (() => {
    try {
      return BigInt(p.pool) - BigInt(p.reserved);
    } catch {
      return null;
    }
  })();
  const st = p.stats ?? {};
  const money = [
    tile("Pool (escrow)", near(p.pool), available !== null ? html`${fmtNear(available.toString())} NEAR not reserved` : ""),
    tile("Reserved", near(p.reserved), "for open submissions at max payout"),
    tile("Bond", near(p.bond), "base bond per report"),
    tile("Verifier fee", near(p.verifier_fee), "per verdict"),
  ];
  const tiles = v2
    ? html`<div class="tiles four">
        ${money}
        ${tile("Dispute bond", near(p.dispute_bond), "owner's stake on dispute(); to the hunter if overruled")}
        ${tile("Challenge window", fmtDuration(p.challenge_period_sec), "a valid report is paid after it")}
        ${tile("Resolve timeout", fmtDuration(p.resolve_timeout_sec), "owner's deadline: needs human, disputed")}
        ${tile("Pending timeout", fmtDuration(p.pending_timeout_sec), "then a report without verdict may be withdrawn")}
      </div>`
    : html`<div class="tiles">
        ${money}
        ${tile("Challenge window", fmtDuration(p.challenge_period_sec), html`pending timeout ${fmtDuration(p.pending_timeout_sec)}`)}
      </div>`;
  return html`
    ${tiles}
    <div class="row-split">
      <div class="panel">
        <h3>Payouts</h3>
        <table class="kv compact">
          ${SEVERITY.map((k) => html`<tr><th>${sevTag(k)}</th><td class="num">${near(p.payouts?.[k])}</td></tr>`)}
        </table>
      </div>
      <div class="panel">
        <h3>Stats</h3>
        <table class="kv compact">
          <tr><th>submissions</th><td class="num">${fmtInt(st.submissions)}</td><th>paid</th><td class="num">${fmtInt(st.paid)}</td></tr>
          <tr><th>invalid</th><td class="num">${fmtInt(st.invalid)}</td><th>duplicate</th><td class="num">${fmtInt(st.duplicate)}</td></tr>
          <tr><th>needs human</th><td class="num">${fmtInt(st.needs_human)}</td><th>disputes</th><td class="num ${Number(st.disputes) > 0 ? "warn-text" : ""}">${fmtInt(st.disputes)}</td></tr>
          ${v2 ? html`<tr><th>overruled</th><td class="num ${Number(st.overruled) > 0 ? "warn-text" : ""}">${fmtInt(st.overruled)}</td><th></th><td></td></tr>` : ""}
          <tr><th>total paid</th><td class="num" colspan="3">${near(st.total_paid)}</td></tr>
        </table>
        ${v2 ? html`<p class="small muted note">overruled: disputes the owner resolved against the verifier; the dispute bond went to the hunter</p>` : ""}
      </div>
      <div class="panel">
        <h3>Accounts</h3>
        <table class="kv compact">
          <tr><th>owner</th><td>${acct(p.owner_id)}</td></tr>
          <tr><th>verifier</th><td>${acct(p.verifier_id)}</td></tr>
          <tr><th>created</th><td>${fmtTime(p.created_at)}</td></tr>
        </table>
      </div>
    </div>`;
}

const HOW_IT_WORKS = [
  ["Submit", "hunter", "Sealed report and deposit go on-chain."],
  ["Replay", "verifier", "The attack is replayed on a copy of the chain."],
  ["Verdict", "verifier", "Fixed rules judge the replay, no AI. Doubtful cases go to the owner."],
  ["Settle", "contract", "Proven bugs get paid. Failed proofs lose the deposit. An owner who overrules pays a penalty."],
];

const repoFile = (path) => `${cfg.repoUrl}/blob/main/${path}`;
const ext = (url, label) => html`<a href="${safeHref(url)}" target="_blank" rel="noopener noreferrer">${label}</a>`;

const ICON = {
  bug: html`<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 8a4 4 0 0 1 8 0v1H8V8Zm-1 3h10v3a5 5 0 0 1-10 0v-3Zm5 0v8M4 8l3 2M20 8l-3 2M3 14h4M21 14h-4M4 20l3-3M20 20l-3-3"/></svg>`,
  bounty: html`<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V6l8-3Zm-3.5 9 2.5 2.5 4.5-5"/></svg>`,
  Submit: html`<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 11h12v9H6v-9Zm3 0V8a3 3 0 0 1 6 0v3"/></svg>`,
  Replay: html`<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 12a8 8 0 1 0 2.5-5.8M4 4v4.5h4.5M10 9l5 3-5 3V9Z"/></svg>`,
  Verdict: html`<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 4l6 6M11 7l6 6M12.5 5.5l-4 4 6 6 4-4M10 12l-6 6 2 2 6-6M4 21h9"/></svg>`,
  Settle: html`<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Zm3 6.5c-.5-1-1.6-1.5-3-1.5-1.7 0-3 .8-3 2s1.3 1.8 3 2 3 .8 3 2-1.300 2-3 2c-1.400 0-2.500-.5-3-1.500M12 6v2M12 16v2"/></svg>`,
};

/** The two ways in for a person. The page itself only reads, so each path ends in commands. */
function rolePaths() {
  return html`
    <div class="roles">
      <details class="role role-hunter">
        <summary><span class="role-icon">${ICON.bug}</span><span class="role-head"><strong>I found a bug</strong><span>Get paid for a bug you can prove</span></span><span class="role-open" aria-hidden="true"></span></summary>
        <ol class="role-steps">
          <li>Write a report: a Markdown file with a Foundry test that runs the attack. ${ext(repoFile("docs/report-template.md"), "Template")} · ${ext(repoFile("engine/reports/01_templedao_stax.md"), "real example")}</li>
          <li>Check it on your machine, free: <code class="cmd">python3 -I engine/replay.py check report.md --no-register --dest check</code></li>
          <li>Submit, which locks the deposit: <code class="cmd">node src/cli.ts submit --program 0 --report report.md --as you.testnet</code></li>
          <li>Follow it here. After the challenge window: <code class="cmd">node src/cli.ts finalize &lt;id&gt;</code></li>
        </ol>
        <p class="role-more">${ext(repoFile("docs/HUNTER.md"), "Full guide for hunters →")}</p>
      </details>
      <details class="role role-owner">
        <summary><span class="role-icon">${ICON.bounty}</span><span class="role-head"><strong>I run a bounty</strong><span>Let replays filter out the noise</span></span><span class="role-open" aria-hidden="true"></span></summary>
        <ol class="role-steps">
          <li>Create a program with a reward pool and the contracts in scope: <code class="cmd">node src/cli.ts create-program --name "My bounty" --pool 10 --scope 1:0xYOUR_CONTRACT</code></li>
          <li>Run the verifier, or have someone run it: <code class="cmd">node src/cli.ts worker</code></li>
          <li>Reports appear here. Object to a verdict or decide a doubtful case: <code class="cmd">node src/cli.ts dispute &lt;id&gt;</code> <code class="cmd">node src/cli.ts resolve &lt;id&gt;</code></li>
        </ol>
        <p class="role-more">${ext(repoFile("docs/OWNER.md"), "Full guide for owners →")}</p>
      </details>
    </div>`;
}

/** One report at a glance: who did what, with the numbers from the chain. */
function reportTrail(s, v) {
  const chain = v ? (Number(v.chain_id) !== 0 ? html`${chainName(v.chain_id)}, block <span class="mono">${fmtInt(v.fork_block)}</span>` : "no fork was replayed") : "waiting";
  const settled = s.status === "paid" ? html`paid ${near(s.payout)}`
    : s.status === "invalid" ? "deposit lost"
    : s.status === "duplicate" ? "deposit back, minus a fee"
    : s.status === "rejected" ? "no payout"
    : s.status === "expired" || s.status === "withdrawn" ? "deposit back"
    : "open";
  const items = [
    ["Submitted", "hunter", html`deposit ${near(s.bond)}`],
    ["Replayed", "verifier", chain],
    ["Verdict", "verifier", v ? html`${outcomeCell(s)}${v.severity ? html` · ${sevTag(v.severity)}` : ""}` : "waiting"],
    ["Settled", "contract", settled],
  ];
  return html`<ol class="trail">${items.map(([what, who, value]) => html`<li><span class="who">${who}</span><strong>${what}</strong><span>${value}</span></li>`)}</ol>`;
}

const TERMS = [
  ["Hunter", "A person or AI agent who finds a bug and reports it."],
  ["Bond", "The deposit a hunter locks with each report. A report whose proof fails usually loses it. A storage fee on top is not refunded."],
  ["Pool (escrow)", "The reward money, held by the contract. Money reserved for open reports cannot be withdrawn by the owner."],
  ["Program", "One bug bounty: its owner, its rewards and its rules."],
  ["Verifier", "The program that replays reports and posts verdicts, with a key that can only post verdicts."],
  ["PoC (proof of concept)", "The code in a report that carries out the attack."],
  ["Fork", "A private copy of a real blockchain at a past moment. An attack can run there without touching the real chain."],
  ["Trace", "The record of the calls and events the code really made during the replay."],
  ["Fingerprint", "A code derived from what a replay did. The same attack usually gives the same code."],
  ["Challenge window", "The wait after a valid verdict, in which the program owner can object."],
  ["Evidence", "The files of a replay. The hash of the main file is on-chain, so your browser can check that file."],
  ["Testnet", "NEAR's test network. Its tokens have no value."],
];

const onShowcase = () => cfg.contractId === cfg.tourContract && Array.isArray(cfg.tour);

/** The guided cases, or nothing on another deployment: their texts describe this one contract. */
async function tourCases() {
  if (!onShowcase()) return [];
  const subs = await Promise.all(cfg.tour.map((c) => view("get_submission", { submission_id: c.id }).catch(() => null)));
  return cfg.tour.flatMap((c, i) => (subs[i] ? [{ ...c, s: subs[i] }] : []));
}

/** The outcome as a court stamp, in plain words; the values come from the chain. */
function stamp(s) {
  const [kind, text] = s.status === "paid" ? ["ok", `paid ${fmtNear(s.payout)} NEAR`]
    : s.status === "invalid" ? ["bad", "deposit lost"]
    : s.status === "rejected" ? ["bad", "rejected"]
    : s.status === "duplicate" ? ["warn", "duplicate"]
    : ["info", own(STATUS, s.status) ? STATUS[s.status].split(" · ")[0] : String(s.status)];
  return html`<span class="stamp stamp-${kind}">${text}</span>`;
}

/** A replay played back line by line, with the real numbers of one showcase report. */
function heroReplay(cases) {
  const r = cfg.heroReplay;
  const c = r && cases.find((x) => x.id === r.id);
  if (!c) return "";
  return html`
    <a class="replay" href="#/submission/${Number(r.id)}">
      <div class="replay-bar"><span></span><span></span><span></span><em>replaying report #${Number(r.id)}</em></div>
      <dl>${r.lines.map(([k, v], i) => html`<div class="replay-line d${i + 1}"><dt>${k}</dt><dd>${v}</dd></div>`)}</dl>
      <div class="replay-stamp">${stamp(c.s)}</div>
    </a>`;
}

async function overview() {
  document.title = "ReplayCourt explorer";
  const [, programs, cases] = await Promise.all([contractVersion(), listAll("list_programs"), tourCases()]);
  const count = (k) => programs.reduce((a, p) => a + Number(p.stats?.[k] ?? 0), 0);
  let paid = 0n;
  for (const p of programs) {
    try {
      paid += BigInt(p.stats?.total_paid ?? 0);
    } catch {
      // ignore malformed values
    }
  }
  return html`
    <section class="hero">
      <div class="hero-inner">
        <div class="hero-copy">
          <p class="eyebrow"><span class="live-dot"></span>Live on NEAR ${cfg.network}${onShowcase() ? " · staged demo with play money" : ""}</p>
          <h1>Bug reports that <em>prove</em> themselves</h1>
          <p class="lede">A bug bounty where reports are judged by replaying the attack.</p>
          <dl class="hero-stats">
            <div><dd>${fmtInt(count("submissions"))}</dd><dt>reports</dt></div>
            <div><dd>${fmtNear(paid.toString())}</dd><dt>NEAR paid out</dt></div>
            <div><dd>${fmtInt(count("invalid"))}</dd><dt>rejected</dt></div>
          </dl>
        </div>
        ${heroReplay(cases)}
      </div>
    </section>
    ${rolePaths()}
    <h2 class="section">How it works</h2>
    <ol class="flow">
      ${HOW_IT_WORKS.map(([title, who, text]) => html`<li><span class="flow-icon">${ICON[title]}</span><h3>${title}</h3><span class="who">${who}</span><p>${text}</p></li>`)}
    </ol>
    ${cases.length ? html`
    <h2 class="section">Open a case</h2>
    <div class="cases">
      ${cases.map((c) => html`
        <a class="case" href="#/submission/${Number(c.id)}">
          <span class="case-id">#${Number(c.id)}</span>
          <span class="case-title">${c.title}</span>
          ${stamp(c.s)}
        </a>`)}
    </div>` : ""}
    <p class="muted small fineprint">This page only reads. <a href="#/details">Numbers and glossary →</a> · ${ext(cfg.repoUrl, "Code")}${cfg.demoPostUrl ? html` · ${ext(cfg.demoPostUrl, "Demo video")}` : ""}</p>`;
}

async function detailsView() {
  document.title = "Details · ReplayCourt";
  const [info, programs] = await Promise.all([contractVersion(), listAll("list_programs")]);
  const totalSubs = programs.reduce((a, p) => a + Number(p.stats?.submissions ?? 0), 0);
  let totalPaid = 0n;
  for (const p of programs) {
    try {
      totalPaid += BigInt(p.stats?.total_paid ?? 0);
    } catch {
      // ignore malformed values
    }
  }
  return html`
    ${crumbs(html`<a href="#/">Overview</a>`, "details")}
    <h1>Details</h1>
    <div class="tiles">
      ${tile("Contract", acct(cfg.contractId), html`${cfg.network} · version ${info.version ?? "?"} (protocol v${info.major})`)}
      ${tile("Programs", fmtInt(programs.length))}
      ${tile("Submissions", fmtInt(totalSubs))}
      ${tile("Paid to hunters", near(totalPaid.toString()))}
    </div>
    <h2>Programs</h2>
    ${programs.length === 0 ? html`<p class="muted">No programs yet.</p>` : ""}
    ${programs.map((p) => html`
      <section class="card">
        <header class="card-head">
          <h3>${progLink(p.id, p.name)}</h3>
          ${activeBadge(p)}
          <span class="spacer"></span>
          ${progLink(p.id, "open →")}
        </header>
        <p class="card-line">${programLine(p)}</p>
      </section>`)}
    <h2>Glossary</h2>
    <dl class="terms">${TERMS.map(([term, text]) => html`<dt>${term}</dt><dd>${text}</dd>`)}</dl>
    <h2>Technical summary</h2>
    ${PITCH}
    ${info.major >= 2 ? PITCH_V2 : ""}`;
}

function programLine(p) {
  return html`${fmtInt(p.stats?.submissions)} report${Number(p.stats?.submissions) === 1 ? "" : "s"} · ${near(p.stats?.total_paid)} paid out · ${near(p.pool)} left in the pool`;
}

function submissionsTable(subs) {
  if (subs.length === 0) return html`<p class="muted">No submissions yet.</p>`;
  return html`
    <div class="table-wrap">
      <table class="list">
        <thead><tr><th>#</th><th>Title</th><th>Hunter</th><th>Status</th><th>Outcome</th><th>Severity</th><th class="num">Payout</th><th class="num">Submitted block</th></tr></thead>
        <tbody>
          ${subs.map((s) => html`<tr>
            <td>${subLink(s.id)}</td>
            <td class="title-cell">${subLink(s.id, s.title)}</td>
            <td class="nowrap">${acct(s.hunter_id)}${s.funded_by_vault === true ? html` ${vaultTag("bond and storage drawn from the hunter's vault")}` : ""}</td>
            <td>${badge(s.status)}</td>
            <td class="nowrap">${outcomeCell(s)}</td>
            <td class="nowrap">${severityCell(s)}</td>
            <td class="num">${payoutCell(s)}</td>
            <td class="num mono">${fmtInt(s.submitted_block)}</td>
          </tr>`)}
        </tbody>
      </table>
    </div>`;
}

async function programView(id) {
  const [info, p, subs] = await Promise.all([
    contractVersion(),
    view("get_program", { program_id: id }),
    listAll("list_submissions", { program_id: id }),
  ]);
  if (!p) return notFound(`Program #${id} does not exist on ${cfg.contractId}.`);
  document.title = `${p.name} · ReplayCourt`;
  subs.sort((a, b) => a.id - b.id);
  return html`
    ${crumbs(html`<a href="#/">Overview</a>`, html`program #${id}`)}
    <div class="title-row"><h1>${p.name}</h1>${activeBadge(p)}</div>
    <p class="card-line">${programLine(p)}</p>
    <h2>Submissions <span class="muted">(${subs.length})</span></h2>
    ${submissionsTable(subs)}
    <p class="muted small">Commit order = submission id order; a duplicate always points to an earlier id.</p>
    <details class="more">
      <summary>Rules and numbers of this program</summary>
      ${programFacts(p, info.major)}
      ${Array.isArray(p.scope) && p.scope.length ? html`
      <div class="panel scope">
        <h3>Scope (informational)</h3>
        <ul class="plain">${p.scope.map((t) => html`<li><span class="muted">${chainName(t.chain_id)}</span> <code>${t.address}</code></li>`)}</ul>
      </div>` : ""}
    </details>`;
}

/** Where the owner's dispute bond of a submission is (SPEC v2 "resolve outcomes"). */
function disputeBondNote(s, p) {
  if (isZero(s.dispute_bond)) return html`<span class="muted">– (not disputed)</span>`;
  const r = s.resolution;
  let where = "held from the program owner until the dispute is resolved";
  if (s.status === "paid" && r?.outcome === "valid") {
    // Resolved as valid: back to the owner, unless the owner's severity pays less than the verifier's.
    let lower = null;
    try {
      const want = r.severity && s.verdict?.severity ? [p?.payouts?.[r.severity], p?.payouts?.[s.verdict.severity]] : null;
      if (want && want[0] !== undefined && want[1] !== undefined) lower = BigInt(want[0]) < BigInt(want[1]);
      else if (!r.severity) lower = false; // default: the verifier's severity
    } catch {
      lower = null;
    }
    where = lower === null
      ? "resolved as valid: back to the owner, or to the hunter if the owner's severity pays less than the verifier's"
      : lower
        ? "to the hunter: the owner resolved as valid with a severity that pays less than the verifier's (overruled)"
        : "back to the owner: the owner resolved the dispute as valid";
  } else if (s.status === "paid") where = "to the hunter: the owner did not resolve the dispute in time";
  else if (s.status === "rejected") where = "to the hunter: the owner overruled the verifier";
  return html`${near(s.dispute_bond)}<div class="small muted">${where}</div>`;
}

async function submissionView(id) {
  const [info, s] = await Promise.all([contractVersion(), view("get_submission", { submission_id: id })]);
  if (!s) return { content: notFound(`Submission #${id} does not exist on ${cfg.contractId}.`) };
  const [p, siblings] = await Promise.all([
    view("get_program", { program_id: s.program_id }).catch(() => null),
    listAll("list_submissions", { program_id: s.program_id }).catch(() => []),
  ]);
  const v2 = info.major >= 2;
  document.title = `#${id} ${s.title} · ReplayCourt`;
  const v = s.verdict;
  const tourText = onShowcase() ? cfg.tour.find((c) => c.id === id)?.text : null;
  const sameFp = v?.fingerprint ? siblings.filter((o) => o.id !== s.id && o.verdict?.fingerprint === v.fingerprint) : [];
  const pendingUntil = s.status === "pending" && p ? addSeconds(s.submitted_at, p.pending_timeout_sec) : null;
  const resolvePassed = s.status === "disputed"
    ? "passed · finalize() pays the hunter plus the owner's dispute bond"
    : "passed · finalize() refunds the full bond (expired)";
  const content = html`
    ${crumbs(html`<a href="#/">Overview</a>`, progLink(s.program_id, p ? p.name : undefined), html`submission #${id}`)}
    <div class="title-row">
      <h1><span class="muted">#${id}</span> ${s.title}</h1>
    </div>
    <p class="meta">by ${acct(s.hunter_id)}${s.funded_by_vault === true ? html` ${vaultTag("bond and storage drawn from the hunter's vault")}` : ""} · submitted ${fmtTime(s.submitted_at)} in block <span class="mono">${fmtInt(s.submitted_block)}</span></p>
    ${statusMeaning(s) ? html`<div class="result"><div class="result-stamp">${stamp(s)}</div><p class="result-main">${statusMeaning(s)}</p>${tourText ? html`<p class="result-why">${tourText}</p>` : v?.reason ? html`<p class="result-why">${renderInline(v.reason)}</p>` : ""}</div>` : ""}
    ${reportTrail(s, v)}

    <section class="evcheck wait" id="evcheck" aria-live="polite">
      <div class="mark">…</div>
      <div><h2>Evidence matches on-chain?</h2><p>Checking…</p></div>
    </section>

    <details class="more">
      <summary>The report the hunter submitted</summary>
      <div id="reportbody" class="md-body"><p class="muted">${v ? "Loading…" : "The report stays sealed until the submission is settled."}</p></div>
    </details>

    <details class="more">
    <summary>Verdict and settlement in detail</summary>
    <div class="row-split two">
      <section class="panel">
        <h2>Verdict</h2>
        ${v ? html`
        <table class="kv">
          <tr><th>outcome</th><td>${outcomeCell(s)}</td></tr>
          <tr><th>severity</th><td>${v.severity ? sevTag(v.severity) : html`<span class="muted">–</span>`}</td></tr>
          ${v.outcome === "duplicate" ? html`<tr><th>duplicate of</th><td>${v.duplicate_of !== null && v.duplicate_of !== undefined ? subLink(v.duplicate_of, `submission #${Number(v.duplicate_of)}`) : "–"}</td></tr>` : ""}
          <tr><th>reason</th><td class="reason">${v.reason ? renderInline(v.reason) : "–"}</td></tr>
          <tr><th>fingerprint</th><td>${v.fingerprint ? html`<code class="hash">${v.fingerprint}</code>` : html`<span class="muted">– (none)</span>`}${sameFp.length ? html`<div class="small">same fingerprint: ${sameFp.map((o, i) => html`${i ? ", " : ""}${subLink(o.id)}`)}</div>` : ""}</td></tr>
          <tr><th>fork</th><td>${chainName(v.chain_id)}${Number(v.chain_id) !== 0 ? html` (chain id ${Number(v.chain_id)})` : ""}, block <span class="mono">${fmtInt(v.fork_block)}</span></td></tr>
          <tr><th>posted</th><td>${fmtTime(v.posted_at)} by ${p ? acct(p.verifier_id) : "the program's verifier"}</td></tr>
          <tr><th>evidence_sha256</th><td><code class="hash">${v.evidence_sha256}</code></td></tr>
          <tr><th>evidence_uri</th><td><code class="hash">${v.evidence_uri || "–"}</code></td></tr>
        </table>` : html`<p class="muted">No verdict yet. The verifier replays the PoC and posts one with its function-call key.</p>`}
      </section>
      <section class="panel">
        <h2>Settlement</h2>
        <table class="kv">
          <tr><th>status</th><td>${badge(s.status)}</td></tr>
          <tr><th>bond</th><td>${near(s.bond)}</td></tr>
          ${v2 ? html`<tr><th>funded by</th><td>${s.funded_by_vault === true
            ? html`the hunter's vault ${vaultTag("submitted with submit_report_from_vault")}<div class="small muted">bond and storage drawn within the vault's on-chain policy; refunds go back into the vault, the payout to the hunter</div>`
            : "the hunter's deposit"}</td></tr>` : ""}
          ${s.storage_cost !== undefined ? html`<tr><th>storage</th><td>${near(s.storage_cost)} <span class="small muted">charged at submission</span></td></tr>` : ""}
          <tr><th>payout</th><td>${payoutCell(s)}</td></tr>
          ${pendingUntil ? html`<tr><th>pending timeout</th><td>${deadline(pendingUntil, "passed · the hunter may withdraw_pending() for the full bond")}</td></tr>` : ""}
          <tr><th>challenge window until</th><td>${deadline(s.valid_until, s.status === "valid" ? "passed · anyone may finalize() to pay the hunter" : null)}</td></tr>
          ${v2 ? html`<tr><th>resolve deadline</th><td>${deadline(s.resolve_until, s.status === "needs_human" || s.status === "disputed" ? resolvePassed : null)}${s.status === "needs_human" || s.status === "disputed" ? html`<div class="small muted">the program owner must resolve() before it</div>` : ""}</td></tr>` : ""}
          ${v2 ? html`<tr><th>dispute bond</th><td>${disputeBondNote(s, p)}</td></tr>` : ""}
          ${s.dispute_reason ? html`<tr><th>dispute</th><td class="reason">${s.dispute_reason}</td></tr>` : ""}
          ${s.resolution ? html`<tr><th>owner resolution</th><td>${s.resolution.outcome}${s.resolution.severity ? html` / ${sevTag(s.resolution.severity)}` : ""} · ${fmtTime(s.resolution.at)}${s.resolution.by ? html` <span class="muted">by ${s.resolution.by}</span>` : ""}<div class="reason">${s.resolution.note}</div></td></tr>` : ""}
          <tr><th>commitment</th><td><code class="hash">${s.commitment}</code>
            ${v2
              ? html`<div class="small muted formula">sha256("replaycourt/commit/v2" ‖ 0x00 ‖ hunter ‖ 0x00 ‖ report)</div>
                <div class="small muted">bound to the hunter's account: a copied seal fails from any other account. The report itself is stored sealed.</div>`
              : html`<div class="small muted">sha256 of the plaintext report (protocol v1, not bound to the hunter); the report itself is stored sealed</div>`}
            <div id="commitcheck" class="small"></div></td></tr>
          <tr><th>program</th><td>${progLink(s.program_id, p ? p.name : undefined)}</td></tr>
        </table>
      </section>
    </div>
    </details>

    <details class="more">
      <summary>The replay's report</summary>
      <section class="panel evidence">
        <div class="panel-head"><h2>Evidence: summary.md</h2><span class="spacer"></span><span id="evlinks" class="small"></span></div>
        <div id="evsummary" class="md-body"><p class="muted">${v ? "Loading…" : "No evidence yet."}</p></div>
      </section>
    </details>`;
  return { content, after: (token) => checkEvidence(s, info, token) };
}

// ---------------------------------------------------------------- evidence check

function setHtml(id, markup) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = String(markup);
}

/** The check box: mark, title and text side by side; `table` (optional) below them at full width. */
function evBox(state, mark, title, body, table) {
  const box = document.getElementById("evcheck");
  if (!box) return;
  box.className = `evcheck ${state}`;
  box.innerHTML = String(html`<div class="evhead"><div class="mark" aria-hidden="true">${mark}</div><div class="evbody"><h2>${title}</h2>${body}</div></div>${table && state === "ok" ? html`<details class="more inner"><summary>Show the check</summary>${table}</details>` : table ?? ""}`);
}

const getOpts = { cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer" };

/** Load a file below runs/: { bytes } | { notFound } (HTTP 404/410: not published) | { error }. */
async function loadFile(url) {
  try {
    if (!globalThis.crypto?.subtle) throw new Error("WebCrypto is not available (open the page via https or http://127.0.0.1)");
    const res = await fetch(url, getOpts);
    if (res.status === 404 || res.status === 410) return { notFound: true };
    if (!res.ok) return { error: `HTTP ${res.status} for ${url.href}` };
    return { bytes: await res.arrayBuffer() };
  } catch (e) {
    return { error: e.message || String(e) };
  }
}

/** For a final submission whose evidence is not there: the related submissions it is held back
 *  for (runs/<network>/<contract>/disclosure.json) that are not final yet, e.g. ["#1 (valid)"]. */
async function heldBy(id) {
  const url = evidenceUrl(`runs/${cfg.network}/${cfg.contractId}/disclosure.json`, cfg.evidenceBase, location.href);
  if (!url) return [];
  const r = await loadFile(url);
  if (!r.bytes) return [];
  let waits = null;
  try {
    waits = heldWaitsFor(JSON.parse(new TextDecoder().decode(r.bytes)), id);
  } catch {
    waits = null;
  }
  if (!waits) return [];
  const open = [];
  for (const w of waits.slice(0, 20)) {
    const o = await view("get_submission", { submission_id: w }).catch(() => null);
    if (o && !isFinal(o.status)) open.push(`#${Number(w)} (${o.status})`);
  }
  return open;
}

const NUMERIC_FIELDS = ["program_id", "submission_id"];
function shown(f, x) {
  if (x === undefined) return "(missing)";
  return typeof x === "string" && !NUMERIC_FIELDS.includes(f) ? x : JSON.stringify(x);
}

function checksTable(r, uri, url) {
  const mark = (ok) => html`<td class="ck ${ok ? "ck-ok" : "ck-bad"}" aria-label="${ok ? "matches" : "differs"}">${ok ? "✓" : "✗"}</td>`;
  const fileName = url ? url.pathname.split("/").pop() : "file";
  return html`
    <div class="table-wrap checks-wrap"><table class="checks">
      <thead><tr><th></th><th>${fileName} (computed / read)</th><th>expected (on-chain)</th><th></th></tr></thead>
      <tbody>
        ${r.checks.map((c) => html`<tr class="${c.ok ? "" : "bad-row"}"><th>${c.field}</th>
          <td><code class="hash">${shown(c.field, c.actual)}</code></td>
          <td><code class="hash">${shown(c.field, c.expected)}</code>${c.field === "network" || c.field === "contract_id" ? html` <span class="muted small">(read by this page)</span>` : ""}</td>
          ${mark(c.ok)}</tr>`)}
        <tr><th>location</th><td><a href="${safeHref(url) ?? "#"}" target="_blank" rel="noopener noreferrer">${uri}</a> <span class="muted">(${fmtInt(r.size)} bytes)</span></td><td>a path below <code>runs/</code></td>${mark(true)}</tr>
      </tbody>
    </table></div>`;
}

function renderEvidence(r, s, info, url) {
  const v = s.verdict;
  const expected = String(v.evidence_sha256 ?? "");
  const uri = v.evidence_uri;
  switch (r.state) {
    case "ok":
      if (r.mode === "v2") {
        evBox("ok", "✓", "Evidence matches on-chain and is bound to this submission ✓", html`
          <p>Checked in your browser against the hash on the blockchain.</p>`,
        html`<p>The sha256 of <code>evidence.json</code>, computed in this browser, equals the <code>evidence_sha256</code> the verifier
          posted on-chain, and the envelope (<code>replaycourt.evidence/v1</code>) names exactly this contract, program, submission, hunter and commitment.</p>
          ${checksTable(r, uri, url)}`);
      } else {
        evBox("ok", "✓", "Evidence hash matches on-chain ✓", html`
          <p>The sha256 of <code>${url.pathname.split("/").pop()}</code>, computed in this browser, equals the <code>evidence_sha256</code> the verifier posted on-chain.
          <span class="muted">v1 evidence (contract ${info.version ?? "?"}, protocol v1): hash only; v1 evidence files carry no binding fields.</span></p>`,
        checksTable(r, uri, url));
      }
      return;
    case "mismatch":
      evBox("bad", "✗", "Evidence hash does not match on-chain ✗", html`
        <p>The sha256 of the evidence file, computed in this browser, differs from the <code>evidence_sha256</code> the verifier posted on-chain.</p>`,
      checksTable(r, uri, url));
      return;
    case "unbound":
      evBox("bad", "✗", "Evidence is not bound to this submission ✗", html`
        <p>The hash matches, but ${r.detail}.</p>`,
      checksTable(r, uri, url));
      return;
    case "refused":
      evBox("bad", "✗", "Evidence location refused ✗", html`
        <p>The on-chain <code>evidence_uri</code> is not a path below <code>runs/</code>, so this page does not load it.</p>
        <table class="kv compact"><tr><th>evidence_uri</th><td><code class="hash">${uri}</code></td></tr></table>`);
      return;
    case "undisclosed":
      evBox("private", "○", r.held ? "Evidence held back until related reports settle" : "Evidence private until settlement", html`
        <p>${r.held
          ? html`This submission is final, but its evidence is ${r.detail.replace(/^final, but /, "")}. It is published together with the evidence of that report.`
          : html`The verifier posted the hash of its evidence on-chain, but the file is published only once the submission is final (it is <strong>${s.status}</strong>), so the details of a live bug are not disclosed before the owner can react.`}
        This is not a failure: the hash can be checked here as soon as the file is published.</p>
        <table class="kv compact"><tr><th>on-chain</th><td><code class="hash">${expected}</code></td></tr><tr><th>file</th><td><code class="hash">${uri}</code> <span class="muted">(not published yet)</span></td></tr></table>`);
      return;
    default:
      evBox("bad", "✗", "Evidence file missing ✗", html`
        <p>${r.detail}.</p>
        <table class="kv compact"><tr><th>on-chain</th><td><code class="hash">${expected}</code></td></tr><tr><th>file</th><td><code class="hash">${url ? url.href : uri}</code></td></tr></table>`);
  }
}

async function checkEvidence(s, info, token) {
  const v = s.verdict;
  const current = () => token === seq;
  if (!v) {
    evBox("none", "–", "No verdict yet", html`<p>Nothing to check until the verifier posts a verdict with its evidence hash.</p>`);
    return;
  }
  const ctx = { network: cfg.network, contractId: cfg.contractId, major: info.major };
  const url = v.evidence_uri ? evidenceUrl(v.evidence_uri, cfg.evidenceBase, location.href) : null;
  let read = {};
  if (v.evidence_uri && !url) read = { refused: true };
  else if (url) {
    read = await loadFile(url);
    if (read.notFound && isFinal(s.status)) read.heldBy = await heldBy(s.id);
  }
  if (!current()) return;
  const r = await assessEvidence(s, ctx, read);
  if (!current()) return;
  renderEvidence(r, s, info, url);

  if (r.state === "undisclosed") {
    setHtml("evsummary", html`<p class="muted">The engine's summary, the decrypted report and the PoC are published with the evidence once the submission is settled.</p>`);
    setHtml("commitcheck", html`<span class="muted">The report stays sealed until the submission is settled.</span>`);
    setHtml("reportbody", html`<p class="muted">The report stays sealed until the submission is settled.</p>`);
    return;
  }
  if (!r.doc) {
    setHtml("evsummary", html`<p class="muted">No readable evidence file.</p>`);
    setHtml("reportbody", html`<p class="muted">The report is not published.</p>`);
    return;
  }
  const files = evidenceFiles(url, r.doc).filter(([, u]) => safeHref(u));
  setHtml("evlinks", html`raw files: ${files.map(([n, u], i) => html`${i ? " · " : ""}<a href="${safeHref(u)}" target="_blank" rel="noopener noreferrer">${n}</a>`)}`);
  const engine = engineVerdict(r.doc);
  const ran = files.some(([n]) => n === "summary.md");
  await Promise.all([
    ran ? showSummary(url, current) : showWorkerVerdict(engine),
    ran ? checkCommitment(s, info, url, current) : Promise.resolve(setHtml("reportbody", html`<p class="muted">This report was judged before the engine ran, so its text is not published.</p>`)),
  ]);
}

async function showSummary(url, current) {
  const sumUrl = siblingUrl(url, "summary.md");
  try {
    const res = await fetch(sumUrl, getOpts);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    if (current()) setHtml("evsummary", renderMarkdown(text));
  } catch (e) {
    if (current()) setHtml("evsummary", html`<p class="muted">summary.md could not be loaded: ${e.message || String(e)}</p>`);
  }
}

function showWorkerVerdict(engine) {
  const reason = engine && typeof engine.reason === "string" ? engine.reason : null;
  setHtml("evsummary", html`<p class="muted">The engine did not run for this submission, so there is no summary.md.</p>
    ${reason ? html`<p>Worker verdict: ${renderInline(reason)}</p>` : ""}`);
}

/** Recompute the commitment from the published report.md (v2: bound to the hunter). */
async function checkCommitment(s, info, url, current) {
  const repUrl = siblingUrl(url, "report.md");
  const r = repUrl ? await loadFile(repUrl) : { error: "no report" };
  if (!current()) return;
  if (!r.bytes) {
    setHtml("commitcheck", html`<span class="muted">report.md is not published, so the commitment cannot be recomputed here.</span>`);
    setHtml("reportbody", html`<p class="muted">The report is not published.</p>`);
    return;
  }
  setHtml("reportbody", renderMarkdown(new TextDecoder().decode(r.bytes).replace(/^---\n([\s\S]*?)\n---\n/, "```\n$1\n```\n")));
  const got = await commitmentOf(r.bytes, s.hunter_id, info.major);
  if (!current()) return;
  const ok = got === String(s.commitment ?? "").toLowerCase();
  setHtml("commitcheck", ok
    ? html`<span class="ok-text">✓ the published report.md reproduces this commitment${info.major >= 2 ? " for this hunter" : ""}</span>`
    : html`<span class="bad-text">✗ the published report.md gives <code class="hash">${got}</code></span>`);
}

// ---------------------------------------------------------------- hunters

function bondFactor(bond, base) {
  try {
    const b = BigInt(bond);
    const k = BigInt(base);
    if (k === 0n) return "";
    if (b === k * 2n) return "×2";
    if (b === k) return "base";
    if (b * 2n === k) return "×½";
    if (b * 4n === k) return "×¼";
  } catch {
    // malformed amounts: no hint
  }
  return "";
}

function vaultCard(vault) {
  const w = vaultWindow(vault);
  const programs = Array.isArray(vault.allowed_programs)
    ? (vault.allowed_programs.length ? vault.allowed_programs.map((id, i) => html`${i ? ", " : ""}${progLink(id, `#${Number(id)}`)}`) : html`<span class="muted">none</span>`)
    : "any program";
  const item = (label, value, hint) => html`<div class="vi"><div class="vi-label">${label}</div><div class="vi-value">${value}</div>${hint ? html`<div class="vi-hint">${hint}</div>` : ""}</div>`;
  return html`
    <div class="panel vault">
      <div class="panel-head"><h3>Vault</h3><span class="muted small">get_vault · policy enforced on-chain for the hunter's agent key</span></div>
      <div class="vault-grid">
        ${item("balance", near(vault.balance))}
        ${vault.policy_set === true ? html`
          ${item("max bond", near(vault.max_bond_per_report), "per report")}
          ${item("max spend", near(vault.max_spend_per_day), "per 24 h window")}
          ${item("programs", programs)}
          ${item("spent in window", html`${near(w.spent)} <span class="muted small">of ${fmtNear(vault.max_spend_per_day)}</span>`, w.running
            ? html`resets ${deadline(w.end, "now (on the next vault submission)")}`
            : (isZero(vault.window_start) ? "no vault submission yet" : html`last window from ${fmtTime(vault.window_start)} has ended`))}`
        : item("policy", html`<span class="warn-text">not set</span>`, "vault submissions are refused until the hunter sets one")}
      </div>
      <p class="small muted note">The agent's function-call key may only call submit_report_from_vault, finalize and withdraw_pending. Changing the policy and withdrawing need 1 yoctoNEAR, which only the hunter's full-access key can attach.</p>
    </div>`;
}

async function huntersView() {
  document.title = "Hunters · ReplayCourt";
  const [info, programs] = await Promise.all([contractVersion(), listAll("list_programs")]);
  const v2 = info.major >= 2;
  const progById = new Map(programs.map((p) => [Number(p.id), p]));
  const subsByHunter = new Map();
  for (const p of programs) {
    for (const s of await listAll("list_submissions", { program_id: p.id })) {
      if (!subsByHunter.has(s.hunter_id)) subsByHunter.set(s.hunter_id, []);
      subsByHunter.get(s.hunter_id).push(s);
    }
  }
  const hunters = [...subsByHunter.keys()].sort();
  const reps = await Promise.all(hunters.map((h) => view("get_hunter", { account_id: h })));
  // v2 only: per-program stats (they set the bond) and the vault. A v1 contract has neither view.
  const extra = v2
    ? await Promise.all(hunters.map(async (h) => {
        const pids = [...new Set(subsByHunter.get(h).map((s) => Number(s.program_id)))].sort((a, b) => a - b);
        const [perProgram, vault] = await Promise.all([
          Promise.all(pids.map(async (pid) => {
            const [st, bond] = await Promise.all([
              view("get_hunter_in_program", { program_id: pid, account_id: h }).catch(() => null),
              view("required_bond", { program_id: pid, hunter_id: h }).catch(() => null),
            ]);
            return { pid, st, bond };
          })),
          view("get_vault", { account_id: h }).catch(() => null),
        ]);
        return { perProgram, vault };
      }))
    : hunters.map(() => ({ perProgram: [], vault: null }));
  const rows = hunters.map((h, i) => ({ h, r: reps[i] ?? {}, ...extra[i], subs: subsByHunter.get(h).sort((a, b) => a.id - b.id) }));
  rows.sort((a, b) => {
    try {
      const d = BigInt(b.r.earned ?? 0) - BigInt(a.r.earned ?? 0);
      return d > 0n ? 1 : d < 0n ? -1 : a.h.localeCompare(b.h);
    } catch {
      return 0;
    }
  });
  const statCells = (r) => html`
    <td class="num">${fmtInt(r.submissions)}</td>
    <td class="num ok-text">${fmtInt(r.valid)}</td>
    <td class="num ${Number(r.invalid) > 0 ? "bad-text" : ""}">${fmtInt(r.invalid)}</td>
    <td class="num">${fmtInt(r.duplicate)}</td>
    <td class="num">${fmtInt(r.needs_human)}</td>
    <td class="num">${near(r.earned)}</td>`;
  return html`
    ${crumbs(html`<a href="#/">Overview</a>`, "hunters")}
    <h1>Hunters</h1>
    ${v2
      ? html`<p class="lead small-lead">A hunter's bond in a program depends only on their record <strong>in that program</strong>: more invalid
        than valid reports double it, one valid report halves it, three valid and no invalid quarter it. The global numbers are for display only.</p>`
      : html`<p class="lead small-lead">Public reputation from <code>get_hunter</code> for every account that has
        submitted to a program on this contract. It changes the bond a hunter must post: more invalid
        than valid reports double it, one valid report halves it, three valid and no invalid quarter it.</p>`}
    ${rows.length === 0 ? html`<p class="muted">No hunters yet.</p>` : html`
    ${v2 ? html`<h2>Global</h2>` : ""}
    <div class="table-wrap">
      <table class="list">
        <thead><tr><th>Hunter</th><th class="num">Submissions</th><th class="num">Valid</th><th class="num">Invalid</th><th class="num">Duplicate</th><th class="num">Needs human</th><th class="num">Earned</th><th>Reports</th></tr></thead>
        <tbody>${rows.map(({ h, r, subs, vault }) => html`<tr>
          <td class="nowrap">${acct(h)}${vault ? html` ${vaultTag("this hunter has a vault")}` : ""}</td>
          ${statCells(r)}
          <td class="ids">${subs.map((s) => html`<a class="chip st-${own(STATUS, s.status) ? s.status : "unknown"}" href="#/submission/${Number(s.id)}" title="${s.title}">#${Number(s.id)} ${own(STATUS, s.status) ? s.status.replace("_", " ") : "?"}</a>`)}</td>
        </tr>`)}</tbody>
      </table>
    </div>
    ${v2 ? html`
    <h2>Per program and vault</h2>
    ${rows.map(({ h, perProgram, vault }) => html`
      <section class="card hunter-card">
        <header class="card-head"><h3>${acct(h)}</h3>${vault ? vaultTag("this hunter has a vault") : ""}</header>
        <div class="hunter-grid">
          <div class="table-wrap">
            <table class="list">
              <thead><tr><th>Program</th><th class="num">Subm.</th><th class="num">Valid</th><th class="num">Invalid</th><th class="num">Dup.</th><th class="num">Needs human</th><th class="num">Earned</th><th class="num" title="required_bond(program_id, hunter_id)">Bond now</th></tr></thead>
              <tbody>${perProgram.map(({ pid, st, bond }) => {
                const p = progById.get(pid);
                const factor = p && bond !== null ? bondFactor(bond, p.bond) : "";
                return html`<tr>
                  <td class="title-cell">${progLink(pid, p ? html`<span class="muted">#${pid}</span> ${p.name}` : undefined)}</td>
                  ${st ? statCells(st) : html`<td class="muted" colspan="6">get_hunter_in_program did not answer</td>`}
                  <td class="num">${bond !== null ? html`${near(bond)}${factor ? html` <span class="muted small">${factor}</span>` : ""}` : html`<span class="muted">–</span>`}</td>
                </tr>`;
              })}</tbody>
            </table>
          </div>
          ${vault ? vaultCard(vault) : ""}
        </div>
      </section>`)}` : ""}`}`;
}

function notFound(msg) {
  document.title = "Not found · ReplayCourt";
  return html`<h1>Not found</h1><p>${msg}</p><p><a href="#/">Back to the overview</a></p>`;
}

// ---------------------------------------------------------------- router, theme, CSP check

async function route() {
  const token = ++seq;
  const parts = location.hash.replace(/^#\/?/, "").split("/");
  const [name, arg] = parts;
  for (const a of document.querySelectorAll("[data-nav]")) {
    a.classList.toggle("active", a.dataset.nav === (name === "hunters" || name === "details" ? name : ""));
  }
  main.setAttribute("aria-busy", "true");
  main.innerHTML = String(html`<p class="loading">Loading from NEAR ${cfg.network}…</p>`);
  let result;
  try {
    if (!name) result = { content: await overview() };
    else if (name === "program" && /^\d{1,15}$/.test(arg ?? "")) result = { content: await programView(Number(arg)) };
    else if (name === "submission" && /^\d{1,15}$/.test(arg ?? "")) result = await submissionView(Number(arg));
    else if (name === "hunters") result = { content: await huntersView() };
    else if (name === "details") result = { content: await detailsView() };
    else result = { content: notFound("There is no such page.") };
  } catch (e) {
    result = {
      content: html`<div class="panel error"><h2>Could not read the contract</h2><p>${e.message || String(e)}</p>
        <p class="muted">Endpoints tried: ${cfg.rpc.join(", ")}. Reload the page to try again.</p></div>`,
    };
  }
  if (token !== seq) return;
  main.innerHTML = String(result.content);
  main.removeAttribute("aria-busy");
  window.scrollTo(0, 0);
  if (name) footer();
  else document.getElementById("footer").textContent = "";
  startTicker();
  if (result.after) result.after(token);
}

function footer() {
  const el = document.getElementById("footer");
  const ep = rpcState.endpoint ? new URL(rpcState.endpoint).host : "–";
  el.innerHTML = String(html`Read-only explorer. Contract ${acct(cfg.contractId)}${versionInfo ? html` (version ${versionInfo.version})` : ""} on NEAR ${cfg.network}, read via
    <span class="mono">${ep}</span> (fallback: ${cfg.rpc.map((u) => new URL(u).host).join(", ")}). Evidence files from
    <span class="mono">${new URL("runs/", new URL(cfg.evidenceBase, location.href)).href}</span>. Titles, names, reasons and
    evidence files are written by whoever submitted them and are shown as untrusted text.`);
}

const THEME_KEY = "replaycourt-theme";
function storedTheme() {
  try {
    return localStorage.getItem(THEME_KEY);
  } catch {
    return null;
  }
}
function effectiveTheme() {
  return document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
}
function applyTheme(t) {
  if (t === "dark" || t === "light") document.documentElement.dataset.theme = t;
  const btn = document.getElementById("theme");
  if (btn) {
    const next = effectiveTheme() === "dark" ? "light" : "dark";
    btn.textContent = next === "dark" ? "☾ Dark" : "☀ Light";
    btn.setAttribute("aria-label", `Switch to ${next} theme`);
  }
}

function cspCheck() {
  const meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  const policy = meta ? meta.content : "";
  const m = /(?:^|;)\s*connect-src\s+([^;]*)/.exec(policy);
  const allowed = m ? m[1].trim().split(/\s+/) : [];
  const needed = [...cfg.rpc.map((u) => new URL(u).origin), new URL(cfg.evidenceBase, location.href).origin];
  const missing = [...new Set(needed)].filter((o) => !(allowed.includes(o) || (o === location.origin && allowed.includes("'self'"))));
  if (missing.length) {
    const b = document.getElementById("banner");
    b.hidden = false;
    b.innerHTML = String(html`<div class="wrap">Configuration: add ${missing.join(" ")} to <code>connect-src</code> in the Content-Security-Policy of <code>web/index.html</code>; the browser blocks requests to hosts that are not listed there.</div>`);
  }
}

function init() {
  document.getElementById("net").textContent = cfg.network;
  const q = new URLSearchParams(location.search).get("theme");
  applyTheme(q === "dark" || q === "light" ? q : storedTheme());
  document.getElementById("theme").addEventListener("click", () => {
    const next = effectiveTheme() === "dark" ? "light" : "dark";
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {
      // private mode: theme just is not remembered
    }
    applyTheme(next);
  });
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => applyTheme());
  cspCheck();
  window.addEventListener("hashchange", route);
  route();
}

init();
