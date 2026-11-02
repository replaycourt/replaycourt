// ReplayCourt demo video - frame player.
// setup(storyboard, timeline, root) builds every scene from storyboard.json; seek(t) puts the
// page into the state of time t (seconds) and returns a signature string that changes whenever
// anything visible changes, so render.mjs can skip screenshots of unchanged frames.
// All texts, hashes and screenshot paths come from storyboard.json; nothing is hard-coded here.
"use strict";

const LOGO_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#2463eb"/><path d="M10 7v18M10 13c0-4 12-4 12 2v3M22 18l-3.5-3.5M22 18l3.5-3.5" fill="none" stroke="#fff" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>';
const ICONS = {
  hunter: '<svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><circle cx="24" cy="16" r="8"/><path d="M8 42c2-9 8-13 16-13s14 4 16 13"/></svg>',
  lock: '<svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="21" width="30" height="21" rx="4"/><path d="M15 21v-6a9 9 0 0 1 18 0v6"/><path d="M24 29v6"/></svg>',
  fork: '<svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><circle cx="14" cy="9" r="4"/><circle cx="34" cy="9" r="4"/><circle cx="24" cy="40" r="4"/><path d="M14 13v4c0 6 10 7 10 14v5M34 13v4c0 6-10 7-10 14"/></svg>',
};

let SIG = [];
let BUILT = [];
let TL = null;
let SB = null;
let ROOT = "";
const CAPTION = { el: null, text: null, cues: [] };

// ---------- helpers ----------
const clamp = (x, a = 0, b = 1) => Math.max(a, Math.min(b, x));
const ease = (p) => 1 - Math.pow(1 - p, 3);
const q = (x, n = 3) => Math.round(x * 10 ** n) / 10 ** n;
const prog = (t, t0, d) => ease(clamp((t - t0) / d));

function setStyle(el, prop, val) {
  if (!el.__s) el.__s = {};
  if (el.__s[prop] !== val) { el.style[prop] = val; el.__s[prop] = val; }
  SIG.push(val);
}
function setText(el, val) {
  if (el.__t !== val) { el.textContent = val; el.__t = val; }
  SIG.push(val);
}
function setClass(el, cls, on) {
  el.classList.toggle(cls, !!on);
  SIG.push(on ? 1 : 0);
}
function h(tag, cls, text) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (text !== undefined && text !== null) el.textContent = text;
  return el;
}
function add(parent, ...kids) { for (const k of kids) if (k) parent.appendChild(k); return parent; }
function svg(markup, cls) { const s = h("span", cls); s.innerHTML = markup; return s; }

// fade + rise in at t0; returns progress 0..1
function fadeIn(el, t, t0, d = 0.5, dy = 18) {
  const p = prog(t, t0, d);
  setStyle(el, "opacity", String(q(p)));
  setStyle(el, "transform", p >= 1 ? "none" : `translateY(${q((1 - p) * dy, 1)}px)`);
  return p;
}
// visible window [t0, t1) with cross-fades
function windowed(el, t, t0, t1, d = 0.35) {
  const vis = t >= t0 - 0.001 && t < t1;
  setStyle(el, "display", vis ? "block" : "none");
  if (!vis) return false;
  const p = Math.min(prog(t, t0, d), clamp((t1 - t) / d));
  setStyle(el, "opacity", String(q(p)));
  return true;
}

// time reference inside a scene: number | "cN" | "cN@frac" | "cN+sec" | "end-sec"
function T(scene, ref) {
  if (typeof ref === "number") return scene.start + ref;
  let m = /^end-([\d.]+)$/.exec(ref);
  if (m) return scene.end - parseFloat(m[1]);
  m = /^c(\d+)(?:@([\d.]+))?(?:\+([\d.]+))?$/.exec(ref);
  if (!m) throw new Error("bad time reference " + ref);
  const c = scene.cues[Number(m[1])];
  if (!c) throw new Error("no cue " + ref + " in scene " + scene.id);
  let x = c.start;
  if (m[2]) x += parseFloat(m[2]) * (c.end - c.start);
  if (m[3]) x += parseFloat(m[3]);
  return x;
}

// terminal block: typed command, then output lines
function terminal(spec) {
  const box = h("div", "term");
  const bar = add(h("div", "term-bar"), h("i"), h("i"), h("i"), h("span", null, spec.title || ""));
  const body = h("div", "term-body");
  const cmdLine = h("span", "line");
  const prompt = h("span", "prompt", "$ ");
  const cmd = h("span", "cmd");
  const caret = h("span", "caret");
  add(cmdLine, prompt, cmd, caret);
  if (spec.cmd) body.appendChild(cmdLine);
  const outs = (spec.out || []).map((s) => {
    const l = h("span", "line");
    // colour tx hashes and urls
    const m = /^(.*?)(tx [1-9A-HJ-NP-Za-km-z]{43,44}|https:\/\/\S+)(.*)$/.exec(s);
    if (m) add(l, document.createTextNode(m[1]), h("span", "tx", m[2]), document.createTextNode(m[3]));
    else l.textContent = s;
    body.appendChild(l);
    return l;
  });
  add(box, bar, body);
  return {
    el: box,
    update(t, tType, tOut, cps = 55) {
      const full = spec.cmd || "";
      const n = clamp(Math.floor((t - tType) * cps), 0, full.length);
      setText(cmd, full.slice(0, n));
      setStyle(caret, "display", n < full.length && t >= tType - 0.4 ? "inline-block" : "none");
      outs.forEach((l, i) => {
        const on = t >= tOut + i * 0.14 && n >= full.length;
        setStyle(l, "display", on ? "block" : "none");
      });
    },
  };
}

// browser-framed screenshot: crop, optional pan, highlight boxes (all in source-image pixels)
function shotPanel(spec, tl) {
  const shot = h("div", "shot");
  const bar = add(h("div", "shot-bar"), h("i"), h("i"), h("i"), h("span", null, spec.caption));
  const view = h("div", "shot-view");
  const layer = h("div", "shot-layer");
  const img = h("img");
  img.src = ROOT + spec.src;
  layer.appendChild(img);
  const hls = spec.highlights.map((b) => { const x = h("div", "hlbox"); layer.appendChild(x); return { el: x, b }; });
  view.appendChild(layer);
  add(shot, bar, view);
  let scale = 0;
  return {
    el: shot,
    update(t) {
      const c = spec.crop;
      if (!scale && view.clientWidth > 0 && img.naturalWidth > 0) {
        scale = view.clientWidth / c.w;
        view.style.height = Math.round(c.h * scale) + "px";
        img.style.width = img.naturalWidth * scale + "px";
        hls.forEach(({ el, b }) => {
          el.style.left = b.x * scale + "px";
          el.style.top = b.y * scale + "px";
          el.style.width = b.w * scale + "px";
          el.style.height = b.h * scale + "px";
        });
      }
      let y = c.y;
      for (const p of spec.pan || []) y += (p.y - y) * prog(t, T(tl, p.at), 0.8);
      setStyle(layer, "transform", `translate(${q(-c.x * scale, 1)}px, ${q(-y * scale, 1)}px)`);
      hls.forEach(({ el, b }) => setStyle(el, "opacity", String(q(prog(t, T(tl, b.at), 0.3)))));
    },
  };
}

// full-width strip under the cards or columns of a scene
function stripBlock(spec) {
  const strip = h("div", "card strip");
  const head = add(h("div", "strip-head"), h("span", "lbl", spec.label), h("span", "res", spec.result), h("span", "src", spec.source));
  const items = h("div", "strip-items");
  if (spec.columns) items.style.gridTemplateColumns = spec.columns;
  spec.items.forEach((x) => items.appendChild(h("div", "it", x)));
  return add(strip, head, items);
}

// ---------- scene builders ----------
const BUILDERS = {};

BUILDERS.problem = (d, tl) => {
  const el = h("div", "scene problem");
  const head = h("h1", "headline", d.headline);
  const facts = h("div", "facts");
  const factEls = d.facts.map((f) => {
    const c = add(h("div", "card fact"), h("div", "org", f.org), h("div", "big", f.big), h("blockquote", null, "“" + f.quote + "”"), h("div", "src", f.source));
    facts.appendChild(c);
    return c;
  });
  const lost = h("div", "card lost");
  const steps = h("div", "lost-steps");
  const stepEls = [];
  d.lost.steps.forEach((s, i) => {
    if (i) { const a = h("div", "lost-arrow", "→"); steps.appendChild(a); stepEls.push({ el: a, at: s.at }); }
    const st = add(h("div", "lost-step"), h("div", "date", s.date), h("div", "text", s.text));
    steps.appendChild(st);
    stepEls.push({ el: st, at: s.at });
  });
  add(lost, h("div", "lost-label", d.lost.label), steps, h("div", "src", d.lost.source));
  add(el, head, facts, lost);
  return {
    el,
    update(t) {
      // the headline is on screen from the very first frame (thumbnail): big and centred first,
      // then it moves up when the facts come in
      setStyle(head, "opacity", "1");
      const mv = prog(t, T(tl, d.facts[0].at) - 0.55, 0.6);
      setStyle(head, "transformOrigin", "0 0");
      setStyle(head, "transform", mv >= 1 ? "none" : `translateY(${q((1 - mv) * 250, 1)}px) scale(${q(1 + 0.12 * (1 - mv))})`);
      d.facts.forEach((f, i) => fadeIn(factEls[i], t, T(tl, f.at)));
      fadeIn(lost, t, T(tl, d.lost.at));
      stepEls.forEach((s) => fadeIn(s.el, t, T(tl, s.at), 0.5, 10));
    },
  };
};

BUILDERS.idea = (d, tl) => {
  const el = h("div", "scene idea");
  const title = add(h("div", "idea-title"), svg(LOGO_SVG, "logo"), h("span", null, d.title));
  const sub = h("div", "idea-sub", d.subtitle);
  const flow = h("div", "flow");
  const parts = [];
  d.nodes.forEach((n, i) => {
    if (i) { const a = h("div", "arrow", "→"); flow.appendChild(a); parts.push({ el: a, at: n.at }); }
    const c = add(h("div", "card node"), svg(ICONS[n.icon] || "", "ico"), h("div", "t", n.title), h("div", "s", n.sub));
    flow.appendChild(c);
    parts.push({ el: c, at: n.at });
  });
  const arrow = h("div", "arrow", "→");
  flow.appendChild(arrow);
  parts.push({ el: arrow, at: d.outcomes[0].at });
  const outs = h("div", "outcomes");
  d.outcomes.forEach((o) => {
    const c = add(h("div", "outcome " + o.kind), h("b", null, o.title), h("span", null, o.sub));
    outs.appendChild(c);
    parts.push({ el: c, at: o.at });
  });
  flow.appendChild(outs);
  add(el, title, sub, flow);
  return {
    el,
    update(t) {
      fadeIn(title, t, T(tl, "c0") - 0.25);
      fadeIn(sub, t, T(tl, "c0@0.35"));
      parts.forEach((p) => fadeIn(p.el, t, T(tl, p.at)));
    },
  };
};

BUILDERS.moment = (d, tl) => {
  const el = h("div", "scene moment");
  // progress rail
  const rail = h("aside", "rail");
  const railEls = d.rail.map((r, i) => {
    const s = add(h("div", "rail-step"), h("div", "dot", String(i + 1)), add(h("div"), h("div", "t", r.title), h("div", "s", r.sub)));
    rail.appendChild(s);
    return s;
  });
  el.appendChild(rail);

  // beat 1: submit
  const bSubmit = h("section", "beat");
  const rep = h("div", "card report");
  const fm = h("div", "fm");
  d.submit.report.lines.forEach(([k, v]) => add(fm, add(h("div"), h("span", "k", k + ": "), h("span", null, v))));
  add(rep, h("div", "file", d.submit.report.file), fm, h("div", "note", d.submit.report.note));
  const term1 = terminal(d.submit.terminal);
  term1.el.style.marginTop = "16px";
  const chips = h("div", "chips");
  chips.appendChild(h("span", "lbl", d.submit.chips.label));
  const chipEls = d.submit.chips.items.map((c) => { const x = h("span", "c" + (/^bond/.test(c) ? " bond" : ""), c); chips.appendChild(x); return x; });
  add(bSubmit, rep, term1.el, chips, h("div", "source", d.submit.source));

  // beat 2: replay
  const bReplay = h("section", "beat");
  const term2 = terminal(d.replay.terminal);
  const eng = h("div", "card engine");
  d.replay.engine.rows.forEach(([k, v]) => add(eng, add(h("div", "row"), h("span", "k", k), h("span", null, v))));
  const prints = add(h("div", "prints"), h("div", "lbl", d.replay.pocPrints.label), h("div", "ln", d.replay.pocPrints.line));
  const trace = h("div", "card trace");
  const table = h("table");
  const thead = h("tr");
  d.replay.trace.head.forEach((c) => thead.appendChild(h("th", null, c)));
  table.appendChild(thead);
  d.replay.trace.rows.forEach((r) => {
    const tr = h("tr");
    r.forEach((c, i) => {
      const td = h("td", null, c);
      if (i === 3) td.className = "num " + (c.startsWith("+") ? "plus" : "minus");
      if (i === 4 && c !== "–") td.className = "num minus";
      tr.appendChild(td);
    });
    table.appendChild(tr);
  });
  add(trace, h("div", "lbl", d.replay.trace.label), table);
  add(bReplay, term2.el, eng, prints, trace, h("div", "source", d.replay.source));

  // beat 3: verdict
  const bVerdict = h("section", "beat");
  const badge = add(h("div", "badge-big"), h("span", null, d.verdict.badge[0]), h("span", null, d.verdict.badge[1]));
  const logT = terminal({ title: "verifier worker", cmd: "", out: [d.verdict.logLine] });
  logT.el.style.marginTop = "22px";
  const fields = h("div", "card fields");
  d.verdict.fields.forEach(([k, v]) => add(fields, add(h("div", "row"), h("span", "k", k), h("span", "v", v))));
  const perm = h("div", "card perm");
  const code = h("code");
  // emphasise the method list
  const pm = /^(.*?)("method_names": ?\[[^\]]*\])(.*)$/.exec(d.verdict.permission);
  if (pm) add(code, document.createTextNode(pm[1]), h("b", null, pm[2]), document.createTextNode(pm[3]));
  else code.textContent = d.verdict.permission;
  add(perm, h("div", "lbl", d.verdict.permissionLabel), code, h("div", "note", d.verdict.permissionNote));
  add(bVerdict, badge, logT.el, fields, perm, h("div", "source", d.verdict.source));

  // beat 4: paid
  const bPaid = h("section", "beat");
  const term4 = terminal(d.paid.terminal);
  const shot = shotPanel(d.paid.screenshot, tl);
  add(bPaid, term4.el, shot.el, h("div", "source", d.paid.source));

  add(el, bSubmit, bReplay, bVerdict, bPaid);
  const beats = [
    { el: bSubmit, at: d.submit.at },
    { el: bReplay, at: d.replay.at },
    { el: bVerdict, at: d.verdict.at },
    { el: bPaid, at: d.paid.at },
  ];
  return {
    el,
    update(t) {
      // screenshot geometry (needs layout once the beat is displayed)
      const starts = beats.map((b, i) => (i === 0 ? tl.start : T(tl, b.at)));
      beats.forEach((b, i) => windowed(b.el, t, starts[i], i + 1 < beats.length ? starts[i + 1] : tl.end + 1));
      const active = starts.reduce((acc, s, i) => (t >= s ? i : acc), 0);
      d.rail.forEach((r, i) => {
        const on = t >= T(tl, r.at);
        setClass(railEls[i], "active", i === active && on);
        setClass(railEls[i], "done", i < active);
        setStyle(railEls[i], "opacity", i <= active || i === 0 ? "1" : "0.55");
      });
      // submit
      fadeIn(rep, t, T(tl, d.submit.at) - 0.2);
      fadeIn(term1.el, t, T(tl, d.submit.terminal.at) - 0.3);
      term1.update(t, T(tl, d.submit.terminal.at), T(tl, d.submit.terminal.outAt), 70);
      chipEls.forEach((c, i) => fadeIn(c, t, T(tl, d.submit.chips.at) + i * 0.25, 0.4, 8));
      fadeIn(chips.firstChild, t, T(tl, d.submit.chips.at), 0.4, 8);
      // replay
      const r0 = T(tl, d.replay.at);
      term2.update(t, r0 + 0.1, r0 + 0.1 + (d.replay.terminal.cmd.length / 55) + 0.2, 55);
      fadeIn(eng, t, T(tl, d.replay.engine.at));
      fadeIn(prints, t, T(tl, d.replay.pocPrints.at));
      fadeIn(trace, t, T(tl, d.replay.trace.at));
      // verdict
      const v0 = T(tl, d.verdict.at);
      const pb = prog(t, v0, 0.45);
      setStyle(badge, "opacity", String(q(pb)));
      setStyle(badge, "transform", `scale(${q(0.92 + 0.08 * pb)})`);
      fadeIn(logT.el, t, v0 + 0.35);
      logT.update(t, v0, v0 + 0.5);
      fadeIn(fields, t, v0 + 0.8);
      fadeIn(perm, t, v0 + 1.4);
      // paid
      const p0 = T(tl, d.paid.at);
      term4.update(t, p0 - 0.1, p0 - 0.1 + d.paid.terminal.cmd.length / 60 + 0.15, 60);
      fadeIn(shot.el, t, p0 + 0.2);
      if (bPaid.style.display === "block") shot.update(t);
    },
  };
};

BUILDERS.spam = (d, tl) => {
  const el = h("div", "scene spam");
  const wrap = h("div", "cards");
  const cards = d.cards.map((c) => {
    const card = h("div", "card scard " + c.kind);
    add(card, add(h("div", "head"), h("span", null, c.head), h("span", "kind", c.kind)), h("div", "ttl", c.title));
    const bars = [];
    const addRows = () => (c.rows || []).forEach((r) => add(card, add(h("div", "row"), h("span", "k", r.label), h("span", "v " + (r.style || ""), r.value))));
    if (!c.rowsAfterBars) addRows();
    if (c.bars) {
      const bw = h("div", "bars");
      c.bars.forEach((b) => {
        const fill = h("div", "fill");
        const row = add(h("div", "bar" + (b.value >= 0.75 ? " hit" : "")), h("span", "k", b.label), add(h("div", "track"), fill), h("span", "val", b.value.toFixed(2)));
        bw.appendChild(row);
        bars.push({ fill, v: b.value });
      });
      add(card, bw, h("div", "bars-note", c.barsNote));
    }
    if (c.rowsAfterBars) addRows();
    if (c.order) { const o = h("div", "order"); c.order.forEach((x) => o.appendChild(h("div", null, x))); card.appendChild(o); }
    if (c.quote) card.appendChild(add(h("div", "squote"), h("div", "lbl", c.quoteLabel || ""), h("div", null, "“" + c.quote + "”")));
    const verdict = h("div", "sverdict", c.verdict);
    const tx = h("div", "tx", c.tx);
    add(card, verdict, tx);
    wrap.appendChild(card);
    return { card, verdict, tx, bars, c };
  });
  const strip = d.strip ? stripBlock(d.strip) : null;
  if (strip) wrap.classList.add("with-strip");
  add(el, wrap, strip, h("div", "source", d.source));
  return {
    el,
    update(t) {
      if (strip) fadeIn(strip, t, T(tl, d.strip.at) - 0.2);
      cards.forEach(({ card, verdict, tx, bars, c }) => {
        const t0 = T(tl, c.at);
        fadeIn(card, t, t0 - 0.2);
        bars.forEach((b, i) => setStyle(b.fill, "width", q(100 * b.v * prog(t, t0 + 0.4 + i * 0.25, 0.7), 1) + "%"));
        fadeIn(verdict, t, T(tl, c.verdictAt), 0.4, 10);
        fadeIn(tx, t, T(tl, c.verdictAt) + 0.3, 0.4, 6);
      });
    },
  };
};

BUILDERS.security = (d, tl) => {
  const el = h("div", "scene security");
  const wrap = h("div", "cols cols-" + d.cols.length);
  const cols = d.cols.map((c) => {
    const col = add(h("div", "card col"), h("h3", null, c.title), h("div", "intro", c.intro));
    if (c.rows) {
      const kv = h("div", "kv");
      c.rows.forEach(([k, v]) => add(kv, h("div", "k", k), h("div", "v", v)));
      col.appendChild(kv);
    }
    if (c.attempts) c.attempts.forEach((a) => add(col, add(h("div", "att"), h("div", "try", a.try), h("div", "err", a.error))));
    if (c.code) col.appendChild(h("div", "codebox", c.code));
    const late = [];
    if (c.call) late.push(h("div", "call", c.call));
    if (c.result) { const r = h("div", "res" + (c.ok ? " ok" : ""), c.result.join("\n")); r.style.whiteSpace = "pre-wrap"; late.push(r); }
    if (c.reason) late.push(h("div", "reason", "“" + c.reason + "”"));
    if (c.note) late.push(h("div", "extra", c.note));
    late.forEach((x) => col.appendChild(x));
    if (c.footer) col.appendChild(h("div", "foot", c.footer));
    col.appendChild(h("div", "src", c.source));
    wrap.appendChild(col);
    return { col, late, c };
  });
  el.appendChild(wrap);
  const strip = d.strip ? stripBlock(d.strip) : null;
  if (strip) { wrap.classList.add("with-strip"); el.appendChild(strip); }
  return {
    el,
    update(t) {
      cols.forEach(({ col, late, c }) => {
        fadeIn(col, t, T(tl, c.at) - 0.2);
        if (c.resultAt) late.forEach((x) => fadeIn(x, t, T(tl, c.resultAt), 0.4, 6));
      });
      if (strip) fadeIn(strip, t, T(tl, d.strip.at) - 0.2);
    },
  };
};

BUILDERS.dispute = (d, tl) => {
  const el = h("div", "scene dispute");
  const left = h("div", "dleft");
  const steps = d.steps.map((s) => {
    const row = add(h("div", "dstep" + (s.kind ? " " + s.kind : "")), h("div", "time", s.time),
      add(h("div", "body"), h("div", "txt", s.text), s.detail ? h("div", "det", s.detail) : null, s.tx ? h("div", "tx", s.tx) : null));
    left.appendChild(row);
    return { row, s };
  });
  const msg = h("div", "dmsg", d.message.text);
  left.appendChild(msg);
  const shot = shotPanel(d.screenshot, tl);
  shot.el.classList.add("dshot");
  add(el, left, shot.el, h("div", "source", d.source));
  return {
    el,
    update(t) {
      steps.forEach(({ row, s }) => fadeIn(row, t, T(tl, s.at) - 0.1));
      fadeIn(msg, t, T(tl, d.message.at) - 0.1);
      fadeIn(shot.el, t, T(tl, d.screenshot.at) - 0.2);
      shot.update(t);
    },
  };
};

BUILDERS.near = (d, tl) => {
  const el = h("div", "scene near");
  const tiles = h("div", "tiles");
  tiles.style.gridTemplateColumns = `repeat(${d.tiles.length}, 1fr)`;
  const tileEls = d.tiles.map((x, i) => {
    const tile = add(h("div", "card tile"), h("div", "n", "0" + (i + 1)), h("h3", null, x.title), h("p", null, x.text));
    tiles.appendChild(tile);
    return tile;
  });
  const cta = add(h("div", "cta"), h("div", "repo", d.cta.repo), h("div", "sub", d.cta.sub));
  const qn = h("div", "question", d.question.text);
  add(el, tiles, cta, qn);
  return {
    el,
    update(t) {
      d.tiles.forEach((x, i) => fadeIn(tileEls[i], t, T(tl, x.at) - 0.15));
      fadeIn(cta, t, T(tl, d.cta.at) - 0.2);
      fadeIn(qn, t, T(tl, d.question.at) - 0.2);
    },
  };
};

// ---------- public API ----------
window.setup = async function setup(storyboard, timeline, root) {
  SB = storyboard;
  TL = timeline;
  ROOT = root;
  document.getElementById("logo").innerHTML = LOGO_SVG;
  document.getElementById("datanote").textContent = SB.meta.dataNote;
  const host = document.getElementById("scenes");
  BUILT = SB.scenes.map((s, i) => {
    const tl = TL.scenes.find((x) => x.id === s.id);
    if (!tl) throw new Error("scene " + s.id + " missing in timeline");
    const b = BUILDERS[s.type](s, tl);
    host.appendChild(b.el);
    return { idx: i, spec: s, tl, el: b.el, update: b.update };
  });
  CAPTION.el = document.getElementById("caption");
  CAPTION.text = document.getElementById("caption-text");
  CAPTION.cues = TL.scenes.flatMap((s) => s.cues);
  await document.fonts.ready;
  await Promise.all([...document.images].map((im) => (im.complete && im.naturalWidth ? null : im.decode())));
  // lay out everything once (some geometry needs display:block)
  for (const b of BUILT) { b.el.style.display = "block"; }
  for (const b of BUILT) { b.update(b.tl.start + 0.01); b.update(b.tl.end - 0.01); }
  for (const b of BUILT) { b.el.style.display = "none"; b.el.__s = {}; }
  return { scenes: BUILT.length, images: document.images.length };
};

window.seek = function seek(t) {
  SIG = [];
  const n = BUILT.length;
  let current = BUILT[0];
  BUILT.forEach((b, i) => {
    const last = i === n - 1;
    const vis = t >= b.tl.start && (t < b.tl.end || last);
    setStyle(b.el, "display", vis ? "block" : "none");
    if (!vis) return;
    current = b;
    const fin = i === 0 ? 1 : clamp((t - b.tl.start) / 0.35);
    const fout = last ? 1 : clamp((b.tl.end - t) / 0.35);
    setStyle(b.el, "opacity", String(q(Math.min(fin, fout))));
    b.update(t);
  });
  setStyle(document.getElementById("datanote"), "opacity", current.spec.showDataNote ? "1" : "0");
  setText(document.getElementById("chapter-num"), `${current.idx + 1} / ${n}`);
  setText(document.getElementById("chapter-name"), current.spec.chapter);
  const cue = CAPTION.cues.find((c) => t >= c.start && t < c.showUntil);
  setStyle(CAPTION.el, "display", cue ? "flex" : "none");
  setText(CAPTION.text, cue ? cue.caption : "");
  return SIG.join("|");
};

// manual preview: open index.html?preview (with timeline.json and storyboard.json reachable via http)
if (location.search.includes("preview")) {
  (async () => {
    const sb = await (await fetch("../storyboard.json")).json();
    const tl = await (await fetch(new URLSearchParams(location.search).get("timeline") || "timeline.json")).json();
    await window.setup(sb, tl, "../../../");
    const r = add(h("input"));
    r.type = "range"; r.min = 0; r.max = tl.duration; r.step = 1 / 30; r.value = 0;
    Object.assign(r.style, { position: "fixed", left: "20px", right: "20px", bottom: "4px", zIndex: 9 });
    r.oninput = () => window.seek(Number(r.value));
    document.body.appendChild(r);
    window.seek(0);
  })();
}
