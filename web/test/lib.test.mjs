// Escaping and parsing helpers of the explorer. Run from the repository root: node --test web/test/*.test.mjs
import assert from "node:assert/strict";
import { test } from "node:test";
import { contractFromQuery, esc, evidenceUrl, fmtDuration, fmtNear, fmtTime, html, renderInline, renderMarkdown, safeHref, sha256Hex, siblingUrl } from "../lib.js";

const HOSTILE = `<img src=x onerror="alert(1)"><script>alert('x')</script>\`&`;

test("html`` escapes every interpolated value, including attribute breakouts", () => {
  const out = String(html`<a title="${HOSTILE}">${HOSTILE}</a>`);
  assert.ok(!out.includes("<img"));
  assert.ok(!out.includes("<script"));
  assert.ok(!/title="[^"]*"[^>]*onerror/.test(out), out);
  assert.equal(out, `<a title="${esc(HOSTILE)}">${esc(HOSTILE)}</a>`);
  assert.equal(esc(`"'<>&\``), "&quot;&#39;&lt;&gt;&amp;&#96;");
});

test("html`` nests safely: arrays and inner html`` are kept, plain strings escaped", () => {
  const items = ["<b>", "ok"];
  assert.equal(String(html`<ul>${items.map((i) => html`<li>${i}</li>`)}</ul>`), "<ul><li>&lt;b&gt;</li><li>ok</li></ul>");
  assert.equal(String(html`${null}${undefined}${false}${0}`), "0");
});

test("renderMarkdown never emits markup from its input", () => {
  const H = HOSTILE.replace("`", ""); // a backtick would open a code span
  const md = [
    `# Title ${HOSTILE}`,
    `Text with **bold ${H}** and \`code ${H}\` and [link](javascript:alert(1)) <iframe src=x>`,
    `- item ${HOSTILE}`,
    `  - nested <svg onload=alert(1)>`,
    `| a | b |`,
    `|---|---|`,
    `| ${HOSTILE} | <b>x</b> |`,
    "```",
    `</code></pre><script>alert(1)</script>`,
    "```",
  ].join("\n");
  const out = String(renderMarkdown(md));
  for (const bad of ["<img", "<script", "<iframe", "<svg", "<b>", 'href="javascript']) assert.ok(!out.includes(bad), `${bad} in ${out}`);
  assert.match(out, /<h3>Title &lt;img/);
  assert.match(out, /<strong>bold &lt;img/);
  assert.match(out, /<code>code &lt;img/);
  assert.match(out, /<ul><li>item &lt;img[^]*<ul><li>nested &lt;svg/);
  assert.match(out, /<table class="md"><thead><tr><th>a<\/th><th>b<\/th><\/tr><\/thead><tbody><tr><td>&lt;img/);
  assert.match(out, /<pre><code>&lt;\/code&gt;&lt;\/pre&gt;&lt;script&gt;/);
});

test("renderInline: code spans and bold only", () => {
  assert.equal(String(renderInline("PoC `testDrain()` <x> **ok**")), "PoC <code>testDrain()</code> &lt;x&gt; <strong>ok</strong>");
});

test("evidenceUrl resolves repository paths below runs/ and refuses everything else", () => {
  const page = "http://127.0.0.1:8000/web/index.html";
  assert.equal(evidenceUrl("runs/testnet/c/0/verdict.json", "../", page).href, "http://127.0.0.1:8000/runs/testnet/c/0/verdict.json");
  assert.equal(evidenceUrl("runs/a/verdict.json", "https://raw.example/o/r/main/", page).href, "https://raw.example/o/r/main/runs/a/verdict.json");
  for (const bad of ["", "javascript:alert(1)", "data:text/plain,x", "http://plain.example/v.json", "https://evidence.example/v.json", "/etc/passwd", "../../x.json", "runs/../../x", "a b.json", "x.json?y", "\\\\host\\share"]) {
    assert.equal(evidenceUrl(bad, "../", page), null, bad);
  }
  const v = evidenceUrl("runs/a/verdict.json", "../", page);
  assert.equal(siblingUrl(v, "summary.md").href, "http://127.0.0.1:8000/runs/a/summary.md");
  assert.equal(siblingUrl(evidenceUrl("runs/a/evidence.json", "../", page), "report.md").href, "http://127.0.0.1:8000/runs/a/report.md");
  assert.equal(siblingUrl(evidenceUrl("runs/a/other.json", "../", page), "summary.md"), null);
});

test("safeHref allows only http(s)", () => {
  assert.equal(safeHref("https://testnet.nearblocks.io/address/a.testnet"), "https://testnet.nearblocks.io/address/a.testnet");
  assert.equal(safeHref("javascript:alert(1)"), null);
  assert.equal(safeHref("data:text/html,x"), null);
});

test("formatting: NEAR amounts, nanosecond timestamps, durations", () => {
  assert.equal(fmtNear("400000000000000000000000"), "0.4");
  assert.equal(fmtNear("1512650000000000000000000"), "1.5126");
  assert.equal(fmtNear("0"), "0");
  assert.equal(fmtNear("1"), "<0.0001");
  assert.equal(fmtNear("not a number"), "?");
  assert.equal(fmtTime("1793612272694108747"), "2026-11-02 09:37:52 UTC");
  assert.equal(fmtDuration(60), "60 s");
  assert.equal(fmtDuration(86400), "1 d");
  assert.equal(fmtDuration(604800), "7 d");
});

test("sha256Hex matches a known vector", async () => {
  assert.equal(await sha256Hex(new TextEncoder().encode("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});

test("?contract= selects another deployment only if it is a valid account id", () => {
  assert.equal(contractFromQuery("?contract=contract.example.testnet", "x.testnet"), "contract.example.testnet");
  assert.equal(contractFromQuery("", "x.testnet"), "x.testnet");
  assert.equal(contractFromQuery("?theme=dark", "x.testnet"), "x.testnet");
  for (const bad of ["<script>", "UPPER.testnet", "a", "a..b", "x".repeat(65), "evil.testnet\"onload=1"]) {
    assert.equal(contractFromQuery("?contract=" + encodeURIComponent(bad), "x.testnet"), "x.testnet", bad);
  }
});
