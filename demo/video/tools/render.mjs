#!/usr/bin/env node
// Render the frames of the demo video with headless Chrome (DevTools protocol over a pipe, no port).
//
//   node render.mjs --work <dir> [--chrome <path>] [--stills 3.5,40,70]
//
// Reads <work>/timeline.json (from voice.py) and ../storyboard.json, opens scenes/index.html,
// calls setup() once and seek(t) for every frame. A frame whose state signature did not change is
// not captured again; identical screenshots are stored once. Output:
//   <work>/frames/*.png and <work>/frames/manifest.txt (one PNG path per video frame)
// With --stills it only writes <work>/stills/t<sec>.png for the given times (quick look).
// Node >= 22, no npm packages.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const VIDEO = path.resolve(HERE, "..");
const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith("--") ? [...acc, [a.slice(2), all[i + 1] && !all[i + 1].startsWith("--") ? all[i + 1] : true]] : acc), []),
);
const WORK = path.resolve(args.work || "work");
const CHROME = args.chrome || process.env.CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

const storyboard = JSON.parse(fs.readFileSync(path.join(VIDEO, "storyboard.json"), "utf8"));
const timeline = JSON.parse(fs.readFileSync(path.join(WORK, "timeline.json"), "utf8"));
const { width, height } = storyboard.meta;

// ---- Chrome with --remote-debugging-pipe: fd 3 = commands in, fd 4 = replies out, \0-separated ----
const profile = fs.mkdtempSync(path.join(WORK, "chrome-profile-"));
const chrome = spawn(CHROME, [
  "--headless=new", "--remote-debugging-pipe", `--user-data-dir=${profile}`,
  "--no-first-run", "--no-default-browser-check", "--disable-extensions", "--disable-background-networking",
  "--disable-sync", "--disable-component-update", "--mute-audio", "--hide-scrollbars",
  "--force-device-scale-factor=1", "--force-color-profile=srgb", "--font-render-hinting=none",
  `--window-size=${width},${height}`, "about:blank",
], { stdio: ["ignore", "ignore", "pipe", "pipe", "pipe"] });
let chromeErr = "";
chrome.stderr.on("data", (b) => { chromeErr = (chromeErr + b.toString()).slice(-4000); });
const toChrome = chrome.stdio[3];
const fromChrome = chrome.stdio[4];

let seq = 0;
const pending = new Map();
const events = [];
let buf = Buffer.alloc(0);
fromChrome.on("data", (chunk) => {
  buf = Buffer.concat([buf, chunk]);
  let i;
  while ((i = buf.indexOf(0)) >= 0) {
    const msg = JSON.parse(buf.subarray(0, i).toString("utf8"));
    buf = buf.subarray(i + 1);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
    } else if (msg.method) events.push(msg);
  }
});
function send(method, params = {}, sessionId) {
  const id = ++seq;
  const msg = { id, method, params };
  if (sessionId) msg.sessionId = sessionId;
  toChrome.write(JSON.stringify(msg) + "\0");
  return new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
}
async function waitEvent(method, timeoutMs = 20000) {
  const t0 = Date.now();
  for (;;) {
    const i = events.findIndex((e) => e.method === method);
    if (i >= 0) return events.splice(i, 1)[0];
    if (Date.now() - t0 > timeoutMs) throw new Error("timeout waiting for " + method);
    await new Promise((r) => setTimeout(r, 20));
  }
}
let closed = false;
async function shutdown() {
  if (closed) return;
  closed = true;
  try { await Promise.race([send("Browser.close"), new Promise((r) => setTimeout(r, 3000))]); } catch {}
  if (chrome.exitCode === null) chrome.kill("SIGKILL");
  fs.rmSync(profile, { recursive: true, force: true });
}
process.on("SIGINT", () => shutdown().then(() => process.exit(130)));
process.on("SIGTERM", () => shutdown().then(() => process.exit(143)));

async function main() {
  const { targetInfos } = await send("Target.getTargets");
  let page = targetInfos.find((t) => t.type === "page");
  if (!page) page = { targetId: (await send("Target.createTarget", { url: "about:blank" })).targetId };
  const { sessionId } = await send("Target.attachToTarget", { targetId: page.targetId, flatten: true });
  const S = (m, p) => send(m, p, sessionId);
  await S("Page.enable");
  await S("Runtime.enable");
  await S("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: false });
  await S("Emulation.setDefaultBackgroundColorOverride", { color: { r: 10, g: 14, b: 22, a: 1 } });
  const url = pathToFileURL(path.join(VIDEO, "scenes", "index.html")).href;
  await S("Page.navigate", { url });
  await waitEvent("Page.loadEventFired");
  const evalJs = async (expression, awaitPromise = false) => {
    const r = await S("Runtime.evaluate", { expression, awaitPromise, returnByValue: true });
    if (r.exceptionDetails) throw new Error("page error: " + JSON.stringify(r.exceptionDetails).slice(0, 1500));
    return r.result.value;
  };
  const info = await evalJs(`setup(${JSON.stringify(storyboard)}, ${JSON.stringify(timeline)}, "../../../")`, true);
  const nextPaint = () => evalJs("new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(1))))", true);
  const capture = async () => Buffer.from((await S("Page.captureScreenshot", { format: "png", optimizeForSpeed: true, captureBeyondViewport: false })).data, "base64");

  if (args.stills) {
    const dir = path.join(WORK, "stills");
    fs.mkdirSync(dir, { recursive: true });
    for (const s of String(args.stills).split(",")) {
      await evalJs(`seek(${Number(s)})`);
      await nextPaint();
      const file = path.join(dir, `t${s}.png`);
      fs.writeFileSync(file, await capture());
      console.log(file);
    }
    return;
  }

  const fps = timeline.fps;
  const frames = timeline.frames;
  const dir = path.join(WORK, "frames");
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  const manifest = [];
  const byHash = new Map();
  let prevSig = null;
  let prevFile = null;
  let captured = 0;
  const t0 = Date.now();
  for (let i = 0; i < frames; i++) {
    const sig = await evalJs(`seek(${i / fps})`);
    if (sig !== prevSig || prevFile === null) {
      await nextPaint();
      const png = await capture();
      captured++;
      const hash = createHash("sha1").update(png).digest("hex");
      let file = byHash.get(hash);
      if (!file) {
        file = path.join(dir, `f${String(i).padStart(5, "0")}.png`);
        fs.writeFileSync(file, png);
        byHash.set(hash, file);
      }
      prevFile = file;
      prevSig = sig;
    }
    manifest.push(prevFile);
    if (i % 300 === 0) console.log(`frame ${i}/${frames}  captured ${captured}  unique ${byHash.size}  ${((Date.now() - t0) / 1000).toFixed(0)} s`);
  }
  fs.writeFileSync(path.join(dir, "manifest.txt"), manifest.join("\n") + "\n");
  console.log(`done: ${frames} frames, ${captured} captured, ${byHash.size} unique PNGs, ${((Date.now() - t0) / 1000).toFixed(0)} s; page ${JSON.stringify(info)}`);
}

main()
  .then(shutdown)
  .catch(async (e) => {
    console.error(e.stack || String(e));
    if (chromeErr) console.error("chrome stderr (tail):\n" + chromeErr);
    await shutdown();
    process.exit(1);
  });
