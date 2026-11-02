import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, describe, it } from "node:test";
import { displayPath, readAllowedReport, resolveAllowedDirs } from "../src/paths.ts";
import { cleanup, tmpDir } from "./helpers.ts";

after(cleanup);

function setup() {
  const root = tmpDir();
  const reports = path.join(root, "reports");
  fs.mkdirSync(path.join(reports, "sub"), { recursive: true });
  fs.mkdirSync(path.join(reports, ".hidden"));
  fs.writeFileSync(path.join(reports, "a.md"), "# A\n");
  fs.writeFileSync(path.join(reports, "sub", "b.markdown"), "# B\n");
  fs.writeFileSync(path.join(reports, ".env.md"), "SECRET=1\n");
  fs.writeFileSync(path.join(reports, ".hidden", "c.md"), "# C\n");
  fs.writeFileSync(path.join(reports, "big.md"), "x".repeat(2000));
  fs.writeFileSync(path.join(reports, "script.sh"), "echo\n");
  const secret = path.join(root, "secret.json");
  fs.writeFileSync(secret, '{"private_key":"ed25519:xyz"}');
  fs.writeFileSync(path.join(root, "outside.md"), "# outside\n");
  fs.symlinkSync(path.join(root, "outside.md"), path.join(reports, "link.md"));
  fs.symlinkSync(secret, path.join(reports, "key.md"));
  fs.symlinkSync(root, path.join(reports, "up"));
  const dirs = resolveAllowedDirs([reports]);
  return { root, reports, dirs, secret };
}

describe("report_path allow-list", () => {
  it("reads files inside the directory, relative or absolute", () => {
    const { reports, dirs } = setup();
    const r1 = readAllowedReport("a.md", dirs, 1000);
    assert.equal(r1.ok, true);
    assert.equal(r1.ok && r1.bytes.toString(), "# A\n");
    assert.equal(readAllowedReport(path.join(reports, "sub", "b.markdown"), dirs, 1000).ok, true);
    assert.equal(readAllowedReport("sub/../a.md", dirs, 1000).ok, true);
  });

  const refused = (r: ReturnType<typeof readAllowedReport>) => (r.ok ? "ok" : r.rule);

  it("refuses ../ escapes and absolute paths outside", () => {
    const { dirs, secret } = setup();
    assert.equal(refused(readAllowedReport("../outside.md", dirs, 1000)), "path_not_allowed");
    assert.equal(refused(readAllowedReport(secret, dirs, 1000)), "path_not_allowed");
    assert.equal(refused(readAllowedReport("/etc/hosts", dirs, 1000)), "path_not_allowed");
    assert.equal(refused(readAllowedReport("~/.near-credentials/testnet/x.json", dirs, 1000)), "path_not_allowed");
  });

  it("refuses symlinks that lead outside, including a key file disguised as .md", () => {
    const { dirs } = setup();
    assert.equal(refused(readAllowedReport("link.md", dirs, 1000)), "path_not_allowed");
    assert.equal(refused(readAllowedReport("key.md", dirs, 1000)), "path_not_allowed");
    assert.equal(refused(readAllowedReport("up/outside.md", dirs, 1000)), "path_not_allowed");
  });

  it("refuses hidden files and directories, other extensions, directories", () => {
    const { dirs } = setup();
    assert.equal(refused(readAllowedReport(".env.md", dirs, 1000)), "path_not_allowed");
    assert.equal(refused(readAllowedReport(".hidden/c.md", dirs, 1000)), "path_not_allowed");
    assert.equal(refused(readAllowedReport("script.sh", dirs, 1000)), "path_not_allowed");
    assert.equal(refused(readAllowedReport("sub", dirs, 1000)), "path_not_allowed");
    assert.equal(refused(readAllowedReport(".", dirs, 1000)), "path_not_allowed");
    assert.equal(refused(readAllowedReport("", dirs, 1000)), "path_not_allowed");
    assert.equal(refused(readAllowedReport("a.md\0.txt", dirs, 1000)), "path_not_allowed");
  });

  it("reports missing and oversized files", () => {
    const { dirs } = setup();
    assert.equal(refused(readAllowedReport("nope.md", dirs, 1000)), "report_not_found");
    assert.equal(refused(readAllowedReport("big.md", dirs, 1000)), "report_too_large");
  });

  it("is disabled without configured directories", () => {
    const r = readAllowedReport("a.md", [], 1000);
    assert.equal(refused(r), "path_not_allowed");
    assert.match((r as { reason: string }).reason, /report_markdown/);
  });

  it("does not reveal the home directory", () => {
    assert.equal(displayPath(path.join(os.homedir(), "x", "y.md")), "~/x/y.md");
    const { dirs } = setup();
    const r = readAllowedReport(path.join(os.homedir(), ".ssh", "id_ed25519.md"), dirs, 1000);
    assert.ok(!r.ok && !r.reason.includes(os.homedir()));
  });

  it("refuses to start with a directory that does not exist", () => {
    assert.throws(() => resolveAllowedDirs([path.join(tmpDir(), "missing")]));
  });
});
