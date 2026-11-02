import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test } from "node:test";
import {
  COMMITMENT_DOMAIN,
  SEAL_ALG,
  SealError,
  commitmentFor,
  commitmentOf,
  generateVerifierKeypair,
  openAndCheck,
  parseSealed,
  publicKeyOf,
  seal,
  unseal,
} from "../src/seal.ts";

const REPORT = Buffer.from("---\ntitle: Test report é€\n---\n\n# Bug\n\n```solidity\npragma solidity ^0.8.0;\n```\n", "utf8");

function envelope(sealed: string): Record<string, string | number> {
  return JSON.parse(Buffer.from(sealed, "base64").toString("utf8"));
}

function reseal(env: Record<string, string | number>): string {
  return Buffer.from(JSON.stringify(env), "utf8").toString("base64");
}

// Independent implementation of the SPEC derivation (RFC 5869 HKDF with HMAC-SHA256).
function hkdfReference(ikm: Buffer, salt: Buffer, info: string): Buffer {
  const prk = crypto.createHmac("sha256", salt).update(ikm).digest();
  return crypto.createHmac("sha256", prk).update(Buffer.concat([Buffer.from(info), Buffer.from([1])])).digest();
}

test("seal/unseal round trip restores the exact bytes", () => {
  const kp = generateVerifierKeypair();
  assert.equal(Buffer.from(kp.publicKey, "base64").length, 32);
  assert.equal(publicKeyOf(kp.privateKey), kp.publicKey);
  const sealed = seal(REPORT, kp.publicKey);
  assert.deepEqual(unseal(sealed, kp.privateKey), REPORT);
  const binary = crypto.randomBytes(5000);
  assert.deepEqual(unseal(seal(binary, kp.publicKey), kp.privateKey), binary);
});

test("envelope has the SPEC shape and fresh randomness per seal", () => {
  const kp = generateVerifierKeypair();
  const a = seal(REPORT, kp.publicKey);
  const b = seal(REPORT, kp.publicKey);
  assert.notEqual(a, b);
  const env = envelope(a);
  assert.deepEqual(Object.keys(env), ["v", "alg", "epk", "iv", "ct", "tag"]);
  assert.equal(env.v, 1);
  assert.equal(env.alg, SEAL_ALG);
  assert.equal(Buffer.from(String(env.epk), "base64").length, 32);
  assert.equal(Buffer.from(String(env.iv), "base64").length, 12);
  assert.equal(Buffer.from(String(env.tag), "base64").length, 16);
  assert.equal(Buffer.from(String(env.ct), "base64").length, REPORT.length);
  assert.equal(parseSealed(a).alg, SEAL_ALG);
});

test("key derivation matches an independent HKDF(shared, epk||recipient, 'replaycourt/v1') implementation", () => {
  const kp = generateVerifierKeypair();
  const env = envelope(seal(REPORT, kp.publicKey));
  const priv = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), Buffer.from(kp.privateKey, "base64")]),
    format: "der",
    type: "pkcs8",
  });
  const epk = crypto.createPublicKey({ key: { kty: "OKP", crv: "X25519", x: Buffer.from(String(env.epk), "base64").toString("base64url") }, format: "jwk" });
  const shared = crypto.diffieHellman({ privateKey: priv, publicKey: epk });
  const salt = Buffer.concat([Buffer.from(String(env.epk), "base64"), Buffer.from(kp.publicKey, "base64")]);
  const key = hkdfReference(shared, salt, "replaycourt/v1");
  const d = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(String(env.iv), "base64"));
  d.setAuthTag(Buffer.from(String(env.tag), "base64"));
  const pt = Buffer.concat([d.update(Buffer.from(String(env.ct), "base64")), d.final()]);
  assert.deepEqual(pt, REPORT);
});

test("tampering with ct, tag, iv or epk is detected", () => {
  const kp = generateVerifierKeypair();
  const env = envelope(seal(REPORT, kp.publicKey));
  const flip = (b64: string, i = 0) => {
    const buf = Buffer.from(b64, "base64");
    buf[i] ^= 0x01;
    return buf.toString("base64");
  };
  for (const field of ["ct", "tag", "iv", "epk"]) {
    const bad = { ...env, [field]: flip(String(env[field])) };
    assert.throws(() => unseal(reseal(bad), kp.privateKey), SealError, `tampered ${field} must fail`);
  }
  const res = openAndCheck(reseal({ ...env, ct: flip(String(env.ct), 3) }), kp.privateKey, commitmentOf(REPORT));
  assert.equal(res.ok, false);
});

test("wrong key, wrong version and garbage are rejected", () => {
  const kp = generateVerifierKeypair();
  const other = generateVerifierKeypair();
  const sealed = seal(REPORT, kp.publicKey);
  assert.throws(() => unseal(sealed, other.privateKey), SealError);
  assert.throws(() => unseal(reseal({ ...envelope(sealed), v: 2 }), kp.privateKey), /version/);
  assert.throws(() => unseal(reseal({ ...envelope(sealed), alg: "rsa" }), kp.privateKey), /algorithm/);
  assert.throws(() => unseal("not base64 !!", kp.privateKey), SealError);
  assert.throws(() => unseal(Buffer.from("{}").toString("base64"), kp.privateKey), SealError);
});

test("commitment is sha256(plaintext) in lowercase hex and mismatches are reported", () => {
  const kp = generateVerifierKeypair();
  const c = commitmentOf(REPORT);
  assert.match(c, /^[0-9a-f]{64}$/);
  assert.equal(c, crypto.createHash("sha256").update(REPORT).digest("hex"));
  const sealed = seal(REPORT, kp.publicKey);
  const ok = openAndCheck(sealed, kp.privateKey, c);
  assert.equal(ok.ok, true);
  const other = commitmentOf(Buffer.from("another report"));
  const bad = openAndCheck(sealed, kp.privateKey, other);
  assert.equal(bad.ok, false);
  assert.match(bad.ok ? "" : bad.error, /commitment mismatch/);
});

// Independent implementation of the SPEC v2 commitment, over the concatenated bytes.
function commitmentReference(hunterId: string, report: Buffer): string {
  const msg = Buffer.concat([Buffer.from("replaycourt/commit/v2"), Buffer.from([0]), Buffer.from(hunterId), Buffer.from([0]), report]);
  return crypto.createHash("sha256").update(msg).digest("hex");
}

test("commitment v2 = sha256('replaycourt/commit/v2' || 0x00 || hunter || 0x00 || report), bound to the account", () => {
  assert.equal(COMMITMENT_DOMAIN, "replaycourt/commit/v2");
  const a = commitmentFor("hunter1.example.testnet", REPORT);
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.equal(a, commitmentReference("hunter1.example.testnet", REPORT));
  // Fixed vector, so that other implementations (mcp/, web/, a contract) can compare.
  assert.equal(commitmentFor("alice.testnet", Buffer.from("report")),
    crypto.createHash("sha256").update("replaycourt/commit/v2\0alice.testnet\0report").digest("hex"));
  // Another account, the same report: another commitment. Not the v1 rule either.
  assert.notEqual(commitmentFor("hunter2.example.testnet", REPORT), a);
  assert.notEqual(commitmentOf(REPORT), a);
  // The separators keep (account, report) pairs apart: "ab" + "c..." != "a" + "bc...".
  assert.notEqual(commitmentFor("ab", Buffer.from("c")), commitmentFor("a", Buffer.from("bc")));
  assert.throws(() => commitmentFor("", REPORT), SealError);
  assert.throws(() => commitmentFor("a\0b", REPORT), SealError);
});

test("openAndCheck with the submitting account checks the v2 commitment", () => {
  const kp = generateVerifierKeypair();
  const sealed = seal(REPORT, kp.publicKey);
  const c = commitmentFor("hunter1.example.testnet", REPORT);
  const ok = openAndCheck(sealed, kp.privateKey, c, "hunter1.example.testnet");
  assert.equal(ok.ok, true);
  if (ok.ok) assert.deepEqual(ok.plaintext, REPORT);
  // The same sealed blob and commitment, submitted from another account: refused.
  const copied = openAndCheck(sealed, kp.privateKey, c, "copycat.example.testnet");
  assert.equal(copied.ok, false);
  assert.match(copied.ok ? "" : copied.error, /commitment mismatch: commitment v2 for copycat\.example\.testnet/);
  // A v1 commitment does not pass the v2 check.
  assert.equal(openAndCheck(sealed, kp.privateKey, commitmentOf(REPORT), "hunter1.example.testnet").ok, false);
  // Without an account, the deprecated v1 rule applies (v1 deployments).
  assert.equal(openAndCheck(sealed, kp.privateKey, commitmentOf(REPORT)).ok, true);
});
