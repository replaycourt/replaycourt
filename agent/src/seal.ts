// Sealed report format (SPEC.md "Sealed report format"), Node's built-in crypto only.
//
//   verifier keypair: X25519, public key published as base64 of the raw 32 bytes
//   sender: ephemeral X25519 keypair; shared = X25519(eph_priv, recipient_pub)
//   key = HKDF-SHA256(shared, salt = epk_raw || recipient_pk_raw, info = "replaycourt/v1", 32 bytes)
//   AES-256-GCM, random 12-byte IV, no AAD
//   sealed = base64(UTF-8 JSON {"v":1,"alg":"x25519-hkdf-sha256-aes256gcm","epk","iv","ct","tag"})
//
// Commitment (SPEC v2, bound to the submitter):
//   commitment = sha256("replaycourt/commit/v2" || 0x00 || hunter_account_id || 0x00 || report_bytes), lowercase hex
// A sealed blob and its commitment copied from someone else's transaction do not verify when they
// are submitted from another account: the worker recomputes the commitment with the account that
// submitted (SubmissionView.hunter_id).

import crypto from "node:crypto";

export const SEAL_VERSION = 1;
export const SEAL_ALG = "x25519-hkdf-sha256-aes256gcm";
export const HKDF_INFO = "replaycourt/v1";

export interface SealedEnvelope {
  v: number;
  alg: string;
  epk: string;
  iv: string;
  ct: string;
  tag: string;
}

export interface VerifierKeypair {
  publicKey: string; // base64 of the raw 32-byte X25519 public key
  privateKey: string; // base64 of the raw 32-byte X25519 private key
}

export class SealError extends Error {}

function b64urlToBuf(s: string): Buffer {
  return Buffer.from(s, "base64url");
}

function rawPublicKey(key: crypto.KeyObject): Buffer {
  const jwk = key.export({ format: "jwk" });
  if (!jwk.x) throw new SealError("not an X25519 key");
  return b64urlToBuf(jwk.x);
}

function decodeB64Exact(value: unknown, len: number | null, what: string): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new SealError(`sealed report: field ${what} is not base64`);
  }
  const buf = Buffer.from(value, "base64");
  if (len !== null && buf.length !== len) {
    throw new SealError(`sealed report: field ${what} has ${buf.length} bytes, expected ${len}`);
  }
  return buf;
}

export function publicKeyFromBase64(b64: string): crypto.KeyObject {
  const raw = decodeB64Exact(b64, 32, "public key");
  return crypto.createPublicKey({ key: { kty: "OKP", crv: "X25519", x: raw.toString("base64url") }, format: "jwk" });
}

export function privateKeyFromBase64(b64: string): crypto.KeyObject {
  const raw = decodeB64Exact(b64, 32, "private key");
  // PKCS#8 wrapper for a raw X25519 private key (OID 1.3.101.110).
  const priv = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), raw]),
    format: "der",
    type: "pkcs8",
  });
  return priv;
}

export function generateVerifierKeypair(): VerifierKeypair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
  const jwk = privateKey.export({ format: "jwk" });
  if (!jwk.d) throw new SealError("key generation failed");
  return {
    publicKey: rawPublicKey(publicKey).toString("base64"),
    privateKey: b64urlToBuf(jwk.d).toString("base64"),
  };
}

export function publicKeyOf(privateKeyB64: string): string {
  const pub = crypto.createPublicKey(privateKeyFromBase64(privateKeyB64));
  return rawPublicKey(pub).toString("base64");
}

function deriveKey(shared: Buffer, epkRaw: Buffer, recipientRaw: Buffer): Buffer {
  const salt = Buffer.concat([epkRaw, recipientRaw]);
  return Buffer.from(crypto.hkdfSync("sha256", shared, salt, Buffer.from(HKDF_INFO, "utf8"), 32));
}

/** Domain tag of the v2 commitment. */
export const COMMITMENT_DOMAIN = "replaycourt/commit/v2";

/**
 * The commitment of a report (SPEC v2): sha256("replaycourt/commit/v2" || 0x00 || hunterId || 0x00 || report),
 * lowercase hex. `hunterId` is the NEAR account that calls submit_report / submit_report_from_vault.
 * Used by the hunter CLI (`submit`), the worker's check and the attack demos.
 */
export function commitmentFor(hunterId: string, report: Uint8Array): string {
  if (typeof hunterId !== "string" || hunterId.length === 0 || hunterId.includes("\0")) {
    throw new SealError("commitment: hunter account id must be a non-empty string without NUL bytes");
  }
  return crypto.createHash("sha256")
    .update(Buffer.from(COMMITMENT_DOMAIN, "utf8"))
    .update(Buffer.from([0]))
    .update(Buffer.from(hunterId, "utf8"))
    .update(Buffer.from([0]))
    .update(report)
    .digest("hex");
}

/**
 * v1 commitment: sha256(plaintext), not bound to the submitter.
 * @deprecated Contracts from v2 on expect {@link commitmentFor}; the v2 worker judges a v1 commitment
 * as "sealed report does not match commitment". Kept for reading v1 deployments.
 */
export function commitmentOf(plaintext: Uint8Array): string {
  return crypto.createHash("sha256").update(plaintext).digest("hex");
}

/** Seal plaintext bytes to the verifier's base64 X25519 public key. Returns the sealed string. */
export function seal(plaintext: Uint8Array, recipientPublicKeyB64: string): string {
  const recipient = publicKeyFromBase64(recipientPublicKeyB64);
  const recipientRaw = rawPublicKey(recipient);
  const eph = crypto.generateKeyPairSync("x25519");
  const epkRaw = rawPublicKey(eph.publicKey);
  const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: recipient });
  const key = deriveKey(shared, epkRaw, recipientRaw);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const env: SealedEnvelope = {
    v: SEAL_VERSION,
    alg: SEAL_ALG,
    epk: epkRaw.toString("base64"),
    iv: iv.toString("base64"),
    ct: ct.toString("base64"),
    tag: tag.toString("base64"),
  };
  return Buffer.from(JSON.stringify(env), "utf8").toString("base64");
}

export function parseSealed(sealed: string): SealedEnvelope {
  if (typeof sealed !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(sealed.trim())) {
    throw new SealError("sealed report is not base64");
  }
  let env: unknown;
  try {
    env = JSON.parse(Buffer.from(sealed.trim(), "base64").toString("utf8"));
  } catch {
    throw new SealError("sealed report is not base64-encoded JSON");
  }
  const e = env as Partial<SealedEnvelope>;
  if (!e || typeof e !== "object") throw new SealError("sealed report is not a JSON object");
  if (e.v !== SEAL_VERSION) throw new SealError(`unsupported sealed report version ${String(e.v)}`);
  if (e.alg !== SEAL_ALG) throw new SealError(`unsupported algorithm ${String(e.alg)}`);
  return e as SealedEnvelope;
}

/** Decrypt a sealed string with the verifier's base64 X25519 private key. Throws SealError. */
export function unseal(sealed: string, privateKeyB64: string): Buffer {
  const env = parseSealed(sealed);
  const epkRaw = decodeB64Exact(env.epk, 32, "epk");
  const iv = decodeB64Exact(env.iv, 12, "iv");
  const tag = decodeB64Exact(env.tag, 16, "tag");
  const ct = decodeB64Exact(env.ct, null, "ct");
  const priv = privateKeyFromBase64(privateKeyB64);
  const recipientRaw = rawPublicKey(crypto.createPublicKey(priv));
  let shared: Buffer;
  try {
    shared = crypto.diffieHellman({ privateKey: priv, publicKey: publicKeyFromBase64(env.epk) });
  } catch (err) {
    throw new SealError(`key agreement failed: ${(err as Error).message}`);
  }
  const key = deriveKey(shared, epkRaw, recipientRaw);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw new SealError("decryption failed (wrong key or tampered report)");
  }
}

/**
 * Unseal and compare with the on-chain commitment. Never throws; returns a verdict-ready result.
 *
 * With `hunterId` (the submitting account, SubmissionView.hunter_id) the v2 commitment
 * {@link commitmentFor} is recomputed; the worker always passes it. Without it the v1 rule
 * sha256(plaintext) is used (deprecated, for v1 deployments only).
 */
export function openAndCheck(
  sealed: string,
  privateKeyB64: string,
  commitment: string,
  hunterId?: string,
): { ok: true; plaintext: Buffer } | { ok: false; error: string } {
  let plaintext: Buffer;
  try {
    plaintext = unseal(sealed, privateKeyB64);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
  let actual: string;
  let rule: string;
  if (hunterId === undefined) {
    actual = commitmentOf(plaintext);
    rule = "sha256(plaintext) (v1)";
  } else {
    try {
      actual = commitmentFor(hunterId, plaintext);
    } catch (err) {
      return { ok: false, error: (err as Error).message };
    }
    rule = `commitment v2 for ${hunterId}`;
  }
  if (actual !== commitment) {
    return { ok: false, error: `commitment mismatch: ${rule}=${actual}, on-chain=${commitment}` };
  }
  return { ok: true, plaintext };
}
