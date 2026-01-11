import crypto from "crypto";
import dotenv from "dotenv";

// Load environment variables from .env
dotenv.config();

// TWOFA_ENC_KEY is the symmetric encryption key used to protect the TOTP secret at rest.
// It must be 32 bytes (32 UTF-8 characters here) to be used as an AES-256 key.
const rawKey = process.env.TWOFA_ENC_KEY;
if (!rawKey || rawKey.length !== 32) {
  throw new Error("TWOFA_ENC_KEY must be set and be exactly 32 characters");
}

const KEY = Buffer.from(rawKey, "utf8");
const ALGO = "aes-256-gcm";

// Encrypts plaintext using AES-256-GCM.
// Output format (base64): [12-byte IV][16-byte auth tag][ciphertext]
// GCM provides both confidentiality (encryption) and integrity (auth tag).
export function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, KEY, iv);
  const enc = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}

// Decrypts payload produced by encrypt().
// It splits the base64 payload back into IV + tag + ciphertext.
// If the auth tag does not verify (tampered data / wrong key), decipher.final() throws.
export function decrypt(payload) {
  const raw = Buffer.from(payload, "base64");
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const enc = raw.subarray(28);
  const decipher = crypto.createDecipheriv(ALGO, KEY, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return dec.toString("utf8");
}
