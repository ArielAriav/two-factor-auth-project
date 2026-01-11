import express from "express";
import * as otplib from "otplib";
import * as QRCode from "qrcode";
import { pool } from "../db.js";
import { encrypt, decrypt } from "../crypto.js";

const router = express.Router();

// 2FA (TOTP) routes.
//
// High-level flow:
// 1) POST /2fa/setup  -> generates a TOTP secret + returns a QR code (Data URL).
//    The secret is encrypted and stored in Postgres (users.twofa_secret_enc).
// 2) POST /2fa/enable -> user scans QR in an authenticator app, then sends a 6-digit code.
//    If the code is valid, we mark users.twofa_enabled = TRUE.
//
// NOTE: For now we accept userId in the request body (no session/JWT yet).
// In a real app, this should be replaced with an auth middleware that derives userId
// from a signed token or a server-side session.

router.post("/setup", async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: "userId is required" });

    const u = await pool.query("SELECT id, email, twofa_enabled FROM users WHERE id = $1", [userId]);
    if (u.rowCount === 0) return res.status(404).json({ error: "user not found" });

    const user = u.rows[0];
    if (user.twofa_enabled) return res.status(409).json({ error: "2fa already enabled" });

    // Generate a new random secret for TOTP.
    const secret = otplib.generateSecret();
    const issuer = "TwoFA Project";

    // Build an "otpauth://" URI that authenticator apps (Google Authenticator, etc.) understand.
    // encodeURIComponent is required by the otpauth URI format.
    const label = encodeURIComponent(`${issuer}:${user.email}`);
    const issuerEnc = encodeURIComponent(issuer);
    const secretEnc = encodeURIComponent(secret);
    const otpauth = `otpauth://totp/${label}?secret=${secretEnc}&issuer=${issuerEnc}&algorithm=SHA1&digits=6&period=30`;

    // Convert the otpauth URI into a QR image (Data URL) so the frontend can render it.
    const qrDataUrl = await QRCode.toDataURL(otpauth);

    // Encrypt the secret before storing it in the DB.
    const encSecret = encrypt(secret);
    await pool.query("UPDATE users SET twofa_secret_enc = $1 WHERE id = $2", [encSecret, user.id]);

    return res.status(200).json({ qrDataUrl });
  } catch (err) {
    console.error("TWOFA_SETUP_ERROR:", err);
    return res.status(500).json({ error: "internal server error" });
  }
});

router.post("/enable", async (req, res) => {
  try {
    const { userId, code } = req.body;
    if (!userId || !code) return res.status(400).json({ error: "userId and code are required" });

    const u = await pool.query(
      "SELECT id, email, twofa_enabled, twofa_secret_enc FROM users WHERE id = $1",
      [userId]
    );
    if (u.rowCount === 0) return res.status(404).json({ error: "user not found" });

    const user = u.rows[0];
    if (user.twofa_enabled) return res.status(409).json({ error: "2fa already enabled" });
    if (!user.twofa_secret_enc) return res.status(400).json({ error: "2fa secret not set, run setup first" });

    // Decrypt the stored secret so we can verify the user's TOTP code.
    const secret = decrypt(user.twofa_secret_enc);

    // Normalize and validate the code format (TOTP is typically 6 digits).
    const cleanCode = String(code).trim();
    if (!/^\d{6}$/.test(cleanCode)) {
      return res.status(400).json({ error: "invalid code format" });
    }

    // Verify the TOTP code against the secret.
    const ok = otplib.verify({
      token: cleanCode,
      secret,
    });

    if (!ok) return res.status(401).json({ error: "invalid 2fa code" });

    // Mark 2FA as enabled only after a successful verification.
    await pool.query("UPDATE users SET twofa_enabled = TRUE WHERE id = $1", [user.id]);

    return res.status(200).json({ status: "2fa_enabled" });
  } catch (err) {
    console.error("TWOFA_ENABLE_ERROR:", err);
    return res.status(500).json({ error: "internal server error" });
  }
});

export default router;
