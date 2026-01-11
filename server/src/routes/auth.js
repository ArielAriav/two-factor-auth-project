import express from "express";
import bcrypt from "bcrypt";
import { pool } from "../db.js";
import { v4 as uuidv4 } from "uuid";

const router = express.Router();

router.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    // basic validation
    if (!email || !password) {
      return res.status(400).json({ error: "email and password are required" });
    }
    if (typeof password !== "string" || password.length < 8) {
      return res.status(400).json({ error: "password must be at least 8 characters" });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    // check if user exists
    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [normalizedEmail]);
    if (existing.rowCount > 0) {
      return res.status(409).json({ error: "email already registered" });
    }

    // hash password
    const passwordHash = await bcrypt.hash(password, 12);

    // insert user
    const inserted = await pool.query(
      "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, twofa_enabled, created_at",
      [normalizedEmail, passwordHash]
    );

    return res.status(201).json({ user: inserted.rows[0] });
  } catch (err) {
    console.error("REGISTER_ERROR:", err);
    return res.status(500).json({ error: "internal server error" });
  }
});

const loginChallenges = new Map(); // challengeId -> { userId, createdAt }
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "email and password are required" });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    const result = await pool.query(
      "SELECT id, email, password_hash, twofa_enabled FROM users WHERE email = $1",
      [normalizedEmail]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({ error: "invalid credentials" });
    }

    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: "invalid credentials" });
    }

    if (!user.twofa_enabled) {
      return res.status(200).json({ status: "ok", user: { id: user.id, email: user.email } });
    }

    const challengeId = uuidv4();
    loginChallenges.set(challengeId, { userId: user.id, createdAt: Date.now() });

    return res.status(200).json({ status: "2fa_required", challengeId });
  } catch (err) {
    console.error("LOGIN_ERROR:", err);
    return res.status(500).json({ error: "internal server error" });
  }
});

export default router;
