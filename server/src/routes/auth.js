import express from "express";
import bcrypt from "bcrypt";
import { pool } from "../db.js";
import { v4 as uuidv4 } from "uuid";
import speakeasy from "speakeasy";
import qrcode from "qrcode";
import { encrypt, decrypt } from "../utils/crypto.js";

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

// שלב א' של 2FA: יצירת סוד והחזרת QR Code
router.post("/setup-2fa", async (req, res) => {
  try {
    const { email } = req.body; // במערכת אמיתית היינו לוקחים את ה-ID מה-Session/Token

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    // 1. בדיקה שהמשתמש קיים
    const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [normalizedEmail]);
    if (userResult.rowCount === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    // 2. יצירת סוד חדש (Secret) עבור המשתמש
    const secret = speakeasy.generateSecret({
      name: `MyApp (${normalizedEmail})` // השם שיופיע באפליקציית Google Auth
    });

    // 3. הצפנת הסוד לפני שמירה ב-DB (דרישת אבטחה)
    const encryptedSecret = encrypt(secret.base32);

    // 4. שמירה ב-DB (עדיין לא מפעילים את ה-2FA, רק שומרים את ההכנה)
    await pool.query(
      "UPDATE users SET twofa_secret_enc = $1 WHERE email = $2",
      [encryptedSecret, normalizedEmail]
    );

    // 5. יצירת תמונת QR Code
    // secret.otpauth_url מכיל את כל המידע שהאפליקציה צריכה
    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

    // 6. החזרה לקליינט
    res.json({
      message: "Scan this QR code with Google Authenticator",
      qrCode: qrCodeUrl, // מחרוזת ארוכה שהיא בעצם תמונה
      secret: secret.base32 // (אופציונלי) למקרה שהסריקה לא עובדת והמשתמש רוצה להקליד ידנית
    });

  } catch (err) {
    console.error("SETUP_2FA_ERROR:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// שלב ב' של 2FA: אימות הקוד והפעלת המנגנון ב-DB
router.post("/verify-2fa", async (req, res) => {
  try {
    const { email, token } = req.body;

    if (!email || !token) {
      return res.status(400).json({ error: "Email and token are required" });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    // 1. שליפת המשתמש והסוד המוצפן
    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1", 
      [normalizedEmail]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = result.rows[0];

    // אם אין סוד שמור, אי אפשר לאמת
    if (!user.twofa_secret_enc) {
      return res.status(400).json({ error: "2FA setup not initiated" });
    }

    // 2. פענוח הסוד (Decrypt) כדי שנוכל להשתמש בו
    const secret = decrypt(user.twofa_secret_enc);

    // 3. בדיקה האם הקוד שהמשתמש שלח תואם לסוד
    // window: 1 מאפשר סטייה של 30 שניות במקרה שהשעונים לא מסונכרנים בול
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: "base32",
      token: token, 
      window: 1 
    });

    if (verified) {
      // 4. הקוד נכון! מעדכנים ב-DB שהמשתמש הפעיל 2FA בהצלחה
      await pool.query(
        "UPDATE users SET twofa_enabled = TRUE WHERE email = $1",
        [normalizedEmail]
      );
      
      res.json({ status: "success", message: "2FA enabled successfully" });
    } else {
      res.status(400).json({ status: "failed", error: "Invalid token" });
    }

  } catch (err) {
    console.error("VERIFY_2FA_ERROR:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// שלב ג': סיום ההתחברות - אימות הקוד מול האתגר
router.post("/login-verify", async (req, res) => {
  try {
    const { challengeId, token } = req.body;

    // ... (בדיקות תקינות קלט ראשוניות - נשאר אותו דבר) ...
    if (!challengeId || !token) {
      return res.status(400).json({ error: "Challenge ID and token are required" });
    }

    const challenge = loginChallenges.get(challengeId);
    if (!challenge) {
      return res.status(400).json({ error: "Invalid or expired challenge" });
    }

    // שליפת המשתמש כולל נתוני הנעילה
    const result = await pool.query(
      "SELECT * FROM users WHERE id = $1", 
      [challenge.userId]
    );
    const user = result.rows[0];

    if (!user) return res.status(400).json({ error: "User not found" });

    // --- 1. בדיקה: האם המשתמש נעול? ---
    if (user.lockout_until && new Date() < new Date(user.lockout_until)) {
      const remainingMinutes = Math.ceil((new Date(user.lockout_until) - new Date()) / 60000);
      return res.status(403).json({ 
        error: `Account is locked due to too many failed attempts. Try again in ${remainingMinutes} minutes.` 
      });
    }

    // פענוח הסוד
    const secret = decrypt(user.twofa_secret_enc);
    
    // בדיקת הקוד מול Google Authenticator
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: "base32",
      token: token,
      window: 1
    });

    if (verified) {
      // --- 2. הצלחה: איפוס המונה ---
      await pool.query(
        "UPDATE users SET login_attempts = 0, lockout_until = NULL WHERE id = $1",
        [user.id]
      );

      loginChallenges.delete(challengeId);
      
      res.json({ 
        status: "ok", 
        message: "Login successful",
        user: { id: user.id, email: user.email }
      });

    } else {
      // --- 3. כישלון: העלאת המונה ובדיקת נעילה ---
      let newAttempts = (user.login_attempts || 0) + 1;
      let lockoutQuery = "UPDATE users SET login_attempts = $1 WHERE id = $2";
      let queryParams = [newAttempts, user.id];

      // אם הגענו ל-5 ניסיונות - נועלים ל-15 דקות
      if (newAttempts >= 5) {
        const lockTime = new Date(Date.now() + 15 * 60000); // עכשיו + 15 דקות
        lockoutQuery = "UPDATE users SET login_attempts = $1, lockout_until = $2 WHERE id = $3";
        queryParams = [newAttempts, lockTime, user.id];
        
        await pool.query(lockoutQuery, queryParams); // שומרים את הנעילה
        
        return res.status(403).json({ 
          error: "Too many failed attempts. Account locked for 15 minutes." 
        });
      }

      // סתם מעדכנים את מספר הניסיונות בלי לנעול עדיין
      await pool.query(lockoutQuery, queryParams);
      
      res.status(401).json({ 
        error: `Invalid 2FA token. Attempt ${newAttempts}/5` 
      });
    }

  } catch (err) {
    console.error("LOGIN_VERIFY_ERROR:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
