import pg from "pg";
import dotenv from "dotenv";

dotenv.config();

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

export async function initDb() {
  // יצירת הטבלה הבסיסית (כמו שהיה קודם)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      twofa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
      twofa_secret_enc TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

  // הוספת עמודות למנגנון הנעילה (אם הן לא קיימות)
  try {
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS login_attempts INT DEFAULT 0;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS lockout_until TIMESTAMP;`);
    console.log("DB Schema updated with lockout columns");
  } catch (err) {
    console.log("Columns might already exist or error updating DB:", err.message);
  }
}
