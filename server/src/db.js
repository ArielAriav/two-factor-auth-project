import pg from "pg";
import dotenv from "dotenv";

dotenv.config();

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

export async function initDb() {
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
}
