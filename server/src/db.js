import pg from "pg";
import dotenv from "dotenv";

// Load environment variables from .env
dotenv.config();

const { Pool } = pg;

// A shared Postgres connection pool.
// DATABASE_URL is expected to look like:
// postgres://user:password@host:port/dbname
export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Initializes the database schema.
// This is called once on server startup (see app.js).
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
