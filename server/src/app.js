import express from "express";
import dotenv from "dotenv";
import { initDb } from "./db.js";
import authRoutes from "./routes/auth.js";
import twofaRoutes from "./routes/twofa.js";

// Load environment variables from .env into process.env
dotenv.config();

// Create the Express application
const app = express();
// Parse JSON request bodies (so req.body works for JSON)
app.use(express.json());

// Ensure DB schema exists before accepting requests
await initDb();

// Simple health-check endpoint
app.get("/", (req, res) => {
  res.send("Two Factor Auth server is running");
});

// Mount routes
// POST /auth/register, POST /auth/login
app.use("/auth", authRoutes);
// POST /2fa/setup, POST /2fa/enable
app.use("/2fa", twofaRoutes);

// Start listening for requests
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
