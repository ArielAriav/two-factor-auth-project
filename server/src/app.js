import express from "express";
import dotenv from "dotenv";
import { initDb } from "./db.js";
import authRoutes from "./routes/auth.js";
import cors from "cors";
import rateLimit from 'express-rate-limit';

dotenv.config();

const app = express();

// Limit login attempts (Brute Force Protection)
// Blocks IP trying more than 5 times in 5 minutes
const limiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 100, // Generally for the application (generous)
  standardHeaders: true, 
  legacyHeaders: false,
});

// Specific hardening on login routes
const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 30, // Maximum of 30 failed registration/login attempts
  message: { error: "Too many login attempts, please try again later" }
});

app.use(limiter); // General protection
app.use("/auth", authLimiter); // Strong protection on authentication

app.use(cors({
  origin: "https://auth-frontend-eaxz.onrender.com", // Allows access from anywhere (for development purposes)
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
  preflightContinue: false,
  optionsSuccessStatus: 204
}));

app.use(express.json());

await initDb();

app.get("/", (req, res) => {
  res.send("Two Factor Auth server is running");
});

// routes
app.use("/auth", authRoutes);

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
