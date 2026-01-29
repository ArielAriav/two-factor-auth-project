import express from "express";
import dotenv from "dotenv";
import { initDb } from "./db.js";
import authRoutes from "./routes/auth.js";
import cors from "cors";
import rateLimit from 'express-rate-limit';

dotenv.config();

const app = express();

// הגבלת ניסיונות כניסה (Brute Force Protection)
// חוסם IP שמנסה יותר מ-5 פעמים ב-5 דקות
const limiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 דקות
  max: 100, // באופן כללי לאפליקציה (נדיב)
  standardHeaders: true, 
  legacyHeaders: false,
});

// החמרה ספציפית על נתיבי התחברות
const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 דקות
  max: 5, // מקסימום 5 ניסיונות כושלים להרשמה/התחברות
  message: { error: "Too many login attempts, please try again later" }
});

app.use(limiter); // הגנה כללית
app.use("/auth", authLimiter); // הגנה חזקה על האימות

app.use(cors({
  origin: "*", // מאפשר גישה מכל מקום (לצורך פיתוח)
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
