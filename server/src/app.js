import express from "express";
import dotenv from "dotenv";
import { initDb } from "./db.js";
import authRoutes from "./routes/auth.js";
import cors from "cors";

dotenv.config();

const app = express();
app.use(cors({
  origin: "*", // מאפשר גישה מכל מקום (לצורך פיתוח)
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
  preflightContinue: false,
  optionsSuccessStatus: 204
}));
app.options('*', cors());
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
