import express from "express";
import dotenv from "dotenv";
import { initDb } from "./db.js";

dotenv.config();

const app = express();
app.use(express.json());

await initDb();

app.get("/", (req, res) => {
  res.send("Two Factor Auth server is running");
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
