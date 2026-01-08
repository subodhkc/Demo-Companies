import express from "express";
import { handleInference } from "./routes.js";

const app = express();
app.use(express.json());

app.post("/infer", handleInference);

app.listen(3000, () => {
  console.log("AI testbed server running");
});
