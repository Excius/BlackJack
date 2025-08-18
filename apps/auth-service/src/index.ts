import express from "express";
import type { User } from "@repo/shared-types/types";
const app = express();

app.get("/", (req, res) => {
  res.send("Hello Guys!");
});

app.listen(3002, () => {
  console.log("Auth service is running on port 3002");
});
