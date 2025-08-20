import "./config/supertokens.js";
import express, { Request, Response, NextFunction } from "express";
import auth from "./routes/authRoutes.js";
import user from "./routes/userRoutes.js";
import cors from "cors";
import cookieparser from "cookie-parser";
import supertokens from "supertokens-node";
import { middleware } from "supertokens-node/framework/express";
import { verifySession } from "supertokens-node/recipe/session/framework/express";
import { errorHandler } from "supertokens-node/framework/express";

// TODO: Add proper rate-limiting on routes
// TODO: Add password reset functionality
// TODO: Add account linkning functionality
// TODO: Add email verification functionality
// TODO: Add user Token Enrichment functionality (ading custom claims to JWTs)
// TODO: Add 2FA functionality
// TODO: Add email verification functionality

const app = express();
const PORT = process.env.PORT || 3001;

// SuperTokens cors configuration
app.use(
  cors({
    origin: process.env.WEBSITE_DOMAIN || "http://localhost:3000",
    allowedHeaders: ["Content-Type", ...supertokens.getAllCORSHeaders()],
    credentials: true,
  })
);

// SuperTokens middleware
app.use(middleware());

// parsing data
app.use(cookieparser());
app.use(express.json());

// Routes
app.use("/auth", auth);
app.use("/user", verifySession(), user);

// SuperTokens error handler
app.use(errorHandler());

// Final error handler
app.use((err: unknown, req: Request, res: Response, next: NextFunction) => {
  console.error(err);
  res.status(500).json({ message: "Internal Server Error" });
});

app.listen(PORT, () => {
  console.log(`Auth service is running on port ${PORT}`);
});
