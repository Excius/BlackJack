import { prisma } from "@repo/db";
import express from "express";

const router = express.Router();

router.get("/", (req, res) => {
  res.status(200).json({
    message: "Welcome to the User Service",
  });
});

router.get("/me/:id", async (req, res) => {
  const userId = req.params.id;

  try {
    if (!userId) {
      return res.status(400).json({
        message: "User ID is required",
      });
    }
    const user = await prisma.users.findUnique({
      where: { superTokenUserId: userId },
    });

    res.status(200).json({
      user: user,
    });
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({
      message: "Internal server error",
    });
  }
});

export default router;
