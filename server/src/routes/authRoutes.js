import express from "express";
import authController from "../controllers/authController.js";
import { authenticate, optionalAuth } from "../middlewares/authMiddleware.js";
import {
  validateRegister,
  validateLogin,
  validateUpdateProfile,
  validateChangePassword,
  validateEmailVerification,
} from "../validations/authValidation.js";

const router = express.Router();

// Public routes (no authentication required)
router.post("/register", validateRegister, authController.register);
router.post("/login", validateLogin, authController.login);
router.post("/refresh-token", authController.refreshToken);
router.get("/verify-email/:token", validateEmailVerification, authController.verifyEmail);

// Protected routes (authentication required)
router.post("/logout", optionalAuth, authController.logout);
router.get("/profile", authenticate, authController.getProfile);
router.put("/profile", authenticate, validateUpdateProfile, authController.updateProfile);
router.put("/change-password", authenticate, validateChangePassword, authController.changePassword);

// Test route to check if user is authenticated
router.get("/check", authenticate, (req, res) => {
  res.json({
    success: true,
    message: "User is authenticated",
    user: req.user
  });
});

export default router;
