import { body, param } from "express-validator";

// User registration validation
export const validateRegister = [
  body("name")
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage("Name must be between 2 and 50 characters")
    .matches(/^[a-zA-Z\s]+$/)
    .withMessage("Name can only contain letters and spaces"),

  body("email")
    .trim()
    .isEmail()
    .withMessage("Please provide a valid email")
    .normalizeEmail()
    .isLength({ max: 100 })
    .withMessage("Email cannot exceed 100 characters"),

  body("password")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters long")
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage("Password must contain at least one lowercase letter, one uppercase letter, and one number"),

  body("confirmPassword")
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("Passwords do not match");
      }
      return true;
    })
];

// User login validation
export const validateLogin = [
  body("email")
    .trim()
    .isEmail()
    .withMessage("Please provide a valid email")
    .normalizeEmail(),

  body("password")
    .notEmpty()
    .withMessage("Password is required")
];

// Update profile validation
export const validateUpdateProfile = [
  body("name")
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage("Name must be between 2 and 50 characters")
    .matches(/^[a-zA-Z\s]+$/)
    .withMessage("Name can only contain letters and spaces"),

  body("preferences.theme")
    .optional()
    .isIn(["light", "dark", "system"])
    .withMessage("Theme must be light, dark, or system"),

  body("preferences.language")
    .optional()
    .isLength({ min: 2, max: 5 })
    .withMessage("Language code must be between 2 and 5 characters"),

  body("preferences.emailNotifications.fileShared")
    .optional()
    .isBoolean()
    .withMessage("Email notification setting must be boolean"),

  body("preferences.emailNotifications.storageAlmost")
    .optional()
    .isBoolean()
    .withMessage("Email notification setting must be boolean"),

  body("preferences.emailNotifications.securityAlerts")
    .optional()
    .isBoolean()
    .withMessage("Email notification setting must be boolean")
];

// Change password validation
export const validateChangePassword = [
  body("currentPassword")
    .notEmpty()
    .withMessage("Current password is required"),

  body("newPassword")
    .isLength({ min: 6 })
    .withMessage("New password must be at least 6 characters long")
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage("New password must contain at least one lowercase letter, one uppercase letter, and one number"),

  body("confirmNewPassword")
    .custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error("New passwords do not match");
      }
      return true;
    })
];

// Email verification token validation
export const validateEmailVerification = [
  param("token")
    .isLength({ min: 64, max: 64 })
    .withMessage("Invalid verification token")
    .isHexadecimal()
    .withMessage("Invalid verification token format")
];

// Password reset request validation
export const validatePasswordResetRequest = [
  body("email")
    .trim()
    .isEmail()
    .withMessage("Please provide a valid email")
    .normalizeEmail()
];

// Password reset validation
export const validatePasswordReset = [
  body("token")
    .isLength({ min: 64, max: 64 })
    .withMessage("Invalid reset token")
    .isHexadecimal()
    .withMessage("Invalid reset token format"),

  body("newPassword")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters long")
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage("Password must contain at least one lowercase letter, one uppercase letter, and one number"),

  body("confirmPassword")
    .custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error("Passwords do not match");
      }
      return true;
    })
];
