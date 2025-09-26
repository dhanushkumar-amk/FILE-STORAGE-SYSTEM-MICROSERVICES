import jwt from "jsonwebtoken";
import crypto from "crypto";
import { validationResult } from "express-validator";
import User from "../models/User.js";
import logger from "../utils/logger.js";
import { StatusCodes } from "http-status-codes";

class AuthController {

  // Generate JWT tokens
  generateTokens(userId) {
    const accessToken = jwt.sign(
      { userId, type: "access" },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || "15m" }
    );

    const refreshToken = jwt.sign(
      { userId, type: "refresh" },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || "30d" }
    );

    return { accessToken, refreshToken };
  }

  // Set secure HTTP-only cookies
  setTokenCookies(res, accessToken, refreshToken) {
    const isProduction = process.env.NODE_ENV === "production";

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "strict" : "lax",
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "strict" : "lax",
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    });
  }

  // User Registration
  register = async (req, res) => {
    try {
      // Check validation errors
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(StatusCodes.BAD_REQUEST).json({
          success: false,
          message: "Validation failed",
          errors: errors.array()
        });
      }

      const { name, email, password } = req.body;

      // Check if user already exists
      const existingUser = await User.findOne({ email: email.toLowerCase() });
      if (existingUser) {
        return res.status(StatusCodes.CONFLICT).json({
          success: false,
          message: "User with this email already exists"
        });
      }

      // Create new user
      const user = new User({
        name: name.trim(),
        email: email.toLowerCase(),
        password
      });

      // Generate email verification token
      if (process.env.ENABLE_EMAIL_VERIFICATION === "true") {
        user.emailVerificationToken = crypto.randomBytes(32).toString("hex");
        user.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
      } else {
        user.isEmailVerified = true;
      }

      await user.save();

      // Generate tokens
      const { accessToken, refreshToken } = this.generateTokens(user._id);

      // Add refresh token to user
      await user.addRefreshToken(refreshToken);

      // Set cookies
      this.setTokenCookies(res, accessToken, refreshToken);

      logger.info(`User registered: ${user.email}`);

      res.status(StatusCodes.CREATED).json({
        success: true,
        message: "User registered successfully",
        data: {
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            accountType: user.accountType,
            isEmailVerified: user.isEmailVerified,
            storageUsed: user.storageUsed,
            storageLimit: user.storageLimit,
            storagePercentage: user.getStoragePercentage(),
          },
          tokens: {
            accessToken,
            refreshToken
          }
        }
      });

    } catch (error) {
      logger.error("Registration error:", error);

      // Handle duplicate key error
      if (error.code === 11000) {
        return res.status(StatusCodes.CONFLICT).json({
          success: false,
          message: "User with this email already exists"
        });
      }

      res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
        success: false,
        message: "Internal server error during registration"
      });
    }
  };

  // User Login
  login = async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(StatusCodes.BAD_REQUEST).json({
          success: false,
          message: "Validation failed",
          errors: errors.array()
        });
      }

      const { email, password } = req.body;

      // Find user and include password for comparison
      const user = await User.findByEmail(email);
      if (!user) {
        return res.status(StatusCodes.UNAUTHORIZED).json({
          success: false,
          message: "Invalid email or password"
        });
      }

      // Check if account is locked
      if (user.isLocked) {
        return res.status(StatusCodes.LOCKED).json({
          success: false,
          message: "Account temporarily locked due to too many failed login attempts"
        });
      }

      // Check if account is active
      if (!user.isActive) {
        return res.status(StatusCodes.FORBIDDEN).json({
          success: false,
          message: "Account has been deactivated"
        });
      }

      // Compare password
      const isPasswordValid = await user.comparePassword(password);
      if (!isPasswordValid) {
        await user.incLoginAttempts();
        return res.status(StatusCodes.UNAUTHORIZED).json({
          success: false,
          message: "Invalid email or password"
        });
      }

      // Reset login attempts on successful login
      await user.resetLoginAttempts();

      // Generate tokens
      const { accessToken, refreshToken } = this.generateTokens(user._id);

      // Add refresh token to user
      await user.addRefreshToken(refreshToken);

      // Set cookies
      this.setTokenCookies(res, accessToken, refreshToken);

      logger.info(`User logged in: ${user.email}`);

      res.status(StatusCodes.OK).json({
        success: true,
        message: "Login successful",
        data: {
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            accountType: user.accountType,
            isEmailVerified: user.isEmailVerified,
            storageUsed: user.storageUsed,
            storageLimit: user.storageLimit,
            storagePercentage: user.getStoragePercentage(),
            lastLoginAt: user.lastLoginAt,
          },
          tokens: {
            accessToken,
            refreshToken
          }
        }
      });

    } catch (error) {
      logger.error("Login error:", error);
      res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
        success: false,
        message: "Internal server error during login"
      });
    }
  };

  // Refresh Access Token
  refreshToken = async (req, res) => {
    try {
      const { refreshToken } = req.cookies;

      if (!refreshToken) {
        return res.status(StatusCodes.UNAUTHORIZED).json({
          success: false,
          message: "Refresh token not provided"
        });
      }

      // Verify refresh token
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

      // Find user and check if refresh token exists
      const user = await User.findById(decoded.userId);
      if (!user || !user.refreshTokens.some(token => token.token === refreshToken)) {
        return res.status(StatusCodes.UNAUTHORIZED).json({
          success: false,
          message: "Invalid refresh token"
        });
      }

      // Check if user is active
      if (!user.isActive) {
        return res.status(StatusCodes.UNAUTHORIZED).json({
          success: false,
          message: "Account has been deactivated"
        });
      }

      // Generate new access token
      const newAccessToken = jwt.sign(
        { userId: user._id, type: "access" },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || "15m" }
      );

      // Set new access token cookie
      const isProduction = process.env.NODE_ENV === "production";
      res.cookie("accessToken", newAccessToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction ? "strict" : "lax",
        maxAge: 15 * 60 * 1000, // 15 minutes
      });

      res.status(StatusCodes.OK).json({
        success: true,
        message: "Token refreshed successfully",
        data: {
          accessToken: newAccessToken
        }
      });

    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(StatusCodes.UNAUTHORIZED).json({
          success: false,
          message: "Refresh token expired"
        });
      } else if (error.name === 'JsonWebTokenError') {
        return res.status(StatusCodes.UNAUTHORIZED).json({
          success: false,
          message: "Invalid refresh token"
        });
      }

      logger.error("Token refresh error:", error);
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        message: "Invalid or expired refresh token"
      });
    }
  };

  // User Logout
  logout = async (req, res) => {
    try {
      const { refreshToken } = req.cookies;
      const userId = req.user?.id;

      // Remove refresh token from database if user is authenticated
      if (userId && refreshToken) {
        const user = await User.findById(userId);
        if (user) {
          await user.removeRefreshToken(refreshToken);
        }
      }

      // Clear cookies
      res.clearCookie("accessToken");
      res.clearCookie("refreshToken");

      logger.info(`User logged out: ${req.user?.email || "unknown"}`);

      res.status(StatusCodes.OK).json({
        success: true,
        message: "Logout successful"
      });

    } catch (error) {
      logger.error("Logout error:", error);
      res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
        success: false,
        message: "Internal server error during logout"
      });
    }
  };

  // Get Current User Profile
  getProfile = async (req, res) => {
    try {
      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(StatusCodes.NOT_FOUND).json({
          success: false,
          message: "User not found"
        });
      }

      res.status(StatusCodes.OK).json({
        success: true,
        message: "Profile retrieved successfully",
        data: {
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            accountType: user.accountType,
            isEmailVerified: user.isEmailVerified,
            storageUsed: user.storageUsed,
            storageLimit: user.storageLimit,
            storagePercentage: user.getStoragePercentage(),
            profilePicture: user.profilePicture,
            preferences: user.preferences,
            createdAt: user.createdAt,
            lastLoginAt: user.lastLoginAt,
          }
        }
      });

    } catch (error) {
      logger.error("Get profile error:", error);
      res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
        success: false,
        message: "Internal server error while fetching profile"
      });
    }
  };

  // Update User Profile
  updateProfile = async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(StatusCodes.BAD_REQUEST).json({
          success: false,
          message: "Validation failed",
          errors: errors.array()
        });
      }

      const userId = req.user.id;
      const allowedUpdates = ['name', 'preferences'];
      const updates = {};

      // Filter only allowed updates
      Object.keys(req.body).forEach(key => {
        if (allowedUpdates.includes(key)) {
          updates[key] = req.body[key];
        }
      });

      // Check if there are any updates to make
      if (Object.keys(updates).length === 0) {
        return res.status(StatusCodes.BAD_REQUEST).json({
          success: false,
          message: "No valid fields to update"
        });
      }

      const user = await User.findByIdAndUpdate(
        userId,
        updates,
        { new: true, runValidators: true }
      );

      if (!user) {
        return res.status(StatusCodes.NOT_FOUND).json({
          success: false,
          message: "User not found"
        });
      }

      logger.info(`Profile updated: ${user.email}`);

      res.status(StatusCodes.OK).json({
        success: true,
        message: "Profile updated successfully",
        data: {
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            preferences: user.preferences,
          }
        }
      });

    } catch (error) {
      logger.error("Update profile error:", error);
      res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
        success: false,
        message: "Internal server error while updating profile"
      });
    }
  };

  // Change Password
  changePassword = async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(StatusCodes.BAD_REQUEST).json({
          success: false,
          message: "Validation failed",
          errors: errors.array()
        });
      }

      const { currentPassword, newPassword } = req.body;
      const userId = req.user.id;

      // Find user with password
      const user = await User.findById(userId).select('+password');
      if (!user) {
        return res.status(StatusCodes.NOT_FOUND).json({
          success: false,
          message: "User not found"
        });
      }

      // Verify current password
      const isCurrentPasswordValid = await user.comparePassword(currentPassword);
      if (!isCurrentPasswordValid) {
        return res.status(StatusCodes.UNAUTHORIZED).json({
          success: false,
          message: "Current password is incorrect"
        });
      }

      // Check if new password is different from current
      const isSamePassword = await user.comparePassword(newPassword);
      if (isSamePassword) {
        return res.status(StatusCodes.BAD_REQUEST).json({
          success: false,
          message: "New password must be different from current password"
        });
      }

      // Update password
      user.password = newPassword;
      await user.save();

      // Clear all refresh tokens (force re-login on all devices)
      user.refreshTokens = [];
      await user.save();

      // Clear cookies
      res.clearCookie("accessToken");
      res.clearCookie("refreshToken");

      logger.info(`Password changed: ${user.email}`);

      res.status(StatusCodes.OK).json({
        success: true,
        message: "Password changed successfully. Please log in again."
      });

    } catch (error) {
      logger.error("Change password error:", error);
      res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
        success: false,
        message: "Internal server error while changing password"
      });
    }
  };

  // Verify Email
  verifyEmail = async (req, res) => {
    try {
      const { token } = req.params;

      if (!token) {
        return res.status(StatusCodes.BAD_REQUEST).json({
          success: false,
          message: "Verification token is required"
        });
      }

      const user = await User.findOne({
        emailVerificationToken: token,
        emailVerificationExpires: { $gt: Date.now() }
      });

      if (!user) {
        return res.status(StatusCodes.BAD_REQUEST).json({
          success: false,
          message: "Invalid or expired verification token"
        });
      }

      user.isEmailVerified = true;
      user.emailVerificationToken = undefined;
      user.emailVerificationExpires = undefined;
      await user.save();

      logger.info(`Email verified: ${user.email}`);

      res.status(StatusCodes.OK).json({
        success: true,
        message: "Email verified successfully"
      });

    } catch (error) {
      logger.error("Email verification error:", error);
      res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
        success: false,
        message: "Internal server error during email verification"
      });
    }
  };

  // Check Authentication Status
  checkAuth = async (req, res) => {
    try {
      // This endpoint is protected by authenticate middleware
      // So if we reach here, user is authenticated
      const user = await User.findById(req.user.id);

      if (!user) {
        return res.status(StatusCodes.NOT_FOUND).json({
          success: false,
          message: "User not found"
        });
      }

      res.status(StatusCodes.OK).json({
        success: true,
        message: "User is authenticated",
        data: {
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            accountType: user.accountType,
            isEmailVerified: user.isEmailVerified,
            storagePercentage: user.getStoragePercentage(),
          }
        }
      });

    } catch (error) {
      logger.error("Check auth error:", error);
      res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
        success: false,
        message: "Internal server error while checking authentication"
      });
    }
  };

  // Get user statistics (admin only - future implementation)
  getUserStats = async (req, res) => {
    try {
      const stats = await User.getUserStats();

      res.status(StatusCodes.OK).json({
        success: true,
        message: "User statistics retrieved successfully",
        data: { stats }
      });

    } catch (error) {
      logger.error("Get user stats error:", error);
      res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
        success: false,
        message: "Internal server error while fetching statistics"
      });
    }
  };
}

export default new AuthController();
