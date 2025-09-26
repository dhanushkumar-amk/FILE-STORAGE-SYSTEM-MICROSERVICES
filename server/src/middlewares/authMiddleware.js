import jwt from "jsonwebtoken";
import User from "../models/User.js";
import logger from "../utils/logger.js";
import { StatusCodes } from "http-status-codes";

// Authentication middleware to verify JWT tokens
export const authenticate = async (req, res, next) => {
  try {
    let token;

    // Check for token in cookies (preferred)
    if (req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    }
    // Fallback: Check Authorization header
    else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        message: "Access token not provided"
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

    // Check if token type is correct
    if (decoded.type !== 'access') {
      return res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        message: "Invalid token type"
      });
    }

    // Find user and check if account is active
    const user = await User.findById(decoded.userId);
    if (!user || !user.isActive) {
      return res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        message: "User not found or account deactivated"
      });
    }

    // Attach user to request
    req.user = {
      id: user._id,
      email: user.email,
      name: user.name,
      role: user.role,
      accountType: user.accountType,
      storageUsed: user.storageUsed,
      storageLimit: user.storageLimit,
    };

    next();

  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        message: "Access token expired",
        code: "TOKEN_EXPIRED"
      });
    } else if (error.name === 'JsonWebTokenError') {
      return res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        message: "Invalid access token"
      });
    }

    logger.error("Authentication error:", error);
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: "Internal server error during authentication"
    });
  }
};

// Optional authentication - doesn't fail if no token provided
export const optionalAuth = async (req, res, next) => {
  try {
    let token;

    if (req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    } else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      req.user = null;
      return next();
    }

    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

    if (decoded.type !== 'access') {
      req.user = null;
      return next();
    }

    const user = await User.findById(decoded.userId);
    if (!user || !user.isActive) {
      req.user = null;
      return next();
    }

    req.user = {
      id: user._id,
      email: user.email,
      name: user.name,
      role: user.role,
      accountType: user.accountType,
      storageUsed: user.storageUsed,
      storageLimit: user.storageLimit,
    };

    next();

  } catch (error) {
    // For optional auth, we don't fail on token errors
    req.user = null;
    next();
  }
};

// Authorization middleware to check user roles
export const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        message: "Authentication required"
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        message: "Insufficient permissions"
      });
    }

    next();
  };
};

// Check if user account is verified
export const requireEmailVerification = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        message: "Authentication required"
      });
    }

    const user = await User.findById(req.user.id);
    if (!user.isEmailVerified) {
      return res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        message: "Email verification required",
        code: "EMAIL_NOT_VERIFIED"
      });
    }

    next();

  } catch (error) {
    logger.error("Email verification check error:", error);
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: "Internal server error"
    });
  }
};

// Check storage quota before file operations
export const checkStorageQuota = (requiredSpace = 0) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(StatusCodes.UNAUTHORIZED).json({
          success: false,
          message: "Authentication required"
        });
      }

      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(StatusCodes.NOT_FOUND).json({
          success: false,
          message: "User not found"
        });
      }

      // Check if user has enough storage space
      if (!user.hasStorageSpace(requiredSpace)) {
        return res.status(StatusCodes.INSUFFICIENT_STORAGE).json({
          success: false,
          message: "Insufficient storage space",
          data: {
            storageUsed: user.storageUsed,
            storageLimit: user.storageLimit,
            requiredSpace,
            availableSpace: user.storageLimit - user.storageUsed
          }
        });
      }

      // Attach storage info to request
      req.userStorage = {
        used: user.storageUsed,
        limit: user.storageLimit,
        available: user.storageLimit - user.storageUsed,
        percentage: user.getStoragePercentage()
      };

      next();

    } catch (error) {
      logger.error("Storage quota check error:", error);
      return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
        success: false,
        message: "Internal server error during storage check"
      });
    }
  };
};

// Rate limiting for specific user actions
export const userRateLimit = (maxRequests, windowMs, message) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(StatusCodes.UNAUTHORIZED).json({
          success: false,
          message: "Authentication required"
        });
      }

      const key = `user_rate_limit:${req.user.id}:${req.route.path}`;

      // This would typically use Redis for production
      // For now, we'll skip the implementation and just call next()
      // You can implement Redis-based rate limiting here

      next();

    } catch (error) {
      logger.error("User rate limit error:", error);
      next(); // Fail open
    }
  };
};

// Middleware to check account type permissions
export const requireAccountType = (...accountTypes) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        message: "Authentication required"
      });
    }

    if (!accountTypes.includes(req.user.accountType)) {
      return res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        message: `This feature requires ${accountTypes.join(' or ')} account`,
        code: "ACCOUNT_UPGRADE_REQUIRED"
      });
    }

    next();
  };
};
