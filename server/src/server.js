import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import logger from "./utils/logger.js";
import errorHandler from "./middlewares/errorHandler.js";
import connectDB from "./config/mongoDB.js";
import initRedis from "./config/redis.js";
import rateLimiter from "./middlewares/rateLimiter.js";

// Import routes
import authRoutes from "./routes/authRoutes.js";

// Load environment variables
dotenv.config();

const app = express();

// Connect to databases
await connectDB();
await initRedis();

// Trust proxy (important for rate limiting and getting real IP)
app.set('trust proxy', 1);

// Middleware Stack
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(cors({
  origin: process.env.CLIENT_URL || "http://localhost:3001",
  credentials: true, // Allow cookies
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser()); // Parse cookies
app.use(express.static("public"));
app.use(morgan("combined"));

// Rate Limiting
app.use(rateLimiter(100, 60)); // 100 requests per minute

// API Routes
app.use("/api/auth", authRoutes);

// Main Route
app.get("/", (req, res) => {
  logger.info(`GET / - IP: ${req.ip}`);
  res.status(200).json({
    success: true,
    message: "Cloud Storage API is running!",
    timestamp: new Date().toISOString(),
    version: "1.0.0",
    endpoints: {
      auth: "/api/auth",
      files: "/api/files (coming soon)",
      folders: "/api/folders (coming soon)",
      health: "/health",
      docs: "/api"
    }
  });
});

// Health Check Route
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "healthy",
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    memory: process.memoryUsage(),
    environment: process.env.NODE_ENV || "development"
  });
});

// API Documentation Route
app.get("/api", (req, res) => {
  res.status(200).json({
    success: true,
    message: "File Storage API Documentation",
    version: "1.0.0",
    baseUrl: `${req.protocol}://${req.get('host')}/api`,
    availableEndpoints: {
      authentication: {
        register: {
          method: "POST",
          path: "/api/auth/register",
          description: "Register a new user account",
          body: {
            name: "string (required)",
            email: "string (required)",
            password: "string (required, min 6 chars)",
            confirmPassword: "string (required)"
          }
        },
        login: {
          method: "POST",
          path: "/api/auth/login",
          description: "Login with email and password",
          body: {
            email: "string (required)",
            password: "string (required)"
          }
        },
        logout: {
          method: "POST",
          path: "/api/auth/logout",
          description: "Logout and invalidate tokens",
          authentication: "Optional"
        },
        profile: {
          method: "GET",
          path: "/api/auth/profile",
          description: "Get current user profile",
          authentication: "Required"
        },
        updateProfile: {
          method: "PUT",
          path: "/api/auth/profile",
          description: "Update user profile",
          authentication: "Required",
          body: {
            name: "string (optional)",
            preferences: "object (optional)"
          }
        },
        changePassword: {
          method: "PUT",
          path: "/api/auth/change-password",
          description: "Change user password",
          authentication: "Required",
          body: {
            currentPassword: "string (required)",
            newPassword: "string (required)",
            confirmNewPassword: "string (required)"
          }
        },
        refreshToken: {
          method: "POST",
          path: "/api/auth/refresh-token",
          description: "Refresh access token using refresh token cookie"
        },
        verifyEmail: {
          method: "GET",
          path: "/api/auth/verify-email/:token",
          description: "Verify email address with token"
        },
        checkAuth: {
          method: "GET",
          path: "/api/auth/check",
          description: "Check if user is authenticated",
          authentication: "Required"
        }
      }
    },
    comingSoon: {
      files: "File upload, download, delete operations",
      folders: "Folder creation, organization, sharing",
      sharing: "File and folder sharing with permissions"
    }
  });
});

// 404 Handler
app.use("*", (req, res) => {
  logger.warn(`404 - Route not found: ${req.method} ${req.originalUrl}`);
  res.status(404).json({
    success: false,
    message: "Route not found",
    path: req.originalUrl,
    method: req.method,
    suggestion: "Check /api for available endpoints",
    availableRoutes: [
      "GET /",
      "GET /health",
      "GET /api",
      "POST /api/auth/register",
      "POST /api/auth/login",
      "POST /api/auth/logout",
      "GET /api/auth/profile"
    ]
  });
});

// Error Handler (must be last)
app.use(errorHandler);

// Server Startup
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  logger.info(`☁️ Cloud Storage Server is running on port ${PORT}`);
  logger.info(`🟩 Environment: ${process.env.NODE_ENV || "development"}`);
  logger.info(`💗 Health check: http://localhost:${PORT}/health`);
  logger.info(`📚 API Info: http://localhost:${PORT}/api`);
  logger.info(`🔐 Auth endpoints: http://localhost:${PORT}/api/auth`);
});

// Graceful Shutdown
const gracefulShutdown = (signal) => {
  logger.info(`${signal} received, shutting down gracefully`);
  server.close(() => {
    logger.info('HTTP server closed');
    process.exit(0);
  });

  // Force close after 30 seconds
  setTimeout(() => {
    logger.error('Forced shutdown after timeout');
    process.exit(1);
  }, 30000);
};

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  gracefulShutdown('UNCAUGHT_EXCEPTION');
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  gracefulShutdown('UNHANDLED_REJECTION');
});

export default app;
