import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import dotenv from "dotenv";
import logger from "./utils/logger.js";
import errorHandler from "./middlewares/errorHandler.js";
import connectDB from "./config/mongoDB.js";
import initRedis from "./config/redis.js";

// Load environment variables
dotenv.config();

const app = express();

// Connect to databases
await connectDB();
await initRedis();


// Middleware Stack
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(morgan("combined"));

// Main Route
app.get("/", (req, res) => {
  logger.info(`GET / - IP: ${req.ip}`);
  res.status(200).json({
    success: true,
    message: "Cloud Storage API is running!",
    timestamp: new Date().toISOString(),
    version: "1.0.0",
  });
});

// Health Check Route
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "healthy",
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

// 404 Handler
app.use("*", (req, res) => {
  logger.warn(`404 - Route not found: ${req.method} ${req.originalUrl}`);
  res.status(404).json({
    success: false,
    message: "Route not found",
    path: req.originalUrl,
  });
});

// Error Handler
app.use(errorHandler);

// Server Startup
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`☁️ Cloud Storage Server is running on port ${PORT}`);
  logger.info(`🟩 Environment: ${process.env.NODE_ENV || "development"}`);
  logger.info(`💗 Health check: http://localhost:${PORT}/health`);
});

// Graceful Shutdown
process.on("SIGTERM", () => {
  logger.info("SIGTERM received, shutting down gracefully");
  process.exit(0);
});

process.on("SIGINT", () => {
  logger.info("SIGINT received, shutting down gracefully");
  process.exit(0);
});
