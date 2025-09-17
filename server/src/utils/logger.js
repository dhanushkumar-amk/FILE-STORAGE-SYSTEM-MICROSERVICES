const path = require("path");
const fs = require("fs");
const winston = require("winston");

// Logs directory inside server/src/logs
const logDir = path.join(__dirname, "../logs");

// Ensure logs directory exists
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

const logger = winston.createLogger({
  level: process.env.NODE_ENV === "production" ? "info" : "debug",
  format: winston.format.combine(
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  transports: [
    // Console logs (for development)
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),

    // Error logs → server/src/logs/error.log
    new winston.transports.File({
      filename: path.join(logDir, "error.log"),
      level: "error",
    }),

    // Combined logs → server/src/logs/combined.log
    new winston.transports.File({
      filename: path.join(logDir, "combined.log"),
    }),
  ],
});

module.exports = logger;
