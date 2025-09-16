// shared/logger.js
const { createLogger, format, transports } = require("winston");
const path = require("path");

// Load service name from env (so each service has its own label)
const serviceName = process.env.SERVICE_NAME || "unknown-service";

const logger = createLogger({
  level: process.env.LOG_LEVEL || "info", // default: info
  format: format.combine(
    format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
    format.errors({ stack: true }),
    format.splat(),
    format.json()
  ),
  defaultMeta: { service: serviceName },
  transports: [
    // Write all logs to combined.log
    new transports.File({
      filename: path.join(__dirname, "../logs/combined.log"),
    }),
    // Write only errors to error.log
    new transports.File({
      filename: path.join(__dirname, "../logs/error.log"),
      level: "error",
    }),
  ],
});

// Add console logging for development
if (process.env.NODE_ENV !== "production") {
  logger.add(
    new transports.Console({
      format: format.combine(
        format.colorize(),
        format.printf(
          (info) =>
            `[${info.timestamp}] [${info.level}] (${info.service}): ${info.message}`
        )
      ),
    })
  );
}

module.exports = logger;
