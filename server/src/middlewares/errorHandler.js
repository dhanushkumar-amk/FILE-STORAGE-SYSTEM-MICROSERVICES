const logger = require("../utils/logger");

// Centralized error handler middleware
const errorHandler = (err, req, res, next) => {
  // Log the error with stack trace
  logger.error(err.stack);

  // Set status code (default: 500)
  const statusCode = err.status || 500;

  res.status(statusCode).json({
    success: false,
    message: err.message || "Internal Server Error",
  });
};

module.exports = errorHandler;
