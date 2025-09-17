import logger from '../utils/logger.js';

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

export default errorHandler;
