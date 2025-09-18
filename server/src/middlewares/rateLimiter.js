import redisClient from "../config/redis.js";

/**
 * Rate Limiting Middleware
 * @param {number} limit - Max requests per window
 * @param {number} window - Time window in seconds
 * @returns {Function} - Middleware function
 */
const rateLimiter = (limit, window) => {
  return async (req, res, next) => {
    try {
      const ip = req.ip || req.connection.remoteAddress;
      const key = `ratelimit:${ip}`;

      // Increment request count
      const requests = await redisClient.toString(key);

      if (requests === 1) {
        // First request → set expiry
        await redisClient.expire(key, window);
      }

      if (requests > limit) {
        return res.status(429).json({
          success: false,
          message: `⛔ Too many requests. Try again later.`,
        });
      }

      // Continue if within limit
      next();
    } catch (err) {
      console.error("Rate limiter error:", err);
      // Fail open (allow request if Redis is down)
      next();
    }
  };
};

export default rateLimiter;
