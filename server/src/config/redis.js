import { createClient } from "redis";
import logger from "../utils/logger.js";

let redisClient;

async function initRedis() {
  if (!redisClient) {
    redisClient = createClient({
      url: process.env.REDIS_URI, 
    });

    // Event listeners
    redisClient.on("connect", () => {
      logger.info("✅ Redis connected successfully");
    });

    redisClient.on("error", (err) => {
      logger.error("❌ Redis connection failed:", err);
    });
    await redisClient.connect();
  }
  return redisClient;
}

export default initRedis;
