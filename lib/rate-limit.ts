import { Redis } from '@upstash/redis';

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL || '',
  token: process.env.UPSTASH_REDIS_REST_TOKEN || '',
});

const WINDOW_SIZE = 60 * 15; // 15 minutes
const MAX_REQUESTS = 5; // 5 attempts per 15 minutes

export async function rateLimit(identifier: string) {
  const key = `rate-limit:${identifier}`;
  
  try {
    const requests = await redis.incr(key);
    
    if (requests === 1) {
      await redis.expire(key, WINDOW_SIZE);
    }
    
    if (requests > MAX_REQUESTS) {
      return {
        success: false,
        limit: MAX_REQUESTS,
        remaining: 0,
        reset: await redis.ttl(key),
      };
    }
    
    return {
      success: true,
      limit: MAX_REQUESTS,
      remaining: Math.max(0, MAX_REQUESTS - requests),
      reset: await redis.ttl(key),
    };
  } catch (error) {
    console.error('Rate limit error:', error);
    // If Redis is not available, allow the request
    return { success: true };
  }
} 