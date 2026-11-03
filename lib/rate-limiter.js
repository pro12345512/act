/**
 * In-Memory Sliding Window Rate Limiter
 * Suitable for Vercel Serverless Function instances.
 */

class RateLimiter {
    constructor() {
        this.requests = new Map();
        // Periodically prune stale entries every 5 minutes
        this.cleanupInterval = 5 * 60 * 1000;
        this.lastCleanup = Date.now();
    }

    /**
     * Check if a request should be allowed.
     * @param {string} key Identifier (e.g., client IP + action)
     * @param {number} limit Maximum requests allowed in the window
     * @param {number} windowMs Window duration in milliseconds (default: 60000ms = 1m)
     * @returns {{ allowed: boolean, remaining: number, resetMs: number }}
     */
    check(key, limit, windowMs = 60000) {
        const now = Date.now();
        this.maybeCleanup(now);

        const timestamps = this.requests.get(key) || [];
        const windowStart = now - windowMs;

        // Filter out timestamps outside the active window
        const activeTimestamps = timestamps.filter(ts => ts > windowStart);

        if (activeTimestamps.length >= limit) {
            const oldestInWindow = activeTimestamps[0];
            const resetMs = Math.max(0, oldestInWindow + windowMs - now);
            return {
                allowed: false,
                remaining: 0,
                resetMs
            };
        }

        activeTimestamps.push(now);
        this.requests.set(key, activeTimestamps);

        return {
            allowed: true,
            remaining: limit - activeTimestamps.length,
            resetMs: windowMs
        };
    }

    maybeCleanup(now) {
        if (now - this.lastCleanup > this.cleanupInterval) {
            const expiryThreshold = now - 600000; // 10 minutes
            for (const [key, timestamps] of this.requests.entries()) {
                const valid = timestamps.filter(ts => ts > expiryThreshold);
                if (valid.length === 0) {
                    this.requests.delete(key);
                } else {
                    this.requests.set(key, valid);
                }
            }
            this.lastCleanup = now;
        }
    }

    reset() {
        this.requests.clear();
    }
}

const globalLimiter = new RateLimiter();

module.exports = {
    RateLimiter,
    rateLimiter: globalLimiter
};
