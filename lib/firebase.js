/**
 * Firebase Realtime Database Client
 * Supports:
 *   1. Google Service Account OAuth2 Authentication (Recommended)
 *   2. Database Secret / Legacy Auth fallback
 *   3. Distributed Rate Limiting via Firebase RTDB
 *   4. Zero credential leaks to logs or clients
 */

const config = require('./config');
const { getAccessToken } = require('./google-auth');

/**
 * Build request URL and headers with proper authentication.
 */
async function getAuthenticatedRequest(path, customQuery = '') {
    const cleanPath = path.startsWith('/') ? path : `/${path}`;
    const base = `${config.FIREBASE_DATABASE_URL}${cleanPath}.json`;
    const headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    };

    // 1. Try Google Service Account OAuth2 Access Token
    const accessToken = await getAccessToken();
    if (accessToken) {
        headers['Authorization'] = `Bearer ${accessToken}`;
        const url = customQuery ? `${base}?${customQuery}` : base;
        return { url, headers };
    }

    // 2. Fallback to FIREBASE_DB_SECRET
    if (config.FIREBASE_DB_SECRET) {
        const authParam = `auth=${encodeURIComponent(config.FIREBASE_DB_SECRET)}`;
        const query = customQuery ? `${customQuery}&${authParam}` : authParam;
        return { url: `${base}?${query}`, headers };
    }

    return { url: customQuery ? `${base}?${customQuery}` : base, headers };
}

/**
 * Fetch distributor record from Firebase RTDB.
 * @param {string} token Device token
 * @returns {Promise<{ found: boolean, data: object|null, error?: string }>}
 */
async function getDistributor(token) {
    if (!token) return { found: false, data: null };

    try {
        const { url, headers } = await getAuthenticatedRequest(`/distributors/${token}`);
        const response = await fetch(url, {
            method: 'GET',
            headers,
            signal: AbortSignal.timeout(8000)
        });

        if (!response.ok) {
            return {
                found: false,
                data: null,
                error: `Firebase returned HTTP ${response.status}`
            };
        }

        const data = await response.json();
        return {
            found: data !== null,
            data: data || null
        };
    } catch (err) {
        // Redact any auth tokens from logs
        const safeError = String(err.message || err).replace(/auth=[^&]+/g, 'auth=[REDACTED]');
        console.error('[FIREBASE GET ERROR]', safeError);
        return {
            found: false,
            data: null,
            error: 'Database connection failed'
        };
    }
}

/**
 * Save or update a distributor record in Firebase RTDB.
 * @param {string} token Device token
 * @param {object} deviceData Distributor metadata
 * @returns {Promise<{ success: boolean, data?: object, error?: string }>}
 */
async function saveDistributor(token, deviceData) {
    if (!token) return { success: false, error: 'Token is required' };

    try {
        const { url, headers } = await getAuthenticatedRequest(`/distributors/${token}`);
        const response = await fetch(url, {
            method: 'PUT',
            headers,
            body: JSON.stringify(deviceData),
            signal: AbortSignal.timeout(8000)
        });

        if (!response.ok) {
            return {
                success: false,
                error: `Firebase returned HTTP ${response.status}`
            };
        }

        const data = await response.json();
        return { success: true, data };
    } catch (err) {
        const safeError = String(err.message || err).replace(/auth=[^&]+/g, 'auth=[REDACTED]');
        console.error('[FIREBASE PUT ERROR]', safeError);
        return { success: false, error: 'Failed to write to database' };
    }
}

/**
 * Log activation code generation event to Firebase RTDB.
 * @param {object} logData Event details
 */
async function logGeneration(logData) {
    if (!config.ENABLE_AUDIT_LOGS) return;

    try {
        const timestamp = Date.now();
        const logId = `log_${timestamp}_${Math.random().toString(36).substring(2, 8)}`;
        const { url, headers } = await getAuthenticatedRequest(`/generation_logs/${logId}`);

        await fetch(url, {
            method: 'PUT',
            headers,
            body: JSON.stringify({
                ...logData,
                timestamp,
                created_at: new Date().toISOString()
            }),
            signal: AbortSignal.timeout(5000)
        });
    } catch (err) {
        console.warn('[AUDIT LOG WARNING] Failed to record generation log:', err.message);
    }
}

/**
 * Distributed Serverless Rate Limiting backed by Firebase RTDB
 * Prevents bypasses across multiple Vercel function instances.
 * 
 * @param {string} rateKey Hashed key (e.g., ip + action)
 * @param {number} limit Maximum requests allowed
 * @param {number} windowMs Window in ms (e.g., 60000ms = 1m)
 * @returns {Promise<{ allowed: boolean, remaining: number, resetMs: number }>}
 */
async function checkDistributedRateLimit(rateKey, limit, windowMs = 60000) {
    const now = Date.now();
    try {
        const { url, headers } = await getAuthenticatedRequest(`/rate_limits/${rateKey}`);

        // 1. Fetch current limit state
        const getRes = await fetch(url, {
            method: 'GET',
            headers,
            signal: AbortSignal.timeout(3000)
        });

        let current = null;
        if (getRes.ok) {
            current = await getRes.json();
        }

        if (!current || !current.window_start || (now - current.window_start) > windowMs) {
            // New window started
            const newState = { count: 1, window_start: now };
            await fetch(url, {
                method: 'PUT',
                headers,
                body: JSON.stringify(newState),
                signal: AbortSignal.timeout(3000)
            });
            return { allowed: true, remaining: limit - 1, resetMs: windowMs };
        }

        if (current.count >= limit) {
            const resetMs = Math.max(0, current.window_start + windowMs - now);
            return { allowed: false, remaining: 0, resetMs };
        }

        // Increment count
        const updatedCount = (current.count || 0) + 1;
        await fetch(url, {
            method: 'PATCH',
            headers,
            body: JSON.stringify({ count: updatedCount }),
            signal: AbortSignal.timeout(3000)
        });

        return {
            allowed: true,
            remaining: Math.max(0, limit - updatedCount),
            resetMs: Math.max(0, current.window_start + windowMs - now)
        };
    } catch {
        // In case of network timeout or sandbox isolation, caller will fall back to local in-memory limiter
        return null;
    }
}

module.exports = {
    getAuthenticatedRequest,
    getDistributor,
    saveDistributor,
    logGeneration,
    checkDistributedRateLimit
};
