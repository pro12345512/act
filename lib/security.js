/**
 * Security & Sanitization Utilities
 */

const crypto = require('crypto');

/**
 * Constant-time string comparison to defend against timing attacks.
 */
function timingSafeEqualStr(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const bufA = Buffer.from(a, 'utf8');
    const bufB = Buffer.from(b, 'utf8');
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Sanitize and validate distributor device token.
 * Accepts alphanumeric, hyphens, and underscores (length 8 to 128).
 */
function sanitizeToken(token) {
    if (!token || typeof token !== 'string') return null;
    const trimmed = token.trim();
    // Enforce strict character whitelist to prevent path traversal or injection
    if (!/^[a-zA-Z0-9\-_]{8,128}$/.test(trimmed)) {
        return null;
    }
    return trimmed;
}

/**
 * Sanitize and validate client Hardware ID (HID).
 * Accepts uppercase alphanumeric, hyphens, and underscores (length 4 to 64).
 */
function sanitizeHid(hid) {
    if (!hid || typeof hid !== 'string') return null;
    const cleaned = hid.trim().toUpperCase().replace(/[^A-Z0-9\-_]/g, '');
    if (cleaned.length < 4 || cleaned.length > 64) {
        return null;
    }
    return cleaned;
}

/**
 * Sanitize distributor display name.
 */
function sanitizeName(name) {
    if (!name || typeof name !== 'string') return 'موزع';
    // Remove HTML tags, control chars, and truncate to 100 characters
    const cleaned = name.replace(/<[^>]*>/g, '').trim().slice(0, 100);
    return cleaned || 'موزع';
}

/**
 * Extract client IP address safely from Vercel / proxy headers.
 */
function getClientIp(req) {
    const xForwardedFor = req.headers['x-forwarded-for'];
    if (xForwardedFor) {
        return xForwardedFor.split(',')[0].trim();
    }
    return req.headers['x-real-ip'] ||
           req.socket?.remoteAddress ||
           req.connection?.remoteAddress ||
           'unknown';
}

/**
 * Apply security headers to response.
 */
function setSecurityHeaders(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
}

/**
 * Handle CORS headers and preflight requests.
 * Returns true if request was handled (OPTIONS), false otherwise.
 */
function handleCors(req, res, allowedOrigins) {
    const origin = req.headers['origin'];

    if (allowedOrigins.includes('*')) {
        res.setHeader('Access-Control-Allow-Origin', origin || '*');
    } else if (origin && allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    } else if (!origin) {
        // Same-origin or server-to-server request
        res.setHeader('Access-Control-Allow-Origin', allowedOrigins[0] || '*');
    } else {
        // Disallowed origin
        res.setHeader('Access-Control-Allow-Origin', 'null');
    }

    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    res.setHeader('Access-Control-Max-Age', '86400');

    if (req.method === 'OPTIONS') {
        res.statusCode = 204;
        res.end();
        return true;
    }
    return false;
}

/**
 * Send sanitized JSON response.
 */
function sendJson(res, statusCode, data) {
    setSecurityHeaders(res);
    res.statusCode = statusCode;
    res.end(JSON.stringify(data));
}

/**
 * Send sanitized error response without leaking internal server information.
 */
function sendError(res, statusCode, publicMessage, internalError = null) {
    if (internalError) {
        console.error(`[API ERROR ${statusCode}]`, publicMessage, internalError);
    }
    sendJson(res, statusCode, {
        success: false,
        message: publicMessage
    });
}

module.exports = {
    timingSafeEqualStr,
    sanitizeToken,
    sanitizeHid,
    sanitizeName,
    getClientIp,
    setSecurityHeaders,
    handleCors,
    sendJson,
    sendError
};
