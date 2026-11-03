/**
 * Shared admin authentication middleware.
 * All admin API routes use this to verify ADMIN_SECRET.
 */

const { timingSafeEqualStr, sendError, setSecurityHeaders } = require('../../lib/security');

/**
 * Verify admin authorization header.
 * Returns true if authorized, sends 401/403 and returns false otherwise.
 */
function verifyAdmin(req, res) {
    setSecurityHeaders(res);
    const adminSecret = process.env.ADMIN_SECRET;
    if (!adminSecret) {
        console.error('[ADMIN AUTH] ADMIN_SECRET environment variable is not set');
        sendError(res, 503, 'Admin interface not configured');
        return false;
    }

    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';

    if (!token || !timingSafeEqualStr(token, adminSecret)) {
        sendError(res, 401, 'Unauthorized');
        return false;
    }
    return true;
}

module.exports = { verifyAdmin };
