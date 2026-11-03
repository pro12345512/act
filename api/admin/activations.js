/**
 * GET /api/admin/activations
 * Lists recent license generation events from /generation_logs.
 *
 * Query params:
 *   ?limit=N  (default: 50, max: 200)
 *
 * Requires: Authorization: Bearer <ADMIN_SECRET>
 */

const { getAuthenticatedRequest } = require('../../lib/firebase');
const { handleCors, sendJson, sendError } = require('../../lib/security');
const { verifyAdmin } = require('./_auth');

module.exports = async function handler(req, res) {
    if (handleCors(req, res, [process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : '*'])) return;
    if (req.method !== 'GET') return sendError(res, 405, 'Method not allowed');
    if (!verifyAdmin(req, res)) return;

    const limit = Math.min(200, parseInt(req.query?.limit) || 50);

    try {
        const { url, headers } = await getAuthenticatedRequest(
            '/generation_logs',
            `orderBy="timestamp"&limitToLast=${limit}`
        );
        const response = await fetch(url, { method: 'GET', headers, signal: AbortSignal.timeout(8000) });

        if (!response.ok) {
            return sendError(res, 502, 'Failed to fetch activation logs');
        }

        const rawLogs = await response.json() || {};

        // Convert to array, sort newest first
        const logs = Object.entries(rawLogs).map(([id, log]) => ({
            log_id: id,
            distributor_token_prefix: log.distributor_token
                ? log.distributor_token.slice(0, 6) + '***'
                : '???',
            client_hid: log.client_hid || null,
            timestamp: log.timestamp || null,
            created_at: log.created_at || null,
            ip: log.ip ? log.ip.replace(/\.\d+$/, '.***') : null, // partial IP masking
            version: log.version || null
        })).sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

        return sendJson(res, 200, {
            success: true,
            activations: logs,
            total: logs.length
        });
    } catch (err) {
        console.error('[ADMIN ACTIVATIONS ERROR]', err.message);
        return sendError(res, 500, 'Failed to fetch activation logs');
    }
};
