/**
 * GET /api/admin/errors
 * Lists recent ERROR and CRITICAL events across all clients.
 *
 * Query params:
 *   ?severity=ERROR|CRITICAL  (default: both)
 *   ?limit=N                  (default: 100, max: 500)
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

    const severityFilter = req.query?.severity?.toUpperCase();
    const allowedSeverities = new Set(
        severityFilter && ['ERROR', 'CRITICAL'].includes(severityFilter)
            ? [severityFilter]
            : ['ERROR', 'CRITICAL']
    );
    const limit = Math.min(500, parseInt(req.query?.limit) || 100);

    try {
        const { url, headers } = await getAuthenticatedRequest('/monitoring/clients');
        const response = await fetch(url, { method: 'GET', headers, signal: AbortSignal.timeout(10000) });

        if (!response.ok) {
            return sendError(res, 502, 'Failed to fetch data from database');
        }

        const clients = await response.json() || {};
        const errors = [];

        for (const [clientId, data] of Object.entries(clients)) {
            if (!data || !data.events) continue;
            const info = data.info || {};
            for (const ev of Object.values(data.events)) {
                if (!ev || !allowedSeverities.has(ev.severity)) continue;
                errors.push({
                    ...ev,
                    client_id: clientId,
                    distributor_name: info.distributor_name || 'Unknown'
                });
            }
        }

        // Sort newest first, then slice
        errors.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
        const result = errors.slice(0, limit);

        return sendJson(res, 200, {
            success: true,
            errors: result,
            total: result.length,
            has_more: errors.length > limit
        });
    } catch (err) {
        console.error('[ADMIN ERRORS ERROR]', err.message);
        return sendError(res, 500, 'Failed to fetch errors');
    }
};
