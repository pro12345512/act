/**
 * GET /api/admin/clients
 * Lists all known monitoring clients with their status.
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

    try {
        const { url, headers } = await getAuthenticatedRequest('/monitoring/clients');
        const response = await fetch(url, { method: 'GET', headers, signal: AbortSignal.timeout(8000) });

        if (!response.ok) {
            return sendError(res, 502, 'Failed to fetch clients from database');
        }

        const rawClients = await response.json() || {};
        const now = Date.now();
        const TEN_MIN = 10 * 60 * 1000;

        // Shape output — don't expose internal Firebase paths, just useful fields
        const clients = Object.entries(rawClients).map(([clientId, data]) => {
            if (!data) return null;
            const info = data.info || {};
            const hb = data.heartbeat || {};
            const lastSeen = info.last_seen || hb.ts || null;
            const isOnline = lastSeen && (now - lastSeen) < TEN_MIN;

            // Count events by severity
            const events = data.events || {};
            const eventArr = Object.values(events);
            const errorCount = eventArr.filter(e => e && e.severity === 'ERROR').length;
            const criticalCount = eventArr.filter(e => e && e.severity === 'CRITICAL').length;
            const totalEvents = eventArr.length;

            return {
                client_id: clientId,
                distributor_name: info.distributor_name || 'Unknown',
                device_token_prefix: info.device_token_prefix || '???',
                last_seen: lastSeen,
                last_version: info.last_version || 'unknown',
                last_os: info.last_os || null,
                last_status: info.last_status || hb.status || 'unknown',
                is_online: isOnline,
                event_counts: {
                    total: totalEvents,
                    errors: errorCount,
                    critical: criticalCount
                }
            };
        }).filter(Boolean);

        // Sort: online first, then by last_seen desc
        clients.sort((a, b) => {
            if (a.is_online !== b.is_online) return a.is_online ? -1 : 1;
            return (b.last_seen || 0) - (a.last_seen || 0);
        });

        return sendJson(res, 200, { success: true, clients, total: clients.length });
    } catch (err) {
        console.error('[ADMIN CLIENTS ERROR]', err.message);
        return sendError(res, 500, 'Failed to fetch clients');
    }
};
