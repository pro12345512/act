/**
 * GET /api/admin/client?id=<clientId>
 * Returns detail view for a single client including recent events.
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

    const clientId = typeof req.query?.id === 'string' ? req.query.id.trim() : null;
    if (!clientId || !/^[a-f0-9]{16}$/.test(clientId)) {
        return sendError(res, 400, 'Valid client id is required (?id=...)');
    }

    try {
        const { url, headers } = await getAuthenticatedRequest(`/monitoring/clients/${clientId}`);
        const response = await fetch(url, { method: 'GET', headers, signal: AbortSignal.timeout(8000) });

        if (!response.ok) {
            return sendError(res, 502, 'Failed to fetch client from database');
        }

        const data = await response.json();
        if (!data) {
            return sendError(res, 404, 'Client not found');
        }

        const info = data.info || {};
        const hb = data.heartbeat || {};
        const now = Date.now();

        // Convert events map to sorted array (newest first), limit to 200
        const eventsMap = data.events || {};
        const events = Object.values(eventsMap)
            .filter(Boolean)
            .sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0))
            .slice(0, 200);

        return sendJson(res, 200, {
            success: true,
            client: {
                client_id: clientId,
                info: {
                    distributor_name: info.distributor_name || 'Unknown',
                    device_token_prefix: info.device_token_prefix || '???',
                    last_seen: info.last_seen || hb.ts || null,
                    last_version: info.last_version || 'unknown',
                    last_os: info.last_os || null,
                    last_status: info.last_status || hb.status || 'unknown',
                    is_online: info.last_seen && (now - info.last_seen) < 10 * 60 * 1000
                },
                heartbeat: {
                    ts: hb.ts || null,
                    status: hb.status || null,
                    version: hb.version || null
                },
                events,
                event_summary: {
                    total: events.length,
                    info: events.filter(e => e.severity === 'INFO').length,
                    warning: events.filter(e => e.severity === 'WARNING').length,
                    error: events.filter(e => e.severity === 'ERROR').length,
                    critical: events.filter(e => e.severity === 'CRITICAL').length
                }
            }
        });
    } catch (err) {
        console.error('[ADMIN CLIENT DETAIL ERROR]', err.message);
        return sendError(res, 500, 'Failed to fetch client details');
    }
};
