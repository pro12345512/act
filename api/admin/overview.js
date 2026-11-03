/**
 * GET /api/admin/overview
 * Returns aggregated statistics for the admin dashboard.
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
        // Fetch distributors
        const { url: distUrl, headers } = await getAuthenticatedRequest('/distributors');
        const distRes = await fetch(distUrl, { method: 'GET', headers, signal: AbortSignal.timeout(8000) });
        const distributors = distRes.ok ? (await distRes.json() || {}) : {};

        // Fetch monitoring clients
        const { url: clientsUrl, headers: ch } = await getAuthenticatedRequest('/monitoring/clients');
        const clientsRes = await fetch(clientsUrl, { method: 'GET', headers: ch, signal: AbortSignal.timeout(8000) });
        const clients = clientsRes.ok ? (await clientsRes.json() || {}) : {};

        // Fetch recent generation logs (last window)
        const { url: logsUrl, headers: lh } = await getAuthenticatedRequest(
            '/generation_logs',
            'orderBy="timestamp"&limitToLast=100'
        );
        const logsRes = await fetch(logsUrl, { method: 'GET', headers: lh, signal: AbortSignal.timeout(8000) });
        const logs = logsRes.ok ? (await logsRes.json() || {}) : {};

        // Aggregate stats
        const distArr = Object.values(distributors);
        const totalDistributors = distArr.length;
        const activeDistributors = distArr.filter(d => d && d.status === 'active').length;
        const totalLicenses = Object.keys(logs).length;

        // Online clients: last_seen within 10 minutes
        const now = Date.now();
        const TEN_MIN = 10 * 60 * 1000;
        const clientArr = Object.entries(clients);
        const totalClients = clientArr.length;
        const onlineClients = clientArr.filter(([, c]) => {
            return c && c.info && c.info.last_seen && (now - c.info.last_seen) < TEN_MIN;
        }).length;

        // Error counts from events (scan last N events for ERROR/CRITICAL)
        let errorCount = 0;
        let criticalCount = 0;
        for (const [, client] of clientArr) {
            if (!client || !client.events) continue;
            for (const ev of Object.values(client.events)) {
                if (!ev) continue;
                if (ev.severity === 'CRITICAL') criticalCount++;
                else if (ev.severity === 'ERROR') errorCount++;
            }
        }

        return sendJson(res, 200, {
            success: true,
            stats: {
                distributors: { total: totalDistributors, active: activeDistributors },
                clients: { total: totalClients, online: onlineClients },
                licenses: { total: totalLicenses },
                errors: { errors: errorCount, critical: criticalCount }
            },
            server_ts: now
        });
    } catch (err) {
        console.error('[ADMIN OVERVIEW ERROR]', err.message);
        return sendError(res, 500, 'Failed to fetch overview data');
    }
};
