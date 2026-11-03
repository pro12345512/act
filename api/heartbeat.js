/**
 * POST /api/heartbeat
 * Receives periodic heartbeat pings from InteliScale desktop clients.
 *
 * Writes to /monitoring/clients/{clientId}/heartbeat
 * Updates /monitoring/clients/{clientId}/info
 */

const { getDistributor, getAuthenticatedRequest } = require('../lib/firebase');
const { sanitizeToken, getClientIp, handleCors, sendJson, sendError, setSecurityHeaders } = require('../lib/security');
const { checkRateLimit } = require('../lib/rate-limiter');
const { createHash } = require('crypto');

module.exports = async function handler(req, res) {
    const requestId = Math.random().toString(36).slice(2, 10);
    res.setHeader('X-Request-ID', requestId);
    setSecurityHeaders(res);

    if (handleCors(req, res, ['*'])) return;

    if (req.method !== 'POST') {
        return sendError(res, 405, 'Method not allowed');
    }

    // Parse body
    let body;
    try {
        if (typeof req.body === 'object') {
            body = req.body;
        } else {
            const text = await new Promise((resolve, reject) => {
                let data = '';
                req.on('data', chunk => { data += chunk; if (data.length > 10000) reject(new Error('Too large')); });
                req.on('end', () => resolve(data));
                req.on('error', reject);
            });
            body = JSON.parse(text);
        }
    } catch {
        return sendError(res, 400, 'Invalid JSON body');
    }

    // Rate limiting: max 5 heartbeats/min per IP (interval is 5min, generous limit)
    const ip = getClientIp(req);
    const rateKey = `heartbeat:${ip}`;
    const rl = checkRateLimit(rateKey, 5, 60000);
    if (!rl.allowed) {
        res.setHeader('Retry-After', Math.ceil(rl.resetMs / 1000));
        return sendError(res, 429, 'Too many requests');
    }

    // Validate device token
    const deviceToken = sanitizeToken(body.device_token);
    if (!deviceToken) {
        return sendError(res, 400, 'Missing or invalid device_token');
    }

    // Verify token in Firebase
    const { found, data: distributor } = await getDistributor(deviceToken);
    if (!found || !distributor) {
        return sendError(res, 401, 'Device not registered');
    }
    if (distributor.status !== 'active') {
        return sendError(res, 403, 'Device is not active');
    }

    // Derive stable client_id from token hash
    const clientId = createHash('sha256').update(deviceToken).digest('hex').slice(0, 16);

    const now = Date.now();
    const version = typeof body.version === 'string' ? body.version.trim().slice(0, 30) : 'unknown';
    const osInfo = typeof body.os_info === 'string' ? body.os_info.trim().slice(0, 200) : null;
    const status = typeof body.status === 'string' ? body.status.trim().slice(0, 30) : 'running';

    // Write heartbeat record
    try {
        const hbPath = `/monitoring/clients/${clientId}/heartbeat`;
        const { url, headers } = await getAuthenticatedRequest(hbPath);
        await fetch(url, {
            method: 'PUT',
            headers,
            body: JSON.stringify({
                ts: now,
                status,
                version,
                os_info: osInfo
            }),
            signal: AbortSignal.timeout(5000)
        });
    } catch (err) {
        console.error('[HEARTBEAT] Firebase write error:', err.message);
        // Still return success — heartbeat should not crash client
    }

    // Update client info
    try {
        const infoPath = `/monitoring/clients/${clientId}/info`;
        const { url, headers } = await getAuthenticatedRequest(infoPath);
        await fetch(url, {
            method: 'PATCH',
            headers,
            body: JSON.stringify({
                client_id: clientId,
                device_token_prefix: deviceToken.slice(0, 6) + '***',
                distributor_name: distributor.name || 'Unknown',
                last_seen: now,
                last_version: version,
                last_os: osInfo,
                last_status: status
            }),
            signal: AbortSignal.timeout(5000)
        });
    } catch {
        // Non-critical
    }

    return sendJson(res, 200, {
        success: true,
        client_id: clientId,
        server_ts: now,
        request_id: requestId
    });
};
