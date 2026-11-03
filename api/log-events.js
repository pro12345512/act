/**
 * POST /api/log-events
 * Receives batch monitoring events from InteliScale desktop clients.
 *
 * Auth: Validates device_token against /distributors in Firebase.
 * Security: Rate limiting, deduplication, input sanitization, no secrets in response.
 */

const { getDistributor, getAuthenticatedRequest } = require('../lib/firebase');
const { sanitizeToken, getClientIp, handleCors, sendJson, sendError, setSecurityHeaders } = require('../lib/security');
const { checkRateLimit } = require('../lib/rate-limiter');

// Allowed event types (allowlist — reject anything unknown)
const ALLOWED_EVENT_TYPES = new Set([
    'APP_START', 'APP_STOP', 'EXCEPTION', 'DB_ERROR',
    'SERIAL_CONNECT', 'SERIAL_DISCONNECT', 'WEIGHT_ERROR',
    'PRINT_ERROR', 'INVOICE_ERROR', 'LICENSE_CHECK', 'LICENSE_OK',
    'LICENSE_FAIL', 'HEARTBEAT', 'NETWORK_ERROR', 'CUSTOM'
]);

// Allowed severity levels
const ALLOWED_SEVERITIES = new Set(['INFO', 'WARNING', 'ERROR', 'CRITICAL']);

// Fields that must NEVER be stored (scrub before writing to Firebase)
const SENSITIVE_FIELD_PATTERNS = [
    /password/i, /secret/i, /key/i, /token/i, /auth/i,
    /firebase/i, /credential/i, /private/i
];

// Max batch size per request
const MAX_BATCH_SIZE = 50;
// Max string field length
const MAX_FIELD_LEN = 2000;

/**
 * Scrub sensitive keys from an object (deep).
 */
function scrubSensitive(obj, depth = 0) {
    if (depth > 5 || typeof obj !== 'object' || obj === null) return obj;
    const result = {};
    for (const [k, v] of Object.entries(obj)) {
        const isSensitive = SENSITIVE_FIELD_PATTERNS.some(p => p.test(k));
        if (isSensitive) {
            result[k] = '[REDACTED]';
        } else if (typeof v === 'object' && v !== null) {
            result[k] = scrubSensitive(v, depth + 1);
        } else if (typeof v === 'string') {
            result[k] = v.slice(0, MAX_FIELD_LEN);
        } else {
            result[k] = v;
        }
    }
    return result;
}

/**
 * Validate and sanitize a single event object.
 * Returns sanitized event or null if invalid.
 */
function validateEvent(raw, clientId, deviceToken) {
    if (!raw || typeof raw !== 'object') return null;

    const eventId = typeof raw.event_id === 'string' ? raw.event_id.trim().slice(0, 64) : null;
    if (!eventId || !/^[a-zA-Z0-9\-_]{8,64}$/.test(eventId)) return null;

    const eventType = typeof raw.event_type === 'string' ? raw.event_type.trim().toUpperCase() : null;
    if (!eventType || !ALLOWED_EVENT_TYPES.has(eventType)) return null;

    const severity = typeof raw.severity === 'string' ? raw.severity.trim().toUpperCase() : 'INFO';
    if (!ALLOWED_SEVERITIES.has(severity)) return null;

    const message = typeof raw.message === 'string' ? raw.message.trim().slice(0, 500) : '';
    const version = typeof raw.version === 'string' ? raw.version.trim().slice(0, 30) : 'unknown';
    const ts = typeof raw.timestamp === 'number' ? raw.timestamp : Date.now();

    // Sanitize optional details object
    let details = null;
    if (raw.details && typeof raw.details === 'object') {
        details = scrubSensitive(raw.details);
    }

    // Sanitize OS info string (no objects from client)
    const osInfo = typeof raw.os_info === 'string' ? raw.os_info.trim().slice(0, 200) : null;

    return {
        event_id: eventId,
        client_id: clientId,
        device_token_hash: deviceToken.slice(0, 6) + '***', // never store full token in events
        event_type: eventType,
        severity,
        message,
        version,
        os_info: osInfo,
        details,
        timestamp: ts,
        server_ts: Date.now()
    };
}

/**
 * Write a single event to Firebase under /monitoring/events/{clientId}/{eventId}
 * Returns true on success, false on failure or duplicate.
 */
async function writeEvent(clientId, event) {
    try {
        const path = `/monitoring/events/${clientId}/${event.event_id}`;
        const { url, headers } = await getAuthenticatedRequest(path);

        // Check for duplicate first (GET)
        const checkRes = await fetch(url, { method: 'GET', headers, signal: AbortSignal.timeout(4000) });
        if (checkRes.ok) {
            const existing = await checkRes.json();
            if (existing !== null) return { written: false, duplicate: true };
        }

        // Write event
        const putRes = await fetch(url, {
            method: 'PUT',
            headers,
            body: JSON.stringify(event),
            signal: AbortSignal.timeout(5000)
        });
        return { written: putRes.ok, duplicate: false };
    } catch {
        return { written: false, duplicate: false };
    }
}

/**
 * Update client's last_seen and info in /monitoring/clients/{clientId}
 */
async function updateClientInfo(clientId, deviceToken, event) {
    try {
        const path = `/monitoring/clients/${clientId}/info`;
        const { url, headers } = await getAuthenticatedRequest(path);
        await fetch(url, {
            method: 'PATCH',
            headers,
            body: JSON.stringify({
                device_token_prefix: deviceToken.slice(0, 6) + '***',
                last_seen: Date.now(),
                last_version: event.version || 'unknown',
                last_os: event.os_info || null,
                last_event: event.event_type
            }),
            signal: AbortSignal.timeout(5000)
        });
    } catch {
        // Non-critical — don't fail the request
    }
}

module.exports = async function handler(req, res) {
    const requestId = Math.random().toString(36).slice(2, 10);
    res.setHeader('X-Request-ID', requestId);
    setSecurityHeaders(res);

    // CORS: allow all origins — Python desktop client may not have an origin
    if (handleCors(req, res, ['*'])) return;

    if (req.method !== 'POST') {
        return sendError(res, 405, 'Method not allowed');
    }

    // --- Parse body ---
    let body;
    try {
        if (typeof req.body === 'object') {
            body = req.body;
        } else {
            const text = await new Promise((resolve, reject) => {
                let data = '';
                req.on('data', chunk => { data += chunk; if (data.length > 100000) reject(new Error('Too large')); });
                req.on('end', () => resolve(data));
                req.on('error', reject);
            });
            body = JSON.parse(text);
        }
    } catch {
        return sendError(res, 400, 'Invalid JSON body');
    }

    // --- Rate limiting (in-memory, per IP) ---
    const ip = getClientIp(req);
    const rateKey = `log-events:${ip}`;
    const rateLimitResult = checkRateLimit(rateKey, 20, 60000); // 20 req/min
    if (!rateLimitResult.allowed) {
        res.setHeader('Retry-After', Math.ceil(rateLimitResult.resetMs / 1000));
        return sendError(res, 429, 'Too many requests. Please try again later.');
    }

    // --- Validate device token ---
    const deviceToken = sanitizeToken(body.device_token);
    if (!deviceToken) {
        return sendError(res, 400, 'Missing or invalid device_token');
    }

    // --- Verify token against Firebase ---
    const { found, data: distributor } = await getDistributor(deviceToken);
    if (!found || !distributor) {
        return sendError(res, 401, 'Device not registered');
    }
    if (distributor.status !== 'active') {
        return sendError(res, 403, 'Device is not active');
    }

    // --- Validate events array ---
    const events = body.events;
    if (!Array.isArray(events) || events.length === 0) {
        return sendError(res, 400, 'events must be a non-empty array');
    }
    if (events.length > MAX_BATCH_SIZE) {
        return sendError(res, 400, `Maximum batch size is ${MAX_BATCH_SIZE} events`);
    }

    // --- Derive client_id from token (never store plain token as key) ---
    const { createHash } = require('crypto');
    const clientId = createHash('sha256').update(deviceToken).digest('hex').slice(0, 16);

    // --- Process events ---
    let written = 0;
    let duplicates = 0;
    let invalid = 0;

    // Find the most recent event to update client info
    let latestEvent = null;

    for (const rawEvent of events) {
        const validated = validateEvent(rawEvent, clientId, deviceToken);
        if (!validated) {
            invalid++;
            continue;
        }

        if (!latestEvent || validated.timestamp > latestEvent.timestamp) {
            latestEvent = validated;
        }

        const result = await writeEvent(clientId, validated);
        if (result.duplicate) duplicates++;
        else if (result.written) written++;
        // If not written and not duplicate: Firebase error — still continue
    }

    // --- Update client info ---
    if (latestEvent) {
        await updateClientInfo(clientId, deviceToken, latestEvent);
    }

    return sendJson(res, 200, {
        success: true,
        accepted: written,
        duplicates,
        invalid,
        client_id: clientId,
        request_id: requestId
    });
};
