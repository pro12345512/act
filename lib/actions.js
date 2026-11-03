/**
 * Core Application Actions
 * Implements business logic for check-device, generate-code, and add-device.
 */

const crypto = require('crypto');
const config = require('./config');
const {
    timingSafeEqualStr,
    sanitizeToken,
    sanitizeHid,
    sanitizeName,
    getClientIp,
    sendJson,
    sendError
} = require('./security');
const { rateLimiter } = require('./rate-limiter');
const { generateHmacCode, issueLicenseV2 } = require('./license');
const {
    getDistributor,
    saveDistributor,
    logGeneration,
    checkDistributedRateLimit
} = require('./firebase');

/**
 * Helper to parse body whether provided by Vercel or raw stream
 */
async function parseBody(req) {
    if (req.body && typeof req.body === 'object') {
        return req.body;
    }
    if (typeof req.body === 'string') {
        try { return JSON.parse(req.body); } catch { return {}; }
    }
    return new Promise((resolve) => {
        let raw = '';
        req.on('data', chunk => { raw += chunk; });
        req.on('end', () => {
            try { resolve(JSON.parse(raw)); } catch { resolve({}); }
        });
        req.on('error', () => resolve({}));
    });
}

/**
 * Hybrid Rate Limiter Helper (L1 In-Memory + L2 Firebase Distributed)
 */
async function enforceRateLimit(ip, action, limit, windowMs = 60000) {
    // 1. Fast L1 In-Memory Check
    const l1 = rateLimiter.check(`${action}:${ip}`, limit, windowMs);
    if (!l1.allowed) {
        return false;
    }

    // 2. L2 Distributed Storage Check (Hashed IP to protect privacy in database)
    const ipHash = crypto.createHash('sha256').update(ip).digest('hex').substring(0, 16);
    const rateKey = `${action}_${ipHash}`;
    const l2 = await checkDistributedRateLimit(rateKey, limit, windowMs);

    if (l2 && !l2.allowed) {
        return false;
    }

    return true;
}

/**
 * ACTION: check-device
 * POST body: { "device_token": "..." }
 */
async function handleCheckDevice(req, res, input) {
    const ip = getClientIp(req);
    const allowed = await enforceRateLimit(ip, 'check', config.RATE_LIMIT_PER_MINUTE * 2, 60000);
    if (!allowed) {
        return sendError(res, 429, 'تم تجاوز حد الطلبات المسموح به. يرجى الانتظار دقيقة.');
    }

    const token = sanitizeToken(input?.device_token);
    if (!token) {
        return sendJson(res, 200, {
            success: false,
            message: 'معرف الجهاز (device_token) مطلوب وغير صالح'
        });
    }

    const result = await getDistributor(token);

    if (result.error) {
        return sendError(res, 500, 'خطأ في الاتصال بقاعدة البيانات. يرجى المحاولة لاحقاً.', result.error);
    }

    if (result.found && result.data && result.data.status === 'active') {
        return sendJson(res, 200, {
            success: true,
            message: 'تم التحقق من التفعيل بنجاح.',
            device_name: result.data.name || 'موزع'
        });
    }

    return sendJson(res, 200, {
        success: false,
        message: 'هذا الجهاز غير مسجل كموزع معتمد. تواصل مع المسؤول على +967770471086'
    });
}

/**
 * ACTION: generate-code
 * POST body: { "device_token": "...", "client_hid": "...", "version": "v1"|"v2" }
 */
async function handleGenerateCode(req, res, input) {
    const ip = getClientIp(req);
    const allowed = await enforceRateLimit(ip, 'gen', config.RATE_LIMIT_PER_MINUTE, 60000);
    if (!allowed) {
        return sendError(res, 429, 'تم تجاوز عدد محاولات التوليد المسموح بها في الدقيقة.');
    }

    const token = sanitizeToken(input?.device_token);
    const clientHid = sanitizeHid(input?.client_hid);

    if (!token || !clientHid) {
        return sendJson(res, 200, {
            success: false,
            message: 'معرف الجهاز وكود العميل (Client HID) مطلوبان وصالحان'
        });
    }

    // Re-verify distributor status before code generation
    const distResult = await getDistributor(token);
    if (distResult.error) {
        return sendError(res, 500, 'فشل التحقق من صلاحية الموزع نتيجة خطأ بالخادم.', distResult.error);
    }

    if (!distResult.found || !distResult.data || distResult.data.status !== 'active') {
        return sendJson(res, 200, {
            success: false,
            message: 'انتهت صلاحية الموزع أو غير مسجل. تواصل مع المسؤول.'
        });
    }

    // Determine requested license version
    const version = (input?.version || config.DEFAULT_LICENSE_VERSION || 'v1').toLowerCase();

    try {
        let code = '';
        let licensePayload = null;

        if (version === 'v2') {
            if (!config.ED25519_PRIVATE_KEY) {
                return sendError(res, 500, 'نظام التوقيع الرقمي Ed25519 غير مهيأ بعد على الخادم.');
            }
            const issueResult = issueLicenseV2({
                clientHid,
                privateKeyPem: config.ED25519_PRIVATE_KEY,
                validDays: parseInt(input?.valid_days, 10) || 365,
                licenseType: input?.license_type || 'COMMERCIAL',
                distributorToken: token
            });
            code = issueResult.licenseKey;
            licensePayload = issueResult.payload;
        } else {
            // Version 1 (Legacy HMAC-SHA256)
            if (!config.SECRET_KEY) {
                return sendError(res, 500, 'مفتاح التوليد السري غير مهيأ على الخادم.');
            }
            code = generateHmacCode(clientHid, config.SECRET_KEY);
        }

        // Audit log asynchronously (non-blocking)
        logGeneration({
            distributor_token: token.substring(0, 8) + '...',
            distributor_name: distResult.data.name || 'موزع',
            client_hid: clientHid,
            version: version,
            ip: ip.includes(':') ? 'ipv6' : ip
        });

        const responseObj = {
            success: true,
            version: version,
            code: code
        };
        if (licensePayload) {
            responseObj.details = licensePayload;
        }

        return sendJson(res, 200, responseObj);
    } catch (err) {
        return sendError(res, 500, 'فشل في توليد كود التفعيل.', err);
    }
}

/**
 * ACTION: add-device (Protected Admin Operation)
 * POST body: { "admin_secret": "...", "device_token": "...", "name": "..." }
 */
async function handleAddDevice(req, res, input) {
    const ip = getClientIp(req);
    // Strict rate limit for admin operations: 5 per minute per IP
    const allowed = await enforceRateLimit(ip, 'admin', 5, 60000);
    if (!allowed) {
        return sendError(res, 429, 'تم حظر الطلبات الإدارية مؤقتاً بسبب تكرار المحاولات.');
    }

    const adminSecret = input?.admin_secret || '';
    if (!config.ADMIN_SECRET || !timingSafeEqualStr(adminSecret, config.ADMIN_SECRET)) {
        console.warn(`[SECURITY ALERT] Unauthorized add-device attempt from IP: ${ip}`);
        return sendJson(res, 403, {
            success: false,
            message: 'غير مصرح'
        });
    }

    const token = sanitizeToken(input?.device_token);
    if (!token) {
        return sendJson(res, 400, {
            success: false,
            message: 'معرف الجهاز (device_token) مطلوب وغير صالح'
        });
    }

    const name = sanitizeName(input?.name);
    const deviceData = {
        status: 'active',
        name: name,
        created_at: new Date().toISOString(),
        token: token
    };

    const saveResult = await saveDistributor(token, deviceData);
    if (!saveResult.success) {
        return sendError(res, 500, 'خطأ في حفظ الجهاز بقاعدة البيانات.', saveResult.error);
    }

    return sendJson(res, 200, {
        success: true,
        message: 'تم إضافة الجهاز بنجاح',
        token: token
    });
}

module.exports = {
    parseBody,
    handleCheckDevice,
    handleGenerateCode,
    handleAddDevice,
    enforceRateLimit
};
