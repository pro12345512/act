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
    sanitizeEmail,
    emailToKey,
    getBearerToken,
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
    findDistributorForUser,
    logGeneration,
    checkDistributedRateLimit
} = require('./firebase');
const { signInWithPassword, lookupIdToken, refreshIdToken } = require('./firebase-auth');

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
 * Ensure an authenticated Firebase user is an active distributor.
 * Auto-creates an active RTDB record on first successful login.
 */
async function resolveEmailDistributor(authUser) {
    const email = sanitizeEmail(authUser.email);
    const uid = authUser.uid;
    if (!email && !uid) {
        return { ok: false, message: 'تعذر قراءة بيانات الحساب.' };
    }

    const result = await findDistributorForUser({ uid, email });
    if (result.error) {
        return { ok: false, message: 'تعذر الاتصال بقاعدة البيانات: ' + result.error };
    }

    if (result.found && result.data) {
        if (result.data.status !== 'active') {
            return { ok: false, message: 'تم إيقاف صلاحية هذا الموزع. تواصل مع المسؤول.' };
        }
        return {
            ok: true,
            key: result.key,
            name: result.data.name || authUser.name || email || 'موزع',
            data: result.data
        };
    }

    const key = emailToKey(email) || uid;
    const deviceData = {
        status: 'active',
        name: sanitizeName(authUser.name || (email ? email.split('@')[0] : 'موزع')),
        email,
        uid: uid || null,
        created_at: new Date().toISOString(),
        login_type: 'email'
    };
    const saveResult = await saveDistributor(key, deviceData);
    if (!saveResult.success) {
        return { ok: false, message: 'تعذر تفعيل حساب الموزع في قاعدة البيانات.' };
    }
    return { ok: true, key, name: deviceData.name, data: deviceData };
}

function extractIdToken(req, input) {
    return (typeof input?.id_token === 'string' && input.id_token.trim())
        || getBearerToken(req)
        || null;
}

/**
 * ACTION: login
 * POST body: { "email": "...", "password": "..." }
 */
async function handleLogin(req, res, input) {
    const ip = getClientIp(req);
    const allowed = await enforceRateLimit(ip, 'login', 5, 60000);
    if (!allowed) {
        return sendError(res, 429, 'تم تجاوز عدد محاولات تسجيل الدخول. انتظر دقيقة ثم أعد المحاولة.');
    }

    const email = sanitizeEmail(input?.email);
    const password = typeof input?.password === 'string' ? input.password : '';

    if (!email || password.length < 6 || password.length > 128) {
        return sendJson(res, 200, {
            success: false,
            message: 'أدخل بريداً إلكترونياً صالحاً وكلمة مرور.'
        });
    }

    const authResult = await signInWithPassword(email, password);
    if (!authResult.success) {
        return sendJson(res, 200, {
            success: false,
            message: authResult.error || 'فشل تسجيل الدخول.'
        });
    }

    const distributor = await resolveEmailDistributor(authResult.user);
    if (!distributor.ok) {
        return sendJson(res, 200, { success: false, message: distributor.message });
    }

    return sendJson(res, 200, {
        success: true,
        message: 'تم تسجيل الدخول بنجاح.',
        id_token: authResult.user.idToken,
        refresh_token: authResult.user.refreshToken,
        expires_at: authResult.user.expiresAt,
        email,
        uid: authResult.user.uid,
        device_name: distributor.name,
        distributor_key: distributor.key
    });
}

/**
 * ACTION: check-session
 * POST body: { "id_token": "..." } or Authorization: Bearer
 */
async function handleCheckSession(req, res, input) {
    const ip = getClientIp(req);
    const allowed = await enforceRateLimit(ip, 'session', config.RATE_LIMIT_PER_MINUTE * 2, 60000);
    if (!allowed) {
        return sendError(res, 429, 'تم تجاوز حد الطلبات المسموح به. يرجى الانتظار دقيقة.');
    }

    const idToken = extractIdToken(req, input);
    if (!idToken) {
        return sendJson(res, 200, {
            success: false,
            message: 'لا توجد جلسة نشطة.'
        });
    }

    const lookup = await lookupIdToken(idToken);
    if (!lookup.success) {
        return sendJson(res, 200, { success: false, message: lookup.error });
    }

    const distributor = await resolveEmailDistributor(lookup.user);
    if (!distributor.ok) {
        return sendJson(res, 200, { success: false, message: distributor.message });
    }

    return sendJson(res, 200, {
        success: true,
        email: lookup.user.email,
        uid: lookup.user.uid,
        device_name: distributor.name,
        distributor_key: distributor.key
    });
}

/**
 * ACTION: refresh-session
 * POST body: { "refresh_token": "..." }
 */
async function handleRefreshSession(req, res, input) {
    const ip = getClientIp(req);
    const allowed = await enforceRateLimit(ip, 'refresh', config.RATE_LIMIT_PER_MINUTE, 60000);
    if (!allowed) {
        return sendError(res, 429, 'تم تجاوز حد الطلبات المسموح به. يرجى الانتظار دقيقة.');
    }

    const refreshToken = typeof input?.refresh_token === 'string' ? input.refresh_token : '';
    const result = await refreshIdToken(refreshToken);
    if (!result.success) {
        return sendJson(res, 200, { success: false, message: result.error });
    }

    return sendJson(res, 200, {
        success: true,
        id_token: result.user.idToken,
        refresh_token: result.user.refreshToken,
        expires_at: result.user.expiresAt,
        uid: result.user.uid
    });
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

    // Check if Firebase credentials exist
    if (!config.FIREBASE_DB_SECRET && !config.FIREBASE_SERVICE_ACCOUNT && !config.FIREBASE_CLIENT_EMAIL) {
        return sendJson(res, 200, {
            success: false,
            message: 'لم يتم ضبط مفاتيح Firebase في Vercel Environment Variables. يرجى إضافتها في Project Settings.'
        });
    }

    // Diagnostic: Detect if Web API Key was used instead of Database Secret
    if (config.FIREBASE_DB_SECRET && config.FIREBASE_DB_SECRET.startsWith('AIzaSy')) {
        return sendJson(res, 200, {
            success: false,
            message: 'تنبيه: قمت بوضع Web API Key (يبدأ بـ AIzaSy) في FIREBASE_DB_SECRET! المطلوب هو Database Secret من Firebase Console (Project Settings -> Service Accounts -> Database secrets).'
        });
    }

    const result = await getDistributor(token);

    if (result.error) {
        return sendJson(res, 200, {
            success: false,
            message: 'تعذر الاتصال بقاعدة البيانات: ' + result.error
        });
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
 * Email login: send Authorization: Bearer <id_token> instead of device_token.
 */
async function handleGenerateCode(req, res, input) {
    const ip = getClientIp(req);
    const allowed = await enforceRateLimit(ip, 'gen', config.RATE_LIMIT_PER_MINUTE, 60000);
    if (!allowed) {
        return sendError(res, 429, 'تم تجاوز عدد محاولات التوليد المسموح بها في الدقيقة.');
    }

    const clientHid = sanitizeHid(input?.client_hid);
    const token = sanitizeToken(input?.device_token);
    const idToken = extractIdToken(req, input);

    if (!clientHid || (!token && !idToken)) {
        return sendJson(res, 200, {
            success: false,
            message: 'معرف الجهاز وكود العميل (Client HID) مطلوبان وصالحان'
        });
    }

    // Check if Firebase credentials exist
    if (!config.FIREBASE_DB_SECRET && !config.FIREBASE_SERVICE_ACCOUNT && !config.FIREBASE_CLIENT_EMAIL) {
        return sendJson(res, 200, {
            success: false,
            message: 'لم يتم ضبط مفاتيح Firebase في Vercel Environment Variables.'
        });
    }

    let distResult;
    let distributorKey = token;

    if (idToken) {
        const lookup = await lookupIdToken(idToken);
        if (!lookup.success) {
            return sendJson(res, 200, { success: false, message: lookup.error });
        }
        const distributor = await resolveEmailDistributor(lookup.user);
        if (!distributor.ok) {
            return sendJson(res, 200, { success: false, message: distributor.message });
        }
        distResult = { found: true, data: distributor.data };
        distributorKey = distributor.key;
    } else {
        distResult = await getDistributor(token);
        if (distResult.error) {
            return sendJson(res, 200, {
                success: false,
                message: 'فشل التحقق من صلاحية الموزع: ' + distResult.error
            });
        }

        if (!distResult.found || !distResult.data || distResult.data.status !== 'active') {
            return sendJson(res, 200, {
                success: false,
                message: 'انتهت صلاحية الموزع أو غير مسجل. تواصل مع المسؤول.'
            });
        }
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
                distributorToken: distributorKey
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
            distributor_token: String(distributorKey).substring(0, 8) + '...',
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
    const email = sanitizeEmail(input?.email);
    const deviceData = {
        status: 'active',
        name: name,
        created_at: new Date().toISOString(),
        token: token
    };
    if (email) {
        deviceData.email = email;
        deviceData.login_type = 'email';
    }

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
    handleLogin,
    handleCheckSession,
    handleRefreshSession,
    handleCheckDevice,
    handleGenerateCode,
    handleAddDevice,
    enforceRateLimit
};
