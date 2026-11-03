/**
 * Firebase Authentication (Email / Password) via Identity Toolkit REST API.
 * Server-side only — the Web API key never ships to the browser.
 */

const config = require('./config');

const AUTH_BASE = 'https://identitytoolkit.googleapis.com/v1';
const TOKEN_BASE = 'https://securetoken.googleapis.com/v1';

function getWebApiKey() {
    return config.FIREBASE_WEB_API_KEY || '';
}

function mapAuthError(errorMessage) {
    const code = String(errorMessage || '').toUpperCase();
    if (code.includes('USER_DISABLED')) {
        return 'تم تعطيل هذا الحساب. تواصل مع المسؤول.';
    }
    if (code.includes('TOO_MANY_ATTEMPTS')) {
        return 'محاولات كثيرة. يرجى الانتظار قليلاً ثم أعد المحاولة.';
    }
    if (code.includes('INVALID_EMAIL')) {
        return 'صيغة البريد الإلكتروني غير صحيحة.';
    }
    return 'البريد الإلكتروني أو كلمة المرور غير صحيحة.';
}

async function postJson(url, body, timeoutMs = 10000) {
    const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs)
    });
    let data = {};
    try {
        data = await response.json();
    } catch {
        data = {};
    }
    return { ok: response.ok, status: response.status, data };
}

/**
 * Sign in with email and password.
 * @returns {Promise<{ success: boolean, user?: object, error?: string }>}
 */
async function signInWithPassword(email, password) {
    const apiKey = getWebApiKey();
    if (!apiKey) {
        console.error('[FIREBASE AUTH] FIREBASE_WEB_API_KEY is missing. Add it from Firebase Console → Project settings → General → Web API Key.');
        return {
            success: false,
            error: 'خدمة تسجيل الدخول غير مهيأة بعد على الخادم. تواصل مع المسؤول.'
        };
    }

    try {
        const { ok, data } = await postJson(
            `${AUTH_BASE}/accounts:signInWithPassword?key=${encodeURIComponent(apiKey)}`,
            { email, password, returnSecureToken: true }
        );

        if (!ok || data.error) {
            return { success: false, error: mapAuthError(data.error?.message) };
        }

        const expiresInSec = parseInt(data.expiresIn, 10) || 3600;
        return {
            success: true,
            user: {
                idToken: data.idToken,
                refreshToken: data.refreshToken,
                uid: data.localId,
                email: data.email,
                name: data.displayName || '',
                expiresAt: Date.now() + (expiresInSec * 1000)
            }
        };
    } catch (err) {
        console.error('[FIREBASE AUTH] signIn failed:', err.message);
        return { success: false, error: 'تعذر الاتصال بخدمة تسجيل الدخول. تحقق من الإنترنت.' };
    }
}

/**
 * Verify an ID token and return the account profile.
 */
async function lookupIdToken(idToken) {
    const apiKey = getWebApiKey();
    if (!apiKey) {
        return { success: false, error: 'خدمة تسجيل الدخول غير مهيأة على الخادم.' };
    }
    if (!idToken || typeof idToken !== 'string') {
        return { success: false, error: 'جلسة غير صالحة. سجّل الدخول مرة أخرى.' };
    }

    try {
        const { ok, data } = await postJson(
            `${AUTH_BASE}/accounts:lookup?key=${encodeURIComponent(apiKey)}`,
            { idToken: idToken.trim() }
        );

        if (!ok || data.error || !Array.isArray(data.users) || !data.users[0]) {
            return { success: false, error: 'انتهت الجلسة أو غير صالحة. سجّل الدخول مرة أخرى.' };
        }

        const user = data.users[0];
        if (user.disabled) {
            return { success: false, error: 'تم تعطيل هذا الحساب. تواصل مع المسؤول.' };
        }

        return {
            success: true,
            user: {
                uid: user.localId,
                email: user.email,
                name: user.displayName || ''
            }
        };
    } catch (err) {
        console.error('[FIREBASE AUTH] lookup failed:', err.message);
        return { success: false, error: 'تعذر التحقق من الجلسة.' };
    }
}

/**
 * Exchange a refresh token for a new ID token.
 */
async function refreshIdToken(refreshToken) {
    const apiKey = getWebApiKey();
    if (!apiKey) {
        return { success: false, error: 'خدمة تسجيل الدخول غير مهيأة على الخادم.' };
    }
    if (!refreshToken || typeof refreshToken !== 'string') {
        return { success: false, error: 'جلسة غير صالحة. سجّل الدخول مرة أخرى.' };
    }

    try {
        const response = await fetch(
            `${TOKEN_BASE}/token?key=${encodeURIComponent(apiKey)}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `grant_type=refresh_token&refresh_token=${encodeURIComponent(refreshToken.trim())}`,
                signal: AbortSignal.timeout(10000)
            }
        );
        const data = await response.json();
        if (!response.ok || data.error) {
            return { success: false, error: 'انتهت الجلسة. سجّل الدخول مرة أخرى.' };
        }

        const expiresInSec = parseInt(data.expires_in, 10) || 3600;
        return {
            success: true,
            user: {
                idToken: data.id_token,
                refreshToken: data.refresh_token || refreshToken,
                uid: data.user_id,
                expiresAt: Date.now() + (expiresInSec * 1000)
            }
        };
    } catch (err) {
        console.error('[FIREBASE AUTH] refresh failed:', err.message);
        return { success: false, error: 'تعذر تجديد الجلسة.' };
    }
}

module.exports = {
    signInWithPassword,
    lookupIdToken,
    refreshIdToken,
    mapAuthError
};
