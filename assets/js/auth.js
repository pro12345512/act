/**
 * InteliScale — Email/password session storage.
 * Tokens stay in localStorage on this device only; the password is never saved.
 */

const SessionManager = (() => {
    const STORAGE_KEY = 'inteli_auth_session';

    function read() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (!raw) return null;
            const parsed = JSON.parse(raw);
            if (!parsed || !parsed.idToken || !parsed.refreshToken) return null;
            return parsed;
        } catch {
            return null;
        }
    }

    function write(session) {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
        } catch (e) {
            console.warn('Unable to persist session', e);
        }
    }

    function clear() {
        try {
            localStorage.removeItem(STORAGE_KEY);
        } catch {
            // ignore
        }
    }

    function get() {
        return read();
    }

    function save(data) {
        write({
            idToken: data.id_token || data.idToken,
            refreshToken: data.refresh_token || data.refreshToken,
            expiresAt: data.expires_at || data.expiresAt || (Date.now() + 3600 * 1000),
            email: data.email || '',
            uid: data.uid || '',
            deviceName: data.device_name || data.deviceName || 'موزع',
            distributorKey: data.distributor_key || data.distributorKey || ''
        });
    }

    function updateTokens(data) {
        const current = read() || {};
        write({
            ...current,
            idToken: data.id_token || data.idToken || current.idToken,
            refreshToken: data.refresh_token || data.refreshToken || current.refreshToken,
            expiresAt: data.expires_at || data.expiresAt || current.expiresAt,
            uid: data.uid || current.uid
        });
    }

    function hasSession() {
        const session = read();
        return !!(session && session.idToken && session.refreshToken);
    }

    function isExpiringSoon(bufferMs = 5 * 60 * 1000) {
        const session = read();
        if (!session || !session.expiresAt) return true;
        return Date.now() >= (session.expiresAt - bufferMs);
    }

    return { get, save, updateTokens, clear, hasSession, isExpiringSoon };
})();
