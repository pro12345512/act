/**
 * InteliScale Generator - Device Token Manager
 * 
 * Generates and persists a unique device token in localStorage.
 * This token is used instead of a Hardware ID (which is unavailable in browsers).
 * 
 * Token format: UUID v4 (e.g., "550e8400-e29b-41d4-a716-446655440000")
 * Storage key: 'inteli_device_token'
 */

const DeviceManager = (() => {

    const STORAGE_KEY = 'inteli_device_token';
    const STORAGE_KEY_NAME = 'inteli_device_name';

    /**
     * Generate a UUID v4
     */
    function generateUUID() {
        if (typeof crypto !== 'undefined' && crypto.randomUUID) {
            return crypto.randomUUID();
        }
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            const r = (Math.random() * 16) | 0;
            const v = c === 'x' ? r : (r & 0x3) | 0x8;
            return v.toString(16);
        });
    }

    /**
     * Cookie Helpers
     */
    function setCookie(name, value, days) {
        let expires = "";
        if (days) {
            let date = new Date();
            date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
            expires = "; expires=" + date.toUTCString();
        }
        // SameSite=Lax helps with some iOS restrictions, Secure if possible (we assume HTTPS or rely on Lax)
        document.cookie = name + "=" + (value || "") + expires + "; path=/; SameSite=Lax";
    }

    function getCookie(name) {
        let nameEQ = name + "=";
        let ca = document.cookie.split(';');
        for (let i = 0; i < ca.length; i++) {
            let c = ca[i];
            while (c.charAt(0) == ' ') c = c.substring(1, c.length);
            if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length, c.length);
        }
        return null;
    }

    /**
     * Get or create the device token.
     * Uses localStorage and falls back to Cookies to support iOS Safari better.
     */
    function getOrCreateToken() {
        let token = null;

        // 1. Try localStorage
        try {
            token = localStorage.getItem(STORAGE_KEY);
        } catch (e) {
            console.warn('localStorage not available', e);
        }

        // 2. Try Cookie if no localStorage token
        if (!token) {
            token = getCookie(STORAGE_KEY);
            if (token) {
                // Restore to localStorage if possible
                try { localStorage.setItem(STORAGE_KEY, token); } catch (e) {}
            }
        }

        // 3. Create new if still no token
        if (!token) {
            token = generateUUID();
            try { localStorage.setItem(STORAGE_KEY, token); } catch (e) {}
            setCookie(STORAGE_KEY, token, 365); // Save for 1 year
        } else {
            // Ensure cookie is set (e.g. if they only had localStorage)
            setCookie(STORAGE_KEY, token, 365);
        }

        return token;
    }

    /**
     * Get the current token (or null if not created yet).
     */
    function getToken() {
        let token = null;
        try { token = localStorage.getItem(STORAGE_KEY); } catch (e) {}
        if (!token) token = getCookie(STORAGE_KEY);
        return token;
    }

    /**
     * Check if a device token already exists (i.e., user has visited before).
     */
    function hasToken() {
        return !!getToken();
    }

    /**
     * Get a short display version of the token (first 8 chars).
     */
    function getShortToken() {
        const token = getOrCreateToken();
        return token.split('-')[0].toUpperCase() + '...';
    }

    /**
     * Save/retrieve the cached activation status to avoid re-checking on every page load.
     */
    function setActivationCache(isActive) {
        if (isActive) {
            try {
                sessionStorage.setItem('inteli_activated', '1');
                sessionStorage.setItem('inteli_activated_at', Date.now().toString());
            } catch (e) {}
        } else {
            try {
                sessionStorage.removeItem('inteli_activated');
                sessionStorage.removeItem('inteli_activated_at');
            } catch (e) {}
        }
    }

    function isActivationCached() {
        try {
            const cached = sessionStorage.getItem('inteli_activated');
            const cachedAt = sessionStorage.getItem('inteli_activated_at');
            if (!cached || !cachedAt) return false;

            // Cache valid for 30 minutes
            const CACHE_DURATION = 30 * 60 * 1000;
            return (Date.now() - parseInt(cachedAt)) < CACHE_DURATION;
        } catch (e) {
            return false;
        }
    }

    function clearActivationCache() {
        try {
            sessionStorage.removeItem('inteli_activated');
            sessionStorage.removeItem('inteli_activated_at');
        } catch (e) {}
    }

    /**
     * Custom HID Storage (for app.js)
     */
    function getCustomHid() {
        let hid = null;
        try { hid = localStorage.getItem('inteli_custom_hid'); } catch (e) {}
        if (!hid) hid = getCookie('inteli_custom_hid');
        return hid;
    }

    function setCustomHid(hid) {
        try { localStorage.setItem('inteli_custom_hid', hid); } catch (e) {}
        setCookie('inteli_custom_hid', hid, 365);
    }

    return {
        getOrCreateToken,
        getToken,
        hasToken,
        getShortToken,
        setActivationCache,
        isActivationCached,
        clearActivationCache,
        getCustomHid,
        setCustomHid
    };

})();
