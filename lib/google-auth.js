/**
 * Google Service Account OAuth2 Token Manager
 * Generates OAuth2 access tokens for Firebase Realtime Database using RS256 JWTs.
 * Built with native Node.js crypto and fetch - no external dependencies required.
 */

const crypto = require('crypto');

let cachedToken = null;
let tokenExpiry = 0;

/**
 * Base64URL encoding helper
 */
function base64url(str) {
    return Buffer.from(str)
        .toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}

/**
 * Parse Service Account credentials from environment variables.
 * Supports:
 *   1. FIREBASE_SERVICE_ACCOUNT (raw JSON string or base64 encoded JSON)
 *   2. FIREBASE_CLIENT_EMAIL + FIREBASE_PRIVATE_KEY (+ optional FIREBASE_PROJECT_ID)
 */
function getServiceAccountCredentials() {
    const rawJson = process.env.FIREBASE_SERVICE_ACCOUNT;
    if (rawJson) {
        try {
            const parsed = JSON.parse(
                rawJson.trim().startsWith('{')
                    ? rawJson
                    : Buffer.from(rawJson, 'base64').toString('utf8')
            );
            return {
                clientEmail: parsed.client_email,
                privateKey: parsed.private_key?.replace(/\\n/g, '\n'),
                projectId: parsed.project_id
            };
        } catch (e) {
            console.error('[AUTH ERROR] Failed to parse FIREBASE_SERVICE_ACCOUNT JSON:', e.message);
        }
    }

    if (process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) {
        return {
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL.trim(),
            privateKey: process.env.FIREBASE_PRIVATE_KEY.trim().replace(/\\n/g, '\n'),
            projectId: process.env.FIREBASE_PROJECT_ID?.trim()
        };
    }

    return null;
}

/**
 * Acquire Google OAuth2 Access Token using Service Account JWT.
 * Returns cached token if still valid.
 * 
 * @returns {Promise<string|null>} OAuth2 Access Token or null if credentials not configured
 */
async function getAccessToken() {
    const now = Math.floor(Date.now() / 1000);

    // Return cached token if valid for at least 5 more minutes
    if (cachedToken && tokenExpiry > now + 300) {
        return cachedToken;
    }

    const credentials = getServiceAccountCredentials();
    if (!credentials || !credentials.clientEmail || !credentials.privateKey) {
        return null;
    }

    try {
        const header = { alg: 'RS256', typ: 'JWT' };
        const payload = {
            iss: credentials.clientEmail,
            scope: 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/firebase.database',
            aud: 'https://oauth2.googleapis.com/token',
            exp: now + 3600,
            iat: now
        };

        const encodedHeader = base64url(JSON.stringify(header));
        const encodedPayload = base64url(JSON.stringify(payload));
        const unsignedToken = `${encodedHeader}.${encodedPayload}`;

        const signer = crypto.createSign('RSA-SHA256');
        signer.update(unsignedToken);
        signer.end();
        const signature = signer.sign(credentials.privateKey, 'base64url');

        const signedJwt = `${unsignedToken}.${signature}`;

        const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                assertion: signedJwt
            }),
            signal: AbortSignal.timeout(8000)
        });

        if (!tokenResponse.ok) {
            const errBody = await tokenResponse.text();
            console.error('[AUTH ERROR] Google OAuth2 token exchange failed:', tokenResponse.status, errBody);
            return null;
        }

        const data = await tokenResponse.json();
        cachedToken = data.access_token;
        tokenExpiry = now + (data.expires_in || 3600);
        return cachedToken;
    } catch (err) {
        console.error('[AUTH ERROR] Exception in getAccessToken:', err.message);
        return null;
    }
}

/**
 * Clear cached token (useful for testing or if token was revoked).
 */
function resetTokenCache() {
    cachedToken = null;
    tokenExpiry = 0;
}

module.exports = {
    getServiceAccountCredentials,
    getAccessToken,
    resetTokenCache,
    base64url
};
