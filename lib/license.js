/**
 * InteliScale Versioned License System
 * 
 * Version 1 (v1): Legacy Symmetric HMAC-SHA256 (12 chars: XXXX-XXXX-XXXX)
 *                 Maintained strictly for backward compatibility with existing client installations.
 * 
 * Version 2 (v2): Asymmetric Digital Signature (Ed25519)
 *                 Server signs structured metadata with Private Key.
 *                 Client verifies with Public Key.
 *                 Impossible to forge offline even if client program is completely decompiled.
 */

const crypto = require('crypto');
const { timingSafeEqualStr } = require('./security');

/**
 * Base64URL helper
 */
function base64url(input) {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
    return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64urlDecode(str) {
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) base64 += '=';
    return Buffer.from(base64, 'base64').toString('utf8');
}

/**
 * Canonical JSON stringifier (guarantees identical key order for signatures)
 */
function canonicalStringify(obj) {
    if (obj === null || typeof obj !== 'object') {
        return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
        return '[' + obj.map(canonicalStringify).join(',') + ']';
    }
    const keys = Object.keys(obj).sort();
    const pairs = keys.map(k => JSON.stringify(k) + ':' + canonicalStringify(obj[k]));
    return '{' + pairs.join(',') + '}';
}

// =====================================================================
// Version 1: Legacy HMAC-SHA256
// =====================================================================

function generateHmacCode(clientHid, secretKey) {
    if (!clientHid || !secretKey) {
        throw new Error('clientHid and secretKey are required');
    }
    const cleanHid = String(clientHid).trim().toUpperCase();
    const hmacHex = crypto
        .createHmac('sha256', secretKey)
        .update(cleanHid, 'utf8')
        .digest('hex')
        .toUpperCase();

    return `${hmacHex.substring(0, 4)}-${hmacHex.substring(4, 8)}-${hmacHex.substring(8, 12)}`;
}

function verifyHmacCode(clientHid, code, secretKey) {
    if (!clientHid || !code || !secretKey) return false;
    try {
        const expected = generateHmacCode(clientHid, secretKey);
        const normalized = String(code).trim().toUpperCase();
        return timingSafeEqualStr(expected, normalized);
    } catch {
        return false;
    }
}

// =====================================================================
// Version 2: Asymmetric Ed25519 Digital Signature
// =====================================================================

function generateEd25519KeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    return { publicKey, privateKey };
}

/**
 * Issue a Version 2 Ed25519 Signed License.
 * 
 * @param {object} options
 * @param {string} options.clientHid Client machine hardware ID
 * @param {string} options.privateKeyPem Server Ed25519 private key (PEM)
 * @param {number} [options.validDays=365] License duration (0 for perpetual)
 * @param {string} [options.licenseType='COMMERCIAL'] License tier/type
 * @param {string} [options.distributorToken=''] Issuer token prefix
 * @returns {{ licenseKey: string, payload: object, signature: string }}
 */
function issueLicenseV2({
    clientHid,
    privateKeyPem,
    validDays = 365,
    licenseType = 'COMMERCIAL',
    distributorToken = ''
}) {
    if (!clientHid || !privateKeyPem) {
        throw new Error('clientHid and privateKeyPem are required to issue v2 license');
    }

    const cleanHid = String(clientHid).trim().toUpperCase();
    const now = Math.floor(Date.now() / 1000);
    // validDays === 0 means perpetual; positive means future days; negative means past (for testing expiration)
    const exp = validDays === 0 ? 0 : now + (validDays * 86400);

    const payload = {
        v: 2,
        hid: cleanHid,
        iat: now,
        exp: exp,
        type: licenseType,
        issuer: distributorToken ? distributorToken.substring(0, 8) : 'INTELISCALE'
    };

    const canonicalData = canonicalStringify(payload);
    const signature = crypto.sign(null, Buffer.from(canonicalData, 'utf8'), privateKeyPem);
    const signatureHex = signature.toString('hex').toUpperCase();

    // Format: IS2.<base64url(payload)>.<signatureHex>
    const encodedPayload = base64url(canonicalData);
    const licenseKey = `IS2.${encodedPayload}.${signatureHex}`;

    return {
        licenseKey,
        payload,
        signature: signatureHex
    };
}

/**
 * Verify a Version 2 License string against client machine HID and public key.
 * 
 * @param {string} licenseKey The full license string (IS2.payload.signature)
 * @param {string} currentHid Client machine hardware ID to compare against
 * @param {string} publicKeyPem Public key in PEM format (stored in client scale.py)
 * @returns {{ valid: boolean, error?: string, payload?: object }}
 */
function verifyLicenseV2(licenseKey, currentHid, publicKeyPem) {
    if (!licenseKey || typeof licenseKey !== 'string') {
        return { valid: false, error: 'License key is missing or invalid format' };
    }

    const parts = licenseKey.trim().split('.');
    if (parts.length !== 3 || parts[0] !== 'IS2') {
        return { valid: false, error: 'Invalid license format or version' };
    }

    try {
        const payloadJson = base64urlDecode(parts[1]);
        const payload = JSON.parse(payloadJson);
        const signatureHex = parts[2];

        // 1. Verify Ed25519 cryptographic signature
        const canonicalData = canonicalStringify(payload);
        const signatureBuf = Buffer.from(signatureHex, 'hex');
        const signatureValid = crypto.verify(
            null,
            Buffer.from(canonicalData, 'utf8'),
            publicKeyPem,
            signatureBuf
        );

        if (!signatureValid) {
            return { valid: false, error: 'Cryptographic signature verification failed (tampered license)' };
        }

        // 2. Verify Hardware ID binding
        const cleanCurrentHid = String(currentHid).trim().toUpperCase();
        if (payload.hid !== cleanCurrentHid) {
            return { valid: false, error: 'License is bound to a different machine hardware ID' };
        }

        // 3. Verify expiration
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp > 0 && now > payload.exp) {
            return { valid: false, error: 'License has expired', payload };
        }

        return { valid: true, payload };
    } catch (e) {
        return { valid: false, error: 'Failed to parse license payload: ' + e.message };
    }
}

module.exports = {
    // V1 (Legacy)
    generateHmacCode,
    verifyHmacCode,
    generateActivationCode: generateHmacCode, // alias for backwards compatibility
    verifyActivationCode: verifyHmacCode,

    // V2 (Asymmetric)
    generateEd25519KeyPair,
    issueLicenseV2,
    verifyLicenseV2,
    canonicalStringify
};
