/**
 * InteliScale Activation Suite - Automated Test Suite
 * Tests security, cryptography, rate limiting, and API handlers.
 * Run with: npm test (or node --test test/api.test.js)
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

// Generate test Ed25519 keypair dynamically for test run
const { generateEd25519KeyPair } = require('../lib/license');
const testKeyPair = generateEd25519KeyPair();

// Set test environment variables before requiring modules
process.env.SECRET_KEY = 'InteliSoft_Secure_2026_Key';
process.env.ED25519_PRIVATE_KEY = testKeyPair.privateKey;
process.env.ED25519_PUBLIC_KEY = testKeyPair.publicKey;
process.env.DEFAULT_LICENSE_VERSION = 'v1';
process.env.FIREBASE_DATABASE_URL = 'https://scale-335ba-default-rtdb.firebaseio.com';
process.env.FIREBASE_DB_SECRET = 'test_firebase_secret_12345';
process.env.ADMIN_SECRET = 'SuperAdminSecret_2026';
process.env.ALLOWED_ORIGINS = '*';
process.env.RATE_LIMIT_PER_MINUTE = '20';
process.env.ENABLE_AUDIT_LOGS = 'false'; // disable network logging during tests

const config = require('../lib/config');
const {
    timingSafeEqualStr,
    sanitizeToken,
    sanitizeHid,
    sanitizeName,
    getClientIp,
    setSecurityHeaders,
    handleCors,
    sendJson,
    sendError
} = require('../lib/security');
const { RateLimiter } = require('../lib/rate-limiter');
const {
    generateHmacCode,
    verifyHmacCode,
    issueLicenseV2,
    verifyLicenseV2,
    canonicalStringify
} = require('../lib/license');
const {
    handleCheckDevice,
    handleGenerateCode,
    handleAddDevice
} = require('../lib/actions');
const generatorHandler = require('../api/generator');

// Mock helper to simulate Serverless req/res
function createMockReqRes({ method = 'POST', query = {}, headers = {}, body = null } = {}) {
    const req = {
        method,
        query,
        headers: { 'content-type': 'application/json', ...headers },
        body,
        socket: { remoteAddress: '127.0.0.1' },
        on: (event, cb) => {
            if (event === 'data' && body) cb(typeof body === 'string' ? body : JSON.stringify(body));
            if (event === 'end') cb();
        }
    };

    let statusCode = 200;
    const responseHeaders = {};
    let responseBody = '';

    const res = {
        get statusCode() { return statusCode; },
        set statusCode(code) { statusCode = code; },
        status(code) { statusCode = code; return res; },
        setHeader(key, value) { responseHeaders[key.toLowerCase()] = value; return res; },
        getHeader(key) { return responseHeaders[key.toLowerCase()]; },
        end(data) {
            if (data !== undefined) responseBody = data;
            return res;
        },
        json(data) {
            responseHeaders['content-type'] = 'application/json; charset=utf-8';
            responseBody = JSON.stringify(data);
            return res;
        },
        _getJSON() {
            try { return JSON.parse(responseBody); } catch { return null; }
        },
        _getRaw() { return responseBody; },
        _getHeaders() { return responseHeaders; }
    };

    return { req, res };
}

// =====================================================================
// 1. Cryptography & License Tests (v1 HMAC & v2 Ed25519)
// =====================================================================
test('License v1: HMAC-SHA256 generates exact code matching PHP & Python specifications', () => {
    const clientHid = '94E8565A211C99D2';
    const secretKey = 'InteliSoft_Secure_2026_Key';

    const code = generateHmacCode(clientHid, secretKey);

    // Expected code verified against PHP hash_hmac and Python hmac
    assert.equal(code, '9F61-A19E-B2F3');
    assert.match(code, /^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/);
});

test('License v1: Handles lowercase, spaces, and edge cases in HID consistently', () => {
    const secretKey = 'InteliSoft_Secure_2026_Key';
    const expected = '9F61-A19E-B2F3';

    assert.equal(generateHmacCode('  94e8565a211c99d2  ', secretKey), expected);
    assert.equal(generateHmacCode('94e8565a211c99d2', secretKey), expected);
});

test('License v1: verifyHmacCode correctly validates codes with timing-safety', () => {
    const clientHid = '94E8565A211C99D2';
    const secretKey = 'InteliSoft_Secure_2026_Key';
    const validCode = '9F61-A19E-B2F3';

    assert.equal(verifyHmacCode(clientHid, validCode, secretKey), true);
    assert.equal(verifyHmacCode(clientHid, '9f61-a19e-b2f3', secretKey), true);
    assert.equal(verifyHmacCode(clientHid, '0000-0000-0000', secretKey), false);
    assert.equal(verifyHmacCode('OTHER_HID', validCode, secretKey), false);
    assert.equal(verifyHmacCode(clientHid, validCode, 'WRONG_SECRET'), false);
});

test('License v2: Ed25519 Asymmetric Digital Signature issuance & verification', () => {
    const clientHid = '94E8565A211C99D2';

    const issued = issueLicenseV2({
        clientHid,
        privateKeyPem: testKeyPair.privateKey,
        validDays: 365,
        licenseType: 'ENTERPRISE',
        distributorToken: 'DIST_ABC123'
    });

    assert.ok(issued.licenseKey.startsWith('IS2.'));
    assert.equal(issued.payload.hid, clientHid);
    assert.equal(issued.payload.type, 'ENTERPRISE');
    assert.equal(issued.payload.v, 2);

    // 1. Verification succeeds on matching machine HID
    const check1 = verifyLicenseV2(issued.licenseKey, clientHid, testKeyPair.publicKey);
    assert.equal(check1.valid, true);
    assert.equal(check1.payload.type, 'ENTERPRISE');

    // 2. Verification fails if machine HID differs
    const check2 = verifyLicenseV2(issued.licenseKey, 'DIFFERENT_MACHINE_HID', testKeyPair.publicKey);
    assert.equal(check2.valid, false);
    assert.match(check2.error, /different machine/);

    // 3. Verification fails if signature is altered
    const tamperedKey = issued.licenseKey.slice(0, -4) + 'AAAA';
    const check3 = verifyLicenseV2(tamperedKey, clientHid, testKeyPair.publicKey);
    assert.equal(check3.valid, false);
    assert.match(check3.error, /signature/i);

    // 4. Verification fails if expired
    const expiredIssued = issueLicenseV2({
        clientHid,
        privateKeyPem: testKeyPair.privateKey,
        validDays: -1 // expired yesterday
    });
    const check4 = verifyLicenseV2(expiredIssued.licenseKey, clientHid, testKeyPair.publicKey);
    assert.equal(check4.valid, false);
    assert.match(check4.error, /expired/);
});

test('License v2: Canonical stringifier ensures deterministic JSON key order', () => {
    const objA = { b: 2, a: 1, c: { y: 2, x: 1 } };
    const objB = { a: 1, c: { x: 1, y: 2 }, b: 2 };
    assert.equal(canonicalStringify(objA), canonicalStringify(objB));
});

// =====================================================================
// 2. Security & Sanitization Tests
// =====================================================================
test('Security: timingSafeEqualStr resists timing attacks', () => {
    assert.equal(timingSafeEqualStr('SecretKey123', 'SecretKey123'), true);
    assert.equal(timingSafeEqualStr('SecretKey123', 'SecretKey124'), false);
    assert.equal(timingSafeEqualStr('SecretKey123', 'Short'), false);
    assert.equal(timingSafeEqualStr(null, 'test'), false);
    assert.equal(timingSafeEqualStr(123, '123'), false);
});

test('Security: sanitizeToken strictly filters malicious input and traversal attempts', () => {
    assert.equal(sanitizeToken('550e8400-e29b-41d4-a716-446655440000'), '550e8400-e29b-41d4-a716-446655440000');
    assert.equal(sanitizeToken('94E8565A211C99D2'), '94E8565A211C99D2');

    // Reject path traversals and dangerous characters
    assert.equal(sanitizeToken('../distributors'), null);
    assert.equal(sanitizeToken('token/with/slash'), null);
    assert.equal(sanitizeToken('token.with.dot'), null);
    assert.equal(sanitizeToken('<script>'), null);
    assert.equal(sanitizeToken('ab'), null); // too short (< 8 chars)
    assert.equal(sanitizeToken('a'.repeat(150)), null); // too long (> 128 chars)
});

test('Security: sanitizeHid validates hardware ID format', () => {
    assert.equal(sanitizeHid('94e8565a-211c99d2'), '94E8565A-211C99D2');
    assert.equal(sanitizeHid('HID-1234-5678'), 'HID-1234-5678');
    assert.equal(sanitizeHid('AB'), null); // too short (< 4 chars)
    assert.equal(sanitizeHid('$$$$'), null); // only invalid symbols
});

test('Security: sanitizeName strips HTML and caps length', () => {
    assert.equal(sanitizeName('شركة الموزع المعتمد'), 'شركة الموزع المعتمد');
    assert.equal(sanitizeName('<script>alert("xss")</script>موزع'), 'alert("xss")موزع');
    assert.equal(sanitizeName(null), 'موزع');
});

test('Security: getClientIp extracts proper IP from proxy headers', () => {
    const req1 = { headers: { 'x-forwarded-for': '203.0.113.195, 70.41.3.18' } };
    assert.equal(getClientIp(req1), '203.0.113.195');

    const req2 = { headers: { 'x-real-ip': '198.51.100.4' } };
    assert.equal(getClientIp(req2), '198.51.100.4');

    const req3 = { headers: {}, socket: { remoteAddress: '127.0.0.1' } };
    assert.equal(getClientIp(req3), '127.0.0.1');
});

test('Security: handleCors handles preflight and allowed origins', () => {
    const { req: reqOpt, res: resOpt } = createMockReqRes({ method: 'OPTIONS' });
    const handled = handleCors(reqOpt, resOpt, ['*']);
    assert.equal(handled, true);
    assert.equal(resOpt.statusCode, 204);
    assert.equal(resOpt.getHeader('access-control-allow-origin'), '*');
});

// =====================================================================
// 3. Rate Limiter Tests
// =====================================================================
test('RateLimiter: enforces sliding window limits', () => {
    const limiter = new RateLimiter();
    const key = 'test-ip-1';
    const limit = 3;
    const windowMs = 1000;

    // Requests 1 to 3 should be allowed
    assert.equal(limiter.check(key, limit, windowMs).allowed, true);
    assert.equal(limiter.check(key, limit, windowMs).allowed, true);
    assert.equal(limiter.check(key, limit, windowMs).allowed, true);

    // 4th request must be rejected
    const blocked = limiter.check(key, limit, windowMs);
    assert.equal(blocked.allowed, false);
    assert.equal(blocked.remaining, 0);
    assert.ok(blocked.resetMs > 0);
});

// =====================================================================
// 4. API Endpoints & Actions Tests (with mocked database)
// =====================================================================
test('API: generator rejects non-POST requests with 405', async () => {
    const { req, res } = createMockReqRes({ method: 'GET' });
    await generatorHandler(req, res);

    assert.equal(res.statusCode, 405);
    const body = res._getJSON();
    assert.equal(body.success, false);
});

test('API: generator rejects unknown action with 400', async () => {
    const { req, res } = createMockReqRes({
        method: 'POST',
        query: { action: 'unknown-action' },
        body: {}
    });
    await generatorHandler(req, res);

    assert.equal(res.statusCode, 400);
    const body = res._getJSON();
    assert.equal(body.success, false);
    assert.match(body.message, /غير معروفة/);
});

test('API: check-device handles missing or invalid token', async () => {
    const { req, res } = createMockReqRes({
        method: 'POST',
        query: { action: 'check-device' },
        body: { device_token: '' }
    });
    await generatorHandler(req, res);

    assert.equal(res.statusCode, 200);
    const body = res._getJSON();
    assert.equal(body.success, false);
    assert.match(body.message, /مطلوب/);
});

test('API: add-device enforces timing-safe admin authentication', async () => {
    // Attempt with incorrect admin secret
    const { req, res } = createMockReqRes({
        method: 'POST',
        query: { action: 'add-device' },
        body: {
            admin_secret: 'WrongSecret',
            device_token: 'valid-token-12345',
            name: 'موزع تجريبي'
        }
    });
    await generatorHandler(req, res);

    assert.equal(res.statusCode, 403);
    const body = res._getJSON();
    assert.equal(body.success, false);
    assert.equal(body.message, 'غير مصرح');
});

test('API: generate-code requires both device_token and client_hid', async () => {
    const { req, res } = createMockReqRes({
        method: 'POST',
        query: { action: 'generate-code' },
        body: { device_token: 'token-123' } // missing client_hid
    });
    await generatorHandler(req, res);

    assert.equal(res.statusCode, 200);
    const body = res._getJSON();
    assert.equal(body.success, false);
    assert.match(body.message, /مطلوبان/);
});
