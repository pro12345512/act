/**
 * Comprehensive Security & Penetration Testing Suite
 * Simulates real HTTP requests against the InteliScale API endpoints.
 */

const http = require('http');
const assert = require('assert');
const server = require('./dev-server');
const { generateHmacCode, generateEd25519KeyPair, issueLicenseV2, verifyLicenseV2 } = require('../lib/license');

const PORT = 3105;
const BASE_URL = `http://localhost:${PORT}`;

async function request(endpoint, options = {}) {
    const url = `${BASE_URL}${endpoint}`;
    const res = await fetch(url, {
        method: options.method || 'GET',
        headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
        body: options.body ? JSON.stringify(options.body) : undefined
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { status: res.status, headers: res.headers, text, json };
}

async function runSecurityAudit() {
    console.log('\n============================================================');
    console.log('🛡️  STARTING COMPREHENSIVE SECURITY & INTEGRATION AUDIT');
    console.log('============================================================\n');

    let passed = 0;
    let failed = 0;

    function record(name, condition, details = '') {
        if (condition) {
            console.log(`  [PASS] ${name}`);
            passed++;
        } else {
            console.error(`  [FAIL] ${name} ${details}`);
            failed++;
        }
    }

    server.listen(PORT, async () => {
        try {
            // 1. Static Web UI & Security Headers
            const homeRes = await request('/');
            record('Web UI loads with 200 OK', homeRes.status === 200);

            const optionsRes = await request('/api/generator', { method: 'OPTIONS' });
            record('CORS OPTIONS preflight returns 204 No Content', optionsRes.status === 204);

            // 2. HTTP Method Validation (Reject GET, PUT, DELETE on API)
            const getApiRes = await request('/api/generator');
            record('GET request to /api/generator rejected with 405', getApiRes.status === 405);

            // 3. Security Headers Enforced on API
            record('X-Content-Type-Options: nosniff present', getApiRes.headers.get('x-content-type-options') === 'nosniff');
            record('X-Frame-Options: DENY present', getApiRes.headers.get('x-frame-options') === 'DENY');

            // 4. Check Unregistered Device
            const unregRes = await request('/api/generator?action=check-device', {
                method: 'POST',
                body: { device_token: 'unregistered-token-uuid-12345' }
            });
            record('Unregistered device rejected with success: false', unregRes.json?.success === false);

            // 5. Malicious & Injection Payloads on device_token
            const injections = [
                '../../etc/passwd',
                '<script>alert("xss")</script>',
                "' OR '1'='1",
                'token; DROP TABLE distributors;--',
                'a'.repeat(250) // buffer overflow attempt
            ];

            for (const payload of injections) {
                const injRes = await request('/api/generator?action=check-device', {
                    method: 'POST',
                    body: { device_token: payload }
                });
                record(`Malicious token injection neutralized: "${payload.substring(0, 15)}..."`,
                    injRes.json?.success === false && !injRes.text.includes('syntax error')
                );
            }

            // 6. Invalid & Malicious HID on generate-code
            const badHids = [
                '',
                '12', // too short
                '$$$$$',
                '<script>',
                '..\\..\\hidden'
            ];
            for (const badHid of badHids) {
                const badHidRes = await request('/api/generator?action=generate-code', {
                    method: 'POST',
                    body: { device_token: '550e8400-e29b-41d4-a716-446655440000', client_hid: badHid }
                });
                record(`Invalid HID rejected safely: "${badHid}"`, badHidRes.json?.success === false);
            }

            // 7. Unauthorized Code Generation Attempt
            const unauthGen = await request('/api/generator?action=generate-code', {
                method: 'POST',
                body: { device_token: 'unregistered-attacker-token', client_hid: '94E8565A211C99D2' }
            });
            record('Unauthorized code generation denied', unauthGen.json?.success === false);

            // 8. Admin Authentication Protection (add-device)
            const badAdmin = await request('/api/generator?action=add-device', {
                method: 'POST',
                body: {
                    admin_secret: 'invalid_pass_12345',
                    device_token: '550e8400-e29b-41d4-a716-446655440000',
                    name: 'Test'
                }
            });
            record('Unauthorized admin request rejected with 403 Forbidden', badAdmin.status === 403 && badAdmin.json?.message === 'غير مصرح');

            // 9. Legacy Rewrite Route Verification (/api/generator.php)
            const legacyRes = await request('/api/generator.php?action=check-device', {
                method: 'POST',
                body: { device_token: 'short' }
            });
            record('Legacy /api/generator.php URL correctly handled by serverless router', legacyRes.status === 200);

            // 10. Rate Limiting Protection (Send rapid burst of requests)
            let rateLimitTriggered = false;
            for (let i = 0; i < 45; i++) {
                const burstRes = await request('/api/generator?action=check-device', {
                    method: 'POST',
                    body: { device_token: 'test-token-12345678' }
                });
                if (burstRes.status === 429) {
                    rateLimitTriggered = true;
                    break;
                }
            }
            record('Rate Limiter successfully triggered 429 Too Many Requests under burst', rateLimitTriggered);

            // 11. Cryptographic Legacy HMAC (v1) Matching Test
            const knownHid = '94E8565A211C99D2';
            const knownSecret = 'InteliSoft_Secure_2026_Key';
            const generatedV1 = generateHmacCode(knownHid, knownSecret);
            record('Legacy HMAC generates exact expected code (9F61-A19E-B2F3)', generatedV1 === '9F61-A19E-B2F3');

            // 12. Cryptographic Next-Gen Ed25519 (v2) Signature & Tamper Resistance
            const keyPair = generateEd25519KeyPair();
            const v2License = issueLicenseV2({ clientHid: knownHid, privateKeyPem: keyPair.privateKey, validDays: 90 });
            const v2CheckValid = verifyLicenseV2(v2License.licenseKey, knownHid, keyPair.publicKey);
            record('Ed25519 license verifies successfully with authentic signature', v2CheckValid.valid === true);

            const v2Tampered = v2License.licenseKey.replace('IS2.', 'IS2.tampered_');
            const v2CheckTampered = verifyLicenseV2(v2Tampered, knownHid, keyPair.publicKey);
            record('Ed25519 license tampering detected and rejected', v2CheckTampered.valid === false);

            console.log('\n============================================================');
            console.log(`📊 AUDIT SUMMARY: ${passed} PASSED | ${failed} FAILED`);
            console.log('============================================================\n');

            server.close();
            if (failed > 0) {
                process.exit(1);
            }
        } catch (err) {
            console.error('Audit execution error:', err);
            server.close();
            process.exit(1);
        }
    });
}

runSecurityAudit();
