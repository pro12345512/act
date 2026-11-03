/**
 * InteliScale Configuration Module
 * Loads and validates environment variables.
 * Safe for serverless environments (Node.js 18+).
 */

const fs = require('fs');
const path = require('path');

// Simple .env parser for local dev without external dotenv package
function loadEnvFile() {
    try {
        const envPath = path.resolve(process.cwd(), '.env');
        if (fs.existsSync(envPath)) {
            const content = fs.readFileSync(envPath, 'utf8');
            content.split('\n').forEach(line => {
                const trimmed = line.trim();
                if (!trimmed || trimmed.startsWith('#')) return;
                const eqIdx = trimmed.indexOf('=');
                if (eqIdx !== -1) {
                    const key = trimmed.slice(0, eqIdx).trim();
                    const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
                    if (!process.env[key]) {
                        process.env[key] = val;
                    }
                }
            });
        }
    } catch {
        // Ignore if unable to read local .env
    }
}

// Load local .env if present
loadEnvFile();

const config = {
    // Cryptographic HMAC Secret Key (Legacy v1 backward compatibility)
    SECRET_KEY: (process.env.SECRET_KEY || '').trim().replace(/^["']|["']$/g, ''),

    // Next-Gen Ed25519 Asymmetric Keys
    ED25519_PRIVATE_KEY: (process.env.ED25519_PRIVATE_KEY || '').trim().replace(/^["']|["']$/g, '').replace(/\\n/g, '\n'),
    ED25519_PUBLIC_KEY: (process.env.ED25519_PUBLIC_KEY || '').trim().replace(/^["']|["']$/g, '').replace(/\\n/g, '\n'),

    // Default license version to issue: 'v1' or 'v2'
    DEFAULT_LICENSE_VERSION: (process.env.DEFAULT_LICENSE_VERSION || 'v1').trim(),

    // Firebase Realtime Database URL
    FIREBASE_DATABASE_URL: (process.env.FIREBASE_DATABASE_URL || 'https://scale-335ba-default-rtdb.firebaseio.com').trim().replace(/^["']|["']$/g, '').replace(/\/$/, ''),

    // Firebase Database Secret / Auth Token (Legacy fallback)
    FIREBASE_DB_SECRET: (process.env.FIREBASE_DB_SECRET || '').trim().replace(/^["']|["']$/g, ''),

    // Firebase Service Account OAuth2 (Recommended)
    FIREBASE_SERVICE_ACCOUNT: (process.env.FIREBASE_SERVICE_ACCOUNT || '').trim(),
    FIREBASE_CLIENT_EMAIL: (process.env.FIREBASE_CLIENT_EMAIL || '').trim().replace(/^["']|["']$/g, ''),
    FIREBASE_PRIVATE_KEY: (process.env.FIREBASE_PRIVATE_KEY || '').trim().replace(/^["']|["']$/g, '').replace(/\\n/g, '\n'),
    FIREBASE_PROJECT_ID: (process.env.FIREBASE_PROJECT_ID || '').trim().replace(/^["']|["']$/g, ''),

    // Firebase Web API Key (Identity Toolkit — email/password login)
    // From: Firebase Console → Project settings → General → Web API Key
    FIREBASE_WEB_API_KEY: (process.env.FIREBASE_WEB_API_KEY || process.env.FIREBASE_API_KEY || '').trim().replace(/^["']|["']$/g, ''),

    // Admin secret for privileged operations like add-device
    ADMIN_SECRET: (process.env.ADMIN_SECRET || process.env.FIREBASE_DB_SECRET || '').trim().replace(/^["']|["']$/g, ''),

    // Allowed CORS Origins
    ALLOWED_ORIGINS: (process.env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim()),

    // Rate Limiting (Requests per minute)
    RATE_LIMIT_PER_MINUTE: parseInt(process.env.RATE_LIMIT_PER_MINUTE, 10) || 20,

    // Audit logs toggle
    ENABLE_AUDIT_LOGS: process.env.ENABLE_AUDIT_LOGS !== 'false',

    // Environment
    NODE_ENV: process.env.NODE_ENV || 'production',

    /**
     * Validate that critical configuration is present.
     */
    validate() {
        const missing = [];
        if (!this.FIREBASE_DATABASE_URL) missing.push('FIREBASE_DATABASE_URL');
        if (!this.FIREBASE_DB_SECRET && !this.FIREBASE_SERVICE_ACCOUNT && !this.FIREBASE_CLIENT_EMAIL) {
            missing.push('FIREBASE credentials (either FIREBASE_SERVICE_ACCOUNT or FIREBASE_DB_SECRET)');
        }
        if (!this.SECRET_KEY && !this.ED25519_PRIVATE_KEY) {
            missing.push('License signing key (either SECRET_KEY or ED25519_PRIVATE_KEY)');
        }

        if (missing.length > 0) {
            console.error(`[CONFIG WARNING] Missing required environment variables: ${missing.join(', ')}`);
            return false;
        }
        return true;
    }
};

module.exports = config;
