/**
 * InteliScale Generator - Main Application Logic
 * 
 * SPA with 3 screens:
 *   1. loading    → Checking device status
 *   2. activation → Device not registered, show token to admin
 *   3. generator  → Activated device, generate codes
 */

// =====================================================================
// Configuration
// =====================================================================

// Vercel Serverless API Endpoint
const API_URL = '/api/generator';

// =====================================================================
// App State
// =====================================================================

const App = {
    deviceToken: null,
    deviceName: 'موزع',
    currentScreen: null,
    isOnline: navigator.onLine,
};

// =====================================================================
// DOM Helpers
// =====================================================================

function $(id) { return document.getElementById(id); }

function showScreen(name) {
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    const screen = $(`screen-${name}`);
    if (screen) {
        screen.classList.add('active');
        App.currentScreen = name;
    }
    // Update step dots
    updateStepDots(name);
}

function updateStepDots(screenName) {
    const dots = document.querySelectorAll('.step-dot');
    const screens = ['loading', 'activation', 'generator'];
    const idx = screens.indexOf(screenName);
    dots.forEach((dot, i) => {
        dot.classList.remove('active', 'done');
        if (i < idx)  dot.classList.add('done');
        if (i === idx) dot.classList.add('active');
    });
}

function showAlert(screenName, type, message) {
    // Hide all alerts in the screen
    const screen = $(`screen-${screenName}`);
    if (!screen) return;
    screen.querySelectorAll('.alert').forEach(a => a.classList.remove('show'));

    // Show the specific alert
    const alert = $(`alert-${screenName}-${type}`);
    if (alert) {
        alert.querySelector('.alert-msg').textContent = message;
        alert.classList.add('show');
    }
}

function hideAlerts(screenName) {
    const screen = $(`screen-${screenName}`);
    if (!screen) return;
    screen.querySelectorAll('.alert').forEach(a => a.classList.remove('show'));
}

function setButtonLoading(btnId, loading) {
    const btn = $(btnId);
    if (!btn) return;
    if (loading) {
        btn.classList.add('loading');
        btn.disabled = true;
    } else {
        btn.classList.remove('loading');
        btn.disabled = false;
    }
}

// =====================================================================
// API Calls
// =====================================================================

async function apiCall(action, body) {
    let response;
    try {
        response = await fetch(`${API_URL}?action=${action}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(15000) // 15s timeout
        });
    } catch (networkErr) {
        throw new Error('تعذر الاتصال بالخادم. تحقق من اتصالك بالإنترنت.');
    }

    let data;
    try {
        data = await response.json();
    } catch {
        throw new Error(`خطأ غير متوقع في استجابة السيرفر (${response.status})`);
    }

    return data;
}

// =====================================================================
// Screen Logic
// =====================================================================

/**
 * SCREEN 1: Loading
 * Check if device is activated, then route accordingly.
 * Supports both UUID tokens (new) and HID strings (existing distributors).
 */
async function performInitialCheck() {
    showScreen('loading');

    // If user previously saved a custom HID, prefer it
    const savedHid = DeviceManager.getCustomHid();
    if (savedHid) {
        App.deviceToken = savedHid;
    } else {
        App.deviceToken = DeviceManager.getOrCreateToken();
    }

    // Pre-fill activation screen
    const tokenEl = $('activation-token');
    if (tokenEl) tokenEl.textContent = App.deviceToken;
    const hidInput = $('manual-hid-input');
    if (hidInput && savedHid) hidInput.value = savedHid;

    // If cached activation exists (session), skip server check
    if (DeviceManager.isActivationCached()) {
        setTimeout(() => showScreen('generator'), 600);
        return;
    }

    // Check internet
    if (!navigator.onLine) {
        showScreen('activation');
        showAlert('activation', 'error', '⚠️ لا يوجد اتصال بالإنترنت. تحقق من اتصالك وأعد المحاولة.');
        return;
    }

    try {
        const data = await apiCall('check-device', { device_token: App.deviceToken });

        if (data.success) {
            App.deviceName = data.device_name || 'موزع';
            DeviceManager.setActivationCache(true);
            setTimeout(() => {
                setupGeneratorScreen();
                showScreen('generator');
            }, 800);
        } else {
            showScreen('activation');
        }

    } catch (err) {
        console.error('Check device error:', err);
        showScreen('activation');
        showAlert('activation', 'error', 'تعذر الاتصال بالسيرفر. تأكد من اتصالك بالإنترنت.');
    }
}

/**
 * Apply a manually entered HID as the active device token.
 * For distributors already registered in Firebase with their Hardware ID.
 */
function applyManualHid() {
    const hidInput = $('manual-hid-input');
    if (!hidInput) return;

    const hid = hidInput.value.trim().toUpperCase().replace(/[^A-Z0-9\-_]/g, '');
    if (!hid) {
        showAlert('activation', 'error', 'يرجى إدخال الـ HID أولاً.');
        return;
    }

    App.deviceToken = hid;
    DeviceManager.setCustomHid(hid);

    // Update display
    if ($('activation-token')) $('activation-token').textContent = hid;
    hideAlerts('activation');
    setTimeout(() => showAlert('activation', 'success', '✅ تم تعيين الـ HID. اضغط التحقق من التفعيل.'), 50);
}

/**
 * SCREEN 2: Activation
 * User copies token and sends to admin. Then clicks "Verify".
 */
async function verifyActivation() {
    hideAlerts('activation');

    if (!navigator.onLine) {
        showAlert('activation', 'error', 'لا يوجد اتصال بالإنترنت. يرجى الاتصال أولاً.');
        return;
    }

    setButtonLoading('btn-verify', true);

    try {
        const data = await apiCall('check-device', { device_token: App.deviceToken });

        if (data.success) {
            App.deviceName = data.device_name || 'موزع';
            DeviceManager.setActivationCache(true);
            showAlert('activation', 'success', '🎉 تم التفعيل بنجاح! جاري الانتقال...');

            setTimeout(() => {
                setupGeneratorScreen();
                showScreen('generator');
            }, 1200);
        } else {
            showAlert('activation', 'error', data.message || 'هذا الجهاز غير مسجل. تواصل مع المسؤول.');
        }

    } catch (err) {
        showAlert('activation', 'error', 'تعذر الاتصال بالسيرفر: ' + err.message);
    } finally {
        setButtonLoading('btn-verify', false);
    }
}

/**
 * SCREEN 3: Generator
 * Generate activation codes for clients.
 */
function setupGeneratorScreen() {
    const nameEl = $('gen-device-name');
    if (nameEl) nameEl.textContent = App.deviceName;

    const resultCode = $('result-code');
    if (resultCode) {
        resultCode.textContent = '---- ---- ----';
        resultCode.classList.add('placeholder');
    }

    const resultBox = $('result-box');
    if (resultBox) resultBox.classList.remove('has-code');

    // Clear input
    const input = $('client-hid-input');
    if (input) input.value = '';

    hideAlerts('generator');
}

async function generateCode() {
    const input = $('client-hid-input');
    const clientHid = input ? input.value.trim().toUpperCase() : '';

    if (!clientHid) {
        showAlert('generator', 'error', 'يرجى إدخال معرف جهاز العميل (Client HID) أولاً.');
        input?.focus();
        return;
    }

    if (!navigator.onLine) {
        showAlert('generator', 'error', 'لا يوجد اتصال بالإنترنت للتحقق من الصلاحية.');
        return;
    }

    hideAlerts('generator');
    setButtonLoading('btn-generate', true);

    // Show loading state in result box
    const resultCode = $('result-code');
    if (resultCode) {
        resultCode.textContent = 'جاري التوليد...';
        resultCode.classList.add('placeholder');
    }

    try {
        const data = await apiCall('generate-code', {
            device_token: App.deviceToken,
            client_hid: clientHid
        });

        if (data.success) {
            if (resultCode) {
                resultCode.textContent = data.code;
                resultCode.classList.remove('placeholder');
            }
            const resultBox = $('result-box');
            if (resultBox) resultBox.classList.add('has-code');

            showAlert('generator', 'success', '✅ تم توليد كود التفعيل بنجاح.');
        } else {
            if (resultCode) {
                resultCode.textContent = '---- ---- ----';
                resultCode.classList.add('placeholder');
            }
            // If distributor revoked, clear cache and force re-check
            if (data.message && data.message.includes('انتهت صلاحية')) {
                DeviceManager.clearActivationCache();
            }
            showAlert('generator', 'error', data.message || 'فشل توليد الكود.');
        }

    } catch (err) {
        if (resultCode) {
            resultCode.textContent = '---- ---- ----';
            resultCode.classList.add('placeholder');
        }
        showAlert('generator', 'error', 'خطأ في الاتصال: ' + err.message);
    } finally {
        setButtonLoading('btn-generate', false);
    }
}

// =====================================================================
// Copy to Clipboard
// =====================================================================

async function copyToClipboard(text, btnId, successText = 'تم النسخ!') {
    try {
        await navigator.clipboard.writeText(text);
        const btn = $(btnId);
        if (btn) {
            const original = btn.textContent;
            btn.textContent = successText;
            btn.classList.add('copied');
            setTimeout(() => {
                btn.textContent = original;
                btn.classList.remove('copied');
            }, 2000);
        }
    } catch (err) {
        // Fallback for older browsers / iOS
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);

        const btn = $(btnId);
        if (btn) {
            const original = btn.textContent;
            btn.textContent = successText;
            btn.classList.add('copied');
            setTimeout(() => {
                btn.textContent = original;
                btn.classList.remove('copied');
            }, 2000);
        }
    }
}

function copyToken() {
    copyToClipboard(App.deviceToken, 'btn-copy-token', '✓ تم!');
}

function copyCode() {
    const codeEl = $('result-code');
    const code = codeEl ? codeEl.textContent : '';
    if (!code || code.includes('----') || code.includes('جاري')) {
        showAlert('generator', 'error', 'لا يوجد كود لنسخه. قم بتوليد الكود أولاً.');
        return;
    }
    copyToClipboard(code, 'btn-copy-code', '✓ تم النسخ!');
}

// Allow Enter key on input
function handleInputKeydown(event) {
    if (event.key === 'Enter') {
        generateCode();
    }
}

// =====================================================================
// Online / Offline Detection
// =====================================================================

function updateOnlineStatus() {
    const banner = $('offline-banner');
    if (!navigator.onLine) {
        if (banner) banner.classList.add('show');
        App.isOnline = false;
    } else {
        if (banner) banner.classList.remove('show');
        App.isOnline = true;
        // If we were on loading or activation screen, retry
        if (App.currentScreen === 'loading') {
            performInitialCheck();
        }
    }
}

// =====================================================================
// Initialization
// =====================================================================

document.addEventListener('DOMContentLoaded', () => {
    // Online/offline events
    window.addEventListener('online', updateOnlineStatus);
    window.addEventListener('offline', updateOnlineStatus);

    // Start the app
    performInitialCheck();
});
