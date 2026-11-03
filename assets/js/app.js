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
    authMode: false,
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
    const screens = ['loading', 'login', 'generator'];
    let idx = screens.indexOf(screenName);
    if (screenName === 'activation') idx = 1;
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

async function apiCall(action, body, options = {}) {
    let response;
    const headers = { 'Content-Type': 'application/json' };
    if (!options.skipAuth && App.authMode) {
        const session = SessionManager.get();
        if (session?.idToken) {
            headers['Authorization'] = `Bearer ${session.idToken}`;
        }
    }
    try {
        response = await fetch(`${API_URL}?action=${action}`, {
            method: 'POST',
            headers,
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

async function restoreEmailSession() {
    if (!SessionManager.hasSession()) return false;
    if (!navigator.onLine) return false;

    try {
        if (SessionManager.isExpiringSoon()) {
            const session = SessionManager.get();
            const refreshed = await apiCall('refresh-session', {
                refresh_token: session.refreshToken
            }, { skipAuth: true });
            if (!refreshed.success) {
                SessionManager.clear();
                return false;
            }
            SessionManager.updateTokens(refreshed);
        }

        const current = SessionManager.get();
        const data = await apiCall('check-session', { id_token: current.idToken }, { skipAuth: true });
        if (!data.success) {
            SessionManager.clear();
            return false;
        }

        App.authMode = true;
        App.deviceName = data.device_name || SessionManager.get()?.deviceName || 'موزع';
        App.deviceToken = data.distributor_key || null;
        return true;
    } catch (err) {
        console.error('Session restore failed:', err);
        return false;
    }
}

/**
 * SCREEN 1: Loading
 * Restore email session if present, otherwise show login.
 * Device HID activation remains available as a fallback.
 */
async function performInitialCheck() {
    showScreen('loading');

    if (await restoreEmailSession()) {
        setTimeout(() => {
            setupGeneratorScreen();
            showScreen('generator');
        }, 500);
        return;
    }

    const savedHid = DeviceManager.getCustomHid();
    App.deviceToken = savedHid || DeviceManager.getOrCreateToken();

    const tokenEl = $('activation-token');
    if (tokenEl) tokenEl.textContent = App.deviceToken;
    const hidInput = $('manual-hid-input');
    if (hidInput && savedHid) hidInput.value = savedHid;

    if (DeviceManager.isActivationCached()) {
        setTimeout(() => showScreen('generator'), 400);
        return;
    }

    // Email login is the default path. Only auto-check a previously saved HID.
    if (!savedHid) {
        showScreen('login');
        return;
    }

    if (!navigator.onLine) {
        showScreen('login');
        showAlert('login', 'error', '⚠️ لا يوجد اتصال بالإنترنت. تحقق من اتصالك وأعد المحاولة.');
        return;
    }

    try {
        const data = await apiCall('check-device', { device_token: App.deviceToken }, { skipAuth: true });

        if (data.success) {
            App.authMode = false;
            App.deviceName = data.device_name || 'موزع';
            DeviceManager.setActivationCache(true);
            setTimeout(() => {
                setupGeneratorScreen();
                showScreen('generator');
            }, 600);
        } else {
            showScreen('login');
        }

    } catch (err) {
        console.error('Check device error:', err);
        showScreen('login');
        showAlert('login', 'error', 'تعذر الاتصال بالسيرفر. تأكد من اتصالك بالإنترنت.');
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
        const data = await apiCall('check-device', { device_token: App.deviceToken }, { skipAuth: true });

        if (data.success) {
            App.authMode = false;
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
        if (App.authMode && SessionManager.isExpiringSoon()) {
            const session = SessionManager.get();
            if (session?.refreshToken) {
                const refreshed = await apiCall('refresh-session', {
                    refresh_token: session.refreshToken
                }, { skipAuth: true });
                if (refreshed.success) {
                    SessionManager.updateTokens(refreshed);
                } else {
                    SessionManager.clear();
                    showAlert('generator', 'error', 'انتهت الجلسة. سجّل الدخول مرة أخرى.');
                    setTimeout(() => showScreen('login'), 1200);
                    return;
                }
            }
        }

        const payload = { client_hid: clientHid };
        if (!App.authMode && App.deviceToken) {
            payload.device_token = App.deviceToken;
        }

        const data = await apiCall('generate-code', payload);

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
            if (data.message && (data.message.includes('انتهت صلاحية') || data.message.includes('الجلسة'))) {
                DeviceManager.clearActivationCache();
                if (App.authMode) {
                    SessionManager.clear();
                    setTimeout(() => showScreen('login'), 1400);
                }
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

function togglePasswordVisibility() {
    const input = $('login-password');
    if (!input) return;
    input.type = input.type === 'password' ? 'text' : 'password';
}

function showDeviceActivation() {
    hideAlerts('activation');
    showScreen('activation');
}

function backToLogin() {
    hideAlerts('login');
    showScreen('login');
}

async function submitLogin(event) {
    if (event) event.preventDefault();
    hideAlerts('login');

    const email = ($('login-email')?.value || '').trim();
    const password = $('login-password')?.value || '';

    if (!email || !password) {
        showAlert('login', 'error', 'أدخل البريد الإلكتروني وكلمة المرور.');
        return;
    }

    if (!navigator.onLine) {
        showAlert('login', 'error', 'لا يوجد اتصال بالإنترنت.');
        return;
    }

    setButtonLoading('btn-login', true);

    try {
        const data = await apiCall('login', { email, password }, { skipAuth: true });
        if (data.success) {
            SessionManager.save(data);
            App.authMode = true;
            App.deviceName = data.device_name || 'موزع';
            App.deviceToken = data.distributor_key || null;
            DeviceManager.clearActivationCache();
            showAlert('login', 'success', 'تم تسجيل الدخول بنجاح.');
            if ($('login-password')) $('login-password').value = '';
            setTimeout(() => {
                setupGeneratorScreen();
                showScreen('generator');
            }, 700);
        } else {
            showAlert('login', 'error', data.message || 'فشل تسجيل الدخول.');
        }
    } catch (err) {
        showAlert('login', 'error', err.message || 'تعذر الاتصال بالسيرفر.');
    } finally {
        setButtonLoading('btn-login', false);
    }
}

function logout() {
    SessionManager.clear();
    DeviceManager.clearActivationCache();
    App.authMode = false;
    App.deviceName = 'موزع';
    hideAlerts('login');
    showScreen('login');
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
