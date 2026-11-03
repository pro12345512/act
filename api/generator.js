/**
 * Vercel Serverless Function: /api/generator
 * Master router handling actions:
 *   - check-device
 *   - generate-code
 *   - add-device
 */

const config = require('../lib/config');
const { handleCors, sendError, sendJson } = require('../lib/security');
const {
    parseBody,
    handleLogin,
    handleCheckSession,
    handleRefreshSession,
    handleCheckDevice,
    handleGenerateCode,
    handleAddDevice
} = require('../lib/actions');

module.exports = async function handler(req, res) {
    // 1. CORS Preflight & Headers
    if (handleCors(req, res, config.ALLOWED_ORIGINS)) {
        return;
    }

    // 2. Only allow POST requests
    if (req.method !== 'POST') {
        return sendError(res, 405, `طريقة الطلب ${req.method} غير مسموح بها. استخدم POST.`);
    }

    try {
        const input = await parseBody(req);
        // Action can be provided via query param ?action=... or in JSON body
        const action = (req.query?.action || input?.action || '').trim();

        switch (action) {
            case 'login':
                return await handleLogin(req, res, input);

            case 'check-session':
                return await handleCheckSession(req, res, input);

            case 'refresh-session':
                return await handleRefreshSession(req, res, input);

            case 'check-device':
                return await handleCheckDevice(req, res, input);

            case 'generate-code':
                return await handleGenerateCode(req, res, input);

            case 'add-device':
                return await handleAddDevice(req, res, input);

            default:
                return sendJson(res, 400, {
                    success: false,
                    message: action ? `العملية غير معروفة: ${action}` : 'معامل action مطلوب'
                });
        }
    } catch (err) {
        return sendError(res, 500, 'حدث خطأ غير متوقع في الخادم.', err);
    }
};
