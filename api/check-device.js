/**
 * Vercel Serverless Function: /api/check-device
 */

const config = require('../lib/config');
const { handleCors, sendError } = require('../lib/security');
const { parseBody, handleCheckDevice } = require('../lib/actions');

module.exports = async function handler(req, res) {
    if (handleCors(req, res, config.ALLOWED_ORIGINS)) return;
    if (req.method !== 'POST') {
        return sendError(res, 405, 'طريقة الطلب غير مسموح بها. استخدم POST.');
    }

    try {
        const input = await parseBody(req);
        return await handleCheckDevice(req, res, input);
    } catch (err) {
        return sendError(res, 500, 'حدث خطأ غير متوقع.', err);
    }
};
