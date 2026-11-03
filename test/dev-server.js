/**
 * InteliScale Local Development Server
 * Serves static assets and mounts Vercel Serverless Functions.
 * Run with: npm start
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const config = require('../lib/config');
const generatorHandler = require('../api/generator');
const checkDeviceHandler = require('../api/check-device');
const generateCodeHandler = require('../api/generate-code');
const addDeviceHandler = require('../api/add-device');

const PORT = parseInt(process.env.PORT, 10) || 3000;
const ROOT = path.resolve(__dirname, '..');

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon'
};

const server = http.createServer(async (req, res) => {
    const parsedUrl = url.parse(req.url, true);
    let pathname = parsedUrl.pathname;

    // Attach parsed query to req for compatibility with Vercel handlers
    req.query = parsedUrl.query;

    // 1. API Routes
    if (pathname === '/api/generator' || pathname === '/api/generator.php') {
        return generatorHandler(req, res);
    }
    if (pathname === '/api/check-device') {
        return checkDeviceHandler(req, res);
    }
    if (pathname === '/api/generate-code') {
        return generateCodeHandler(req, res);
    }
    if (pathname === '/api/add-device') {
        return addDeviceHandler(req, res);
    }

    // 2. Static File Serving
    if (pathname === '/' || pathname === '') {
        pathname = '/index.html';
    }

    // Prevent directory traversal
    const safePath = path.normalize(pathname).replace(/^(\.\.[\/\\])+/, '');
    const filePath = path.join(ROOT, safePath);

    // Verify file stays within ROOT
    if (!filePath.startsWith(ROOT)) {
        res.statusCode = 403;
        return res.end('Access Denied');
    }

    fs.stat(filePath, (err, stats) => {
        if (err || !stats.isFile()) {
            res.statusCode = 404;
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            return res.end('404 Not Found');
        }

        const ext = path.extname(filePath).toLowerCase();
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';

        res.statusCode = 200;
        res.setHeader('Content-Type', contentType);
        fs.createReadStream(filePath).pipe(res);
    });
});

if (require.main === module) {
    server.listen(PORT, () => {
        console.log(`\n==================================================`);
        console.log(`🚀 InteliScale Local Dev Server is running:`);
        console.log(`   ➜ Web App: http://localhost:${PORT}`);
        console.log(`   ➜ API:     http://localhost:${PORT}/api/generator`);
        console.log(`==================================================\n`);
    });
}

module.exports = server;
