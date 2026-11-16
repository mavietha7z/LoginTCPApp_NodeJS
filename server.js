'use strict';

const http = require('node:http');
const { loadConfig } = require('./src/config');
const { timingSafeEqual } = require('node:crypto');
const { loginAndGetKeys } = require('./src/services/login-service');

function constantTimeApiKeyMatch(suppliedKey, expectedKey) {
    if (typeof suppliedKey !== 'string') return false;
    const actual = Buffer.from(suppliedKey, 'utf8');
    const expected = Buffer.from(expectedKey, 'utf8');
    return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function sendJson(response, statusCode, payload) {
    const output = Buffer.from(JSON.stringify(payload), 'utf8');
    response.writeHead(statusCode, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Content-Length': output.length,
    });
    response.end(output);
}

async function readJsonBody(request, maximumBytes = 16 * 1024) {
    const chunks = [];
    let byteCount = 0;
    for await (const chunk of request) {
        byteCount += chunk.length;
        if (byteCount > maximumBytes) {
            const error = new Error('Request body exceeds the allowed size');
            error.statusCode = 413;
            throw error;
        }
        chunks.push(chunk);
    }
    try {
        return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
        const error = new Error('Invalid JSON request body');
        error.statusCode = 400;
        throw error;
    }
}

function createServer(config, loginService = loginAndGetKeys) {
    let activeLogins = 0;
    const server = http.createServer(async (request, response) => {
        if (request.method === 'GET' && request.url === '/health') {
            sendJson(response, 200, { status: 'ok' });
            return;
        }
        if (request.url !== '/api/login' || request.method !== 'POST') {
            sendJson(response, 404, { code: -1, error: 'Not found. Use POST /api/login' });
            return;
        }
        const apiKey = request.headers['x-api-key'];
        if (!constantTimeApiKeyMatch(apiKey, config.apiKey)) {
            sendJson(response, 401, { code: -1, error: 'Unauthorized' });
            return;
        }
        if (!request.headers['content-type']?.toLowerCase().startsWith('application/json')) {
            sendJson(response, 415, { code: -1, error: 'Content-Type must be application/json' });
            return;
        }
        if (activeLogins >= config.maxConcurrentLogins) {
            sendJson(response, 429, { code: -1, error: 'Too many concurrent login requests' });
            return;
        }
        let payload;
        try {
            payload = await readJsonBody(request);
        } catch (error) {
            sendJson(response, error.statusCode || 400, { code: -1, error: error.message });
            return;
        }
        const username = payload?.username;
        const password = payload?.password;
        if (
            typeof username !== 'string' ||
            username.length < 1 ||
            username.length > 256 ||
            typeof password !== 'string' ||
            password.length < 1 ||
            password.length > 1024
        ) {
            sendJson(response, 400, { code: -1, error: 'Missing or invalid username/password' });
            return;
        }
        activeLogins += 1;
        try {
            const result = await loginService(username, password, {
                maxRetries: config.maxRetries,
                transportOptions: config.transportOptions,
                deviceIdentifier: config.deviceIdentifier,
                randomMode: config.randomMode,
                responseWindowMs: config.responseWindowMs,
                responseIdleTimeoutMs: config.responseIdleTimeoutMs,
            });
            sendJson(response, 200, result);
        } catch {
            sendJson(response, 502, { code: -999, error: 'Login service encountered an internal error' });
        } finally {
            activeLogins -= 1;
        }
    });
    server.requestTimeout = 30_000;
    server.headersTimeout = 15_000;
    return server;
}

if (require.main === module) {
    try {
        const config = loadConfig();
        const server = createServer(config);
        server.listen(config.httpPort, config.httpHost, () => {
            console.log(`Login TCP API listening on http://${config.httpHost}:${config.httpPort}`);
            console.log('Do not expose this credential-handling API directly to the public Internet.');
        });
    } catch (error) {
        console.error(`Startup failed: ${error.message}`);
        process.exitCode = 1;
    }
}

module.exports = { createServer, constantTimeApiKeyMatch, readJsonBody };
