'use strict';

const { performance } = require('node:perf_hooks');
const { generateEncryptionKey } = require('../crypto/encryption-key');
const { LoginPrepareRequest, LoginRequestHandler, LoginTokenGetRequest, EmptyPacket } = require('../protocol/requests');
const {
    decodePacket,
    decryptResponseData,
    decodeLoginPrepareReplyData,
    decodeLoginReplyData,
    SystemResponse,
} = require('../protocol/responses');
const { TcpClient, TimeoutError } = require('../transport/tcp-client');

function durationSeconds(startedAt) {
    return Math.round((performance.now() - startedAt) / 10) / 100;
}

function systemErrorResult(code, message, startedAt, attempts) {
    return {
        code,
        ...(message ? { msg: message } : {}),
        duration: durationSeconds(startedAt),
        attempts,
    };
}

async function loginAndGetKeys(account, password, options = {}) {
    const startedAt = performance.now();
    const maxRetries = options.maxRetries ?? 3;
    const retryableSystemCodes = new Set([110]); // ERROR_DECRYPT
    let lastErrorCode = -5999;
    let lastErrorMessage = null;
    let attempt = 0;
    const randomMode = options.randomMode || 'legacy';
    const requestOptions = {
        deviceIdentifier: options.deviceIdentifier,
        randomMode,
    };

    for (attempt = 1; attempt <= maxRetries; attempt += 1) {
        const client = options.transportFactory ? options.transportFactory() : new TcpClient(options.transportOptions);
        try {
            await client.connect();

            // Step 1: LoginPrepare, command 256 (unencrypted outer header).
            const prepareFrame = await client.sendMessage(new LoginPrepareRequest(account, requestOptions).buildFullPacket());
            const prepareReply = new SystemResponse(decodePacket(prepareFrame));
            if (!prepareReply.isSuccess()) {
                lastErrorCode = prepareReply.code;
                lastErrorMessage = prepareReply.message;
                // Do not retry CAPTCHA/auth/account blocks automatically.
                if (!retryableSystemCodes.has(lastErrorCode)) {
                    return systemErrorResult(lastErrorCode, lastErrorMessage, startedAt, attempt);
                }
                continue;
            }
            if (!prepareReply.body.encrypt_key || !prepareReply.body.data) {
                lastErrorCode = -2;
                lastErrorMessage = 'Missing LoginPrepare encryption fields';
                continue;
            }
            const prepareData = decodeLoginPrepareReplyData(decryptResponseData(prepareReply.body.encrypt_key, prepareReply.body.data));
            if (!prepareData.salt || !prepareData.verify_code) {
                lastErrorCode = -2;
                lastErrorMessage = 'Missing LoginPrepare salt or verification code';
                continue;
            }

            // Step 2: Login, command 257. MD5 -> SHA256 -> SHA256 yields 16-byte XTEA key.
            const loginEncryptionKey = generateEncryptionKey(password, prepareData.salt, prepareData.verify_code);
            const loginFrame = await client.sendMessage(
                new LoginRequestHandler(password, loginEncryptionKey, requestOptions).buildFullPacket(),
            );
            const loginReply = new SystemResponse(decodePacket(loginFrame));
            if (!loginReply.isSuccess()) {
                lastErrorCode = loginReply.code;
                lastErrorMessage = loginReply.message;
                if (!retryableSystemCodes.has(lastErrorCode)) {
                    return systemErrorResult(lastErrorCode, lastErrorMessage, startedAt, attempt);
                }
                continue;
            }
            if (!loginReply.body.data) {
                lastErrorCode = -3;
                lastErrorMessage = 'Missing Login reply data';
                continue;
            }
            const loginData = decodeLoginReplyData(decryptResponseData(loginEncryptionKey, loginReply.body.data));
            const sessionKey = loginData.session_key;
            if (!sessionKey || !/^[0-9a-f]{32}$/.test(sessionKey)) {
                lastErrorCode = -3;
                lastErrorMessage = 'Invalid 16-byte session key';
                continue;
            }

            // Step 3: Request token, command 277; subsequent commands use fully encrypted frames.
            const tokenFrame = await client.sendMessage(new LoginTokenGetRequest(sessionKey, requestOptions).buildFullPacket());
            const tokenReply = new SystemResponse(decodePacket(tokenFrame, Buffer.from(sessionKey, 'hex')));
            if (!tokenReply.isSuccess()) {
                lastErrorCode = tokenReply.code;
                lastErrorMessage = tokenReply.message;
                if (!retryableSystemCodes.has(lastErrorCode)) {
                    return systemErrorResult(lastErrorCode, lastErrorMessage, startedAt, attempt);
                }
                continue;
            }

            const followUpCommands = [278, 511, 276, 278, 442, 342];
            const followUpPackets = followUpCommands.map((command) =>
                new EmptyPacket(sessionKey, command, requestOptions).buildFullPacket(),
            );
            await client.write(Buffer.concat(followUpPackets));

            // Step 4: Collect responses without depending on recv() chunk boundaries.
            const responseWindowMs = options.responseWindowMs ?? 3000;
            const responseIdleTimeoutMs = options.responseIdleTimeoutMs ?? 500;
            const responseDeadline = Date.now() + responseWindowMs;
            const maxFollowUpFrames = options.maxFollowUpFrames ?? 64;
            let ssoKey = null;
            for (let frameIndex = 0; frameIndex < maxFollowUpFrames; frameIndex += 1) {
                const remainingMs = responseDeadline - Date.now();
                if (remainingMs <= 0) break;
                let replyFrame;
                try {
                    replyFrame = await client.readFrame(Math.min(remainingMs, responseIdleTimeoutMs));
                } catch (error) {
                    if (
                        error instanceof TimeoutError ||
                        error.message === 'TCP connection ended' ||
                        error.message === 'TCP connection closed'
                    ) {
                        break;
                    }
                    throw error;
                }
                const reply = decodePacket(replyFrame, Buffer.from(sessionKey, 'hex'));
                if (reply.message_type === 'SsoKeyGetReply' && reply.body.sso_key) {
                    ssoKey = reply.body.sso_key;
                    break;
                }
            }
            if (ssoKey && ssoKey.length >= 8) {
                return {
                    code: 0,
                    uid: loginData.uid,
                    session_key: sessionKey,
                    SsoKeyGetReply: { sso_key: ssoKey },
                    duration: durationSeconds(startedAt),
                    attempts: attempt,
                };
            }
            lastErrorCode = -4;
            lastErrorMessage = 'SSO key was not returned';
        } catch (error) {
            lastErrorCode = -5;
            // Errors remain in the backend only; never echo internal host/proxy details through HTTP.
            lastErrorMessage = error instanceof TimeoutError ? 'TCP connection timed out' : error.message;
        } finally {
            client.close();
        }
    }
    return systemErrorResult(lastErrorCode, lastErrorMessage, startedAt, Math.min(attempt - 1, maxRetries));
}

module.exports = { loginAndGetKeys };
