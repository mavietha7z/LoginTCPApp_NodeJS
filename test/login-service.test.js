'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const { loginAndGetKeys } = require('../src/services/login-service');
const { createServer } = require('../server');
const { TcpClient } = require('../src/transport/tcp-client');
const { XteaCustom } = require('../src/crypto/xtea-custom');
const { generateEncryptionKey } = require('../src/crypto/encryption-key');
const { encodeVarintField, encodeBytesField } = require('../src/protocol/protobuf');
const { buildPacket, buildFullyEncryptedPacket } = require('../src/protocol/packets');

const salt = 'salt-123';
const verifyCode = 'verify-123';
const account = 'test@example.com';
const password = 'example-password';
const prepareKey = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
const sessionKey = Buffer.from('fedcba98765432100123456789abcdef', 'hex');
const initializationVector = Buffer.from('1032547698badcfe', 'hex');

function createReplyFrame(command, body, encryptionKey = null, resultCode = 0) {
    const header = Buffer.concat([
        encodeVarintField(1, 285212918),
        encodeVarintField(3, 3),
        encodeVarintField(4, command),
        encodeVarintField(5, resultCode),
    ]);
    if (!encryptionKey) return buildPacket(header, body);
    const packet = buildPacket(header, body);
    return buildFullyEncryptedPacket(packet.subarray(4), encryptionKey, { initializationVector });
}

function buildMockReplyFrames(resultCode = 0) {
    const preparedData = Buffer.concat([encodeBytesField(1, Buffer.from(salt)), encodeBytesField(2, Buffer.from(verifyCode))]);
    const prepareBody = Buffer.concat([
        encodeBytesField(1, prepareKey),
        encodeBytesField(2, new XteaCustom(prepareKey).encrypt(preparedData, initializationVector)),
    ]);
    const loginKey = generateEncryptionKey(password, salt, verifyCode);
    const loginData = Buffer.concat([encodeVarintField(1, 123456), encodeBytesField(2, sessionKey)]);
    const loginBody = encodeBytesField(1, new XteaCustom(loginKey).encrypt(loginData, initializationVector));
    return {
        prepare: createReplyFrame(256, resultCode ? Buffer.alloc(0) : prepareBody, null, resultCode),
        login: createReplyFrame(257, loginBody),
        token: createReplyFrame(277, Buffer.alloc(0), sessionKey),
        sso: createReplyFrame(442, encodeBytesField(1, Buffer.from('mock-sso-key-123')), sessionKey),
    };
}

class FakeTransport {
    constructor(replyFrames) {
        this.replyFrames = replyFrames;
        this.requestCount = 0;
        this.closed = false;
        this.batchSent = null;
    }

    async connect() {}

    async sendMessage() {
        const response = [this.replyFrames.prepare, this.replyFrames.login, this.replyFrames.token][this.requestCount];
        this.requestCount += 1;
        return response;
    }

    async write(batch) {
        this.batchSent = batch;
    }

    async readFrame() {
        return this.replyFrames.sso;
    }

    close() {
        this.closed = true;
    }
}

test('the full login sequence parses the mocked server and returns keys', async () => {
    const transport = new FakeTransport(buildMockReplyFrames());
    const result = await loginAndGetKeys(account, password, {
        deviceIdentifier: '123456789012345',
        transportFactory: () => transport,
        maxRetries: 1,
    });
    assert.equal(result.code, 0, result.msg);
    assert.equal(result.uid, 123456);
    assert.equal(result.session_key, sessionKey.toString('hex'));
    assert.equal(result.SsoKeyGetReply.sso_key, 'mock-sso-key-123');
    assert.equal(result.attempts, 1);
    assert.equal(transport.requestCount, 3);
    assert.ok(transport.batchSent.length > 6 * 4);
    assert.equal(transport.closed, true);
});

test('CAPTCHA response 105 is not retried or bypassed', async () => {
    let transportCreated = 0;
    const result = await loginAndGetKeys(account, password, {
        deviceIdentifier: '123456789012345',
        transportFactory: () => {
            transportCreated += 1;
            return new FakeTransport(buildMockReplyFrames(105));
        },
        maxRetries: 3,
    });
    assert.equal(result.code, 105);
    assert.equal(result.attempts, 1);
    assert.equal(transportCreated, 1);
});

test('HTTP API requires API key, POST, and valid JSON', async (context) => {
    let loginCalls = 0;
    const config = {
        apiKey: 'very-long-unit-test-secret-is-not-production',
        maxConcurrentLogins: 2,
        maxRetries: 1,
        transportOptions: {},
    };
    const server = createServer(config, async () => {
        loginCalls += 1;
        return { code: 0, uid: 1234, session_key: 'mock-only' };
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    context.after(() => new Promise((resolve) => server.close(resolve)));
    const port = server.address().port;
    const endpoint = `http://127.0.0.1:${port}/api/login`;
    const unauthorized = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: account, password }),
    });
    assert.equal(unauthorized.status, 401);
    assert.equal(loginCalls, 0);
    const unsupportedGet = await fetch(endpoint + `?username=${account}&password=${password}`);
    assert.equal(unsupportedGet.status, 404);
    const authorized = await fetch(endpoint, {
        method: 'POST',
        headers: { 'X-API-Key': config.apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: account, password }),
    });
    assert.equal(authorized.status, 200);
    assert.equal(authorized.headers.get('cache-control'), 'no-store');
    assert.equal((await authorized.json()).uid, 1234);
    assert.equal(loginCalls, 1);
});

test('TCP reader reassembles a packet whose 4-byte header arrives in pieces', async (context) => {
    const dataFrame = buildPacket(Buffer.concat([encodeVarintField(3, 3), encodeVarintField(4, 277), encodeVarintField(5, 0)]));
    const server = net.createServer((socket) => {
        socket.write(dataFrame.subarray(0, 2));
        setTimeout(() => socket.write(dataFrame.subarray(2, 7)), 5);
        setTimeout(() => socket.write(dataFrame.subarray(7)), 10);
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const client = new TcpClient({
        serverHost: '127.0.0.1',
        serverPort: server.address().port,
        readTimeoutMs: 1000,
    });
    context.after(() => {
        client.close();
        return new Promise((resolve) => server.close(resolve));
    });
    await client.connect();
    assert.deepEqual(await client.readFrame(), dataFrame);
});

test('SOCKS5h negotiation works with a mocked local proxy', async (context) => {
    const dataFrame = buildPacket(Buffer.concat([encodeVarintField(3, 3), encodeVarintField(4, 277), encodeVarintField(5, 0)]));
    const proxyServer = net.createServer((socket) => {
        let step = 0;
        socket.on('data', (data) => {
            if (step === 0) {
                assert.equal(data[0], 5);
                socket.write(Buffer.from([5, 0]));
                step = 1;
            } else if (step === 1) {
                assert.equal(data[0], 5);
                assert.equal(data[1], 1);
                socket.write(Buffer.concat([Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]), dataFrame]));
                step = 2;
            }
        });
    });
    await new Promise((resolve) => proxyServer.listen(0, '127.0.0.1', resolve));
    const client = new TcpClient({
        serverHost: 'example.com',
        serverPort: 19000,
        proxyUrl: `socks5h://127.0.0.1:${proxyServer.address().port}`,
    });
    context.after(() => {
        client.close();
        return new Promise((resolve) => proxyServer.close(resolve));
    });
    await client.connect();
    assert.deepEqual(await client.readFrame(), dataFrame);
});

test('end-to-end login works against a local TCP protocol simulator', async (context) => {
    const replyFrames = buildMockReplyFrames();
    const receivedCommands = [];
    const simulator = net.createServer((socket) => {
        let receivedBytes = Buffer.alloc(0);
        socket.on('data', (chunk) => {
            receivedBytes = Buffer.concat([receivedBytes, chunk]);
            while (receivedBytes.length >= 4) {
                const packetLength = receivedBytes.readUInt32LE(0);
                if (receivedBytes.length < packetLength + 4) break;
                const incomingPacket = Buffer.from(receivedBytes.subarray(0, packetLength + 4));
                receivedBytes = Buffer.from(receivedBytes.subarray(packetLength + 4));
                const { decodePacket } = require('../src/protocol/responses');
                const parsedPacket = decodePacket(incomingPacket, sessionKey);
                receivedCommands.push(parsedPacket.header.command);
                if (parsedPacket.header.command === 256) {
                    socket.write(replyFrames.prepare.subarray(0, 3));
                    socket.write(replyFrames.prepare.subarray(3));
                } else if (parsedPacket.header.command === 257) {
                    socket.write(replyFrames.login);
                } else if (parsedPacket.header.command === 277) {
                    socket.write(replyFrames.token);
                } else if (parsedPacket.header.command === 442) {
                    socket.write(replyFrames.sso);
                }
            }
        });
    });
    await new Promise((resolve) => simulator.listen(0, '127.0.0.1', resolve));
    context.after(() => new Promise((resolve) => simulator.close(resolve)));
    const result = await loginAndGetKeys(account, password, {
        maxRetries: 1,
        deviceIdentifier: '123456789012345',
        transportOptions: {
            serverHost: '127.0.0.1',
            serverPort: simulator.address().port,
            readTimeoutMs: 1000,
            connectTimeoutMs: 1000,
        },
    });
    assert.equal(result.code, 0, result.msg);
    assert.equal(result.uid, 123456);
    assert.equal(result.SsoKeyGetReply.sso_key, 'mock-sso-key-123');
    assert.deepEqual(receivedCommands, [256, 257, 277, 278, 511, 276, 278, 442, 342]);
});
