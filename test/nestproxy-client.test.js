import http from 'node:http';
import test from 'node:test';
import assert from 'node:assert/strict';

import { loadConfiguration } from '../src/configuration.js';
import { loginAndGetKeys } from '../src/services/login-service.js';
import { NestproxyClient, NestproxyError } from '../src/proxy/nestproxy-client.js';

/**
 * Dựng máy chủ nestproxy giả trên cổng ngẫu nhiên.
 *
 * - `context` (TestContext): Ngữ cảnh test, dùng để đóng máy chủ khi test xong.
 * - `routes` (object): Map đường dẫn -> hàm trả về { status, body }.
 * - Trả về (Promise<object>): { baseUrl, requests } với `requests` là danh sách URL đã nhận.
 */
async function startFakeNestproxy(context, routes) {
    const requests = [];
    const server = http.createServer((request, response) => {
        const requestUrl = new URL(request.url, 'http://localhost');
        requests.push(requestUrl);

        const route = routes[requestUrl.pathname];
        const { status, body } = route ? route(requestUrl) : { status: 404, body: { message: 'not found' } };
        response.writeHead(status, { 'Content-Type': 'application/json' });
        response.end(JSON.stringify(body));
    });

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    context.after(() => new Promise((resolve) => server.close(resolve)));

    return { baseUrl: `http://127.0.0.1:${server.address().port}`, requests };
}

/**
 * Đồng hồ giả cho test: bắt đầu tại một mốc cố định, tăng bằng `advance`.
 *
 * - Trả về (object): { now, advance, isoAfter } với `isoAfter(giây)` trả chuỗi ISO sau mốc hiện tại.
 */
function createFakeClock() {
    let currentTime = Date.parse('2026-11-20T00:00:00.000Z');

    return {
        now: () => currentTime,
        advance: (milliseconds) => {
            currentTime += milliseconds;
        },
        isoAfter: (seconds) => new Date(currentTime + seconds * 1000).toISOString(),
    };
}

test('nestproxy keeps the current proxy until canChangeAt, then switches to a new IP', async (context) => {
    const clock = createFakeClock();
    const currentCanChangeAt = clock.isoAfter(20);
    const availableProxies = ['10.0.0.2:20002', '10.0.0.3:20003'];
    const fakeNestproxy = await startFakeNestproxy(context, {
        '/api/client/proxy/current': () => ({
            status: 200,
            body: { proxy: '10.0.0.1:20001', vip: false, canChangeAt: currentCanChangeAt },
        }),
        '/api/client/proxy/available': () => ({
            status: 200,
            body: { proxy: availableProxies.shift(), vip: false, canChangeAt: clock.isoAfter(60) },
        }),
    });
    const nestproxyClient = new NestproxyClient({
        proxyKey: 'test-proxy-key',
        apiBaseUrl: fakeNestproxy.baseUrl,
        nowFunction: clock.now,
    });

    /*
     * IP đang gán cho key còn 20 giây mới được đổi: dùng tiếp, không xin IP mới.
     */
    assert.equal(await nestproxyClient.getProxyUrl(), 'socks5://10.0.0.1:20001');
    clock.advance(19000);
    assert.equal(await nestproxyClient.getProxyUrl(), 'socks5://10.0.0.1:20001');
    assert.equal(fakeNestproxy.requests[0].searchParams.get('proxy_key'), 'test-proxy-key');

    /*
     * Quá mốc đổi: xin IP mới, IP cũ không dùng nữa; IP mới giữ đủ 60 giây.
     */
    clock.advance(2000);
    assert.equal(await nestproxyClient.getProxyUrl(), 'socks5://10.0.0.2:20002');
    clock.advance(59000);
    assert.equal(await nestproxyClient.getProxyUrl(), 'socks5://10.0.0.2:20002');
    clock.advance(1000);
    assert.equal(await nestproxyClient.getProxyUrl(), 'socks5://10.0.0.3:20003');

    assert.deepEqual(
        fakeNestproxy.requests.map((requestUrl) => requestUrl.pathname),
        ['/api/client/proxy/current', '/api/client/proxy/available', '/api/client/proxy/available'],
    );
});

test('nestproxy asks for an available proxy when the key has none assigned', async (context) => {
    const clock = createFakeClock();
    const fakeNestproxy = await startFakeNestproxy(context, {
        '/api/client/proxy/current': () => ({
            status: 200,
            body: { message: 'Chưa có proxy nào được gán cho key này' },
        }),
        '/api/client/proxy/available': () => ({
            status: 200,
            body: { proxy: '10.0.0.5:20000', vip: false, canChangeAt: clock.isoAfter(60) },
        }),
    });
    const nestproxyClient = new NestproxyClient({
        proxyKey: 'test-proxy-key',
        apiBaseUrl: fakeNestproxy.baseUrl,
        nowFunction: clock.now,
    });

    assert.equal(await nestproxyClient.getProxyUrl(), 'socks5://10.0.0.5:20000');
    assert.deepEqual(
        fakeNestproxy.requests.map((requestUrl) => requestUrl.pathname),
        ['/api/client/proxy/current', '/api/client/proxy/available'],
    );

    /*
     * Sau invalidate (kết nối lỗi), lần sau hỏi lại proxy hiện tại trước.
     */
    nestproxyClient.invalidate();
    await nestproxyClient.getProxyUrl();
    assert.equal(fakeNestproxy.requests[2].pathname, '/api/client/proxy/current');
});

test('nestproxy keeps the old proxy when a new IP is refused with 429, and retries after retryAfter', async (context) => {
    const clock = createFakeClock();
    let availableCallCount = 0;
    const fakeNestproxy = await startFakeNestproxy(context, {
        '/api/client/proxy/current': () => ({
            status: 200,
            body: { proxy: '10.0.0.1:20001', vip: false, canChangeAt: clock.isoAfter(-5) },
        }),
        '/api/client/proxy/available': () => {
            availableCallCount += 1;
            if (availableCallCount === 1) {
                return {
                    status: 429,
                    body: { error: 'TooManyRequests', message: 'Vui lòng đợi', retryAfter: 15, code: 'IP_CHANGE_LIMIT' },
                };
            }

            return { status: 200, body: { proxy: '10.0.0.9:20009', vip: false, canChangeAt: clock.isoAfter(60) } };
        },
    });
    const nestproxyClient = new NestproxyClient({
        proxyKey: 'test-proxy-key',
        apiBaseUrl: fakeNestproxy.baseUrl,
        nowFunction: clock.now,
    });

    assert.equal(await nestproxyClient.getProxyUrl(), 'socks5://10.0.0.1:20001');
    clock.advance(14000);
    assert.equal(await nestproxyClient.getProxyUrl(), 'socks5://10.0.0.1:20001');
    assert.equal(availableCallCount, 1);
    clock.advance(1000);
    assert.equal(await nestproxyClient.getProxyUrl(), 'socks5://10.0.0.9:20009');
});

test('nestproxy cooldown without any proxy and invalid proxy values become NestproxyError', async (context) => {
    const fakeNestproxy = await startFakeNestproxy(context, {
        '/api/client/proxy/current': () => ({ status: 200, body: { message: 'Chưa có proxy nào được gán cho key này' } }),
        '/api/client/proxy/available': () => ({
            status: 429,
            body: { error: 'TooManyRequests', message: 'Vui lòng đợi', retryAfter: 57, code: 'IP_CHANGE_LIMIT' },
        }),
    });
    const cooldownClient = new NestproxyClient({ proxyKey: 'test-proxy-key', apiBaseUrl: fakeNestproxy.baseUrl });
    await assert.rejects(cooldownClient.getProxyUrl(), (error) => error instanceof NestproxyError && error.retryAfterSeconds === 57);

    const invalidProxyServer = await startFakeNestproxy(context, {
        '/api/client/proxy/current': () => ({ status: 200, body: { proxy: 'not a proxy' } }),
        '/api/client/proxy/available': () => ({ status: 200, body: { proxy: 'still not a proxy' } }),
    });
    const invalidProxyClient = new NestproxyClient({ proxyKey: 'test-proxy-key', apiBaseUrl: invalidProxyServer.baseUrl });
    await assert.rejects(invalidProxyClient.getProxyUrl(), NestproxyError);
});

test('login uses the proxy from the provider and drops it after a connection error', async () => {
    const receivedProxyUrls = [];
    let invalidateCount = 0;
    const proxyProvider = {
        getProxyUrl: async () => 'socks5://10.0.0.5:20000',
        invalidate: () => {
            invalidateCount += 1;
        },
    };

    const result = await loginAndGetKeys('test@example.com', 'example-password', {
        deviceIdentifier: '123456789012345',
        maximumRetries: 2,
        proxyProvider,
        transportOptions: { serverHost: '127.0.0.1', serverPort: 19000 },
        transportFactory: (transportOptions) => {
            receivedProxyUrls.push(transportOptions.proxyUrl);
            return {
                connect: async () => {
                    throw new Error('proxy unreachable');
                },
                close: () => {},
            };
        },
    });

    assert.equal(result.code, -5);
    assert.deepEqual(receivedProxyUrls, ['socks5://10.0.0.5:20000', 'socks5://10.0.0.5:20000']);
    assert.equal(invalidateCount, 2);
});

test('configuration reads the nestproxy key and rotation interval, and ignores SOCKS_PROXY_URL', () => {
    const savedEnvironment = { ...process.env };
    try {
        process.env.API_KEY = 'very-long-unit-test-secret-is-not-production';
        process.env.SOCKS_PROXY_URL = 'socks5://127.0.0.1:1080';
        process.env.NESTPROXY_PROXY_KEY = ' test-proxy-key ';
        process.env.NESTPROXY_ROTATE_SECONDS = '120';

        const configuration = loadConfiguration();
        assert.equal(configuration.nestproxyProxyKey, 'test-proxy-key');
        assert.equal(configuration.nestproxyRotateSeconds, 120);
        assert.equal(configuration.transportOptions.proxyUrl, null);

        process.env.NESTPROXY_ROTATE_SECONDS = '30';
        assert.throws(() => loadConfiguration(), /NESTPROXY_ROTATE_SECONDS/);
    } finally {
        process.env = savedEnvironment;
    }
});
