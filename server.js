import { timingSafeEqual } from 'node:crypto';
import http from 'node:http';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadConfiguration } from './src/configuration.js';
import { loginAndGetKeys } from './src/services/login-service.js';

/**
 * HTTP API bọc dịch vụ đăng nhập. Thay cho route Flask `GET /api/login` trong `LoginTCPApp.py`
 * (dòng 985–1006): chỉ nhận `POST /api/login` kèm header `X-API-Key`, và `GET /health`.
 */

/** Kích thước tối đa của body JSON (byte). */
const MAXIMUM_REQUEST_BODY_BYTES = 16 * 1024;
/** Độ dài tối đa của username và password nhận từ request. */
const MAXIMUM_USERNAME_LENGTH = 256;
const MAXIMUM_PASSWORD_LENGTH = 1024;

/**
 * So sánh API key trong thời gian không đổi để tránh tấn công đo thời gian (timing attack).
 *
 * @param {string|string[]|undefined} suppliedKey - Giá trị header `X-API-Key` người gọi gửi lên.
 * @param {string} expectedKey - API key đúng trong cấu hình.
 * @returns {boolean} true nếu hai khóa trùng khớp.
 */
function isApiKeyMatchingInConstantTime(suppliedKey, expectedKey) {
    if (typeof suppliedKey !== 'string') return false;

    const actual = Buffer.from(suppliedKey, 'utf8');
    const expected = Buffer.from(expectedKey, 'utf8');

    // timingSafeEqual yêu cầu hai buffer cùng độ dài nên kiểm tra độ dài trước.
    return actual.length === expected.length && timingSafeEqual(actual, expected);
}

/**
 * Gửi phản hồi JSON kèm các header chống cache và chống đoán kiểu nội dung.
 *
 * @param {http.ServerResponse} response - Đối tượng phản hồi HTTP.
 * @param {number} statusCode - Mã trạng thái HTTP.
 * @param {object} payload - Dữ liệu sẽ chuyển thành JSON.
 */
function sendJson(response, statusCode, payload) {
    const output = Buffer.from(JSON.stringify(payload), 'utf8');

    response.writeHead(statusCode, {
        'Content-Type': 'application/json; charset=utf-8',
        // Không cho trình duyệt/proxy lưu cache vì phản hồi có thể chứa session key.
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Content-Length': output.length,
    });
    response.end(output);
}

/**
 * Đọc toàn bộ body request và phân tích thành JSON.
 *
 * @param {http.IncomingMessage} request - Request HTTP.
 * @param {number} [maximumBytes] - Kích thước tối đa cho phép.
 * @returns {Promise<*>} Giá trị JSON đã phân tích.
 * @throws {Error} Có thuộc tính `statusCode`: 413 khi body quá lớn, 400 khi JSON không hợp lệ.
 */
async function readJsonBody(request, maximumBytes = MAXIMUM_REQUEST_BODY_BYTES) {
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

/**
 * Kiểm tra username/password trong body có đúng kiểu và độ dài cho phép.
 *
 * @param {*} username - Giá trị username.
 * @param {*} password - Giá trị password.
 * @returns {boolean} true nếu hợp lệ.
 */
function areCredentialsValid(username, password) {
    const usernameIsValid = typeof username === 'string' && username.length >= 1 && username.length <= MAXIMUM_USERNAME_LENGTH;
    const passwordIsValid = typeof password === 'string' && password.length >= 1 && password.length <= MAXIMUM_PASSWORD_LENGTH;

    return usernameIsValid && passwordIsValid;
}

/**
 * Tạo HTTP server.
 *
 * Thứ tự kiểm tra một request đăng nhập: đúng route/method -> API key -> Content-Type
 * -> giới hạn số login đồng thời -> body JSON -> username/password -> gọi dịch vụ đăng nhập.
 *
 * @param {object} configuration - Cấu hình từ `loadConfiguration()`.
 * @param {Function} [loginService] - Hàm đăng nhập; mặc định là `loginAndGetKeys` (test có thể thay bằng hàm giả).
 * @returns {http.Server} Server chưa listen.
 */
function createServer(configuration, loginService = loginAndGetKeys) {
    // Số request đăng nhập đang được xử lý.
    let activeLoginCount = 0;

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
        if (!isApiKeyMatchingInConstantTime(apiKey, configuration.apiKey)) {
            sendJson(response, 401, { code: -1, error: 'Unauthorized' });
            return;
        }

        const contentType = request.headers['content-type'];
        if (!contentType?.toLowerCase().startsWith('application/json')) {
            sendJson(response, 415, { code: -1, error: 'Content-Type must be application/json' });
            return;
        }

        if (activeLoginCount >= configuration.maximumConcurrentLogins) {
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
        if (!areCredentialsValid(username, password)) {
            sendJson(response, 400, { code: -1, error: 'Missing or invalid username/password' });
            return;
        }

        activeLoginCount += 1;
        try {
            const result = await loginService(username, password, {
                maximumRetries: configuration.maximumRetries,
                transportOptions: configuration.transportOptions,
                deviceIdentifier: configuration.deviceIdentifier,
                randomMode: configuration.randomMode,
                responseWindowMilliseconds: configuration.responseWindowMilliseconds,
                responseIdleTimeoutMilliseconds: configuration.responseIdleTimeoutMilliseconds,
            });
            sendJson(response, 200, result);
        } catch {
            sendJson(response, 502, { code: -999, error: 'Login service encountered an internal error' });
        } finally {
            activeLoginCount -= 1;
        }
    });

    // Giới hạn thời gian nhận toàn bộ request (30 giây) và phần header (15 giây).
    server.requestTimeout = 30_000;
    server.headersTimeout = 15_000;

    return server;
}

// Chỉ khởi động server khi chạy trực tiếp `node server.js`, không chạy khi được `import` trong test.
// So sánh đường dẫn file đang chạy (process.argv[1]) với đường dẫn của chính module này.
const isRunDirectly = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isRunDirectly) {
    try {
        const configuration = loadConfiguration();
        const server = createServer(configuration);

        server.listen(configuration.httpPort, configuration.httpHost, () => {
            console.log(`Login TCP API listening on http://${configuration.httpHost}:${configuration.httpPort}`);
            console.log('Do not expose this credential-handling API directly to the public Internet.');
        });
    } catch (error) {
        console.error(`Startup failed: ${error.message}`);
        process.exitCode = 1;
    }
}

export { createServer, isApiKeyMatchingInConstantTime, readJsonBody };
