'use strict';

/**
 * Đọc và kiểm tra cấu hình từ biến môi trường (xem `.env.example` và bảng biến trong README).
 * Tên biến môi trường giữ nguyên dạng `*_MS`, `MAX_*` để tương thích với file `.env` đã có.
 */

/**
 * Đọc một biến môi trường kiểu số nguyên và kiểm tra nằm trong khoảng cho phép.
 *
 * @param {string} name - Tên biến môi trường.
 * @param {number} defaultValue - Giá trị dùng khi biến không được đặt.
 * @param {number} minimum - Giá trị nhỏ nhất cho phép.
 * @param {number} maximum - Giá trị lớn nhất cho phép.
 * @returns {number} Giá trị số nguyên hợp lệ.
 * @throws {Error} Khi giá trị không phải số nguyên hoặc nằm ngoài khoảng.
 */
function readIntegerEnvironmentVariable(name, defaultValue, minimum, maximum) {
    const value = process.env[name] === undefined ? defaultValue : Number(process.env[name]);
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
        throw new Error(`Invalid ${name}: expected an integer between ${minimum} and ${maximum}`);
    }
    return value;
}

/**
 * Tạo object cấu hình cho server HTTP và dịch vụ đăng nhập.
 *
 * @returns {{
 *   apiKey: string,
 *   httpHost: string,
 *   httpPort: number,
 *   maximumConcurrentLogins: number,
 *   deviceIdentifier: string|undefined,
 *   randomMode: string,
 *   maximumRetries: number,
 *   responseWindowMilliseconds: number,
 *   responseIdleTimeoutMilliseconds: number,
 *   transportOptions: {
 *     serverHost: string,
 *     serverPort: number,
 *     proxyUrl: string|null,
 *     connectTimeoutMilliseconds: number,
 *     readTimeoutMilliseconds: number,
 *     maximumPacketBytes: number,
 *   },
 * }} Cấu hình đã kiểm tra.
 * @throws {Error} Khi thiếu `API_KEY` (hoặc ngắn hơn 24 ký tự), proxy sai định dạng, hoặc biến số không hợp lệ.
 */
function loadConfiguration() {
    // Khóa bảo vệ API: bắt buộc, tối thiểu 24 ký tự.
    const apiKey = process.env.API_KEY;
    if (!apiKey || apiKey.length < 24) {
        throw new Error('Set a long API_KEY (at least 24 characters) in the environment');
    }

    // Proxy chỉ chấp nhận SOCKS5 (phân giải DNS tại máy) hoặc SOCKS5h (proxy phân giải DNS).
    const socksProxyUrl = process.env.SOCKS_PROXY_URL || null;
    if (socksProxyUrl && !/^socks5h?:\/\//i.test(socksProxyUrl)) {
        throw new Error('SOCKS_PROXY_URL must start with socks5:// or socks5h://');
    }

    return {
        apiKey,
        httpHost: process.env.HTTP_HOST || '127.0.0.1',
        httpPort: readIntegerEnvironmentVariable('HTTP_PORT', 5000, 1, 65535),
        maximumConcurrentLogins: readIntegerEnvironmentVariable('MAX_CONCURRENT_LOGINS', 3, 1, 100),
        deviceIdentifier: process.env.DEVICE_ID || undefined,
        randomMode: process.env.XTEA_RANDOM_MODE || 'legacy',
        maximumRetries: readIntegerEnvironmentVariable('MAX_RETRIES', 3, 1, 3),
        responseWindowMilliseconds: readIntegerEnvironmentVariable('RESPONSE_WINDOW_MS', 3000, 250, 30000),
        responseIdleTimeoutMilliseconds: readIntegerEnvironmentVariable('RESPONSE_IDLE_TIMEOUT_MS', 500, 100, 5000),
        transportOptions: {
            serverHost: process.env.TCP_SERVER_HOST || '103.247.205.15',
            serverPort: readIntegerEnvironmentVariable('TCP_SERVER_PORT', 19000, 1, 65535),
            proxyUrl: socksProxyUrl,
            connectTimeoutMilliseconds: readIntegerEnvironmentVariable('CONNECT_TIMEOUT_MS', 8000, 100, 60000),
            readTimeoutMilliseconds: readIntegerEnvironmentVariable('READ_TIMEOUT_MS', 5000, 100, 60000),
            maximumPacketBytes: readIntegerEnvironmentVariable('MAX_PACKET_BYTES', 1024 * 1024, 1024, 8 * 1024 * 1024),
        },
    };
}

module.exports = { loadConfiguration };
