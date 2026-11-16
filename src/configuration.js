/**
 * Đọc và kiểm tra cấu hình từ biến môi trường (xem `.env.example` và bảng biến trong README).
 * Tên biến môi trường giữ nguyên dạng `*_MS`, `MAX_*` để tương thích với file `.env` đã có.
 */

/**
 * Đọc một biến môi trường kiểu số nguyên và kiểm tra nằm trong khoảng cho phép.
 *
 * - `name` (string): Tên biến môi trường.
 * - `defaultValue` (number): Giá trị dùng khi biến không được đặt.
 * - `minimum` (number): Giá trị nhỏ nhất cho phép.
 * - `maximum` (number): Giá trị lớn nhất cho phép.
 * - Trả về (number): Giá trị số nguyên hợp lệ.
 * - Ném lỗi Error: Khi giá trị không phải số nguyên hoặc nằm ngoài khoảng.
 */
function readIntegerEnvironmentVariable(name, defaultValue, minimum, maximum) {
    const value = process.env[name] === undefined ? defaultValue : Number(process.env[name]);
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
        throw new Error(`${name} không hợp lệ: yêu cầu một số nguyên nằm trong khoảng từ ${minimum} đến ${maximum}`);
    }

    return value;
}

/**
 * Tạo object cấu hình cho server HTTP và dịch vụ đăng nhập.
 *
 * - Trả về (object): Cấu hình đã kiểm tra, gồm:
 *   - `apiKey` (string): Khóa bảo vệ API.
 *   - `httpHost` (string), `httpPort` (number): Địa chỉ và cổng HTTP lắng nghe.
 *   - `maximumConcurrentLogins` (number): Số lượt đăng nhập xử lý song song tối đa.
 *   - `deviceIdentifier` (string hoặc undefined): Device ID lấy từ `DEVICE_ID`.
 *   - `randomMode` (string): Cách sinh IV của XTEA.
 *   - `maximumRetries` (number): Số lần thử đăng nhập tối đa.
 *   - `responseWindowMilliseconds`, `responseIdleTimeoutMilliseconds` (number): Thời gian chờ phản hồi SSO.
 *   - `transportOptions` (object): Tùy chọn cho `TcpClient` gồm `serverHost`, `serverPort`, `proxyUrl`,
 *     `connectTimeoutMilliseconds`, `readTimeoutMilliseconds`, `maximumPacketBytes`.
 * - Ném lỗi Error: Khi thiếu `API_KEY` (hoặc ngắn hơn 24 ký tự), proxy sai định dạng, hoặc biến số không hợp lệ.
 */
function loadConfiguration() {
    /*
     * Khóa bảo vệ API: bắt buộc, tối thiểu 24 ký tự.
     */
    const apiKey = process.env.API_KEY;
    if (!apiKey || apiKey.length < 24) {
        throw new Error('Thiết lập API_KEY dài (ít nhất 24 ký tự) trong môi trường');
    }

    /*
     * Proxy chỉ chấp nhận SOCKS5 (phân giải DNS tại máy) hoặc SOCKS5h (proxy phân giải DNS).
     */
    const socksProxyUrl = process.env.SOCKS_PROXY_URL || null;
    if (socksProxyUrl && !/^socks5h?:\/\//i.test(socksProxyUrl)) {
        throw new Error('SOCKS_PROXY_URL phải bắt đầu với socks5:// hoặc socks5h://');
    }

    return {
        apiKey,
        httpHost: process.env.HTTP_HOST || 'localhost',
        deviceIdentifier: process.env.DEVICE_ID || undefined,
        randomMode: process.env.XTEA_RANDOM_MODE || 'legacy',
        httpPort: readIntegerEnvironmentVariable('HTTP_PORT', 6666, 1, 65535),
        maximumRetries: readIntegerEnvironmentVariable('MAX_RETRIES', 3, 1, 3),
        maximumConcurrentLogins: readIntegerEnvironmentVariable('MAX_CONCURRENT_LOGINS', 3, 1, 100),
        responseWindowMilliseconds: readIntegerEnvironmentVariable('RESPONSE_WINDOW_MS', 3000, 250, 30000),
        responseIdleTimeoutMilliseconds: readIntegerEnvironmentVariable('RESPONSE_IDLE_TIMEOUT_MS', 500, 100, 5000),
        transportOptions: {
            proxyUrl: socksProxyUrl,
            serverHost: process.env.TCP_SERVER_HOST || '103.247.205.15',
            serverPort: readIntegerEnvironmentVariable('TCP_SERVER_PORT', 19000, 1, 65535),
            readTimeoutMilliseconds: readIntegerEnvironmentVariable('READ_TIMEOUT_MS', 5000, 100, 60000),
            connectTimeoutMilliseconds: readIntegerEnvironmentVariable('CONNECT_TIMEOUT_MS', 8000, 100, 60000),
            maximumPacketBytes: readIntegerEnvironmentVariable('MAX_PACKET_BYTES', 1024 * 1024, 1024, 8 * 1024 * 1024),
        },
    };
}

export { loadConfiguration };
