/**
 * Lấy proxy SOCKS5 từ dịch vụ nestproxy.com theo `proxy_key`, đổi sang IP mới sau mỗi chu kỳ.
 *
 * API nestproxy (Client Proxy API) dùng ở đây:
 *   - GET /api/client/proxy/current?proxy_key=...   -> { proxy: "IP:port", vip, canChangeAt } hoặc
 *     { message: "Chưa có proxy nào được gán cho key này" } khi key chưa được gán proxy.
 *   - GET /api/client/proxy/available?proxy_key=... -> cấp IP mới; trả 429 kèm `retryAfter` nếu chưa hết thời gian chờ.
 * Proxy trả về chỉ có dạng `IP:port`, không có tài khoản; đã kiểm tra là proxy SOCKS5.
 *
 * Cách đổi IP: IP mới được dùng tới thời điểm đổi = chậm nhất trong hai mốc `canChangeAt` của nestproxy và
 * thời điểm nhận IP + chu kỳ đổi (mặc định 60 giây). Sau mốc đó, lượt đăng nhập tiếp theo gọi `available`
 * để lấy IP mới và không dùng IP cũ nữa. Việc đổi chỉ xảy ra khi có request (không chạy nền).
 */

/**
 * Địa chỉ gốc của API nestproxy.
 */
const DEFAULT_API_BASE_URL = 'https://nestproxy.com';

/**
 * Thời gian chờ tối đa cho mỗi lần gọi API nestproxy (mili giây).
 */
const DEFAULT_REQUEST_TIMEOUT_MILLISECONDS = 5000;

/**
 * Chu kỳ đổi IP mặc định (mili giây); nestproxy cho đổi tối thiểu mỗi 60 giây.
 */
const DEFAULT_ROTATE_INTERVAL_MILLISECONDS = 60000;

/**
 * Thời gian chờ thêm khi nestproxy báo chưa được đổi (429) mà không ghi rõ số giây (mili giây).
 */
const DEFAULT_RETRY_AFTER_MILLISECONDS = 10000;

/**
 * Định dạng hợp lệ của trường `proxy`: tên máy hoặc IPv4, dấu hai chấm, cổng.
 */
const PROXY_ADDRESS_PATTERN = /^[A-Za-z0-9.-]+:\d{1,5}$/;

/**
 * Lỗi khi không lấy được proxy từ nestproxy. Không chứa `proxy_key` để tránh lộ key qua log hoặc API.
 */
class NestproxyError extends Error {
    /**
     * - `message` (string): Nội dung lỗi.
     * - `retryAfterSeconds` (number, không bắt buộc): Số giây nestproxy yêu cầu chờ (lỗi 429).
     * - `statusCode` (number, không bắt buộc): Mã HTTP nestproxy trả về.
     */
    constructor(message, retryAfterSeconds = null, statusCode = null) {
        super(message);
        this.name = 'NestproxyError';
        this.retryAfterSeconds = retryAfterSeconds;
        this.statusCode = statusCode;
    }
}

/**
 * Client gọi API nestproxy, trả về URL proxy SOCKS5 cho `TcpClient` và tự đổi IP theo chu kỳ.
 */
class NestproxyClient {
    /**
     * - `options` (object): Các tùy chọn sau:
     *   - `options.proxyKey` (string): `proxy_key` của nestproxy (bắt buộc).
     *   - `options.apiBaseUrl` (string, mặc định 'https://nestproxy.com'): Địa chỉ gốc của API.
     *   - `options.requestTimeoutMilliseconds` (number, mặc định 5000): Thời gian chờ mỗi lần gọi API.
     *   - `options.rotateIntervalMilliseconds` (number, mặc định 60000): Dùng một IP tối đa bao lâu trước khi đổi IP mới.
     *   - `options.fetchFunction` (Function, mặc định `fetch`): Hàm gọi HTTP, thay bằng hàm giả trong test.
     *   - `options.nowFunction` (Function, mặc định `Date.now`): Hàm lấy thời gian hiện tại, thay trong test.
     * - Ném lỗi TypeError: Khi thiếu `proxyKey`.
     */
    constructor(options = {}) {
        if (typeof options.proxyKey !== 'string' || options.proxyKey.trim() === '') {
            throw new TypeError('Thiếu proxy_key của nestproxy');
        }

        this.proxyKey = options.proxyKey.trim();
        this.apiBaseUrl = options.apiBaseUrl || DEFAULT_API_BASE_URL;
        this.requestTimeoutMilliseconds = options.requestTimeoutMilliseconds ?? DEFAULT_REQUEST_TIMEOUT_MILLISECONDS;
        this.rotateIntervalMilliseconds = options.rotateIntervalMilliseconds ?? DEFAULT_ROTATE_INTERVAL_MILLISECONDS;
        this.fetchFunction = options.fetchFunction || fetch;
        this.nowFunction = options.nowFunction || Date.now;

        /**
         * Proxy đang dùng (`socks5://IP:port`) và thời điểm được đổi sang IP mới (mili giây kể từ epoch).
         */
        this.currentProxyUrl = null;
        this.changeAt = 0;

        /**
         * Lời gọi đang chạy, để nhiều lượt đăng nhập cùng lúc chỉ gọi nestproxy một lần.
         */
        this.pendingRequest = null;
    }

    /**
     * Lấy URL proxy SOCKS5 cho lượt đăng nhập hiện tại: dùng IP đang giữ nếu chưa tới lúc đổi,
     * ngược lại xin IP mới từ nestproxy.
     *
     * - Trả về (Promise<string>): URL dạng `socks5://IP:port`.
     * - Ném lỗi NestproxyError: Khi nestproxy lỗi, hết thời gian chờ, hoặc không cấp được proxy.
     */
    async getProxyUrl() {
        if (this.currentProxyUrl && this.nowFunction() < this.changeAt) {
            return this.currentProxyUrl;
        }

        if (!this.pendingRequest) {
            this.pendingRequest = this.refreshProxy().finally(() => {
                this.pendingRequest = null;
            });
        }

        return this.pendingRequest;
    }

    /**
     * Bỏ proxy đang giữ để lần sau hỏi lại nestproxy (gọi khi kết nối qua proxy thất bại).
     * Lần sau sẽ hỏi proxy hiện tại trước, chỉ xin IP mới khi đã tới lúc được đổi.
     */
    invalidate() {
        this.currentProxyUrl = null;
        this.changeAt = 0;
    }

    /**
     * Chọn proxy mới cho chu kỳ tiếp theo.
     *
     * - Chưa giữ proxy nào: hỏi `current`; nếu key đã có proxy và chưa tới lúc đổi thì dùng tiếp, còn lại xin IP mới.
     * - Đã giữ proxy và tới lúc đổi: xin IP mới qua `available`.
     * - Nestproxy báo chưa được đổi (429): tiếp tục dùng proxy đang có, hẹn lại sau `retryAfter`.
     *
     * - Trả về (Promise<string>): URL dạng `socks5://IP:port`.
     * - Ném lỗi NestproxyError: Khi không có proxy nào dùng được.
     */
    async refreshProxy() {
        if (!this.currentProxyUrl) {
            const currentResponse = await this.callApi('/api/client/proxy/current');
            const currentProxyAddress = readProxyAddress(currentResponse);
            const currentChangeAt = parseTimestamp(currentResponse.canChangeAt);

            /*
             * Key đã có proxy và chưa tới lúc được đổi: dùng tiếp tới đúng mốc `canChangeAt` (không cộng thêm chu kỳ,
             * vì IP này đã được cấp từ trước). Không có `canChangeAt` thì dùng thêm một chu kỳ.
             */
            const isCurrentStillValid = currentChangeAt === null || this.nowFunction() < currentChangeAt;
            if (currentProxyAddress && isCurrentStillValid) {
                const changeAt = currentChangeAt ?? this.nowFunction() + this.rotateIntervalMilliseconds;
                return this.useProxy(currentProxyAddress, changeAt);
            }

            if (currentProxyAddress) {
                /*
                 * Key đã có proxy nhưng đã quá thời gian đổi: giữ làm phương án dự phòng nếu xin IP mới bị từ chối.
                 */
                this.currentProxyUrl = `socks5://${currentProxyAddress}`;
            }
        }

        try {
            const availableResponse = await this.callApi('/api/client/proxy/available');
            const newProxyAddress = readProxyAddress(availableResponse);
            if (!newProxyAddress) {
                const providerMessage = typeof availableResponse.message === 'string' ? `: ${availableResponse.message}` : '';
                throw new NestproxyError(`Nestproxy không trả về proxy hợp lệ${providerMessage}`);
            }

            /*
             * IP mới: dùng ít nhất một chu kỳ, và không đổi trước mốc `canChangeAt` của nestproxy.
             */
            const intervalChangeAt = this.nowFunction() + this.rotateIntervalMilliseconds;
            const providerChangeAt = parseTimestamp(availableResponse.canChangeAt);
            const changeAt = providerChangeAt === null ? intervalChangeAt : Math.max(providerChangeAt, intervalChangeAt);

            return this.useProxy(newProxyAddress, changeAt);
        } catch (error) {
            const isCooldown = error instanceof NestproxyError && error.statusCode === 429;
            if (isCooldown && this.currentProxyUrl) {
                /*
                 * Chưa được đổi IP: dùng tiếp proxy cũ thêm một lúc, hẹn thử đổi lại sau thời gian nestproxy yêu cầu.
                 */
                const retryAfterMilliseconds = error.retryAfterSeconds ? error.retryAfterSeconds * 1000 : DEFAULT_RETRY_AFTER_MILLISECONDS;
                this.changeAt = this.nowFunction() + retryAfterMilliseconds;

                return this.currentProxyUrl;
            }

            throw error;
        }
    }

    /**
     * Ghi nhận proxy đang dùng và thời điểm đổi sang IP mới.
     *
     * - `proxyAddress` (string): Địa chỉ dạng `IP:port`.
     * - `changeAt` (number): Thời điểm đổi IP (mili giây kể từ epoch).
     * - Trả về (string): URL dạng `socks5://IP:port`.
     */
    useProxy(proxyAddress, changeAt) {
        this.currentProxyUrl = `socks5://${proxyAddress}`;
        this.changeAt = changeAt;

        return this.currentProxyUrl;
    }

    /**
     * Gọi một endpoint GET của nestproxy với `proxy_key`.
     *
     * - `path` (string): Đường dẫn endpoint, ví dụ '/api/client/proxy/current'.
     * - Trả về (Promise<object>): Body JSON của phản hồi.
     * - Ném lỗi NestproxyError: Khi lỗi mạng, hết thời gian chờ, mã HTTP lỗi hoặc body không phải JSON.
     */
    async callApi(path) {
        const requestUrl = new URL(path, this.apiBaseUrl);
        requestUrl.searchParams.set('proxy_key', this.proxyKey);

        let response;
        try {
            response = await this.fetchFunction(requestUrl, {
                headers: { Accept: 'application/json' },
                signal: AbortSignal.timeout(this.requestTimeoutMilliseconds),
            });
        } catch (error) {
            const isTimeout = error?.name === 'TimeoutError' || error?.name === 'AbortError';
            throw new NestproxyError(isTimeout ? 'Gọi nestproxy hết thời gian chờ' : 'Không kết nối được tới nestproxy');
        }

        let responseBody = null;
        try {
            responseBody = await response.json();
        } catch {
            responseBody = null;
        }

        if (response.status === 429) {
            const retryAfterSeconds = Number(responseBody?.retryAfter) || null;
            throw new NestproxyError('Nestproxy yêu cầu chờ trước khi cấp IP mới', retryAfterSeconds, 429);
        }

        if (!response.ok) {
            throw new NestproxyError(`Nestproxy trả lỗi HTTP ${response.status}`, null, response.status);
        }

        if (!responseBody || typeof responseBody !== 'object') {
            throw new NestproxyError('Nestproxy trả dữ liệu không phải JSON');
        }

        return responseBody;
    }
}

/**
 * Đọc địa chỉ proxy `IP:port` hợp lệ từ phản hồi nestproxy.
 *
 * - `responseBody` (object): Body JSON của nestproxy.
 * - Trả về (string|null): Địa chỉ proxy, hoặc null nếu không có hoặc sai định dạng.
 */
function readProxyAddress(responseBody) {
    const proxyAddress = typeof responseBody?.proxy === 'string' ? responseBody.proxy.trim() : '';

    return PROXY_ADDRESS_PATTERN.test(proxyAddress) ? proxyAddress : null;
}

/**
 * Đổi chuỗi thời gian ISO 8601 (ví dụ `canChangeAt`) sang mili giây.
 *
 * - `value` (string, không bắt buộc): Chuỗi thời gian.
 * - Trả về (number|null): Mili giây kể từ epoch, hoặc null nếu không đọc được.
 */
function parseTimestamp(value) {
    const timestamp = typeof value === 'string' ? Date.parse(value) : Number.NaN;

    return Number.isFinite(timestamp) ? timestamp : null;
}

export { NestproxyClient, NestproxyError };
