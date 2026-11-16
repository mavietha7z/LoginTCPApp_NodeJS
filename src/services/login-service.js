import { performance } from 'node:perf_hooks';

import { generateEncryptionKey } from '../crypto/encryption-key.js';
import { TcpClient, TimeoutError } from '../transport/tcp-client.js';
import { EmptyPacket, LoginPrepareRequest, LoginRequest, LoginTokenGetRequest } from '../protocol/requests.js';
import {
    decodePacket,
    SystemResponse,
    decryptResponseData,
    decodeLoginReplyData,
    decodeLoginPrepareReplyData,
} from '../protocol/responses.js';

/**
 * Điều phối toàn bộ luồng đăng nhập TCP và lấy SSO key.
 * Tương ứng hàm `login_and_get_keys` trong `LoginTCPApp.py` (dòng 837–981).
 */

/**
 * Mã lỗi máy chủ được phép thử lại: 110 = ERROR_DECRYPT. CAPTCHA/lỗi xác thực không thử lại.
 */
const RETRYABLE_ERROR_CODES = new Set([110]);

/**
 * Các lệnh gửi gộp sau khi lấy token, theo đúng thứ tự của Python.
 */
const FOLLOW_UP_COMMANDS = [278, 511, 276, 278, 442, 342];

/**
 * Mã lỗi nội bộ (âm) — không phải mã của máy chủ.
 */
const INTERNAL_ERROR_CODES = Object.freeze({
    /**
     * Chưa có lần thử nào ghi nhận lỗi (ví dụ maximumRetries = 0).
     */
    NO_ATTEMPT: -5999,

    /**
     * LoginPrepareReply thiếu khóa, dữ liệu, salt hoặc verify_code.
     */
    MISSING_PREPARE_DATA: -2,

    /**
     * LoginReply thiếu dữ liệu hoặc session key không hợp lệ.
     */
    INVALID_LOGIN_DATA: -3,

    /**
     * Không nhận được SSO key hợp lệ trong thời gian chờ.
     */
    MISSING_SSO_KEY: -4,

    /**
     * Lỗi kết nối hoặc lỗi phân tích packet.
     */
    TRANSPORT_ERROR: -5,
});

/**
 * Tính thời gian đã trôi qua, làm tròn 2 chữ số thập phân (giống `round(..., 2)` của Python).
 *
 * - `startTime` (number): Mốc thời gian lấy từ `performance.now()`.
 * - Trả về (number): Số giây đã trôi qua.
 */
function calculateElapsedSeconds(startTime) {
    return Math.round((performance.now() - startTime) / 10) / 100;
}

/**
 * Dựng object kết quả lỗi trả về cho người gọi.
 *
 * - `code` (number): Mã lỗi (của máy chủ hoặc nội bộ).
 * - `message` (string|null): Mô tả lỗi; bỏ qua nếu rỗng.
 * - `startTime` (number): Mốc bắt đầu, dùng để tính `duration`.
 * - `attempts` (number): Số lần đã thử.
 * - Trả về (object): Kết quả lỗi dạng { code: number, msg?: string, duration: number, attempts: number }.
 */
function buildErrorResult(code, message, startTime, attempts) {
    const result = { code };
    if (message) {
        result.msg = message;
    }

    result.duration = calculateElapsedSeconds(startTime);
    result.attempts = attempts;

    return result;
}

/**
 * Kiểm tra lỗi đọc frame có phải là "hết dữ liệu" (timeout hoặc máy chủ đóng kết nối) hay không.
 *
 * - `error` (Error): Lỗi từ `readFrame`.
 * - Trả về (boolean): true nếu nên dừng thu thập reply một cách bình thường.
 */
function isEndOfResponseStream(error) {
    return error instanceof TimeoutError || error.message === 'TCP connection ended' || error.message === 'TCP connection closed';
}

/**
 * Đăng nhập vào máy chủ TCP và lấy uid, session key, SSO key.
 *
 * Trình tự mỗi lần thử (mỗi lần mở kết nối TCP mới):
 *   1. LoginPrepare (256): nhận salt và verify_code.
 *   2. Login (257): gửi MD5 mật khẩu đã mã hóa, nhận uid và session key.
 *   3. LoginTokenGet (277): packet mã hóa toàn bộ bằng session key.
 *   4. Gửi gộp các lệnh 278, 511, 276, 278, 442, 342 rồi chờ SsoKeyGetReply.
 * Chỉ thử lại với lỗi kết nối, dữ liệu thiếu, hoặc mã lỗi trong RETRYABLE_ERROR_CODES.
 *
 * - `account` (string): Tên tài khoản hoặc email.
 * - `password` (string): Mật khẩu.
 * - `options` (object, không bắt buộc): Các tùy chọn sau:
 *   - `options.maximumRetries` (number, mặc định 3): Số lần thử tối đa.
 *   - `options.deviceIdentifier` (string, không bắt buộc): Device ID thập phân; bỏ trống để tự xác định.
 *   - `options.randomMode` ('legacy'|'cryptographic', mặc định 'legacy'): Cách sinh IV của XTEA.
 *   - `options.transportOptions` (object, không bắt buộc): Tùy chọn truyền cho `TcpClient`.
 *   - `options.transportFactory` (() => object, không bắt buộc): Hàm tạo transport thay cho `TcpClient` (dùng trong test).
 *   - `options.responseWindowMilliseconds` (number, mặc định 3000): Tổng thời gian chờ SsoKeyGetReply.
 *   - `options.responseIdleTimeoutMilliseconds` (number, mặc định 500): Thời gian chờ tối đa giữa hai frame.
 *   - `options.maximumFollowUpFrames` (number, mặc định 64): Số frame tối đa đọc khi chờ SSO key.
 * - Trả về (Promise<object>): Khi thành công: { code: 0, uid, session_key, SsoKeyGetReply: { sso_key }, duration, attempts };
 *   khi thất bại: { code, msg?, duration, attempts }.
 */
async function loginAndGetKeys(account, password, options = {}) {
    const startTime = performance.now();
    const randomMode = options.randomMode || 'legacy';
    const maximumRetries = options.maximumRetries ?? 3;
    const requestOptions = { deviceIdentifier: options.deviceIdentifier, randomMode };

    let attempt = 0;
    let lastErrorMessage = null;
    let lastErrorCode = INTERNAL_ERROR_CODES.NO_ATTEMPT;

    for (attempt = 1; attempt <= maximumRetries; attempt += 1) {
        const tcpClient = options.transportFactory ? options.transportFactory() : new TcpClient(options.transportOptions);

        try {
            await tcpClient.connect();

            /*
             * Bước 1: LoginPrepare, command 256 (header ở dạng rõ).
             */
            const loginPreparePacket = new LoginPrepareRequest(account, requestOptions).buildFullPacket();
            const loginPrepareFrame = await tcpClient.sendMessage(loginPreparePacket);
            const loginPrepareReply = new SystemResponse(decodePacket(loginPrepareFrame));

            if (!loginPrepareReply.isSuccess()) {
                lastErrorCode = loginPrepareReply.code;
                lastErrorMessage = loginPrepareReply.message;

                /*
                 * Không tự thử lại khi gặp CAPTCHA, lỗi xác thực hoặc tài khoản bị khóa.
                 */
                if (!RETRYABLE_ERROR_CODES.has(lastErrorCode)) {
                    return buildErrorResult(lastErrorCode, lastErrorMessage, startTime, attempt);
                }

                continue;
            }

            if (!loginPrepareReply.body.encrypt_key || !loginPrepareReply.body.data) {
                lastErrorCode = INTERNAL_ERROR_CODES.MISSING_PREPARE_DATA;
                lastErrorMessage = 'Thiếu thông tin đăng nhập, chuẩn bị các trường mã hóa';

                continue;
            }

            const decryptedPrepareData = decryptResponseData(loginPrepareReply.body.encrypt_key, loginPrepareReply.body.data);
            const loginPrepareData = decodeLoginPrepareReplyData(decryptedPrepareData);
            if (!loginPrepareData.salt || !loginPrepareData.verify_code) {
                lastErrorCode = INTERNAL_ERROR_CODES.MISSING_PREPARE_DATA;
                lastErrorMessage = 'Thiếu salt hoặc mã xác thực trong LoginPrepare';

                continue;
            }

            /*
             * Bước 2: Login, command 257. MD5 -> SHA256 -> SHA256 cho ra khóa XTEA 16 byte.
             */
            const loginEncryptionKey = generateEncryptionKey(password, loginPrepareData.salt, loginPrepareData.verify_code);
            const loginPacket = new LoginRequest(password, loginEncryptionKey, requestOptions).buildFullPacket();
            const loginFrame = await tcpClient.sendMessage(loginPacket);
            const loginReply = new SystemResponse(decodePacket(loginFrame));

            if (!loginReply.isSuccess()) {
                lastErrorCode = loginReply.code;
                lastErrorMessage = loginReply.message;

                if (!RETRYABLE_ERROR_CODES.has(lastErrorCode)) {
                    return buildErrorResult(lastErrorCode, lastErrorMessage, startTime, attempt);
                }

                continue;
            }

            if (!loginReply.body.data) {
                lastErrorCode = INTERNAL_ERROR_CODES.INVALID_LOGIN_DATA;
                lastErrorMessage = 'Thiếu dữ liệu phản hồi đăng nhập';

                continue;
            }

            const decryptedLoginData = decryptResponseData(loginEncryptionKey, loginReply.body.data);
            const loginData = decodeLoginReplyData(decryptedLoginData);
            const sessionKey = loginData.session_key;

            /*
             * Session key hợp lệ phải đúng 16 byte, tức 32 ký tự hex.
             */
            if (!sessionKey || !/^[0-9a-f]{32}$/.test(sessionKey)) {
                lastErrorCode = INTERNAL_ERROR_CODES.INVALID_LOGIN_DATA;
                lastErrorMessage = 'Khóa phiên không hợp lệ, phải đúng 16 byte';

                continue;
            }

            const sessionKeyBytes = Buffer.from(sessionKey, 'hex');

            /*
             * Bước 3: lấy token, command 277; từ đây mọi packet đều mã hóa toàn bộ bằng session key.
             */
            const tokenPacket = new LoginTokenGetRequest(sessionKey, requestOptions).buildFullPacket();
            const tokenFrame = await tcpClient.sendMessage(tokenPacket);
            const tokenReply = new SystemResponse(decodePacket(tokenFrame, sessionKeyBytes));

            if (!tokenReply.isSuccess()) {
                lastErrorCode = tokenReply.code;
                lastErrorMessage = tokenReply.message;

                if (!RETRYABLE_ERROR_CODES.has(lastErrorCode)) {
                    return buildErrorResult(lastErrorCode, lastErrorMessage, startTime, attempt);
                }

                continue;
            }

            /*
             * Gửi gộp các lệnh tiếp theo trong một lần ghi, giống `sendall` của Python.
             */
            const followUpPackets = FOLLOW_UP_COMMANDS.map((command) =>
                new EmptyPacket(sessionKey, command, requestOptions).buildFullPacket(),
            );
            await tcpClient.write(Buffer.concat(followUpPackets));

            /*
             * Bước 4: đọc reply cho tới khi gặp SsoKeyGetReply, hết thời gian, hoặc hết số frame cho phép.
             */
            const responseWindowMilliseconds = options.responseWindowMilliseconds ?? 3000;
            const responseIdleTimeoutMilliseconds = options.responseIdleTimeoutMilliseconds ?? 500;
            const maximumFollowUpFrames = options.maximumFollowUpFrames ?? 64;
            const responseDeadline = Date.now() + responseWindowMilliseconds;

            let ssoKey = null;
            for (let frameIndex = 0; frameIndex < maximumFollowUpFrames; frameIndex += 1) {
                const remainingMilliseconds = responseDeadline - Date.now();
                if (remainingMilliseconds <= 0) break;

                let replyFrame;
                try {
                    const frameTimeoutMilliseconds = Math.min(remainingMilliseconds, responseIdleTimeoutMilliseconds);
                    replyFrame = await tcpClient.readFrame(frameTimeoutMilliseconds);
                } catch (error) {
                    if (isEndOfResponseStream(error)) {
                        break;
                    }

                    throw error;
                }

                const reply = decodePacket(replyFrame, sessionKeyBytes);
                if (reply.message_type === 'SsoKeyGetReply' && reply.body.sso_key) {
                    ssoKey = reply.body.sso_key;

                    break;
                }
            }

            /*
             * Giống Python: SSO key phải dài tối thiểu 8 ký tự mới coi là hợp lệ.
             */
            if (ssoKey && ssoKey.length >= 8) {
                return {
                    code: 0,
                    attempts: attempt,
                    uid: loginData.uid,
                    session_key: sessionKey,
                    SsoKeyGetReply: { sso_key: ssoKey },
                    duration: calculateElapsedSeconds(startTime),
                };
            }

            lastErrorCode = INTERNAL_ERROR_CODES.MISSING_SSO_KEY;
            lastErrorMessage = 'Không nhận được SSO key';
        } catch (error) {
            lastErrorCode = INTERNAL_ERROR_CODES.TRANSPORT_ERROR;

            /*
             * LƯU Ý: error.message hiện vẫn được trả ra HTTP qua trường `msg`, có thể lộ địa chỉ
             * máy chủ/proxy (lỗi đã ghi nhận khi audit, chưa sửa vì đợt này giữ nguyên logic).
             */
            lastErrorMessage = error instanceof TimeoutError ? 'Kết nối TCP hết thời gian chờ' : error.message;
        } finally {
            tcpClient.close();
        }
    }

    /*
     * Sau vòng lặp, attempt = maximumRetries + 1 nên số lần đã thử là attempt - 1.
     */
    const attemptCount = Math.min(attempt - 1, maximumRetries);
    return buildErrorResult(lastErrorCode, lastErrorMessage, startTime, attemptCount);
}

export { loginAndGetKeys };
