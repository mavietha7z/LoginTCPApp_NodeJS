import { networkInterfaces } from 'node:os';
import { createHash, randomBytes } from 'node:crypto';

import { XteaCustom } from '../crypto/xtea-custom.js';
import { encodeBytesField, encodeVarintField } from './protobuf.js';
import { buildFullyEncryptedPacket, buildPacket } from './packets.js';

/**
 * Các lớp dựng packet gửi lên máy chủ, tương ứng các lớp request trong `LoginTCPApp.py`
 * (dòng 371–523). Byte sinh ra phải khớp tuyệt đối với `test/fixtures/python-packets.json`.
 */

/**
 * command_type của packet client gửi lên (máy chủ trả về 3 hoặc 4).
 */
const CLIENT_COMMAND_TYPE = 2;

/**
 * Phiên bản giao thức ghi vào field 1 của header.
 */
const PROTOCOL_VERSION = 285212918;

/**
 * Xác định device ID ghi vào header (field 2) và body bước Login (field 4).
 *
 * Thứ tự ưu tiên:
 *   1. Biến môi trường `DEVICE_ID` (chỉ gồm chữ số thập phân).
 *   2. Địa chỉ MAC của card mạng đầu tiên không phải loopback, đổi sang số thập phân.
 * Python dùng `hash(uuid.getnode())`, có thể chọn card mạng khác nên kết quả có thể khác.
 *
 * - Trả về (string): Device ID dạng chuỗi số thập phân.
 * - Ném lỗi Error: Khi `DEVICE_ID` không hợp lệ hoặc không tìm được địa chỉ MAC.
 */
function discoverDeviceIdentifier() {
    const configuredValue = process.env.DEVICE_ID;
    if (configuredValue) {
        if (!/^\d+$/.test(configuredValue)) {
            throw new Error('DEVICE_ID chỉ được chứa chữ số thập phân');
        }
        return configuredValue;
    }

    const networkDevices = Object.values(networkInterfaces()).flat().filter(Boolean);
    const candidate = networkDevices.find((device) => !device.internal && device.mac && device.mac !== '00:00:00:00:00:00');
    if (!candidate) {
        throw new Error('Không thể xác định DEVICE_ID; hãy thiết lập DEVICE_ID từ máy chủ Python gốc');
    }

    /*
     * MAC "aa:bb:cc:dd:ee:ff" -> số nguyên 0xaabbccddeeff -> chuỗi thập phân.
     */
    const hexadecimalMac = candidate.mac.replace(/[:-]/g, '');
    return BigInt(`0x${hexadecimalMac}`).toString();
}

/**
 * Lớp cơ sở cho mọi request: lưu device ID, timestamp, khóa ngẫu nhiên và dựng header chung.
 * Tương ứng `BaseLoginRequest` trong Python (dòng 371–408).
 */
class BaseLoginRequest {
    /**
     * - `options` (object, không bắt buộc): Các tùy chọn sau:
     *   - `options.deviceIdentifier` (string, không bắt buộc): Device ID thập phân; bỏ trống để tự xác định.
     *   - `options.timestamp` (number, không bắt buộc): Unix timestamp (giây); bỏ trống để lấy thời điểm hiện tại.
     *   - `options.randomKey` (Buffer, không bắt buộc): Khóa 16 byte dùng ở bước LoginPrepare; bỏ trống để sinh ngẫu nhiên.
     *   - `options.initializationVector` (Buffer, không bắt buộc): IV 8 byte cố định (chỉ dùng cho test).
     *   - `options.randomMode` ('legacy'|'cryptographic', mặc định 'legacy'): Cách sinh IV của XTEA.
     */
    constructor(options = {}) {
        this.deviceIdentifier = options.deviceIdentifier || discoverDeviceIdentifier();
        this.timestamp = options.timestamp ?? Math.floor(Date.now() / 1000);
        this.randomKey = options.randomKey || randomBytes(16);
        this.initializationVector = options.initializationVector;
        this.randomMode = options.randomMode || 'legacy';
    }

    /**
     * Dựng header Protobuf: version, device ID, command_type = 2, command, timestamp.
     *
     * - `command` (number): Mã lệnh (ví dụ 256, 257, 277).
     * - Trả về (Buffer): Byte header.
     */
    buildHeader(command) {
        return Buffer.concat([
            encodeVarintField(1, PROTOCOL_VERSION),
            encodeVarintField(2, this.deviceIdentifier),
            encodeVarintField(3, CLIENT_COMMAND_TYPE),
            encodeVarintField(4, command),
            encodeVarintField(6, this.timestamp),
        ]);
    }

    /**
     * Mã hóa dữ liệu bằng XTEA tùy biến.
     *
     * - `plaintext` (Buffer): Dữ liệu cần mã hóa.
     * - `encryptionKey` (Buffer, không bắt buộc): Khóa 16 byte; mặc định là `randomKey`.
     * - Trả về (Buffer): Bản mã.
     */
    encryptData(plaintext, encryptionKey = this.randomKey) {
        const cipher = new XteaCustom(encryptionKey, { randomMode: this.randomMode });
        return cipher.encrypt(plaintext, this.initializationVector);
    }

    /**
     * Dựng body gồm field 1 = khóa và field 2 = dữ liệu đã mã hóa.
     *
     * - `encryptionKey` (Buffer): Khóa dùng để mã hóa (gửi kèm cho máy chủ).
     * - `encryptedData` (Buffer): Dữ liệu đã mã hóa.
     * - Trả về (Buffer): Byte body.
     */
    buildEncryptedBody(encryptionKey, encryptedData) {
        return Buffer.concat([encodeBytesField(1, encryptionKey), encodeBytesField(2, encryptedData)]);
    }
}

/**
 * Request LoginPrepare (command 256): gửi tài khoản để nhận salt và verify_code.
 * Tương ứng `LoginPrepareRequest` trong Python (dòng 411–439).
 */
class LoginPrepareRequest extends BaseLoginRequest {
    /**
     * - `account` (string): Tên tài khoản hoặc email.
     * - `options` (object, không bắt buộc): Xem `BaseLoginRequest`.
     */
    constructor(account, options = {}) {
        super(options);
        this.account = account;

        /*
         * auth_type: luôn là 0.
         */
        this.authenticationType = 0;

        /*
         * account_type: 2 nếu tài khoản có dạng email, ngược lại 1.
         */
        this.accountType = /^[^@]+@[^@]+\.[^@]+/.test(account) ? 2 : 1;

        /*
         * client_type và client_version lấy nguyên từ Python, chưa xác minh còn được máy chủ chấp nhận.
         */
        this.clientType = 4352;
        this.clientVersion = 246;
    }

    /**
     * Dựng dữ liệu gốc (trước khi mã hóa):
     * field 1 = auth_type, 2 = account_type, 3 = tài khoản UTF-8, 4 = client_type, 5 = client_version.
     *
     * - Trả về (Buffer): Byte dữ liệu.
     */
    buildRequestData() {
        return Buffer.concat([
            encodeVarintField(1, this.authenticationType),
            encodeVarintField(2, this.accountType),
            encodeBytesField(3, Buffer.from(this.account, 'utf8')),
            encodeVarintField(4, this.clientType),
            encodeVarintField(5, this.clientVersion),
        ]);
    }

    /**
     * Dựng packet hoàn chỉnh dạng header rõ; body = [field 1: randomKey][field 2: XTEA(randomKey, dữ liệu)].
     *
     * - Trả về (Buffer): Packet gửi lên máy chủ.
     */
    buildFullPacket() {
        const header = this.buildHeader(256);
        const encryptedData = this.encryptData(this.buildRequestData());
        const body = this.buildEncryptedBody(this.randomKey, encryptedData);

        return buildPacket(header, body);
    }
}

/**
 * Request Login (command 257): gửi MD5 mật khẩu, đã mã hóa bằng khóa sinh từ salt/verify_code.
 * Tương ứng `LoginRequestHandler` trong Python (dòng 442–478); đổi tên vì đây là request, không phải handler.
 */
class LoginRequest extends BaseLoginRequest {
    /**
     * - `password` (string): Mật khẩu gốc.
     * - `encryptionKey` (Buffer|string): Khóa 16 byte (Buffer hoặc chuỗi hex) từ `generateEncryptionKey`.
     * - `options` (object, không bắt buộc): Xem `BaseLoginRequest`.
     */
    constructor(password, encryptionKey, options = {}) {
        super(options);
        this.password = password;
        this.encryptionKey = Buffer.isBuffer(encryptionKey) ? encryptionKey : Buffer.from(encryptionKey, 'hex');

        /*
         * login_mode: luôn là 0.
         */
        this.loginMode = 0;

        /*
         * user_status: giá trị cố định 4608 lấy từ Python.
         */
        this.userStatus = 4608;
    }

    /**
     * Dựng dữ liệu gốc (trước khi mã hóa):
     * field 1 = chuỗi hex MD5 của mật khẩu, 2 = login_mode,
     * 3 = message lồng có field 2 = user_status, 4 = device ID dạng chuỗi.
     *
     * - Trả về (Buffer): Byte dữ liệu.
     */
    buildRequestData() {
        const passwordHash = createHash('md5').update(this.password, 'utf8').digest('hex');
        const userStatusMessage = encodeVarintField(2, this.userStatus);

        return Buffer.concat([
            encodeBytesField(1, Buffer.from(passwordHash, 'utf8')),
            encodeVarintField(2, this.loginMode),
            encodeBytesField(3, userStatusMessage),
            encodeBytesField(4, Buffer.from(this.deviceIdentifier, 'utf8')),
        ]);
    }

    /**
     * Dựng packet hoàn chỉnh dạng header rõ; body chỉ có field 1 = bản mã (khác LoginPrepare).
     *
     * - Trả về (Buffer): Packet gửi lên máy chủ.
     */
    buildFullPacket() {
        const header = this.buildHeader(257);
        const encryptedData = this.encryptData(this.buildRequestData(), this.encryptionKey);

        return buildPacket(header, encodeBytesField(1, encryptedData));
    }
}

/**
 * Request LoginTokenGet (command 277): packet đầu tiên dạng mã hóa toàn bộ bằng session key.
 * Tương ứng `LoginTokenGetRequest` trong Python (dòng 502–523).
 */
class LoginTokenGetRequest extends BaseLoginRequest {
    /**
     * - `sessionKey` (Buffer|string): Session key 16 byte (Buffer hoặc chuỗi hex) nhận từ LoginReply.
     * - `options` (object, không bắt buộc): Xem `BaseLoginRequest`.
     */
    constructor(sessionKey, options = {}) {
        super(options);
        this.sessionKey = Buffer.isBuffer(sessionKey) ? sessionKey : Buffer.from(sessionKey, 'hex');
    }

    /**
     * Dữ liệu body: field 1 = 1.
     *
     * - Trả về (Buffer): Byte body.
     */
    buildRequestData() {
        return encodeVarintField(1, 1);
    }

    /**
     * Dựng packet: [u32 LE độ dài bản mã][XTEA(sessionKey, [u16 BE độ dài header][header][body])].
     *
     * - Trả về (Buffer): Packet gửi lên máy chủ.
     */
    buildFullPacket() {
        const header = this.buildHeader(277);
        const headerLength = Buffer.alloc(2);

        headerLength.writeUInt16BE(header.length);

        const plaintext = Buffer.concat([headerLength, header, this.buildRequestData()]);
        const encrypted = this.encryptData(plaintext, this.sessionKey);

        const frameLength = Buffer.alloc(4);

        frameLength.writeUInt32LE(encrypted.length);

        return Buffer.concat([frameLength, encrypted]);
    }
}

/**
 * Packet không có body, chỉ có header với command tùy ý, mã hóa toàn bộ bằng session key.
 * Dùng cho loạt lệnh 278, 511, 276, 278, 442, 342 sau khi lấy token.
 * Tương ứng `EmptyPacket` trong Python (dòng 481–500).
 */
class EmptyPacket extends BaseLoginRequest {
    /**
     * - `sessionKey` (Buffer|string): Session key 16 byte (Buffer hoặc chuỗi hex).
     * - `command` (number): Mã lệnh ghi vào header.
     * - `options` (object, không bắt buộc): Xem `BaseLoginRequest`.
     */
    constructor(sessionKey, command, options = {}) {
        super(options);
        this.sessionKey = Buffer.isBuffer(sessionKey) ? sessionKey : Buffer.from(sessionKey, 'hex');
        this.command = command;
    }

    /**
     * Dựng packet: [u32 LE độ dài bản mã][XTEA(sessionKey, [u16 BE độ dài header][header])].
     *
     * - Trả về (Buffer): Packet gửi lên máy chủ.
     */
    buildFullPacket() {
        const header = this.buildHeader(this.command);
        const headerLength = Buffer.alloc(2);
        headerLength.writeUInt16BE(header.length);

        const plaintextPacket = Buffer.concat([headerLength, header]);
        const encryptionOptions = {
            randomMode: this.randomMode,
            initializationVector: this.initializationVector,
        };

        return buildFullyEncryptedPacket(plaintextPacket, this.sessionKey, encryptionOptions);
    }
}

export { discoverDeviceIdentifier, BaseLoginRequest, LoginPrepareRequest, LoginRequest, LoginTokenGetRequest, EmptyPacket };
