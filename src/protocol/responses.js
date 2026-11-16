import { XteaCustom } from '../crypto/xtea-custom.js';
import { parsePacketPayload } from './packets.js';
import { convertBigIntForJson, decodeProtobufFields } from './protobuf.js';
import systemErrorCodes from './system-errors.json' with { type: 'json' };

/**
 * Giải mã các packet máy chủ trả về.
 * Tương ứng `SystemResponse` (dòng 616–629) và `PacketReceiver` (dòng 632–748) trong `LoginTCPApp.py`.
 */

/** Bộ giải mã UTF-8 chế độ nghiêm ngặt: ném lỗi khi gặp byte không hợp lệ thay vì thay bằng ký tự lỗi. */
const strictUtf8Decoder = new TextDecoder('utf-8', { fatal: true });

/**
 * Giải mã buffer thành chuỗi UTF-8; nếu không phải UTF-8 hợp lệ thì trả về chuỗi hex.
 *
 * @param {Buffer} inputBuffer - Dữ liệu cần giải mã.
 * @returns {string} Chuỗi UTF-8 hoặc chuỗi hex.
 */
function decodeUtf8TextOrHexadecimal(inputBuffer) {
    try {
        return strictUtf8Decoder.decode(inputBuffer);
    } catch {
        return inputBuffer.toString('hex');
    }
}

/**
 * Lấy giá trị của một field kiểu bytes (wire type 2).
 *
 * @param {Map<number, {wireType: number, value: *}>} fields - Kết quả từ `decodeProtobufFields`.
 * @param {number} fieldNumber - Số thứ tự field.
 * @param {boolean} [required=false] - Ném lỗi nếu field không tồn tại.
 * @returns {Buffer|null} Giá trị field, hoặc null nếu không có và không bắt buộc.
 * @throws {Error} Khi field bắt buộc bị thiếu hoặc field không phải kiểu bytes.
 */
function getBytesField(fields, fieldNumber, required = false) {
    const field = fields.get(fieldNumber);
    if (!field) {
        if (required) {
            throw new Error(`Response is missing protobuf field ${fieldNumber}`);
        }
        return null;
    }

    if (field.wireType !== 2) {
        throw new Error(`Response protobuf field ${fieldNumber} is not bytes`);
    }

    return field.value;
}

/**
 * Giải mã body LoginPrepareReply: field 1 = khóa mã hóa, field 2 = dữ liệu đã mã hóa.
 *
 * @param {Buffer} bodyBytes - Body Protobuf.
 * @returns {{ encrypt_key?: string, data?: string }} Các giá trị dạng hex (chỉ có khi field tồn tại).
 */
function decodeLoginPrepareReply(bodyBytes) {
    const fields = decodeProtobufFields(bodyBytes);
    const decoded = {};

    if (fields.has(1)) {
        decoded.encrypt_key = getBytesField(fields, 1).toString('hex');
    }
    if (fields.has(2)) {
        decoded.data = getBytesField(fields, 2).toString('hex');
    }

    return decoded;
}

/**
 * Giải mã body LoginReply: field 1 = dữ liệu đã mã hóa.
 *
 * @param {Buffer} bodyBytes - Body Protobuf.
 * @returns {{ data?: string }} Dữ liệu dạng hex (chỉ có khi field tồn tại).
 */
function decodeLoginReply(bodyBytes) {
    const fields = decodeProtobufFields(bodyBytes);
    return fields.has(1) ? { data: getBytesField(fields, 1).toString('hex') } : {};
}

/**
 * Giải mã body SsoKeyGetReply: field 1 = SSO key.
 *
 * @param {Buffer} bodyBytes - Body Protobuf.
 * @returns {{ sso_key: string|null }} SSO key dạng chuỗi UTF-8 (hoặc hex), null nếu không có.
 */
function decodeSsoKeyGetReply(bodyBytes) {
    const fields = decodeProtobufFields(bodyBytes);
    const ssoKey = fields.has(1) ? decodeUtf8TextOrHexadecimal(getBytesField(fields, 1)) : null;

    return { sso_key: ssoKey };
}

/**
 * Giải mã phần dữ liệu đã mã hóa trong reply bằng XTEA tùy biến.
 *
 * @param {Buffer|string} encryptionKey - Khóa 16 byte (Buffer hoặc chuỗi hex).
 * @param {Buffer|string} ciphertext - Bản mã (Buffer hoặc chuỗi hex).
 * @returns {Buffer} Dữ liệu đã giải mã.
 */
function decryptResponseData(encryptionKey, ciphertext) {
    const keyBuffer = Buffer.isBuffer(encryptionKey) ? encryptionKey : Buffer.from(encryptionKey, 'hex');
    const ciphertextBuffer = Buffer.isBuffer(ciphertext) ? ciphertext : Buffer.from(ciphertext, 'hex');

    return new XteaCustom(keyBuffer).decrypt(ciphertextBuffer);
}

/**
 * Đọc dữ liệu LoginPrepareReply sau khi giải mã: field 1 = salt, field 2 = verify_code.
 *
 * @param {Buffer} plaintextData - Dữ liệu đã giải mã.
 * @returns {{ salt: string, verify_code: string }} Chuỗi rỗng nếu field không tồn tại.
 */
function decodeLoginPrepareReplyData(plaintextData) {
    const fields = decodeProtobufFields(plaintextData);
    const salt = getBytesField(fields, 1);
    const verifyCode = getBytesField(fields, 2);

    return {
        salt: salt ? decodeUtf8TextOrHexadecimal(salt) : '',
        verify_code: verifyCode ? decodeUtf8TextOrHexadecimal(verifyCode) : '',
    };
}

/**
 * Đọc dữ liệu LoginReply sau khi giải mã: field 1 = uid, field 2 = session key 16 byte.
 *
 * @param {Buffer} plaintextData - Dữ liệu đã giải mã.
 * @returns {{ uid?: number|string|null, session_key?: string }}
 *   uid là số (hoặc chuỗi nếu quá lớn / là bytes); session_key dạng hex.
 */
function decodeLoginReplyData(plaintextData) {
    const fields = decodeProtobufFields(plaintextData);
    const decoded = {};

    if (fields.has(1)) {
        const userIdentifier = fields.get(1);
        if (userIdentifier.wireType === 0) {
            decoded.uid = convertBigIntForJson(userIdentifier.value);
        } else if (userIdentifier.wireType === 2) {
            decoded.uid = decodeUtf8TextOrHexadecimal(userIdentifier.value);
        } else {
            decoded.uid = null;
        }
    }

    if (fields.has(2)) {
        decoded.session_key = getBytesField(fields, 2).toString('hex');
    }

    return decoded;
}

/**
 * Giải mã một frame TCP hoàn chỉnh và nhận diện loại message theo command_type/command.
 *
 * Loại message nhận diện được:
 *   - LoginPrepareReply: command_type 3, command 256
 *   - LoginReply:        command_type 3, command 257 hoặc 259
 *   - SsoKeyGetReply:    command_type 3 hoặc 4, command 274, 294 hoặc 442
 * Các trường hợp khác (hoặc body rỗng) trả về `UNKNOWN` với body rỗng.
 *
 * @param {Buffer} framedPacket - Frame gồm 4 byte độ dài + payload.
 * @param {Buffer|null} [encryptionKey] - Session key để giải mã packet dạng mã hóa toàn bộ.
 * @returns {{ header: object, message_type: string, body: object }} Kết quả giải mã.
 * @throws {Error} Khi frame quá ngắn, độ dài khai báo không khớp hoặc không phân tích được.
 */
function decodePacket(framedPacket, encryptionKey = null) {
    if (!Buffer.isBuffer(framedPacket) || framedPacket.length < 6) {
        throw new Error('TCP packet is too short');
    }

    const declaredPayloadLength = framedPacket.readUInt32LE(0);
    if (declaredPayloadLength !== framedPacket.length - 4) {
        throw new Error('TCP packet framing length mismatch');
    }

    const payloadBytes = framedPacket.subarray(4);
    const { header, bodyBytes } = parsePacketPayload(payloadBytes, encryptionKey);

    let messageType = 'UNKNOWN';
    let decodedBody = {};

    if (bodyBytes.length > 0) {
        const isLoginPrepareReply = header.command_type === 3 && header.command === 256;
        const isLoginReply = header.command_type === 3 && [257, 259].includes(header.command);
        const isSsoKeyGetReply = [3, 4].includes(header.command_type) && [274, 294, 442].includes(header.command);

        if (isLoginPrepareReply) {
            messageType = 'LoginPrepareReply';
            decodedBody = decodeLoginPrepareReply(bodyBytes);
        } else if (isLoginReply) {
            messageType = 'LoginReply';
            decodedBody = decodeLoginReply(bodyBytes);
        } else if (isSsoKeyGetReply) {
            messageType = 'SsoKeyGetReply';
            decodedBody = decodeSsoKeyGetReply(bodyBytes);
        }
    }

    return { header, message_type: messageType, body: decodedBody };
}

/**
 * Bọc kết quả `decodePacket` để đọc mã lỗi (field 5 `result` của header).
 */
class SystemResponse {
    /**
     * @param {{ header: object, body: object, message_type: string }} decodedPacket - Kết quả từ `decodePacket`.
     */
    constructor(decodedPacket) {
        this.header = decodedPacket.header;
        this.body = decodedPacket.body;
        this.messageType = decodedPacket.message_type;
        // Không có field `result` dạng số thì coi là lỗi -1.
        this.code = typeof this.header.result === 'number' ? this.header.result : -1;
        // Tên lỗi lấy từ bảng `system-errors.json` (ví dụ 105 -> ERROR_CAPTCHA).
        this.message = systemErrorCodes[this.code] || 'UNKNOWN_ERROR';
    }

    /**
     * @returns {boolean} true khi mã kết quả là 0 (SUCCESS).
     */
    isSuccess() {
        return this.code === 0;
    }
}

export {
    decodePacket,
    decodeLoginPrepareReply,
    decodeLoginReply,
    decodeSsoKeyGetReply,
    decodeLoginPrepareReplyData,
    decodeLoginReplyData,
    decryptResponseData,
    SystemResponse,
    systemErrorCodes,
};
