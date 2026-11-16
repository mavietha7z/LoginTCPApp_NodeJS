'use strict';

const { XteaCustom } = require('../crypto/xtea-custom');
const { decodePacketHeader } = require('./protobuf');

/**
 * Đóng gói (framing) packet TCP. Có hai dạng packet:
 *   - Dạng header rõ:     [u32 LE độ dài payload][u16 BE độ dài header][header Protobuf][body]
 *   - Dạng mã hóa toàn bộ: [u32 LE độ dài bản mã][XTEA([u16 BE độ dài header][header][body])]
 * Tương ứng `PacketSend` (dòng 98–118) và phần nhận diện packet trong `PacketReceiver` của Python.
 */

/**
 * Dựng packet dạng header rõ.
 *
 * @param {Buffer} headerBytes - Header Protobuf, tối đa 65535 byte.
 * @param {Buffer} [bodyBytes] - Body Protobuf; mặc định rỗng.
 * @returns {Buffer} Packet hoàn chỉnh, gồm cả 4 byte độ dài ở đầu.
 * @throws {Error} Khi header dài quá 65535 byte (không vừa trường u16).
 */
function buildPacket(headerBytes, bodyBytes = Buffer.alloc(0)) {
    if (headerBytes.length > 65535) {
        throw new Error('Packet header exceeds 65535 bytes');
    }

    // Độ dài payload = 2 byte độ dài header + header + body.
    const payloadLength = 2 + headerBytes.length + bodyBytes.length;
    const framingBytes = Buffer.alloc(4);
    framingBytes.writeUInt32LE(payloadLength);

    const headerLengthBytes = Buffer.alloc(2);
    headerLengthBytes.writeUInt16BE(headerBytes.length);

    return Buffer.concat([framingBytes, headerLengthBytes, headerBytes, bodyBytes]);
}

/**
 * Dựng packet dạng mã hóa toàn bộ: chỉ 4 byte độ dài để ở dạng rõ.
 *
 * @param {Buffer} plaintextPacket - Nội dung cần mã hóa: [u16 BE độ dài header][header][body].
 * @param {Buffer} encryptionKey - Khóa XTEA 16 byte (thường là session key).
 * @param {object} [encryptionOptions] - Tùy chọn cho `XteaCustom`, có thể kèm `initializationVector` cố định.
 * @returns {Buffer} Packet hoàn chỉnh.
 */
function buildFullyEncryptedPacket(plaintextPacket, encryptionKey, encryptionOptions) {
    const cipher = new XteaCustom(encryptionKey, encryptionOptions);
    const ciphertext = cipher.encrypt(plaintextPacket, encryptionOptions?.initializationVector);

    const framingBytes = Buffer.alloc(4);
    framingBytes.writeUInt32LE(ciphertext.length);

    return Buffer.concat([framingBytes, ciphertext]);
}

/**
 * Phân tích payload dạng header rõ (payload = phần sau 4 byte độ dài).
 *
 * @param {Buffer} payloadBytes - [u16 BE độ dài header][header][body].
 * @returns {{ header: object, bodyBytes: Buffer }} Header đã giải mã và phần body còn lại.
 * @throws {Error} Khi độ dài header sai hoặc header thiếu `command_type`/`command`.
 */
function parsePlainPayload(payloadBytes) {
    if (payloadBytes.length < 2) {
        throw new Error('Packet has no header length');
    }

    const headerLength = payloadBytes.readUInt16BE(0);
    if (headerLength < 1 || headerLength > payloadBytes.length - 2) {
        throw new Error('Invalid packet header length');
    }

    const headerBytes = payloadBytes.subarray(2, 2 + headerLength);
    const header = decodePacketHeader(headerBytes);
    if (!('command_type' in header) || !('command' in header)) {
        throw new Error('Missing packet command fields');
    }

    return { header, bodyBytes: payloadBytes.subarray(2 + headerLength) };
}

/**
 * Phân tích payload, hỗ trợ cả hai dạng packet.
 * Giao thức không có cờ phân biệt nên thử dạng header rõ trước; nếu thất bại và có khóa
 * thì giải mã XTEA rồi phân tích lại.
 *
 * @param {Buffer} payloadBytes - Payload (không gồm 4 byte độ dài).
 * @param {Buffer|null} [encryptionKey] - Khóa để giải mã khi payload là dạng mã hóa toàn bộ.
 * @returns {{ header: object, bodyBytes: Buffer }} Header và body.
 * @throws {Error} Khi không phân tích được ở cả hai dạng.
 */
function parsePacketPayload(payloadBytes, encryptionKey = null) {
    try {
        // Nếu phần đầu bản mã ngẫu nhiên trông giống một header ngắn, bước kiểm tra cấu trúc
        // Protobuf sẽ chặn không cho nhận nhầm là dạng rõ.
        return parsePlainPayload(payloadBytes);
    } catch (plainPacketError) {
        if (!encryptionKey) {
            throw plainPacketError;
        }

        const plaintextBytes = new XteaCustom(encryptionKey).decrypt(payloadBytes);
        return parsePlainPayload(plaintextBytes);
    }
}

module.exports = {
    buildPacket,
    buildFullyEncryptedPacket,
    parsePacketPayload,
};
