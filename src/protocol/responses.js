'use strict';

const systemErrorCodes = require('./system-errors.json');
const { decodeProtobufFields, convertBigIntForJson } = require('./protobuf');
const { parsePacketPayload } = require('./packets');
const { XteaCustom } = require('../crypto/xtea-custom');

const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

function textOrHex(inputBuffer) {
    try {
        return utf8Decoder.decode(inputBuffer);
    } catch {
        return inputBuffer.toString('hex');
    }
}

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

function decodeLoginPrepareReply(bodyBytes) {
    const fields = decodeProtobufFields(bodyBytes);
    return {
        ...(fields.has(1) ? { encrypt_key: getBytesField(fields, 1).toString('hex') } : {}),
        ...(fields.has(2) ? { data: getBytesField(fields, 2).toString('hex') } : {}),
    };
}

function decodeLoginReply(bodyBytes) {
    const fields = decodeProtobufFields(bodyBytes);
    return fields.has(1) ? { data: getBytesField(fields, 1).toString('hex') } : {};
}

function decodeSsoKeyGetReply(bodyBytes) {
    const fields = decodeProtobufFields(bodyBytes);
    return { sso_key: fields.has(1) ? textOrHex(getBytesField(fields, 1)) : null };
}

function decryptResponseData(encryptionKey, ciphertext) {
    const keyBuffer = Buffer.isBuffer(encryptionKey) ? encryptionKey : Buffer.from(encryptionKey, 'hex');
    const ciphertextBuffer = Buffer.isBuffer(ciphertext) ? ciphertext : Buffer.from(ciphertext, 'hex');
    return new XteaCustom(keyBuffer).decrypt(ciphertextBuffer);
}

function decodeLoginPrepareReplyData(plaintextData) {
    const fields = decodeProtobufFields(plaintextData);
    const salt = getBytesField(fields, 1);
    const verifyCode = getBytesField(fields, 2);
    return {
        salt: salt ? textOrHex(salt) : '',
        verify_code: verifyCode ? textOrHex(verifyCode) : '',
    };
}

function decodeLoginReplyData(plaintextData) {
    const fields = decodeProtobufFields(plaintextData);
    const decoded = {};
    if (fields.has(1)) {
        const userIdentifier = fields.get(1);
        decoded.uid =
            userIdentifier.wireType === 0
                ? convertBigIntForJson(userIdentifier.value)
                : userIdentifier.wireType === 2
                  ? textOrHex(userIdentifier.value)
                  : null;
    }
    if (fields.has(2)) {
        decoded.session_key = getBytesField(fields, 2).toString('hex');
    }
    return decoded;
}

function decodePacket(framedPacket, encryptionKey = null) {
    if (!Buffer.isBuffer(framedPacket) || framedPacket.length < 6) {
        throw new Error('TCP packet is too short');
    }
    const declaredPayloadLength = framedPacket.readUInt32LE(0);
    if (declaredPayloadLength !== framedPacket.length - 4) {
        throw new Error('TCP packet framing length mismatch');
    }
    const payloadBytes = framedPacket.subarray(4);
    const parsed = parsePacketPayload(payloadBytes, encryptionKey);
    const { header, bodyBytes } = parsed;
    let messageType = 'UNKNOWN';
    let decodedBody = {};
    if (bodyBytes.length > 0) {
        if (header.command_type === 3 && header.command === 256) {
            messageType = 'LoginPrepareReply';
            decodedBody = decodeLoginPrepareReply(bodyBytes);
        } else if (header.command_type === 3 && [257, 259].includes(header.command)) {
            messageType = 'LoginReply';
            decodedBody = decodeLoginReply(bodyBytes);
        } else if ([3, 4].includes(header.command_type) && [274, 294, 442].includes(header.command)) {
            messageType = 'SsoKeyGetReply';
            decodedBody = decodeSsoKeyGetReply(bodyBytes);
        }
    }
    return { header, message_type: messageType, body: decodedBody };
}

class SystemResponse {
    constructor(decodedPacket) {
        this.header = decodedPacket.header;
        this.body = decodedPacket.body;
        this.messageType = decodedPacket.message_type;
        this.code = typeof this.header.result === 'number' ? this.header.result : -1;
        this.message = systemErrorCodes[this.code] || 'UNKNOWN_ERROR';
    }

    isSuccess() {
        return this.code === 0;
    }
}

module.exports = {
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
