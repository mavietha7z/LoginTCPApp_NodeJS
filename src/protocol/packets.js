'use strict';

const { decodePacketHeader } = require('./protobuf');
const { XteaCustom } = require('../crypto/xtea-custom');

function buildPacket(headerBytes, bodyBytes = Buffer.alloc(0)) {
    if (headerBytes.length > 65535) {
        throw new Error('Packet header exceeds 65535 bytes');
    }
    const payloadLength = 2 + headerBytes.length + bodyBytes.length;
    const framingBytes = Buffer.alloc(4);
    framingBytes.writeUInt32LE(payloadLength);
    const headerLengthBytes = Buffer.alloc(2);
    headerLengthBytes.writeUInt16BE(headerBytes.length);
    return Buffer.concat([framingBytes, headerLengthBytes, headerBytes, bodyBytes]);
}

function buildFullyEncryptedPacket(plaintextPacket, encryptionKey, encryptionOptions) {
    const ciphertext = new XteaCustom(encryptionKey, encryptionOptions).encrypt(plaintextPacket, encryptionOptions?.initializationVector);
    const framingBytes = Buffer.alloc(4);
    framingBytes.writeUInt32LE(ciphertext.length);
    return Buffer.concat([framingBytes, ciphertext]);
}

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

// Support both plaintext-header packets and packets with a fully encrypted payload.
function parsePacketPayload(payloadBytes, encryptionKey = null) {
    try {
        // If a random encrypted prefix happens to look like a short header, protobuf
        // structural validation prevents it from being accepted as plaintext.
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
