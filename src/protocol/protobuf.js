'use strict';

const HEADER_FIELD_NAMES = Object.freeze({
    1: 'version',
    2: 'id',
    3: 'command_type',
    4: 'command',
    5: 'result',
    6: 'timestamp',
    7: 'fragment_number',
    8: 'fragment_index',
});

function asUnsignedBigInt(value) {
    const result = typeof value === 'bigint' ? value : BigInt(value);
    if (result < 0n || result > (1n << 64n) - 1n) {
        throw new RangeError('Protobuf varint must fit an unsigned 64-bit integer');
    }
    return result;
}

function encodeVarint(value) {
    let remaining = asUnsignedBigInt(value);
    const encodedBytes = [];
    do {
        let nextByte = Number(remaining & 0x7fn);
        remaining >>= 7n;
        if (remaining !== 0n) {
            nextByte |= 0x80;
        }
        encodedBytes.push(nextByte);
    } while (remaining !== 0n);
    return Buffer.from(encodedBytes);
}

function decodeVarint(buffer, startOffset) {
    let value = 0n;
    let offset = startOffset;
    for (let index = 0; index < 10; index += 1) {
        if (offset >= buffer.length) {
            throw new Error('Unexpected end of protobuf varint');
        }
        const nextByte = buffer[offset];
        offset += 1;
        if (index === 9 && nextByte > 1) {
            throw new Error('Protobuf varint exceeds 64-bit range');
        }
        value |= BigInt(nextByte & 0x7f) << BigInt(7 * index);
        if ((nextByte & 0x80) === 0) {
            return { value, offset };
        }
    }
    throw new Error('Protobuf varint is too long');
}

function encodeVarintField(fieldNumber, value) {
    return Buffer.concat([encodeVarint((fieldNumber << 3) | 0), encodeVarint(value)]);
}

function encodeBytesField(fieldNumber, value) {
    const valueBuffer = Buffer.isBuffer(value) ? value : Buffer.from(value);
    return Buffer.concat([encodeVarint((fieldNumber << 3) | 2), encodeVarint(valueBuffer.length), valueBuffer]);
}

function decodeProtobufFields(buffer) {
    if (!Buffer.isBuffer(buffer)) {
        throw new TypeError('Protobuf input must be a Buffer');
    }
    const decodedFields = new Map();
    let offset = 0;
    while (offset < buffer.length) {
        const fieldHeader = decodeVarint(buffer, offset);
        offset = fieldHeader.offset;
        const fieldNumber = Number(fieldHeader.value >> 3n);
        const wireType = Number(fieldHeader.value & 7n);
        if (fieldNumber < 1 || !Number.isSafeInteger(fieldNumber)) {
            throw new Error('Invalid protobuf field number');
        }
        let value;
        if (wireType === 0) {
            const decoded = decodeVarint(buffer, offset);
            value = decoded.value;
            offset = decoded.offset;
        } else if (wireType === 1 || wireType === 5) {
            const fixedWidth = wireType === 1 ? 8 : 4;
            if (offset + fixedWidth > buffer.length) {
                throw new Error('Truncated protobuf fixed-width field');
            }
            value = Buffer.from(buffer.subarray(offset, offset + fixedWidth));
            offset += fixedWidth;
        } else if (wireType === 2) {
            const decodedLength = decodeVarint(buffer, offset);
            const length = Number(decodedLength.value);
            offset = decodedLength.offset;
            if (!Number.isSafeInteger(length) || length < 0 || length > buffer.length - offset) {
                throw new Error('Truncated or invalid protobuf length-delimited field');
            }
            value = Buffer.from(buffer.subarray(offset, offset + length));
            offset += length;
        } else {
            throw new Error(`Unsupported protobuf wire type ${wireType} for field ${fieldNumber}`);
        }
        // Mirrors the Python dictionary: repeated tag values replace earlier values.
        decodedFields.set(fieldNumber, { wireType, value });
    }
    return decodedFields;
}

function convertBigIntForJson(value) {
    return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString();
}

function decodePacketHeader(headerBytes) {
    const fields = decodeProtobufFields(headerBytes);
    const header = {};
    for (const [fieldNumber, field] of fields) {
        const fieldName = HEADER_FIELD_NAMES[fieldNumber] || `unknown_field_${fieldNumber}`;
        if (field.wireType === 0) {
            header[fieldName] = convertBigIntForJson(field.value);
        } else if (field.wireType === 1) {
            header[fieldName] = convertBigIntForJson(field.value.readBigUInt64LE(0));
        } else if (field.wireType === 5) {
            header[fieldName] = field.value.readUInt32LE(0);
        } else {
            header[fieldName] = field.value.toString('hex');
        }
    }
    return header;
}

module.exports = {
    encodeVarint,
    decodeVarint,
    encodeVarintField,
    encodeBytesField,
    decodeProtobufFields,
    decodePacketHeader,
    convertBigIntForJson,
};
