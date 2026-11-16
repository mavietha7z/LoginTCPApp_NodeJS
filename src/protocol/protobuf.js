/**
 * Bộ mã hóa/giải mã Protobuf tối giản, tự viết (không dùng file .proto).
 * Tương ứng `BaseProtobufDecoder` (dòng 18–95) và `ProtobufEncoder` (dòng 352–368) trong `LoginTCPApp.py`.
 *
 * Hỗ trợ các wire type: 0 = varint, 1 = fixed64, 2 = length-delimited (bytes), 5 = fixed32.
 */

/**
 * Tên của từng field trong header packet, đánh số theo field number của Protobuf.
 */
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

/**
 * Chuyển giá trị sang BigInt và kiểm tra nằm trong phạm vi số nguyên không dấu 64 bit.
 *
 * - `value` (number|bigint|string): Giá trị cần chuyển.
 * - Trả về (bigint): Giá trị dạng BigInt trong khoảng [0, 2^64 - 1].
 * - Ném lỗi RangeError: Khi giá trị âm hoặc vượt quá 64 bit.
 */
function toUnsignedBigInt(value) {
    const result = typeof value === 'bigint' ? value : BigInt(value);
    if (result < 0n || result > (1n << 64n) - 1n) {
        throw new RangeError('Giá trị varint Protobuf phải nằm trong khoảng số nguyên không dấu 64 bit');
    }
    return result;
}

/**
 * Mã hóa số nguyên không dấu thành varint Protobuf (mỗi byte chứa 7 bit, bit cao = còn byte tiếp).
 *
 * - `value` (number|bigint|string): Số nguyên không dấu tối đa 64 bit.
 * - Trả về (Buffer): Các byte varint.
 */
function encodeVarint(value) {
    let remaining = toUnsignedBigInt(value);
    const encodedBytes = [];

    do {
        let nextByte = Number(remaining & 0x7fn);
        remaining >>= 7n;
        if (remaining !== 0n) {
            /*
             * Bật bit 0x80 để báo vẫn còn byte phía sau.
             */
            nextByte |= 0x80;
        }
        encodedBytes.push(nextByte);
    } while (remaining !== 0n);

    return Buffer.from(encodedBytes);
}

/**
 * Đọc một varint từ buffer.
 *
 * - `buffer` (Buffer): Dữ liệu nguồn.
 * - `startOffset` (number): Vị trí bắt đầu đọc.
 * - Trả về ({ value: bigint, offset: number }): Giá trị đọc được và vị trí ngay sau varint.
 * - Ném lỗi Error: Khi hết dữ liệu giữa chừng hoặc varint vượt quá 64 bit.
 */
function decodeVarint(buffer, startOffset) {
    let value = 0n;
    let offset = startOffset;

    /*
     * Varint 64 bit dài tối đa 10 byte.
     */
    for (let index = 0; index < 10; index += 1) {
        if (offset >= buffer.length) {
            throw new Error('Unexpected end of protobuf varint');
        }

        const nextByte = buffer[offset];
        offset += 1;

        /*
         * Byte thứ 10 chỉ được phép mang 1 bit (bit thứ 64).
         */
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

/**
 * Mã hóa một field kiểu varint (wire type 0): [tag][giá trị varint].
 *
 * - `fieldNumber` (number): Số thứ tự field.
 * - `value` (number|bigint|string): Giá trị số nguyên không dấu.
 * - Trả về (Buffer): Byte của field.
 */
function encodeVarintField(fieldNumber, value) {
    const tag = encodeVarint((fieldNumber << 3) | 0);
    return Buffer.concat([tag, encodeVarint(value)]);
}

/**
 * Mã hóa một field kiểu bytes (wire type 2): [tag][độ dài varint][dữ liệu].
 *
 * - `fieldNumber` (number): Số thứ tự field.
 * - `value` (Buffer|string|Uint8Array): Dữ liệu; nếu không phải Buffer sẽ được chuyển bằng `Buffer.from`.
 * - Trả về (Buffer): Byte của field.
 */
function encodeBytesField(fieldNumber, value) {
    const valueBuffer = Buffer.isBuffer(value) ? value : Buffer.from(value);
    const tag = encodeVarint((fieldNumber << 3) | 2);
    const length = encodeVarint(valueBuffer.length);

    return Buffer.concat([tag, length, valueBuffer]);
}

/**
 * Giải mã toàn bộ các field của một message Protobuf.
 * Field trùng số thứ tự sẽ ghi đè giá trị trước (giống dict trong Python), không gom thành mảng.
 *
 * - `buffer` (Buffer): Message Protobuf.
 * - Trả về (Map<number, { wireType: number, value: bigint|Buffer }>):
 *   Map từ số field sang { wireType, value }; varint là BigInt, các kiểu còn lại là Buffer.
 * - Ném lỗi TypeError: Khi input không phải Buffer.
 * - Ném lỗi Error: Khi dữ liệu bị cắt cụt, field number không hợp lệ hoặc wire type không hỗ trợ.
 */
function decodeProtobufFields(buffer) {
    if (!Buffer.isBuffer(buffer)) {
        throw new TypeError('Dữ liệu Protobuf phải là Buffer');
    }

    const decodedFields = new Map();
    let offset = 0;

    while (offset < buffer.length) {
        /*
         * Tag = (fieldNumber << 3) | wireType.
         */
        const fieldHeader = decodeVarint(buffer, offset);
        offset = fieldHeader.offset;

        const fieldNumber = Number(fieldHeader.value >> 3n);
        const wireType = Number(fieldHeader.value & 7n);
        if (fieldNumber < 1 || !Number.isSafeInteger(fieldNumber)) {
            throw new Error('Số thứ tự field Protobuf không hợp lệ');
        }

        let value;
        if (wireType === 0) {
            /*
             * Varint.
             */
            const decoded = decodeVarint(buffer, offset);
            value = decoded.value;
            offset = decoded.offset;
        } else if (wireType === 1 || wireType === 5) {
            /*
             * fixed64 (8 byte) hoặc fixed32 (4 byte), giữ nguyên dạng byte.
             */
            const fixedWidth = wireType === 1 ? 8 : 4;
            if (offset + fixedWidth > buffer.length) {
                throw new Error('Field fixed-width Protobuf bị cắt cụt');
            }

            value = Buffer.from(buffer.subarray(offset, offset + fixedWidth));
            offset += fixedWidth;
        } else if (wireType === 2) {
            /*
             * Length-delimited: [độ dài varint][dữ liệu].
             */
            const decodedLength = decodeVarint(buffer, offset);
            const length = Number(decodedLength.value);
            offset = decodedLength.offset;

            const lengthIsValid = Number.isSafeInteger(length) && length >= 0 && length <= buffer.length - offset;
            if (!lengthIsValid) {
                throw new Error('Field Protobuf dạng length-delimited bị cắt cụt hoặc không hợp lệ');
            }

            value = Buffer.from(buffer.subarray(offset, offset + length));
            offset += length;
        } else {
            throw new Error(`Wire type Protobuf ${wireType} không được hỗ trợ cho field ${fieldNumber}`);
        }

        /*
         * Giống dict trong Python: tag lặp lại sẽ thay thế giá trị trước đó.
         */
        decodedFields.set(fieldNumber, { wireType, value });
    }

    return decodedFields;
}

/**
 * Chuyển BigInt sang kiểu an toàn cho JSON: Number nếu không vượt `Number.MAX_SAFE_INTEGER`,
 * ngược lại trả chuỗi thập phân để không mất độ chính xác.
 *
 * - `value` (bigint): Giá trị BigInt.
 * - Trả về (number|string): Giá trị dùng được trong JSON.
 */
function convertBigIntForJson(value) {
    return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString();
}

/**
 * Giải mã header packet thành object có tên field (xem `HEADER_FIELD_NAMES`).
 * Field lạ được đặt tên `unknown_field_<số>`; field bytes được biểu diễn dạng chuỗi hex.
 *
 * - `headerBytes` (Buffer): Byte header Protobuf.
 * - Trả về (Record<string, number|string>): Header đã giải mã.
 */
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

export { encodeVarint, decodeVarint, encodeVarintField, encodeBytesField, decodeProtobufFields, decodePacketHeader, convertBigIntForJson };
