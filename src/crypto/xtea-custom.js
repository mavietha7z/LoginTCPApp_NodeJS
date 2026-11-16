import { randomBytes } from 'node:crypto';

/**
 * Cài đặt XTEA tùy biến, chuyển nguyên từ lớp `XTEACBC` trong `LoginTCPApp.py` (dòng 136–349).
 *
 * LƯU Ý: đây KHÔNG phải XTEA-CBC chuẩn. Định dạng bản mã gồm:
 *   [block khởi tạo sinh từ IV][các block dữ liệu CBC][block padding][block checksum]
 * Mọi thay đổi ở file này đều phải giữ test đối chiếu với fixture Python
 * (`test/fixtures/python-vectors.json`) chạy đạt.
 */

/** Kích thước một block XTEA (byte). */
const BLOCK_SIZE = 8;
/** Mặt nạ giữ lại 32 bit thấp khi tính toán bằng BigInt. */
const UNSIGNED_32_BIT_MASK = 0xffff_ffffn;
/** Hằng số delta chuẩn của XTEA, cộng vào tổng sau mỗi vòng mã hóa. */
const ROUND_DELTA = 0x9e37_79b9;
/** Giá trị âm của ROUND_DELTA theo modulo 2^32 (Python gọi là c = 1640531527), dùng khi giải mã. */
const REVERSE_ROUND_DELTA = 0x61c8_8647;
/** Tổng khởi đầu khi giải mã = ROUND_DELTA * 32 (mod 2^32). */
const DECRYPT_INITIAL_SUM = 0xc6ef_3720;
/** Số vòng mã hóa XTEA. */
const ROUND_COUNT = 32;

/**
 * Cộng hai số nguyên không dấu 32 bit, bỏ phần tràn.
 *
 * @param {number} first - Số hạng thứ nhất.
 * @param {number} second - Số hạng thứ hai.
 * @returns {number} Tổng (first + second) mod 2^32.
 */
function addUnsigned32(first, second) {
    return (first + second) >>> 0;
}

/**
 * Trừ hai số nguyên không dấu 32 bit, bỏ phần tràn.
 *
 * @param {number} first - Số bị trừ.
 * @param {number} second - Số trừ.
 * @returns {number} Hiệu (first - second) mod 2^32.
 */
function subtractUnsigned32(first, second) {
    return (first - second) >>> 0;
}

/**
 * Thành phần phi tuyến của XTEA: value + ((value << 4) ^ (value >>> 5)).
 *
 * @param {number} value - Nửa block 32 bit.
 * @returns {number} Kết quả 32 bit không dấu.
 */
function nonlinearTerm(value) {
    return (value + (((value << 4) ^ (value >>> 5)) >>> 0)) >>> 0;
}

/**
 * Mã hóa một block 64 bit (hai word 32 bit) bằng XTEA 32 vòng.
 *
 * @param {number} firstWord - Word trái (32 bit đầu của block).
 * @param {number} secondWord - Word phải (32 bit sau của block).
 * @param {number[]} keyWords - Khóa 128 bit tách thành 4 word 32 bit little-endian.
 * @returns {[number, number]} Cặp word [trái, phải] sau khi mã hóa.
 */
function encryptBlock(firstWord, secondWord, keyWords) {
    let roundSum = 0;
    let left = firstWord >>> 0;
    let right = secondWord >>> 0;

    for (let round = 0; round < ROUND_COUNT; round += 1) {
        const firstKey = addUnsigned32(roundSum, keyWords[roundSum & 3]);
        left = addUnsigned32(left, (nonlinearTerm(right) ^ firstKey) >>> 0);

        roundSum = addUnsigned32(roundSum, ROUND_DELTA);

        const secondKey = addUnsigned32(roundSum, keyWords[(roundSum >>> 11) & 3]);
        right = addUnsigned32(right, (nonlinearTerm(left) ^ secondKey) >>> 0);
    }

    return [left, right];
}

/**
 * Giải mã một block 64 bit. Đây là phép nghịch đảo đúng theo cách viết của Python gốc
 * (`_xtea_decrypt_block_custom`), không phải AES/CBC có sẵn của Node.
 *
 * @param {number} firstWord - Word trái của block bản mã.
 * @param {number} secondWord - Word phải của block bản mã.
 * @param {number[]} keyWords - Khóa 128 bit tách thành 4 word 32 bit little-endian.
 * @returns {[number, number]} Cặp word [trái, phải] sau khi giải mã.
 */
function decryptBlock(firstWord, secondWord, keyWords) {
    let roundSum = DECRYPT_INITIAL_SUM;
    let left = firstWord >>> 0;
    let right = secondWord >>> 0;

    for (let round = 0; round < ROUND_COUNT; round += 1) {
        // Chỉ số khóa tính theo công thức của Python, tương đương (roundSum >>> 11) & 3.
        const firstIndex = ((roundSum >>> 9) & 0x0c) >>> 2;
        const firstKey = addUnsigned32(roundSum, keyWords[firstIndex]);
        right = subtractUnsigned32(right, (nonlinearTerm(left) ^ firstKey) >>> 0);

        // Chỉ số khóa thứ hai: ((roundSum & 0xff) + 71) & 3, giữ nguyên như Python.
        const secondIndex = ((roundSum & 0xff) + 71) & 3;
        const secondKey = addUnsigned32(addUnsigned32(roundSum, keyWords[secondIndex]), REVERSE_ROUND_DELTA);
        left = subtractUnsigned32(left, (nonlinearTerm(right) ^ secondKey) >>> 0);

        roundSum = addUnsigned32(roundSum, REVERSE_ROUND_DELTA);
    }

    return [left, right];
}

/**
 * Bộ sinh số giả ngẫu nhiên 48 bit theo hàm POSIX `lrand48`
 * (tương ứng lớp `Lrand48` trong Python, dòng 124–133).
 *
 * Seed là số giây hiện tại nên kết quả đoán trước được; chỉ dùng để tương thích với Python.
 */
class Lrand48 {
    /**
     * @param {number} seedSeconds - Seed (thường là Unix timestamp tính bằng giây).
     */
    constructor(seedSeconds) {
        // Trạng thái 48 bit: 32 bit seed dịch trái 16 bit, OR với hằng số 0x330E như srand48.
        this.state = ((BigInt(seedSeconds) & UNSIGNED_32_BIT_MASK) << 16n) | 0x330en;
        // Mặt nạ giữ lại 48 bit (modulo 2^48).
        this.modulusMask = (1n << 48n) - 1n;
    }

    /**
     * Sinh số tiếp theo theo công thức tuyến tính đồng dư: state = state * 0x5DEECE66D + 0xB (mod 2^48).
     *
     * @returns {number} Số nguyên không âm 31 bit.
     */
    next() {
        this.state = (this.state * 0x5deece66dn + 0x0bn) & this.modulusMask;
        return Number(this.state >> 17n);
    }
}

/**
 * Tạo IV 8 byte theo cách của Python: hai số lrand48 liên tiếp, ghi little-endian.
 *
 * @param {number} [seedSeconds] - Seed tính bằng giây; mặc định là thời điểm hiện tại.
 * @returns {Buffer} IV dài 8 byte.
 */
function createLegacyInitializationVector(seedSeconds = Math.floor(Date.now() / 1000)) {
    const generator = new Lrand48(seedSeconds);
    const initializationVector = Buffer.alloc(8);

    initializationVector.writeUInt32LE(generator.next(), 0);
    initializationVector.writeUInt32LE(generator.next(), 4);

    return initializationVector;
}

/**
 * Cộng hai số 64 bit, mỗi số được biểu diễn bằng cặp (word thấp, word cao) 32 bit.
 *
 * @param {number} firstLow - Word thấp của số thứ nhất.
 * @param {number} firstHigh - Word cao của số thứ nhất.
 * @param {number} secondLow - Word thấp của số thứ hai.
 * @param {number} secondHigh - Word cao của số thứ hai.
 * @returns {[number, number]} Tổng mod 2^64 dưới dạng [word thấp, word cao].
 */
function addUnsigned64Pairs(firstLow, firstHigh, secondLow, secondHigh) {
    const first = (BigInt(firstHigh) << 32n) | BigInt(firstLow);
    const second = (BigInt(secondHigh) << 32n) | BigInt(secondLow);
    const sum = (first + second) & ((1n << 64n) - 1n);

    return [Number(sum & UNSIGNED_32_BIT_MASK), Number((sum >> 32n) & UNSIGNED_32_BIT_MASK)];
}

/**
 * Bộ mã hóa/giải mã XTEA tùy biến theo định dạng của Python.
 */
class XteaCustom {
    /**
     * @param {Buffer} encryptionKey - Khóa đúng 16 byte.
     * @param {object} [options]
     * @param {'legacy'|'cryptographic'} [options.randomMode='legacy'] - Cách sinh IV khi không truyền IV:
     *   `legacy` dùng Lrand48 giống Python; `cryptographic` dùng `crypto.randomBytes`.
     * @throws {TypeError} Khi khóa không phải Buffer 16 byte.
     * @throws {Error} Khi randomMode không hợp lệ.
     */
    constructor(encryptionKey, options = {}) {
        if (!Buffer.isBuffer(encryptionKey) || encryptionKey.length !== 16) {
            throw new TypeError('XTEA encryption key must be a 16-byte Buffer');
        }

        // Tách khóa 16 byte thành 4 word 32 bit little-endian.
        this.keyWords = [0, 1, 2, 3].map((index) => encryptionKey.readUInt32LE(index * 4));

        this.randomMode = options.randomMode || 'legacy';
        if (!['legacy', 'cryptographic'].includes(this.randomMode)) {
            throw new Error('XTEA random mode must be legacy or cryptographic');
        }
    }

    /**
     * Mã hóa dữ liệu theo định dạng của Python.
     * Độ dài bản mã = (số block đầy đủ * 8) + 24 byte (block khởi tạo + block padding + block checksum).
     *
     * @param {Buffer} plaintext - Dữ liệu cần mã hóa.
     * @param {Buffer} [providedInitializationVector] - IV 8 byte cố định (dùng cho test); bỏ trống để tự sinh.
     * @returns {Buffer} Bản mã.
     * @throws {TypeError} Khi plaintext không phải Buffer.
     * @throws {Error} Khi IV không dài đúng 8 byte.
     */
    encrypt(plaintext, providedInitializationVector) {
        if (!Buffer.isBuffer(plaintext)) {
            throw new TypeError('Plaintext must be a Buffer');
        }

        // Chọn IV: ưu tiên IV truyền vào, nếu không thì sinh theo randomMode.
        let initializationVector = providedInitializationVector;
        if (!initializationVector) {
            const usesLegacyRandom = this.randomMode === 'legacy';
            initializationVector = usesLegacyRandom ? createLegacyInitializationVector() : randomBytes(8);
        }
        if (!Buffer.isBuffer(initializationVector) || initializationVector.length !== BLOCK_SIZE) {
            throw new Error('Initialization vector must be exactly 8 bytes');
        }

        const fullBlockCount = Math.floor(plaintext.length / BLOCK_SIZE);
        const ciphertext = Buffer.alloc(fullBlockCount * BLOCK_SIZE + 24);

        // Block khởi tạo: sinh từ IV theo cách riêng của Python.
        const seedLeft = initializationVector.readUInt32LE(0);
        const seedRight = initializationVector.readUInt32LE(4);
        // Python OR bit cao nhất của seedRight vào seedLeft trước khi mã hóa block đầu.
        const firstCipherRight = (seedLeft | (seedRight >>> 31)) >>> 0;
        const firstCipherLeft = seedRight;
        let [previousCipherLeft, previousCipherRight] = encryptBlock(firstCipherLeft, firstCipherRight, this.keyWords);
        ciphertext.writeUInt32LE(previousCipherLeft, 0);
        ciphertext.writeUInt32LE(previousCipherRight, 4);

        // Tổng cộng dồn 64 bit của plaintext, dùng để tạo block checksum cuối.
        let rollingLow = seedRight;
        let rollingHigh = firstCipherRight;
        let outputOffset = BLOCK_SIZE;

        // Mã hóa các block đầy đủ theo kiểu CBC: XOR với block bản mã trước rồi mã hóa.
        for (let blockIndex = 0; blockIndex < fullBlockCount; blockIndex += 1) {
            const inputOffset = blockIndex * BLOCK_SIZE;
            const plaintextLeft = plaintext.readUInt32LE(inputOffset);
            const plaintextRight = plaintext.readUInt32LE(inputOffset + 4);

            [rollingLow, rollingHigh] = addUnsigned64Pairs(rollingLow, rollingHigh, plaintextLeft, plaintextRight);

            const blockLeft = (plaintextLeft ^ previousCipherLeft) >>> 0;
            const blockRight = (plaintextRight ^ previousCipherRight) >>> 0;
            [previousCipherLeft, previousCipherRight] = encryptBlock(blockLeft, blockRight, this.keyWords);

            ciphertext.writeUInt32LE(previousCipherLeft, outputOffset);
            ciphertext.writeUInt32LE(previousCipherRight, outputOffset + 4);
            outputOffset += BLOCK_SIZE;
        }

        // Block padding kiểu PKCS#7: phần dư của plaintext, điền byte có giá trị = số byte thiếu.
        // Python gốc bị lỗi với plaintext < 8 byte (biến `leftover` chưa được gán);
        // lấy đúng phần đuôi thực tế sẽ sửa lỗi đó mà không đổi kết quả với input >= 8 byte.
        const remainder = plaintext.length % BLOCK_SIZE;
        const paddedBlock = Buffer.alloc(BLOCK_SIZE, BLOCK_SIZE - remainder);
        plaintext.copy(paddedBlock, 0, fullBlockCount * BLOCK_SIZE);

        const paddedLeft = paddedBlock.readUInt32LE(0);
        const paddedRight = paddedBlock.readUInt32LE(4);
        const [paddedCipherLeft, paddedCipherRight] = encryptBlock(
            (paddedLeft ^ previousCipherLeft) >>> 0,
            (paddedRight ^ previousCipherRight) >>> 0,
            this.keyWords,
        );
        ciphertext.writeUInt32LE(paddedCipherLeft, outputOffset);
        ciphertext.writeUInt32LE(paddedCipherRight, outputOffset + 4);
        outputOffset += BLOCK_SIZE;

        // Block checksum: cộng thêm block padding vào tổng, XOR với block padding đã mã hóa rồi mã hóa.
        const [checksumLow, checksumHigh] = addUnsigned64Pairs(rollingLow, rollingHigh, paddedLeft, paddedRight);
        const [checksumCipherLeft, checksumCipherRight] = encryptBlock(
            (paddedCipherLeft ^ checksumLow) >>> 0,
            (paddedCipherRight ^ checksumHigh) >>> 0,
            this.keyWords,
        );
        ciphertext.writeUInt32LE(checksumCipherLeft, outputOffset);
        ciphertext.writeUInt32LE(checksumCipherRight, outputOffset + 4);

        return ciphertext;
    }

    /**
     * Giải mã bản mã theo định dạng của Python và bỏ padding.
     * Block checksum cuối bị bỏ qua, KHÔNG được kiểm tra (giống Python gốc).
     *
     * @param {Buffer} ciphertext - Bản mã, tối thiểu 24 byte và chia hết cho 8.
     * @returns {Buffer} Dữ liệu gốc đã bỏ padding.
     * @throws {Error} Khi độ dài bản mã hoặc padding không hợp lệ.
     */
    decrypt(ciphertext) {
        const hasValidLength = Buffer.isBuffer(ciphertext) && ciphertext.length >= 24 && ciphertext.length % BLOCK_SIZE === 0;
        if (!hasValidLength) {
            throw new Error('Encrypted XTEA payload must have at least 24 bytes and be divisible by 8');
        }

        // Giải mã CBC: mỗi block giải mã rồi XOR với block bản mã đứng trước (bỏ qua block khởi tạo).
        const decryptedBlocks = Buffer.alloc(ciphertext.length - BLOCK_SIZE);
        let previousCipherLeft = ciphertext.readUInt32LE(0);
        let previousCipherRight = ciphertext.readUInt32LE(4);

        for (let inputOffset = BLOCK_SIZE; inputOffset < ciphertext.length; inputOffset += BLOCK_SIZE) {
            const cipherLeft = ciphertext.readUInt32LE(inputOffset);
            const cipherRight = ciphertext.readUInt32LE(inputOffset + 4);
            const [decryptedLeft, decryptedRight] = decryptBlock(cipherLeft, cipherRight, this.keyWords);

            const outputOffset = inputOffset - BLOCK_SIZE;
            decryptedBlocks.writeUInt32LE((decryptedLeft ^ previousCipherLeft) >>> 0, outputOffset);
            decryptedBlocks.writeUInt32LE((decryptedRight ^ previousCipherRight) >>> 0, outputOffset + 4);

            previousCipherLeft = cipherLeft;
            previousCipherRight = cipherRight;
        }

        // Bỏ block checksum cuối (8 byte) — định dạng gốc dùng nó để kiểm tra, nhưng Python không kiểm tra.
        const paddedData = decryptedBlocks.subarray(0, ciphertext.length - 16);

        // Kiểm tra và bỏ padding kiểu PKCS#7.
        const paddingLength = paddedData[paddedData.length - 1];
        if (paddingLength < 1 || paddingLength > BLOCK_SIZE) {
            throw new Error('Invalid XTEA padding length');
        }
        for (let index = paddedData.length - paddingLength; index < paddedData.length; index += 1) {
            if (paddedData[index] !== paddingLength) {
                throw new Error('Invalid XTEA padding');
            }
        }

        return Buffer.from(paddedData.subarray(0, paddedData.length - paddingLength));
    }
}

export {
    XteaCustom,
    Lrand48,
    createLegacyInitializationVector,
};
