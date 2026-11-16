'use strict';

const { randomBytes } = require('node:crypto');

const BLOCK_SIZE = 8;
const UINT32_MASK = 0xffff_ffffn;
const ROUND_DELTA = 0x9e37_79b9;
const REVERSE_ROUND_DELTA = 0x61c8_8647;
const DECRYPT_INITIAL_SUM = 0xc6ef_3720;
const ROUND_COUNT = 32;

function addUnsigned32(first, second) {
    return (first + second) >>> 0;
}

function subtractUnsigned32(first, second) {
    return (first - second) >>> 0;
}

function nonlinearTerm(value) {
    return (value + (((value << 4) ^ (value >>> 5)) >>> 0)) >>> 0;
}

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

// This is intentionally the inverse of the Python custom XTEA, not Node's native AES/CBC.
function decryptBlock(firstWord, secondWord, keyWords) {
    let roundSum = DECRYPT_INITIAL_SUM;
    let left = firstWord >>> 0;
    let right = secondWord >>> 0;
    for (let round = 0; round < ROUND_COUNT; round += 1) {
        const firstIndex = ((roundSum >>> 9) & 0x0c) >>> 2;
        const firstKey = addUnsigned32(roundSum, keyWords[firstIndex]);
        right = subtractUnsigned32(right, (nonlinearTerm(left) ^ firstKey) >>> 0);
        const secondIndex = ((roundSum & 0xff) + 71) & 3;
        const secondKey = addUnsigned32(addUnsigned32(roundSum, keyWords[secondIndex]), REVERSE_ROUND_DELTA);
        left = subtractUnsigned32(left, (nonlinearTerm(right) ^ secondKey) >>> 0);
        roundSum = addUnsigned32(roundSum, REVERSE_ROUND_DELTA);
    }
    return [left, right];
}

class Lrand48 {
    constructor(seedSeconds) {
        this.state = ((BigInt(seedSeconds) & UINT32_MASK) << 16n) | 0x330en;
        this.modulusMask = (1n << 48n) - 1n;
    }

    next() {
        this.state = (this.state * 0x5deece66dn + 0x0bn) & this.modulusMask;
        return Number(this.state >> 17n);
    }
}

function createLegacyInitializationVector(seedSeconds = Math.floor(Date.now() / 1000)) {
    const generator = new Lrand48(seedSeconds);
    const initializationVector = Buffer.alloc(8);
    initializationVector.writeUInt32LE(generator.next(), 0);
    initializationVector.writeUInt32LE(generator.next(), 4);
    return initializationVector;
}

function addUnsigned64Pairs(firstLow, firstHigh, secondLow, secondHigh) {
    const first = (BigInt(firstHigh) << 32n) | BigInt(firstLow);
    const second = (BigInt(secondHigh) << 32n) | BigInt(secondLow);
    const sum = (first + second) & ((1n << 64n) - 1n);
    return [Number(sum & UINT32_MASK), Number((sum >> 32n) & UINT32_MASK)];
}

class XteaCustom {
    constructor(encryptionKey, options = {}) {
        if (!Buffer.isBuffer(encryptionKey) || encryptionKey.length !== 16) {
            throw new TypeError('XTEA encryption key must be a 16-byte Buffer');
        }
        this.keyWords = [0, 1, 2, 3].map((index) => encryptionKey.readUInt32LE(index * 4));
        this.randomMode = options.randomMode || 'legacy';
        if (!['legacy', 'cryptographic'].includes(this.randomMode)) {
            throw new Error('XTEA random mode must be legacy or cryptographic');
        }
    }

    encrypt(plaintext, providedInitializationVector) {
        if (!Buffer.isBuffer(plaintext)) {
            throw new TypeError('Plaintext must be a Buffer');
        }
        const initializationVector =
            providedInitializationVector || (this.randomMode === 'legacy' ? createLegacyInitializationVector() : randomBytes(8));
        if (!Buffer.isBuffer(initializationVector) || initializationVector.length !== BLOCK_SIZE) {
            throw new Error('Initialization vector must be exactly 8 bytes');
        }

        const fullBlockCount = Math.floor(plaintext.length / BLOCK_SIZE);
        const ciphertext = Buffer.alloc(fullBlockCount * BLOCK_SIZE + 24);
        const seedLeft = initializationVector.readUInt32LE(0);
        const seedRight = initializationVector.readUInt32LE(4);
        // The Python implementation ORs in the high bit of seedRight before encrypting the first block.
        let firstCipherRight = (seedLeft | (seedRight >>> 31)) >>> 0;
        let firstCipherLeft = seedRight;
        let [previousCipherLeft, previousCipherRight] = encryptBlock(firstCipherLeft, firstCipherRight, this.keyWords);
        ciphertext.writeUInt32LE(previousCipherLeft, 0);
        ciphertext.writeUInt32LE(previousCipherRight, 4);

        let rollingLow = seedRight;
        let rollingHigh = firstCipherRight;
        let outputOffset = BLOCK_SIZE;
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

        // The Python source crashes for plaintext.length < 8 because `leftover` is undefined;
        // choosing the actual tail fixes that bug without changing any valid >= 8-byte vector.
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

    decrypt(ciphertext) {
        if (!Buffer.isBuffer(ciphertext) || ciphertext.length < 24 || ciphertext.length % BLOCK_SIZE !== 0) {
            throw new Error('Encrypted XTEA payload must have at least 24 bytes and be divisible by 8');
        }
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
        // Final encrypted block is an integrity/check block in the original format.
        const paddedData = decryptedBlocks.subarray(0, ciphertext.length - 16);
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

module.exports = {
    XteaCustom,
    Lrand48,
    createLegacyInitializationVector,
};
