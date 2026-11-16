'use strict';

const { randomBytes, createHash } = require('node:crypto');
const { networkInterfaces } = require('node:os');
const { XteaCustom } = require('../crypto/xtea-custom');
const { encodeVarintField, encodeBytesField } = require('./protobuf');
const { buildPacket, buildFullyEncryptedPacket } = require('./packets');

function discoverDeviceIdentifier() {
    const configuredValue = process.env.DEVICE_ID;
    if (configuredValue) {
        if (!/^\d+$/.test(configuredValue)) {
            throw new Error('DEVICE_ID must contain only decimal digits');
        }
        return configuredValue;
    }
    const networkDevices = Object.values(networkInterfaces()).flat().filter(Boolean);
    const candidate = networkDevices.find((device) => !device.internal && device.mac && device.mac !== '00:00:00:00:00:00');
    if (!candidate) {
        throw new Error('Cannot determine DEVICE_ID; set DEVICE_ID from the original Python host');
    }
    return BigInt(`0x${candidate.mac.replace(/[:-]/g, '')}`).toString();
}

class BaseLoginRequest {
    constructor(options = {}) {
        this.deviceIdentifier = options.deviceIdentifier || discoverDeviceIdentifier();
        this.timestamp = options.timestamp ?? Math.floor(Date.now() / 1000);
        this.randomKey = options.randomKey || randomBytes(16);
        this.initializationVector = options.initializationVector;
        this.randomMode = options.randomMode || 'legacy';
    }

    buildHeader(command) {
        return Buffer.concat([
            encodeVarintField(1, 285212918),
            encodeVarintField(2, this.deviceIdentifier),
            encodeVarintField(3, 2),
            encodeVarintField(4, command),
            encodeVarintField(6, this.timestamp),
        ]);
    }

    encryptData(plaintext, encryptionKey = this.randomKey) {
        return new XteaCustom(encryptionKey, { randomMode: this.randomMode }).encrypt(plaintext, this.initializationVector);
    }

    buildEncryptedBody(encryptionKey, encryptedData) {
        return Buffer.concat([encodeBytesField(1, encryptionKey), encodeBytesField(2, encryptedData)]);
    }
}

class LoginPrepareRequest extends BaseLoginRequest {
    constructor(account, options = {}) {
        super(options);
        this.account = account;
        this.authenticationType = 0;
        this.accountType = /^[^@]+@[^@]+\.[^@]+/.test(account) ? 2 : 1;
        this.clientType = 4352;
        this.clientVersion = 246;
    }

    buildRequestData() {
        return Buffer.concat([
            encodeVarintField(1, this.authenticationType),
            encodeVarintField(2, this.accountType),
            encodeBytesField(3, Buffer.from(this.account, 'utf8')),
            encodeVarintField(4, this.clientType),
            encodeVarintField(5, this.clientVersion),
        ]);
    }

    buildFullPacket() {
        return buildPacket(this.buildHeader(256), this.buildEncryptedBody(this.randomKey, this.encryptData(this.buildRequestData())));
    }
}

class LoginRequestHandler extends BaseLoginRequest {
    constructor(password, encryptionKey, options = {}) {
        super(options);
        this.password = password;
        this.encryptionKey = Buffer.isBuffer(encryptionKey) ? encryptionKey : Buffer.from(encryptionKey, 'hex');
        this.loginMode = 0;
        this.userStatus = 4608;
    }

    buildRequestData() {
        const passwordHash = createHash('md5').update(this.password, 'utf8').digest('hex');
        return Buffer.concat([
            encodeBytesField(1, Buffer.from(passwordHash, 'utf8')),
            encodeVarintField(2, this.loginMode),
            encodeBytesField(3, encodeVarintField(2, this.userStatus)),
            encodeBytesField(4, Buffer.from(this.deviceIdentifier, 'utf8')),
        ]);
    }

    buildFullPacket() {
        const encryptedData = this.encryptData(this.buildRequestData(), this.encryptionKey);
        return buildPacket(this.buildHeader(257), encodeBytesField(1, encryptedData));
    }
}

class LoginTokenGetRequest extends BaseLoginRequest {
    constructor(sessionKey, options = {}) {
        super(options);
        this.sessionKey = Buffer.isBuffer(sessionKey) ? sessionKey : Buffer.from(sessionKey, 'hex');
    }

    buildRequestData() {
        return encodeVarintField(1, 1);
    }

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

class EmptyPacket extends BaseLoginRequest {
    constructor(sessionKey, command, options = {}) {
        super(options);
        this.sessionKey = Buffer.isBuffer(sessionKey) ? sessionKey : Buffer.from(sessionKey, 'hex');
        this.command = command;
    }

    buildFullPacket() {
        const header = this.buildHeader(this.command);
        const headerLength = Buffer.alloc(2);
        headerLength.writeUInt16BE(header.length);
        return buildFullyEncryptedPacket(Buffer.concat([headerLength, header]), this.sessionKey, {
            randomMode: this.randomMode,
            initializationVector: this.initializationVector,
        });
    }
}

module.exports = {
    discoverDeviceIdentifier,
    BaseLoginRequest,
    LoginPrepareRequest,
    LoginRequestHandler,
    LoginTokenGetRequest,
    EmptyPacket,
};
