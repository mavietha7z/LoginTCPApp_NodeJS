'use strict';

const { createHash } = require('node:crypto');

function generateEncryptionKey(password, salt, verifyCode) {
    if (![password, salt, verifyCode].every((value) => typeof value === 'string')) {
        throw new TypeError('Password, salt and verify code must be strings');
    }
    const passwordDigest = createHash('md5').update(password, 'utf8').digest('hex');
    const saltedDigest = createHash('sha256')
        .update(passwordDigest + salt, 'utf8')
        .digest('hex');
    return createHash('sha256')
        .update(saltedDigest + verifyCode, 'utf8')
        .digest()
        .subarray(0, 16);
}

module.exports = { generateEncryptionKey };
