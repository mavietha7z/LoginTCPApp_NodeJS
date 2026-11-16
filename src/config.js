'use strict';

function integerEnvironment(name, defaultValue, minimum, maximum) {
    const value = process.env[name] === undefined ? defaultValue : Number(process.env[name]);
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
        throw new Error(`Invalid ${name}: expected an integer between ${minimum} and ${maximum}`);
    }
    return value;
}

function loadConfig() {
    const apiKey = process.env.API_KEY;
    if (!apiKey || apiKey.length < 24) {
        throw new Error('Set a long API_KEY (at least 24 characters) in the environment');
    }
    const socksProxyUrl = process.env.SOCKS_PROXY_URL || null;
    if (socksProxyUrl && !/^socks5h?:\/\//i.test(socksProxyUrl)) {
        throw new Error('SOCKS_PROXY_URL must start with socks5:// or socks5h://');
    }
    return {
        apiKey,
        httpHost: process.env.HTTP_HOST || '127.0.0.1',
        httpPort: integerEnvironment('HTTP_PORT', 5000, 1, 65535),
        maxConcurrentLogins: integerEnvironment('MAX_CONCURRENT_LOGINS', 3, 1, 100),
        deviceIdentifier: process.env.DEVICE_ID || undefined,
        randomMode: process.env.XTEA_RANDOM_MODE || 'legacy',
        maxRetries: integerEnvironment('MAX_RETRIES', 3, 1, 3),
        responseWindowMs: integerEnvironment('RESPONSE_WINDOW_MS', 3000, 250, 30000),
        responseIdleTimeoutMs: integerEnvironment('RESPONSE_IDLE_TIMEOUT_MS', 500, 100, 5000),
        transportOptions: {
            serverHost: process.env.TCP_SERVER_HOST || '103.247.205.15',
            serverPort: integerEnvironment('TCP_SERVER_PORT', 19000, 1, 65535),
            proxyUrl: socksProxyUrl,
            connectTimeoutMs: integerEnvironment('CONNECT_TIMEOUT_MS', 8000, 100, 60000),
            readTimeoutMs: integerEnvironment('READ_TIMEOUT_MS', 5000, 100, 60000),
            maxPacketBytes: integerEnvironment('MAX_PACKET_BYTES', 1024 * 1024, 1024, 8 * 1024 * 1024),
        },
    };
}

module.exports = { loadConfig };
