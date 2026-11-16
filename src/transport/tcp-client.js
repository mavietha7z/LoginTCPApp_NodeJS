'use strict';

const net = require('node:net');
const dns = require('node:dns/promises');

class TimeoutError extends Error {
    constructor(message) {
        super(message);
        this.name = 'TimeoutError';
    }
}

class TcpClient {
    constructor(options = {}) {
        this.serverHost = options.serverHost || '103.247.205.15';
        this.serverPort = Number(options.serverPort || 19000);
        this.proxyUrl = options.proxyUrl || null;
        this.connectTimeoutMs = options.connectTimeoutMs ?? 8000;
        this.readTimeoutMs = options.readTimeoutMs ?? 5000;
        this.maxPacketBytes = options.maxPacketBytes ?? 1024 * 1024;
        this.maxBufferedBytes = options.maxBufferedBytes ?? 2 * this.maxPacketBytes;
        this.socket = null;
        this.incomingBuffer = Buffer.alloc(0);
        this.waitingRead = null;
        this.terminalError = null;
        this.pendingFrameHeader = null;
        this.frameReadInProgress = false;
    }

    attachSocket(socket) {
        this.socket = socket;
        socket.setNoDelay(true);
        socket.on('data', (chunk) => {
            this.incomingBuffer = Buffer.concat([this.incomingBuffer, chunk]);
            if (this.incomingBuffer.length > this.maxBufferedBytes) {
                socket.destroy(new Error('TCP receive buffer exceeded the allowed size'));
                return;
            }
            this.processWaitingRead();
        });
        socket.on('error', (error) => {
            this.handleTerminalError(error);
        });
        socket.on('close', () => {
            this.handleTerminalError(new Error('TCP connection closed'));
        });
        socket.on('end', () => {
            this.handleTerminalError(new Error('TCP connection ended'));
        });
    }

    handleTerminalError(error) {
        if (!this.terminalError) {
            this.terminalError = error;
        }
        if (this.waitingRead) {
            const waitingRead = this.waitingRead;
            this.waitingRead = null;
            clearTimeout(waitingRead.timeoutHandle);
            waitingRead.reject(this.terminalError);
        }
    }

    processWaitingRead() {
        if (!this.waitingRead || this.incomingBuffer.length < this.waitingRead.length) {
            return;
        }
        const waitingRead = this.waitingRead;
        this.waitingRead = null;
        clearTimeout(waitingRead.timeoutHandle);
        const bytes = Buffer.from(this.incomingBuffer.subarray(0, waitingRead.length));
        this.incomingBuffer = Buffer.from(this.incomingBuffer.subarray(waitingRead.length));
        waitingRead.resolve(bytes);
    }

    async readExactly(byteCount, timeoutMs = this.readTimeoutMs) {
        if (!Number.isSafeInteger(byteCount) || byteCount < 0 || byteCount > this.maxPacketBytes) {
            throw new Error('Invalid TCP read length');
        }
        if (byteCount === 0) {
            return Buffer.alloc(0);
        }
        if (this.incomingBuffer.length >= byteCount) {
            const data = Buffer.from(this.incomingBuffer.subarray(0, byteCount));
            this.incomingBuffer = Buffer.from(this.incomingBuffer.subarray(byteCount));
            return data;
        }
        if (this.terminalError) {
            throw this.terminalError;
        }
        if (this.waitingRead) {
            throw new Error('Concurrent TCP reads on the same connection are unsupported');
        }
        return new Promise((resolve, reject) => {
            const timeoutHandle = setTimeout(
                () => {
                    this.waitingRead = null;
                    reject(new TimeoutError('Timed out receiving TCP data'));
                },
                Math.max(timeoutMs, 1),
            );
            this.waitingRead = { length: byteCount, resolve, reject, timeoutHandle };
            this.processWaitingRead();
        });
    }

    async write(data) {
        if (!this.socket || this.terminalError) {
            throw this.terminalError || new Error('TCP connection not established');
        }
        return new Promise((resolve, reject) => {
            this.socket.write(data, (error) => (error ? reject(error) : resolve()));
        });
    }

    async connect() {
        if (this.socket) {
            throw new Error('TCP connection already exists');
        }
        let connectHost = this.serverHost;
        let connectPort = this.serverPort;
        let proxy = null;
        if (this.proxyUrl) {
            proxy = new URL(this.proxyUrl);
            if (!['socks5:', 'socks5h:'].includes(proxy.protocol)) {
                throw new Error('Only socks5:// and socks5h:// proxies are supported');
            }
            connectHost = proxy.hostname;
            connectPort = Number(proxy.port || 1080);
        }
        const socket = net.createConnection({ host: connectHost, port: connectPort });
        this.attachSocket(socket);
        await new Promise((resolve, reject) => {
            let settled = false;
            const timeoutHandle = setTimeout(() => finish(new TimeoutError('TCP connection timed out')), this.connectTimeoutMs);
            const finish = (error = null) => {
                if (settled) return;
                settled = true;
                clearTimeout(timeoutHandle);
                socket.off('connect', connected);
                socket.off('error', failed);
                if (error) {
                    socket.destroy();
                    reject(error);
                } else {
                    resolve();
                }
            };
            const connected = () => finish();
            const failed = (error) => finish(error);
            socket.once('connect', connected);
            socket.once('error', failed);
        });
        if (proxy) {
            try {
                await this.performSocks5Handshake(proxy);
            } catch (error) {
                this.close();
                throw error;
            }
        }
    }

    async performSocks5Handshake(proxy) {
        const username = decodeURIComponent(proxy.username);
        const password = decodeURIComponent(proxy.password);
        const hasCredentials = username.length > 0 || password.length > 0;
        const methods = hasCredentials ? Buffer.from([0x00, 0x02]) : Buffer.from([0x00]);
        await this.write(Buffer.concat([Buffer.from([0x05, methods.length]), methods]));
        const greetingReply = await this.readExactly(2, this.connectTimeoutMs);
        if (greetingReply[0] !== 0x05 || greetingReply[1] === 0xff) {
            throw new Error('SOCKS5 proxy did not accept authentication methods');
        }
        if (![0x00, 0x02].includes(greetingReply[1])) {
            throw new Error('Unsupported SOCKS5 authentication method');
        }
        if (greetingReply[1] === 0x02) {
            if (!hasCredentials) {
                throw new Error('SOCKS5 proxy requires username and password');
            }
            const usernameBytes = Buffer.from(username, 'utf8');
            const passwordBytes = Buffer.from(password, 'utf8');
            if (usernameBytes.length > 255 || passwordBytes.length > 255) {
                throw new Error('SOCKS5 credentials are too long');
            }
            await this.write(
                Buffer.concat([
                    Buffer.from([0x01, usernameBytes.length]),
                    usernameBytes,
                    Buffer.from([passwordBytes.length]),
                    passwordBytes,
                ]),
            );
            const authenticationReply = await this.readExactly(2, this.connectTimeoutMs);
            if (authenticationReply[0] !== 0x01 || authenticationReply[1] !== 0x00) {
                throw new Error('SOCKS5 authentication failed');
            }
        }

        let destinationHost = this.serverHost;
        if (proxy.protocol === 'socks5:' && net.isIP(destinationHost) === 0) {
            // socks5:// resolves the destination on the local computer; socks5h:// resolves remotely.
            destinationHost = (await dns.lookup(destinationHost)).address;
        }
        let addressBytes;
        let addressType;
        if (net.isIP(destinationHost) === 4) {
            addressType = 0x01;
            addressBytes = Buffer.from(destinationHost.split('.').map(Number));
        } else if (net.isIP(destinationHost) === 6) {
            // IPv6 addresses are passed as a domain name to avoid depending on a third-party package.
            // The Python file's fixed destination is IPv4, so its behavior is unaffected.
            addressType = 0x03;
            const domainBytes = Buffer.from(destinationHost, 'utf8');
            if (domainBytes.length > 255) throw new Error('SOCKS5 destination is too long');
            addressBytes = Buffer.concat([Buffer.from([domainBytes.length]), domainBytes]);
        } else {
            addressType = 0x03;
            const domainBytes = Buffer.from(destinationHost, 'utf8');
            if (domainBytes.length > 255) throw new Error('SOCKS5 destination is too long');
            addressBytes = Buffer.concat([Buffer.from([domainBytes.length]), domainBytes]);
        }
        const portBytes = Buffer.alloc(2);
        portBytes.writeUInt16BE(this.serverPort);
        await this.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, addressType]), addressBytes, portBytes]));
        const replyHeader = await this.readExactly(4, this.connectTimeoutMs);
        if (replyHeader[0] !== 0x05 || replyHeader[1] !== 0x00) {
            throw new Error(`SOCKS5 connect failed (reply ${replyHeader[1]})`);
        }
        if (replyHeader[3] === 0x01) {
            await this.readExactly(4 + 2, this.connectTimeoutMs);
        } else if (replyHeader[3] === 0x04) {
            await this.readExactly(16 + 2, this.connectTimeoutMs);
        } else if (replyHeader[3] === 0x03) {
            const domainLength = (await this.readExactly(1, this.connectTimeoutMs))[0];
            await this.readExactly(domainLength + 2, this.connectTimeoutMs);
        } else {
            throw new Error('SOCKS5 proxy returned an unknown address format');
        }
    }

    async readFrame(timeoutMs = this.readTimeoutMs) {
        if (this.frameReadInProgress) {
            throw new Error('Concurrent TCP frame reads are unsupported');
        }
        this.frameReadInProgress = true;
        const deadline = Date.now() + timeoutMs;
        const remainingTime = () => Math.max(1, deadline - Date.now());
        try {
            if (!this.pendingFrameHeader) {
                this.pendingFrameHeader = await this.readExactly(4, remainingTime());
            }
            const payloadLength = this.pendingFrameHeader.readUInt32LE(0);
            if (payloadLength < 2 || payloadLength > this.maxPacketBytes - 4) {
                throw new Error(`Invalid TCP payload length ${payloadLength}`);
            }
            const payload = await this.readExactly(payloadLength, remainingTime());
            const frame = Buffer.concat([this.pendingFrameHeader, payload]);
            this.pendingFrameHeader = null;
            return frame;
        } finally {
            this.frameReadInProgress = false;
        }
    }

    async sendMessage(message, timeoutMs = this.readTimeoutMs) {
        await this.write(message);
        return this.readFrame(timeoutMs);
    }

    close() {
        if (this.socket) {
            this.socket.destroy();
            this.socket = null;
        }
        this.handleTerminalError(new Error('TCP client closed'));
    }
}

module.exports = { TcpClient, TimeoutError };
