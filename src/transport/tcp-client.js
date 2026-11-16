import net from 'node:net';
import dns from 'node:dns/promises';

/**
 * Lớp kết nối TCP tới máy chủ đăng nhập, có hỗ trợ SOCKS5/SOCKS5h.
 * Tương ứng `TcpClient` trong `LoginTCPApp.py` (dòng 772–834), đã sửa các lỗi của bản gốc:
 * đọc thiếu byte, không có timeout, không giới hạn kích thước packet.
 */

/**
 * Cổng máy chủ mặc định lấy từ Python gốc.
 */
const DEFAULT_SERVER_PORT = 19000;

/**
 * Địa chỉ máy chủ mặc định lấy từ Python gốc (chưa xác minh còn hoạt động).
 */
const DEFAULT_SERVER_HOST = '103.247.205.15';

/**
 * Byte phiên bản giao thức SOCKS5.
 */
const SOCKS_VERSION = 0x05;

/**
 * Cổng SOCKS mặc định khi URL proxy không ghi cổng.
 */
const DEFAULT_SOCKS_PORT = 1080;

/**
 * Lệnh SOCKS5 CONNECT.
 */
const SOCKS_COMMAND_CONNECT = 0x01;

/**
 * Kiểu địa chỉ SOCKS5: IPv4.
 */
const SOCKS_ADDRESS_TYPE_IPV4 = 0x01;

/**
 * Kiểu địa chỉ SOCKS5: IPv6.
 */
const SOCKS_ADDRESS_TYPE_IPV6 = 0x04;

/**
 * Kiểu địa chỉ SOCKS5: tên miền.
 */
const SOCKS_ADDRESS_TYPE_DOMAIN = 0x03;

/**
 * Máy chủ SOCKS5 từ chối mọi phương thức xác thực được đề nghị.
 */
const SOCKS_METHOD_NOT_ACCEPTABLE = 0xff;

/**
 * Phương thức xác thực SOCKS5: username/password (RFC 1929).
 */
const SOCKS_METHOD_USERNAME_PASSWORD = 0x02;

/**
 * Phương thức xác thực SOCKS5: không cần xác thực.
 */
const SOCKS_METHOD_NO_AUTHENTICATION = 0x00;

/**
 * Lỗi riêng cho trường hợp hết thời gian chờ, giúp phân biệt với lỗi kết nối khác.
 */
class TimeoutError extends Error {
    /**
     * - `message` (string): Nội dung lỗi.
     */
    constructor(message) {
        super(message);
        this.name = 'TimeoutError';
    }
}

/**
 * Client TCP đọc dữ liệu theo frame [u32 LE độ dài][payload].
 * Dữ liệu nhận được gom vào buffer nội bộ để đọc đúng số byte, không phụ thuộc cách TCP chia gói.
 * Không hỗ trợ nhiều lệnh đọc đồng thời trên cùng một kết nối.
 */
class TcpClient {
    /**
     * - `options` (object, không bắt buộc): Các tùy chọn sau:
     *   - `options.serverHost` (string, không bắt buộc): Địa chỉ máy chủ đích.
     *   - `options.serverPort` (number, không bắt buộc): Cổng máy chủ đích.
     *   - `options.proxyUrl` (string|null, không bắt buộc): URL proxy dạng `socks5://` hoặc `socks5h://`, có thể kèm user:pass.
     *   - `options.connectTimeoutMilliseconds` (number, mặc định 8000): Thời gian chờ kết nối và bắt tay SOCKS.
     *   - `options.readTimeoutMilliseconds` (number, mặc định 5000): Thời gian chờ mặc định khi đọc một frame.
     *   - `options.maximumPacketBytes` (number, mặc định 1048576): Kích thước tối đa một frame (gồm 4 byte độ dài).
     *   - `options.maximumBufferedBytes` (number, không bắt buộc): Dung lượng tối đa của buffer nhận; mặc định gấp đôi maximumPacketBytes.
     */
    constructor(options = {}) {
        this.proxyUrl = options.proxyUrl || null;
        this.serverHost = options.serverHost || DEFAULT_SERVER_HOST;
        this.maximumPacketBytes = options.maximumPacketBytes ?? 1024 * 1024;
        this.serverPort = Number(options.serverPort || DEFAULT_SERVER_PORT);
        this.readTimeoutMilliseconds = options.readTimeoutMilliseconds ?? 5000;
        this.connectTimeoutMilliseconds = options.connectTimeoutMilliseconds ?? 8000;
        this.maximumBufferedBytes = options.maximumBufferedBytes ?? 2 * this.maximumPacketBytes;

        /**
         * Socket đang dùng, null khi chưa kết nối hoặc đã đóng.
         */
        this.socket = null;

        /**
         * Lệnh đọc đang chờ đủ dữ liệu: { length, resolve, reject, timeoutHandle } hoặc null.
         */
        this.waitingRead = null;

        /**
         * Lỗi khiến kết nối kết thúc; khi đã có thì mọi lệnh đọc/ghi sau đều thất bại.
         */
        this.terminalError = null;

        /**
         * 4 byte độ dài của frame đã đọc nhưng chưa đọc xong payload (giữ lại khi bị timeout giữa chừng).
         */
        this.pendingFrameHeader = null;

        /**
         * Cờ chống gọi `readFrame` đồng thời.
         */
        this.frameReadInProgress = false;

        /**
         * Dữ liệu đã nhận nhưng chưa được đọc.
         */
        this.incomingBuffer = Buffer.alloc(0);
    }

    /**
     * Gắn các bộ xử lý sự kiện cho socket.
     *
     * - `socket` (net.Socket): Socket vừa tạo.
     */
    attachSocket(socket) {
        this.socket = socket;
        socket.setNoDelay(true);

        socket.on('data', (chunk) => {
            this.incomingBuffer = Buffer.concat([this.incomingBuffer, chunk]);

            /*
             * Chặn máy chủ gửi dồn quá nhiều dữ liệu làm tràn bộ nhớ.
             */
            if (this.incomingBuffer.length > this.maximumBufferedBytes) {
                socket.destroy(new Error('Bộ đệm nhận TCP đã vượt quá kích thước cho phép'));
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

    /**
     * Ghi nhận lỗi kết thúc kết nối (chỉ giữ lỗi đầu tiên) và hủy lệnh đọc đang chờ.
     *
     * - `error` (Error): Lỗi gây kết thúc.
     */
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

    /**
     * Nếu buffer đã đủ byte cho lệnh đọc đang chờ thì cắt dữ liệu ra và hoàn tất lệnh đọc đó.
     */
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

    /**
     * Đọc chính xác `byteCount` byte, chờ thêm dữ liệu nếu cần.
     *
     * - `byteCount` (number): Số byte cần đọc (0 đến maximumPacketBytes).
     * - `timeoutMilliseconds` (number, không bắt buộc): Thời gian chờ tối đa; mặc định là readTimeoutMilliseconds.
     * - Trả về (Promise<Buffer>): Đúng `byteCount` byte.
     * - Ném lỗi TimeoutError: Khi hết thời gian chờ.
     * - Ném lỗi Error: Khi độ dài không hợp lệ, kết nối đã kết thúc hoặc đang có lệnh đọc khác.
     */
    async readExactly(byteCount, timeoutMilliseconds = this.readTimeoutMilliseconds) {
        if (!Number.isSafeInteger(byteCount) || byteCount < 0 || byteCount > this.maximumPacketBytes) {
            throw new Error('Độ dài đọc TCP không hợp lệ');
        }
        if (byteCount === 0) {
            return Buffer.alloc(0);
        }

        /*
         * Buffer đã đủ dữ liệu: trả ngay, không cần chờ.
         */
        if (this.incomingBuffer.length >= byteCount) {
            const data = Buffer.from(this.incomingBuffer.subarray(0, byteCount));

            this.incomingBuffer = Buffer.from(this.incomingBuffer.subarray(byteCount));

            return data;
        }

        if (this.terminalError) {
            throw this.terminalError;
        }

        if (this.waitingRead) {
            throw new Error('Không hỗ trợ đọc TCP đồng thời trên cùng một kết nối');
        }

        /*
         * Đăng ký lệnh đọc chờ; `processWaitingRead` sẽ hoàn tất khi dữ liệu về đủ.
         */
        return new Promise((resolve, reject) => {
            const timeoutHandle = setTimeout(
                () => {
                    this.waitingRead = null;
                    reject(new TimeoutError('Hết thời gian chờ nhận dữ liệu TCP'));
                },

                Math.max(timeoutMilliseconds, 1),
            );

            this.waitingRead = { length: byteCount, resolve, reject, timeoutHandle };
            this.processWaitingRead();
        });
    }

    /**
     * Ghi dữ liệu ra socket và chờ ghi xong.
     *
     * - `data` (Buffer): Dữ liệu cần gửi.
     * - Trả về (Promise<void>): Hoàn tất khi thao tác xong.
     * - Ném lỗi Error: Khi chưa kết nối, kết nối đã kết thúc hoặc ghi thất bại.
     */
    async write(data) {
        if (!this.socket || this.terminalError) {
            throw this.terminalError || new Error('Kết nối TCP chưa được thiết lập');
        }

        return new Promise((resolve, reject) => {
            this.socket.write(data, (error) => (error ? reject(error) : resolve()));
        });
    }

    /**
     * Mở kết nối TCP: kết nối thẳng tới máy chủ, hoặc tới proxy rồi bắt tay SOCKS5.
     *
     * - Trả về (Promise<void>): Hoàn tất khi thao tác xong.
     * - Ném lỗi TimeoutError: Khi kết nối quá connectTimeoutMilliseconds.
     * - Ném lỗi Error: Khi đã có kết nối, proxy không hỗ trợ hoặc bắt tay SOCKS5 thất bại.
     */
    async connect() {
        if (this.socket) {
            throw new Error('Kết nối TCP đã tồn tại');
        }

        /*
         * Xác định nơi mở socket: máy chủ đích, hoặc proxy nếu có cấu hình.
         */
        let proxy = null;
        let connectionHost = this.serverHost;
        let connectionPort = this.serverPort;
        if (this.proxyUrl) {
            proxy = new URL(this.proxyUrl);

            if (!['socks5:', 'socks5h:'].includes(proxy.protocol)) {
                throw new Error('Chỉ hỗ trợ proxy socks5:// và socks5h://');
            }

            connectionHost = proxy.hostname;
            connectionPort = Number(proxy.port || DEFAULT_SOCKS_PORT);
        }

        const socket = net.createConnection({ host: connectionHost, port: connectionPort });
        this.attachSocket(socket);

        /*
         * Chờ sự kiện 'connect', hoặc lỗi, hoặc hết thời gian — cái nào tới trước thì kết thúc.
         */
        await new Promise((resolve, reject) => {
            let settled = false;

            const timeoutHandle = setTimeout(
                () => finish(new TimeoutError('Kết nối TCP hết thời gian chờ')),
                this.connectTimeoutMilliseconds,
            );

            const finish = (error = null) => {
                if (settled) return;
                settled = true;

                clearTimeout(timeoutHandle);
                socket.off('connect', handleConnected);
                socket.off('error', handleFailed);

                if (error) {
                    socket.destroy();
                    reject(error);
                } else {
                    resolve();
                }
            };
            const handleConnected = () => finish();
            const handleFailed = (error) => finish(error);

            socket.once('connect', handleConnected);
            socket.once('error', handleFailed);
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

    /**
     * Bắt tay SOCKS5 (RFC 1928) và xác thực username/password (RFC 1929) nếu proxy yêu cầu.
     * `socks5://` phân giải DNS tại máy này; `socks5h://` gửi tên miền để proxy tự phân giải.
     *
     * - `proxy` (URL): URL proxy đã phân tích.
     * - Trả về (Promise<void>): Hoàn tất khi thao tác xong.
     * - Ném lỗi Error: Khi proxy từ chối, xác thực thất bại hoặc trả dữ liệu không hợp lệ.
     */
    async performSocks5Handshake(proxy) {
        /*
         * Bước 1: chào hỏi, đề nghị các phương thức xác thực.
         */
        const username = decodeURIComponent(proxy.username);
        const password = decodeURIComponent(proxy.password);
        const hasCredentials = username.length > 0 || password.length > 0;

        const methods = hasCredentials
            ? Buffer.from([SOCKS_METHOD_NO_AUTHENTICATION, SOCKS_METHOD_USERNAME_PASSWORD])
            : Buffer.from([SOCKS_METHOD_NO_AUTHENTICATION]);

        await this.write(Buffer.concat([Buffer.from([SOCKS_VERSION, methods.length]), methods]));

        const greetingReply = await this.readExactly(2, this.connectTimeoutMilliseconds);
        if (greetingReply[0] !== SOCKS_VERSION || greetingReply[1] === SOCKS_METHOD_NOT_ACCEPTABLE) {
            throw new Error('Proxy SOCKS5 không chấp nhận phương thức xác thực');
        }

        if (![SOCKS_METHOD_NO_AUTHENTICATION, SOCKS_METHOD_USERNAME_PASSWORD].includes(greetingReply[1])) {
            throw new Error('Phương thức xác thực SOCKS5 không được hỗ trợ');
        }

        /*
         * Bước 2: xác thực username/password nếu proxy chọn phương thức này.
         */
        if (greetingReply[1] === SOCKS_METHOD_USERNAME_PASSWORD) {
            if (!hasCredentials) {
                throw new Error('Proxy SOCKS5 yêu cầu tên người dùng và mật khẩu');
            }

            const usernameBytes = Buffer.from(username, 'utf8');
            const passwordBytes = Buffer.from(password, 'utf8');
            if (usernameBytes.length > 255 || passwordBytes.length > 255) {
                throw new Error('Thông tin xác thực SOCKS5 quá dài');
            }

            /*
             * Gói xác thực: [0x01][độ dài user][user][độ dài pass][pass].
             */
            await this.write(
                Buffer.concat([
                    Buffer.from([0x01, usernameBytes.length]),
                    usernameBytes,
                    Buffer.from([passwordBytes.length]),
                    passwordBytes,
                ]),
            );

            const authenticationReply = await this.readExactly(2, this.connectTimeoutMilliseconds);
            if (authenticationReply[0] !== 0x01 || authenticationReply[1] !== 0x00) {
                throw new Error('Xác thực SOCKS5 thất bại');
            }
        }

        /*
         * Bước 3: xác định địa chỉ đích gửi cho proxy.
         */
        let destinationHost = this.serverHost;
        if (proxy.protocol === 'socks5:' && net.isIP(destinationHost) === 0) {
            /*
             * socks5:// phân giải tên miền tại máy này; socks5h:// để proxy phân giải.
             */
            destinationHost = (await dns.lookup(destinationHost)).address;
        }

        let addressType;
        let addressBytes;
        if (net.isIP(destinationHost) === 4) {
            addressType = SOCKS_ADDRESS_TYPE_IPV4;
            addressBytes = Buffer.from(destinationHost.split('.').map(Number));
        } else if (net.isIP(destinationHost) === 6) {
            /*
             * Địa chỉ IPv6 được gửi như tên miền để không phụ thuộc thư viện ngoài.
             * Địa chỉ cố định trong Python là IPv4 nên hành vi gốc không bị ảnh hưởng.
             */
            addressType = SOCKS_ADDRESS_TYPE_DOMAIN;
            const domainBytes = Buffer.from(destinationHost, 'utf8');

            if (domainBytes.length > 255) {
                throw new Error('Địa chỉ đích SOCKS5 quá dài');
            }

            addressBytes = Buffer.concat([Buffer.from([domainBytes.length]), domainBytes]);
        } else {
            addressType = SOCKS_ADDRESS_TYPE_DOMAIN;
            const domainBytes = Buffer.from(destinationHost, 'utf8');

            if (domainBytes.length > 255) {
                throw new Error('Địa chỉ đích SOCKS5 quá dài');
            }

            addressBytes = Buffer.concat([Buffer.from([domainBytes.length]), domainBytes]);
        }

        /*
         * Bước 4: gửi lệnh CONNECT: [0x05][0x01][0x00][kiểu địa chỉ][địa chỉ][cổng u16 BE].
         */
        const portBytes = Buffer.alloc(2);
        portBytes.writeUInt16BE(this.serverPort);
        const connectRequestHeader = Buffer.from([SOCKS_VERSION, SOCKS_COMMAND_CONNECT, 0x00, addressType]);
        await this.write(Buffer.concat([connectRequestHeader, addressBytes, portBytes]));

        /*
         * Bước 5: đọc phản hồi CONNECT: [0x05][mã trả lời][0x00][kiểu địa chỉ][địa chỉ gắn kết][cổng].
         */
        const replyHeader = await this.readExactly(4, this.connectTimeoutMilliseconds);
        if (replyHeader[0] !== SOCKS_VERSION || replyHeader[1] !== 0x00) {
            throw new Error(`Kết nối SOCKS5 thất bại (reply ${replyHeader[1]})`);
        }

        /*
         * Đọc bỏ địa chỉ gắn kết (bound address) và cổng để buffer chỉ còn dữ liệu của máy chủ đích.
         */
        if (replyHeader[3] === SOCKS_ADDRESS_TYPE_IPV4) {
            await this.readExactly(4 + 2, this.connectTimeoutMilliseconds);
        } else if (replyHeader[3] === SOCKS_ADDRESS_TYPE_IPV6) {
            await this.readExactly(16 + 2, this.connectTimeoutMilliseconds);
        } else if (replyHeader[3] === SOCKS_ADDRESS_TYPE_DOMAIN) {
            const domainLength = (await this.readExactly(1, this.connectTimeoutMilliseconds))[0];
            await this.readExactly(domainLength + 2, this.connectTimeoutMilliseconds);
        } else {
            throw new Error('Proxy SOCKS5 trả về định dạng địa chỉ không xác định');
        }
    }

    /**
     * Đọc một frame hoàn chỉnh: 4 byte độ dài (u32 LE) + payload.
     * Nếu bị timeout sau khi đã đọc 4 byte độ dài, phần đó được giữ lại cho lần đọc sau.
     *
     * - `timeoutMilliseconds` (number, không bắt buộc): Thời gian chờ cho cả frame; mặc định là readTimeoutMilliseconds.
     * - Trả về (Promise<Buffer>): Frame gồm cả 4 byte độ dài.
     * - Ném lỗi TimeoutError: Khi hết thời gian chờ.
     * - Ném lỗi Error: Khi độ dài payload không hợp lệ hoặc đang có lệnh đọc frame khác.
     */
    async readFrame(timeoutMilliseconds = this.readTimeoutMilliseconds) {
        if (this.frameReadInProgress) {
            throw new Error('Đang có lệnh đọc frame TCP khác');
        }

        this.frameReadInProgress = true;
        const deadline = Date.now() + timeoutMilliseconds;
        const remainingTime = () => Math.max(1, deadline - Date.now());

        try {
            if (!this.pendingFrameHeader) {
                this.pendingFrameHeader = await this.readExactly(4, remainingTime());
            }

            /*
             * Payload tối thiểu 2 byte (độ dài header) và không vượt giới hạn frame.
             */
            const payloadLength = this.pendingFrameHeader.readUInt32LE(0);
            if (payloadLength < 2 || payloadLength > this.maximumPacketBytes - 4) {
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

    /**
     * Gửi một packet rồi đọc frame trả lời ngay sau đó.
     *
     * - `message` (Buffer): Packet cần gửi.
     * - `timeoutMilliseconds` (number, không bắt buộc): Thời gian chờ frame trả lời.
     * - Trả về (Promise<Buffer>): Frame trả lời.
     */
    async sendMessage(message, timeoutMilliseconds = this.readTimeoutMilliseconds) {
        await this.write(message);

        return this.readFrame(timeoutMilliseconds);
    }

    /**
     * Đóng kết nối và hủy mọi lệnh đọc đang chờ. Gọi nhiều lần không gây lỗi.
     */
    close() {
        if (this.socket) {
            this.socket.destroy();
            this.socket = null;
        }

        this.handleTerminalError(new Error('Kết nối TCP client đã đóng'));
    }
}

export { TcpClient, TimeoutError };
