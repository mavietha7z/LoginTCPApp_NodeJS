# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Ngôn ngữ

Người dùng làm việc bằng **tiếng Việt**: trả lời, giải thích, viết tài liệu (README, ANALYSIS) bằng tiếng Việt.

Quy ước code:

- Comment trong code viết bằng **tiếng Việt**, luôn dùng dạng khối nhiều dòng (`/** ... */` cho class/hàm/hằng số, `/* ... */` cho giải thích bên trong hàm), **không dùng `//`** và **không dùng thẻ JSDoc `@param`/`@returns`/`@throws`**. Mỗi class/hàm/method có mô tả mục đích, dòng tương ứng trong `LoginTCPApp.py`, rồi gạch đầu dòng: ``- `tênThamSố` (kiểu, không bắt buộc / mặc định x): mô tả``, `- Trả về (kiểu): ...`, `- Ném lỗi Kiểu: ...`.
- Tên hàm/biến viết bằng tiếng Anh, **không viết tắt** (`maximumRetries`, `readTimeoutMilliseconds`, `configuration`; không dùng `max…`, `…Ms`, `config`). Ngoại lệ: từ viết tắt chuẩn ngành (XTEA, TCP, SSO, JSON, HTTP, UTF-8, SOCKS5, MD5, SHA256, varint, `Lrand48`).
- Không lồng nhiều lệnh gọi trên một dòng; tách thành biến trung gian có tên rõ nghĩa.
- Giữ nguyên các tên thuộc hợp đồng bên ngoài: biến môi trường (`MAX_RETRIES`, `*_MS`…), key JSON trả về (`code`, `uid`, `session_key`, `sso_key`, `message`; không có `msg`, `attempts`, `duration`, `SsoKeyGetReply`), key đối chiếu Python (`encrypt_key`, `verify_code`, `message_type`, `command_type`), và hàm `loginAndGetKeys`.
- Thông báo lỗi (`new Error(...)`) giữ tiếng Anh vì một số được trả thẳng ra API và test có so khớp.
- ES Module: dùng `import`/`export` có tên (không default export); đường dẫn nội bộ phải ghi đủ đuôi `.js`; file JSON nạp bằng `import ... with { type: 'json' }`. Không có `require`, `module.exports`, `__dirname`.

## Tổng quan

Bản port Node.js (**ES Module** — `"type": "module"`, Node >= 22.12, **không có dependency npm**) của `LoginTCPApp.py`. Ứng dụng đăng nhập vào một máy chủ TCP dùng Protobuf tự viết + custom XTEA, lấy `uid`, `session_key`, `sso_key`, và mở HTTP API `POST /api/login`. `LoginTCPApp.py` là **nguồn tham chiếu gốc**, không chạy trong dự án — dùng để đối chiếu hành vi. `ANALYSIS.md` ghi lại phân tích từng class Python (kèm số dòng) và các lỗi đã sửa khi port.

Là git repo (remote `origin` trên GitHub, nhánh `main`).

## Lệnh

```bash
npm test                                   # node --test, chạy toàn bộ test/ (offline, dùng server giả lập)
node --test --test-name-pattern="CAPTCHA"  # chạy một test theo tên
node --test test/protocol.test.js          # chạy một file test
npm start                                  # node --env-file=.env server.js (cần .env, copy từ .env.example)
npm run start:env                          # chạy với biến môi trường có sẵn, không đọc .env
```

Không có linter/build. `API_KEY` bắt buộc (>= 24 ký tự) nếu không server sẽ không khởi động.

## Kiến trúc

Luồng gọi: `server.js` → `src/services/login-service.js` (`loginAndGetKeys`) → `src/protocol/requests.js` (dựng packet) + `src/transport/tcp-client.js` (gửi/nhận frame) → `src/protocol/responses.js` (giải mã reply).

Trình tự đăng nhập trong `loginAndGetKeys` (mỗi lần retry mở kết nối TCP mới):

1. **256 LoginPrepare** — header rõ; body = `[field1: random key 16B][field2: XTEA(random key, data)]`. Reply trả `salt`, `verify_code` (đã mã hóa bằng `encrypt_key` trong reply).
2. **257 Login** — key = `SHA256(hex(SHA256(md5hex(pw)+salt)) + verify_code)[0:16]` (`src/crypto/encryption-key.js`). Body chỉ có field1 = ciphertext. Reply trả `uid`, `session_key` (16B, hex).
3. **277 LoginTokenGet** và các lệnh sau dùng **packet mã hóa toàn bộ**: chỉ 4 byte độ dài để ở dạng rõ, phần `[header_len][header][body]` mã hóa bằng `session_key`.
4. Gửi gộp `278, 511, 276, 278, 442, 342` rồi đọc frame trong `RESPONSE_WINDOW_MS` cho tới khi gặp `SsoKeyGetReply` (command 274/294/442).

Định dạng wire (phải giữ đúng từng byte):

- Packet header rõ: `[u32 LE payload_len][u16 BE header_len][protobuf header][body]`. Header luôn gồm field 1=version `285212918`, 2=device id, 3=command_type (2 khi gửi, 3/4 khi nhận), 4=command, 6=timestamp; field 5=`result` là mã lỗi (bảng `system-errors.json`).
- `parsePacketPayload` (`src/protocol/packets.js`) thử parse dạng rõ trước, thất bại mới decrypt bằng key — vì không có cờ phân biệt hai dạng packet.

### Những điểm dễ phá vỡ tương thích

- `src/crypto/xtea-custom.js` **không phải XTEA-CBC chuẩn**: block đầu tạo từ IV theo cách riêng, có block checksum cuối (khi decrypt bị bỏ qua, không verify). Đừng "sửa cho chuẩn" hoặc thay bằng thư viện.
- IV mặc định (`XTEA_RANDOM_MODE=legacy`) sinh bằng `Lrand48` seed theo giây — cố ý giống Python. `cryptographic` chưa được xác minh với server thật.
- Device ID: Python dùng `hash(uuid.getnode())`; Node lấy MAC interface đầu tiên không phải internal (`discoverDeviceIdentifier` trong `requests.js`) hoặc `DEVICE_ID`. Hai giá trị có thể khác nhau.
- Protobuf decoder (`src/protocol/protobuf.js`): varint là BigInt; field trùng tag ghi đè (giống dict Python); `convertBigIntForJson` đổi sang string khi > 2^53−1.
- Mọi thay đổi packet/crypto phải giữ test parity xanh: `test/fixtures/python-vectors.json` và `python-packets.json` là byte do Python sinh ra. Muốn sinh fixture mới thì chạy lại code Python gốc, không tự tạo từ Node.

### Các quyết định có chủ ý (khác Python)

- HTTP: chỉ `POST /api/login/garena` (JSON) + header `X-API-Key` (so sánh `timingSafeEqual`), `GET /health`; không nhận `proxy` từ request (proxy chỉ cấu hình qua `SOCKS_PROXY_URL`); bind mặc định `127.0.0.1`; giới hạn đồng thời `MAX_CONCURRENT_LOGINS`.
- Chỉ retry mã 110 (ERROR_DECRYPT) và lỗi transport/thiếu dữ liệu; **không retry CAPTCHA (105) hay lỗi xác thực**, không cài đặt bỏ qua CAPTCHA/OTP.
- SOCKS5/SOCKS5h tự cài trên `node:net` (có user/pass auth); `socks5://` resolve DNS cục bộ, `socks5h://` để proxy resolve.
- `TcpClient` đọc chính xác số byte qua buffer nội bộ, giới hạn `MAX_PACKET_BYTES`, không hỗ trợ đọc đồng thời trên cùng kết nối.
- `session_key`/`sso_key` là bí mật: không log ra ngoài, không đưa vào URL.

## Test

`test/login-service.test.js` dựng mock TCP server, mock SOCKS5 và HTTP server trong tiến trình (cổng ngẫu nhiên). `createServer(configuration, loginService)` nhận `loginService` inject được; `loginAndGetKeys` nhận `options.transportFactory` để thay `TcpClient` bằng transport giả — dùng các điểm này khi viết test mới thay vì gọi mạng thật.

## Triển khai

Xem `DEPLOY.md`. VPS Ubuntu 24.04 chạy app bằng systemd (`deploy/login-tcp-api.service`, user `logintcp`, `/opt/login-tcp-api`), Caddy làm HTTPS cho `api-gateway.ha2cm.com` và proxy về `127.0.0.1:HTTP_PORT`. Trên VPS app gọi thẳng máy chủ TCP (không đặt `SOCKS_PROXY_URL`); máy local mở `ssh -D 127.0.0.1:1080` tới user `tunnel` trên VPS, user này chỉ được forward tới `TCP_SERVER_HOST:TCP_SERVER_PORT` (`PermitOpen` trong `deploy/sshd-tunnel.conf`). `deploy/setup-vps.sh` cài toàn bộ và chạy lại được; đổi máy chủ TCP thì phải chạy lại script để cập nhật `PermitOpen`.
