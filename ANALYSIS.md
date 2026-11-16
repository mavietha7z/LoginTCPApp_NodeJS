# Phân tích đầy đủ `LoginTCPApp.py` và bản chuyển đổi Node.js

Nguồn được phân tích: file Python 1006 dòng do người dùng gửi. Phạm vi: **chuyển đổi chức năng hiện có**, không tự suy đoán API nạp vật phẩm hay cách vượt qua xác minh tài khoản của bên thứ ba.

## 1. Thư viện và những import không sử dụng

- `socket`, `struct`, `socks`: kết nối TCP, framing và SOCKS5.
- `hashlib`, `os`, `time`, `uuid`, `re`, `binascii`: hash, dữ liệu ngẫu nhiên, timestamp, MAC, nhận dạng email và chuyển hex.
- `Flask`, `request`, `jsonify`: HTTP server.
- `base64`, `random`, `traceback`, `requests`: được import nhưng không thấy sử dụng trong logic file.
- Node.js chuyển sang các thư viện có sẵn: `node:net`, `node:crypto`, `node:http`, `node:os`, `node:dns/promises`.

## 2. `BaseProtobufDecoder` (dòng 18–95)

- Có bảng field number 1–8 tương ứng `version`, `id`, `command_type`, `command`, `result`, `timestamp`, `fragment_number`, `fragment_index`.
- Giải mã Protobuf wire types: varint=0, fixed64=1, length-delimited=2, fixed32=5.
- Giá trị bytes được biểu diễn thành hex trong header. Trường trùng tag ghi đè nhau (không gom repeated fields).
- **Lỗi:** không kiểm tra offset sau khi đọc fixed32/fixed64/length-delimited; trường bị cắt ngắn có thể bị phân tích nhầm.
- **Node.js:** `src/protocol/protobuf.js`, có kiểm tra giới hạn, varint dùng BigInt, JSON không mất chính xác số nguyên > 2^53−1.

## 3. `PacketSend` (dòng 98–118)

Cấu trúc request có header rõ:

```text
[4 byte payload_length, little-endian]
[2 byte header_length, big-endian]
[protobuf header]
[protobuf body]
```

- **Node.js:** `buildPacket()` trong `src/protocol/packets.js`, giữ byte order hoàn toàn.

## 4. `Lrand48` (dòng 124–133)

- Bộ sinh pseudo-random 48 bit, seed bằng số giây hiện tại, cho ra giá trị 31 bit.
- Dùng để khởi tạo mã hóa XTEA ở Python.
- **Vấn đề:** seed là thời gian nên có thể đoán; nhiều packet trong cùng giây có nguy cơ dùng các giá trị khởi tạo giống nhau.
- **Node.js:** tương thích `legacy`, cho tùy chọn `cryptographic` tạo ngẫu nhiên bằng `crypto.randomBytes`, **nhưng phải xác nhận server chấp nhận trước khi chuyển sang chế độ này**.

## 5. `XTEACBC` (dòng 136–349)

- Key chính xác 16 byte, block size 8 byte, 32 vòng.
- Đây **không phải CBC/XTEA tiêu chuẩn có thể thay bằng AES**. Nó có cách tạo block đầu đặc biệt, CBC qua các block, PKCS#7-like padding, thêm một block cuối được mã hóa để xử lý/check dữ liệu.
- Phương thức decrypt bỏ một block cuối nhưng **không thực sự kiểm tra tính toàn vẹn của block đó**.
- **Lỗi đã tái hiện bằng Python:** `crypt_xtea_cbc_encrypt()` chạy với input dưới 8 byte gây `UnboundLocalError` do biến `leftover` chỉ được gán bên trong vòng lặp xử lý các block đầy đủ.
- **Node.js:** `src/crypto/xtea-custom.js`; sửa lỗi input 0–7 byte, còn các input ≥8 byte cho kết quả giống hệt Python. Kiểm thử 150 bộ ngẫu nhiên, toàn bộ khớp.

## 6. `ProtoUtils` (dòng 352–368)

- Tạo Protobuf varint; đóng gói length-delimited là `varint(length) + bytes`.
- **Node.js:** `encodeVarint()`, `encodeVarintField()`, `encodeBytesField()`.

## 7. `BaseLoginRequest` (dòng 371–408)

- Sinh key 16 byte ngẫu nhiên cho LoginPrepare.
- Header chứa: version=285212918; id=`hash(uuid.getnode())`; command_type=2; command=theo request; timestamp=Unix seconds.
- **Lưu ý:** `hash(uuid.getnode())` thường là giá trị MAC dưới dạng số nguyên, không phải UUID ngẫu nhiên. Việc tìm MAC ở Node có thể khác Python; có `DEVICE_ID` để khớp.
- Body mặc định có field 1 là key 16 byte và field 2 là dữ liệu mã hóa.
- **Node.js:** `BaseLoginRequest`.

## 8. `LoginPrepareRequest` (dòng 411–439)

Command **256**. Plaintext body:

| Field | Protobuf type | Giá trị                                           |
| ----- | ------------- | ------------------------------------------------- |
| 1     | varint        | `auth_type=0`                                     |
| 2     | varint        | `account_type=2` nếu có dạng email, ngược lại `1` |
| 3     | bytes         | Tài khoản UTF-8                                   |
| 4     | varint        | `client_type=4352`                                |
| 5     | varint        | `client_version=246`                              |

Body gốc được mã hóa bằng khóa ngẫu nhiên rồi đặt vào field 2 của body ngoài; chính khóa đó nằm ở field 1. Bản Node giữ đúng toàn bộ các field.

## 9. `LoginRequestHandler` (dòng 442–478) — bản Node đổi tên thành `LoginRequest`

Command **257**. Body sau giải mã:

| Field | Giá trị                                         |
| ----- | ----------------------------------------------- |
| 1     | Chuỗi hexdigest MD5 mật khẩu, UTF-8 bytes       |
| 2     | `login_mode=0`                                  |
| 3     | Nested protobuf có field 2 = `user_status=4608` |
| 4     | Chuỗi thập phân device ID, UTF-8 bytes          |

Key mã hóa bước 2 là kết quả `EncryptionKeyGenerator` (không còn là random key của bước chuẩn bị). Outer body ở lệnh này chứa **chỉ field 1 là ciphertext**, khác `LoginPrepareRequest`.

## 10. `EmptyPacket` và `LoginTokenGetRequest` (dòng 481–523)

- Các packet phiên sau login mã hóa **toàn bộ `[header_length][header][body]`**, chỉ giữ `[frame_length]` rõ ở ngoài.
- `LoginTokenGetRequest`: command 277, body field 1 = varint 1.
- `EmptyPacket`: body rỗng, command được truyền vào; file sử dụng 278, 511, 276, 278, 442, 342.
- Node.js giữ byte format; đã so sánh chính xác với Python đối với command 277 và 442.

## 11. `SystemError`, `SystemResponse` (dòng 526–629)

- Bảng 78 mã lỗi được chuyển nguyên vào `system-errors.json`.
- Các mã cần chú ý: 0 SUCCESS, 101 ACCOUNT_NOT_EXIST, 103 ACCOUNT_LOCKED, 104 VERSION_TOO_LOW, 105 CAPTCHA, 107 TOKEN_EXPIRED, 110 DECRYPT, 130 OTP_REQUIRE, 133 OTP_CODE_INVALID, 159 IP_LIMIT, 173 AUTH_USER_BAN.
- Node.js dùng `SystemResponse` và không tự thử lại khi máy chủ yêu cầu CAPTCHA hoặc từ chối xác thực.

## 12. `PacketReceiver` (dòng 632–748)

- LoginPrepareReply command 256 với command_type=3; body chứa encrypt_key ở field 1 và encrypted data ở field 2.
- LoginReply command 257/259 với command_type=3; body field 1 chứa encrypted data.
- SsoKeyGetReply command 274/294/442 với command_type=3 hoặc 4; body field 1 là SSO key.
- Dữ liệu của LoginPrepareReply sau decrypt có salt và verify_code ở field 1/2.
- LoginReply sau decrypt có uid và session_key ở field 1/2.
- **Lỗi:** mã gốc phân biệt packet mã hóa toàn bộ bằng cách đoán 2 byte đầu là độ dài header; có xác suất nhỏ đọc nhầm. Bản Node kiểm tra cấu trúc Protobuf trước, thất bại mới chuyển sang giải mã.
- **Lỗi:** đoạn gốc không bảo đảm mọi trường bắt buộc có đúng kiểu dữ liệu trước khi gọi `.hex()`.
- **Node.js:** `src/protocol/responses.js`.

## 13. `EncryptionKeyGenerator` (dòng 752–769)

Quy trình:

```text
md5_pass = hex(MD5(utf8(password)))
digest_step2 = SHA256(utf8(md5_pass + salt))
hex_step2 = hex(digest_step2)
final_digest = SHA256(utf8(hex_step2 + verify_code))
key = final_digest[0:16]
```

- Không thay MD5 bằng bcrypt/argon2 trong giao thức này vì sẽ thay đổi packet và mất tương thích. Phần ứng dụng tự xây dựng mới vẫn phải dùng chuẩn lưu mật khẩu hiện đại.
- Node.js: `src/crypto/encryption-key.js`, kiểm thử output khớp Python.

## 14. `TCPClient` (dòng 772–834)

- TCP đích mặc định: `103.247.205.15:19000`.
- Có SOCKS5 hoặc SOCKS5h; với hậu tố h, DNS được xử lý ở phía proxy.
- **Lỗi:** không có connection timeout mặc định.
- **Lỗi:** `recv(4)` có thể trả về ít hơn 4 byte, làm lệch việc tách frame.
- **Lỗi:** `send_message()` nuốt mọi exception và trả mảng rỗng.
- **Lỗi:** không giới hạn payload length trước khi cấp bộ nhớ.
- **Node.js:** `src/transport/tcp-client.js` đọc đúng số byte, ghép đúng các frame bị chia nhỏ, có timeout, giới hạn kích thước, tự bắt tay SOCKS5 (hỗ trợ cả username/password).

## 15. `login_and_get_keys` (dòng 837–981)

Trình tự:

1. Kết nối TCP trực tiếp hoặc thông qua SOCKS5.
2. Gửi LoginPrepare 256 và lấy `salt`, `verify_code`.
3. Tạo key 16 byte từ mật khẩu/salt/verify_code.
4. Gửi Login 257 và lấy `uid`, `session_key`.
5. Gửi LoginTokenGet 277, nhận phản hồi.
6. Gửi batch command `278,511,276,278,442,342`.
7. Đọc các reply, tìm `SsoKeyGetReply.sso_key` và trả key/UID.
8. Đóng kết nối, thử lại khi lỗi được phép.

- **Lỗi:** lỗi nhận packet đầu tiên gây `break` ngay, không dùng hết retry.
- **Lỗi:** `resp[0]`, `resp[1]` sau lấy token không kiểm tra đủ độ dài.
- **Lỗi:** vòng thu reply có thể chạy không có deadline tổng nếu liên tục xuất hiện packet chưa nhận dạng.
- **Lỗi:** `attempts=max_retries` ở một số nhánh lỗi không phản ánh đúng số lần đã thử.
- **Lỗi:** retry code 105 CAPTCHA không giúp xác minh người dùng, gây request lặp không cần thiết.
- **Node.js:** `src/services/login-service.js`; trả `attempts` đúng, kiểm tra reply, timeout và frame count, `finally` đóng kết nối.

## 16. Flask `/api/login` (dòng 985–1006)

Python dùng `GET` cho tài khoản, mật khẩu và proxy; không yêu cầu API key, chạy debug trên `0.0.0.0:5000`.

Node.js thay thành:

- `POST /api/login` với JSON body.
- Header bắt buộc `X-API-Key` dùng `crypto.timingSafeEqual`.
- Không nhận `proxy` từ request; proxy chỉ cấu hình trong `.env`.
- Mặc định bind `127.0.0.1` thay vì mở toàn mạng.
- `GET /health` đơn giản, không lộ session key.
- Giới hạn kích thước JSON, số request đồng thời và timeout TCP.
- `Cache-Control: no-store` cho phản hồi có dữ liệu phiên.

**Đổi API GET -> POST là thay đổi có chủ ý vì bảo mật; bên gọi API Python cũ cần cập nhật.**

## 17. Khả năng sử dụng cho nạp game

File này thực hiện **xác thực TCP và lấy token/SSO**, không có:

- API tra cứu tài khoản game hoặc role ID.
- API vật phẩm/đơn hàng/bảng giá.
- API thanh toán hay nạp vật phẩm.
- Xác minh giao dịch, hoàn tiền, idempotency, callback.

Vì vậy chức năng nạp tự động phải thiết kế một module nghiệp vụ riêng và chỉ tích hợp với cơ chế chính thức/được cấp quyền. Không coi `session_key` hoặc `sso_key` là chứng cứ nạp thành công.

## 18. Trạng thái và kiểm thử

| Kiểm tra                                            | Kết quả                                 |
| --------------------------------------------------- | --------------------------------------- |
| 6 vector XTEA từ Python cố định                     | PASS                                    |
| 150 vector XTEA ngẫu nhiên Python/Node, 8–257 byte  | PASS                                    |
| LoginPrepare packet byte-for-byte                   | PASS                                    |
| Login packet byte-for-byte                          | PASS                                    |
| LoginTokenGet packet byte-for-byte                  | PASS                                    |
| EmptyPacket packet byte-for-byte                    | PASS                                    |
| Protobuf varint 64 bit / dữ liệu lỗi                | PASS                                    |
| Mock server đăng nhập đủ 3 bước + SSO               | PASS                                    |
| Đăng nhập end-to-end với TCP server mô phỏng nội bộ | PASS                                    |
| Không retry CAPTCHA 105                             | PASS                                    |
| HTTP POST auth / deny GET                           | PASS                                    |
| TCP fragmented framing                              | PASS                                    |
| Mock SOCKS5h                                        | PASS                                    |
| Đăng nhập với máy chủ thật                          | CHƯA KIỂM CHỨNG                         |
| OTP/CAPTCHA tương tác                               | Không có trong Python, không tự bổ sung |

Các bài test ở `test/` dùng **dữ liệu giả và máy chủ giả lập**, không thực hiện đăng nhập vào hệ thống bên thứ ba.
