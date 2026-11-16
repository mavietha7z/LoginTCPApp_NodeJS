# LoginTCPApp — phiên bản Node.js

Chuyển đổi từ file `LoginTCPApp.py` gốc sang Node.js **ES Module, Node >= 22.12**, giữ nguyên wire format Protobuf, custom XTEA và trình tự command TCP. Không cần cài thư viện npm bên ngoài.

**Trạng thái kiểm thử:** 14/14 test offline đạt; 150/150 vector XTEA ngẫu nhiên khớp với Python; 4 loại packet khớp từng byte với Python. **Chưa xác minh đăng nhập trên máy chủ thật**. Sử dụng cho tài khoản và dịch vụ mà bạn được phép truy cập; không tự động bỏ qua CAPTCHA hoặc các giới hạn xác thực.

## Cấu trúc

```text
LoginTCPApp_NodeJS/
├── server.js                          # POST /api/login, API key, kiểm soát đồng thời
├── package.json                       # npm start / npm test
├── .env.example                       # Mẫu cấu hình
├── .gitignore
├── README.md
├── ANALYSIS.md                         # Phân tích chi tiết file Python
├── DEPLOY.md                           # Hướng dẫn triển khai VPS + SSH tunnel
├── deploy/                             # Script cài đặt, systemd, Caddy, cấu hình SSH tunnel
├── src/
│   ├── configuration.js                # Đọc và kiểm tra biến môi trường
│   ├── crypto/
│   │   ├── xtea-custom.js              # Custom XTEA (đúng thuật toán Python)
│   │   └── encryption-key.js           # MD5 -> SHA256 -> SHA256
│   ├── protocol/
│   │   ├── protobuf.js                 # Wire types 0,1,2,5; varint 64 bit
│   │   ├── packets.js                  # Đóng gói frame và nhận diện packet mã hóa
│   │   ├── requests.js                 # 256, 257, 277, 278, 511, 276, 442, 342
│   │   ├── responses.js                # Đọc kết quả và giải mã reply
│   │   └── system-errors.json          # 78 mã lỗi trích nguyên từ Python
│   ├── transport/
│   │   └── tcp-client.js               # Đọc stream TCP theo frame, SOCKS5/SOCKS5h
│   └── services/
│       └── login-service.js            # LoginPrepare -> Login -> Token -> SSO
└── test/
    ├── protocol.test.js                # Đối chiếu XTEA, Protobuf, packet với Python
    ├── login-service.test.js           # Máy chủ giả, SOCKS5 giả, xác thực HTTP
    └── fixtures/
        ├── python-vectors.json         # Vector mã hóa do Python sinh ra
        └── python-packets.json         # Packet do Python sinh ra
```

## Cài đặt trên Windows PowerShell

Bạn cần cài **Node.js 22.12 hoặc mới hơn** (cần cho `import` file JSON không kèm cảnh báo).

```powershell
node --version
npm --version
cd LoginTCPApp_NodeJS
Copy-Item .env.example .env
```

Mở `.env` và sửa `API_KEY` thành chuỗi bí mật mạnh. Tạo chuỗi mẫu bằng:

```powershell
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

Nếu dùng SSH SOCKS5 qua VPS trung gian và tunnel `127.0.0.1:1080` đã bật, bỏ dấu `#` ở dòng:

```dotenv
SOCKS_PROXY_URL=socks5h://127.0.0.1:1080
```

Lưu ý: TCP đi qua SOCKS5 **khác** HTTP Axios/fetch proxy. Bản Node.js tự triển khai SOCKS5 trên `node:net`, không cần `socks-proxy-agent` hay `axios`.

Chạy kiểm thử và API:

```powershell
npm test
npm start
```

Mặc định API lắng nghe tại `http://127.0.0.1:5000`. Kiểm tra hoạt động:

```powershell
Invoke-RestMethod -Uri 'http://127.0.0.1:5000/health'
```

## Gọi API

**Python gốc:** `GET /api/login?username=...&password=...&proxy=...` (không an toàn).

**Node.js:** `POST /api/login` với `Content-Type: application/json` và header `X-API-Key`. Proxy được cấu hình ở máy chủ, không cho người gọi chỉ định proxy bất kỳ.

```http
POST /api/login HTTP/1.1
Host: 127.0.0.1:5000
Content-Type: application/json
X-API-Key: <your-secret-from-env>

{"username":"your-account","password":"your-password"}
```

PowerShell (dùng tài khoản thuộc quyền quản lý của bạn):

```powershell
$apiKey = Read-Host 'Nhap API_KEY'
$username = Read-Host 'Nhap username'
$password = Read-Host 'Nhap password'
$body = @{ username = $username; password = $password } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:5000/api/login' `
  -Headers @{ 'X-API-Key' = $apiKey } `
  -ContentType 'application/json' -Body $body
```

Kết quả thành công có định dạng tương tự Python:

```json
{
    "code": 0,
    "uid": 123456,
    "session_key": "<32 hex characters>",
    "SsoKeyGetReply": { "sso_key": "<secret-sso-key>" },
    "duration": 0.62,
    "attempts": 1
}
```

`session_key` và `sso_key` là **dữ liệu bí mật**, không ghi vào log, URL, frontend hoặc database ở dạng rõ. Nếu cần lưu tại backend, sử dụng cơ chế mã hóa có quản lý khóa và phân quyền đọc.

Ví dụ một mã lỗi:

```json
{ "code": 105, "msg": "ERROR_CAPTCHA", "duration": 0.17, "attempts": 1 }
```

Hệ thống không cố bỏ qua CAPTCHA. `GET /api/login` đã bị bỏ để tránh rò rỉ mật khẩu. Các request thiếu API key trả HTTP 401.

## Các biến môi trường

| Biến                       | Mặc định         | Mô tả                                                                                                         |
| -------------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------- |
| `API_KEY`                  | Bắt buộc         | Khóa bảo vệ API, tối thiểu 24 ký tự                                                                           |
| `HTTP_HOST`                | `127.0.0.1`      | Mặc định chỉ cho phép truy cập cục bộ                                                                         |
| `HTTP_PORT`                | `5000`           | Cổng API                                                                                                      |
| `TCP_SERVER_HOST`          | `103.247.205.15` | Địa chỉ có trong Python gốc, chưa xác minh còn hoạt động                                                      |
| `TCP_SERVER_PORT`          | `19000`          | Cổng TCP trong Python                                                                                         |
| `SOCKS_PROXY_URL`          | Trống            | Ví dụ `socks5h://127.0.0.1:1080`                                                                              |
| `DEVICE_ID`                | Lấy từ MAC máy   | Device ID dưới dạng số thập phân                                                                              |
| `MAX_RETRIES`              | `3`              | Số lần thử tối đa (không thử lại khi gặp CAPTCHA hoặc lỗi xác thực)                                           |
| `MAX_CONCURRENT_LOGINS`    | `3`              | Giới hạn số lượt đăng nhập song song trong một tiến trình                                                     |
| `CONNECT_TIMEOUT_MS`       | `8000`           | Thời gian chờ kết nối TCP và bắt tay SOCKS                                                                    |
| `READ_TIMEOUT_MS`          | `5000`           | Thời gian chờ nhận một packet                                                                                 |
| `MAX_PACKET_BYTES`         | `1048576`        | Chặn packet quá lớn                                                                                           |
| `RESPONSE_WINDOW_MS`       | `3000`           | Tổng thời gian chờ nhận phản hồi SSO                                                                          |
| `RESPONSE_IDLE_TIMEOUT_MS` | `500`            | Thời gian chờ tối đa giữa hai packet liên tiếp                                                                |
| `XTEA_RANDOM_MODE`         | `legacy`         | `legacy`: tương thích với Python; `cryptographic`: IV ngẫu nhiên mạnh hơn (cần kiểm tra máy chủ có chấp nhận) |

**Device ID:** Python gọi `hash(uuid.getnode())`. Node.js dùng địa chỉ MAC của card mạng đầu tiên không phải loopback. Hai giá trị này **không nhất thiết giống nhau** trên máy có nhiều card mạng hoặc khi đổi máy. Để có cùng giá trị như Python, chạy lệnh sau trên máy chạy Python gốc:

```bash
python -c "import uuid; print(hash(uuid.getnode()))"
```

Sao chép kết quả số thập phân vào `DEVICE_ID=...` của `.env`. Đây là thiết lập tương thích, không phải kỹ thuật vượt qua ràng buộc thiết bị hay bảo mật dịch vụ.

## Triển khai lên VPS

Xem [DEPLOY.md](DEPLOY.md): Ubuntu 24.04, Caddy (HTTPS cho `api-gateway.ha2cm.com`), systemd. Trên VPS app gọi thẳng máy chủ TCP; máy local dùng SSH SOCKS tunnel tới VPS (`SOCKS_PROXY_URL=socks5h://127.0.0.1:1080`) để đi ra cùng IP.

## Tích hợp vào backend dự án khác

Nếu muốn gọi trực tiếp từ backend Node.js (không mở thêm cổng HTTP), sử dụng:

```js
import { loginAndGetKeys } from './src/services/login-service.js';

const result = await loginAndGetKeys('account-owned-by-you', 'password', {
    maximumRetries: 1,
    deviceIdentifier: process.env.DEVICE_ID,
    transportOptions: {
        serverHost: process.env.TCP_SERVER_HOST,
        serverPort: Number(process.env.TCP_SERVER_PORT),
        proxyUrl: process.env.SOCKS_PROXY_URL || null,
    },
});
```

Nên giữ lớp giao tiếp TCP tách riêng khỏi controller nghiệp vụ nạp vật phẩm. File gốc **không hề chứa chức năng nạp vật phẩm hoặc thanh toán**; muốn bổ sung phải dựa trên hợp đồng/API được phép sử dụng, không suy ra chỉ từ SSO key.

## Giới hạn xác minh

1. Đã đối chiếu packet và XTEA với Python, nhưng **chưa có phiên kiểm thử xác thực trên hệ thống thật**.
2. Chưa xác minh máy chủ `103.247.205.15:19000` còn được vận hành hay không, và các giá trị `client_version`, `client_type` còn được chấp nhận hay không.
3. Chưa thử qua proxy doanh nghiệp có quy tắc xác thực phức tạp; đã kiểm thử SOCKS5h với proxy giả lập cục bộ.
4. Chưa kiểm chứng luồng OTP, CAPTCHA hay xác thực bổ sung; mã gốc cũng không triển khai các luồng đó.
5. Custom XTEA trong mã Python gốc không có cơ chế xác thực toàn vẹn thông điệp hiện đại; tương thích không đồng nghĩa với an toàn mật mã.

Xem `ANALYSIS.md` để biết các lỗi và quyết định chuyển đổi theo từng thành phần Python.
