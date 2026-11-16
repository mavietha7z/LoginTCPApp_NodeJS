# Triển khai lên VPS

Mô hình triển khai:

```text
VPS (Ubuntu 24.04)
  Internet ─HTTPS─▶ Caddy (api-gateway.ha2cm.com) ─▶ 127.0.0.1:6666 Node ─TCP thẳng─▶ 103.247.205.15:19000

Máy local (Windows, khi phát triển)
  Node local ─▶ 127.0.0.1:1080 ══ SSH tunnel (user `tunnel`) ══▶ VPS ─▶ 103.247.205.15:19000
```

- **Trên VPS:** app gọi thẳng máy chủ TCP, không dùng proxy (`SOCKS_PROXY_URL` để trống).
- **Ở máy local:** app đi qua tunnel SOCKS tới VPS, nên máy chủ TCP thấy cùng IP với bản chạy trên VPS.
- **User `tunnel` trên VPS:** không có shell, chỉ đăng nhập được bằng SSH key, và chỉ được mở kết nối tới đúng `TCP_SERVER_HOST:TCP_SERVER_PORT`.

Các file cấu hình nằm trong thư mục `deploy/`:

| File                    | Vai trò                                            |
| ----------------------- | -------------------------------------------------- |
| `setup-vps.sh`          | Script cài đặt toàn bộ, chạy lại nhiều lần được    |
| `login-tcp-api.service` | Dịch vụ systemd chạy app, tự khởi động lại khi lỗi |
| `Caddyfile`             | Reverse proxy + HTTPS tự động cho domain           |
| `sshd-tunnel.conf`      | Giới hạn quyền SSH của user `tunnel`               |

## 1. Chuẩn bị

- **VPS:** Ubuntu 24.04 LTS, 1 vCPU, 1 GB RAM, 10–20 GB SSD là đủ. Nên chọn vị trí gần máy chủ TCP để độ trễ thấp.
- **DNS:** tạo bản ghi `A` `api-gateway.ha2cm.com` trỏ về IP của VPS. Nếu dùng Cloudflare, để chế độ **DNS only** (đám mây xám) cho tới khi Caddy cấp xong chứng chỉ.
- **SSH key cho tunnel:** tạo trên máy local Windows (PowerShell):

```powershell
ssh-keygen -t ed25519 -f "$HOME\.ssh\login_tcp_tunnel" -C "login-tcp-tunnel"
Get-Content "$HOME\.ssh\login_tcp_tunnel.pub"
```

Dòng in ra (bắt đầu bằng `ssh-ed25519`) là public key, dùng ở bước 3.

## 2. Đưa code lên VPS

SSH vào VPS bằng tài khoản quản trị, rồi:

```bash
sudo apt-get update && sudo apt-get install -y git
sudo git clone https://github.com/mavietha7z/LoginTCPApp_NodeJS.git /opt/login-tcp-api
```

Nếu repo để private, GitHub sẽ hỏi đăng nhập. Dùng Personal Access Token có quyền đọc repo, hoặc tạo deploy key cho VPS.

## 3. Chạy script cài đặt

```bash
sudo DOMAIN=api-gateway.ha2cm.com \
     TUNNEL_PUBLIC_KEY="ssh-ed25519 AAAA...dán-public-key... login-tcp-tunnel" \
     bash /opt/login-tcp-api/deploy/setup-vps.sh
```

Script sẽ:

1. Cài Node.js 24, Caddy, ufw.
2. Tạo user `logintcp` (chạy app) và `tunnel` (chỉ dùng cho SOCKS tunnel).
3. Tạo `/opt/login-tcp-api/.env` nếu chưa có: sinh `API_KEY` ngẫu nhiên, đặt `HTTP_HOST=127.0.0.1`, `HTTP_PORT=6666`. Nếu `SOCKS_PROXY_URL` đang bật thì tắt đi.
4. Cài và khởi động dịch vụ `login-tcp-api`.
5. Cấu hình Caddy cho domain. HTTPS tự cấp khi DNS đã trỏ đúng.
6. Bật firewall: chỉ mở cổng SSH đang dùng, 80 và 443.
7. Kiểm tra app có phản hồi `/health`, và VPS có kết nối được tới máy chủ TCP.

Xem `API_KEY` vừa tạo:

```bash
sudo grep ^API_KEY= /opt/login-tcp-api/.env
```

Nên đặt thêm `DEVICE_ID` trong `.env` (xem README) để device ID không phụ thuộc card mạng của VPS, rồi khởi động lại app:

```bash
sudo systemctl restart login-tcp-api
```

## 4. Kiểm tra API trên domain

```bash
curl https://api-gateway.ha2cm.com/health
```

Gọi đăng nhập (dùng tài khoản bạn được phép sử dụng):

```bash
curl -X POST https://api-gateway.ha2cm.com/api/login \
  -H "X-API-Key: <API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"username":"tai-khoan","password":"mat-khau"}'
```

## 5. Dùng tunnel từ máy local

Thêm vào `C:\Users\<bạn>\.ssh\config` (tạo file nếu chưa có):

```text
Host login-tcp-tunnel
    HostName <IP VPS>
    User tunnel
    IdentityFile ~/.ssh/login_tcp_tunnel
    DynamicForward 127.0.0.1:1080
    ServerAliveInterval 30
    ServerAliveCountMax 3
    ExitOnForwardFailure yes
```

Mở tunnel và giữ cửa sổ này chạy:

```powershell
ssh -N login-tcp-tunnel
```

Lệnh không in gì là tunnel đang chạy. Đóng cửa sổ là tunnel tắt.

Trong `.env` ở máy local, bật proxy rồi chạy app:

```dotenv
SOCKS_PROXY_URL=socks5h://127.0.0.1:1080
```

```powershell
npm start
```

Kiểm tra cổng tunnel đã mở:

```powershell
Test-NetConnection 127.0.0.1 -Port 1080
```

Tunnel chỉ cho đi tới máy chủ TCP. Truy cập web qua cổng 1080 (ví dụ trình duyệt) sẽ bị từ chối; đó là hành vi đúng.

## 6. Cập nhật code

```bash
cd /opt/login-tcp-api
sudo git pull
sudo systemctl restart login-tcp-api
```

Nếu đổi `TCP_SERVER_HOST` hoặc `TCP_SERVER_PORT`, hoặc sửa file trong `deploy/`, hãy chạy lại `setup-vps.sh` để cập nhật giới hạn đích của tunnel và cấu hình Caddy/systemd.

## 7. Bảo mật nên làm thêm

- **Tắt đăng nhập SSH bằng mật khẩu** cho mọi user, sau khi đã chắc chắn đăng nhập bằng key được: đặt `PasswordAuthentication no` trong `/etc/ssh/sshd_config.d/`, rồi chạy `sudo sshd -t && sudo systemctl reload ssh`.
- **Giới hạn IP gọi API:** nếu chỉ backend của bạn gọi API, bỏ comment khối `@notAllowed` trong `/etc/caddy/Caddyfile` rồi chạy `sudo systemctl reload caddy`.
- **Không bật `log` trong Caddyfile:** access log ghi cả header `X-API-Key`.
- **Sửa các lỗi audit trước khi chạy thật:** `error.message` (chứa địa chỉ máy chủ/proxy) đang bị trả ra trường `message` của API, và giới hạn số request đồng thời có thể bị vượt qua.

## 8. Gỡ lỗi

| Hiện tượng                                                 | Kiểm tra                                                                                                                   |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Domain không vào được HTTPS                                | `sudo journalctl -u caddy -n 50`; DNS đã trỏ đúng IP chưa; cổng 80/443 có bị nhà cung cấp chặn không                       |
| API trả 502 hoặc không phản hồi                            | `sudo systemctl status login-tcp-api`, `sudo journalctl -u login-tcp-api -n 50`                                            |
| Đăng nhập trả `code: -5`                                   | VPS tới máy chủ TCP: `nc -vz 103.247.205.15 19000`; ở local: tunnel còn chạy không                                         |
| `ssh -N login-tcp-tunnel` báo `Permission denied`          | Public key đã nằm trong `/home/tunnel/.ssh/authorized_keys` chưa; đường dẫn `IdentityFile` đúng chưa                       |
| Tunnel mở được nhưng app local lỗi `SOCKS5 connect failed` | `TCP_SERVER_HOST:TCP_SERVER_PORT` ở local khác với giá trị trên VPS (PermitOpen chặn); chạy lại `setup-vps.sh` sau khi đổi |
