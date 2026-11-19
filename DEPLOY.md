# Triển khai lên VPS

```text
Người dùng ─HTTPS─▶ Cloudflare ─HTTPS (Full strict)─▶ Caddy (VPS) ─▶ Node 127.0.0.1:6666 ─SOCKS5 (nestproxy)─▶ 103.247.205.15:19000
```

Deploy bằng **một lệnh** từ máy Windows (mở **Git Bash** trong thư mục dự án):

```bash
bash deploy.sh
```

Script hỏi **mật khẩu VPS** (một lần), gửi code trong thư mục này lên VPS `103.68.84.27`, thay code cũ ở `/opt/login-tcp-api` (**giữ nguyên file `.env` trên VPS**), cài những gì còn thiếu và khởi động lại app. Không cần git push trước. Cuối cùng script kiểm tra `https://api-gateway.ha2cm.com/health`.

Từ PowerShell thì chạy:

```powershell
& "C:\Program Files\Git\bin\bash.exe" deploy.sh
```

## Chuẩn bị cho lần deploy đầu tiên

1. **Cloudflare:** bản ghi `A` `api-gateway` trỏ về `103.68.84.27`, bật **Proxied** (đám mây cam). **SSL/TLS** chọn **Full (strict)**, bật **Always Use HTTPS**.
2. **Chứng chỉ Origin:** Cloudflare → **SSL/TLS** → **Origin Server** → **Create Certificate** (RSA 2048, 15 năm). Lưu hai ô vào máy local (thư mục này không bị commit):
    - Ô _Origin Certificate_ → `deploy/secrets/origin.pem`
    - Ô _Private Key_ → `deploy/secrets/origin.key` (chỉ hiện một lần, copy ngay)
3. **proxy_key nestproxy:** truyền khi deploy lần đầu:

```bash
NESTPROXY_PROXY_KEY='<proxy_key>' bash deploy.sh
```

Các lần sau chỉ cần `bash deploy.sh`: chứng chỉ và `proxy_key` đã nằm trên VPS.

## Các thao tác thường dùng (trên VPS)

Xem API key:

```bash
grep ^API_KEY= /opt/login-tcp-api/.env
```

Sửa cấu hình (ví dụ `NESTPROXY_ROTATE_SECONDS`, `DEVICE_ID`), lưu rồi khởi động lại:

```bash
nano /opt/login-tcp-api/.env
```

```bash
systemctl restart login-tcp-api
```

Xem log app:

```bash
journalctl -u login-tcp-api -f
```

Đổi `proxy_key` nestproxy: chạy lại từ máy local `NESTPROXY_PROXY_KEY='<key mới>' bash deploy.sh` (dùng `none` để tắt proxy).

## Proxy nestproxy

- Mỗi lượt đăng nhập lấy proxy SOCKS5 từ nestproxy theo `proxy_key`. Mỗi IP dùng `NESTPROXY_ROTATE_SECONDS` giây (mặc định và tối thiểu 60), hết hạn thì lượt kế tiếp xin IP mới, không dùng IP cũ nữa. Đổi IP chỉ xảy ra khi có request.
- Nestproxy báo chưa được đổi (HTTP 429) thì dùng tiếp IP cũ tới hết `retryAfter`. Nestproxy không trả được proxy thì lượt đăng nhập trả `code: -5`, không gọi thẳng.

## Gỡ lỗi

| Hiện tượng                                | Kiểm tra                                                                               |
| ----------------------------------------- | -------------------------------------------------------------------------------------- |
| Script dừng ở "Chưa có chứng chỉ Origin"  | Đặt `origin.pem` / `origin.key` vào `deploy/secrets/` rồi chạy lại `deploy.sh`         |
| Cloudflare lỗi **526**                    | Chứng chỉ trong `deploy/secrets/` có phải Origin Certificate của domain này không      |
| Cloudflare lỗi **521** / **522**          | `systemctl status caddy`; `ufw status` có dải IP Cloudflare ở cổng 443 không           |
| `ERR_TOO_MANY_REDIRECTS` hoặc lỗi **525** | Cloudflare chưa để **Full (strict)**                                                   |
| API trả 502                               | `journalctl -u login-tcp-api -n 50`                                                    |
| Đăng nhập trả `code: -5`                  | Xem `message`; cuối `deploy.sh` có dòng kiểm tra kết nối tới máy chủ TCP qua nestproxy |

## Bảo mật nên làm

- Không bật `log` trong Caddyfile: access log ghi cả header `X-API-Key`.
- Chỉ backend của bạn gọi API thì bỏ comment khối `@notAllowed` trong `deploy/Caddyfile` (điền IP backend) rồi deploy lại.
- Sửa lỗi `message` trả ra nguyên lỗi kỹ thuật (có thể lộ địa chỉ máy chủ/proxy) trước khi cho người khác dùng.
