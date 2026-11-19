# README – Setup & Deploy production `api-gateway.ha2cm.com` từ VPS mới đến `./deploy.sh`

> **Mục tiêu:** đây là tài liệu vận hành từng bước cho production `api-gateway.ha2cm.com` (LoginTCP API) trên VPS `103.68.84.27`. Cài VPS **một lần** theo Phần A–G, sau đó mỗi lần sửa code chỉ cần chạy `./deploy.sh`. Mỗi bước đều cố gắng trả lời 4 câu hỏi:
>
> 1. **Cần sửa/thay giá trị nào?**
> 2. **Chạy lệnh nào?**
> 3. **Output nào chứng minh bước đó thành công?**
> 4. **Nếu output khác thì kiểm tra ở đâu?**
>
> Domain, IP, đường dẫn, port, tên service trong README là giá trị thật của production; chỉ secret còn để dạng placeholder `<...>`. Phần N ở cuối mô tả API và cách phát triển local.

## Cách đọc README này

Chỉ secret còn để dạng `<...>`. Không copy nguyên placeholder lên server, không ghi giá trị thật của secret vào README, Git, chat hoặc shell history nếu không cần:

| Placeholder             | Ý nghĩa                                                                          |
| ----------------------- | -------------------------------------------------------------------------------- |
| `<API_KEY>`             | Khóa bảo vệ API (`X-API-Key`), sinh bằng `openssl rand -hex 32` (mục 14)         |
| `<NESTPROXY_PROXY_KEY>` | `proxy_key` của nestproxy.com, lấy trên trang quản lý nestproxy (mục 14)         |
| `<DEPLOY_PASSWORD>`     | Password SSH của user `deploy`, sinh bằng `openssl rand -base64 24` (mục 6)      |
| `<ADMIN_IP>`            | IP cố định của máy quản trị nếu muốn giới hạn SSH (mục 5)                        |
| `<repo-root>`           | Thư mục repository trên máy deploy (Git Bash: `/d/Workspace/LoginTCPApp_NodeJS`) |
| `<release-id>`          | Tên release dạng `YYYYMMDD-HHMMSS` do `deploy.sh` tạo                            |

### Quy ước trạng thái

- `THAY:` giá trị bạn phải sửa trước khi chạy.
- `CHẠY:` lệnh thực tế.
- `THÀNH CÔNG KHI:` output hoặc trạng thái phải nhìn thấy.
- `NẾU FAIL:` bước kiểm tra tiếp theo.
- `KHÔNG ĐƯỢC:` lỗi cấu hình dễ gây hỏng production.

---

## 0. Thông số production `api-gateway.ha2cm.com`

Bảng đối chiếu chính của toàn bộ README:

| Thông số        | Giá trị                                                         | Dùng ở đâu                            |
| --------------- | --------------------------------------------------------------- | ------------------------------------- |
| IP VPS          | `103.68.84.27`                                                  | SSH, DNS Cloudflare                   |
| Domain          | `api-gateway.ha2cm.com`                                         | Cloudflare, Nginx, chứng chỉ Origin   |
| OS              | Ubuntu 24.04 LTS                                                | VPS                                   |
| Cấu hình VPS    | tối thiểu 1 vCPU / 1 GB RAM / 10 GB SSD (mục 3)                 | VPS                                   |
| Node.js         | 24.x, source yêu cầu `>=22.12`                                  | VPS + máy deploy                      |
| Nginx           | gói `nginx` của Ubuntu (1.24.x)                                 | Reverse proxy                         |
| App dir         | `/srv/apps/api-gateway.ha2cm.com`                               | release/shared/runtime                |
| App port        | `6666` (chỉ listen `127.0.0.1`)                                 | Node + Nginx upstream                 |
| Service         | `login-tcp-api.service`                                         | systemd + `deploy.sh`                 |
| Env production  | `/srv/apps/api-gateway.ha2cm.com/shared/.env` (mode 600)        | systemd `--env-file`                  |
| Nginx vhost     | `/etc/nginx/sites-available/api-gateway.ha2cm.com.conf`         | Nginx                                 |
| Nginx log       | `/var/log/nginx/api-gateway.ha2cm.com.access.log`, `.error.log` | Nginx                                 |
| Sudoers         | `/etc/sudoers.d/login-tcp-api-deploy`                           | quyền `sudo -n` của `deploy`          |
| Certificate     | `/etc/ssl/cloudflare/api-gateway.ha2cm.com.pem` + `.key`        | Nginx (Cloudflare Origin Certificate) |
| Cloudflare      | Proxied + SSL/TLS Full (strict)                                 | DNS, TLS, WAF                         |
| API             | `POST https://api-gateway.ha2cm.com/api/login/garena`           | Backend thenhanh.vn gọi               |
| Gọi máy chủ TCP | `103.247.205.15:19000` qua proxy SOCKS5 của nestproxy           | `NESTPROXY_PROXY_KEY`                 |
| Deploy          | `./deploy.sh` ở `<repo-root>`, SSH password user `deploy`       | release symlink + health + rollback   |

> Secret/password/token không ghi vào README, Git, chat hoặc shell history nếu không cần. Lưu ngoài VPS (mục 14.1).

---

## 1. Kiến trúc triển khai

```text
Backend thenhanh.vn (máy gọi máy)
    │
    │ HTTPS POST /api/login/garena + X-API-Key
    ▼
Cloudflare (Proxied, Full strict)
    │
    │ HTTPS 443, UFW chỉ nhận 443 từ dải IP Cloudflare (mục 11)
    ▼
Nginx :443 (103.68.84.27), Cloudflare Origin Certificate
    │
    ▼
Node.js 127.0.0.1:6666 (login-tcp-api.service)
    │
    │ TCP qua proxy SOCKS5 (nestproxy, đổi IP mỗi NESTPROXY_ROTATE_SECONDS giây)
    ▼
Máy chủ TCP 103.247.205.15:19000
```

Cây thư mục trên VPS:

```text
/srv/apps/api-gateway.ha2cm.com/
├── releases/
│   └── <release-id>/
│       ├── server.js, package.json, src/
│       ├── RELEASE               # commit, tests, thời điểm build
│       └── .env -> ../../shared/.env
├── current -> releases/<release-id>
└── shared/
    └── .env                      # mode 600, deploy.sh không bao giờ ghi đè
```

App không có dependency npm, không database, không ghi file: mỗi release chỉ gồm `server.js`, `package.json`, `src/` và file `RELEASE`.

---

## 2. Thông số source hiện tại

```text
Node.js >= 22.12 (ES Module, không dependency npm)
HTTP: node:http, chỉ POST /api/login/garena và GET /health
Một process duy nhất (giới hạn MAX_CONCURRENT_LOGINS lượt đăng nhập song song)
```

Khi khởi động, `src/configuration.js` kiểm tra biến môi trường; sai thì app in `Startup failed: ...` và thoát, không mở port. `deploy.sh` chạy trước bước kiểm tra này với `shared/.env` thật trước khi chuyển release (mục 19).

---

# PHẦN A – CÀI MỚI MỘT VPS

## 3. Cấu hình VPS production

API này nhẹ (không database, không build): **1 vCPU / 1 GB RAM / 10 GB SSD, Ubuntu 24.04 LTS** là đủ. Nếu nhà cung cấp cho chọn hệ điều hành khi reset VPS, chọn **Ubuntu 24.04 LTS (64-bit)**.

**CHẠY** (sau khi SSH vào ở mục 4):

```bash
echo "=== OS ==="
grep VERSION_ID /etc/os-release

echo "=== CPU ==="
nproc

echo "=== RAM ==="
free -h

echo "=== DISK ==="
df -h /
```

**THÀNH CÔNG KHI:**

- `VERSION_ID="24.04"`;
- `nproc` in từ `1` trở lên;
- `free -h`, dòng `Mem:` cột `total` từ khoảng `900Mi` trở lên;
- `df -h /`, cột `Avail` từ `5G` trở lên.

**NẾU FAIL:** OS khác `24.04` thì cài lại VPS bằng Ubuntu 24.04 LTS từ trang quản lý của nhà cung cấp; README không hỗ trợ bản khác.

---

## 4. Cập nhật Ubuntu và cài package nền

SSH bằng `root` lần đầu (password do nhà cung cấp VPS cấp).

**CHẠY:**

```bash
ssh root@103.68.84.27
```

**THÀNH CÔNG KHI:** prompt chuyển sang VPS, ví dụ:

```text
root@instance-name:~#
```

**NẾU FAIL:**

- `Connection timed out` → kiểm tra IP/firewall của nhà cung cấp.
- `Permission denied` → kiểm tra password root.
- `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!` sau khi reset VPS → xóa host key cũ ở **máy local** rồi SSH lại:

```bash
ssh-keygen -R 103.68.84.27
```

Đổi password root ngay (password cũ có thể đã lộ qua email/chat):

```bash
passwd
```

Cập nhật hệ thống:

```bash
apt update
apt upgrade -y
```

Cài package:

```bash
apt install -y \
  nginx \
  curl \
  ca-certificates \
  gnupg \
  ufw \
  openssl
```

Bật Nginx:

```bash
systemctl enable nginx
systemctl start nginx
systemctl status nginx --no-pager
```

**THÀNH CÔNG KHI:** status có:

```text
Active: active (running)
```

**NẾU FAIL:**

```bash
journalctl -u nginx -n 100 --no-pager
nginx -t
```

### 4.1. Tự cập nhật bản vá bảo mật và đồng bộ giờ

```bash
apt install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
cat /etc/apt/apt.conf.d/20auto-upgrades
```

Khi `dpkg-reconfigure` hỏi, chọn `Yes`.

**THÀNH CÔNG KHI:** file có:

```text
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
```

Kiểm tra đồng hồ hệ thống đồng bộ NTP (timestamp trong packet gửi máy chủ TCP lấy từ giờ hệ thống):

```bash
timedatectl
```

**THÀNH CÔNG KHI:**

```text
System clock synchronized: yes
NTP service: active
```

**NẾU FAIL:**

```bash
timedatectl set-ntp true
systemctl status systemd-timesyncd --no-pager
```

`Time zone: Etc/UTC` là **đúng**, không cần đổi. Log `journalctl` và Nginx hiện giờ UTC, tức **chậm 7 giờ** so với giờ Việt Nam.

---

## 5. Firewall

IP origin `103.68.84.27` có trong README và `deploy.sh`, nên phải coi như công khai. Vì vậy:

- SSH `22` mở (hoặc chỉ cho IP quản trị cố định nếu có);
- 443 **chỉ** nhận từ dải IP Cloudflare (script ở mục 11 sinh rule, timer mục 11.2 làm mới hằng tuần);
- 80 và mọi port khác đóng (Cloudflare Full strict chỉ gọi origin qua 443).

Đặt default policy và cho SSH **trước khi** bật UFW để không tự khóa mình khỏi VPS:

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw enable
ufw status verbose
```

Nếu có IP quản trị cố định, có thể thay `ufw allow OpenSSH` bằng rule giới hạn nguồn. Máy chạy `./deploy.sh` cũng phải nằm trong danh sách; IP nhà mạng động thì giữ `OpenSSH` mở và dựa vào fail2ban (mục 6.2):

```bash
ufw allow from <ADMIN_IP> to any port 22 proto tcp comment 'ssh-admin'
```

**KHÔNG ĐƯỢC** chạy `ufw allow 'Nginx Full'`, `ufw allow 80,443/tcp` hoặc mở port `6666`.

**THÀNH CÔNG KHI:** `ufw status verbose` có:

```text
Status: active
Default: deny (incoming), allow (outgoing), ...
22/tcp (OpenSSH)           ALLOW IN    Anywhere
```

và sau mục 11 có thêm các dòng `443/tcp ALLOW IN <dải IP Cloudflare> # cloudflare-web`.

---

## 6. Tạo user `deploy`

`deploy.sh` đăng nhập bằng user `deploy`, không dùng `root`.

```bash
adduser deploy
usermod -aG sudo deploy
```

Khi `adduser` hỏi password, dùng password mạnh (`openssl rand -base64 24`) và lưu vào password manager; đây là `<DEPLOY_PASSWORD>` nhập mỗi lần chạy `./deploy.sh`. Các câu hỏi Full Name/Room… nhấn Enter bỏ qua.

Kiểm tra:

```bash
id deploy
```

**THÀNH CÔNG KHI:**

```text
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),27(sudo)
```

Mở **terminal mới** ở máy local và đăng nhập:

```bash
ssh deploy@103.68.84.27
```

Test:

```bash
whoami
sudo whoami
```

Mong đợi:

```text
deploy
root
```

### 6.1. Cho phép SSH bằng password

`deploy.sh` dùng password mode. Kiểm tra SSH server cho phép password:

```bash
sudo sshd -T | grep passwordauthentication
```

**THÀNH CÔNG KHI:**

```text
passwordauthentication yes
```

Nếu trả `passwordauthentication no`:

```bash
sudo tee /etc/ssh/sshd_config.d/00-deploy-password.conf >/dev/null <<'EOF_SSH'
PasswordAuthentication yes
EOF_SSH

sudo sshd -t
sudo systemctl reload ssh
sudo sshd -T | grep passwordauthentication
```

> `sshd` lấy giá trị **đầu tiên** gặp được cho mỗi option; các file trong `/etc/ssh/sshd_config.d/` được đọc theo thứ tự tên. Image cloud thường có `50-cloud-init.conf` đặt `PasswordAuthentication no`, nên file của mình đặt tiền tố `00-`. Luôn xác nhận giá trị hiệu lực bằng `sshd -T`.

### 6.2. SSH hardening

User `deploy` nằm trong group `sudo` và đăng nhập bằng password, nên **lộ password `deploy` = lộ quyền root**. Bắt buộc:

- không cho `root` đăng nhập SSH;
- chỉ cho user `deploy` đăng nhập;
- chặn brute-force bằng fail2ban.

Chỉ làm bước này sau khi đã xác nhận ở **terminal mới** `ssh deploy@103.68.84.27` và `sudo whoami` trả `root`. Giữ nguyên phiên `root` đang mở cho tới khi kiểm tra xong.

```bash
sudo tee /etc/ssh/sshd_config.d/00-hardening.conf >/dev/null <<'EOF_SSH'
PermitRootLogin no
AllowUsers deploy
EOF_SSH

sudo sshd -t
sudo systemctl reload ssh
sudo sshd -T | grep -E '^(permitrootlogin|allowusers|passwordauthentication) '
```

**THÀNH CÔNG KHI:**

```text
permitrootlogin no
allowusers deploy
passwordauthentication yes
```

và terminal mới vẫn `ssh deploy@103.68.84.27` được, còn `ssh root@103.68.84.27` bị từ chối.

Cài fail2ban cho `sshd`:

```bash
sudo apt install -y fail2ban

sudo tee /etc/fail2ban/jail.d/sshd.local >/dev/null <<'EOF_JAIL'
[sshd]
enabled = true
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
EOF_JAIL

sudo systemctl enable --now fail2ban
sudo systemctl restart fail2ban
sleep 3
sudo fail2ban-client status sshd
```

**THÀNH CÔNG KHI:** `fail2ban-client status sshd` in `Status for the jail: sshd`.

> Nhập sai password nhiều lần khi chạy `./deploy.sh` cũng có thể bị ban IP máy deploy. Gỡ ban từ console của nhà cung cấp VPS hoặc một phiên SSH khác: `sudo fail2ban-client set sshd unbanip <IP máy deploy>`.

Từ đây trở đi, các lệnh trong README chạy bằng user `deploy` (có `sudo` khi cần).

---

## 7. Tạo swap

VPS 1 GB RAM nên có **1 GB swap** để chống OOM khi `apt upgrade` chạy cùng app. VPS từ 2 GB RAM trở lên có thể bỏ qua.

```bash
swapon --show
```

Nếu đã có swap, **không tạo lại**. Nếu chưa có:

```bash
sudo fallocate -l 1G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
grep -F '/swapfile none swap sw 0 0' /etc/fstab || \
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
echo 'vm.swappiness=10' | sudo tee /etc/sysctl.d/99-swappiness.conf
sudo sysctl --system >/dev/null
```

**THÀNH CÔNG KHI:** `swapon --show` có dòng `/swapfile file 1024M`.

---

## 8. Reboot nếu Ubuntu báo pending kernel upgrade

```bash
[ -f /var/run/reboot-required ] && sudo reboot
```

Đăng nhập lại bằng `ssh deploy@103.68.84.27` và kiểm tra `uname -r`.

---

# PHẦN B – CÀI NODE.JS

## 9. Cài Node.js 24 system-wide

```bash
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
sudo apt install -y nodejs
node -v
which node
```

**THÀNH CÔNG KHI:**

```text
v24.x.x
/usr/bin/node
```

`login-tcp-api.service` (mục 15) gọi đúng `/usr/bin/node`. `deploy.sh` kiểm tra Node VPS đạt `engines.node` (`>=22.12`) trong remote preflight.

---

# PHẦN C – CLOUDFLARE

## 10. DNS và SSL trên Cloudflare

Trong Cloudflare, zone `ha2cm.com` → **DNS → Records**:

| Type | Name          | Content        | Proxy status              |
| ---- | ------------- | -------------- | ------------------------- |
| `A`  | `api-gateway` | `103.68.84.27` | **Proxied** (đám mây cam) |

### 10.1. SSL mode

**SSL/TLS → Overview** chọn **Full (strict)**. **SSL/TLS → Edge Certificates** bật **Always Use HTTPS**.

**KHÔNG ĐƯỢC** dùng **Flexible**: Cloudflare sẽ gọi origin bằng HTTP không mã hóa (request có username/password, response có `session_key`/`sso_key`), và Nginx ở mục 17 không nghe cổng 80.

### 10.2. Không chặn request máy gọi máy

`/api/login/garena` được backend thenhanh.vn gọi từ server, không phải trình duyệt, nên không vượt qua được challenge/JavaScript của Cloudflare:

- **Security → Bots**: tắt **Bot Fight Mode**;
- **Security → WAF → Custom rules** → **Create rule**:
    - Rule name: `Skip API login`;
    - Field `URI Path`, Operator `equals`, Value `/api/login/garena`;
    - Action **Skip**, chọn tất cả các mục còn lại (_All remaining custom rules_, _Rate limiting rules_, _All managed rules_, _All Super Bot Fight Mode Rules_ nếu có);
    - **Deploy**, kéo rule lên **First**;
- không bật **Under Attack Mode** cho domain này.

API đã tự bảo vệ bằng `X-API-Key`, giới hạn đồng thời và (tùy chọn) giới hạn IP ở Nginx (mục 17).

---

## 11. Chỉ nhận traffic từ Cloudflare

Một script sinh từ danh sách IP chính thức của Cloudflare:

- `/etc/nginx/conf.d/cloudflare-realip.conf` (`set_real_ip_from` + `real_ip_header CF-Connecting-IP`), để log Nginx ghi IP thật của người gọi;
- rule UFW cổng 443 chỉ từ các dải đó (comment `cloudflare-web`).

Tạo script:

```bash
sudo tee /usr/local/sbin/login-tcp-api-cloudflare-ips.sh >/dev/null <<'EOF_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
umask 022

REALIP_CONF=/etc/nginx/conf.d/cloudflare-realip.conf
UFW_COMMENT=cloudflare-web
WORK_DIR="$(mktemp -d)"
trap 'rm -rf -- "$WORK_DIR"' EXIT

curl -fsS --max-time 20 https://www.cloudflare.com/ips-v4 -o "$WORK_DIR/ips-v4"
curl -fsS --max-time 20 https://www.cloudflare.com/ips-v6 -o "$WORK_DIR/ips-v6"

# File của Cloudflare có thể thiếu newline cuối; thêm newline để hai danh sách không dính dòng.
{ cat "$WORK_DIR/ips-v4"; echo; cat "$WORK_DIR/ips-v6"; echo; } | tr -d '\r' | sed '/^$/d' > "$WORK_DIR/ips"

# Không áp dụng danh sách rỗng hoặc sai dạng, tránh tự chặn toàn bộ traffic web.
[[ "$(wc -l < "$WORK_DIR/ips")" -ge 10 ]] || { echo "Danh sách IP Cloudflare quá ngắn" >&2; exit 1; }
if grep -vqE '^[0-9A-Fa-f:.]+/[0-9]+$' "$WORK_DIR/ips"; then
    echo "Danh sách IP Cloudflare sai dạng" >&2
    exit 1
fi

# Nginx: ghi file mới, nginx -t PASS mới reload; FAIL thì khôi phục file cũ.
{
    echo "# Sinh bởi /usr/local/sbin/login-tcp-api-cloudflare-ips.sh, không sửa tay."
    while IFS= read -r range; do
        echo "set_real_ip_from $range;"
    done < "$WORK_DIR/ips"
    echo "real_ip_header CF-Connecting-IP;"
} > "$WORK_DIR/realip.conf"

if [[ -f "$REALIP_CONF" ]]; then
    cp "$REALIP_CONF" "$WORK_DIR/realip.conf.old"
fi
install -m 644 "$WORK_DIR/realip.conf" "$REALIP_CONF"
if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx
else
    if [[ -f "$WORK_DIR/realip.conf.old" ]]; then
        install -m 644 "$WORK_DIR/realip.conf.old" "$REALIP_CONF"
    else
        rm -f "$REALIP_CONF"
    fi
    echo "nginx -t FAIL với danh sách mới; đã khôi phục cấu hình cũ" >&2
    exit 1
fi

# UFW: thêm dải mới trước (rule đã có thì UFW bỏ qua), rồi xóa dải không còn trong danh sách.
while IFS= read -r range; do
    ufw allow proto tcp from "$range" to any port 443 comment "$UFW_COMMENT" >/dev/null
done < "$WORK_DIR/ips"

ufw status | awk -v comment="# $UFW_COMMENT" 'index($0, comment) { for (i = 1; i <= NF; i++) if ($i == "#") print $(i - 1) }' \
    | sort -u | while IFS= read -r existing_range; do
        if ! grep -qxF "$existing_range" "$WORK_DIR/ips"; then
            ufw delete allow proto tcp from "$existing_range" to any port 443 >/dev/null || true
        fi
    done

echo "Cloudflare IP: $(wc -l < "$WORK_DIR/ips") dải, Nginx realip + UFW 443 đã cập nhật"
EOF_SCRIPT

sudo chmod 755 /usr/local/sbin/login-tcp-api-cloudflare-ips.sh
sudo /usr/local/sbin/login-tcp-api-cloudflare-ips.sh
sudo ufw status verbose
```

**THÀNH CÔNG KHI:** script in `Cloudflare IP: <số> dải, Nginx realip + UFW 443 đã cập nhật` và `ufw status verbose` có nhiều dòng `443/tcp ALLOW IN <dải IP> # cloudflare-web`, SSH vẫn mở.

**NẾU FAIL:** `nginx -t FAIL` → chạy `sudo nginx -t` để xem dòng lỗi; `curl` lỗi → VPS chưa ra được Internet, kiểm tra DNS/mạng của nhà cung cấp.

### 11.1. Kiểm tra chặn truy cập thẳng origin

Chạy **trên máy ngoài VPS** (Git Bash ở máy cá nhân), **không** chạy trong phiên SSH của VPS:

```bash
curl -sS --max-time 10 -o /dev/null -w '%{http_code}\n' --resolve api-gateway.ha2cm.com:443:103.68.84.27 https://api-gateway.ha2cm.com/health
```

**THÀNH CÔNG KHI:** lệnh chờ đủ khoảng 10 giây rồi in:

```text
curl: (28) Connection timed out after 10002 milliseconds
000
```

nghĩa là UFW đã chặn IP không thuộc Cloudflare (đúng).

**NẾU FAIL:** in `200` hoặc phản hồi ngay → kết nối đã tới Nginx, UFW chưa chặn; xem lại `sudo ufw status verbose` và gỡ rule mở 443 cho mọi IP.

### 11.2. Timer làm mới IP Cloudflare

```bash
sudo tee /etc/systemd/system/login-tcp-api-cloudflare-ips.service >/dev/null <<'EOF_UNIT'
[Unit]
Description=Làm mới dải IP Cloudflare cho Nginx realip và UFW
Wants=network-online.target
After=network-online.target nginx.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/login-tcp-api-cloudflare-ips.sh
EOF_UNIT

sudo tee /etc/systemd/system/login-tcp-api-cloudflare-ips.timer >/dev/null <<'EOF_UNIT'
[Unit]
Description=Làm mới dải IP Cloudflare hằng tuần

[Timer]
OnCalendar=weekly
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF_UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now login-tcp-api-cloudflare-ips.timer
systemctl list-timers login-tcp-api-cloudflare-ips.timer --no-pager
```

**THÀNH CÔNG KHI:** `list-timers` có dòng `login-tcp-api-cloudflare-ips.timer` với thời điểm `NEXT`.

---

# PHẦN D – CHỨNG CHỈ ORIGIN

## 12. Cloudflare Origin Certificate

Chứng chỉ Origin chỉ được Cloudflare tin (đủ cho Full strict), hạn 15 năm, không cần gia hạn hay API token.

Trong Cloudflare: zone `ha2cm.com` → **SSL/TLS → Origin Server → Create Certificate**:

- **Generate private key and CSR with Cloudflare**, key type **RSA (2048)**;
- Hostnames: `api-gateway.ha2cm.com` (hoặc giữ mặc định `*.ha2cm.com`, `ha2cm.com`);
- Validity: **15 years** → **Create**.

Cloudflare hiện hai ô **Origin Certificate** và **Private Key**. **Private Key chỉ hiện một lần**, copy ngay.

Trên VPS, dán từng ô vào file tương ứng (dán xong `Ctrl+O`, `Enter`, `Ctrl+X`):

```bash
sudo mkdir -p /etc/ssl/cloudflare
sudo nano /etc/ssl/cloudflare/api-gateway.ha2cm.com.pem
sudo nano /etc/ssl/cloudflare/api-gateway.ha2cm.com.key
sudo chmod 644 /etc/ssl/cloudflare/api-gateway.ha2cm.com.pem
sudo chmod 600 /etc/ssl/cloudflare/api-gateway.ha2cm.com.key
```

Kiểm tra chứng chỉ đúng domain và khớp private key:

```bash
sudo openssl x509 -in /etc/ssl/cloudflare/api-gateway.ha2cm.com.pem -noout -checkhost api-gateway.ha2cm.com -enddate
sudo openssl x509 -in /etc/ssl/cloudflare/api-gateway.ha2cm.com.pem -noout -pubkey | openssl sha256
sudo openssl pkey -in /etc/ssl/cloudflare/api-gateway.ha2cm.com.key -pubout | openssl sha256
```

**THÀNH CÔNG KHI:** dòng đầu có `Hostname api-gateway.ha2cm.com does match certificate`, `notAfter` khoảng 15 năm sau, và hai dòng `SHA2-256(stdin)= ...` **giống hệt nhau**.

**NẾU FAIL:** `unable to load certificate` → dán thiếu dòng `-----BEGIN ...-----`/`-----END ...-----`; hai hash khác nhau → dán nhầm private key của chứng chỉ khác, tạo lại chứng chỉ.

---

# PHẦN E – CẤU TRÚC APP TRÊN SERVER

## 13. Tạo thư mục app

```bash
sudo mkdir -p /srv/apps/api-gateway.ha2cm.com/releases
sudo mkdir -p /srv/apps/api-gateway.ha2cm.com/shared
sudo chown -R deploy:deploy /srv/apps/api-gateway.ha2cm.com
```

**THÀNH CÔNG KHI:** `ls -l /srv/apps/api-gateway.ha2cm.com` có `releases` và `shared`, owner `deploy deploy`.

---

## 14. Tạo production `shared/.env`

Sinh `API_KEY` mới (**không** dùng lại key cũ đã từng đưa qua chat hoặc Git):

```bash
openssl rand -hex 32
```

Tạo file với quyền 600 rồi mở để điền:

```bash
install -m 600 /dev/null /srv/apps/api-gateway.ha2cm.com/shared/.env
nano /srv/apps/api-gateway.ha2cm.com/shared/.env
```

**THAY** `<API_KEY>` và `<NESTPROXY_PROXY_KEY>`, giữ nguyên các dòng còn lại:

```dotenv
HTTP_HOST=127.0.0.1
HTTP_PORT=6666
API_KEY=<API_KEY>

TCP_SERVER_HOST=103.247.205.15
TCP_SERVER_PORT=19000

NESTPROXY_PROXY_KEY=<NESTPROXY_PROXY_KEY>
NESTPROXY_ROTATE_SECONDS=60

MAX_RETRIES=3
READ_TIMEOUT_MS=5000
CONNECT_TIMEOUT_MS=8000
MAX_CONCURRENT_LOGINS=3
RESPONSE_WINDOW_MS=3000
MAX_PACKET_BYTES=1048576
RESPONSE_IDLE_TIMEOUT_MS=500
XTEA_RANDOM_MODE=legacy
```

- Giá trị ghi thô, **không** bọc nháy, **không** comment cuối dòng.
- `HTTP_HOST` phải là `127.0.0.1` và `HTTP_PORT` phải khớp `DEPLOY_ORIGIN_HEALTH_URL` (mặc định `6666`); `deploy.sh` kiểm tra cả hai.
- Ý nghĩa từng biến ở mục 36.

Kiểm tra:

```bash
stat -c '%a %U' /srv/apps/api-gateway.ha2cm.com/shared/.env
grep -c '<' /srv/apps/api-gateway.ha2cm.com/shared/.env
```

**THÀNH CÔNG KHI:** dòng đầu `600 deploy`, dòng hai `0` (không còn placeholder).

### 14.1. Bảo quản secret

- Lưu `API_KEY` và `NESTPROXY_PROXY_KEY` vào password manager ngoài VPS.
- `API_KEY` là giá trị backend thenhanh.vn đặt vào `GARENA_LOGIN_API_KEY`; chỉ gửi qua kênh an toàn, không commit.
- Đổi `API_KEY`: sửa `shared/.env`, `sudo systemctl restart login-tcp-api.service`, rồi cập nhật bên gọi API ngay (key cũ hết hiệu lực khi restart).
- Đổi `NESTPROXY_PROXY_KEY` (ví dụ xoay key trên nestproxy): sửa `shared/.env` rồi restart service như trên.

---

# PHẦN F – SYSTEMD

## 15. Tạo service

```bash
sudo tee /etc/systemd/system/login-tcp-api.service >/dev/null <<'EOF_UNIT'
[Unit]
Description=api-gateway.ha2cm.com LoginTCP API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=deploy
Group=deploy

WorkingDirectory=/srv/apps/api-gateway.ha2cm.com/current
ExecStart=/usr/bin/node --env-file=/srv/apps/api-gateway.ha2cm.com/shared/.env /srv/apps/api-gateway.ha2cm.com/current/server.js

Restart=on-failure
RestartSec=5

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF_UNIT

sudo systemctl daemon-reload
sudo systemctl enable login-tcp-api.service
```

**THÀNH CÔNG KHI:** `systemctl is-enabled login-tcp-api.service` in `enabled`.

Ở VPS mới chưa có `current`, **chưa start**. `deploy.sh` đầu tiên sẽ tạo `current` rồi restart service. Sửa `shared/.env` xong phải `sudo systemctl restart login-tcp-api.service` mới có hiệu lực.

---

## 16. Chỉ cho deploy user restart đúng service

`deploy.sh` gọi `sudo -n` (không hỏi password) cho đúng các lệnh sau: restart service khi deploy/rollback, stop service khi deploy đầu tiên lỗi, đọc journal khi deploy lỗi, kiểm tra cấu hình Nginx. Sudoers phải khớp nguyên văn đường dẫn và tham số:

```bash
sudo tee /etc/sudoers.d/login-tcp-api-deploy >/dev/null <<'EOF_SUDO'
deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart login-tcp-api.service, /usr/bin/systemctl stop login-tcp-api.service
deploy ALL=(root) NOPASSWD: /usr/bin/journalctl -u login-tcp-api.service -n 100 --no-pager
deploy ALL=(root) NOPASSWD: /usr/sbin/nginx -t, /usr/sbin/nginx -T
EOF_SUDO

sudo chmod 440 /etc/sudoers.d/login-tcp-api-deploy
sudo visudo -cf /etc/sudoers.d/login-tcp-api-deploy
```

**THÀNH CÔNG KHI:**

```text
/etc/sudoers.d/login-tcp-api-deploy: parsed OK
```

**KHÔNG ĐƯỢC** cấp `NOPASSWD: ALL` cho `deploy`.

---

# PHẦN G – NGINX

## 17. Nginx config cho `api-gateway.ha2cm.com`

Ẩn phiên bản Nginx và chỉ cho TLS 1.2/1.3 (sửa dòng có sẵn trong `nginx.conf`, không khai báo lần hai):

```bash
sudo sed -i 's/^\s*#\?\s*server_tokens .*/\tserver_tokens off;/' /etc/nginx/nginx.conf
grep -q 'server_tokens off' /etc/nginx/nginx.conf || sudo sed -i '/http {/a \\tserver_tokens off;' /etc/nginx/nginx.conf
sudo sed -i 's/^\s*ssl_protocols .*/\tssl_protocols TLSv1.2 TLSv1.3;/' /etc/nginx/nginx.conf
```

Tạo vhost:

```bash
sudo tee /etc/nginx/sites-available/api-gateway.ha2cm.com.conf >/dev/null <<'EOF_NGINX'
# HTTPS sai SNI (quét IP 103.68.84.27, domain lạ trỏ về VPS): từ chối ở bước TLS handshake.
server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    ssl_reject_handshake on;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name api-gateway.ha2cm.com;

    ssl_certificate     /etc/ssl/cloudflare/api-gateway.ha2cm.com.pem;
    ssl_certificate_key /etc/ssl/cloudflare/api-gateway.ha2cm.com.key;

    # Log mặc định không ghi header (X-API-Key) hay body (username/password).
    access_log /var/log/nginx/api-gateway.ha2cm.com.access.log;
    error_log  /var/log/nginx/api-gateway.ha2cm.com.error.log;

    client_max_body_size 16k;

    # Tùy chọn: chỉ cho IP backend thenhanh.vn gọi API (IP thật lấy từ CF-Connecting-IP, mục 11).
    # Bỏ dấu # ở hai dòng dưới và thay IP.
    # allow 103.68.84.19;
    # deny all;

    location / {
        proxy_pass http://127.0.0.1:6666;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_connect_timeout 5s;
        proxy_read_timeout 60s;
    }
}
EOF_NGINX

sudo ln -sf /etc/nginx/sites-available/api-gateway.ha2cm.com.conf /etc/nginx/sites-enabled/api-gateway.ha2cm.com.conf
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx
```

**THÀNH CÔNG KHI:**

```text
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

**NẾU FAIL:** `cannot load certificate` → xem lại mục 12; `duplicate ... directive` → dòng `server_tokens`/`ssl_protocols` bị khai báo hai lần trong `nginx.conf`, xóa dòng thừa.

Trước lần deploy đầu, `https://api-gateway.ha2cm.com/health` trả lỗi **502** từ Nginx (chưa có app); đó là bình thường.

---

# PHẦN H – DEPLOY MỘT LỆNH

## 18. Chạy `deploy.sh`

Máy deploy (Windows) cần: **Git Bash** (đi kèm Git for Windows), **Node.js >= 22.12**. Chạy ở `<repo-root>`:

```bash
./deploy.sh
```

Từ PowerShell thì chạy:

```powershell
& "C:\Program Files\Git\bin\bash.exe" deploy.sh
```

Mỗi lần deploy chỉ hỏi **một lần** `SSH password cho deploy@103.68.84.27:` (nhập `<DEPLOY_PASSWORD>`, không hiện ký tự). Sau này sửa code: commit rồi chạy lại `./deploy.sh`; `shared/.env` trên VPS được giữ nguyên.

`deploy.sh` đã có sẵn mặc định cho production, **không cần** file cấu hình:

```text
DEPLOY_HOST=103.68.84.27
DEPLOY_DOMAIN=api-gateway.ha2cm.com
DEPLOY_USER=deploy
DEPLOY_APP_DIR=/srv/apps/api-gateway.ha2cm.com
DEPLOY_SERVICE=login-tcp-api.service
DEPLOY_ORIGIN_HEALTH_URL=http://127.0.0.1:6666/health
DEPLOY_PUBLIC_HEALTH_URL=https://api-gateway.ha2cm.com/health
DEPLOY_KEEP_RELEASES=5
```

Chỉ khi cần ghi đè (ví dụ VPS đổi IP), tạo `.deploy/env` (thư mục `.deploy/` đã nằm trong `.gitignore`):

```bash
mkdir -p .deploy
cat > .deploy/env <<'EOF_DEPLOY_ENV'
# Chỉ ghi các biến cần đổi; bỏ dòng để dùng mặc định của deploy.sh.
DEPLOY_HOST=<IP VPS mới>
EOF_DEPLOY_ENV
```

- File chỉ nhận dòng `KEY=VALUE` với đúng các biến `DEPLOY_*` ở trên; script đọc từng dòng, không `source`. Dòng sai dạng hoặc biến lạ làm script dừng.
- Biến truyền trực tiếp khi chạy được ưu tiên hơn file, ví dụ `DEPLOY_KEEP_RELEASES=3 ./deploy.sh`.
- Working tree phải đã commit. Muốn deploy cả thay đổi chưa commit: `DEPLOY_ALLOW_DIRTY=1 ./deploy.sh` (file `RELEASE` ghi `git_dirty=true`).
- `npm test` luôn chạy trước khi đóng gói (vài giây). Chỉ bỏ qua bằng `DEPLOY_SKIP_TESTS=1 ./deploy.sh` khi vừa tự chạy `npm test` cho đúng commit đó.

**THÀNH CÔNG KHI đầu log có dạng:**

```text
==> Preflight
PASS Node v24.x.x (yêu cầu >=22.12.0)
==> npm test
PASS npm test
SSH password cho deploy@103.68.84.27:
==> Remote preflight
PASS Node VPS 24.x.x
PASS SSH deploy@103.68.84.27 / app dirs / .env / Node / systemd / sudoers / Nginx PASS
```

Nếu fail ở `Remote preflight`, **không chạy lại nhiều lần** (sai password nhiều lần sẽ bị fail2ban chặn, mục 6.2). Đọc dòng `ERROR ...` in từ VPS; mỗi dòng ghi mục README cần xem lại.

---

## 19. `deploy.sh` làm gì

```text
Đọc .deploy/env (nếu có) + mặc định api-gateway.ha2cm.com / 103.68.84.27
        ↓
Preflight local: node/npm/tar/ssh/scp/git, working tree sạch,
server.js/package.json/src, Node local >= engines.node
        ↓
npm test (toàn bộ, offline)
        ↓
Hỏi SSH password một lần (SSH_ASKPASS cho các lệnh ssh/scp sau)
        ↓
Remote preflight: releases/ ghi được, shared/.env mode 600, Node VPS,
HTTP_HOST=127.0.0.1, HTTP_PORT khớp origin health URL, API_KEY >= 24 ký tự,
systemd unit có, sudo -n restart được, nginx -t + upstream 127.0.0.1:<PORT>
        ↓
Đóng gói server.js + package.json + src/ + RELEASE (commit, git_dirty, tests)
        ↓
SHA-256 → SCP package lên /tmp
        ↓
Tạo releases/<release-id> (umask 022) → verify SHA-256 → giải nén → CRLF -> LF
        ↓
Link .env -> shared/.env
        ↓
Kiểm tra cấu hình bằng code release mới (loadConfiguration với .env thật)
        ↓
Thử kết nối máy chủ TCP qua nestproxy (lỗi chỉ cảnh báo)
        ↓
Atomic current -> release mới → restart systemd
        ↓
Origin /health retry ~60 giây: phải có "status":"ok"
        ↓
FAIL -> in status + journal, rollback release cũ (restart + health)
PASS -> giữ release mới
        ↓
Public HTTPS health check (fail chỉ cảnh báo)
        ↓
Giữ N release mới nhất (mặc định 5)
```

Lỗi trước bước chuyển `current` thì giữ nguyên `current` và **xóa release dở dang**. Lỗi sau bước chuyển thì in status/journal của service rồi rollback; rollback health PASS thì release lỗi cũng bị xóa. Lần deploy đầu tiên không có release cũ: script dừng service và giữ release lỗi để debug.

### 19.1. Output deploy thành công

Cuối log phải có:

```text
REMOTE ==> TCP connectivity check
PASS TCP 103.247.205.15:19000 (qua nestproxy <IP:port>)
REMOTE ==> Origin health PASS
REMOTE ==> Public health PASS
REMOTE ==> Prune old releases (keep 5)
REMOTE ==> DEPLOY SUCCESS: <release-id>
PASS DEPLOY SUCCESS <release-id> -> https://api-gateway.ha2cm.com
```

### 19.2. Nếu deploy fail

```text
REMOTE ERROR: deploy thất bại.
REMOTE ==> Service status
REMOTE ==> Service journal (last 100 lines)
REMOTE ==> Rollback về /srv/apps/api-gateway.ha2cm.com/releases/<old-release>
REMOTE ==> Rollback health PASS
```

Đọc phần journal để biết lỗi thật (ví dụ `Startup failed: ...` do `shared/.env` sai), sửa rồi chạy lại `./deploy.sh`.

---

# PHẦN I – KIỂM TRA SAU DEPLOY

## 20. Service và API

Trên VPS:

```bash
systemctl status login-tcp-api.service --no-pager
curl -fsS http://127.0.0.1:6666/health
cat /srv/apps/api-gateway.ha2cm.com/current/RELEASE
```

**THÀNH CÔNG KHI:** `Active: active (running)`, health trả `{"status":"ok"}`, `RELEASE` ghi đúng `git_commit` vừa deploy.

Từ máy ngoài (qua Cloudflare):

```bash
curl -fsS https://api-gateway.ha2cm.com/health
```

Gọi thử đăng nhập bằng tài khoản bạn được phép dùng (đọc key/password từ bàn phím để không lưu vào shell history):

```bash
read -r -s -p 'API_KEY: ' API_KEY; echo
read -r -p 'Username: ' LOGIN_USERNAME
read -r -s -p 'Password: ' LOGIN_PASSWORD; echo
curl -sS -X POST https://api-gateway.ha2cm.com/api/login/garena \
  -H "X-API-Key: $API_KEY" \
  -H 'Content-Type: application/json' \
  --data "$(node -e 'console.log(JSON.stringify({ username: process.argv[1], password: process.argv[2] }))' "$LOGIN_USERNAME" "$LOGIN_PASSWORD")"
unset API_KEY LOGIN_USERNAME LOGIN_PASSWORD
```

**THÀNH CÔNG KHI:** JSON có đủ `code`, `uid`, `session_key`, `sso_key`, `message` (mục 35). `code: -1` + `API key không hợp lệ` → sai `X-API-Key`.

Xem log:

```bash
journalctl -u login-tcp-api.service -f
sudo tail -f /var/log/nginx/api-gateway.ha2cm.com.access.log
```

---

# PHẦN J – ROLLBACK THỦ CÔNG

## 21. Xem release hiện tại

```bash
readlink -f /srv/apps/api-gateway.ha2cm.com/current
ls -1 /srv/apps/api-gateway.ha2cm.com/releases | sort -r
cat /srv/apps/api-gateway.ha2cm.com/current/RELEASE
```

## 22. Rollback thủ công

Ví dụ rollback về `releases/20261120-101500`:

```bash
cd /srv/apps/api-gateway.ha2cm.com
ln -s /srv/apps/api-gateway.ha2cm.com/releases/20261120-101500 current.rollback
mv -Tf current.rollback current
sudo systemctl restart login-tcp-api.service
curl -fsS http://127.0.0.1:6666/health
```

`deploy.sh` đã tự rollback khi origin health của release mới thất bại; chỉ làm tay khi release mới chạy được nhưng sai nghiệp vụ.

---

# PHẦN K – TROUBLESHOOTING

## 23. Remote preflight báo `ERROR`

| Dòng `ERROR`                                  | Sửa                                                                 |
| --------------------------------------------- | ------------------------------------------------------------------- |
| `Thiếu thư mục .../releases`                  | Mục 13                                                              |
| `Thiếu .../shared/.env` / `phải có quyền 600` | Mục 14 (`chmod 600 /srv/apps/api-gateway.ha2cm.com/shared/.env`)    |
| `HTTP_HOST=127.0.0.1` / `HTTP_PORT`           | Sửa `shared/.env` (mục 14) hoặc `DEPLOY_ORIGIN_HEALTH_URL` (mục 18) |
| `API_KEY ... giá trị mẫu`                     | Sinh key mới (mục 14)                                               |
| `Chưa có systemd unit`                        | Mục 15                                                              |
| `chưa có quyền sudo -n restart`               | Mục 16 (sudoers phải khớp nguyên văn tên service)                   |
| `nginx -t FAIL` / `Nginx chưa proxy tới`      | Mục 16, 17                                                          |
| `Permission denied (publickey,password)`      | Sai `<DEPLOY_PASSWORD>`; mục 6.1 nếu password mode bị tắt           |

## 24. Bị fail2ban chặn IP

Triệu chứng: `./deploy.sh` hoặc `ssh` báo `Connection timed out`/`Connection refused` sau vài lần nhập sai password. Vào console web của nhà cung cấp VPS, đăng nhập rồi:

```bash
sudo fail2ban-client status sshd
sudo fail2ban-client set sshd unbanip <IP máy deploy>
```

## 25. Cloudflare báo lỗi 52x

| Lỗi     | Kiểm tra                                                                                             |
| ------- | ---------------------------------------------------------------------------------------------------- |
| **521** | Nginx không chạy hoặc UFW chưa mở 443 cho Cloudflare: `systemctl status nginx`, mục 11               |
| **522** | Timeout tới origin: `sudo ufw status verbose` có rule `cloudflare-web` chưa (mục 11)                 |
| **525** | Lỗi TLS handshake: Nginx chưa có `server_name api-gateway.ha2cm.com` trên 443 (mục 17)               |
| **526** | Chứng chỉ không hợp lệ: chứng chỉ trong `/etc/ssl/cloudflare/` không phải Origin của domain (mục 12) |
| **502** | Nginx chạy nhưng app không chạy: `journalctl -u login-tcp-api.service -n 50`                         |

## 26. Đăng nhập trả `code: -5`

`-5` là lỗi kết nối/giải mã. Xem trường `message` và:

```bash
journalctl -u login-tcp-api.service -n 50 --no-pager
```

- Lỗi nestproxy (`Nestproxy ...`): kiểm tra `NESTPROXY_PROXY_KEY` còn hạn trên trang nestproxy; `Nestproxy yêu cầu chờ trước khi cấp IP mới` là đang trong thời gian chờ đổi IP.
- Lỗi SOCKS5/timeout: proxy hiện tại chập chờn; app tự bỏ proxy lỗi, lần gọi sau lấy lại.
- Chạy lại `./deploy.sh` để xem dòng `TCP connectivity check`.

## 27. `current -> current` / `Too many levels of symbolic links`

`current` phải trỏ tới một thư mục trong `releases/`. Sửa bằng rollback thủ công (mục 22) về một release còn tồn tại.

## 28. Git Bash không hỏi password hoặc treo

- Chạy đúng bằng Git Bash (`bash.exe` của Git for Windows), không chạy bằng `bash` của WSL.
- Xóa host key cũ nếu VPS vừa cài lại: `ssh-keygen -R 103.68.84.27`.
- Thử SSH tay `ssh deploy@103.68.84.27`; được thì chạy lại `./deploy.sh`.

---

# PHẦN L – CHECKLIST DEPLOY LẦN ĐẦU

## 29. Checklist

```text
[ ] VPS Ubuntu 24.04 (cài lại sạch), cấu hình đúng (mục 3); passwd root; apt upgrade,
    unattended-upgrades, NTP synchronized (mục 4, 4.1)
[ ] UFW: chỉ SSH mở; 80/6666 đóng (mục 5)
[ ] User deploy + sudo, SSH password mode (mục 6, 6.1)
[ ] PermitRootLogin no, AllowUsers deploy, fail2ban (mục 6.2)
[ ] Swap 1 GB nếu RAM 1 GB (mục 7)
[ ] Node.js 24, /usr/bin/node (mục 9)

[ ] Cloudflare: A api-gateway -> 103.68.84.27 Proxied, SSL/TLS Full (strict), Always Use HTTPS (mục 10, 10.1)
[ ] Bot Fight Mode Off + WAF Skip cho /api/login/garena (mục 10.2)
[ ] cloudflare-realip.conf + UFW 443 chỉ IP Cloudflare + timer làm mới (mục 11, 11.2);
    curl thẳng origin từ máy ngoài VPS timeout 000 (mục 11.1)
[ ] Origin Certificate ở /etc/ssl/cloudflare/, khớp private key (mục 12)

[ ] /srv/apps/api-gateway.ha2cm.com/{releases,shared} owner deploy (mục 13)
[ ] shared/.env mode 600, API_KEY mới, NESTPROXY_PROXY_KEY (mục 14)
[ ] login-tcp-api.service enable (mục 15)
[ ] /etc/sudoers.d/login-tcp-api-deploy parsed OK (mục 16)
[ ] Vhost Nginx, xóa sites-enabled/default, nginx -t PASS (mục 17)

[ ] ./deploy.sh -> PASS DEPLOY SUCCESS <release-id> (mục 18, 19.1)
[ ] Public /health PASS, gọi thử POST /api/login/garena (mục 20)
```

### 29.1. Việc ngoài server

```text
[ ] Gửi API_KEY mới cho thenhanh.vn (GARENA_LOGIN_API_KEY) qua kênh an toàn; key cũ từng bị commit
    trong Git của thenhanh.vn nên coi như đã lộ
[ ] Xoay NESTPROXY_PROXY_KEY trên nestproxy nếu key từng bị commit vào Git hoặc gửi qua chat
[ ] Lưu vào password manager: password root, <DEPLOY_PASSWORD>, API_KEY, NESTPROXY_PROXY_KEY
[ ] Bật 2FA cho tài khoản Cloudflare, nhà cung cấp VPS và nestproxy
```

---

# PHẦN M – NGUYÊN TẮC VẬN HÀNH

## 30. Chỉ deploy bằng `deploy.sh`

Không `git clone`/`git pull` hay sửa code trực tiếp trong `/srv/apps/api-gateway.ha2cm.com/releases/`. Mọi thay đổi code đi qua commit → `./deploy.sh`, để mỗi release có `RELEASE` ghi đúng commit và có thể rollback.

## 31. Không xóa `shared/`

`shared/.env` là nơi duy nhất chứa secret production. Dọn release cũ chỉ xóa trong `releases/` (`deploy.sh` đã tự giữ 5 release mới nhất).

## 32. Không đưa secret vào Git

`.env`, `.deploy/` đã nằm trong `.gitignore`. `.env.example` chỉ chứa giá trị mẫu, không chứa key thật.

---

# PHẦN N – API VÀ PHÁT TRIỂN

Chuyển đổi từ file `LoginTCPApp.py` gốc sang Node.js **ES Module, Node >= 22.12**, giữ nguyên wire format Protobuf, custom XTEA và trình tự command TCP. Không cần cài thư viện npm.

**Trạng thái kiểm thử:** `npm test` 20/20 test offline đạt; 150/150 vector XTEA ngẫu nhiên khớp với Python; 4 loại packet khớp từng byte với Python. Sử dụng cho tài khoản và dịch vụ mà bạn được phép truy cập; không tự động bỏ qua CAPTCHA hoặc các giới hạn xác thực.

## 33. Cấu trúc source

```text
LoginTCPApp_NodeJS/
├── server.js                          # POST /api/login/garena, API key, kiểm soát đồng thời
├── deploy.sh                          # Deploy production một lệnh (Phần H)
├── package.json                       # npm start / npm test
├── .env.example                       # Mẫu cấu hình local
├── README.md
├── ANALYSIS.md                        # Phân tích chi tiết file Python
├── LoginTCPApp.py                     # Bản Python gốc (tham chiếu)
├── src/
│   ├── configuration.js               # Đọc và kiểm tra biến môi trường
│   ├── proxy/nestproxy-client.js      # Lấy proxy SOCKS5 từ nestproxy, đổi IP theo chu kỳ
│   ├── crypto/                        # Custom XTEA, sinh khóa MD5 -> SHA256 -> SHA256
│   ├── protocol/                      # Protobuf, packet, request/response, bảng mã lỗi
│   ├── transport/tcp-client.js        # Đọc stream TCP theo frame, SOCKS5/SOCKS5h
│   └── services/login-service.js      # LoginPrepare -> Login -> Token -> SSO
└── test/                              # Test offline với máy chủ giả + fixture do Python sinh
```

## 34. Chạy local

```powershell
Copy-Item .env.example .env
npm test
npm start
```

Sửa `API_KEY` trong `.env` (tạo bằng `node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"`), điền `NESTPROXY_PROXY_KEY` nếu muốn đi qua nestproxy. Mặc định API nghe tại `http://localhost:6666`:

```powershell
Invoke-RestMethod -Uri 'http://localhost:6666/health'
```

## 35. Gọi API

`POST /api/login/garena` với `Content-Type: application/json` và header `X-API-Key`. Proxy cấu hình ở máy chủ, người gọi không gửi proxy.

```http
POST /api/login/garena HTTP/1.1
Host: api-gateway.ha2cm.com
Content-Type: application/json
X-API-Key: <API_KEY>

{"username":"your-account","password":"your-password"}
```

Mọi kết quả đăng nhập đều có đủ 5 field `code`, `uid`, `session_key`, `sso_key`, `message`. Thành công:

```json
{
    "code": 0,
    "uid": 123456,
    "session_key": "<32 hex characters>",
    "sso_key": "<secret-sso-key>",
    "message": "SUCCESS"
}
```

Thất bại (ví dụ CAPTCHA):

```json
{ "code": 105, "uid": null, "session_key": null, "sso_key": null, "message": "ERROR_CAPTCHA" }
```

- `code > 0`: mã lỗi máy chủ TCP (`src/protocol/system-errors.json`); `-2`/`-3`: thiếu dữ liệu reply; `-4`: không nhận được SSO key; `-5`: lỗi kết nối/giải mã (mục 26).
- Lỗi tầng HTTP (401, 404, 415, 429, 400, 413, 502) có dạng `{ "code": -1, "message": "..." }` (502 dùng `code: -999`).
- `session_key` và `sso_key` là **dữ liệu bí mật**, không ghi vào log, URL, frontend hoặc database ở dạng rõ.

## 36. Biến môi trường

| Biến                       | Mặc định         | Mô tả                                                                                                         |
| -------------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------- |
| `API_KEY`                  | Bắt buộc         | Khóa bảo vệ API, tối thiểu 24 ký tự                                                                           |
| `HTTP_HOST`                | `localhost`      | Địa chỉ lắng nghe; production phải là `127.0.0.1`                                                             |
| `HTTP_PORT`                | `6666`           | Cổng API                                                                                                      |
| `TCP_SERVER_HOST`          | `103.247.205.15` | Máy chủ TCP                                                                                                   |
| `TCP_SERVER_PORT`          | `19000`          | Cổng máy chủ TCP                                                                                              |
| `NESTPROXY_PROXY_KEY`      | Trống            | `proxy_key` của nestproxy.com: mỗi lượt đăng nhập tự lấy proxy SOCKS5 từ nestproxy; trống thì gọi thẳng       |
| `NESTPROXY_ROTATE_SECONDS` | `60`             | Dùng một IP nestproxy bao nhiêu giây rồi đổi IP mới (tối thiểu 60)                                            |
| `DEVICE_ID`                | Lấy từ MAC máy   | Device ID dưới dạng số thập phân (mục 37)                                                                     |
| `MAX_RETRIES`              | `3`              | Số lần thử tối đa (không thử lại khi gặp CAPTCHA hoặc lỗi xác thực)                                           |
| `MAX_CONCURRENT_LOGINS`    | `3`              | Giới hạn số lượt đăng nhập song song                                                                          |
| `CONNECT_TIMEOUT_MS`       | `8000`           | Thời gian chờ kết nối TCP và bắt tay SOCKS                                                                    |
| `READ_TIMEOUT_MS`          | `5000`           | Thời gian chờ nhận một packet                                                                                 |
| `MAX_PACKET_BYTES`         | `1048576`        | Chặn packet quá lớn                                                                                           |
| `RESPONSE_WINDOW_MS`       | `3000`           | Tổng thời gian chờ nhận phản hồi SSO                                                                          |
| `RESPONSE_IDLE_TIMEOUT_MS` | `500`            | Thời gian chờ tối đa giữa hai packet liên tiếp                                                                |
| `XTEA_RANDOM_MODE`         | `legacy`         | `legacy`: tương thích với Python; `cryptographic`: IV ngẫu nhiên mạnh hơn (cần kiểm tra máy chủ có chấp nhận) |

## 37. Device ID

Python gọi `hash(uuid.getnode())`. Node.js dùng địa chỉ MAC của card mạng đầu tiên không phải loopback. Hai giá trị **không nhất thiết giống nhau**. Để có cùng giá trị như Python, chạy trên máy chạy Python gốc rồi ghi kết quả vào `DEVICE_ID=...`:

```bash
python -c "import uuid; print(hash(uuid.getnode()))"
```

## 38. Tích hợp vào backend Node.js khác

```js
import { loginAndGetKeys } from './src/services/login-service.js';
import { NestproxyClient } from './src/proxy/nestproxy-client.js';

/* Tạo một lần và dùng chung, để mỗi IP được dùng đủ chu kỳ rồi mới đổi. */
const proxyProvider = new NestproxyClient({ proxyKey: process.env.NESTPROXY_PROXY_KEY });

const result = await loginAndGetKeys('account-owned-by-you', 'password', {
    maximumRetries: 1,
    proxyProvider,
    deviceIdentifier: process.env.DEVICE_ID,
    transportOptions: {
        serverHost: process.env.TCP_SERVER_HOST,
        serverPort: Number(process.env.TCP_SERVER_PORT),
    },
});
```

## 39. Giới hạn xác minh

1. Đã đối chiếu packet và XTEA với Python, nhưng **chưa có phiên kiểm thử xác thực trên hệ thống thật**.
2. Chưa xác minh các giá trị `client_version`, `client_type` còn được máy chủ chấp nhận hay không.
3. Chưa kiểm chứng luồng OTP, CAPTCHA hay xác thực bổ sung; mã gốc cũng không triển khai các luồng đó.
4. Custom XTEA trong mã Python gốc không có cơ chế xác thực toàn vẹn thông điệp hiện đại; tương thích không đồng nghĩa với an toàn mật mã.

Xem `ANALYSIS.md` để biết các lỗi và quyết định chuyển đổi theo từng thành phần Python.
