#!/usr/bin/env bash
#
# Cài đặt Login TCP API lên VPS Ubuntu 24.04 LTS.
#
# Việc script làm:
#   - Cài Node.js 24 (NodeSource), Caddy (reverse proxy), ufw.
#   - Tạo user `logintcp` chạy app và user `tunnel` chỉ dùng cho SOCKS tunnel từ máy local.
#   - Tạo .env cho VPS: gọi thẳng máy chủ TCP (không proxy), chỉ lắng nghe 127.0.0.1.
#   - Cài dịch vụ systemd, cấu hình Caddy cho domain, cấu hình SSH cho user tunnel, bật firewall.
#
# Cách chạy (code đã có sẵn tại /opt/login-tcp-api):
#   sudo DOMAIN=api-gateway.ha2cm.com \
#        TUNNEL_PUBLIC_KEY="ssh-ed25519 AAAA... may-local" \
#        bash /opt/login-tcp-api/deploy/setup-vps.sh
#
# SSL_MODE (mặc định flexible) phải khớp chế độ SSL/TLS trên Cloudflare:
#   - flexible: Cloudflare gọi VPS bằng HTTP. Caddy chỉ nghe cổng 80, firewall chỉ cho dải IP Cloudflare vào cổng 80.
#   - full:     Caddy tự xin chứng chỉ Let's Encrypt (dùng với Cloudflare "Full (strict)"), mở cổng 80 và 443.
#
# Chạy lại nhiều lần được: không ghi đè .env đã có, không thêm trùng public key.

set -euo pipefail

DOMAIN="${DOMAIN:-api-gateway.ha2cm.com}"
APP_DIR="${APP_DIR:-/opt/login-tcp-api}"
APP_USER="logintcp"
TUNNEL_USER="tunnel"
TUNNEL_PUBLIC_KEY="${TUNNEL_PUBLIC_KEY:-}"
DEFAULT_APP_PORT="6666"
SSL_MODE="${SSL_MODE:-flexible}"

log() { printf '\n\033[1;32m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[cảnh báo] %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m[lỗi] %s\033[0m\n' "$*" >&2; exit 1; }

# Đọc giá trị một biến trong file .env (dòng không bị comment).
read_env_value() {
    local name="$1" file="$2"
    grep -E "^${name}=" "$file" | tail -n 1 | cut -d '=' -f 2- || true
}

# Đặt giá trị một biến trong .env: thay dòng có sẵn (kể cả đang bị comment) hoặc thêm mới.
set_env_value() {
    local name="$1" value="$2" file="$3"
    if grep -qE "^#?\s*${name}=" "$file"; then
        sed -i -E "s|^#?\s*${name}=.*|${name}=${value}|" "$file"
    else
        printf '%s=%s\n' "$name" "$value" >> "$file"
    fi
}

[[ $EUID -eq 0 ]] || fail "Cần chạy bằng root (sudo)."
[[ "$SSL_MODE" == "flexible" || "$SSL_MODE" == "full" ]] || fail "SSL_MODE chỉ nhận flexible hoặc full."
[[ -f "$APP_DIR/server.js" ]] || fail "Không thấy $APP_DIR/server.js. Hãy clone code vào $APP_DIR trước."
if ! grep -q 'VERSION_ID="24.04"' /etc/os-release; then
    warn "Script được viết cho Ubuntu 24.04; hệ điều hành hiện tại có thể cần chỉnh."
fi

log "Cài gói hệ thống"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl ca-certificates gnupg ufw openssl netcat-openbsd \
    debian-keyring debian-archive-keyring apt-transport-https

log "Cài Node.js 24"
node_major=0
if command -v node >/dev/null 2>&1; then
    node_major="$(node -p 'process.versions.node.split(".")[0]')"
fi
if (( node_major < 22 )); then
    curl -fsSL https://deb.nodesource.com/setup_24.x | bash -
    apt-get install -y nodejs
fi
node -e 'const [major, minor] = process.versions.node.split(".").map(Number);
if (major < 22 || (major === 22 && minor < 12)) { console.error("Cần Node >= 22.12"); process.exit(1); }'
echo "Node $(node --version) tại $(command -v node)"

log "Cài Caddy"
if ! command -v caddy >/dev/null 2>&1; then
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
        | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
        > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -y
    apt-get install -y caddy
fi

log "Tạo user hệ thống"
if ! id -u "$APP_USER" >/dev/null 2>&1; then
    useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$APP_USER"
fi
if ! id -u "$TUNNEL_USER" >/dev/null 2>&1; then
    useradd --create-home --shell /usr/sbin/nologin "$TUNNEL_USER"
fi
tunnel_home="$(getent passwd "$TUNNEL_USER" | cut -d ':' -f 6)"
install -d -m 700 -o "$TUNNEL_USER" -g "$TUNNEL_USER" "$tunnel_home/.ssh"
touch "$tunnel_home/.ssh/authorized_keys"
if [[ -n "$TUNNEL_PUBLIC_KEY" ]]; then
    if ! grep -qxF "$TUNNEL_PUBLIC_KEY" "$tunnel_home/.ssh/authorized_keys"; then
        printf '%s\n' "$TUNNEL_PUBLIC_KEY" >> "$tunnel_home/.ssh/authorized_keys"
        echo "Đã thêm public key cho user $TUNNEL_USER."
    fi
else
    warn "Chưa truyền TUNNEL_PUBLIC_KEY: máy local chưa mở được tunnel. Thêm key vào $tunnel_home/.ssh/authorized_keys sau."
fi
chown "$TUNNEL_USER:$TUNNEL_USER" "$tunnel_home/.ssh/authorized_keys"
chmod 600 "$tunnel_home/.ssh/authorized_keys"

log "Tạo file .env cho VPS"
env_file="$APP_DIR/.env"
if [[ ! -f "$env_file" ]]; then
    cp "$APP_DIR/.env.example" "$env_file"
    generated_api_key="$(openssl rand -hex 32)"
    set_env_value API_KEY "$generated_api_key" "$env_file"
    set_env_value HTTP_PORT "$DEFAULT_APP_PORT" "$env_file"
    echo "Đã tạo $env_file với API_KEY mới (xem bằng: sudo grep ^API_KEY= $env_file)."
fi
# Trên VPS: chỉ lắng nghe nội bộ (Caddy đứng trước) và gọi thẳng máy chủ TCP, không qua proxy.
set_env_value HTTP_HOST 127.0.0.1 "$env_file"
if grep -qE '^SOCKS_PROXY_URL=' "$env_file"; then
    sed -i -E 's|^SOCKS_PROXY_URL=|# SOCKS_PROXY_URL=|' "$env_file"
    echo "Đã tắt SOCKS_PROXY_URL trong .env của VPS (VPS gọi thẳng)."
fi
chown "root:$APP_USER" "$env_file"
chmod 640 "$env_file"

app_port="$(read_env_value HTTP_PORT "$env_file")"
app_port="${app_port:-$DEFAULT_APP_PORT}"
target_host="$(read_env_value TCP_SERVER_HOST "$env_file")"
target_host="${target_host:-103.247.205.15}"
target_port="$(read_env_value TCP_SERVER_PORT "$env_file")"
target_port="${target_port:-19000}"

log "Cấu hình SSH cho user $TUNNEL_USER (chỉ được đi tới $target_host:$target_port)"
sed "s|__TARGET__|${target_host}:${target_port}|g" "$APP_DIR/deploy/sshd-tunnel.conf" \
    > /etc/ssh/sshd_config.d/60-login-tcp-tunnel.conf
chmod 644 /etc/ssh/sshd_config.d/60-login-tcp-tunnel.conf
sshd -t || fail "Cấu hình SSH không hợp lệ; đã dừng trước khi nạp lại để tránh mất kết nối."
systemctl reload-or-restart ssh

log "Cài dịch vụ systemd login-tcp-api"
install -m 644 "$APP_DIR/deploy/login-tcp-api.service" /etc/systemd/system/login-tcp-api.service
sed -i "s|/opt/login-tcp-api|${APP_DIR}|g" /etc/systemd/system/login-tcp-api.service
systemctl daemon-reload
systemctl enable login-tcp-api >/dev/null
systemctl restart login-tcp-api

log "Cấu hình Caddy cho $DOMAIN (SSL_MODE=$SSL_MODE)"
if [[ -f /etc/caddy/Caddyfile && ! -f /etc/caddy/Caddyfile.original ]]; then
    cp /etc/caddy/Caddyfile /etc/caddy/Caddyfile.original
fi
if [[ "$SSL_MODE" == "flexible" ]]; then
    # Chỉ HTTP: không xin chứng chỉ và không chuyển hướng sang HTTPS (tránh vòng lặp với Cloudflare Flexible).
    site_address="http://${DOMAIN}"
else
    site_address="${DOMAIN}"
fi
sed -e "s|__SITE_ADDRESS__|${site_address}|g" -e "s|__APP_PORT__|${app_port}|g" \
    "$APP_DIR/deploy/Caddyfile" > /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
systemctl reload caddy || systemctl restart caddy

log "Bật firewall"
# Mở đúng cổng SSH đang dùng (kể cả khi không phải 22) để không tự khóa mình ngoài VPS.
for ssh_port in $(sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }'); do
    ufw allow "${ssh_port}/tcp" >/dev/null
done
# Xóa quy tắc mở cổng web cho mọi IP của lần chạy trước (nếu có), rồi mở lại theo SSL_MODE.
ufw delete allow 80/tcp >/dev/null 2>&1 || true
ufw delete allow 443/tcp >/dev/null 2>&1 || true
if [[ "$SSL_MODE" == "flexible" ]]; then
    # Chỉ dải IP Cloudflare được vào cổng 80, để không ai gọi thẳng HTTP vào VPS mà bỏ qua Cloudflare.
    cloudflare_ranges="$(curl -fsS https://www.cloudflare.com/ips-v4 || true) $(curl -fsS https://www.cloudflare.com/ips-v6 || true)"
    if [[ -z "${cloudflare_ranges// /}" ]]; then
        warn "Không tải được danh sách IP Cloudflare; tạm mở cổng 80 cho mọi IP. Chạy lại script sau để siết lại."
        ufw allow 80/tcp >/dev/null
    else
        for cloudflare_range in $cloudflare_ranges; do
            ufw allow proto tcp from "$cloudflare_range" to any port 80 >/dev/null
        done
        echo "Cổng 80 chỉ mở cho các dải IP Cloudflare."
    fi
else
    ufw allow 80/tcp >/dev/null
    ufw allow 443/tcp >/dev/null
fi
ufw --force enable >/dev/null
ufw status

log "Kiểm tra"
sleep 2
if curl -fsS "http://127.0.0.1:${app_port}/health"; then
    echo "  <- app chạy trên 127.0.0.1:${app_port}"
else
    warn "App chưa phản hồi. Xem log: journalctl -u login-tcp-api -n 50"
fi
if [[ "$SSL_MODE" == "flexible" ]]; then
    if curl -fsS -H "Host: ${DOMAIN}" "http://127.0.0.1/health"; then
        echo "  <- Caddy chuyển tiếp đúng tới app qua cổng 80"
    else
        warn "Caddy chưa phản hồi trên cổng 80. Xem log: journalctl -u caddy -n 50"
    fi
fi
if nc -vz -w 5 "$target_host" "$target_port"; then
    echo "VPS kết nối được tới máy chủ TCP $target_host:$target_port."
else
    warn "VPS không kết nối được tới $target_host:$target_port (nhà cung cấp chặn cổng hoặc máy chủ không hoạt động)."
fi

log "Xong"
cat <<EOF
- API công khai:   POST https://${DOMAIN}/api/login/garena
- Cloudflare:      SSL/TLS phải khớp SSL_MODE=${SSL_MODE} (flexible: chế độ Flexible và bản ghi DNS bật Proxied)
- Log app:         journalctl -u login-tcp-api -f
- Tunnel từ local: ssh -D 127.0.0.1:1080 -N ${TUNNEL_USER}@<IP VPS>   (dùng IP, không dùng domain đi qua Cloudflare)
EOF
