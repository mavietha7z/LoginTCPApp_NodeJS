#!/usr/bin/env bash
#
# Cài đặt / cập nhật Login TCP API trên VPS Ubuntu 24.04. Thường được `deploy.sh` (ở máy local) gọi sau khi
# gửi code lên; cũng chạy tay được:  sudo bash /opt/login-tcp-api/deploy/setup-vps.sh
#
# Việc script làm (chạy lại nhiều lần được, không ghi đè API_KEY trong .env đã có):
#   - Cài Node.js 24, Caddy, ufw nếu chưa có; tạo user `logintcp` chạy app.
#   - Tạo .env nếu chưa có; đặt NESTPROXY_PROXY_KEY nếu được truyền vào.
#   - Cài dịch vụ systemd, cấu hình Caddy dùng Cloudflare Origin Certificate (Cloudflare để Full (strict)),
#     firewall chỉ cho dải IP Cloudflare vào cổng 443.
#   - Kiểm tra app và mở thử kết nối tới máy chủ TCP qua proxy nestproxy.
#
# Biến môi trường:
#   DOMAIN               Domain của API (mặc định api-gateway.ha2cm.com).
#   APP_DIR              Thư mục code (mặc định /opt/login-tcp-api).
#   NESTPROXY_PROXY_KEY  proxy_key của nestproxy; bỏ trống thì giữ nguyên giá trị trong .env, `none` để tắt proxy.
# Chứng chỉ Origin phải có sẵn ở /etc/ssl/cloudflare/<domain>.pem và .key (deploy.sh tự đặt ở lần đầu).

set -euo pipefail

DOMAIN="${DOMAIN:-api-gateway.ha2cm.com}"
APP_DIR="${APP_DIR:-/opt/login-tcp-api}"
NESTPROXY_PROXY_KEY="${NESTPROXY_PROXY_KEY:-}"
APP_USER="logintcp"
DEFAULT_APP_PORT="6666"
ORIGIN_CERTIFICATE_FILE="/etc/ssl/cloudflare/${DOMAIN}.pem"
ORIGIN_KEY_FILE="/etc/ssl/cloudflare/${DOMAIN}.key"

log() { printf '\n\033[1;32m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[cảnh báo] %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m[lỗi] %s\033[0m\n' "$*" >&2; exit 1; }

# Đọc giá trị một biến trong file .env (dòng không bị comment).
read_env_value() {
    local name="$1" file="$2"
    grep -E "^${name}=" "$file" | tail -n 1 | cut -d '=' -f 2- || true
}

# Đặt giá trị một biến trong .env: thay dòng có sẵn (kể cả đang bị comment) hoặc thêm mới.
# Dùng Node thay cho sed để giá trị chứa ký tự đặc biệt không làm hỏng lệnh.
set_env_value() {
    ENV_FILE="$3" ENV_NAME="$1" ENV_VALUE="$2" node -e '
const fs = require("node:fs");
const { ENV_FILE: file, ENV_NAME: name, ENV_VALUE: value } = process.env;
const lines = fs.readFileSync(file, "utf8").split("\n");
const pattern = new RegExp(`^#?\\s*${name}=`);
const index = lines.findIndex((line) => pattern.test(line));
if (index >= 0) lines[index] = `${name}=${value}`;
else lines.splice(lines.at(-1) === "" ? lines.length - 1 : lines.length, 0, `${name}=${value}`);
fs.writeFileSync(file, lines.join("\n"));
'
}

# Thêm dấu # trước dòng đang bật của một biến trong .env (tắt biến đó).
disable_env_value() {
    local name="$1" file="$2"
    sed -i -E "s|^${name}=|# ${name}=|" "$file"
}

[[ $EUID -eq 0 ]] || fail "Cần chạy bằng root (sudo)."
[[ -f "$APP_DIR/server.js" ]] || fail "Không thấy $APP_DIR/server.js."
[[ -f "$ORIGIN_CERTIFICATE_FILE" && -f "$ORIGIN_KEY_FILE" ]] || fail "Chưa có chứng chỉ Origin ở $ORIGIN_CERTIFICATE_FILE và $ORIGIN_KEY_FILE.
Tạo ở Cloudflare (SSL/TLS -> Origin Server -> Create Certificate), lưu vào deploy/secrets/origin.pem và
deploy/secrets/origin.key ở máy local rồi chạy lại deploy.sh (xem DEPLOY.md)."

log "Kiểm tra phần mềm cần thiết"
export DEBIAN_FRONTEND=noninteractive
node_major=0
if command -v node >/dev/null 2>&1; then
    node_major="$(node -p 'process.versions.node.split(".")[0]')"
fi
if (( node_major < 22 )) || ! command -v caddy >/dev/null 2>&1 || ! command -v ufw >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y curl ca-certificates gnupg ufw openssl debian-keyring debian-archive-keyring apt-transport-https
    if (( node_major < 22 )); then
        curl -fsSL https://deb.nodesource.com/setup_24.x | bash -
        apt-get install -y nodejs
    fi
    if ! command -v caddy >/dev/null 2>&1; then
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
            | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
            > /etc/apt/sources.list.d/caddy-stable.list
        apt-get update -y
        apt-get install -y caddy
    fi
fi
node -e 'const [major, minor] = process.versions.node.split(".").map(Number);
if (major < 22 || (major === 22 && minor < 12)) { console.error("Cần Node >= 22.12"); process.exit(1); }'
echo "Node $(node --version), $(caddy version | cut -d ' ' -f 1)"
if ! id -u "$APP_USER" >/dev/null 2>&1; then
    useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$APP_USER"
fi

log "Cấu hình file .env"
env_file="$APP_DIR/.env"
if [[ ! -f "$env_file" ]]; then
    cp "$APP_DIR/.env.example" "$env_file"
    set_env_value API_KEY "$(openssl rand -hex 32)" "$env_file"
    set_env_value HTTP_PORT "$DEFAULT_APP_PORT" "$env_file"
    echo "Đã tạo $env_file với API_KEY mới (xem bằng: grep ^API_KEY= $env_file)."
fi
# App chỉ lắng nghe nội bộ, Caddy đứng trước nhận request từ Cloudflare.
set_env_value HTTP_HOST 127.0.0.1 "$env_file"
if [[ "$NESTPROXY_PROXY_KEY" == "none" ]]; then
    disable_env_value NESTPROXY_PROXY_KEY "$env_file"
    echo "Đã tắt NESTPROXY_PROXY_KEY: app gọi thẳng máy chủ TCP."
elif [[ -n "$NESTPROXY_PROXY_KEY" ]]; then
    set_env_value NESTPROXY_PROXY_KEY "$NESTPROXY_PROXY_KEY" "$env_file"
    echo "Đã đặt NESTPROXY_PROXY_KEY trong .env."
fi
# SOCKS_PROXY_URL không còn được hỗ trợ: tắt nếu .env cũ còn bật.
disable_env_value SOCKS_PROXY_URL "$env_file"
chown "root:$APP_USER" "$env_file"
chmod 640 "$env_file"
app_port="$(read_env_value HTTP_PORT "$env_file")"
app_port="${app_port:-$DEFAULT_APP_PORT}"

log "Khởi động lại app"
install -m 644 "$APP_DIR/deploy/login-tcp-api.service" /etc/systemd/system/login-tcp-api.service
sed -i "s|/opt/login-tcp-api|${APP_DIR}|g" /etc/systemd/system/login-tcp-api.service
systemctl daemon-reload
systemctl enable login-tcp-api >/dev/null
systemctl restart login-tcp-api

log "Cấu hình Caddy cho $DOMAIN"
# Chứng chỉ phải dành cho đúng domain và private key phải khớp chứng chỉ.
openssl x509 -in "$ORIGIN_CERTIFICATE_FILE" -noout -checkhost "$DOMAIN" | grep -q "does match" \
    || fail "Chứng chỉ $ORIGIN_CERTIFICATE_FILE không dành cho $DOMAIN."
certificate_public_key="$(openssl x509 -in "$ORIGIN_CERTIFICATE_FILE" -noout -pubkey | openssl sha256)"
private_key_public_key="$(openssl pkey -in "$ORIGIN_KEY_FILE" -pubout | openssl sha256)"
[[ "$certificate_public_key" == "$private_key_public_key" ]] || fail "Private key không khớp với chứng chỉ Origin."
chown root:caddy "$ORIGIN_CERTIFICATE_FILE" "$ORIGIN_KEY_FILE"
chmod 644 "$ORIGIN_CERTIFICATE_FILE"
chmod 640 "$ORIGIN_KEY_FILE"
sed -e "s|__DOMAIN__|${DOMAIN}|g" \
    -e "s|__CERTIFICATE_FILE__|${ORIGIN_CERTIFICATE_FILE}|g" \
    -e "s|__KEY_FILE__|${ORIGIN_KEY_FILE}|g" \
    -e "s|__APP_PORT__|${app_port}|g" \
    "$APP_DIR/deploy/Caddyfile" > /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null
systemctl reload caddy || systemctl restart caddy

log "Cấu hình firewall"
# Mở đúng cổng SSH đang dùng (kể cả khi không phải 22) để không tự khóa mình ngoài VPS.
for ssh_port in $(sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }'); do
    ufw allow "${ssh_port}/tcp" >/dev/null
done
cloudflare_ranges="$(curl -fsS https://www.cloudflare.com/ips-v4 || true) $(curl -fsS https://www.cloudflare.com/ips-v6 || true)"
if [[ -z "${cloudflare_ranges// /}" ]]; then
    warn "Không tải được danh sách IP Cloudflare; giữ nguyên quy tắc firewall cũ."
else
    # Xóa mọi quy tắc cổng 80/443 cũ rồi chỉ mở 443 cho dải IP Cloudflare.
    for port in 80 443; do
        ufw delete allow "${port}/tcp" >/dev/null 2>&1 || true
        for cloudflare_range in $cloudflare_ranges; do
            ufw delete allow proto tcp from "$cloudflare_range" to any port "$port" >/dev/null 2>&1 || true
        done
    done
    for cloudflare_range in $cloudflare_ranges; do
        ufw allow proto tcp from "$cloudflare_range" to any port 443 >/dev/null
    done
fi
ufw --force enable >/dev/null
echo "Cổng mở: SSH, 443 (chỉ dải IP Cloudflare)."

log "Kiểm tra"
sleep 2
if curl -fsS "http://127.0.0.1:${app_port}/health" >/dev/null; then
    echo "App chạy trên 127.0.0.1:${app_port}."
else
    warn "App chưa phản hồi. Xem log: journalctl -u login-tcp-api -n 50"
fi
# Chứng chỉ Origin chỉ được Cloudflare tin, nên kiểm tra nội bộ phải bỏ qua bước xác thực chứng chỉ (-k).
if curl -fsS -k --resolve "${DOMAIN}:443:127.0.0.1" "https://${DOMAIN}/health" >/dev/null; then
    echo "Caddy chuyển tiếp đúng tới app."
else
    warn "Caddy chưa phản hồi. Xem log: journalctl -u caddy -n 50"
fi
# Mở thử kết nối tới máy chủ TCP bằng chính code của app, qua proxy nestproxy nếu có NESTPROXY_PROXY_KEY.
if node --env-file="$env_file" --input-type=module -e "
const { loadConfiguration } = await import('${APP_DIR}/src/configuration.js');
const { TcpClient } = await import('${APP_DIR}/src/transport/tcp-client.js');
const { NestproxyClient } = await import('${APP_DIR}/src/proxy/nestproxy-client.js');
const configuration = loadConfiguration();
const transportOptions = { ...configuration.transportOptions };
let proxyDescription = ' (gọi thẳng, không proxy).';
if (configuration.nestproxyProxyKey) {
    const nestproxyClient = new NestproxyClient({ proxyKey: configuration.nestproxyProxyKey });
    transportOptions.proxyUrl = await nestproxyClient.getProxyUrl();
    proxyDescription = ' qua proxy nestproxy ' + transportOptions.proxyUrl.replace('socks5://', '') + '.';
}
const tcpClient = new TcpClient(transportOptions);
await tcpClient.connect();
tcpClient.close();
console.log('Kết nối được tới máy chủ TCP ' + transportOptions.serverHost + ':' + transportOptions.serverPort + proxyDescription);
"; then
    :
else
    warn "Không kết nối được tới máy chủ TCP. Kiểm tra proxy_key nestproxy hoặc máy chủ TCP còn hoạt động không."
fi
