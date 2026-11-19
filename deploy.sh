#!/usr/bin/env bash
#
# Deploy Login TCP API lên VPS chỉ bằng một lệnh (chạy từ Git Bash trên Windows, hoặc Linux/macOS):
#
#   bash deploy.sh
#
# Script mở MỘT kết nối SSH (nên chỉ hỏi mật khẩu VPS một lần), gửi code trong thư mục này lên VPS,
# thay code cũ ở /opt/login-tcp-api (GIỮ NGUYÊN file .env trên VPS), rồi chạy deploy/setup-vps.sh để
# cài đặt/cập nhật và khởi động lại app. Không cần git push trước khi deploy.
#
# Lần deploy đầu tiên cần thêm:
#   - Chứng chỉ Cloudflare Origin đặt ở deploy/secrets/origin.pem và deploy/secrets/origin.key
#     (thư mục này không được commit). Các lần sau không cần nữa.
#   - proxy_key của nestproxy, truyền qua biến môi trường:  NESTPROXY_PROXY_KEY='...' bash deploy.sh
#
# Có thể đổi máy đích bằng biến môi trường: VPS_HOST, VPS_USER, DOMAIN, APP_DIR.

set -euo pipefail

VPS_HOST="${VPS_HOST:-103.68.84.27}"
VPS_USER="${VPS_USER:-root}"
DOMAIN="${DOMAIN:-api-gateway.ha2cm.com}"
NESTPROXY_PROXY_KEY="${NESTPROXY_PROXY_KEY:-}"
APP_DIR="${APP_DIR:-/opt/login-tcp-api}"

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$project_dir"

# Chỉ gửi những file app cần để chạy trên VPS.
upload_paths=(server.js package.json .env.example src deploy/setup-vps.sh deploy/Caddyfile deploy/login-tcp-api.service)
for upload_path in "${upload_paths[@]}"; do
    [[ -e "$upload_path" ]] || { echo "[lỗi] Thiếu $upload_path trong $project_dir" >&2; exit 1; }
done
if [[ -f deploy/secrets/origin.pem && -f deploy/secrets/origin.key ]]; then
    upload_paths+=(deploy/secrets/origin.pem deploy/secrets/origin.key)
    echo "Có chứng chỉ Origin trong deploy/secrets/, sẽ gửi kèm."
fi

# Lệnh chạy trên VPS. Truyền vào `bash -c` dưới dạng base64 để stdin của SSH dành cho gói code.
remote_script=$(cat <<'REMOTE'
set -euo pipefail
staging_dir="$(mktemp -d)"
trap 'rm -rf "$staging_dir"' EXIT

echo "==> Nhận code mới"
tar -xzf - -C "$staging_dir"
[[ -f "$staging_dir/server.js" ]] || { echo "[lỗi] Gói code không hợp lệ" >&2; exit 1; }

# File gửi từ Windows có thể dùng xuống dòng CRLF: đổi về LF để bash và Node đọc đúng.
find "$staging_dir" -type f \( -name '*.js' -o -name '*.json' -o -name '*.sh' -o -name '*.service' \
    -o -name 'Caddyfile' -o -name '.env.example' -o -name '*.pem' -o -name '*.key' \) -exec sed -i 's/\r$//' {} +

# Chứng chỉ Origin (chỉ có ở lần deploy đầu hoặc khi đổi chứng chỉ).
if [[ -f "$staging_dir/deploy/secrets/origin.pem" ]]; then
    install -d -m 755 /etc/ssl/cloudflare
    install -m 644 "$staging_dir/deploy/secrets/origin.pem" "/etc/ssl/cloudflare/${DOMAIN}.pem"
    install -m 600 "$staging_dir/deploy/secrets/origin.key" "/etc/ssl/cloudflare/${DOMAIN}.key"
    rm -rf "$staging_dir/deploy/secrets"
    echo "Đã cập nhật chứng chỉ Origin."
fi

echo "==> Thay code ở ${APP_DIR} (giữ nguyên .env)"
mkdir -p "$APP_DIR"
find "$APP_DIR" -mindepth 1 -maxdepth 1 ! -name .env -exec rm -rf {} +
cp -a "$staging_dir/." "$APP_DIR/"
chmod +x "$APP_DIR/deploy/setup-vps.sh"

DOMAIN="$DOMAIN" APP_DIR="$APP_DIR" NESTPROXY_PROXY_KEY="$NESTPROXY_PROXY_KEY" bash "$APP_DIR/deploy/setup-vps.sh"
REMOTE
)

# Giá trị truyền sang VPS được đặt trong dấu nháy an toàn bằng printf %q.
remote_command="DOMAIN=$(printf %q "$DOMAIN") APP_DIR=$(printf %q "$APP_DIR") NESTPROXY_PROXY_KEY=$(printf %q "$NESTPROXY_PROXY_KEY")"
encoded_script="$(printf '%s' "$remote_script" | base64 | tr -d '\n')"

echo "==> Deploy lên ${VPS_USER}@${VPS_HOST} (nhập mật khẩu VPS khi được hỏi)"
tar -czf - "${upload_paths[@]}" \
    | ssh -o StrictHostKeyChecking=accept-new "${VPS_USER}@${VPS_HOST}" \
        "${remote_command} bash -c \"\$(echo ${encoded_script} | base64 -d)\""

echo "==> Kiểm tra https://${DOMAIN}/health"
if curl -fsS --max-time 15 "https://${DOMAIN}/health"; then
    echo
    echo "Deploy xong."
else
    echo "[cảnh báo] Chưa gọi được https://${DOMAIN}/health; kiểm tra Cloudflare (Full (strict)) và log trên VPS: journalctl -u login-tcp-api -n 50" >&2
fi
