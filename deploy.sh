#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================================
# api-gateway.ha2cm.com (LoginTCPApp_NodeJS) - one-command production deploy
#
# Chạy bằng Git Bash trên Windows (hoặc shell macOS/Linux) tại thư mục gốc dự án:
#   ./deploy.sh
#
# Đích production: api-gateway.ha2cm.com trên VPS 103.68.84.27 (ghi đè biến
# DEPLOY_* trong .deploy/env hoặc truyền trực tiếp khi chạy). VPS phải được cài
# theo README (Phần A–G) trước lần deploy đầu tiên; script này chỉ deploy code.
#
# Working tree phải đã commit; chỉ dùng DEPLOY_ALLOW_DIRTY=1 ./deploy.sh khi chủ
# động deploy cả thay đổi chưa commit. Test (`npm test`) luôn chạy trước khi đóng
# gói; DEPLOY_SKIP_TESTS=1 chỉ dùng khi vừa tự chạy `npm test` cho đúng commit đó.
#
# SSH: hỏi password MỘT lần, rồi mọi lệnh ssh/scp sau đó nhận lại password qua
# SSH_ASKPASS. Password chỉ nằm trong biến môi trường của tiến trình này, không
# ghi ra đĩa, và bị xóa khi script kết thúc.
#
# Trên VPS: mỗi lần deploy tạo releases/<YYYYMMDD-HHMMSS>, chuyển symlink
# `current` sang release mới, restart service rồi kiểm tra /health; lỗi thì tự
# rollback về release cũ. File shared/.env trên VPS không bao giờ bị ghi đè.
# ============================================================================

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
DEPLOY_DIR="$ROOT_DIR/.deploy"

# ------------------------------- UI helpers ---------------------------------
if [[ -t 1 ]]; then
    BOLD='\033[1m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    RED='\033[0;31m'
    RESET='\033[0m'
else
    BOLD=''
    GREEN=''
    YELLOW=''
    RED=''
    RESET=''
fi

info() { printf '%b\n' "${BOLD}==>${RESET} $*"; }
success() { printf '%b\n' "${GREEN}PASS${RESET} $*"; }
warn() { printf '%b\n' "${YELLOW}WARN${RESET} $*"; }
die() { printf '%b\n' "${RED}ERROR${RESET} $*" >&2; exit 1; }

# ------------------------------ Site config ---------------------------------
# Biến deploy được phép đặt trong file cấu hình máy local (mặc định .deploy/env,
# đã nằm trong .gitignore). Biến truyền trực tiếp khi chạy lệnh luôn được ưu tiên
# hơn giá trị trong file.
DEPLOY_VARIABLE_NAMES=(
    DEPLOY_DOMAIN
    DEPLOY_HOST
    DEPLOY_USER
    DEPLOY_APP_DIR
    DEPLOY_SERVICE
    DEPLOY_ORIGIN_HEALTH_URL
    DEPLOY_PUBLIC_HEALTH_URL
    DEPLOY_KEEP_RELEASES
)

# Đọc file KEY=VALUE thay vì `source` để file cấu hình không thể chạy lệnh shell.
# Chỉ nhận các biến trong DEPLOY_VARIABLE_NAMES; bỏ dòng trống và dòng comment.
load_deploy_env_file() {
    local env_file="$1"
    local line key value name is_known

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"

        if [[ -z "${line//[[:space:]]/}" || "$line" =~ ^[[:space:]]*# ]]; then
            continue
        fi

        if [[ ! "$line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Z0-9_]+)=(.*)$ ]]; then
            die "Dòng không đúng dạng KEY=VALUE trong $env_file: $line"
        fi

        key="${BASH_REMATCH[2]}"
        value="${BASH_REMATCH[3]}"

        is_known=0
        for name in "${DEPLOY_VARIABLE_NAMES[@]}"; do
            if [[ "$name" == "$key" ]]; then
                is_known=1
            fi
        done

        if [[ "$is_known" -ne 1 ]]; then
            die "Biến $key không được hỗ trợ trong $env_file"
        fi

        if [[ "$value" =~ ^\"(.*)\"$ || "$value" =~ ^\'(.*)\'$ ]]; then
            value="${BASH_REMATCH[1]}"
        fi

        if [[ -z "${!key+x}" ]]; then
            printf -v "$key" '%s' "$value"
        fi
    done < "$env_file"
}

DEPLOY_ENV_FILE="${DEPLOY_ENV_FILE:-$DEPLOY_DIR/env}"
if [[ -f "$DEPLOY_ENV_FILE" ]]; then
    load_deploy_env_file "$DEPLOY_ENV_FILE"
fi

DEPLOY_DOMAIN="${DEPLOY_DOMAIN:-api-gateway.ha2cm.com}"
DEPLOY_HOST="${DEPLOY_HOST:-103.68.84.27}"
DEPLOY_USER="${DEPLOY_USER:-deploy}"
DEPLOY_APP_DIR="${DEPLOY_APP_DIR:-/srv/apps/api-gateway.ha2cm.com}"
DEPLOY_SERVICE="${DEPLOY_SERVICE:-login-tcp-api.service}"
DEPLOY_ORIGIN_HEALTH_URL="${DEPLOY_ORIGIN_HEALTH_URL:-http://127.0.0.1:6666/health}"
DEPLOY_PUBLIC_HEALTH_URL="${DEPLOY_PUBLIC_HEALTH_URL:-https://$DEPLOY_DOMAIN/health}"
DEPLOY_KEEP_RELEASES="${DEPLOY_KEEP_RELEASES:-5}"

if [[ -z "$DEPLOY_HOST" ]]; then
    die "DEPLOY_HOST không được để trống (mặc định 103.68.84.27)"
fi

if [[ ! "$DEPLOY_KEEP_RELEASES" =~ ^[1-9][0-9]*$ ]]; then
    die "DEPLOY_KEEP_RELEASES phải là số nguyên dương, đang là: $DEPLOY_KEEP_RELEASES"
fi

# App chỉ listen 127.0.0.1 (HTTP_HOST trong shared/.env), nên origin health phải
# gọi đúng IPv4 loopback; `localhost` có thể phân giải sang ::1 và luôn FAIL.
ORIGIN_HEALTH_PATTERN='^http://127\.0\.0\.1:([0-9]+)/health$'
if [[ ! "$DEPLOY_ORIGIN_HEALTH_URL" =~ $ORIGIN_HEALTH_PATTERN ]]; then
    die "DEPLOY_ORIGIN_HEALTH_URL phải có dạng http://127.0.0.1:<PORT>/health, đang là: $DEPLOY_ORIGIN_HEALTH_URL"
fi

RELEASE_ID="$(date +%Y%m%d-%H%M%S)"
WORK_DIR="$DEPLOY_DIR/work-$RELEASE_ID"
RUNTIME_DIR="$WORK_DIR/runtime"
PACKAGE_FILE="$DEPLOY_DIR/login-tcp-api-release-$RELEASE_ID.tar.gz"
REMOTE_PACKAGE="/tmp/login-tcp-api-release-$RELEASE_ID.tar.gz"
REMOTE="$DEPLOY_USER@$DEPLOY_HOST"

# Hỏi SSH password đúng một lần. Các tiến trình ssh/scp sau nhận lại password từ
# SSH_ASKPASS mà không mở prompt mới. Script helper không chứa secret; nó chỉ in
# biến môi trường thuộc tiến trình deploy này.
SSH_ASKPASS_SCRIPT="$DEPLOY_DIR/ssh-askpass-$RELEASE_ID-$$.sh"
SSH_OPTS=(
    -o PreferredAuthentications=password
    -o PasswordAuthentication=yes
    -o KbdInteractiveAuthentication=no
    -o PubkeyAuthentication=no
    -o NumberOfPasswordPrompts=1
    -o ConnectTimeout=10
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=3
    -o StrictHostKeyChecking=accept-new
)
SCP_OPTS=(
    -o PreferredAuthentications=password
    -o PasswordAuthentication=yes
    -o KbdInteractiveAuthentication=no
    -o PubkeyAuthentication=no
    -o NumberOfPasswordPrompts=1
    -o ConnectTimeout=10
    -o StrictHostKeyChecking=accept-new
)

cleanup() {
    unset DEPLOY_SSH_PASSWORD SSH_ASKPASS SSH_ASKPASS_REQUIRE DISPLAY || true
    rm -f -- "$SSH_ASKPASS_SCRIPT" >/dev/null 2>&1 || true
    rm -rf -- "$WORK_DIR"
    rm -f -- "$PACKAGE_FILE"
}
trap cleanup EXIT

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Thiếu command: $1"
}

# Git Bash/Linux có sha256sum; macOS mặc định chỉ có shasum.
compute_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# ------------------------------ Preconditions -------------------------------
info "Preflight"
for cmd in node npm tar ssh scp git; do
    require_command "$cmd"
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    die "Thiếu command: sha256sum hoặc shasum"
fi

# Release phải tương ứng một commit cụ thể. Tree còn thay đổi (kể cả file
# untracked) thì dừng, trừ khi chủ động chạy DEPLOY_ALLOW_DIRTY=1 ./deploy.sh.
git -C "$ROOT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "$ROOT_DIR không phải Git working tree"
if [[ -n "$(git -C "$ROOT_DIR" status --porcelain)" ]]; then
    if [[ "${DEPLOY_ALLOW_DIRTY:-0}" != "1" ]]; then
        git -C "$ROOT_DIR" status --short >&2
        die "Working tree còn thay đổi chưa commit. Commit trước khi deploy hoặc chạy DEPLOY_ALLOW_DIRTY=1 ./deploy.sh"
    fi
    warn "Deploy cả thay đổi chưa commit (DEPLOY_ALLOW_DIRTY=1); RELEASE sẽ ghi git_dirty=true"
fi

[[ -f "$ROOT_DIR/server.js" ]] || die "Không tìm thấy server.js"
[[ -f "$ROOT_DIR/package.json" ]] || die "Không tìm thấy package.json"
[[ -d "$ROOT_DIR/src" ]] || die "Không tìm thấy thư mục src/"

# Phiên bản Node tối thiểu lấy từ engines.node của package.json, dùng chung cho
# máy deploy và VPS. Chỉ hỗ trợ dạng ">=X.Y" hoặc ">=X.Y.Z".
REQUIRED_NODE_RANGE="$(cd "$ROOT_DIR" && node -p "require('./package.json').engines?.node ?? ''")"
NODE_RANGE_PATTERN='^>=([0-9]+)\.([0-9]+)(\.([0-9]+))?$'
if [[ ! "$REQUIRED_NODE_RANGE" =~ $NODE_RANGE_PATTERN ]]; then
    die "package.json engines.node phải có dạng >=X.Y hoặc >=X.Y.Z, đang là: ${REQUIRED_NODE_RANGE:-<trống>}"
fi
REQUIRED_NODE_VERSION="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[4]:-0}"

# Kiểm tra Node local; remote preflight dùng đoạn kiểm tra tương tự trên VPS.
NODE_VERSION_CHECK='
const actual = process.versions.node.split(".").map(Number);
const required = process.env.REQUIRED_NODE_VERSION.split(".").map(Number);
for (let index = 0; index < 3; index += 1) {
    if (actual[index] !== required[index]) {
        if (actual[index] < required[index]) {
            console.error(`ERROR Node ${process.versions.node} không đạt yêu cầu >=${process.env.REQUIRED_NODE_VERSION}`);
            process.exit(1);
        }
        break;
    }
}
'
REQUIRED_NODE_VERSION="$REQUIRED_NODE_VERSION" node -e "$NODE_VERSION_CHECK"
success "Node $(node -v) (yêu cầu >=$REQUIRED_NODE_VERSION)"

# ---------------------------------- Test -------------------------------------
# Toàn bộ test chạy offline với máy chủ giả, mất vài giây nên luôn chạy đủ.
if [[ "${DEPLOY_SKIP_TESTS:-0}" == "1" ]]; then
    TEST_STATUS="skipped"
    warn "Bỏ qua npm test theo DEPLOY_SKIP_TESTS=1; RELEASE sẽ ghi tests=skipped"
else
    info "npm test"
    (
        cd "$ROOT_DIR"
        npm test --silent
    )
    TEST_STATUS="passed"
    success "npm test"
fi

# ------------------------------ SSH password ---------------------------------
# Hỏi một lần ở terminal local, rồi buộc OpenSSH dùng SSH_ASKPASS cho mọi kết nối
# sau. Cách này không phụ thuộc ControlMaster (hay lỗi trên Git Bash Windows).
mkdir -p "$DEPLOY_DIR"
cat > "$SSH_ASKPASS_SCRIPT" <<'ASKPASS'
#!/usr/bin/env bash
printf '%s\n' "${DEPLOY_SSH_PASSWORD:?}"
ASKPASS
chmod 700 "$SSH_ASKPASS_SCRIPT"

printf 'SSH password cho %s: ' "$REMOTE"
IFS= read -r -s DEPLOY_SSH_PASSWORD
printf '\n'
[[ -n "$DEPLOY_SSH_PASSWORD" ]] || die "SSH password không được để trống"

export DEPLOY_SSH_PASSWORD
export SSH_ASKPASS="$SSH_ASKPASS_SCRIPT"
export SSH_ASKPASS_REQUIRE=force
# OpenSSH trên một số nền tảng vẫn đòi DISPLAY trước khi gọi askpass; giá trị
# không được dùng tới với helper chạy trong terminal này.
export DISPLAY="${DISPLAY:-deploy-askpass}"

# ---------------------------- Remote preflight -------------------------------
# Kiểm tra mọi điều kiện trên VPS trước khi đóng gói và upload.
info "Remote preflight"
if ! ssh "${SSH_OPTS[@]}" -T "$REMOTE" bash -s -- \
    "$DEPLOY_APP_DIR" \
    "$DEPLOY_SERVICE" \
    "$DEPLOY_ORIGIN_HEALTH_URL" \
    "$REQUIRED_NODE_VERSION" <<'REMOTE_PREFLIGHT'
set -euo pipefail

# Tham số chỉ là giá trị đơn giản (không khoảng trắng): ssh ghép tham số thành một
# dòng lệnh và shell trên VPS tách lại theo khoảng trắng.
APP_DIR="$1"
SERVICE="$2"
ORIGIN_HEALTH_URL="$3"
REQUIRED_NODE_VERSION="$4"
ENV_FILE="$APP_DIR/shared/.env"

fail() {
    printf 'ERROR %s\n' "$*" >&2
    exit 1
}

# Đọc giá trị đầu tiên của một key trong .env, bỏ CR và cặp nháy bao ngoài.
read_env_value() {
    local value
    value="$(sed -n "/^$1=/{s/^$1=//p;q}" "$ENV_FILE" | tr -d '\r')"

    case "$value" in
        \"*\")
            value="${value#\"}"
            value="${value%\"}"
            ;;
        \'*\')
            value="${value#\'}"
            value="${value%\'}"
            ;;
    esac

    printf '%s' "$value"
}

[[ -d "$APP_DIR/releases" ]] || fail "Thiếu thư mục $APP_DIR/releases (README mục 13)"
[[ -w "$APP_DIR/releases" ]] || fail "User $(id -un) không ghi được $APP_DIR/releases"
[[ -f "$ENV_FILE" ]] || fail "Thiếu $ENV_FILE (README mục 14)"
[[ "$(stat -c %a "$ENV_FILE")" == "600" ]] || fail "$ENV_FILE phải có quyền 600 (chmod 600)"

command -v node >/dev/null 2>&1 || fail "VPS chưa cài Node.js (README mục 9)"
REQUIRED_NODE_VERSION="$REQUIRED_NODE_VERSION" node -e '
const actual = process.versions.node.split(".").map(Number);
const required = process.env.REQUIRED_NODE_VERSION.split(".").map(Number);
for (let index = 0; index < 3; index += 1) {
    if (actual[index] !== required[index]) {
        if (actual[index] < required[index]) {
            console.error(`ERROR Node VPS ${process.versions.node} không đạt yêu cầu >=${process.env.REQUIRED_NODE_VERSION}`);
            process.exit(1);
        }
        break;
    }
}
console.log(`PASS Node VPS ${process.versions.node}`);
' || fail "Node VPS không đạt yêu cầu (README mục 9)"

# App phải chỉ listen loopback, Nginx đứng trước nhận request từ Cloudflare.
[[ "$(read_env_value HTTP_HOST)" == "127.0.0.1" ]] || fail ".env phải có HTTP_HOST=127.0.0.1"

[[ "$ORIGIN_HEALTH_URL" =~ ^http://127\.0\.0\.1:([0-9]+)/health$ ]] \
    || fail "DEPLOY_ORIGIN_HEALTH_URL phải có dạng http://127.0.0.1:<PORT>/health"
ORIGIN_PORT="${BASH_REMATCH[1]}"
APP_PORT="$(read_env_value HTTP_PORT)"
APP_PORT="${APP_PORT:-6666}"
[[ "$ORIGIN_PORT" == "$APP_PORT" ]] \
    || fail "DEPLOY_ORIGIN_HEALTH_URL dùng port $ORIGIN_PORT nhưng .env có HTTP_PORT=$APP_PORT"

API_KEY_VALUE="$(read_env_value API_KEY)"
(( ${#API_KEY_VALUE} >= 24 )) || fail ".env phải có API_KEY dài ít nhất 24 ký tự (README mục 14)"
[[ "$API_KEY_VALUE" != thay-bang-* ]] || fail "API_KEY trong .env vẫn là giá trị mẫu; sinh key mới (README mục 14)"
unset API_KEY_VALUE

[[ -n "$(read_env_value NESTPROXY_PROXY_KEY)" ]] \
    || printf 'WARN .env chưa có NESTPROXY_PROXY_KEY: app sẽ gọi thẳng máy chủ TCP bằng IP VPS\n' >&2

/usr/bin/systemctl cat "$SERVICE" >/dev/null 2>&1 || fail "Chưa có systemd unit $SERVICE (README mục 15)"
sudo -n -l /usr/bin/systemctl restart "$SERVICE" >/dev/null 2>&1 \
    || fail "User $(id -un) chưa có quyền sudo -n restart $SERVICE (README mục 16)"

sudo -n /usr/sbin/nginx -t >/dev/null 2>&1 || fail "nginx -t FAIL hoặc deploy user chưa có quyền sudo cho nginx -t (README mục 16, 17)"
if ! sudo -n /usr/sbin/nginx -T 2>/dev/null | grep -F "127.0.0.1:$APP_PORT" >/dev/null; then
    fail "Nginx chưa proxy tới 127.0.0.1:$APP_PORT khớp HTTP_PORT của .env (README mục 17)"
fi
REMOTE_PREFLIGHT
then
    die "Remote preflight FAIL: xem dòng ERROR phía trên (SSH, thư mục app, .env, Node VPS, systemd, sudoers hoặc Nginx)."
fi
success "SSH $REMOTE / app dirs / .env / Node / systemd / sudoers / Nginx PASS"

# ---------------------------- Runtime package --------------------------------
info "Đóng gói runtime"
rm -rf -- "$WORK_DIR"
mkdir -p "$RUNTIME_DIR"

# Chỉ đóng gói file cần chạy: không có test, tài liệu, file Python, .env hay .git.
tar -cf - -C "$ROOT_DIR" server.js package.json src | tar -xf - -C "$RUNTIME_DIR"

GIT_COMMIT="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
if [[ -n "$(git -C "$ROOT_DIR" status --porcelain 2>/dev/null)" ]]; then
    GIT_DIRTY="true"
else
    GIT_DIRTY="false"
fi

cat > "$RUNTIME_DIR/RELEASE" <<META
release_id=$RELEASE_ID
domain=$DEPLOY_DOMAIN
git_commit=$GIT_COMMIT
git_dirty=$GIT_DIRTY
tests=$TEST_STATUS
built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
node=$(node -v)
META

tar -czf "$PACKAGE_FILE" -C "$RUNTIME_DIR" .
PACKAGE_SHA256="$(compute_sha256 "$PACKAGE_FILE")"
success "Runtime package $(du -h "$PACKAGE_FILE" | awk '{print $1}') / sha256=$PACKAGE_SHA256"

# -------------------------------- Upload -------------------------------------
info "Upload release $RELEASE_ID"
scp "${SCP_OPTS[@]}" "$PACKAGE_FILE" "$REMOTE:$REMOTE_PACKAGE"
success "Upload complete"

# ------------------------------- Remote deploy --------------------------------
info "Deploy trên VPS"
ssh "${SSH_OPTS[@]}" -T "$REMOTE" bash -s -- \
    "$DEPLOY_APP_DIR" \
    "$DEPLOY_SERVICE" \
    "$RELEASE_ID" \
    "$REMOTE_PACKAGE" \
    "$PACKAGE_SHA256" \
    "$DEPLOY_ORIGIN_HEALTH_URL" \
    "$DEPLOY_PUBLIC_HEALTH_URL" \
    "$DEPLOY_KEEP_RELEASES" <<'REMOTE_SCRIPT'
# Không dùng `set -E` và ERR trap: rollback chạy đúng một lần trong EXIT trap của
# shell chính; `set -e` bảo đảm mọi lệnh lỗi đều dẫn tới đó.
set -euo pipefail

APP_DIR="$1"
SERVICE="$2"
RELEASE_ID="$3"
PACKAGE="$4"
EXPECTED_SHA256="$5"
ORIGIN_HEALTH_URL="$6"
PUBLIC_HEALTH_URL="$7"
KEEP_RELEASES="$8"

ENV_FILE="$APP_DIR/shared/.env"
RELEASE_DIR="$APP_DIR/releases/$RELEASE_ID"
CURRENT_LINK="$APP_DIR/current"
PREVIOUS_TARGET=""
RELEASE_CREATED=0
SWITCHED=0
DEPLOY_SUCCEEDED=0
ROLLBACK_SUCCEEDED=0

# Chỉ ghi nhận previous release là thư mục thật nằm trong APP_DIR/releases, để
# rollback không bao giờ tạo symlink lỗi `current -> current`.
if [[ -L "$CURRENT_LINK" ]]; then
    candidate_previous="$(readlink -f -- "$CURRENT_LINK" 2>/dev/null || true)"
    if [[ -n "$candidate_previous" \
        && "$candidate_previous" != "$CURRENT_LINK" \
        && "$candidate_previous" == "$APP_DIR/releases/"* \
        && -d "$candidate_previous" ]]; then
        PREVIOUS_TARGET="$candidate_previous"
    fi
fi

log() { printf 'REMOTE ==> %s\n' "$*"; }

restart_service() {
    sudo -n /usr/bin/systemctl restart "$SERVICE"
}

# Health hợp lệ khi app trả JSON có "status":"ok".
wait_origin_health() {
    local attempt health_body
    for attempt in $(seq 1 30); do
        health_body="$(curl -fsS --max-time 5 "$ORIGIN_HEALTH_URL" 2>/dev/null || true)"
        if grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"' <<<"$health_body"; then
            return 0
        fi
        sleep 2
    done
    printf 'Origin health cuối cùng: %s\n' "${health_body:-<không phản hồi>}" >&2
    return 1
}

on_exit() {
    local exit_code="$?"

    # Rollback là best-effort: không để một lệnh chẩn đoán lỗi cắt ngang handler.
    set +e

    if [[ "$DEPLOY_SUCCEEDED" -eq 1 ]]; then
        rm -f -- "$PACKAGE"
        exit "$exit_code"
    fi

    if [[ "$exit_code" -eq 0 ]]; then
        exit_code=1
    fi

    printf 'REMOTE ERROR: deploy thất bại.\n' >&2

    # Lỗi trước bước chuyển `current`: release mới chưa từng chạy, xóa luôn để
    # không bị tính vào KEEP_RELEASES và đẩy mất release tốt dùng để rollback.
    if [[ "$SWITCHED" -eq 0 \
        && "$RELEASE_CREATED" -eq 1 \
        && -d "$RELEASE_DIR" \
        && "$(readlink -f "$CURRENT_LINK" 2>/dev/null)" != "$RELEASE_DIR" ]]; then
        printf 'REMOTE ==> Xóa release chưa chuyển %s\n' "$RELEASE_DIR" >&2
        rm -rf -- "$RELEASE_DIR"
    fi

    # In lỗi thật của service trước khi đổi `current`, để chẩn đoán ngay từ output deploy.
    if [[ "$SWITCHED" -eq 1 ]]; then
        printf 'REMOTE ==> Service status\n' >&2
        /usr/bin/systemctl status "$SERVICE" --no-pager -l >&2
        printf 'REMOTE ==> Service journal (last 100 lines)\n' >&2
        sudo -n /usr/bin/journalctl -u "$SERVICE" -n 100 --no-pager >&2 \
            || /usr/bin/journalctl -u "$SERVICE" -n 100 --no-pager >&2
    fi

    if [[ "$SWITCHED" -eq 1 \
        && -n "$PREVIOUS_TARGET" \
        && "$PREVIOUS_TARGET" != "$CURRENT_LINK" \
        && "$PREVIOUS_TARGET" == "$APP_DIR/releases/"* \
        && -d "$PREVIOUS_TARGET" ]]; then
        printf 'REMOTE ==> Rollback về %s\n' "$PREVIOUS_TARGET" >&2
        rm -f "$APP_DIR/current.rollback"
        if ln -s "$PREVIOUS_TARGET" "$APP_DIR/current.rollback" \
            && mv -Tf "$APP_DIR/current.rollback" "$CURRENT_LINK" \
            && restart_service \
            && wait_origin_health; then
            ROLLBACK_SUCCEEDED=1
            printf 'REMOTE ==> Rollback health PASS\n' >&2
        else
            printf 'REMOTE ==> CẢNH BÁO: rollback symlink, service hoặc health vẫn FAIL\n' >&2
        fi
    elif [[ "$SWITCHED" -eq 1 ]]; then
        printf 'REMOTE ==> Không có previous release hợp lệ để rollback; giữ release lỗi để debug.\n' >&2
        # Tránh systemd tự restart liên tục ở lần deploy đầu tiên bị lỗi.
        sudo -n /usr/bin/systemctl stop "$SERVICE" >/dev/null 2>&1
    fi

    # Chỉ xóa release lỗi sau khi rollback đã health PASS; lần deploy đầu tiên
    # (hoặc rollback cũng lỗi) thì giữ lại để kiểm tra.
    if [[ "$ROLLBACK_SUCCEEDED" -eq 1 \
        && -d "$RELEASE_DIR" \
        && "$(readlink -f "$CURRENT_LINK" 2>/dev/null)" != "$RELEASE_DIR" ]]; then
        rm -rf -- "$RELEASE_DIR"
    fi

    rm -f -- "$PACKAGE"
    exit "$exit_code"
}
trap on_exit EXIT

if [[ ! "$KEEP_RELEASES" =~ ^[1-9][0-9]*$ ]]; then
    printf 'KEEP_RELEASES phải là số nguyên dương: %s\n' "$KEEP_RELEASES" >&2
    exit 1
fi

log "Verify package"
printf '%s  %s\n' "$EXPECTED_SHA256" "$PACKAGE" | sha256sum -c -

[[ ! -e "$RELEASE_DIR" ]] || { printf 'Release đã tồn tại: %s\n' "$RELEASE_DIR" >&2; exit 1; }

umask 022
mkdir -p "$RELEASE_DIR"
RELEASE_CREATED=1
tar -xzf "$PACKAGE" -C "$RELEASE_DIR"
chmod 755 "$RELEASE_DIR"

# File gửi từ Windows có thể dùng xuống dòng CRLF: đổi về LF cho đồng nhất.
find "$RELEASE_DIR" -type f \( -name '*.js' -o -name '*.json' \) -exec sed -i 's/\r$//' {} +

[[ -f "$RELEASE_DIR/server.js" ]]
[[ -f "$RELEASE_DIR/package.json" ]]
[[ -f "$RELEASE_DIR/src/configuration.js" ]]
[[ -f "$RELEASE_DIR/RELEASE" ]]
[[ -f "$ENV_FILE" ]]

log "Link persistent .env"
ln -s "$ENV_FILE" "$RELEASE_DIR/.env"

# Chỉ đọc và kiểm tra cấu hình bằng code của release mới với .env thật.
log "Runtime env validation"
(
    cd "$RELEASE_DIR"
    node --env-file="$ENV_FILE" --input-type=module -e "
const { loadConfiguration } = await import('./src/configuration.js');
loadConfiguration();
console.log('Configuration OK');
"
)

# Mở thử kết nối tới máy chủ TCP qua nestproxy bằng code của release mới. Lỗi chỉ
# cảnh báo: máy chủ TCP/proxy chập chờn không phải lý do để chặn deploy.
log "TCP connectivity check"
(
    cd "$RELEASE_DIR"
    node --env-file="$ENV_FILE" --input-type=module -e "
const { loadConfiguration } = await import('./src/configuration.js');
const { TcpClient } = await import('./src/transport/tcp-client.js');
const { NestproxyClient } = await import('./src/proxy/nestproxy-client.js');
const configuration = loadConfiguration();
const transportOptions = { ...configuration.transportOptions };
let route = 'gọi thẳng, không proxy';
if (configuration.nestproxyProxyKey) {
    const nestproxyClient = new NestproxyClient({ proxyKey: configuration.nestproxyProxyKey });
    transportOptions.proxyUrl = await nestproxyClient.getProxyUrl();
    route = 'qua nestproxy ' + transportOptions.proxyUrl.replace('socks5://', '');
}
const tcpClient = new TcpClient(transportOptions);
await tcpClient.connect();
tcpClient.close();
console.log('PASS TCP ' + transportOptions.serverHost + ':' + transportOptions.serverPort + ' (' + route + ')');
"
) || printf 'REMOTE WARN: Không kết nối được tới máy chủ TCP (kiểm tra NESTPROXY_PROXY_KEY hoặc máy chủ TCP)\n' >&2

log "Atomic switch current -> $RELEASE_ID"
rm -f "$APP_DIR/current.new"
ln -s "$RELEASE_DIR" "$APP_DIR/current.new"
mv -Tf "$APP_DIR/current.new" "$CURRENT_LINK"
SWITCHED=1

log "Restart $SERVICE"
restart_service

log "Origin health check"
if ! wait_origin_health; then
    printf 'Origin health FAIL: %s\n' "$ORIGIN_HEALTH_URL" >&2
    exit 1
fi
printf 'REMOTE ==> Origin health PASS\n'

# Lỗi Cloudflare/mạng công khai không phải lý do rollback một origin đang khỏe.
log "Public health check"
if curl -fsS --max-time 15 "$PUBLIC_HEALTH_URL" \
    | grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"'; then
    printf 'REMOTE ==> Public health PASS\n'
else
    printf 'REMOTE WARN: Public health failed but origin is healthy: %s\n' "$PUBLIC_HEALTH_URL" >&2
fi

DEPLOY_SUCCEEDED=1

# Giữ N release mới nhất theo tên (YYYYMMDD-HHMMSS nên sort tên đúng thứ tự thời
# gian). Không bao giờ xóa target hiện tại. Lỗi prune chỉ cảnh báo.
log "Prune old releases (keep $KEEP_RELEASES)"
CURRENT_TARGET="$(readlink -f "$CURRENT_LINK")"
mapfile -t RELEASE_NAMES < <(
    find "$APP_DIR/releases" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' \
        | grep -E '^[0-9]{8}-[0-9]{6}$' \
        | sort -r
)
if (( ${#RELEASE_NAMES[@]} > KEEP_RELEASES )); then
    for old_release_name in "${RELEASE_NAMES[@]:KEEP_RELEASES}"; do
        old_release="$APP_DIR/releases/$old_release_name"
        if [[ "$old_release" != "$CURRENT_TARGET" ]]; then
            rm -rf -- "$old_release" \
                || printf 'REMOTE WARN: không xóa được %s\n' "$old_release" >&2
        fi
    done
fi

printf 'REMOTE ==> DEPLOY SUCCESS: %s\n' "$RELEASE_ID"
REMOTE_SCRIPT

success "DEPLOY SUCCESS $RELEASE_ID -> https://$DEPLOY_DOMAIN"
