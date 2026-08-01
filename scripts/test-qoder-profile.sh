#!/bin/bash
set -euo pipefail

# Qoder profile 独立生命周期测试：普通会话无 ccsqc 环境、复用已有代理、认证不进 argv、三档模型与 statusline marker。
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PROFILE="${QODER_PROFILE_FILE:-$HOME/.config/claude-teammate/profiles/qoder.sh}"
[ -r "$PROFILE" ] || { echo "profile 不可读: $PROFILE" >&2; exit 1; }
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/qoder-profile-test.XXXXXX")
cleanup() {
  if [ -n "${STANDALONE_PID:-}" ] && kill -0 "$STANDALONE_PID" 2>/dev/null; then
    kill -TERM "$STANDALONE_PID" 2>/dev/null || true
    wait "$STANDALONE_PID" 2>/dev/null || true
  fi
  if command -v trash >/dev/null 2>&1; then
    trash "$TMP_DIR" 2>/dev/null || true
  else
    printf '[WARN] trash 不可用，保留临时目录: %s\n' "$TMP_DIR" >&2
  fi
}
trap cleanup EXIT

FAKE_BIN="$TMP_DIR/fake-qoder-proxy"
ARGS_FILE="$TMP_DIR/args"
ENV_FILE="$TMP_DIR/env"
cat > "$FAKE_BIN" <<'SH'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" > "$FAKE_ARGS_FILE"
printf '%s\n' "${QODER_PROXY_API_KEY:-}" > "$FAKE_ENV_FILE"
exec python3 - "$PORT" <<'PY'
import json
import signal
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port = int(sys.argv[1])
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/internal/quota":
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"percentage": 12, "used": 3, "total": 25, "remaining": 22, "unit": "requests"}).encode())
    def log_message(self, *_):
        pass
server = HTTPServer(("127.0.0.1", port), Handler)
signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
server.serve_forever()
PY
SH
chmod 700 "$FAKE_BIN"

run_profile() {
  FAKE_ARGS_FILE="$ARGS_FILE" FAKE_ENV_FILE="$ENV_FILE" QODER_PROXY_BIN="$FAKE_BIN" \
    QODER_PROXY_DIR="$ROOT_DIR" HOME="$HOME" \
    ANTHROPIC_BASE_URL="${1:-}" ANTHROPIC_AUTH_TOKEN="${2:-}" \
    bash -c 'source "$1"; printf "base=%s\nkey=%s\nopus=%s\nsonnet=%s\nhaiku=%s\nstatusline=%s\n" "$ANTHROPIC_BASE_URL" "$ANTHROPIC_AUTH_TOKEN" "$ANTHROPIC_DEFAULT_OPUS_MODEL" "$ANTHROPIC_DEFAULT_SONNET_MODEL" "$ANTHROPIC_DEFAULT_HAIKU_MODEL" "$QODER_PROXY_STATUSLINE"' bash "$PROFILE"
}

# 普通 Claude 会话：没有 ccsqc 的 URL/token，profile 自己启动代理并完成 readiness。
OUT=$(run_profile)
printf '%s\n' "$OUT" | grep -E '^base=http://127\.0\.0\.1:[0-9]+$' >/dev/null
printf '%s\n' "$OUT" | grep -Fx 'opus=qmodel_preview[1m]' >/dev/null
printf '%s\n' "$OUT" | grep -Fx 'sonnet=qmodel_latest[1m]' >/dev/null
printf '%s\n' "$OUT" | grep -Fx 'haiku=q36fmodel[1m]' >/dev/null
printf '%s\n' "$OUT" | grep -Fx 'statusline=1' >/dev/null
[ "$(cat "$ARGS_FILE")" = "serve" ]
[ -n "$(cat "$ENV_FILE")" ]
! grep -F "$(cat "$ENV_FILE")" "$ARGS_FILE"

# 源码 fallback：没有已安装 npm CLI 时，profile 通过 bun src/cli.ts serve 启动。
FAKE_BUN_DIR="$TMP_DIR/bin"
mkdir -p "$FAKE_BUN_DIR"
cat > "$FAKE_BUN_DIR/bun" <<SH
#!/bin/bash
exec "$FAKE_BIN" "\$@"
SH
chmod 700 "$FAKE_BUN_DIR/bun"
rm -f "$ARGS_FILE" "$ENV_FILE"
OUT=$(FAKE_ARGS_FILE="$ARGS_FILE" FAKE_ENV_FILE="$ENV_FILE" QODER_PROXY_BIN= \
  QODER_PROXY_DIR="$ROOT_DIR" PATH="$FAKE_BUN_DIR:$PATH" \
  ANTHROPIC_BASE_URL= ANTHROPIC_AUTH_TOKEN= \
  bash -c 'source "$1"; printf "base=%s statusline=%s\n" "$ANTHROPIC_BASE_URL" "$QODER_PROXY_STATUSLINE"' bash "$PROFILE")
printf '%s\n' "$OUT" | grep -E '^base=http://127\.0\.0\.1:[0-9]+ statusline=1$' >/dev/null
[ "$(cat "$ARGS_FILE")" = "src/cli.ts serve" ]
[ -n "$(cat "$ENV_FILE")" ]

# 复用已有 loopback 代理：profile 不重新启动 QODER_PROXY_BIN。
PORT_FILE="$TMP_DIR/port"
python3 - "$PORT_FILE" <<'PY' &
import json
import os
import signal
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port_file = sys.argv[1]
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/internal/quota":
            self.send_response(404); self.end_headers(); return
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps({"percentage": 1}).encode())
    def log_message(self, *_): pass
server = HTTPServer(("127.0.0.1", 0), Handler)
with open(port_file, "w") as f: f.write(str(server.server_port))
signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
server.serve_forever()
PY
STANDALONE_PID=$!
for _ in $(seq 1 50); do [ -s "$PORT_FILE" ] && break; sleep 0.1; done
[ -s "$PORT_FILE" ]
PORT=$(cat "$PORT_FILE")
rm -f "$ARGS_FILE" "$ENV_FILE"
OUT=$(FAKE_ARGS_FILE="$ARGS_FILE" FAKE_ENV_FILE="$ENV_FILE" QODER_PROXY_BIN="$FAKE_BIN" \
  ANTHROPIC_BASE_URL="http://127.0.0.1:$PORT" ANTHROPIC_AUTH_TOKEN=existing-key \
  bash -c 'source "$1"; printf "%s %s %s\n" "$ANTHROPIC_BASE_URL" "$ANTHROPIC_AUTH_TOKEN" "$QODER_PROXY_STATUSLINE"' bash "$PROFILE")
printf '%s\n' "$OUT" | grep -Fx "http://127.0.0.1:$PORT existing-key 1" >/dev/null
[ ! -e "$ARGS_FILE" ]
[ ! -e "$ENV_FILE" ]

# 静态安全断言：profile 不启动 qoderclicn、不读取 security、也不把认证写入 argv。
! grep -Eq 'qoderclicn|\.qoder/security' "$PROFILE"

echo "qoder profile lifecycle test: pass"
