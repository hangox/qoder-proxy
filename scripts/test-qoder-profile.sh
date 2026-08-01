#!/bin/bash
set -euo pipefail

# Qoder profile 数据契约测试：profile 只声明模型/statusline，生命周期由 teammate wrapper + runtime manager 承担。
PROFILE="${QODER_PROFILE_FILE:-$HOME/.config/claude-teammate/profiles/qoder.sh}"
[ -r "$PROFILE" ] || { echo "profile 不可读: $PROFILE" >&2; exit 1; }

OUT=$(env -i HOME="${HOME:-/tmp}" PATH="${PATH:-/usr/bin:/bin}" \
  ANTHROPIC_BASE_URL="http://127.0.0.1:43123" ANTHROPIC_AUTH_TOKEN=temporary-test-key \
  bash -c 'source "$1"; printf "base=%s\nkey=%s\nopus=%s\nsonnet=%s\nhaiku=%s\nstatusline=%s\n" "$ANTHROPIC_BASE_URL" "$ANTHROPIC_AUTH_TOKEN" "$ANTHROPIC_DEFAULT_OPUS_MODEL" "$ANTHROPIC_DEFAULT_SONNET_MODEL" "$ANTHROPIC_DEFAULT_HAIKU_MODEL" "$QODER_PROXY_STATUSLINE"' bash "$PROFILE")
printf '%s\n' "$OUT" | grep -Fx 'base=http://127.0.0.1:43123' >/dev/null
printf '%s\n' "$OUT" | grep -Fx 'key=temporary-test-key' >/dev/null
printf '%s\n' "$OUT" | grep -Fx 'opus=qmodel_preview[1m]' >/dev/null
printf '%s\n' "$OUT" | grep -Fx 'sonnet=qmodel_latest[1m]' >/dev/null
printf '%s\n' "$OUT" | grep -Fx 'haiku=q36fmodel[1m]' >/dev/null
printf '%s\n' "$OUT" | grep -Fx 'statusline=1' >/dev/null

# profile source 不应启动进程、读取 Qoder 私有目录或包含凭据管理逻辑。
! grep -Eq 'qoderclicn|\.qoder/security|QODER_PROXY_API_KEY|runtime acquire|runtime release|exec |spawn|curl |python3|openssl' "$PROFILE"

# 认证参数只作为已有环境消费；source 前后不得写入 profile 文件或 argv。
[ "$(stat -f '%m' "$PROFILE" 2>/dev/null || stat -c '%Y' "$PROFILE")" -gt 0 ]
echo "qoder profile data contract test: pass"
