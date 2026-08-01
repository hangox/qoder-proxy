# qoder-proxy CLAUDE.md

Anthropic Messages → Qoder 中国站 legacy 代理。Gate 1 Walking Skeleton 阶段。

## 参考仓库（只读）

- `codemaker-proxy`：工程形态参考（Hono 服务、CLI 生命周期、并行工具索引 Map）。**只读不改**。
- `codex-proxy`：协议健壮性参考（SSE frame parser、tool 状态机、Anthropic block 生命周期）。**只读不改**。
- `experiments/qoder-cn-auth-bridge-poc.ts`：Gate 0 已验证 PoC。**只读不改**——迁移已验证能力，不复制临时 capture/replay 探针。

## 已验证最小 body 原则

所有 CN legacy 请求字段必须来自 Gate 0 真实证据（PoC SHA 见记忆记录）。禁止猜测未验证字段。未知字段 fail-closed。

## 凭据安全

- 凭据永不入库（`.gitignore` 覆盖 `auth-*.json`）。
- token 不得进入 argv、日志或报告。
- 生产请求全内存，不落盘 capture。
- 生产代理不得读取 Qoder 私有凭据目录；仅用户显式执行受审计的 `auth import-qoder` 时，允许读取指定来源目录下精确的 `machine_id` 与 `user`，禁止枚举或读取 `security/` 等其他内容。
- 不得启动 `qoderclicn` 子进程；只允许只读官方二进制并在内存中加载 Auth WASM。

## 协议约束

- 首版最多并行双工具，3+ fail-closed。
- 不支持 `thinking`、`tool_choice type=tool`——必须明确返回错误或可观测降级。
- `metadata` 等语义字段显式降级（记录到 provenance，不静默丢弃，provenance 不进入上游 body）。
- `max_tokens` 上限 1024（已验证范围），超出显式记录截断。
