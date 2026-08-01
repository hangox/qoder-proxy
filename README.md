# qoder-proxy

Anthropic Messages API → Qoder 中国站 legacy 接口的本地代理。基础 Gate 1 链路曾在历史固定快照上完成 GO 验收；其脱敏真实 Qoder、Claude CLI 与凭据导入证据见 [`docs/GATE1-EVIDENCE.md`](docs/GATE1-EVIDENCE.md)。此后新增的 Models API / 动态目录实现属于后续变更，必须以当前 Reviewer 与 QA 结论为准，不能沿用历史 GO 自动视为已最终认证。

## 现状

- HTTP 路由与请求编排：`src/proxy.ts`
- 模型目录领域层：`src/models.ts`
- Auth WASM、凭据与会话：`src/auth/`
- CLI 入口：`src/cli.ts`
- 日志：`src/logger.ts`

## 运行

```bash
bun install
bun start          # 直接运行 src/cli.ts
bun dev             # watch 模式
bun run build       # 产出 dist/qoder-proxy.js
bun run start:dist  # 运行构建产物
```

本地验包或发布后也可通过 scoped npm 包安装；运行时仍要求 Bun：

```bash
npm install -g @hangox/qoder-proxy
qoder-proxy auth import-qoder
qoder-proxy serve
```

监听端口由 `PORT` 环境变量指定，未设置时使用 `7788`（见 `docs/CONFIG.md`）。

## 模型发现与路由

代理从当前账号的官方 Qoder `assistant` 模型目录动态发现可用模型；不会维护静态生产列表，也不会猜测 provider ID。先查询当前启用的 routing key：

```bash
curl -sS http://127.0.0.1:7788/v1/models \
  -H "x-api-key: $QODER_PROXY_API_KEY" \
  -H "anthropic-version: 2023-06-01"
```

指定官方 routing key 发起 Messages 请求：

```bash
curl -sS http://127.0.0.1:7788/v1/messages \
  -H "content-type: application/json" \
  -H "x-api-key: $QODER_PROXY_API_KEY" \
  -d '{
    "model": "qmodel_preview",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "你好"}]
  }'
```

当前已核实映射：`qmodel_preview` → `Qwen3.8-Max-Preview`。该 ID 会同时进入 CN `model_config.key`、官方签名 `prepareInferRequest` 和 Anthropic 响应的 `model` 字段。请求省略 `model` 时，可用 `QODER_CN_INFER_MODEL_KEY` 设置代理默认值；该值仍必须存在于当前启用目录，否则代理 fail-closed。未设置默认值时使用启用的 `auto` 条目。

## 导入已有 Qoder 登录

导入命令只在本地读取并校验来源，不发网络请求，也不要求 `QODER_PROXY_API_KEY`：

```bash
# 仅验证来源、官方 WASM 解密、字段映射和目标状态；零写入
bun src/cli.ts auth import-qoder

# 已有代理凭据时，必须显式确认替换
bun src/cli.ts auth import-qoder --apply --replace

# 可选自定义来源；必须是绝对路径
bun src/cli.ts auth import-qoder --source-dir "$HOME/.qoder-cn/.auth"
```

应用成功会返回脱敏的 backup ID。若 stdout 中断或进程在 durable commit 后退出，可重新发现未确认导入；验证新凭据后确认，或在当前目标未变化时回滚：

```bash
bun src/cli.ts auth import-status
bun src/cli.ts auth finalize-import --backup-id <uuid>
bun src/cli.ts auth rollback-import --backup-id <uuid>
```

存在 committed 但未 finalize 的 backup 时，代理仍可加载当前凭据，但所有 token rotation/save/delete 会 fail-closed；必须先 `finalize-import` 或 `rollback-import`。

运行代理时也可从安全文件读取 machine ID；不能与 `QODER_CN_MACHINE_ID` 同时设置：

```bash
QODER_CN_MACHINE_ID_FILE="$HOME/.qoder-cn/.auth/machine_id" bun start
```

## 模型发现

`GET /v1/models` 与 `GET /v1/models/:model_id` 使用当前凭据对应的官方 Qoder `assistant` 目录。除代理 API key 外，请求必须带：

```text
anthropic-version: 2023-06-01
```

目录默认缓存 100 秒，远端刷新失败不会无限返回旧 entitlement。Models 响应带 `request-id` 和 `Cache-Control: private, no-store`。

## 测试

```bash
bun test          # 一次性运行 vitest
bun test:watch    # watch 模式
```

## 类型检查

```bash
bun run typecheck
```

## 文档索引

| 文档 | 内容 |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 架构、数据流、WASM Auth Bridge、参考仓库 |
| [docs/SECURITY.md](docs/SECURITY.md) | 安全边界，已核实 / 待验证声明 |
| [docs/CONFIG.md](docs/CONFIG.md) | 环境变量、凭据文件契约 |
| [docs/API-CONTRACT.md](docs/API-CONTRACT.md) | 路由、字段支持矩阵、错误映射 |
| [docs/SSE-PROTOCOL.md](docs/SSE-PROTOCOL.md) | CN legacy SSE 解析与 Anthropic SSE 发射 |
| [docs/GATE1-EVIDENCE.md](docs/GATE1-EVIDENCE.md) | 历史基础 Gate 1 脱敏验收证据、真实 E2E 计数与适用范围 |

## Gate 状态

历史基础 Gate 1 快照曾采用最小真实认证合同：Qoder preflight 1 次 + 无工具文本 inference 1 次；隔离 `claude -p` preflight 1 次 + invocation/inference 各 1 次；两者 refresh、retry、tools 均为 0。凭据导入当时完成 dry-run、apply/replace、真实验证和 finalize。该证据不覆盖此后新增的 Models API / 动态目录代码；当前实现是否放行以最新冻结快照的独立 Reviewer 与 QA 结果为准。

没有为了取证而故意触发 live 401/refresh；不得仅为补充证据主动制造凭据失败。完整证据、秘密处理边界和仍未支持的协议范围见 [`docs/GATE1-EVIDENCE.md`](docs/GATE1-EVIDENCE.md)。
