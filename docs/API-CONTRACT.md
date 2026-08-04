# API 契约

以下描述基于当前实现。模型发现和推理路由都以当前凭据对应的 Qoder 官方 `assistant` 模型目录为权威来源，不维护静态生产模型表。

## 认证

除 `GET /health` 外，本文所有路由都要求与 Messages API 相同的代理认证：

- `x-api-key: <QODER_PROXY_API_KEY>`；或
- `Authorization: Bearer <QODER_PROXY_API_KEY>`。

比较使用定长时间比较。未配置服务端 API key 时返回 HTTP 500；凭据错误或缺失时返回 HTTP 401 `authentication_error`。

## 路由

### `GET /health`

返回 `{"status":"ok"}`，HTTP 200。仅用于存活探测，不发起任何上游调用。

### `GET /v1/models`

要求请求头 `anthropic-version: 2023-06-01`。代理只遍历官方 Qoder 根对象的 `assistant` 数组，因此忽略整个独立的 `byok_enterprise` scene；同时额外过滤 `assistant` 内显式标记 `server_scene === "byok_enterprise"` 的条目。其余 `enable` 不为 `false` 且不为 `0` 的模型按官方 `assistant` 数组权威顺序返回。BYOK 边界不使用 `source`、`provider`、URL 或 key 前缀猜测。目录没有可信发布时间时不会伪造 recent 排序，也不会反转上游顺序。

支持的查询参数：

| 参数 | 语义 |
|---|---|
| `limit` | 每页数量，默认 `20`，范围 `1-1000` |
| `after_id` | 返回该精确模型 ID 之后的一页 |
| `before_id` | 返回该精确模型 ID 之前的一页 |

`before_id` 与 `after_id` 不能同时提供。未知参数、重复参数、空游标、未知游标或越界 `limit` 返回 HTTP 400 `invalid_request_error`。

响应包含 `data`、`has_more`、`first_id`、`last_id`。空页的 `first_id` / `last_id` 为 `null`。每个模型对象包含当前 Anthropic Models API 的 `id`、`type`、`display_name`、`created_at`、`max_input_tokens`、`max_tokens` 和 `capabilities`。

`created_at` 固定为 Unix epoch，避免把非 ABI 字段误当发布时间。`max_tokens` 为目录明确输出上限与代理硬上限 `1024` 的较小值；目录未提供时返回 `1024`。`capabilities` 描述本代理当前实际支持面，因此全部为 `supported: false`，不会把 Qoder 的 `is_vl` / `is_reasoning` 误映射为 Anthropic 代理能力。

成功与错误响应都带 `request-id` 响应头和 `Cache-Control: private, no-store`；错误 JSON 额外带同值的顶层 `request_id`。

### `GET /v1/models/:model_id`

路径参数由路由层 URL 解码一次，再对当前启用目录做大小写敏感的精确 ID 查找。不存在、disabled、display name 或任意 alias 都返回 HTTP 404 `not_found_error`。该路由不接受查询参数。

公开 `id` 是官方 Qoder routing key，例如当前已核实的：

- `qmodel_38max` → `Qwen3.8-Max`

目录没有提供独立 provider/canonical ID，因此代理不会构造 `qwen3.8-max-preview` 等猜测 ID。Claude Code 或其他客户端 UI 显示的模型层级标签不等同于 Qoder routing key；以 `/v1/models` 与实际解析结果为准。

### `POST /v1/messages/count_tokens`

返回保守估算的 `{"input_tokens": <正整数>}`，HTTP 200。

**待验证**：当前不是 Anthropic 官方 tokenizer 的精确计数，不能用于账单或硬上下文边界。

### `POST /v1/messages`

接收 Anthropic Messages 请求体，先解析并验证模型，再转换为 CN legacy body，通过 Auth WASM 签名后转发给 CN 推理网关，将 CN legacy SSE 转换为流式或非流式 Anthropic 响应。

模型解析顺序：

1. 请求显式提供 `model`：必须精确匹配当前启用目录，否则 HTTP 404，且不发起推理。
2. 请求省略 `model` 且配置 `QODER_CN_INFER_MODEL_KEY`：配置值必须精确匹配当前启用目录，否则 fail-closed 返回 HTTP 500。
3. 两者都没有：使用目录中启用的精确 `auto` 条目；不存在则 HTTP 500。

解析后的 routing key 同时用于 CN `model_config.key`、官方 `prepareInferRequest(..., modelKey)`，以及 Anthropic 流式/非流式响应的 `model` 字段。不会回显未经目录验证的客户端标签。解析结果与不可变目录 snapshot 的 generation 绑定；若目录刷新发生在解析与签名之间，签名 fail-closed 并重新读取当前 snapshot。推理 401 刷新后也会重新获取目录、重新解析和重新转换请求体。

仅在显式启用本地 QA routing attestation 时，代理会把上述四个模型边界和精确调用计数写入私有 JSONL 证据文件；它不是 HTTP 响应的一部分，也不会改变任何 API 响应、请求头或上游请求。

## 请求体字段支持矩阵

已识别的顶层字段（`ANTHROPIC_KNOWN`）：
`model`、`system`、`messages`、`tools`、`max_tokens`、`tool_choice`、`stream`、`metadata`、`stop_sequences`、`thinking`、`context_management`、`output_config`

其中不直接透传给 CN legacy 的字段（`ANTHROPIC_IGNORED`）：
`metadata`、`stop_sequences`、`thinking`、`context_management`、`output_config`、`model`、`stream`

`model` 虽不作为原始字段透传，但会在官方目录验证后转换为受信 routing key。其他忽略字段会记录到内部 provenance，不回传给客户端。未知顶层字段返回 HTTP 400 `invalid_request_error`。

## 显式拒绝（HTTP 400，`type: "invalid_request_error"`）

- 请求体不是合法 JSON
- 顶层存在未知字段
- `model` 不是非空字符串
- `messages` 为空数组或非数组
- 某条 message 的 `role` 不受支持
- `assistant` / `user` 消息中出现不支持的 content block
- `tool_choice.type === "tool"`
- `tool_choice` 取值不受支持

## `max_tokens`

- CN 侧硬上限：`MAX_CN_MAX_TOKENS = 1024`
- 请求值超过上限时截断为 1024，并记录内部 provenance

## 并行工具

- 上限：`MAX_PARALLEL_TOOLS = 2`
- 含 `tools` 的请求先完整缓冲并验证上游 SSE；验证成功后，流式请求由代理回放已验证的 Anthropic SSE，非流式请求返回已验证 Message
- 四类 tool finalize 格式错误（缺少 id、缺少 name、arguments 非法 JSON、arguments 非 object）最多由代理在尚未向客户端发送任何 SSE 前重试一次
- 两次均失败时返回 HTTP 503 `api_error`，并带 `x-should-retry: true`；不发送部分或伪造的 SSE
- 无 `tools` 请求保持原有流式路径
- 聚合阶段检测到超过 2 个并行 tool call 时仍 fail-closed，不重试、不串行化、不丢弃第三个工具

## 模型目录获取与错误映射

代理使用官方 Auth WASM 通用签名入口构造：

```text
GET https://gateway.qoder.com.cn/api/v2/model/list?Encode=1
```

响应经过有界读取、官方明文/解密语义、JSON 解析和严格 `assistant` scene 校验。生产路径远端优先，只保留脱敏、不可变的进程内 snapshot；不读取磁盘目录缓存。目录按 Promise single-flight 缓存，默认 TTL 为 100 秒；凭据刷新后立即失效。TTL 到期后的刷新失败返回 502，不无限使用 stale 数据。目录 401 使用现有刷新 single-flight 后仅重试一次。

| 场景 | 响应 |
|---|---|
| 目录上游 401 / 403 / 429 | 对应 HTTP 状态及 Anthropic 风格认证/权限/限流错误类型，消息固定为 `model catalog unavailable` |
| 目录上游 400、404、5xx，以及网络、解密或 schema 失败 | HTTP 502 `api_error`，不暴露上游原文 |
| 推理网关 HTTP 非 2xx | 对应既有 400/401/403/429 映射；其他状态为 HTTP 502 |
| 代理内部异常 | HTTP 500 `api_error`；详细错误只进入脱敏日志 |
| 请求体转换失败 | HTTP 400 `invalid_request_error` |
