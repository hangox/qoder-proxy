# SSE 协议说明

## CN legacy → 内部解析

### 帧解析（`parseSseFrames`）

- 按标准 SSE 规范以空行（`\n\n`）切分帧，兼容 `\r\n`
- 每帧提取 `event:`（默认 `message`）与多行 `data:`（换行拼接）

### 双信封解包（`unwrapEnvelope`）

CN legacy 响应在标准 SSE `data:` 之外还包了一层信封：

- 外层 JSON 的 `body` 字段若为字符串，视为内层 JSON 的序列化结果，需要二次 `JSON.parse`
- 内层 `body === "[DONE]"` 时视为流结束哨兵
- 外层 JSON 若无字符串 `body` 字段，则外层本身即为有效载荷

### tool_call 增量聚合

- 以 `${outerIndex}:${tc.index}` 为 key 聚合分片（当前实现固定 `outerIndex = 0`）
- 首次出现 `id` 后再次出现不同 `id` 视为冲突，立即发 `error` 事件并中断流
- `arguments` 按分片顺序做字符串拼接，不做增量 JSON 校验
- `finish_reason` 出现时按 `index` 排序统一发射已聚合的 `tool_use` blocks

## Anthropic SSE 发射（`emitAnthropicSseStream`）

### 正常事件序列

```
message_start
(content_block_start → content_block_delta* → content_block_stop)*   // 文本块 / tool_use 块，按顺序追加 index
message_delta   // stop_reason: "end_turn" | "tool_use"
message_stop
```

### 无 CN 响应体时（`cnBody` 为空）

直接发 `message_delta`（`stop_reason: "end_turn"`）→ `message_stop`，不产生任何 content block。

### 错误路径

| 触发条件 | 行为 |
|---|---|
| CN SSE `event: error` 帧 | 关闭已打开文本块 → 发 `error` 事件（`api_error` / `"upstream error"`）→ 停止读取 |
| 内层 chunk 携带 `error` 字段 | 同上，消息为 `"upstream chunk error"` |
| tool_call 聚合阶段 `id` 冲突 | 发 `error` 事件并中断流；不重试 |
| 聚合后 finalize 格式错误 | 内部细分为 `missing-id`、`missing-name`、`invalid-json`、`non-object`，仅写固定 reason、索引、参数字节数和 fragment 数，不记录 id/name/arguments |
| 无 tools 的流式请求遇到错误 | 保持原有已发 SSE 的 `error` 事件路径 |
| 含 tools 的请求 finalize 失败 | 在客户端收到任何 SSE 前重试一次；成功则回放完整已验证 Anthropic SSE |
| 含 tools 的请求连续两次 finalize 失败 | 返回 HTTP 503 JSON `api_error` 与 `x-should-retry: true`，不发送部分 SSE |
| 并行 tool_call 超过上限 | 仍 fail-closed，不重试、不串行化、不丢弃第三个工具 |
| 流处理过程中抛出未捕获异常 | 发 `error` 事件（`"proxy stream error"`）后关闭流 |
