# 安全边界

本文档逐条对照 `CLAUDE.md`「凭据安全」章节与当前代码实现，标注核实状态。**核实状态基于静态代码检查，不代表已有 Gate 1 运行时证据**（运行时证据见 `docs/GATE1-EVIDENCE.md`）。

## 已核实（有明确代码依据）

| 声明 | 依据 | 状态 |
|---|---|---|
| 凭据永不入库 | `.gitignore` 覆盖 `auth-*.json`、`**/auth-cn.json` | 已核实（仓库配置层面） |
| 凭据文件权限收紧 | `createConfigStore`：目录以 `mkdir(..., { mode: 0o700 })` 创建，文件写入后 `chmod(0o600)` | 已核实 |
| 凭据原子写入 | `createConfigStore.save`：先写临时文件（含 pid + uuid）→ `chmod` → `sync` → `rename` 替换正式文件 | 已核实 |
| 凭据文件绑定本机 | `machineIdHash = sha256(machineId)`；`load()` / `save()` 通过 `validate()` 校验 `machineIdHash` 与当前环境一致，不匹配即抛错拒绝使用 | 已核实 |
| token 不进日志 | `src/logger.ts` 仅允许白名单字段；proxy/CLI 只记录状态、错误类别、计数或 hash，不传 body/token/凭据对象 | 已核实（针对当前调用点） |
| QA routing attestation 默认关闭且隔离普通日志 | `src/attestation.ts` 只在目录与随机 nonce 同时设置时创建新 `0700` 私有目录；JSONL 文件以 `O_EXCL | O_NOFOLLOW` 创建为 `0600`，普通 logger 白名单未扩容 | 已核实 |
| token 不进 argv | CLI 只接受来源目录、操作 flag 与非敏感 backup UUID；不接受 token 参数 | 已核实 |
| 生产请求全内存，不落盘 capture | 生产推理请求不落盘；磁盘写入限于安全凭据、rotation/import 恢复证据 | 已核实 |
| 生产代理不读取 Qoder 私有凭据 | serve/preflight 只读代理 config；只有用户显式执行 `auth import-qoder` 时，才读取指定来源目录下精确的 `machine_id` 与 `user` | 已核实 |
| 导入来源窄边界 | 来源目录/文件执行 owner、权限、普通文件、非 symlink、大小与 dev/ino 复核；不读取 `security/` 或其他文件 | 已核实 |
| 不启动 `qoderclicn` 子进程 | `locateQoderCli` 仅定位，`loadAuthBridge` 只读二进制并内存实例化 WASM；导入也只调用 WASM `credential_storage_decrypt` | 已核实 |
| body 无 `_` 前缀字段自检 | `convertAnthropicToCnBody` 末尾显式检查，命中即抛错 | 已核实 |

## QA routing attestation 的数据最小化

- 固定 schema 恰为 `qoder-proxy-live-attestation/v1`，只含 `schema`、`message`、四个 routing key 边界、`completed` 与固定计数器；成功记录的模型值固定为当前 catalog 验证的 `qmodel_38max`，失败早期阶段允许 `null`。
- 禁止字段包括 header、Authorization/Bearer、token、API key、CN body、prompt 内容、catalog 原文、UID、machine ID、URL、query、响应或错误原文和时间戳。
- 每个 QA run 只能绑定一个显式 `qmodel_38max` 目标请求且只能 finalize 一次；envelope/catalog/模型解析先完成，`auto`、unknown、disabled 不占 artifact，但每个已认证 Messages 请求都会在任何 `await` 前取得 reservation，并保持至非流式终态、流式 `message_stop`、取消或错误。目标 reservation 只能在没有其他 Messages/辅助 lease 时原子 claim；先到的 non-target 或辅助请求会使 target 返回 503，claim 后新 Messages/辅助请求也返回 503。成功完成的 pre-target Models 辅助 lease 会把本 lease 的 list/retrieve/catalog/refresh/retry 计数提交到 run-level ledger，并只在 target claim 时原子转入 artifact；失败、取消、失效 lease 全部丢弃 pending 计数。共享 AuthSession 的 catalog/refresh observer 随 reservation 传递；后台 single-flight 即使在路由 finally 后才完成，其已释放 observer 的计数回调也会 inert no-op，且 observer 回调异常被隔离，不能 poison catalog/refresh promise 或归因到后续 target。`retries` 明确计 401 恢复造成的全部额外 operation attempt：catalog retry 与 infer retry 都计入；`extraInference` 仅计额外 infer，`refresh` 仅计实际 auth single-flight 启动。因此 `refresh` 不再要求由 extraInference 推导，而在当前仅 401 触发 refresh 的实现中不大于 `retries`。流式响应仅在发出正常 `message_stop` 后记成功；取消、协议异常、上游失败或内部异常记唯一 `completed: false` 终态，`responseModel` 为 `null`，`response` 不递增。
- sink 是单独 opt-in QA 机制，默认生产路径没有文件、没有额外 stderr、没有客户端可观测字段。启用失败会在 bind 前 fail-closed。

## 待验证（不得视为已生效）

1. **provenance 信息不对客户端可观测**：`ANTHROPIC_IGNORED` 字段（`metadata` / `stop_sequences` / `thinking` / `context_management` / `output_config`）和 `max_tokens` 截断结果会被计算进 `CnConversion.provenance`，但未见写入日志、也未见在响应中返回给客户端——调用方目前对这些静默降级不可感知。
   **结论**：是否需要以某种形式回传给客户端（例如响应头、自定义字段），待产品决策；当前只能称其为「内部记录」。

## 协议约束（与凭据 / 降级处理相关，非安全边界但一并说明）

- 不支持 `thinking`：被静默忽略并计入 `provenance`（可观测性见上文待验证 #3）。
- 不支持 `tool_choice.type === "tool"`：`convertToolChoice` 中显式抛错，返回 400，**不是静默降级**。
- `max_tokens` 硬上限 1024（`MAX_CN_MAX_TOKENS`）：超出静默截断且仅记录 `provenance`（可观测性见上文待验证 #3）。
- 并行工具上限 2（`MAX_PARALLEL_TOOLS`）：超过时在流式聚合阶段显式发 Anthropic `error` 事件并中断流，**是可观测的显式失败**，已核实（见 `emitAnthropicSseStream`）。
