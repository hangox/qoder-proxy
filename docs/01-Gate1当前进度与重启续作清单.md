# Gate 1 历史进度与重启续作清单

> 原始保存时间：2026-07-29
> 最终状态更新：2026-07-31
>
> **归档提示：** 本文件第 2 节之后主要保留 2026-07-29 的历史开发快照、风险清单和当时的续作步骤，不再是当前执行计划。Gate 1 implementation 已最终 **GO（0 Blocker / 0 Major）**；固定 `src/` + `tests/` manifest 为 `d8de86be516c6e629f7b6a13e0e1fb153d2da148102691c5efa82e33fbc8ebfe`。真实 Qoder 最小验证、隔离 `CLAUDECODE`-unset `claude -p`、凭据 dry-run/apply/finalize 均已通过，最终无未决 import backup，正常 refresh/rotation 已恢复。当前权威证据请读 [`GATE1-EVIDENCE.md`](GATE1-EVIDENCE.md)。不得仅为补证主动触发 live 401/refresh。

## 1. 当前结论

- **Gate 0 已通过**，中国站协议可行性已经有真实证据。
- Gate 0 最终 PoC 冻结 SHA-256：`e028d89f0372f3d1231c21895f95f9ca3c1297b28bb82eb6074164d1b3e60352`
- Gate 0 PoC 位于项目外部只读路径：`$HOME/ai/experiments/qoder-cn-auth-bridge-poc.ts`
- **Gate 1 Walking Skeleton 的核心代码已经完成第一轮实现，自动测试、类型检查和构建已通过。**
- **Gate 1 还没有最终完成**：独立 Reviewer 复审与 QA 真实网络/真实 `claude -p` 验证尚未执行完，不能宣称 MVP 完成。
- 当前业务代码应视为“开发冻结候选快照”；重启后先核对摘要和自动测试，确认无漂移，再开始复审和真实验证。

## 2. Gate 0 已证明的能力

冻结 PoC 与前序独立 QA/Reviewer 已验证以下中国站真实能力：

1. 安全 config 凭据恢复，`credentialSource=config`，不触发 Device Flow。
2. 仅只读官方 `qoderclicn` 二进制并内存加载 Auth WASM，不启动其子进程。
3. 官方 Auth WASM 的角色匹配、用户信息、运行时认证字段和签名请求构造。
4. CN legacy SSE 的双信封解析、正文、usage、finish reason、error 与 `[DONE]`。
5. 单工具首轮 `tool_calls`、原 ID 回传、工具结果二轮、最终 `stop`。
6. 并行双工具按 `choiceIndex:toolIndex` 独立聚合、各原 ID 回传、各执行一次、二轮 `stop`。
7. 真实 Claude Code 2.1.220 请求：约 156347 字节、system 约 6306 字符、29 个工具 schema，经转换后被中国站真实 HTTP 200 + SSE 接受，并返回 `stop`、`DONE`、usage。
8. 生产正文不落盘；Gate 0 capture/replay 探针的 provenance、marker 与临时文件生命周期已完成安全收口。

Gate 0 只证明协议兼容子集，不等于正式产品完成。正式项目仍必须遵守：最多并行双工具、3+ fail-closed、thinking 不支持、`tool_choice.type=tool` 不支持、`max_tokens` 上限 1024 且截断可观测。

## 3. 当前项目文件状态

项目根目录使用 `$PROJ_DIR_MINE/qoder-proxy` 表示。

### 3.1 核心代码

- `src/auth/bridge.ts`：官方 Auth WASM 定位、提取、ABI glue、导出角色、签名产物校验、URL 白名单、dispose。
- `src/auth/session.ts`：安全 config、userinfo、Auth context、签名请求编排、AbortSignal。
- `src/convert.ts`：Anthropic Messages → CN legacy body 纯转换器。
- `src/sse.ts`：CN legacy SSE 解析、tool call 聚合、Anthropic 流式发射与非流式收集。
- `src/proxy.ts`：Hono HTTP 层、本地鉴权、provenance 日志、401 单次刷新、流式/非流式、错误映射。
- `src/cli.ts`：默认监听 `127.0.0.1:7788`，优雅退出。
- `src/logger.ts`：字段白名单结构化 stderr 日志。

### 3.2 测试

- `tests/auth.test.ts`
- `tests/convert.test.ts`
- `tests/sse.test.ts`
- `tests/proxy.test.ts`
- `tests/smoke.test.ts`

### 3.3 已写入技术文档

- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/SECURITY.md`
- `docs/CONFIG.md`
- `docs/API-CONTRACT.md`
- `docs/SSE-PROTOCOL.md`
- `docs/GATE1-EVIDENCE.md`
- 本文件：`docs/01-Gate1当前进度与重启续作清单.md`

这些文档在开发复审前写入，其中部分“待验证”声明可能已被本轮代码修复。Reviewer/QA 完成后必须根据最终代码更新文档和 `docs/GATE1-EVIDENCE.md`。

## 4. 重启前冻结基线

### 4.1 自动验证结果

2026-07-29 重启前独立运行：

```text
bun run typecheck  -> PASS，exit 0
bun test           -> PASS，62 tests / 0 fail / 117 expect
bun run build      -> PASS，Bundled 34 modules，dist/cli.js 约 62.52 KB
```

### 4.2 当前任务状态

- Task #1 `实现 Gate 1 核心链路`：completed
- Task #2 `复审 Gate 1 实现`：in_progress，Reviewer 等待冻结后从头复审
- Task #3 `验证 Gate 1 实现`：in_progress，QA 等待冻结后执行完整矩阵
- Task #4 `编写项目技术文档`：completed

注意：Agent/Task 的运行态可能不会跨电脑重启保存。重启后应按本文件重新创建团队和任务，不要依赖旧任务编号仍然存在。

### 4.3 冻结摘要

- 纳入摘要的项目文件数：26
- 项目清单 SHA-256：`db5ff34400679d6ff7a14a122a961a8c39c09715906dad7342593c9bbdde654f`

该摘要的生成口径：纳入根配置、`src/`、`tests/`、`docs/` 和 `README.md`，排除 `.git/`、`node_modules/`、`dist/`。

关键业务文件 SHA-256：

```text
src/proxy.ts         f1a1bb16625bdfd16dfb6f3d7067cb0b193d9d3b10d8d6ca8193d1c0ae3989cd
src/convert.ts       598cb064142a2e1731461bf5e65376e1226f809a6ff991fbb37b1fb987b781b7
src/sse.ts           c7b37c46c35b1e3a8d8f4e9af69825dcf1f2adfc6963f8408e739551f5b8e3dc
src/cli.ts           824f614b5bb7ab8e1449fcfe4cf6802c4a2e548f3cb42f48f7c27afc5f791360
src/logger.ts        b8f4fb9687d31b2ce2de32e4dc96dd740661d80d5ac3e29fc4f51e41eed3b766
```

`src/auth/bridge.ts` 和 `src/auth/session.ts` 已存在，但重启前的简版 SHA 清单未单独输出；应使用第 8 节命令重新生成全清单核对。

## 5. 本轮已实现的关键能力

### 5.1 Auth 与签名请求

- 已迁移 CN HTTPS host allowlist，并覆盖 OpenAPI base、infer base 与 WASM 签名产物 URL。
- `RequestResult.headers` 不再是死代码；签名 headers 从 WASM 产物读取并校验，不再只硬编码 `content-type`。
- 校验 headers 必须是 `Map`、数量不超过 64、`headerCount` 与 Map size 一致。
- `RequestResult` / `QoderContext` 支持幂等 dispose 和 use-after-free 阻断。
- userinfo 与 infer fetch 可传播 AbortSignal。
- 401 时在尚未向客户端输出响应前刷新认证字段并只重试一次。

### 5.2 请求转换

- 未知 Anthropic 顶层字段 fail-closed。
- `tool_choice` 支持 auto / any|required / none；`type=tool` fail-closed。
- system string / text blocks、assistant text+tool_use、user tool_result 已转换。
- tool_result 通过前序 tool_use ID 回查工具名，生成 `role=tool` 时带 `name`。
- 同一 user 消息中的 tool_result 先生成 `role=tool`，普通文本随后生成 user 消息，避免破坏工具回合顺序。
- `max_tokens` 上限 1024，原值、实际值、截断布尔值进入 provenance。
- thinking、metadata、stop_sequences、context_management、output_config、stream 等已知不支持字段进入 provenance，不进入上游 body。
- provenance 不进入上游 CN body。

### 5.3 SSE 与工具

- 已知事件白名单：message / finish / error；未知事件 fail-closed。
- 支持 CRLF、半包、粘包、多 data 行、64 MiB 缓冲上限。
- 支持双信封和 `[DONE]`。
- error 路径只发 error 并终止，不再伪造正常 `message_stop`。
- usage 映射为 Anthropic input/output tokens。
- finish reason：`tool_calls → tool_use`、`length → max_tokens`、其他结束 → `end_turn`。
- tool call 按 `choiceIndex:toolIndex` 独立聚合，id/name 冲突 fail-closed。
- arguments 必须为 JSON object；空参数标准化为 `{}`。
- 最多两个并行工具，3+ 在发射任何工具 block 前 fail-closed。
- 已实现流式 Anthropic SSE 与非流式 Anthropic Message JSON。

### 5.4 HTTP 与 CLI

- `/health`
- `/v1/messages/count_tokens` 使用保守字符估算，不再恒返回 1。
- `/v1/messages` 支持 `stream:true` 与非流式默认行为。
- Messages 和 count_tokens 要求 `QODER_PROXY_API_KEY`，支持 `x-api-key` 或 Bearer。
- 默认监听 `127.0.0.1:7788`，不绑定全网卡。
- 请求 abort + 120 秒默认超时接入上游 fetch。
- provenance 以脱敏结构化日志记录，不打印 token/正文。
- 上游 400/401/403/429 映射到相应 Anthropic 错误类型，其他失败映射为 502。

## 6. 重启后必须优先复审的风险点

即使当前自动测试全绿，以下问题仍需 Reviewer 从头确认，不能只相信开发汇报：

1. **WASM ABI 正确性**
   - `RequestResult.headers` 的 wasm-bindgen object handle、retptr 和 headerCount 读取是否与冻结 PoC 完全一致。
   - `qodercontext_free` / `requestresult_free` 的调用签名是否正确，不能因错误 free 导致真实运行崩溃。
2. **Auth 刷新语义**
   - 当前 401 `refreshAuthFields` 入参是否与 PoC 实测结构一致。
   - 是否真的只重试一次，且未输出下游 payload 前才可重试。
   - refreshToken / expiresAt 的产品策略是否需要补充；Gate 1 可先明确“安全 config 缺失或失效时失败，不进入 Device Flow”。
3. **machine ID**
   - 当前部分路径仍可能把缺失的 `QODER_CN_MACHINE_ID` 当空字符串。Reviewer 应判断是否必须改为启动期 fail-closed。
4. **CN body 字段溯源**
   - `src/convert.ts` 的整个 CN body 必须逐字段与冻结 PoC 中真实 replay 已接受的 converter 对齐。
   - 不得新增冻结 PoC 中没有、也没有真实证据的默认字段。
5. **SSE 尾帧**
   - 当前 `parseSseFrames` 在 EOF 时没有显式解析非空残余缓冲。需要 Reviewer 判定：协议要求未以空行终止的尾帧是 fail-closed 还是应解析；不得静默丢失。
6. **Abort 生命周期**
   - `ReadableStream.cancel()` 本身为空，虽然 parser finally 会 cancel/release reader，但需要验证客户端取消是否确实触发上游 fetch abort，而不是只在 request signal 变化时生效。
7. **流式错误生命周期**
   - error、tool conflict、3+ 工具、非法 arguments 后不得继续发 `message_delta` / `message_stop`。
8. **非流式错误语义**
   - 非流式 collector 遇 error、abort、非法工具时的 HTTP 状态和错误类型是否符合客户端预期。
9. **日志脱敏**
   - 任何 catch 都只能记录 `errorClass`、状态/hash/计数等白名单，不得出现 raw error message、token、正文、arguments。
10. **本地 API key 与 Claude Code 兼容**
   - 确认 Claude Code 可使用本地代理 API key，不会因 header 选择导致真实 `claude -p` 失败。
11. **测试清理方式**
   - `tests/auth.test.ts` 当前使用 Node `rm()` 清理测试临时目录。团队全局习惯要求手动清理使用 `trash`；Reviewer 应判断自动化临时测试中的 `rm()` 是否允许，若不允许则改为项目约定的安全清理策略。
12. **未提交状态**
   - 当前仓库尚无提交，所有文件显示为 untracked。电脑重启不会丢文件，但缺少 Git 提交保护；未获得用户明确要求前不要 commit/push。

## 7. 重启后执行顺序

### 第一步：恢复环境和团队

```bash
cd "$PROJ_DIR_MINE/qoder-proxy"
scutil --get LocalHostName
printf '%s\n' "$PROJ_DIR_MINE"
git status --short
```

先读：

1. `CLAUDE.md`
2. `docs/01-Gate1当前进度与重启续作清单.md`
3. `docs/GATE1-EVIDENCE.md`
4. `$HOME/ai/experiments/qoder-cn-auth-bridge-poc.ts`，只读
5. `$HOME/.claude/plans/snappy-conjuring-bear.md`，当前内容是《qoder-proxy Gate 1 完成计划》，可作为七阶段执行计划补充；它已覆盖此前架构裁决的大部分 P0，但不是 gpt-sol 原始裁决全文

重新组织团队时沿用用户指定角色：

- Developer：实现和修复
- Reviewer：独立只读复审
- QA：独立测试与真实 E2E
- K3 顾问：协议证据与 fail-closed 边界
- gpt-sol 顾问：架构和最终裁定
- 文档角色：最终冻结后更新文档

重启前已通知所有队员暂停，不应继续中间写入。

### 第二步：核对冻结摘要和自动基线

```bash
bun install
bun run typecheck
bun test
bun run build
```

重新生成项目摘要：

```bash
manifest_file=$(mktemp)
find . -type f \
  \( -path './src/*' -o -path './tests/*' -o -path './docs/*' \
     -o -name 'README.md' -o -name 'CLAUDE.md' -o -name 'package.json' \
     -o -name 'bun.lock' -o -name 'tsconfig.json' -o -name 'tsconfig.build.json' \
     -o -name 'vitest.config.ts' -o -name '.gitignore' \) \
  -not -path './node_modules/*' -not -path './dist/*' -print0 \
  | sort -z | xargs -0 shasum -a 256 > "$manifest_file"
shasum -a 256 "$manifest_file"
wc -l "$manifest_file"
trash "$manifest_file"
```

预期摘要：`db5ff34400679d6ff7a14a122a961a8c39c09715906dad7342593c9bbdde654f`。由于本续作文件刚刚新增，重启后按同一口径计算时文件数和摘要会改变；应先把本文件排除，或接受新摘要并记录到 `docs/GATE1-EVIDENCE.md`。关键业务文件 SHA 应保持第 4.3 节所列值。

### 第三步：Reviewer 独立复审

Reviewer 必须在固定快照上从头复审：

- Auth WASM headers / URL / dispose / refresh
- secure config / machine ID / symlink / 权限
- Anthropic → CN body 字段溯源
- tool_result 顺序、name 和 ID
- SSE framing、EOF、错误生命周期、usage、finish、multi-choice
- 单/双工具与 3+ fail-closed
- 流式/非流式
- abort / timeout / 401
- local bind / API key
- provenance / 日志脱敏

若复审期间文件 SHA 改变，应立即中止并要求 Developer 重新冻结。

### 第四步：QA 独立自动验证

不修改业务代码，执行：

1. typecheck / 62+ tests / build。
2. 用 mock/fixture 覆盖：
   - host allowlist
   - WASM headers 校验
   - config 权限和 symlink
   - conversion 全合同
   - SSE 半包/粘包/CRLF/多 data/尾帧/64 MiB
   - error 生命周期
   - 单/双工具、ID 冲突、name 冲突、非法 args、3+
   - stream 与 non-stream
   - abort/timeout
   - 401 刷新只一次
   - 本地 API key
3. 启动构建产物，验证 `/health`、本地监听地址、未配置 API key 时拒绝。

### 第五步：真实 Qoder E2E

满足以下前置条件后才能执行：

- Reviewer 已确认无 Blocker。
- 使用安全 config，不读 Qoder 私有凭据目录。
- 不启动 `qoderclicn` 子进程。
- token 不进命令行、日志、报告。
- 临时文件用受控路径并及时 `trash`。

真实矩阵：

1. 真实文本流式：HTTP 200、SSE、正文、usage、stop、DONE。
2. 真实文本非流式：单个 Anthropic Message JSON。
3. 真实单工具二轮：原 ID、一工具一次、二轮 stop。
4. 真实并行双工具：两个 ID/结果不串线、各一次、二轮 stop。
5. 3+ 工具：明确 fail-closed。
6. 401：刷新一次；第二次仍 401 时返回 authentication_error。
7. abort：客户端取消后上游请求被取消，无残留连接/进程。
8. `unset CLAUDECODE` 后真实 `claude -p` 经代理执行无副作用工具：返回码 0、工具一次、原 ID 一致、最终文本正常。

注意：本地 `simulateTool` 只能证明代理闭环，不得表述为 Claude Code 已真实执行工具。Gate 1 的最终硬证据必须包含真实 `claude -p` 客户端往返。

### 第六步：文档和最终裁定

- 用真实测试结果填写 `docs/GATE1-EVIDENCE.md`。
- 更新 README、SECURITY、API-CONTRACT、SSE-PROTOCOL 中已从“待验证”变为“已验证”的条目。
- 记录仍未支持的范围：thinking、`tool_choice.type=tool`、3+ 工具、多模型、prompt cache 等。
- Reviewer、QA、K3、gpt-sol 给出最终 Gate 1 GO / NO-GO。
- Gate 1 GO 前不得称 qoder-proxy MVP 完成。

## 8. 建议补充或确认的实现项

这些项目未必全部阻断首次真实文本链路，但必须在 Gate 1 最终裁定前明确：

- [ ] 缺失 `QODER_CN_MACHINE_ID` 时启动期 fail-closed，禁止用空字符串弱化机器绑定。
- [ ] SSE EOF 非空残余缓冲：解析或显式报错，不得静默丢帧。
- [ ] `ReadableStream.cancel()` 与上游 AbortController 真正联动。
- [ ] Auth session 是否改为进程内缓存，而不是每请求 userinfo + 创建 context；若暂不缓存，必须证明无泄漏且性能可接受。
- [ ] refreshToken / expiresAt 策略：至少把过期/不可刷新错误映射为可操作的 authentication_error。
- [ ] CN body 中每个硬编码字段逐项标注冻结 PoC 来源。最终架构裁定前需特别出示证据，确认 `model_config.key`、`agent_id`、`session_type`、`version`、`source`、`max_input_tokens` 均来自 Gate 0 真实接受的 body；若证据覆盖则 P0-0 解除，否则继续阻断。
- [ ] `count_tokens` 明确为保守估算而非官方精确 token 计数，并验证 Claude Code 不因估算失效。
- [ ] 代理本地 API key 的配置和 Claude Code 接入说明。
- [ ] 对 `stream`、thinking、metadata 等降级在日志中可观测，但绝不进入上游 body。
- [ ] 真实测试后删除所有临时脚本、capture、日志和残留进程。

## 9. Git 与安全提醒

- 当前仓库没有提交历史，全部文件均为 untracked；这是当前事实，不是文件丢失。
- 未经用户明确要求，不要 commit、push、创建 PR。
- 不要把 token、auth config、真实请求正文或完整工具 arguments 加入 Git。
- 不读取 `~/.qoder/.auth`、`security/`、`~/.Trash` 内容。
- 不启动 `qoderclicn` 子进程；仅只读二进制并内存加载官方 Auth WASM。
- 生产请求全内存，不落盘 capture。
- 手动清理文件使用 `trash`，禁止直接 `rm`。
- 外部参考项目与 Gate 0 PoC均为只读。

## 10. 一句话恢复提示

> 先核对业务文件 SHA 和 62 个测试；再让 Reviewer 固定快照复审、QA 跑 mock/真实 Qoder/真实 `claude -p`；修完 findings 后更新证据文档并由 K3 + gpt-sol 裁定 Gate 1。当前代码已完成第一轮实现，但 Gate 1 尚未最终放行。
