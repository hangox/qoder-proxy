# Gate 1 历史验收证据

> 历史结论日期：2026-07-31
> 证据范围：脱敏、只记录状态/计数/摘要，不记录 token、machine ID、用户标识、请求正文或上游 headers。
> **范围提示：** 本文冻结的是新增 Models API / 动态模型目录之前的基础 Gate 1 快照。历史 SHA、测试计数和 GO 结论不能自动认证之后的源码变更；当前实现必须以最新冻结 manifest、Reviewer 和 QA 报告为准。

## 1. 历史结论

- **历史基础 Gate 1 implementation：GO**
- 当时严重度统计：**0 Blocker / 0 Major**（仅限当时执行和认证的范围）
- 历史基础实现 `src/` + `tests/` 固定清单 SHA-256：
  `d8de86be516c6e629f7b6a13e0e1fb153d2da148102691c5efa82e33fbc8ebfe`
- Gate 0 PoC SHA-256：
  `e028d89f0372f3d1231c21895f95f9ca3c1297b28bb82eb6074164d1b3e60352`
- 当时最终验证后，历史实现清单和 Gate 0/CN provenance 均无漂移。

该历史结论覆盖：安全凭据导入闭环、真实 Qoder 最小文本链路、隔离的 Claude CLI 端到端链路，以及当时的自动化协议/生命周期/恢复测试。它不覆盖后续新增的 Models API / 动态目录实现，也不扩张项目已声明的不支持范围。

## 2. 后续 Task 210 / 211 自动化冻结（2026-07-31）

该冻结覆盖 routing attestation retry 语义及 Bun capability runtime 修复，不覆盖真实网络、凭据或 `qoderclicn`。标准测试入口固定为 Bun 串行执行，避免 Node-hosted Vitest 运行 `bun:ffi` capability 进程树。

| 项目 | 结果 |
|---|---|
| `bun run typecheck` | PASS |
| `bun run build` | PASS |
| `bun run test`（`bun test --max-concurrency=1`） | 3/3 PASS；每轮 434 tests / 1547 assertions |
| `bun test --max-concurrency=1` | 3/3 PASS；每轮 434 tests / 1547 assertions |
| attestation verifier + sink focused | PASS；17 tests / 32 assertions |
| Node-hosted Vitest capability focused | PASS；9 tests |
| Full manifest（排除本自引用证据文件） | 33 files；SHA-256 `2c8ceb986e76d0233bdd7c7c1616a6177bb6187003a2c2a28d36375ccd8f71dd` |
| Core manifest（`src`、`tests`、`package.json`、`docs/CONFIG.md`；排除本文件） | 28 files；SHA-256 `ccb0fa082b0c23311e4630bf6442caa79eab2f38bf877b0582619b4bc81af9c8` |

capability runtime 解析顺序为显式 dependency、`BUN_EXEC_PATH`、当前 Bun runtime、绝对 `PATH` 目录；每个候选都以 `--version` 证明为 Bun。supervisor、worker、executor 与默认 watchdog 共享同一已验证 runtime；无 Bun 或无效 override 均 fail-closed，不回退为 Node。测试 fixture 也显式通过该 resolver 启动，以免 Node 的 TypeScript strip-only loader 掩盖 capability 生命周期测试。

## 3. 自动化与复审证据

在历史基础实现快照上完成：

| 项目 | 结果 |
|---|---|
| TypeScript typecheck | PASS |
| Build | PASS |
| 严格串行 full suite | 3/3 轮 PASS；每轮 338 tests / 1308 assertions |
| Import focused suite | 29/29 PASS |
| Import crash/recovery critical stress | 10/10 PASS |
| 独立 Reviewer | GO，0B/0M（另记录非阻断 schema 文档项） |
| 独立 QA | GO，0B/0M（另记录非阻断 schema 文档项） |

复审覆盖包括：官方 Auth WASM ABI/retptr/free/error 路径、来源文件 owner/mode/no-follow/dev-ino、machine binding、CLI 脱敏、import 与 rotation 互斥、crash-safe publication/recovery、EPIPE 后状态发现、rollback/finalize TOCTOU 防护，以及历史 auth/SSE/convert/proxy/security 矩阵。

## 4. 真实凭据导入事务

真实导入严格按用户分阶段授权执行：

1. **Dry-run：PASS**
   - 来源文件安全检查和 schema 检查通过。
   - 脱敏状态：目标已存在、需要显式 replace、refresh token 和 expiry 均存在。
   - 零写入、零网络、零代理 bind、零 `qoderclicn` 启动。
2. **Apply + replace：PASS**
   - 仅执行一次支持的导入命令。
   - 新目标与预备导入内容、machine binding 一致。
   - 旧目标进入 crash-safe committed backup；目标为当前 owner、`0600`，backup 目录 `0700`、内部文件 `0600`。
   - 无 pending/temp/mutation-lock/rotation 残留。
3. **验证窗口：PASS**
   - committed backup 保留期间未发生 refresh/rotation；配置和 backup 状态在真实验证前后不变。
4. **Finalize：PASS**
   - 用户在真实 Qoder 和 Claude CLI 均通过后另行明确授权。
   - 最终只执行一次支持的 finalize；`import-status` 为空，rollback bundle 已移除。
   - 当前凭据 bytes、inode/dev/size、schema 和 `0600` mode 均未改变。
   - 正常 refresh/rotation 的运行限制已解除；rollback 已关闭且不再需要。

整个事务未把秘密放入 argv、stdout、stderr 报告、日志或 capture；未启动 `qoderclicn`，未手工删除事务文件，未自动重试或隐式回滚。

## 5. 真实 Qoder 最小认证链路

为消除执行范围歧义，最终采用一项全新的、计数固定的最小验证：

| 计数 | 实际值 |
|---|---:|
| standalone preflight | 1 |
| inference | 1 |
| tool request | 0 |
| refresh | 0 |
| retry | 0 |
| local negative control | 0 |
| `claude -p` | 0 |

结果：

- bounded preflight clean；
- 仅绑定随机 `127.0.0.1` 端口；
- 单个无工具文本请求返回 HTTP 200；
- Anthropic 事件为完整 `message` / `end_turn` / text-only；
- 脱敏扫描未发现 secret-shaped 输出；
- config、import status 和当时的 committed backup 均无变化；
- process/port/tmp/probe/marker/pending/lock/rotation 残留为 0。

## 6. 隔离 Claude CLI 端到端证据

执行合同：`CLAUDECODE` 显式 unset，prompt 通过 stdin，tools disabled，`max-turns=1`，仅走新的 loopback proxy。

| 计数 | 实际值 |
|---|---:|
| proxy preflight | 1 |
| `claude -p` invocation | 1 |
| inference | 1 |
| tools | 0 |
| refresh | 0 |
| retries | 0 |

结果：

- Claude CLI exit 0；
- 输出 `type=result`、`is_error=false`；
- 返回非空、连贯文本；
- 脱敏扫描未发现 secret-shaped 内容；
- 代理只观察到一次签名 inference，无 refresh/retry；
- config/import status 未变化；
- helper/PID/port/tmp/probe/marker/pending/lock/rotation 残留为 0。

## 7. 安全与清理结论

- token、refresh token、machine ID、用户标识、请求正文和完整 headers 未进入证据文档。
- 凭据未进入 argv、源码、Git、日志或 capture。
- 生产链路全内存；验证完成后没有相关进程、监听端口、临时脚本、probe、marker、pending、mutation lock 或 rotation journal 残留。
- 真实来源在 dry-run/apply 前后身份与摘要不变；实现源码/测试在全部真实验证后保持固定摘要。
- Finalize 后 config 目录只保留当前目标凭据，import status 为空。

## 8. 明确未覆盖与非阻断项

- **没有为了取证而故意触发 live 401/refresh。** 最小真实验证中 refresh 计数为 0。Finalize 后正常 refresh/rotation 已恢复，但不得仅为补充证据主动制造凭据失败。
- 最终认证的最小真实 Qoder 和 Claude CLI 证据均为 `tools=0`；自动化测试继续覆盖已声明的工具协议边界。早期更宽矩阵观察不作为本节的精确计数证据。
- Import schema 仍有两个非阻断收口项：
  1. `refresh_token` 的空白/首尾空白应与 access token alias 一样严格 fail-closed；
  2. expiry 应要求 safe positive integer epoch，拒绝 fractional/unsafe integer。
  真实导入前的脱敏 shape 检查确认本次来源不命中这两个边界。
- 项目原有不支持范围保持不变，包括 thinking、`tool_choice.type=tool`、3+ 并行工具及其他未获真实协议证据的扩展语义。

## 9. 运维结论

当前凭据已完成导入、真实验证和 finalize：

- 无未决 import backup；
- 无可用 rollback bundle；
- refresh/rotation 可正常运行；
- 无需再次执行 import/finalize；
- 不应为补证主动触发 401/refresh。

若未来需要再次迁移凭据，必须重新从 dry-run 开始，并取得新的分阶段用户授权。
