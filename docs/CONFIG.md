# 配置与环境变量契约

## 环境变量

| 变量 | 用途 | 默认值 | 必需 | 代码位置 |
|---|---|---|---|---|
| `PORT` | HTTP 监听端口 | `7788` | 否 | `src/cli.ts` |
| `QODERICN_BIN` | 显式指定 `qoderclicn` 二进制路径 | 无（未设置时走 `PATH` 搜索 → `$HOME/.local/bin/qoderclicn`） | 否 | `src/auth/bridge.ts`（`locateQoderCli`） |
| `QODER_CN_MACHINE_ID` | 传入 WASM 签名流程的 machine ID，同时用于凭据文件绑定哈希 | 无 | 是（二选一） | `src/auth/session.ts` |
| `QODER_CN_MACHINE_ID_FILE` | 在 preflight 前从安全单行文件读取 machine ID；不得与 `QODER_CN_MACHINE_ID` 同时设置 | 无 | 是（二选一） | `src/cli.ts` / `src/auth/import.ts` |
| `QODER_CN_COSY_VERSION` | 客户端版本号，传入 `QoderContext.create` | `1.1.6` | 否 | `src/auth/session.ts` |
| `QODER_OPENAPI_BASE` | OpenAPI base（用于 `fetchOpenApiUserInfo`） | `https://openapi.qoder.com.cn` | 否 | `src/auth/session.ts` |
| `QODER_CN_INFER_BASE` | 推理网关 base | `https://gateway.qoder.com.cn` | 否 | `src/auth/session.ts` |
| `QODER_CN_INFER_MODEL_KEY` | 请求省略 `model` 时使用的代理默认 Qoder routing key；每次使用前必须存在于当前启用的官方 `assistant` 目录 | 无（未设置时使用目录中的启用 `auto`） | 否 | `src/proxy.ts` / `src/auth/session.ts` |
| `QODER_CN_INFER_SOURCE` | 传入 `prepareInferRequest` 的 source | 无 | 否 | `src/auth/session.ts` |
| `QODER_PROXY_MODEL_CATALOG_TTL_MS` | 官方模型目录缓存 TTL；远端优先、内存不可变 snapshot、Promise single-flight，凭据刷新后立即失效 | `100000`（100 秒）；有效范围 `1000-600000` | 否 | `src/auth/session.ts` |
| `QODER_PROXY_MODEL_CATALOG_TIMEOUT_MS` | 单次模型目录操作 timeout（包括一次 401 refresh/retry 流程的调用预算） | `30000` | 否 | `src/auth/session.ts` |
| `QODER_PROXY_CONFIG_DIR` | 凭据文件所在目录 | `$HOME/.config/qoder-proxy` | 否 | `src/auth/session.ts`（`DEFAULT_CONFIG_DIR`） |
| `BUN_EXEC_PATH` | fd-bound 凭据发布 capability 子进程使用的 Bun 可执行文件绝对路径；仅在运行时不在 Bun 中时覆盖自动发现 | 无（当前 Bun runtime 用自身；否则仅从绝对 `PATH` 目录定位 `bun`） | 否 | `src/auth/session.ts`（`requireBunExecutable`） |
| `QODER_PROXY_QA_ATTESTATION_DIR` | **仅本地 QA** 路由证明新建目录；必须与 nonce 同时设置，目录名必须为 `qoder-proxy-qa-attestation-<nonce>` | 无（关闭） | 否 | `src/attestation.ts` |
| `QODER_PROXY_QA_ATTESTATION_NONCE` | **仅本地 QA** 32 位小写十六进制随机 nonce；与目录共同构成 opt-in，防止误写入普通日志路径 | 无（关闭） | 否 | `src/attestation.ts` |

`QODER_OPENAPI_BASE` / `QODER_CN_INFER_BASE` 会经过 `requireCnAllowedUrl` 的 HTTPS 与中国站 host allowlist 校验，越界配置 fail-closed。fd-bound publication capability 始终以已验证的 Bun runtime 启动 supervisor、worker、executor 与默认 watchdog；显式 `BUN_EXEC_PATH` 不存在、不是绝对路径或不能证明为 Bun 时 fail-closed，不回退为 Node。

模型目录不是静态配置：代理使用当前凭据签名获取官方目录，只公开 `assistant` scene 中启用的 routing key。显式请求模型优先于 `QODER_CN_INFER_MODEL_KEY`；配置默认值若已 disabled、拼写错误或不属于当前账号，会 fail-closed，而不会回退到其他模型。

## 本地 QA 路由证明

默认完全关闭。只有两个 `QODER_PROXY_QA_ATTESTATION_*` 变量同时有效时，代理才会在调用进程新建的专用目录中以 `O_EXCL | O_NOFOLLOW` 写入 `routing-attestation.jsonl`；目录必须先前不存在且为 `0700`，文件为 `0600`。启动时路径、nonce、目录名、owner、类型或权限不符合契约即 fail-closed。

每个 QA run 只绑定一条显式 `qmodel_preview` 的已接受 Messages 请求，并最终只写一行 `qoder-proxy-live-attestation/v1` 记录：`schema`、`message`、`modelProvided`、`requestModel`、`resolvedModel`、`prepareInferModel`、`responseModel`、`completed` 与精确 `counters`。计数键固定为 `preflight`、`catalogRemoteLoad`、`modelsList`、`modelRetrieve`、`prompt`、`inference`、`response`、`tools`、`refresh`、`retries`、`extraInference`；`retries` 计本 target run 中由 401 恢复触发的全部额外上游 operation attempt（目录第二次加载或 infer 第二次尝试），`extraInference = inference - 1` 只计额外推理，`refresh` 只计实际启动的 auth single-flight，`tools` 计该请求声明工具数。因此目录 401 恢复且首个 infer 成功为 `catalogRemoteLoad:2`、`refresh:1`、`retries:1`、`inference:1`、`extraInference:0`；infer 401 恢复为 `inference:2`、`refresh:1`、`retries:1`、`extraInference:1`。成功只在流式 `message_stop` 或非流式成功收集后写 `completed: true` 和 `response: 1`；取消、SSE 错误、非 SSE、上游错误和内部错误也写唯一 `completed: false` 终态，`responseModel` 为 `null`。

启用时每个 `/v1/messages` 都会在任何异步读取前取得自己的 reservation，并保持至非流式终态、流式 `message_stop`、流取消或错误终态；无论是显式/默认 `auto`、unknown、disabled 还是目标请求，都不会在尚存活时让其他请求抢占 claim。只有显式请求并解析为 `qmodel_preview` 的 reservation，才可在没有其他 Messages 或辅助 lease 时原子提升为 target；target claim 前已有辅助或其他 Messages 请求时返回 503，target claim 后新入站的 Messages 和辅助请求也返回 503。目标 claim 前成功完成的 Models list/retrieve 辅助 lease 会先把自己的路由计数提交到 run-level ledger，再由 target claim 原子转入最终 artifact；失败、取消或失效的辅助 lease 不提交。目录加载与 refresh 的 observer 只随各自 reservation 传入共享 `AuthSession`；若路由已释放而后台 single-flight 才结束，旧 observer 的计数回调会安全 no-op，observer 自身异常也不会改变 catalog/refresh 的产品结果或污染后续 target artifact。成功记录的四个模型字段固定为经当前 catalog 验证的目标 routing key `qmodel_preview`，失败早期阶段可为 `null`；不记录 body、prompt 内容、headers、token、URL、query、catalog、UID、machine ID、响应文本或 API key。该文件是私有 QA 证据，不是普通日志、客户端 API 或生产可观测性接口。

## 凭据文件

- 路径：`${QODER_PROXY_CONFIG_DIR:-$HOME/.config/qoder-proxy}/auth-cn.json`
- 权限：目录 `0700`，文件 `0600`
- 写入方式：临时文件 + `rename` 原子替换（详见 `docs/SECURITY.md`）
- 不受 git 跟踪：`.gitignore` 已覆盖 `auth-*.json`

### 字段（`StoredCredential`）

| 字段 | 类型 | 说明 |
|---|---|---|
| `version` | `1`（字面量） | schema 版本，当前仅支持 `1` |
| `site` | `"cn"`（字面量） | 站点标识，当前仅支持 `"cn"` |
| `machineIdHash` | string | `sha256(QODER_CN_MACHINE_ID)`，加载时校验与当前运行环境一致 |
| `token` | string | 访问 CN OpenAPI 的 Bearer token |
| `refreshToken` | string（可选） | 刷新令牌 |
| `expiresAt` | number（可选） | token 过期时间 |
| `refreshTokenExpiresAt` | number（可选） | 刷新令牌过期时间 |
| `userId` | string（可选） | 用户 id |
| `userName` | string（可选） | 用户名 |

**约束**：任何字段校验失败（`version` / `site` / `machineIdHash` 不匹配，或 `token` 非字符串）都会在 `load()` 时抛错，代理不会静默使用不匹配的凭据。凭据文件不存在（`ENOENT`）时 `load()` 返回 `undefined`，preflight 会拒绝启动。

## Qoder 凭据导入

- 默认来源目录：`$HOME/.qoder-cn/.auth`；可用 `--source-dir <absolute-path>` 覆盖。
- 只读取精确文件 `machine_id` 与 `user`，不枚举或进入其他 Qoder 私有路径。
- 来源目录必须是真实目录、当前用户拥有且 group/other 不可写；来源文件必须为当前用户拥有的普通非 symlink 文件、权限不宽于 `0600`、尺寸受限。
- `user` 由官方 Auth WASM 的 `credential_storage_decrypt` 解密，key 为完整 machine ID 的前 16 个字符；不会启动 `qoderclicn`。
- 字段映射：`security_oauth_token` 优先作为 `token`；若同时存在不一致的 `access_token` 则拒绝；同步映射 `refresh_token`、`expire_time`、`refresh_token_expire_time`、`uid`、`name`。
- 应用使用 `auth-cn.import.pending` 与 `.auth-cn.import.<uuid>/` 备份目录完成 crash-safe transaction。备份目录 `0700`，其中 receipt/旧原始字节为 `0600`。
- `auth import-status` 返回脱敏的 backup UUID 与状态，可在 apply 成功但 stdout/EPIPE/进程退出后重新发现 recovery handle。
- 导入成功后必须显式 `finalize-import` 删除备份，或在目标 hash 未变化时 `rollback-import` 恢复。
- committed 且未 finalize 的 backup 与 rotation/save/delete 互斥；`load()` 可继续读取当前已提交凭据，但 mutation 会 fail-closed。
