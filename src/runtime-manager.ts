// Qoder session runtime manager：代理与临时认证只存在 daemon 内存中。
// daemon 为每个 run 维护一个稳定 gateway（HTTP 反向代理），backend 子进程可在 owner 存活期间有界重建；
// client 侧看到的 baseUrl/token 在 lease 生命周期内保持不变，backend 侧凭据随每次重建轮换。
import { randomBytes, timingSafeEqual } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { appendFileSync, chmodSync, closeSync, existsSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import { dirname, join } from "node:path";
import { createServer as createHttpServer, request as httpRequest, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { readMachineIdFile, resolveMachineIdSource } from "./machine-id.ts";
import { createStreamingSecretRedactor } from "./secret-redactor.ts";
import { expectedModelForRoutingKey, hasExpectedModelIdentity, QODER_TIER_REGISTRY, QoderModelCatalogUnavailableError, QoderModelUnavailableError, type QoderTier } from "./model-registry.ts";
export { QODER_TIER_REGISTRY } from "./model-registry.ts";
export type { QoderTier } from "./model-registry.ts";

export type RuntimeEnv = Record<string, string | undefined>;
export type RuntimeIo = { stdout(value: string): void; stderr(value: string): void };
type RuntimeRequest = { op: "acquire" | "release" | "shutdown" | "ping" | "status"; runId?: string; ownerPid?: number; leaseId?: string; tier?: string };
type RuntimeDiagnostics = { stderrPath: string; maxBytes: number; rotationFiles: number };
type RuntimeResponse = { ok: true; active?: boolean; runId?: string; ownerPid?: number; leaseId?: string; baseUrl?: string; backendReady?: boolean; socketPath?: string; token?: string; released?: boolean; tier?: QoderTier; routingKey?: string; diagnostics?: RuntimeDiagnostics } | { ok: false; error: string; code?: "model-unavailable" | "catalog-unavailable" | "startup-failed"; routingKey?: string };
type Backend = { generation: number; baseUrl: string; token: string; child: ChildProcess };
// 首次 acquire()/startLease() 在 lease 真正进入 this.leases 之前的在途状态：stop() 必须能看到它、
// 主动 abort 并强杀已知子进程，否则一次尚未 await 完成的 acquire 可能在 stop() 返回之后才悄悄成功，
// 留下一个 daemon 完全没有追踪到的孤儿 backend/gateway。
type InitialStart = { abort: AbortController; child: ChildProcess | undefined };
type Lease = {
  runId: string;
  leaseId: string;
  tier: QoderTier;
  clientToken: string;
  gatewayBaseUrl: string;
  gatewayPort: number;
  gatewayServer: HttpServer;
  owners: Set<number>;
  backend: Backend | undefined;
  generation: number;
  rebuildAttempts: number;
  circuitOpenUntil: number | undefined;
  rebuilding: Promise<void> | undefined;
  // teardown 时立即 abort：重建循环下一个检查点就会退出，backoff 睡眠会被立刻打断，不会傻等到自然到期。
  rebuildAbort: AbortController;
  // 重建循环当前正在等待 readiness 的子进程（如果有）；teardown 必须能立刻拿到它强制杀掉，
  // 而不是等它自己发现 lease 已经消失。
  currentSpawnChild: ChildProcess | undefined;
};
const QODER_RUNTIME_STATUS_SCHEMA = "qoder-runtime/status/v1";
function tierValue(value: unknown): QoderTier {
  if (value === "opus" || value === "sonnet" || value === "haiku") return value;
  throw new Error("非法 Qoder model tier");
}

const runtimeDirectory = (env: RuntimeEnv = process.env): string => env.QODER_PROXY_RUNTIME_DIR || (env.QODER_PROXY_RUNTIME_SOCKET ? dirname(env.QODER_PROXY_RUNTIME_SOCKET) : join(env.TMPDIR || "/tmp", `qoder-proxy-runtime-${typeof process.getuid === "function" ? process.getuid() : "user"}`));
const socketPath = (env: RuntimeEnv = process.env): string => env.QODER_PROXY_RUNTIME_SOCKET || join(runtimeDirectory(env), "runtime.sock");
const lockPath = (env: RuntimeEnv = process.env): string => join(runtimeDirectory(env), "daemon.lock");
const READY_TIMEOUT_MS = 20_000;
const MAX_FRAME_BYTES = 16 * 1024;
const CLIENT_TIMEOUT_MS = 2_000;
const IDLE_TIMEOUT_MS = 3_000;
const RUNTIME_LOG_MAX_BYTES = 256 * 1024;
const RUNTIME_LOG_ROTATIONS = 3;
const DEFAULT_REAPER_MS = 500;
const DEFAULT_REBUILD_MAX_ATTEMPTS = 3;
const DEFAULT_REBUILD_BACKOFF_MS = 250;
const DEFAULT_REBUILD_CIRCUIT_MS = 10_000;
const GATEWAY_UNAVAILABLE_MESSAGE = "qoder-proxy backend unavailable; retry the request";
// SIGTERM 之后给子进程的优雅退出窗口；超时未退出则升级 SIGKILL 并再等一小段，避免留下孤儿进程。
const KILL_GRACEFUL_MS = 1_000;
const KILL_FORCE_WAIT_MS = 1_000;
// teardown 已经 abort 重建信号、直接杀掉已知子进程之后，给后台重建循环一个短上限去自行发现并返回；
// 到点不管有没有真正 settle 都不再等——该杀的子进程已经杀了，不会有遗留进程。
const TEARDOWN_REBUILD_GRACE_MS = 3_000;
// stop() 排空 pendingTeardowns 的总体上限；每个 teardownLease 内部已经是有界的（立即 kill + 短 grace），
// 这里是防御性的第二层上限，避免任何未预见的挂起把 stop() 拖成无界等待。
const STOP_DRAIN_TIMEOUT_MS = 8_000;
function runtimeLogPath(env: RuntimeEnv): string { return join(runtimeDirectory(env), "qoder-proxy.stderr.log"); }
function appendRuntimeStderr(env: RuntimeEnv, chunk: Buffer | string): void {
  const path = runtimeLogPath(env);
  try {
    const directory = runtimeDirectory(env);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    chmodSync(directory, 0o700);
    const raw = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8");
    if (raw.length === 0) return;
    const text = raw.length > RUNTIME_LOG_MAX_BYTES ? raw.subarray(raw.length - RUNTIME_LOG_MAX_BYTES) : raw;
    if (existsSync(path) && statSync(path).size + text.length > RUNTIME_LOG_MAX_BYTES) {
      for (let index = RUNTIME_LOG_ROTATIONS - 1; index >= 1; index--) {
        const source = `${path}.${index}`;
        const target = `${path}.${index + 1}`;
        if (existsSync(source)) { if (index === RUNTIME_LOG_ROTATIONS - 1) unlinkSync(source); else renameSync(source, target); }
      }
      if (existsSync(path)) renameSync(path, `${path}.1`);
    }
    appendFileSync(path, text, { mode: 0o600 });
    chmodSync(path, 0o600);
  } catch {}
}
function createRuntimeStderrWriter(env: RuntimeEnv, secret: string): { write(chunk: Buffer | string): void; flush(): void } {
  return createStreamingSecretRedactor(secret, (chunk) => appendRuntimeStderr(env, chunk));
}
// daemon 自身发出的结构化事件（重建/熔断等）复用同一份受保护日志文件；字段白名单，绝不包含 token/body/头部。
const RUNTIME_EVENT_FIELDS = new Set(["leaseId", "generation", "attempt", "errorClass", "code", "cooldownMs", "backoffMs", "reason"]);
function logRuntimeEvent(env: RuntimeEnv, level: "info" | "warn" | "error", message: string, fields?: Record<string, unknown>): void {
  const safe: Record<string, unknown> = {};
  if (fields) for (const [key, value] of Object.entries(fields)) if (RUNTIME_EVENT_FIELDS.has(key)) safe[key] = value;
  appendRuntimeStderr(env, `${JSON.stringify({ level, message, ...safe, ts: new Date().toISOString() })}\n`);
}
function reaperIntervalMs(env: RuntimeEnv): number {
  const parsed = Number(env.QODER_RUNTIME_REAPER_MS);
  return Number.isInteger(parsed) && parsed >= 50 && parsed <= 60_000 ? parsed : DEFAULT_REAPER_MS;
}
function rebuildMaxAttempts(env: RuntimeEnv): number {
  const parsed = Number(env.QODER_RUNTIME_REBUILD_MAX_ATTEMPTS);
  return Number.isInteger(parsed) && parsed >= 1 && parsed <= 10 ? parsed : DEFAULT_REBUILD_MAX_ATTEMPTS;
}
function rebuildBackoffMs(env: RuntimeEnv): number {
  const parsed = Number(env.QODER_RUNTIME_REBUILD_BACKOFF_MS);
  return Number.isInteger(parsed) && parsed >= 0 && parsed <= 60_000 ? parsed : DEFAULT_REBUILD_BACKOFF_MS;
}
function rebuildCircuitMs(env: RuntimeEnv): number {
  const parsed = Number(env.QODER_RUNTIME_REBUILD_CIRCUIT_MS);
  return Number.isInteger(parsed) && parsed >= 0 && parsed <= 600_000 ? parsed : DEFAULT_REBUILD_CIRCUIT_MS;
}

function validRunId(value: unknown): value is string { return typeof value === "string" && /^[A-Za-z0-9._:-]{1,160}$/.test(value); }
function validOwnerPid(value: unknown): value is number { return typeof value === "number" && Number.isInteger(value) && value > 1; }
function secureExecutable(path: string): boolean { try { const st = lstatSync(path); return st.isFile() && (st.mode & 0o111) !== 0 && !st.isSymbolicLink(); } catch { return false; } }
function which(name: string, env: RuntimeEnv): string | undefined { for (const dir of (env.PATH || "").split(":")) { const candidate = join(dir || ".", name); if (secureExecutable(candidate)) return candidate; } return undefined; }
function rejectPrivateCli(path: string): void {
  try {
    if (realpathSync(path).split("/").at(-1) === "qoderclicn" || path.split("/").at(-1) === "qoderclicn") throw new Error("禁止使用 qoderclicn");
  } catch (error) {
    if (error instanceof Error && error.message === "禁止使用 qoderclicn") throw error;
  }
}
function resolveProxyCommand(env: RuntimeEnv): { command: string; args: string[]; cwd?: string } {
  const explicit = env.QODER_PROXY_BIN;
  if (explicit) {
    if (explicit.includes("/")) { if (!secureExecutable(explicit)) throw new Error("QODER_PROXY_BIN 不可执行或不安全"); rejectPrivateCli(explicit); return { command: explicit, args: ["serve"] }; }
    const path = which(explicit, env); if (!path) throw new Error(`未找到 QODER_PROXY_BIN: ${explicit}`); rejectPrivateCli(path); return { command: path, args: ["serve"] };
  }
  const installed = which("qoder-proxy", env);
  if (installed) { rejectPrivateCli(installed); return { command: installed, args: ["serve"] }; }
  const proxyDir = env.QODER_PROXY_DIR || join(env.PROJ_DIR_MINE || join(env.HOME || "", "Desktop/MyProjects"), "qoder-proxy");
  if (!existsSync(join(proxyDir, "src/cli.ts")) || !existsSync(join(proxyDir, "node_modules"))) throw new Error("未找到 qoder-proxy CLI 或源码依赖");
  const bun = which("bun", env); if (!bun) throw new Error("源码 fallback 需要 bun");
  return { command: bun, args: [join(proxyDir, "src/cli.ts"), "serve"], cwd: proxyDir };
}
async function reservePort(): Promise<number> {
  return await new Promise((resolve, reject) => {
    const server = createServer(); server.once("error", reject);
    server.listen(0, "127.0.0.1", () => { const address = server.address(); const port = typeof address === "object" && address ? address.port : 0; server.close(() => port > 0 ? resolve(port) : reject(new Error("无法分配本地端口"))); });
  });
}
async function requestStatus(url: string, token: string): Promise<{ status: number; body: string }> {
  return await new Promise((resolve, reject) => {
    const request = httpRequest(new URL(url), { headers: { authorization: `Bearer ${token}` } }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.once("end", () => resolve({ status: response.statusCode || 0, body: Buffer.concat(chunks).toString("utf8") }));
    });
    request.once("error", reject);
    request.setTimeout(500, () => request.destroy(new Error("request timeout")));
    request.end();
  });
}
function startupErrorFromFile(path: string): Error | undefined {
  try {
    const value = JSON.parse(readFileSync(path, "utf8")) as { code?: unknown; routingKey?: unknown; status?: unknown };
    if (value.code === "model-unavailable" && typeof value.routingKey === "string") return new QoderModelUnavailableError(value.routingKey);
    if (value.code === "catalog-unavailable") return new QoderModelCatalogUnavailableError();
  } catch {}
  return undefined;
}

function childExitError(child: ChildProcess, startupErrorPath: string): Error {
  return startupErrorFromFile(startupErrorPath) ?? new Error(`qoder-proxy 在 readiness 前退出（status=${child.exitCode ?? "none"}, signal=${child.signalCode ?? "none"}）`);
}

async function waitReady(baseUrl: string, token: string, child: ChildProcess, startupErrorPath: string, routingKey: string): Promise<void> {
  const deadline = Date.now() + READY_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) throw childExitError(child, startupErrorPath);
    try {
      if ((await requestStatus(`${baseUrl}/internal/quota`, token)).status !== 200) throw new Error("quota readiness failed");
      const routing = await requestStatus(`${baseUrl}/internal/model-routing`, token);
      if (routing.status === 200) {
        let body: { routingKey?: unknown; displayName?: unknown };
        try { body = JSON.parse(routing.body) as { routingKey?: unknown; displayName?: unknown }; } catch { throw new Error("model routing readiness 响应无效"); }
        if (body.routingKey !== routingKey) throw new QoderModelUnavailableError(routingKey, "identity-mismatch");
        if (expectedModelForRoutingKey(routingKey) !== undefined && (typeof body.displayName !== "string" || !hasExpectedModelIdentity({ key: routingKey, displayName: body.displayName }, routingKey))) {
          throw new QoderModelUnavailableError(routingKey, "identity-mismatch");
        }
        return;
      }
      if (routing.status === 404) throw new QoderModelUnavailableError(routingKey);
      if (routing.status === 500 || routing.status === 502) throw new QoderModelCatalogUnavailableError();
      throw new Error(`model routing readiness failed: ${routing.status}`);
    } catch (error) {
      if (error instanceof QoderModelUnavailableError || error instanceof QoderModelCatalogUnavailableError) throw error;
      if (child.exitCode !== null || child.signalCode !== null) throw childExitError(child, startupErrorPath);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (child.exitCode !== null || child.signalCode !== null) throw childExitError(child, startupErrorPath);
  throw new Error("qoder-proxy readiness 超时");
}
function killChild(child: ChildProcess): void { if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM"); }
function isChildAlive(child: ChildProcess): boolean { return child.exitCode === null && child.signalCode === null; }
async function waitForExit(child: ChildProcess, timeoutMs: number): Promise<boolean> {
  if (!isChildAlive(child)) return true;
  return await new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => resolve(false), timeoutMs);
    child.once("exit", () => { clearTimeout(timer); resolve(true); });
  });
}
// SIGTERM → 有界优雅等待 → 仍存活则 SIGKILL → 再有界等待一次，绝不会停在"发了信号就不管了"的状态，
// 避免 SIGTERM 被子进程忽略/来不及处理时，daemon 自己已经放弃等待、留下孤儿进程。
async function killChildAndWait(child: ChildProcess): Promise<void> {
  if (!isChildAlive(child)) return;
  killChild(child);
  if (await waitForExit(child, KILL_GRACEFUL_MS)) return;
  if (isChildAlive(child)) child.kill("SIGKILL");
  await waitForExit(child, KILL_FORCE_WAIT_MS);
}
// 可被 AbortSignal 立即打断的 sleep：teardown 触发 abort 后，正在 backoff 里等待的重建循环不用傻等到自然到期。
function sleepAbortable(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const onAbort = (): void => { clearTimeout(timer); resolve(); };
    const timer = setTimeout(() => { signal.removeEventListener("abort", onAbort); resolve(); }, ms);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}
function alive(pid: number): boolean { try { process.kill(pid, 0); return true; } catch { return false; } }
function lockRecord(path: string): { pid: number; nonce: string; inode: bigint } | undefined {
  try {
    const fd = openSync(path, "r");
    try {
      const stat = fstatSync(fd);
      if ((stat.mode & 0o777) !== 0o600) return undefined;
      const [pidText, nonce] = readFileSync(fd, "utf8").trim().split("\n");
      const pid = Number(pidText);
      return validOwnerPid(pid) && /^[0-9a-f]{32}$/.test(nonce || "") ? { pid, nonce: nonce!, inode: BigInt(stat.ino) } : undefined;
    } finally { closeSync(fd); }
  } catch { return undefined; }
}
function classifyRuntimeError(error: unknown): { code: "model-unavailable" | "catalog-unavailable" | "startup-failed"; errorClass: string; routingKey?: string } {
  if (error instanceof QoderModelUnavailableError) return { code: "model-unavailable", errorClass: error.name, routingKey: error.routingKey };
  if (error instanceof QoderModelCatalogUnavailableError) return { code: "catalog-unavailable", errorClass: error.name };
  return { code: "startup-failed", errorClass: error instanceof Error ? error.name : "Error" };
}

// --- 稳定 gateway：client 侧永远只看到 lease 的固定 baseUrl/token，backend 子进程可独立重建 ---
function constantTimeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) { timingSafeEqual(bufA, bufA); return false; }
  return timingSafeEqual(bufA, bufB);
}
function extractBearerToken(req: IncomingMessage): string | undefined {
  const header = req.headers.authorization;
  return typeof header === "string" && header.startsWith("Bearer ") ? header.slice(7) : undefined;
}
function sendJson(res: ServerResponse, status: number, body: unknown, headers?: Record<string, string>): void {
  if (res.writableEnded || res.headersSent) return;
  const payload = Buffer.from(JSON.stringify(body), "utf8");
  try { res.writeHead(status, { "content-type": "application/json", "content-length": String(payload.length), ...headers }); res.end(payload); } catch {}
}
function sendGatewayUnavailable(res: ServerResponse): void {
  sendJson(res, 503, { type: "error", error: { type: "api_error", message: GATEWAY_UNAVAILABLE_MESSAGE } }, { "x-should-retry": "true" });
}
function sendUnauthorized(res: ServerResponse): void {
  sendJson(res, 401, { type: "error", error: { type: "authentication_error", message: "unauthorized" } });
}

export class QoderRuntimeManager {
  private readonly leases = new Map<string, Lease>();
  private readonly inflight = new Map<string, Promise<{ runId: string; leaseId: string; baseUrl: string; socketPath: string; token: string }>>();
  private readonly env: RuntimeEnv;
  private server: Server | undefined;
  private lockFd: number | undefined;
  private lockNonce: string | undefined;
  private socketInode: bigint | undefined;
  private idleTimer: NodeJS.Timeout | undefined;
  private reaper: NodeJS.Timeout | undefined;
  private stopped = false;
  // 所有 teardownLease() 的在途 promise 都必须先在这里登记，无论触发入口是 release()/reapDeadOwners()（此时 lease
  // 已经从 this.leases 摘除，daemon 不再持有任何其它引用）还是 stop() 自身；stop() 收敛的依据是这个集合清空，
  // 而不是某个只在调用瞬间生效的 leases 快照——否则先于 stop() 触发、仍在后台跑的 teardown 会被漏等。
  private readonly pendingTeardowns = new Set<Promise<void>>();
  private stopping: Promise<void> | undefined;
  // 首次 acquire 的在途状态：key 是 runId。stop() 一旦被调用就同步置位 stopRequested（拒绝新 acquire），
  // 再逐一 abort + 强杀这里登记的子进程，并等待它们各自的 startup promise 真正 settle。
  private readonly initialStarts = new Map<string, InitialStart>();
  private stopRequested = false;
  constructor(env: RuntimeEnv = process.env) { this.env = env; }
  isStopped(): boolean { return this.stopped; }
  private releaseOwnLock(): void {
    if (this.lockFd !== undefined) {
      closeSync(this.lockFd);
      this.lockFd = undefined;
    }
    try {
      const record = lockRecord(lockPath(this.env));
      if (record?.pid === process.pid && record.nonce === this.lockNonce) unlinkSync(lockPath(this.env));
    } catch {}
    this.lockNonce = undefined;
  }
  async acquire(runId: string, ownerPid: number, tier: QoderTier = "sonnet"): Promise<{ runId: string; leaseId: string; baseUrl: string; socketPath: string; token: string; tier: QoderTier; routingKey: string }> {
    if (!validRunId(runId) || !validOwnerPid(ownerPid) || !alive(ownerPid)) throw new Error("非法 runtime run/owner");
    // stop() 一旦被调用就同步置位；任何在那之后才发起的新 acquire 直接拒绝，绝不允许在停止流程开始后
    // 还发布一个 daemon 完全没有机会追踪到的新 lease。
    if (this.stopRequested) throw new Error("runtime daemon 正在停止，拒绝新的 acquire");
    const normalizedTier = tierValue(tier);
    if (this.idleTimer) { clearTimeout(this.idleTimer); this.idleTimer = undefined; }
    const existing = this.leases.get(runId);
    if (existing) {
      if (existing.tier !== normalizedTier) throw new Error("同一 runtime run 不允许切换 model tier");
      existing.owners.add(ownerPid);
      return { runId, leaseId: existing.leaseId, baseUrl: existing.gatewayBaseUrl, socketPath: socketPath(this.env), token: existing.clientToken, tier: existing.tier, routingKey: QODER_TIER_REGISTRY[existing.tier].routingKey };
    }
    const pending = this.inflight.get(runId);
    if (pending) {
      const result = await pending;
      const lease = this.leases.get(runId);
      if (!lease) throw new Error("runtime lease lost");
      if (lease.tier !== normalizedTier) throw new Error("同一 runtime run 不允许切换 model tier");
      lease.owners.add(ownerPid);
      return { ...result, tier: lease.tier, routingKey: QODER_TIER_REGISTRY[lease.tier].routingKey };
    }
    const startState: InitialStart = { abort: new AbortController(), child: undefined };
    this.initialStarts.set(runId, startState);
    const startup = this.startLease(runId, ownerPid, normalizedTier, startState); this.inflight.set(runId, startup);
    try { return await startup; } finally { this.inflight.delete(runId); this.initialStarts.delete(runId); }
  }
  // 只负责启动一个 backend 子进程（首次或重建都复用），不涉及 lease/gateway 记账。
  // onSpawnedChild 用于把"当前正在等待 readiness 的子进程"实时登记给调用方（重建路径登记到 lease 上，
  // 首次 acquire 路径登记到 InitialStart 上），这样 teardown/stop 能立刻拿到引用强杀，
  // 而不必等它自己发现自己已经被抛弃；成功或失败收尾时都会用 undefined 反向通知"不再需要跟踪"。
  private async spawnBackend(runId: string, tier: QoderTier, generation: number, onSpawnedChild?: (child: ChildProcess | undefined) => void): Promise<Backend> {
    const port = await reservePort();
    const backendToken = randomBytes(32).toString("hex");
    const attemptId = randomBytes(16).toString("hex");
    const command = resolveProxyCommand(this.env);
    const machineSource = resolveMachineIdSource(this.env);
    const routingKey = QODER_TIER_REGISTRY[tier].routingKey;
    const childEnv: RuntimeEnv = { ...process.env, ...this.env, PORT: String(port), QODER_PROXY_API_KEY: backendToken, QODER_CN_INFER_MODEL_KEY: routingKey };
    delete childEnv.QODER_CN_MACHINE_ID;
    delete childEnv.QODER_CN_MACHINE_ID_FILE;
    if (machineSource.direct !== undefined) {
      childEnv.QODER_CN_MACHINE_ID = machineSource.direct;
      delete childEnv.QODER_CN_MACHINE_ID_FILE;
    } else {
      const machineId = machineSource.file!;
      await readMachineIdFile(machineId);
      childEnv.QODER_CN_MACHINE_ID_FILE = machineId;
      delete childEnv.QODER_CN_MACHINE_ID;
    }
    const startupErrorPath = join(runtimeDirectory(this.env), `startup-error-${runId}-${attemptId}.json`);
    childEnv.QODER_PROXY_STARTUP_ERROR_FILE = startupErrorPath;
    try { unlinkSync(startupErrorPath); } catch {}
    const child = spawn(command.command, command.args, { cwd: command.cwd, detached: false, stdio: ["ignore", "ignore", "pipe"], env: childEnv });
    onSpawnedChild?.(child);
    const stderrWriter = createRuntimeStderrWriter(this.env, backendToken);
    child.stderr?.on("data", (chunk: Buffer) => stderrWriter.write(chunk));
    child.once("close", () => stderrWriter.flush());
    const baseUrl = `http://127.0.0.1:${port}`;
    // spawn 本身失败（如可执行文件在竞态中消失）只发 error 事件、不一定跟 exit；显式监听避免变成未处理事件，
    // 并让失败更快地反映到 readiness 结果里，而不是傻等到 20s readiness 超时。
    const readyPromise = waitReady(baseUrl, backendToken, child, startupErrorPath, routingKey);
    readyPromise.catch(() => {});
    const spawnErrorPromise = new Promise<never>((_, reject) => { child.once("error", (error) => reject(error instanceof Error ? error : new Error(String(error)))); });
    spawnErrorPromise.catch(() => {});
    try {
      await Promise.race([readyPromise, spawnErrorPromise]);
      onSpawnedChild?.(undefined);
      try { unlinkSync(startupErrorPath); } catch {}
      return { generation, baseUrl, token: backendToken, child };
    } catch (error) {
      onSpawnedChild?.(undefined);
      try { unlinkSync(startupErrorPath); } catch {}
      await killChildAndWait(child);
      throw error;
    }
  }
  private async startLease(runId: string, ownerPid: number, tier: QoderTier, startState: InitialStart): Promise<{ runId: string; leaseId: string; baseUrl: string; socketPath: string; token: string; tier: QoderTier; routingKey: string }> {
    // 首次 acquire 必须保持既有语义：readiness 失败直接 reject，不留下 lease/gateway/子进程。
    // onSpawnedChild 把子进程引用实时同步给 startState：stop() 一旦看到它就能立刻强杀，
    // 不用等 waitReady() 自己在下一轮 100ms 轮询里才发现子进程已死。
    const backend = await this.spawnBackend(runId, tier, 1, (child) => { startState.child = child; });
    // 即便 spawnBackend 侥幸在 stop() 强杀之前就已经就绪成功，这里也必须再检查一次 abort 信号——
    // stop() 期间任何阶段都不允许把结果继续往下发布成一个新 lease。
    if (startState.abort.signal.aborted) { await killChildAndWait(backend.child); throw new Error("runtime daemon 正在停止"); }
    const routingKey = QODER_TIER_REGISTRY[tier].routingKey;
    const clientToken = randomBytes(32).toString("hex");
    const leaseId = randomBytes(16).toString("hex");
    const lease = {
      runId, leaseId, tier, clientToken,
      gatewayBaseUrl: "",
      gatewayPort: 0,
      owners: new Set([ownerPid]),
      backend,
      generation: 1,
      rebuildAttempts: 0,
      circuitOpenUntil: undefined,
      rebuilding: undefined,
      rebuildAbort: new AbortController(),
      currentSpawnChild: undefined,
    } as Lease;
    lease.gatewayServer = this.createGatewayServer(lease);
    try {
      // 直接在真实 gateway server 上 listen(0)、事后读它自己的 address().port，而不是先探测一个"空闲端口"再
      // 关掉重新绑定——消除探测和真正绑定之间的 TOCTOU 窗口（这段窗口里端口理论上可能被其它进程抢先占用）。
      await new Promise<void>((resolve, reject) => {
        lease.gatewayServer.once("error", reject);
        lease.gatewayServer.listen(0, "127.0.0.1", () => resolve());
      });
      const address = lease.gatewayServer.address();
      const gatewayPort = typeof address === "object" && address ? address.port : 0;
      if (gatewayPort <= 0) throw new Error("gateway 无法分配本地端口");
      lease.gatewayPort = gatewayPort;
      lease.gatewayBaseUrl = `http://127.0.0.1:${gatewayPort}`;
    } catch (error) {
      try { lease.gatewayServer.close(); } catch {}
      await killChildAndWait(backend.child);
      throw error;
    }
    // 最后一道关卡：gateway 也已经绑定完成，正要把 lease 正式发布进 this.leases 之前，最后确认一次没有被 stop() 抢跑。
    if (startState.abort.signal.aborted) {
      try { lease.gatewayServer.close(); } catch {}
      await killChildAndWait(backend.child);
      throw new Error("runtime daemon 正在停止");
    }
    this.leases.set(runId, lease);
    backend.child.once("exit", () => this.onBackendExit(lease, backend));
    return { runId, leaseId, baseUrl: lease.gatewayBaseUrl, socketPath: socketPath(this.env), token: clientToken, tier, routingKey };
  }
  // backend 意外退出（非 release/stop 主动杀死）时，只要 owner 还在，就有界重建；lease/gateway 全程保留。
  private onBackendExit(lease: Lease, deadBackend: Backend): void {
    if (lease.backend !== deadBackend) return; // 已被更新的 generation 替换，这是旧 backend 的迟到事件
    lease.backend = undefined;
    if (lease.owners.size === 0 || !this.leases.has(lease.runId)) return;
    logRuntimeEvent(this.env, "warn", "backend 意外退出", { leaseId: lease.leaseId, generation: deadBackend.generation });
    void this.scheduleRebuild(lease);
  }
  // 单飞：并发触发只跑一次重建循环；有界次数 + 固定退避；耗尽后开熔断，冷却结束由下一次触发（退出事件或网关请求）懒重试。
  private scheduleRebuild(lease: Lease): Promise<void> {
    if (lease.rebuilding) return lease.rebuilding;
    const maxAttempts = rebuildMaxAttempts(this.env);
    const backoffMs = rebuildBackoffMs(this.env);
    const circuitMs = rebuildCircuitMs(this.env);
    const aborted = (): boolean => lease.rebuildAbort.signal.aborted || lease.owners.size === 0 || !this.leases.has(lease.runId);
    const task = (async (): Promise<void> => {
      try {
        for (;;) {
          if (aborted()) return;
          if (lease.circuitOpenUntil !== undefined) {
            if (Date.now() < lease.circuitOpenUntil) return;
            lease.circuitOpenUntil = undefined;
            lease.rebuildAttempts = 0;
          }
          await sleepAbortable(backoffMs, lease.rebuildAbort.signal);
          if (aborted()) return;
          // generation 在每次实际尝试（无论成败）时都推进一格，日志里的编号才能唯一对应每一次真实 spawn 尝试。
          lease.generation += 1;
          const generation = lease.generation;
          try {
            const backend = await this.spawnBackend(lease.runId, lease.tier, generation, (child) => { lease.currentSpawnChild = child; });
            if (aborted()) { await killChildAndWait(backend.child); return; }
            const succeededAfterAttempts = lease.rebuildAttempts;
            lease.backend = backend;
            lease.rebuildAttempts = 0;
            backend.child.once("exit", () => this.onBackendExit(lease, backend));
            logRuntimeEvent(this.env, "info", "backend 重建成功", { leaseId: lease.leaseId, generation, attempt: succeededAfterAttempts + 1 });
            return;
          } catch (error) {
            lease.rebuildAttempts += 1;
            const { code, errorClass } = classifyRuntimeError(error);
            logRuntimeEvent(this.env, "warn", "backend 重建失败", { leaseId: lease.leaseId, generation, attempt: lease.rebuildAttempts, errorClass, code });
            if (lease.rebuildAttempts >= maxAttempts) {
              lease.circuitOpenUntil = Date.now() + circuitMs;
              logRuntimeEvent(this.env, "error", "backend 重建熔断", { leaseId: lease.leaseId, cooldownMs: circuitMs });
              return;
            }
          }
        }
      } finally {
        lease.rebuilding = undefined;
      }
    })();
    lease.rebuilding = task;
    return task;
  }
  private createGatewayServer(lease: Lease): HttpServer {
    return createHttpServer((req, res) => { void this.handleGatewayRequest(lease, req, res); });
  }
  // gateway 对同一次入站请求最多向 backend 转发一次：未就绪/熔断中直接 pre-response 503+x-should-retry，
  // 已建立转发后无论 backend 返回业务错误还是连接中途失败，都不做内部重试或重放。
  private async handleGatewayRequest(lease: Lease, req: IncomingMessage, res: ServerResponse): Promise<void> {
    const provided = extractBearerToken(req);
    if (provided === undefined || !constantTimeEqual(provided, lease.clientToken)) { req.resume(); sendUnauthorized(res); return; }
    const backend = lease.backend;
    const circuitOpen = lease.circuitOpenUntil !== undefined && Date.now() < lease.circuitOpenUntil;
    if (!backend || circuitOpen) {
      req.resume();
      sendGatewayUnavailable(res);
      if (lease.owners.size > 0) void this.scheduleRebuild(lease);
      return;
    }
    let target: URL;
    try { target = new URL(req.url || "/", backend.baseUrl); } catch { req.resume(); sendJson(res, 400, { type: "error", error: { type: "invalid_request_error", message: "invalid path" } }); return; }
    const outboundHeaders: Record<string, string | string[]> = {};
    for (const [key, value] of Object.entries(req.headers)) {
      if (value === undefined) continue;
      const lower = key.toLowerCase();
      if (lower === "authorization" || lower === "host" || lower === "connection") continue;
      outboundHeaders[key] = value;
    }
    outboundHeaders.authorization = `Bearer ${backend.token}`;
    outboundHeaders.host = target.host;
    // 用 res 的 close（而非 req 的 close，它在请求体正常读完时也会触发）判断客户端是否提前断开。
    let proxyReq: ReturnType<typeof httpRequest> | undefined;
    let headersFlushed = false;
    res.once("close", () => { if (!res.writableEnded) proxyReq?.destroy(); });
    proxyReq = httpRequest(target, { method: req.method, headers: outboundHeaders }, (proxyRes) => {
      headersFlushed = true;
      try { res.writeHead(proxyRes.statusCode || 502, proxyRes.headers); } catch { proxyRes.resume(); return; }
      proxyRes.pipe(res);
      proxyRes.once("error", () => { if (!res.writableEnded) res.destroy(); });
    });
    proxyReq.once("error", () => {
      if (!headersFlushed && !res.headersSent && !res.writableEnded) { sendGatewayUnavailable(res); return; }
      if (!res.writableEnded) res.destroy();
    });
    req.pipe(proxyReq);
  }
  release(runId: string, ownerPid: number, leaseId?: string): void {
    const lease = this.leases.get(runId);
    if (!lease) return;
    if (!alive(ownerPid)) return;
    if (leaseId !== undefined && lease.leaseId !== leaseId) return;
    lease.owners.delete(ownerPid);
    if (lease.owners.size === 0) { this.leases.delete(runId); this.trackTeardown(lease); this.armIdleExit(); }
  }
  reapDeadOwners(): void {
    for (const [runId, lease] of this.leases) {
      for (const owner of lease.owners) if (!alive(owner)) lease.owners.delete(owner);
      if (lease.owners.size === 0) { this.leases.delete(runId); this.trackTeardown(lease); }
    }
    if (this.leases.size === 0) this.armIdleExit();
  }
  // 统一登记入口：teardownLease() 一旦被触发（无论谁触发），其 promise 必须活在 pendingTeardowns 里直到自然完成，
  // 这样 stop() 才能可靠等到"所有已经开始、包括 stop 调用那一刻还没开始"的 teardown 都收敛，而不会漏掉
  // 已经从 this.leases 摘除、daemon 再也没有其它途径引用到的 lease。
  private trackTeardown(lease: Lease): Promise<void> {
    const settled = this.teardownLease(lease).catch((error) => {
      // 清理失败不能被静默吞掉误报成"已收敛"：记一条固定安全分类（不含子进程/网络细节），
      // 但仍然让这个 promise 正常 resolve——teardownLease 内部各步骤已经用 allSettled 互相隔离，
      // 这里只兜底捕获真正意外逃逸出来的异常。
      logRuntimeEvent(this.env, "error", "lease 清理出现未预期异常", { leaseId: lease.leaseId, errorClass: error instanceof Error ? error.name : "Error" });
    });
    this.pendingTeardowns.add(settled);
    void settled.finally(() => { this.pendingTeardowns.delete(settled); });
    return settled;
  }
  // owner 归零：显式 abort 语义——立即杀 backend、停止 gateway 接受新连接并强制断开已有连接，不做优雅 drain。
  private async teardownLease(lease: Lease): Promise<void> {
    // 立刻发 abort：重建循环的下一个检查点（包括正在等待的 backoff sleep）会马上退出，不再进入新的 spawn。
    lease.rebuildAbort.abort();
    const backend = lease.backend;
    lease.backend = undefined;
    lease.circuitOpenUntil = undefined;
    const spawningChild = lease.currentSpawnChild;
    const tasks: { label: "backend" | "spawning-child" | "gateway-close"; run: Promise<void> }[] = [];
    if (backend) tasks.push({ label: "backend", run: killChildAndWait(backend.child) });
    // 不等重建循环自己发现 lease 消失才清理——它当前正在等 readiness 的子进程立刻强杀，避免留下孤儿。
    if (spawningChild) tasks.push({ label: "spawning-child", run: killChildAndWait(spawningChild) });
    try { (lease.gatewayServer as unknown as { closeAllConnections?: () => void }).closeAllConnections?.(); } catch {}
    tasks.push({ label: "gateway-close", run: new Promise<void>((resolve) => lease.gatewayServer.close(() => resolve())) });
    // 用 allSettled 而不是 all：任何一步失败都不能连带跳过其它并行步骤或后面的重建等待——
    // 逐个记录失败分类，尽力清理完所有已知资源，而不是一步异常就整体提前放弃。
    const results = await Promise.allSettled(tasks.map((task) => task.run));
    results.forEach((result, index) => {
      if (result.status === "rejected") {
        logRuntimeEvent(this.env, "error", "lease 清理步骤失败", { leaseId: lease.leaseId, errorClass: result.reason instanceof Error ? result.reason.name : "Error", reason: tasks[index]!.label });
      }
    });
    // 已知子进程都已经强杀；重建循环理论上会在下一个检查点很快自行返回，这里给一个短上限兜底等待，
    // 而不是无界等到它自己 settle——避免任何未预见的挂起把 teardown 拖成无界阻塞。
    if (lease.rebuilding) {
      await Promise.race([
        lease.rebuilding.catch(() => {}),
        new Promise<void>((resolve) => setTimeout(resolve, TEARDOWN_REBUILD_GRACE_MS)),
      ]);
    }
  }
  private armIdleExit(): void { if (this.idleTimer || this.leases.size > 0) return; this.idleTimer = setTimeout(() => void this.stop(), IDLE_TIMEOUT_MS); }
  async listen(): Promise<void> {
    if (this.server || this.stopped) throw new Error("runtime manager 已停止或已启动");
    const directory = runtimeDirectory(this.env);
    try {
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      chmodSync(directory, 0o700);
      if (dirname(socketPath(this.env)) !== directory) throw new Error("runtime socket 必须位于受保护目录");
    } catch { throw new Error("runtime 目录不可用"); }
    const path = socketPath(this.env);
    const lock = lockPath(this.env);
    const takeLock = (): void => {
      const nonce = randomBytes(16).toString("hex");
      const fd = openSync(lock, "wx", 0o600);
      try {
        writeFileSync(fd, `${process.pid}\n${nonce}\n`, { encoding: "utf8" });
        this.lockFd = fd;
        this.lockNonce = nonce;
      } catch (error) {
        closeSync(fd);
        try { unlinkSync(lock); } catch {}
        throw error;
      }
    };
    try { takeLock(); }
    catch {
      try { const probe = await socketClient({ op: "ping" }, this.env); if (probe.ok) throw new Error("runtime daemon 已在运行"); } catch (error) { if (error instanceof Error && error.message === "runtime daemon 已在运行") throw error; }
      const record = lockRecord(lock);
      if (record !== undefined && alive(record.pid)) throw new Error("runtime daemon 锁被占用");
      if (record !== undefined) {
        try {
          const current = statSync(lock);
          if (BigInt(current.ino) === record.inode && lockRecord(lock)?.nonce === record.nonce) unlinkSync(lock);
        } catch {}
      }
      try { takeLock(); } catch { throw new Error("runtime daemon 锁被占用"); }
    }
    if (existsSync(path)) {
      try {
        const mode = statSync(path).mode & 0o777;
        if (mode !== 0o600) throw new Error("runtime socket 权限不安全");
      } catch { this.releaseOwnLock(); throw new Error("runtime socket 不可用"); }
      this.releaseOwnLock();
      throw new Error("runtime socket 已存在");
    }
    this.server = createServer((socket) => this.handle(socket));
    try {
      await new Promise<void>((resolve, reject) => { this.server!.once("error", reject); this.server!.listen(path, () => { try { chmodSync(path, 0o600); this.socketInode = BigInt(statSync(path).ino); } catch {} resolve(); }); });
      this.reaper = setInterval(() => this.reapDeadOwners(), reaperIntervalMs(this.env)); this.reaper.unref();
      this.server.once("close", () => { this.stopped = true; });
    } catch (error) {
      await this.stop();
      throw error;
    }
  }
  private handle(socket: Socket): void {
    let data = "";
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => {
      data += chunk;
      if (Buffer.byteLength(data, "utf8") > MAX_FRAME_BYTES) { socket.end('{"ok":false,"error":"runtime frame too large"}\n'); return; }
      const newline = data.indexOf("\n");
      if (newline < 0) return;
      let request: RuntimeRequest;
      try { request = JSON.parse(data.slice(0, newline)) as RuntimeRequest; } catch { socket.end('{"ok":false,"error":"invalid runtime request"}\n'); return; }
      void this.dispatch(socket, request);
    });
  }
  private async dispatch(socket: Socket, request: RuntimeRequest): Promise<void> {
    try {
      if (request.op === "ping") { socket.end('{"ok":true}\n'); return; }
      if (request.op === "status") {
        if (!validRunId(request.runId) || !validOwnerPid(request.ownerPid) || typeof request.leaseId !== "string") throw new Error("非法 runtime run/owner/lease");
        const lease = this.leases.get(request.runId);
        const active = !!lease && lease.leaseId === request.leaseId && lease.owners.has(request.ownerPid) && alive(request.ownerPid);
        socket.end(JSON.stringify({ schema: QODER_RUNTIME_STATUS_SCHEMA, ok: true, active, runId: request.runId, ownerPid: request.ownerPid, leaseId: request.leaseId, baseUrl: active ? lease?.gatewayBaseUrl : undefined, backendReady: active ? !!lease?.backend : undefined, socketPath: socketPath(this.env), diagnostics: { stderrPath: runtimeLogPath(this.env), maxBytes: RUNTIME_LOG_MAX_BYTES, rotationFiles: RUNTIME_LOG_ROTATIONS } }) + "\n"); return;
      }
      if (request.op === "acquire") { const result = await this.acquire(request.runId || "", request.ownerPid || 0, tierValue(request.tier)); socket.end(JSON.stringify({ ok: true, ...result }) + "\n"); return; }
      if (request.op === "release") { this.release(request.runId || "", request.ownerPid || 0, request.leaseId); socket.end(JSON.stringify({ ok: true, released: true, runId: request.runId, ownerPid: request.ownerPid, leaseId: request.leaseId, socketPath: socketPath(this.env) }) + "\n"); return; }
      if (request.op === "shutdown") { await this.stop(); socket.end('{"ok":true}\n'); return; }
      throw new Error("未知 runtime 操作");
    } catch (error) { socket.end(JSON.stringify(QoderRuntimeManager.runtimeError(error)) + "\n"); }
  }
  private static runtimeError(error: unknown): RuntimeResponse {
    const { code, routingKey } = classifyRuntimeError(error);
    return { ok: false, error: error instanceof Error ? error.message : "runtime failed", code, routingKey };
  }
  // 幂等 + 并发安全：多次/并发调用 stop() 都返回同一个 in-flight（或已完成）promise，不会重复关闭已释放的资源。
  async stop(): Promise<void> {
    // 同步、在任何 await 之前立即生效：调用 stop() 那一刻起，acquire() 就必须拒绝任何新请求，
    // 不给"stop() 已经在跑，但还有新 acquire 溜进来"的窗口。
    this.stopRequested = true;
    if (this.stopping) return this.stopping;
    this.stopping = this.stopInternal();
    return this.stopping;
  }
  private async stopInternal(): Promise<void> {
    if (this.idleTimer) { clearTimeout(this.idleTimer); this.idleTimer = undefined; }
    if (this.reaper) { clearInterval(this.reaper); this.reaper = undefined; }
    // 首次 acquire 在途状态：逐个 abort，已知子进程立刻强杀——不等 startLease 自己发现被抛弃。
    // 之后再等它们各自的 startup promise 真正 settle（无论成功后被 startLease 自我丢弃、还是直接失败）。
    const initialStartKills: Promise<void>[] = [];
    for (const state of this.initialStarts.values()) {
      state.abort.abort();
      if (state.child) initialStartKills.push(killChildAndWait(state.child));
    }
    const initialStartsSettled = Promise.allSettled([...this.inflight.values()]);
    // 把当前 map 里还活着的 lease 也并入统一 teardown 追踪（与 release()/reapDeadOwners() 走同一条登记路径），
    // 避免维护两套"等待逻辑"。
    for (const [runId, lease] of [...this.leases]) {
      this.leases.delete(runId);
      this.trackTeardown(lease);
    }
    // 反复排空：每一轮都重新读取 pendingTeardowns/initialStarts 当前内容，直到确实为空——
    // 这样 stop() 执行期间新触发（例如并发的 release()、reaper tick、或某个 teardown 内部又间接触发了别的清理）的
    // teardown 也一定会被等到，而不是只等 "调用 stop() 那一刻" 的快照。
    // 每个 teardownLease 内部已经是有界的（abort 信号 + 立即强杀已知子进程 + 短 grace），这里的整体上限是
    // 第二层防御，避免任何未预见的挂起把 stop() 拖成无界等待——已知子进程该杀的都已经杀过，不会有遗留进程。
    const drainDeadline = Date.now() + STOP_DRAIN_TIMEOUT_MS;
    while ((this.pendingTeardowns.size > 0 || this.initialStarts.size > 0) && Date.now() < drainDeadline) {
      await Promise.race([
        Promise.allSettled([...this.pendingTeardowns, initialStartsSettled]),
        new Promise<void>((resolve) => setTimeout(resolve, Math.max(0, drainDeadline - Date.now()))),
      ]);
    }
    await Promise.allSettled(initialStartKills);
    await new Promise<void>((resolve) => this.server?.close(() => resolve()) ?? resolve());
    const path = socketPath(this.env);
    try {
      if (existsSync(path) && this.socketInode !== undefined && BigInt(statSync(path).ino) === this.socketInode) unlinkSync(path);
    } catch {}
    this.releaseOwnLock();
    this.socketInode = undefined;
    this.server = undefined;
    this.stopped = true;
  }
}

function socketClient(request: RuntimeRequest, env: RuntimeEnv): Promise<RuntimeResponse> { return new Promise((resolve, reject) => { const socket = createConnection(socketPath(env)); let data = ""; const timer = setTimeout(() => { socket.destroy(); reject(new Error("runtime daemon unavailable")); }, CLIENT_TIMEOUT_MS); socket.setEncoding("utf8"); socket.on("error", (error) => { clearTimeout(timer); reject(error); }); socket.on("data", (chunk) => { data += chunk; if (Buffer.byteLength(data, "utf8") > MAX_FRAME_BYTES) { clearTimeout(timer); socket.destroy(); reject(new Error("runtime frame too large")); return; } const newline = data.indexOf("\n"); if (newline < 0) return; clearTimeout(timer); socket.end(); try { resolve(JSON.parse(data.slice(0, newline)) as RuntimeResponse); } catch (error) { reject(error); } }); socket.write(JSON.stringify(request) + "\n"); }); }
async function startDaemon(env: RuntimeEnv): Promise<void> { const script = process.argv[1]; if (!script) throw new Error("runtime CLI entry unavailable"); const child = spawn(process.execPath, [script, "runtime", "daemon"], { detached: true, stdio: "ignore", env: { ...process.env, ...env } }); child.unref(); }
export async function runRuntimeCommand(args: string[], env: RuntimeEnv = process.env, io: RuntimeIo = { stdout: (value) => process.stdout.write(value), stderr: (value) => process.stderr.write(value) }): Promise<void> {
  const command = args[0]; if (command === "daemon") { const manager = new QoderRuntimeManager(env); await manager.listen(); process.on("SIGTERM", () => void manager.stop().then(() => process.exit(0))); process.on("SIGINT", () => void manager.stop().then(() => process.exit(0))); await new Promise(() => {}); }
  if (command !== "acquire" && command !== "release" && command !== "shutdown" && command !== "status") throw new Error("runtime 用法：acquire|release|status|shutdown");
  const request: RuntimeRequest = { op: command, runId: args[1], ownerPid: Number(args[2] || process.ppid), leaseId: command === "acquire" ? undefined : args[3], tier: command === "acquire" ? args[3] : undefined }; let response: RuntimeResponse | undefined;
  const canStartDaemon = command === "acquire";
  for (let attempt = 0; attempt < 4 && !response; attempt++) {
    try { response = await socketClient(request, env); }
    catch {
      if (canStartDaemon && attempt === 0) await startDaemon(env);
      else if (!canStartDaemon) break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  if (!response) throw new Error("runtime daemon 启动超时");
  if (!response.ok) {
    const error = new Error(response.error) as Error & { code?: string; routingKey?: string };
    error.code = response.code;
    error.routingKey = response.routingKey;
    throw error;
  }
  if (command === "acquire") io.stdout(`${JSON.stringify({ runId: response.runId, leaseId: response.leaseId, baseUrl: response.baseUrl, socketPath: response.socketPath, token: response.token, tier: response.tier, routingKey: response.routingKey })}\n`);
  else if (command === "status") io.stdout(`${JSON.stringify({ active: response.active === true, runId: response.runId, ownerPid: response.ownerPid, leaseId: response.leaseId, baseUrl: response.baseUrl, backendReady: response.backendReady, socketPath: response.socketPath, diagnostics: response.diagnostics })}\n`);
  else if (command === "release") io.stdout(`${JSON.stringify({ released: response.released === true, runId: response.runId, ownerPid: response.ownerPid, leaseId: response.leaseId, socketPath: response.socketPath })}\n`);
}
