// Qoder session runtime manager：代理与临时认证只存在 daemon 内存中。
import { randomBytes } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { chmodSync, closeSync, existsSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import { dirname, join } from "node:path";
import { request as httpRequest } from "node:http";

export type RuntimeEnv = Record<string, string | undefined>;
export type RuntimeIo = { stdout(value: string): void; stderr(value: string): void };
export const QODER_TIER_REGISTRY = {
  opus: { claudeModel: "qmodel_preview[1m]", routingKey: "qmodel_preview" },
  sonnet: { claudeModel: "qmodel_latest[1m]", routingKey: "qmodel_latest" },
  haiku: { claudeModel: "q36fmodel[1m]", routingKey: "q36fmodel" },
} as const;
export type QoderTier = keyof typeof QODER_TIER_REGISTRY;
type RuntimeRequest = { op: "acquire" | "release" | "shutdown" | "ping" | "status"; runId?: string; ownerPid?: number; leaseId?: string; tier?: string };
type RuntimeResponse = { ok: true; active?: boolean; runId?: string; ownerPid?: number; leaseId?: string; baseUrl?: string; socketPath?: string; token?: string; released?: boolean; tier?: QoderTier; routingKey?: string } | { ok: false; error: string };
type Lease = { runId: string; token: string; leaseId: string; tier: QoderTier; baseUrl: string; child: ChildProcess; owners: Set<number>; invalid: boolean };
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
const DEFAULT_REAPER_MS = 500;
function reaperIntervalMs(env: RuntimeEnv): number {
  const parsed = Number(env.QODER_RUNTIME_REAPER_MS);
  return Number.isInteger(parsed) && parsed >= 50 && parsed <= 60_000 ? parsed : DEFAULT_REAPER_MS;
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
function machineIdFile(env: RuntimeEnv): string {
  const value = env.QODER_CN_MACHINE_ID_FILE;
  if (!value) throw new Error("必须显式提供 QODER_CN_MACHINE_ID_FILE");
  if (!existsSync(value)) throw new Error("Qoder machine ID 文件不可用或不安全");
  const st = lstatSync(value); if (!st.isFile() || st.isSymbolicLink()) throw new Error("Qoder machine ID 文件不可用或不安全");
  return value;
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
async function waitReady(baseUrl: string, token: string): Promise<void> {
  const deadline = Date.now() + READY_TIMEOUT_MS;
  while (Date.now() < deadline) {
    try { if ((await requestStatus(`${baseUrl}/internal/quota`, token)).status === 200) return; } catch { /* readiness retry */ }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("qoder-proxy readiness 超时");
}
function killChild(child: ChildProcess): void { if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM"); }
async function waitChildExit(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, 1_000);
    child.once("exit", () => { clearTimeout(timer); resolve(); });
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
  constructor(env: RuntimeEnv = process.env) { this.env = env; }
  isStopped(): boolean { return this.stopped; }
  async acquire(runId: string, ownerPid: number, tier: QoderTier = "sonnet"): Promise<{ runId: string; leaseId: string; baseUrl: string; socketPath: string; token: string; tier: QoderTier; routingKey: string }> {
    if (!validRunId(runId) || !validOwnerPid(ownerPid) || !alive(ownerPid)) throw new Error("非法 runtime run/owner");
    const normalizedTier = tierValue(tier);
    if (this.idleTimer) { clearTimeout(this.idleTimer); this.idleTimer = undefined; }
    const existing = this.leases.get(runId); if (existing) { if (existing.invalid) { this.leases.delete(runId); throw new Error("runtime lease 已失效"); } if (existing.tier !== normalizedTier) throw new Error("同一 runtime run 不允许切换 model tier"); existing.owners.add(ownerPid); return { runId, leaseId: existing.leaseId, baseUrl: existing.baseUrl, socketPath: socketPath(this.env), token: existing.token, tier: existing.tier, routingKey: QODER_TIER_REGISTRY[existing.tier].routingKey }; }
    const pending = this.inflight.get(runId); if (pending) { const result = await pending; const lease = this.leases.get(runId); if (!lease) throw new Error("runtime lease lost"); if (lease.tier !== normalizedTier) throw new Error("同一 runtime run 不允许切换 model tier"); lease.owners.add(ownerPid); return { ...result, tier: lease.tier, routingKey: QODER_TIER_REGISTRY[lease.tier].routingKey }; }
    const startup = this.startLease(runId, ownerPid, normalizedTier); this.inflight.set(runId, startup);
    try { return await startup; } finally { this.inflight.delete(runId); }
  }
  private async startLease(runId: string, ownerPid: number, tier: QoderTier): Promise<{ runId: string; leaseId: string; baseUrl: string; socketPath: string; token: string; tier: QoderTier; routingKey: string }> {
    const port = await reservePort(); const token = randomBytes(32).toString("hex"); const leaseId = randomBytes(16).toString("hex"); const command = resolveProxyCommand(this.env); const machineId = machineIdFile(this.env); const routingKey = QODER_TIER_REGISTRY[tier].routingKey;
    const child = spawn(command.command, command.args, { cwd: command.cwd, detached: false, stdio: "ignore", env: { ...process.env, ...this.env, PORT: String(port), QODER_PROXY_API_KEY: token, QODER_CN_MACHINE_ID_FILE: machineId, QODER_CN_INFER_MODEL_KEY: routingKey } });
    const lease: Lease = { runId, token, leaseId, tier, baseUrl: `http://127.0.0.1:${port}`, child, owners: new Set([ownerPid]), invalid: false }; this.leases.set(runId, lease);
    child.once("exit", () => {
      lease.invalid = true;
      if (this.leases.get(runId) === lease) { this.leases.delete(runId); this.armIdleExit(); }
    });
    try { await waitReady(lease.baseUrl, token); return { runId, leaseId, baseUrl: lease.baseUrl, socketPath: socketPath(this.env), token, tier, routingKey }; } catch (error) { this.leases.delete(runId); killChild(child); throw error; }
  }
  release(runId: string, ownerPid: number, leaseId?: string): void { const lease = this.leases.get(runId); if (!lease || (leaseId !== undefined && lease.leaseId !== leaseId)) return; lease.owners.delete(ownerPid); if (lease.owners.size === 0) { this.leases.delete(runId); killChild(lease.child); this.armIdleExit(); } }
  reapDeadOwners(): void { for (const [runId, lease] of this.leases) { for (const owner of lease.owners) if (!alive(owner)) lease.owners.delete(owner); if (lease.owners.size === 0) { this.leases.delete(runId); killChild(lease.child); } } if (this.leases.size === 0) this.armIdleExit(); }
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
      } catch { if (this.lockFd !== undefined) closeSync(this.lockFd); this.lockFd = undefined; throw new Error("runtime socket 不可用"); }
      if (this.lockFd !== undefined) closeSync(this.lockFd); this.lockFd = undefined; throw new Error("runtime socket 已存在");
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
        const active = !!lease && !lease.invalid && lease.leaseId === request.leaseId && lease.owners.has(request.ownerPid) && alive(request.ownerPid);
        socket.end(JSON.stringify({ schema: QODER_RUNTIME_STATUS_SCHEMA, ok: true, active, runId: request.runId, ownerPid: request.ownerPid, leaseId: request.leaseId, baseUrl: active ? lease?.baseUrl : undefined, socketPath: socketPath(this.env) }) + "\n"); return;
      }
      if (request.op === "acquire") { const result = await this.acquire(request.runId || "", request.ownerPid || 0, tierValue(request.tier)); socket.end(JSON.stringify({ ok: true, ...result }) + "\n"); return; }
      if (request.op === "release") { this.release(request.runId || "", request.ownerPid || 0, request.leaseId); socket.end(JSON.stringify({ ok: true, released: true, runId: request.runId, ownerPid: request.ownerPid, leaseId: request.leaseId, socketPath: socketPath(this.env) }) + "\n"); return; }
      if (request.op === "shutdown") { await this.stop(); socket.end('{"ok":true}\n'); return; }
      throw new Error("未知 runtime 操作");
    } catch (error) { socket.end(JSON.stringify({ ok: false, error: error instanceof Error ? error.message : "runtime failed" }) + "\n"); }
  }
  async stop(): Promise<void> {
    if (this.stopped && !this.server) return;
    if (this.idleTimer) { clearTimeout(this.idleTimer); this.idleTimer = undefined; }
    if (this.reaper) clearInterval(this.reaper);
    const children = [...new Set([...this.leases.values()].map((lease) => lease.child))];
    for (const child of children) killChild(child);
    await Promise.all(children.map(waitChildExit));
    this.leases.clear();
    await new Promise<void>((resolve) => this.server?.close(() => resolve()) ?? resolve());
    const path = socketPath(this.env);
    try {
      if (existsSync(path) && this.socketInode !== undefined && BigInt(statSync(path).ino) === this.socketInode) unlinkSync(path);
    } catch {}
    if (this.lockFd !== undefined) {
      closeSync(this.lockFd);
      this.lockFd = undefined;
      try {
        const record = lockRecord(lockPath(this.env));
        if (record?.pid === process.pid && record.nonce === this.lockNonce) unlinkSync(lockPath(this.env));
      } catch {}
      this.lockNonce = undefined;
    }
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
  if (!response) throw new Error("runtime daemon 启动超时"); if (!response.ok) throw new Error(response.error);
  if (command === "acquire") io.stdout(`${JSON.stringify({ runId: response.runId, leaseId: response.leaseId, baseUrl: response.baseUrl, socketPath: response.socketPath, token: response.token, tier: response.tier, routingKey: response.routingKey })}\n`);
  else if (command === "status") io.stdout(`${JSON.stringify({ active: response.active === true, runId: response.runId, ownerPid: response.ownerPid, leaseId: response.leaseId, baseUrl: response.baseUrl, socketPath: response.socketPath })}\n`);
  else if (command === "release") io.stdout(`${JSON.stringify({ released: response.released === true, runId: response.runId, ownerPid: response.ownerPid, leaseId: response.leaseId, socketPath: response.socketPath })}\n`);
}
