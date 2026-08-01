// Qoder session runtime manager：代理与临时认证只存在 daemon 内存中。
import { randomBytes } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { chmodSync, existsSync, lstatSync, unlinkSync } from "node:fs";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import { join } from "node:path";
import { request as httpRequest } from "node:http";

export type RuntimeEnv = Record<string, string | undefined>;
export type RuntimeIo = { stdout(value: string): void; stderr(value: string): void };
type RuntimeRequest = { op: "acquire" | "release" | "shutdown"; runId?: string; ownerPid?: number };
type RuntimeResponse = { ok: true; baseUrl?: string; token?: string } | { ok: false; error: string };
type Lease = { runId: string; token: string; baseUrl: string; child: ChildProcess; owners: Set<number> };

const socketPath = (env: RuntimeEnv = process.env): string => env.QODER_PROXY_RUNTIME_SOCKET || join(env.TMPDIR || "/tmp", `qoder-proxy-runtime-${typeof process.getuid === "function" ? process.getuid() : "user"}.sock`);
const READY_TIMEOUT_MS = 20_000;
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
function resolveProxyCommand(env: RuntimeEnv): { command: string; args: string[]; cwd?: string } {
  const explicit = env.QODER_PROXY_BIN;
  if (explicit) {
    if (explicit.includes("/")) { if (!secureExecutable(explicit)) throw new Error("QODER_PROXY_BIN 不可执行或不安全"); return { command: explicit, args: ["serve"] }; }
    const path = which(explicit, env); if (!path) throw new Error(`未找到 QODER_PROXY_BIN: ${explicit}`); return { command: path, args: ["serve"] };
  }
  const installed = which("qoder-proxy", env);
  if (installed) return { command: installed, args: ["serve"] };
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

export class QoderRuntimeManager {
  private readonly leases = new Map<string, Lease>();
  private readonly inflight = new Map<string, Promise<{ baseUrl: string; token: string }>>();
  private readonly env: RuntimeEnv;
  private server: Server | undefined;
  private idleTimer: NodeJS.Timeout | undefined;
  private reaper: NodeJS.Timeout | undefined;
  constructor(env: RuntimeEnv = process.env) { this.env = env; }
  async acquire(runId: string, ownerPid: number): Promise<{ baseUrl: string; token: string }> {
    if (!validRunId(runId) || !validOwnerPid(ownerPid)) throw new Error("非法 runtime run/owner");
    const existing = this.leases.get(runId); if (existing) { existing.owners.add(ownerPid); return { baseUrl: existing.baseUrl, token: existing.token }; }
    const pending = this.inflight.get(runId); if (pending) { const result = await pending; const lease = this.leases.get(runId); if (!lease) throw new Error("runtime lease lost"); lease.owners.add(ownerPid); return result; }
    const startup = this.startLease(runId, ownerPid); this.inflight.set(runId, startup);
    try { return await startup; } finally { this.inflight.delete(runId); }
  }
  private async startLease(runId: string, ownerPid: number): Promise<{ baseUrl: string; token: string }> {
    const port = await reservePort(); const token = randomBytes(32).toString("hex"); const command = resolveProxyCommand(this.env); const machineId = machineIdFile(this.env);
    const child = spawn(command.command, command.args, { cwd: command.cwd, detached: false, stdio: "ignore", env: { ...process.env, ...this.env, PORT: String(port), QODER_PROXY_API_KEY: token, QODER_CN_MACHINE_ID_FILE: machineId, QODER_CN_INFER_MODEL_KEY: "qmodel_preview" } });
    const lease: Lease = { runId, token, baseUrl: `http://127.0.0.1:${port}`, child, owners: new Set([ownerPid]) }; this.leases.set(runId, lease);
    try { await waitReady(lease.baseUrl, token); return { baseUrl: lease.baseUrl, token }; } catch (error) { this.leases.delete(runId); killChild(child); throw error; }
  }
  release(runId: string, ownerPid: number): void { const lease = this.leases.get(runId); if (!lease) return; lease.owners.delete(ownerPid); if (lease.owners.size === 0) { this.leases.delete(runId); killChild(lease.child); this.armIdleExit(); } }
  reapDeadOwners(): void { for (const [runId, lease] of this.leases) { for (const owner of lease.owners) if (!alive(owner)) lease.owners.delete(owner); if (lease.owners.size === 0) { this.leases.delete(runId); killChild(lease.child); } } if (this.leases.size === 0) this.armIdleExit(); }
  private armIdleExit(): void { if (this.idleTimer || this.leases.size > 0) return; this.idleTimer = setTimeout(() => void this.stop(), IDLE_TIMEOUT_MS); }
  async listen(): Promise<void> {
    const path = socketPath(this.env); try { if (existsSync(path)) unlinkSync(path); } catch { /* stale socket is fail-closed */ }
    this.server = createServer((socket) => this.handle(socket));
    await new Promise<void>((resolve, reject) => { this.server!.once("error", reject); this.server!.listen(path, () => { try { chmodSync(path, 0o600); } catch {} resolve(); }); });
    this.reaper = setInterval(() => this.reapDeadOwners(), reaperIntervalMs(this.env)); this.reaper.unref();
  }
  private handle(socket: Socket): void { let data = ""; socket.setEncoding("utf8"); socket.on("data", (chunk) => { data += chunk; const newline = data.indexOf("\n"); if (newline < 0) return; let request: RuntimeRequest; try { request = JSON.parse(data.slice(0, newline)) as RuntimeRequest; } catch { socket.end('{"ok":false,"error":"invalid runtime request"}\n'); return; } void this.dispatch(socket, request); }); }
  private async dispatch(socket: Socket, request: RuntimeRequest): Promise<void> { try { if (request.op === "acquire") { const result = await this.acquire(request.runId || "", request.ownerPid || 0); socket.end(JSON.stringify({ ok: true, ...result }) + "\n"); return; } if (request.op === "release") { this.release(request.runId || "", request.ownerPid || 0); socket.end('{"ok":true}\n'); return; } if (request.op === "shutdown") { await this.stop(); socket.end('{"ok":true}\n'); return; } throw new Error("未知 runtime 操作"); } catch (error) { socket.end(JSON.stringify({ ok: false, error: error instanceof Error ? error.message : "runtime failed" }) + "\n"); } }
  async stop(): Promise<void> {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    if (this.reaper) clearInterval(this.reaper);
    const children = [...this.leases.values()].map((lease) => lease.child);
    for (const child of children) killChild(child);
    await Promise.all(children.map(waitChildExit));
    this.leases.clear();
    await new Promise<void>((resolve) => this.server?.close(() => resolve()) ?? resolve());
    const path = socketPath(this.env); try { if (existsSync(path)) unlinkSync(path); } catch {}
  }
}

function socketClient(request: RuntimeRequest, env: RuntimeEnv): Promise<RuntimeResponse> { return new Promise((resolve, reject) => { const socket = createConnection(socketPath(env)); let data = ""; const timer = setTimeout(() => { socket.destroy(); reject(new Error("runtime daemon unavailable")); }, CLIENT_TIMEOUT_MS); socket.setEncoding("utf8"); socket.on("error", (error) => { clearTimeout(timer); reject(error); }); socket.on("data", (chunk) => { data += chunk; const newline = data.indexOf("\n"); if (newline < 0) return; clearTimeout(timer); socket.end(); try { resolve(JSON.parse(data.slice(0, newline)) as RuntimeResponse); } catch (error) { reject(error); } }); socket.write(JSON.stringify(request) + "\n"); }); }
async function startDaemon(env: RuntimeEnv): Promise<void> { const script = process.argv[1]; if (!script) throw new Error("runtime CLI entry unavailable"); const child = spawn(process.execPath, [script, "runtime", "daemon"], { detached: true, stdio: "ignore", env: { ...process.env, ...env } }); child.unref(); }
export async function runRuntimeCommand(args: string[], env: RuntimeEnv = process.env, io: RuntimeIo = { stdout: (value) => process.stdout.write(value), stderr: (value) => process.stderr.write(value) }): Promise<void> {
  const command = args[0]; if (command === "daemon") { const manager = new QoderRuntimeManager(env); await manager.listen(); process.on("SIGTERM", () => void manager.stop().then(() => process.exit(0))); process.on("SIGINT", () => void manager.stop().then(() => process.exit(0))); await new Promise(() => {}); }
  if (command !== "acquire" && command !== "release" && command !== "shutdown") throw new Error("runtime 用法：acquire|release|shutdown");
  const request: RuntimeRequest = { op: command, runId: args[1], ownerPid: Number(args[2] || process.ppid) }; let response: RuntimeResponse | undefined;
  for (let attempt = 0; attempt < 4 && !response; attempt++) { try { response = await socketClient(request, env); } catch { if (attempt === 0) await startDaemon(env); await new Promise((resolve) => setTimeout(resolve, 100)); } }
  if (!response) throw new Error("runtime daemon 启动超时"); if (!response.ok) throw new Error(response.error); if (command === "acquire") io.stdout(`${JSON.stringify({ baseUrl: response.baseUrl, token: response.token })}\n`);
}
