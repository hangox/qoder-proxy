// 安全 config store + 进程级 AuthSession。
// 生产会话仅使用既有安全 config；永不触发 Device Flow、不读 Qoder 私有凭据、不启动 qoderclicn。

import { readFile, chmod, mkdir, open, rename, unlink, lstat, link, readdir, rmdir, realpath } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { basename, delimiter, dirname, isAbsolute, join } from "node:path";
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { sha256, requireCnAllowedUrl, QoderContext, validatePreparedResult, decryptOrPlain, generateRuntimeAuthFields, loadAuthBridge, type Bridge, type PreparedRequest } from "./bridge.ts";
import { parseQoderAssistantCatalog, type QoderAssistantModel } from "../models.ts";
import type { RoutingAttestationSessionObserver } from "../attestation.ts";

export type StoredCredential = {
  version: 1;
  site: "cn";
  machineIdHash: string;
  token: string;
  refreshToken?: string;
  expiresAt?: number;
  refreshTokenExpiresAt?: number;
  userId?: string;
  userName?: string;
};

export type RotationReservation = string;
export type ImportTargetState = { exists: boolean };
export type ImportApplyResult = { backupId: string; replaced: boolean };
export type ImportStatus = { backupId: string; state: "committed" | "pending-apply" | "pending-rollback" | "pending-finalize" };
export type CredentialStore = {
  load(): Promise<StoredCredential | undefined>;
  isCommitted(v: StoredCredential): Promise<boolean>;
  isRotationStaged?(v: StoredCredential, owner: RotationReservation): Promise<boolean>;
  reserveRotation(base: StoredCredential, signal?: AbortSignal): Promise<RotationReservation>;
  markRotationNetworkStarted?(owner: RotationReservation): Promise<void>;
  clearRotationReservation(owner: RotationReservation): Promise<void>;
  stageRotation(v: StoredCredential, owner: RotationReservation): Promise<void>;
  stageEmergencyRotation?(v: StoredCredential, owner: RotationReservation): Promise<void>;
  save(v: StoredCredential, owner?: RotationReservation): Promise<void>;
  delete(owner?: RotationReservation): Promise<void>;
  inspectImportTarget?(): Promise<ImportTargetState>;
  importStatus?(): Promise<ImportStatus[]>;
  applyImport?(v: StoredCredential, replace: boolean): Promise<ImportApplyResult>;
  rollbackImport?(backupId: string): Promise<void>;
  finalizeImport?(backupId: string): Promise<void>;
};
export type AuthInputs = { uid: string; organization_id: unknown; organization_tags: unknown; data_policy_agreed: boolean };
export type SignedAttempt = { context: QoderContext; prepared: PreparedRequest; auth: AuthInputs };
export type ModelCatalogSnapshot = { readonly models: readonly QoderAssistantModel[]; readonly generation: number };
export type QoderQuotaBucket = {
  readonly total: number;
  readonly used: number;
  readonly remaining: number;
  readonly percentage: number;
  readonly unit: string;
};
export type QoderQuotaUsage = {
  readonly totalUsagePercentage: number;
  readonly expiresAt: number;
  readonly userQuota: QoderQuotaBucket;
  readonly addOnQuota?: QoderQuotaBucket & { readonly detailUrl: string };
  readonly orgResourcePackage?: {
    readonly used: number;
    readonly cap: number;
    readonly remaining: number;
    readonly percentage: number;
    readonly available: boolean;
    readonly unit: string;
  };
  readonly isQuotaExceeded: boolean;
};

export class StaleModelCatalogError extends Error {
  constructor() {
    super("模型目录 generation 已变化，必须重新解析模型");
    this.name = "StaleModelCatalogError";
  }
}

const DEFAULT_CONFIG_DIR = join(homedir(), ".config", "qoder-proxy");
const CONFIG_FILE = "auth-cn.json";
const ROTATION_FILE = "auth-cn.rotation.json";
const EMERGENCY_ROTATION_FILE = "auth-cn.rotation.emergency.json";
const ROTATION_RESERVATION_FILE = "auth-cn.rotation.pending";
const IMPORT_PENDING_FILE = "auth-cn.import.pending";
const IMPORT_BACKUP_PREFIX = ".auth-cn.import.";
const IMPORT_FILE_MAX_BYTES = 4 * 1024 * 1024;
const DEFAULT_COSY_VERSION = "1.1.6";
const DEFAULT_REFRESH_TIMEOUT_MS = 30_000;
const DEFAULT_CAPABILITY_TIMEOUT_MS = 1_000;
const MAX_REFRESH_TIMEOUT_MS = 10 * 60_000;
const DEFAULT_MODEL_CATALOG_TTL_MS = 100_000;
const MAX_MODEL_CATALOG_TTL_MS = 10 * 60_000;
const DEFAULT_MODEL_CATALOG_TIMEOUT_MS = 30_000;
const MAX_MODEL_CATALOG_BYTES = 4 * 1024 * 1024;
const DEFAULT_QUOTA_TTL_MS = 15_000;
const MAX_QUOTA_TTL_MS = 10 * 60_000;
const DEFAULT_QUOTA_TIMEOUT_MS = 8_000;
const MAX_QUOTA_BYTES = 64 * 1024;
const MAX_QUOTA_IDENTITY_LENGTH = 256;
const MAX_QUOTA_UNIT_LENGTH = 32;
const MAX_QUOTA_DETAIL_URL_LENGTH = 2_048;
const MODEL_CATALOG_PATH = "/api/v2/model/list?Encode=1";
const QUOTA_USAGE_PATH = "/api/v2/quota/usage";
const CN_WW_CLIENT_CONTEXT = { client_type: "5", business_product: "cli", business_type: "agent", scene: "assistant" };
const ACTIVE_ROTATION_OWNERS = new Set<RotationReservation>();
const execFileAsync = promisify(execFile);
let processStartIdentityPromise: Promise<string> | undefined;
async function processStartIdentity(pid = process.pid): Promise<string | undefined> {
  if (pid === process.pid && processStartIdentityPromise) return processStartIdentityPromise;
  const read = async (): Promise<string> => {
    const { stdout } = await execFileAsync("ps", ["-o", "lstart=", "-p", String(pid)]);
    const value = stdout.trim();
    if (!value) throw new Error("进程启动身份不可用");
    return sha256(value);
  };
  if (pid === process.pid) processStartIdentityPromise = read();
  try { return await (pid === process.pid ? processStartIdentityPromise : read()); }
  catch { return undefined; }
}

export async function evaluateProcessOwnerActivity(
  expectedStartIdentity: string,
  probePid: () => "dead" | "live-or-unknown",
  readStartIdentity: () => Promise<string | undefined>,
): Promise<boolean> {
  if (probePid() === "dead") return false;
  const actual = await readStartIdentity();
  return actual === undefined || actual === expectedStartIdentity;
}

function resolveConfigDir(env: Record<string, string | undefined>): string {
  const dir = env.QODER_PROXY_CONFIG_DIR === undefined || env.QODER_PROXY_CONFIG_DIR.length === 0 ? DEFAULT_CONFIG_DIR : env.QODER_PROXY_CONFIG_DIR;
  if (!isAbsolute(dir)) throw new Error("QODER_PROXY_CONFIG_DIR 必须是绝对路径");
  return dir;
}

function validate(v: unknown, machineIdHash: string): StoredCredential {
  const c = v as Record<string, unknown>;
  if (typeof c !== "object" || c === null) throw new Error("config 凭据不是对象");
  if (c.version !== 1 || c.site !== "cn") throw new Error("config 凭据版本或站点不匹配");
  if (c.machineIdHash !== machineIdHash) throw new Error("config 凭据与当前 machine ID 不匹配");
  if (typeof c.token !== "string" || c.token.length === 0) throw new Error("config 凭据缺少 token");
  for (const key of ["refreshToken", "userId", "userName"] as const) if (c[key] !== undefined && typeof c[key] !== "string") throw new Error(`config 凭据字段 ${key} 类型错误`);
  for (const key of ["expiresAt", "refreshTokenExpiresAt"] as const) if (c[key] !== undefined && !(typeof c[key] === "number" && Number.isFinite(c[key]))) throw new Error(`config 凭据字段 ${key} 类型错误`);
  return v as StoredCredential;
}

export function requireMachineId(env: Record<string, string | undefined>): string {
  const machineId = env.QODER_CN_MACHINE_ID;
  if (typeof machineId !== "string" || machineId.length === 0) throw new Error("QODER_CN_MACHINE_ID 必须是非空字符串");
  return machineId;
}

export function requireCosyVersion(env: Record<string, string | undefined>): string {
  const value = env.QODER_CN_COSY_VERSION ?? DEFAULT_COSY_VERSION;
  if (value.length === 0) throw new Error("QODER_CN_COSY_VERSION 不得为空");
  return value;
}

export async function requireBunExecutable(env: Record<string, string | undefined>, configured?: string): Promise<string> {
  const requested = configured ?? env.BUN_EXEC_PATH;
  if (requested !== undefined && requested.length === 0) throw new Error("BUN_EXEC_PATH 不得为空");
  const verify = async (candidate: string): Promise<string> => {
    if (!isAbsolute(candidate)) throw new Error("Bun capability runtime 必须是绝对路径");
    const executable = await realpath(candidate);
    const { stdout } = await execFileAsync(executable, ["--version"], { timeout: 1_000, windowsHide: true });
    if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\s*$/.test(stdout)) throw new Error("capability runtime 不是受支持的 Bun executable");
    return executable;
  };
  if (requested !== undefined) {
    try { return await verify(requested); }
    catch (error) { throw Object.assign(new Error("Bun capability runtime 不可用"), { cause: error, code: (error as NodeJS.ErrnoException).code }); }
  }
  if (process.versions.bun) return verify(process.execPath);
  for (const directory of (env.PATH ?? process.env.PATH ?? "").split(delimiter)) {
    if (!directory || !isAbsolute(directory)) continue;
    try { return await verify(join(directory, "bun")); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT" && (error as NodeJS.ErrnoException).code !== "ENOTDIR") throw error;
    }
  }
  throw new Error("无法定位 Bun capability runtime，拒绝运行 fd capability probe");
}

type RotationPublishPhase = "before-create" | "after-create" | "after-write" | "after-chmod" | "after-file-fsync" | "before-publish" | "after-publish" | "before-directory-fsync" | "after-directory-fsync";
type CapabilityProbeMode = "native" | "async-pending" | "sync-block" | "late-success" | "late-reject" | "unsupported" | "unsupported-native";
type CapabilityWatchdogMode = "normal" | "spawn-eagain" | "spawn-emfile" | "error-only" | "early-exit" | "ready-timeout" | "wrong-nonce" | "wrong-identity" | "identity-transient" | "identity-permanent" | "post-ready-exit" | "post-ready-error" | "post-ready-close" | "post-ready-sigterm" | "post-ready-sigkill";
type ConfigStoreDependencies = {
  onRotationPublishPhase?: (phase: RotationPublishPhase, paths: { temp: string; target: string }) => void | Promise<void>;
  beforeRotationTempCleanup?: (path: string) => void | Promise<void>;
  beforeOrphanPromotionLink?: (source: string, target: string) => void | Promise<void>;
  afterOrphanClaimAcquire?: (source: string, claim: string) => void | Promise<void>;
  afterOrphanPromotionPublish?: (claim: string, target: string) => void | Promise<void>;
  capabilityProbeMode?: CapabilityProbeMode;
  capabilityProbeReadyPath?: string;
  capabilityNativeStartedPath?: string;
  capabilityProbeWorkDelayMs?: number;
  capabilitySupervisorReadyPath?: string;
  capabilitySupervisorStartupDelayMs?: number;
  capabilityWatchdogMode?: CapabilityWatchdogMode;
  capabilityWatchdogExecutable?: string;
  capabilityExecutable?: string;
  spawnCapabilityProcess?: typeof spawn;
  publishFdExclusive?: (sourceFd: number, target: string) => void | Promise<void>;
  onImportPhase?: (phase: "after-receipt" | "after-backup" | "after-pending" | "after-replace" | "after-pending-cleanup" | "after-rollback-pending" | "after-rollback-replace" | "after-finalize-pending") => void | Promise<void>;
  afterImportNoReplaceLink?: (paths: { temp: string; target: string }) => void | Promise<void>;
  beforeImportTargetRecheck?: (operation: "rollback" | "finalize") => void | Promise<void>;
};

const CAPABILITY_WORKER_WATCHDOG_SCRIPT = String.raw`
const [nonce, targetPidText, targetIdentity, supervisorPidText, supervisorIdentity, parentPidText, parentIdentity, mode = "normal"] = process.argv.slice(1);
if (!nonce || !targetIdentity || !supervisorIdentity || !parentIdentity) throw new Error("missing watchdog identity arguments");
const targetPid = Number(targetPidText), supervisorPid = Number(supervisorPidText), parentPid = Number(parentPidText);
const { execFile } = await import("node:child_process");
const { promisify } = await import("node:util");
const { createHash } = await import("node:crypto");
const execFileAsync = promisify(execFile);
const rawIdentity = async (pid) => {
  try {
    const { stdout } = await execFileAsync("ps", ["-o", "lstart=", "-p", String(pid)]);
    const value = stdout.trim();
    return value ? createHash("sha256").update(value).digest("hex") : undefined;
  } catch { return undefined; }
};
let identityAttempts = 0;
const identity = async (pid) => {
  identityAttempts++;
  if (mode === "identity-permanent") return undefined;
  if (mode === "identity-transient" && identityAttempts <= 6) return undefined;
  return rawIdentity(pid);
};
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch (error) { return error?.code === "EPERM"; } };
if (mode === "early-exit") process.exit(23);
if (mode === "error-only") {
  await new Promise((resolve) => process.stdout.write(JSON.stringify({ watchdogFailure: true, nonce, code: "EAGAIN", message: "injected watchdog error" }) + "\n", resolve));
  process.exit(126);
}
if (mode === "ready-timeout") await new Promise(() => {});
const ownIdentity = await rawIdentity(process.pid);
if (!ownIdentity) {
  // 不能证明自身 PID/start identity 时不得谎报 ready；保持存活，让 worker 的 readiness deadline fail closed。
  await new Promise(() => {});
}
const readyNonce = mode === "wrong-nonce" ? nonce + "-wrong" : nonce;
const readyTargetIdentity = mode === "wrong-identity" ? targetIdentity + "-wrong" : targetIdentity;
await new Promise((resolve, reject) => process.stdout.write(JSON.stringify({
  version: 1,
  nonce: readyNonce,
  watchdogPid: process.pid,
  watchdogStartIdentity: ownIdentity,
  targetPid,
  targetIdentity: readyTargetIdentity,
  supervisorPid,
  supervisorIdentity,
  parentPid,
  parentIdentity,
}) + "\n", (error) => error ? reject(error) : resolve()));
let executorPid;
let executorIdentity;
let normalShutdown = false;
let armed = false;
let resolveArmed;
const armedPromise = new Promise((resolve) => { resolveArmed = resolve; });
let stopPromise;
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const terminateVerified = async (pid, expectedIdentity, allowDirectParent = false) => {
  let backoffMs = 10;
  while (alive(pid)) {
    const current = await rawIdentity(pid);
    const directParent = allowDirectParent && process.ppid === pid;
    if (current !== undefined && current !== expectedIdentity && !directParent) return;
    if (current === expectedIdentity || directParent) {
      try { process.kill(pid, "SIGKILL"); } catch {}
    }
    // identity 暂时未知时不能把可能仍在 native busy-loop 的 owner 当作已死亡；保持 watchdog 存活并重试。
    await delay(backoffMs);
    backoffMs = Math.min(250, backoffMs * 2);
  }
};
const killOwned = async () => {
  // 先终止直接父 worker：executor 的 IPC death channel 会立即终止其同步 worker thread；随后再用 identity 复核兜底。
  await terminateVerified(targetPid, targetIdentity, true);
  if (executorPid && executorIdentity) await terminateVerified(executorPid, executorIdentity);
};
const stopOwned = () => {
  if (!stopPromise) stopPromise = killOwned().finally(() => process.exit(137));
  return stopPromise;
};
const injectPostReadyFailure = () => {
  setTimeout(() => {
    if (mode === "post-ready-exit") process.exit(31);
    if (mode === "post-ready-error") { process.stderr.write("injected post-ready watchdog error\n", () => process.exit(32)); return; }
    if (mode === "post-ready-close") { if (process.connected) process.disconnect(); return; }
    if (mode === "post-ready-sigterm") process.kill(process.pid, "SIGTERM");
    if (mode === "post-ready-sigkill") process.kill(process.pid, "SIGKILL");
  }, 20);
};
process.on("disconnect", () => { if (!normalShutdown) void stopOwned(); });
process.on("SIGTERM", () => { if (!normalShutdown) void stopOwned(); });
process.on("SIGINT", () => { if (!normalShutdown) void stopOwned(); });
process.on("message", (message) => {
  if (message?.nonce !== nonce) return;
  if (message?.type === "register-executor" && typeof message?.executorPid === "number" && typeof message?.executorIdentity === "string") {
    if (executorPid !== undefined && (executorPid !== message.executorPid || executorIdentity !== message.executorIdentity)) { void stopOwned(); return; }
    executorPid = message.executorPid;
    executorIdentity = message.executorIdentity;
    if (process.connected) process.send({ type: "executor-registered", nonce, executorPid, executorIdentity });
    return;
  }
  if (message?.type === "arm") {
    if (armed || executorPid === undefined || executorIdentity === undefined) { void stopOwned(); return; }
    armed = true;
    resolveArmed(true);
    if (process.connected) process.send({ type: "armed", nonce });
    injectPostReadyFailure();
    return;
  }
  if (message?.type === "shutdown") {
    void (async () => {
      if (executorPid && alive(executorPid)) { await stopOwned(); return; }
      normalShutdown = true;
      if (process.connected) process.send({ type: "shutdown-ack", nonce });
      process.exit(0);
    })();
  }
});
if (!await Promise.race([armedPromise, delay(1_000).then(() => false)])) await stopOwned();
let backoffMs = 25;
while (!normalShutdown) {
  if (!alive(targetPid)) { await stopOwned(); break; }
  const targetCurrent = await identity(targetPid);
  if (targetCurrent !== undefined && targetCurrent !== targetIdentity) { await stopOwned(); break; }
  const supervisorAlive = alive(supervisorPid);
  const parentAlive = alive(parentPid);
  const supervisorCurrent = supervisorAlive ? await identity(supervisorPid) : undefined;
  const parentCurrent = parentAlive ? await identity(parentPid) : undefined;
  const ownerVerifiedDeadOrReused = !supervisorAlive || !parentAlive
    || (supervisorCurrent !== undefined && supervisorCurrent !== supervisorIdentity)
    || (parentCurrent !== undefined && parentCurrent !== parentIdentity);
  // process.ppid 是内核绑定的直接父子关系：identity 查询未知时仍可安全识别原 worker；一旦 PID 被复用 watchdog 已被 reparent，不会误杀。
  const targetStillOwnParent = process.ppid === targetPid;
  if (ownerVerifiedDeadOrReused && (targetCurrent === targetIdentity || targetStillOwnParent)) {
    await stopOwned();
    break;
  }
  // 任一 identity unknown 时继续监护而不是退出；有界指数退避限制 ps/resource 压力。
  await delay(backoffMs);
  backoffMs = Math.min(250, backoffMs * 2);
}
`;

const CAPABILITY_EXECUTOR_SCRIPT = String.raw`
const [probeDir, mode = "native", nonce = "", nativeStartedPath = "", workDelayText = "0"] = process.argv.slice(1);
if (!probeDir || !nonce || !process.connected) throw new Error("missing executor lifecycle channel");
await new Promise((resolve, reject) => {
  const timeout = setTimeout(() => reject(new Error("executor start attestation timeout")), 1_000);
  process.once("disconnect", () => { clearTimeout(timeout); reject(new Error("executor owner disconnected before start")); });
  process.once("message", (message) => {
    clearTimeout(timeout);
    if (message?.type !== "start" || message?.nonce !== nonce) reject(new Error("executor start attestation invalid"));
    else resolve();
  });
});
const fs = await import("node:fs/promises");
const workDelayMs = Number(workDelayText);
if (Number.isFinite(workDelayMs) && workDelayMs > 0) await new Promise((resolve) => setTimeout(resolve, workDelayMs));
if (nativeStartedPath) await fs.writeFile(nativeStartedPath, "native-started\n" + probeDir + "\n", "utf8");
const { Worker } = await import("node:worker_threads");
const taskScript = ${JSON.stringify(String.raw`
const { parentPort, workerData } = require("node:worker_threads");
(async () => {
  const { probeDir, mode } = workerData;
  const source = probeDir + "/source";
  const target = probeDir + "/target";
  const fs = await import("node:fs/promises");
  if (mode === "sync-block") { while (true) {} }
  if (mode === "async-pending") await new Promise(() => {});
  if (mode === "late-success" || mode === "late-reject") {
    await new Promise((resolve) => setTimeout(resolve, 250));
    if (mode === "late-reject") throw new Error("late reject");
  } else if (mode === "unsupported" || mode === "unsupported-native") {
    parentPort.postMessage({ type: "result", value: mode === "unsupported" ? { code: "ENOTSUP", errno: 45 } : { errno: 45 }, exitCode: 2 });
    return;
  } else {
    const constants = (await import("node:fs")).constants;
    const handle = await fs.open(source, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const ffi = await import("bun:ffi");
      const library = process.platform === "darwin" ? "libSystem.B.dylib" : "libc.so.6";
      const libc = process.platform === "darwin"
        ? ffi.dlopen(library, { fclonefileat: { args: ["i32", "i32", "cstring", "u32"], returns: "i32" }, __error: { args: [], returns: "ptr" } })
        : ffi.dlopen(library, { linkat: { args: ["i32", "cstring", "i32", "cstring", "i32"], returns: "i32" }, __errno_location: { args: [], returns: "ptr" } });
      const errnoLocation = process.platform === "darwin" ? libc.symbols.__error : libc.symbols.__errno_location;
      const result = process.platform === "darwin"
        ? Number(libc.symbols.fclonefileat(handle.fd, -2, Buffer.from(target + "\0"), 0))
        : Number(libc.symbols.linkat(-2, Buffer.from("/proc/self/fd/" + handle.fd + "\0"), -2, Buffer.from(target + "\0"), 0x400));
      if (result !== 0) {
        const pointer = errnoLocation();
        const errno = pointer === null ? -1 : ffi.toBuffer(pointer, 0, 4).readInt32LE(0);
        parentPort.postMessage({ type: "result", value: { errno }, exitCode: 2 });
      }
    } finally { await handle.close(); }
  }
  parentPort.postMessage({ type: "done" });
})().catch((error) => { throw error; });
`)};
const task = new Worker(taskScript, { eval: true, workerData: { probeDir, mode } });
let stopping = false;
let result;
const stop = (code) => {
  if (stopping) return;
  stopping = true;
  void task.terminate().catch(() => undefined).finally(() => process.exit(code));
};
// executor 主线程始终保持可调度；owner IPC 消失时可终止同步阻塞的 native worker thread。
process.on("disconnect", () => stop(137));
process.on("SIGTERM", () => stop(137));
process.on("SIGINT", () => stop(137));
task.on("message", (message) => { if (message?.type === "result") result = message; });
task.once("error", (error) => {
  if (stopping) return;
  stopping = true;
  process.stderr.write(String(error?.message ?? error) + "\n", () => process.exit(1));
});
task.once("exit", (code) => {
  if (stopping) return;
  stopping = true;
  const exitCode = result?.exitCode ?? code;
  if (result?.value !== undefined) process.stdout.write(JSON.stringify(result.value) + "\n", () => process.exit(exitCode));
  else process.exit(exitCode);
});
`;

const CAPABILITY_WORKER_SCRIPT = String.raw`
const [probeDir, mode = "native", supervisorPidText = "", supervisorIdentity = "", parentPidText = "", parentIdentity = "", nonce = "", watchdogScriptBase64 = "", executorScriptBase64 = "", runtimeExecutable = "", watchdogExecutable = "", watchdogMode = "normal", nativeStartedPath = "", workDelayText = "0"] = process.argv.slice(1);
if (!probeDir || !supervisorPidText || !supervisorIdentity || !parentPidText || !parentIdentity || !nonce || !watchdogScriptBase64 || !executorScriptBase64 || !runtimeExecutable || !watchdogExecutable) throw new Error("missing worker lifecycle arguments");
const { spawn, execFile } = await import("node:child_process");
const { promisify } = await import("node:util");
const { createHash } = await import("node:crypto");
const execFileAsync = promisify(execFile);
const supervisorPid = Number(supervisorPidText);
const parentPid = Number(parentPidText);
const processIdentity = async (pid) => {
  const { stdout } = await execFileAsync("ps", ["-o", "lstart=", "-p", String(pid)]);
  const value = stdout.trim();
  if (!value) throw new Error("process start identity unavailable");
  return createHash("sha256").update(value).digest("hex");
};
const targetIdentity = await processIdentity(process.pid);
const watchdogScript = Buffer.from(watchdogScriptBase64, "base64").toString("utf8");
const executorScript = Buffer.from(executorScriptBase64, "base64").toString("utf8");
const failWorker = async (code, message) => {
  await new Promise((resolve) => process.stdout.write(JSON.stringify({ workerFailure: true, nonce, code, message }) + "\n", resolve));
  process.exit(126);
};
if (watchdogMode === "spawn-eagain" || watchdogMode === "spawn-emfile") await failWorker(watchdogMode === "spawn-eagain" ? "EAGAIN" : "EMFILE", "injected watchdog spawn failure");
const watchdog = spawn(watchdogExecutable, ["-e", watchdogScript, nonce, String(process.pid), targetIdentity, String(supervisorPid), supervisorIdentity, String(parentPid), parentIdentity, watchdogMode], { stdio: ["ignore", "pipe", "ignore", "ipc"] });
let watchdogOutput = "";
let resolveWatchdogReady;
const watchdogReady = new Promise((resolve) => { resolveWatchdogReady = resolve; });
watchdog.stdout?.setEncoding("utf8");
watchdog.stdout?.on("data", (chunk) => {
  watchdogOutput += chunk;
  const line = watchdogOutput.split("\n").find(Boolean);
  if (!line) return;
  try {
    const parsed = JSON.parse(line);
    if (parsed?.watchdogFailure === true && parsed?.nonce === nonce) resolveWatchdogReady({ type: "failure", value: parsed });
    else resolveWatchdogReady({ type: "ready", value: parsed });
  }
  catch (error) { resolveWatchdogReady({ type: "malformed", error }); }
});
const watchdogStart = new Promise((resolve) => {
  let settled = false;
  const finish = (value) => { if (!settled) { settled = true; resolve(value); } };
  watchdog.once("spawn", () => finish({ spawned: true }));
  watchdog.once("error", (error) => finish({ spawned: false, error }));
});
let normalShutdown = false;
const watchdogDeath = new Promise((resolve) => {
  const finish = (type, detail) => { if (!normalShutdown) resolve({ type, ...detail }); };
  watchdog.once("error", (error) => finish("error", { error }));
  watchdog.once("exit", (code, signal) => finish("exit", { code, signal }));
  watchdog.once("close", (code, signal) => finish("close", { code, signal }));
  watchdog.once("disconnect", () => finish("disconnect", {}));
  watchdog.stdout?.once("close", () => finish("channel-close", {}));
});
const started = await watchdogStart;
if (!started.spawned) await failWorker(started.error?.code ?? "ECHILD", started.error?.message ?? "watchdog spawn 失败");
const ready = await Promise.race([watchdogReady, watchdogDeath, new Promise((resolve) => setTimeout(() => resolve({ type: "timeout" }), 250))]);
if (ready.type !== "ready") {
  try { watchdog.kill("SIGKILL"); } catch {}
  await failWorker(ready.value?.code ?? ready.error?.code ?? (ready.type === "timeout" ? "ETIMEDOUT" : "ECHILD"), ready.value?.message ?? ("watchdog readiness 失败（" + ready.type + "）"));
}
const attestation = ready.value;
if (attestation.version !== 1 || attestation.nonce !== nonce || typeof attestation.watchdogPid !== "number" || typeof attestation.watchdogStartIdentity !== "string" || attestation.targetPid !== process.pid || attestation.targetIdentity !== targetIdentity || attestation.supervisorPid !== supervisorPid || attestation.supervisorIdentity !== supervisorIdentity || attestation.parentPid !== parentPid || attestation.parentIdentity !== parentIdentity) {
  try { watchdog.kill("SIGKILL"); } catch {}
  throw new Error("watchdog readiness attestation 不匹配");
}
// 保留 stdout/death 监听贯穿整个 executor 生命周期；任何 watchdog 消失都先杀 executor，再向 supervisor fail closed。
const executor = spawn(runtimeExecutable, ["-e", executorScript, probeDir, mode, nonce, nativeStartedPath, workDelayText], { stdio: ["ignore", "pipe", "ignore", "ipc"] });
let executorOutput = "";
executor.stdout?.setEncoding("utf8");
executor.stdout?.on("data", (chunk) => { executorOutput += chunk; });
const executorDone = new Promise((resolve) => {
  executor.once("error", (error) => resolve({ type: "executor-error", error }));
  executor.once("close", (code, signal) => resolve({ type: "executor-close", code, signal }));
});
const executorSpawned = await new Promise((resolve) => {
  let settled = false;
  const finish = (value) => { if (!settled) { settled = true; resolve(value); } };
  executor.once("spawn", () => finish({ ok: true }));
  executor.once("error", (error) => finish({ ok: false, error }));
});
if (!executorSpawned.ok) throw executorSpawned.error;
const executorIdentity = await processIdentity(executor.pid);
const registered = new Promise((resolve) => {
  watchdog.on("message", (message) => {
    if (message?.type === "executor-registered" && message?.nonce === nonce && message?.executorPid === executor.pid && message?.executorIdentity === executorIdentity) resolve(true);
  });
});
watchdog.send({ type: "register-executor", nonce, executorPid: executor.pid, executorIdentity });
if (!await Promise.race([registered, watchdogDeath.then(() => false), new Promise((resolve) => setTimeout(() => resolve(false), 250))])) {
  try { executor.kill("SIGKILL"); } catch {}
  throw new Error("watchdog executor registration 失败");
}
const armed = new Promise((resolve) => watchdog.on("message", (message) => { if (message?.type === "armed" && message?.nonce === nonce) resolve(true); }));
watchdog.send({ type: "arm", nonce });
if (!await Promise.race([armed, watchdogDeath.then(() => false), new Promise((resolve) => setTimeout(() => resolve(false), 250))])) {
  try { executor.kill("SIGKILL"); } catch {}
  throw new Error("watchdog continuous ownership arm 失败");
}
await new Promise((resolve, reject) => process.stdout.write(JSON.stringify({ workerReady: true, nonce, executorPid: executor.pid, executorIdentity, watchdogPid: attestation.watchdogPid, watchdogStartIdentity: attestation.watchdogStartIdentity }) + "\n", (error) => error ? reject(error) : resolve()));
executor.send({ type: "start", nonce });
const processAlive = (pid) => { try { process.kill(pid, 0); return true; } catch (error) { return error?.code === "EPERM"; } };
const terminateExecutor = async () => {
  let backoffMs = 10;
  while (processAlive(executor.pid)) {
    const current = await processIdentity(executor.pid).catch(() => undefined);
    if (current !== undefined && current !== executorIdentity) throw new Error("executor PID 已复用，拒绝误杀");
    if (current === executorIdentity) try { executor.kill("SIGKILL"); } catch {}
    await new Promise((resolve) => setTimeout(resolve, backoffMs));
    backoffMs = Math.min(250, backoffMs * 2);
  }
};
const outcome = await Promise.race([executorDone, watchdogDeath]);
if (outcome.type !== "executor-close") {
  await terminateExecutor();
  process.stdout.write(JSON.stringify({ watchdogRuntimeFailure: outcome.type }) + "\n");
  process.exit(24);
}
if (processAlive(executor.pid)) await terminateExecutor();
const watchdogClosed = new Promise((resolve) => watchdog.once("close", resolve));
const shutdownAck = new Promise((resolve) => watchdog.on("message", (message) => { if (message?.type === "shutdown-ack" && message?.nonce === nonce) resolve(true); }));
if (watchdog.connected) watchdog.send({ type: "shutdown", nonce });
const shutdown = await Promise.race([shutdownAck, watchdogDeath.then(() => false), new Promise((resolve) => setTimeout(() => resolve(false), 250))]);
if (shutdown !== true) { try { watchdog.kill("SIGKILL"); } catch {} }
normalShutdown = true;
await Promise.race([watchdogClosed, new Promise((resolve) => setTimeout(resolve, 250))]);
if (executorOutput) await new Promise((resolve) => process.stdout.write(executorOutput, resolve));
if (outcome.signal) process.kill(process.pid, outcome.signal);
else process.exit(outcome.code ?? 1);
`;

const CAPABILITY_SUPERVISOR_SCRIPT = String.raw`
const [probeDir, mode = "native", readyPath = "", parentPidText = "", parentIdentity = "", nonce = "", workerScriptBase64 = "", workerWatchdogScriptBase64 = "", executorScriptBase64 = "", supervisorReadyPath = "", startupDelayText = "0", runtimeExecutable = "", watchdogExecutable = "", watchdogMode = "normal", nativeStartedPath = "", workDelayText = "0"] = process.argv.slice(1);
if (!probeDir || !parentPidText || !parentIdentity || !nonce || !workerScriptBase64 || !workerWatchdogScriptBase64 || !executorScriptBase64 || !runtimeExecutable || !watchdogExecutable) throw new Error("missing supervisor arguments");
const startupDelayMs = Number(startupDelayText);
const parentPid = Number(parentPidText);
const { spawn, execFile } = await import("node:child_process");
const { promisify } = await import("node:util");
const { createHash } = await import("node:crypto");
const fs = await import("node:fs/promises");
const execFileAsync = promisify(execFile);
const identity = async (pid) => {
  try {
    const { stdout } = await execFileAsync("ps", ["-o", "lstart=", "-p", String(pid)]);
    const value = stdout.trim();
    return value ? createHash("sha256").update(value).digest("hex") : undefined;
  } catch { return undefined; }
};
const workerScript = Buffer.from(workerScriptBase64, "base64").toString("utf8");
let worker;
let startupState = "checking";
let finishing = false;
let watchdog;
let stopPromise;
const processIsAlive = (pid) => {
  try { process.kill(pid, 0); return true; }
  catch (error) { return error?.code === "EPERM"; }
};
const waitForDeath = async (pid, timeoutMs) => {
  const deadline = Date.now() + timeoutMs;
  do {
    if (!processIsAlive(pid)) return true;
    await new Promise((resolve) => setTimeout(resolve, 10));
  } while (Date.now() < deadline);
  return !processIsAlive(pid);
};
const cleanupProbe = async () => {
  for (const name of ["target", "source", "lifecycle.json"]) {
    try { await fs.unlink(probeDir + "/" + name); }
    catch (error) { if (error?.code !== "ENOENT") throw error; }
  }
  try { await fs.rmdir(probeDir); }
  catch (error) { if (error?.code !== "ENOENT") throw error; }
};
const stopTree = () => {
  if (stopPromise) return stopPromise;
  startupState = "stopping";
  stopPromise = (async () => {
    if (watchdog) clearInterval(watchdog);
    let lifecycle;
    try { lifecycle = JSON.parse(await fs.readFile(probeDir + "/lifecycle.json", "utf8")); } catch {}
    const terminateRecorded = async (pid, expectedIdentity) => {
      if (!Number.isInteger(pid) || pid <= 0 || typeof expectedIdentity !== "string") return;
      while (processIsAlive(pid)) {
        const current = await identity(pid);
        if (current !== undefined && current !== expectedIdentity) return;
        if (current === expectedIdentity) try { process.kill(pid, "SIGKILL"); } catch {}
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
    };
    await terminateRecorded(lifecycle?.executorPid, lifecycle?.executorStartIdentity);
    await terminateRecorded(lifecycle?.watchdogPid, lifecycle?.watchdogStartIdentity);
    const pid = worker?.pid;
    if (pid && processIsAlive(pid)) {
      try { worker.kill("SIGKILL"); } catch {}
      // supervisor 必须保持存活直到 worker 真正消失；父进程可 kill supervisor，但不得产生无 watchdog 的 orphan worker。
      while (!await waitForDeath(pid, 100)) {
        try { process.kill(pid, "SIGKILL"); } catch {}
      }
    }
    try { await cleanupProbe(); } catch {}
    startupState = "stopped";
    if (process.connected) process.disconnect();
    process.exit(137);
  })();
  return stopPromise;
};
const requestStop = () => { void stopTree(); };
process.on("disconnect", () => { if (!finishing) requestStop(); });
process.on("SIGTERM", requestStop);
process.on("SIGINT", requestStop);
const parentIsAlive = () => processIsAlive(parentPid);
const parentMatches = async () => {
  if (!process.connected || !parentIsAlive()) return false;
  const current = await identity(parentPid);
  // identity unknown 不能证明仍是原父进程，启动阶段必须 fail closed。
  return current !== undefined && current === parentIdentity && process.connected && parentIsAlive();
};
const stopBeforeWorker = async () => {
  await stopTree();
  await new Promise(() => {});
};
if (supervisorReadyPath) await fs.writeFile(supervisorReadyPath, "supervisor-started\n" + probeDir + "\n" + process.pid + "\n", "utf8");
if (Number.isFinite(startupDelayMs) && startupDelayMs > 0) await new Promise((resolve) => setTimeout(resolve, startupDelayMs));
if (startupState === "stopping" || startupState === "stopped" || !await parentMatches()) await stopBeforeWorker();
// 单线程同步门：设置 spawning 后到 spawn 返回及监听器安装之间没有 await，stop 事件只能在 worker 已登记后执行。
startupState = "spawning";
const supervisorIdentityForWorker = await identity(process.pid);
if (!supervisorIdentityForWorker || !await parentMatches()) await stopBeforeWorker();
worker = spawn(runtimeExecutable, ["-e", workerScript, probeDir, mode, String(process.pid), supervisorIdentityForWorker, String(parentPid), parentIdentity, nonce, workerWatchdogScriptBase64, executorScriptBase64, runtimeExecutable, watchdogExecutable, watchdogMode, nativeStartedPath, workDelayText], { stdio: ["ignore", "pipe", "ignore"] });
const startResultPromise = new Promise((resolve) => {
  let settled = false;
  const finish = (value) => { if (!settled) { settled = true; resolve(value); } };
  worker.once("spawn", () => finish({ ok: true }));
  worker.once("error", (error) => finish({ ok: false, error }));
});
let terminalSettled = false;
let resolveWorkerTerminal;
const workerTerminal = new Promise((resolve) => { resolveWorkerTerminal = resolve; });
const finishWorkerTerminal = (value) => { if (!terminalSettled) { terminalSettled = true; resolveWorkerTerminal(value); } };
worker.once("error", (error) => finishWorkerTerminal({ type: "error", error }));
worker.once("exit", (code, signal) => {
  const timer = setTimeout(() => finishWorkerTerminal({ type: "exit", code, signal }), 50);
  timer.unref();
});
worker.once("close", (code, signal) => finishWorkerTerminal({ type: "close", code, signal }));
let output = "";
let lineBuffer = "";
let resolveWorkerReady;
const workerReadyPromise = new Promise((resolve) => { resolveWorkerReady = resolve; });
let resolveWorkerFailure;
const workerFailurePromise = new Promise((resolve) => { resolveWorkerFailure = resolve; });
worker.stdout?.setEncoding("utf8");
worker.stdout?.on("data", (chunk) => {
  output += chunk;
  lineBuffer += chunk;
  while (lineBuffer.includes("\n")) {
    const newline = lineBuffer.indexOf("\n");
    const line = lineBuffer.slice(0, newline);
    lineBuffer = lineBuffer.slice(newline + 1);
    if (!line) continue;
    try {
      const parsed = JSON.parse(line);
      if (parsed?.workerFailure === true && parsed?.nonce === nonce) resolveWorkerFailure({ type: "failure", value: parsed });
      if (parsed?.workerReady === true) resolveWorkerReady({ type: "ready", value: parsed });
    } catch { /* worker 失败输出由 terminal 处理 */ }
  }
  if (output.length > 65536) requestStop();
});
if (startupState === "stopping" || startupState === "stopped" || !await parentMatches()) await stopBeforeWorker();
startupState = "running";
const startResult = await startResultPromise;
if (!startResult.ok) {
  finishing = true;
  await new Promise((resolve) => process.stdout.write(JSON.stringify({ spawnError: startResult.error?.code ?? "ECHILD" }) + "\n", resolve));
  if (process.connected) process.disconnect();
  process.exit(126);
}
let workerIdentity;
for (let attempt = 0; attempt < 20 && workerIdentity === undefined; attempt++) {
  workerIdentity = await identity(worker.pid);
  if (workerIdentity === undefined) await new Promise((resolve) => setTimeout(resolve, 5));
}
if (!workerIdentity) await stopBeforeWorker();
const supervisorIdentity = await identity(process.pid);
if (!supervisorIdentity) await stopBeforeWorker();
const workerReadiness = await Promise.race([
  workerReadyPromise,
  workerFailurePromise,
  workerTerminal.then((terminal) => ({ type: "terminal", terminal })),
  new Promise((resolve) => setTimeout(() => resolve({ type: "timeout" }), 1_000)),
]);
if (workerReadiness.type === "failure") {
  finishing = true;
  await new Promise((resolve) => process.stdout.write(JSON.stringify({ workerFailure: true, nonce, code: workerReadiness.value.code ?? "ECHILD", message: workerReadiness.value.message }) + "\n", resolve));
  if (process.connected) process.disconnect();
  process.exit(126);
}
if (workerReadiness.type !== "ready") await stopBeforeWorker();
const workerAttestation = workerReadiness.value;
if (workerAttestation.nonce !== nonce || typeof workerAttestation.executorPid !== "number" || !Number.isInteger(workerAttestation.executorPid) || workerAttestation.executorPid <= 0 || typeof workerAttestation.executorIdentity !== "string" || typeof workerAttestation.watchdogPid !== "number" || !Number.isInteger(workerAttestation.watchdogPid) || workerAttestation.watchdogPid <= 0 || typeof workerAttestation.watchdogStartIdentity !== "string") await stopBeforeWorker();
const [executorCurrent, watchdogCurrent] = await Promise.all([identity(workerAttestation.executorPid), identity(workerAttestation.watchdogPid)]);
if (executorCurrent !== workerAttestation.executorIdentity || watchdogCurrent !== workerAttestation.watchdogStartIdentity) await stopBeforeWorker();
const lifecyclePath = probeDir + "/lifecycle.json";
const lifecycle = await fs.open(lifecyclePath, "wx", 0o600);
try {
  await lifecycle.writeFile(JSON.stringify({ version: 1, nonce, supervisorPid: process.pid, supervisorStartIdentity: supervisorIdentity, workerPid: worker.pid, workerStartIdentity: workerIdentity, watchdogPid: workerAttestation.watchdogPid, watchdogStartIdentity: workerAttestation.watchdogStartIdentity, executorPid: workerAttestation.executorPid, executorStartIdentity: workerAttestation.executorIdentity }) + "\n", "utf8");
  await lifecycle.chmod(0o600);
  await lifecycle.sync();
} finally { await lifecycle.close(); }
const probeHandle = await fs.open(probeDir, "r");
try { await probeHandle.sync(); } finally { await probeHandle.close(); }
if (readyPath) await fs.writeFile(readyPath, "capability-started\n" + probeDir + "\n" + process.pid + "\n" + worker.pid + "\n" + workerAttestation.watchdogPid + "\n" + workerAttestation.executorPid + "\n", "utf8");
watchdog = setInterval(async () => {
  if (finishing || startupState === "stopping" || startupState === "stopped") return;
  if (!parentIsAlive()) { requestStop(); return; }
  const current = await identity(parentPid);
  if (current !== undefined && current !== parentIdentity) requestStop();
}, 50);
const terminal = await workerTerminal;
if (finishing || startupState === "stopping" || startupState === "stopped") await new Promise(() => {});
finishing = true;
clearInterval(watchdog);
if (terminal.type === "error") await new Promise((resolve) => process.stdout.write(JSON.stringify({ spawnError: terminal.error?.code ?? "ECHILD" }) + "\n", resolve));
else {
  if (output) await new Promise((resolve) => process.stdout.write(output, resolve));
  if (terminal.type === "close" && terminal.code === 0 && terminal.signal === null) await new Promise((resolve) => process.stdout.write(JSON.stringify({ ok: true, nonce }) + "\n", resolve));
}
if (process.connected) process.disconnect();
if (terminal.signal) process.kill(process.pid, terminal.signal);
else process.exit(terminal.code ?? 1);
`;


let publishFdExclusivePromise: Promise<(sourceFd: number, target: string) => void> | undefined;
async function publishFdExclusive(sourceFd: number, target: string): Promise<void> {
  if (!publishFdExclusivePromise) publishFdExclusivePromise = (async () => {
    // 避免把 Bun 专属 FFI 类型泄漏到通用 tsc；运行时只加载系统 libc 的 fd-bound create API。
    const ffi = await (new Function("specifier", "return import(specifier)"))("bun:ffi") as {
      dlopen(name: string, symbols: Record<string, { args: string[]; returns: string }>): { symbols: Record<string, (...args: unknown[]) => unknown> };
      toBuffer(pointer: unknown, offset: number, length: number): Buffer;
    };
    const library = process.platform === "darwin" ? "libSystem.B.dylib" : "libc.so.6";
    const libc = process.platform === "darwin"
      ? ffi.dlopen(library, {
          fclonefileat: { args: ["i32", "i32", "cstring", "u32"], returns: "i32" },
          __error: { args: [], returns: "ptr" },
        })
      : ffi.dlopen(library, {
          linkat: { args: ["i32", "cstring", "i32", "cstring", "i32"], returns: "i32" },
          __errno_location: { args: [], returns: "ptr" },
        });
    const errnoLocation = process.platform === "darwin" ? libc.symbols.__error! : libc.symbols.__errno_location!;
    return (fd: number, to: string): void => {
      const result = process.platform === "darwin"
        ? Number(libc.symbols.fclonefileat!(fd, -2, Buffer.from(`${to}\0`), 0))
        // /proc/self/fd/N 是不可由目录攻击者替换的 fd 视图；AT_SYMLINK_FOLLOW 创建普通 hard link，普通用户无需 AT_EMPTY_PATH capability。
        : Number(libc.symbols.linkat!(-2, Buffer.from(`/proc/self/fd/${fd}\0`), -2, Buffer.from(`${to}\0`), 0x400));
      if (result === 0) return;
      const errnoPointer = errnoLocation();
      const errno = errnoPointer === null ? -1 : ffi.toBuffer(errnoPointer, 0, 4).readInt32LE(0);
      const code = errno === 17 ? "EEXIST"
        : errno === 2 ? "ENOENT"
          : errno === 18 ? "EXDEV"
            : errno === 45 || errno === 95 ? "ENOTSUP"
              : `ERRNO_${errno}`;
      throw Object.assign(new Error(`fd-bound no-replace publish 失败（${code}）`), { code, errno });
    };
  })();
  (await publishFdExclusivePromise)(sourceFd, target);
}

// 安全 config store：目录 0700、文件 0600、原子写、拒绝符号链接。
export function createConfigStore(machineId: string, env: Record<string, string | undefined>, dependencies: ConfigStoreDependencies = {}): CredentialStore {
  if (!machineId) throw new Error("machine ID 不得为空");
  const machineIdHash = sha256(machineId);
  const configDir = resolveConfigDir(env);
  const configPath = join(configDir, CONFIG_FILE);
  const machineIdPath = join(configDir, "machine_id");
  const rotationPath = join(configDir, ROTATION_FILE);
  const emergencyRotationPath = join(configDir, EMERGENCY_ROTATION_FILE);
  const rotationReservationPath = join(configDir, ROTATION_RESERVATION_FILE);
  const importPendingPath = join(configDir, IMPORT_PENDING_FILE);
  const mutationLockPath = join(configDir, ".auth-cn.rotation.mutation.lock");
  const guardConfigDir = async (allowMissing: boolean): Promise<boolean> => {
    try {
      const dirStat = await lstat(configDir);
      if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) throw new Error("config 目录必须是真实目录，不能是符号链接");
      if (typeof dirStat.uid === "number" && typeof process.getuid === "function" && dirStat.uid !== process.getuid()) throw new Error("config 目录所有者不是当前用户");
      if ((dirStat.mode & 0o077) !== 0) throw new Error("config 目录权限必须为 0700");
      return true;
    } catch (e) {
      if (allowMissing && (e as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw e;
    }
  };
  type ReservationRecord = { version: 1; owner: string; processId: number; processStartIdentity: string; baseCredentialHash: string; phase?: "capability" | "refresh-started" };
  type RotationRecord = { version: 1; owner: string; artifactId?: string; sourceArtifactId?: string; baseCredentialHash: string; targetCredentialHash: string; credential: StoredCredential };
  type ImportRecord = {
    version: 1;
    backupId: string;
    previousPresent: boolean;
    previousHash?: string;
    machinePreviousPresent: boolean;
    machinePreviousHash?: string;
    targetHash: string;
    targetMachineHash?: string;
    action?: "apply" | "rollback-cleanup" | "finalize-cleanup";
  };
  const credentialHash = (credential: StoredCredential): string => sha256(JSON.stringify([
    credential.version,
    credential.site,
    credential.machineIdHash,
    credential.token,
    credential.refreshToken ?? null,
    credential.expiresAt ?? null,
    credential.refreshTokenExpiresAt ?? null,
    credential.userId ?? null,
    credential.userName ?? null,
  ]));
  const readReservation = async (): Promise<ReservationRecord | undefined> => {
    if (!await guardConfigDir(true)) return undefined;
    try {
      const fileStat = await lstat(rotationReservationPath);
      if (fileStat.isSymbolicLink() || !fileStat.isFile()) throw new Error("rotation reservation 必须是普通文件，不能是符号链接");
      if ((fileStat.mode & 0o077) !== 0) throw new Error("rotation reservation 文件权限必须为 0600");
      const parsed = JSON.parse(await readFile(rotationReservationPath, "utf8")) as Record<string, unknown>;
      if (parsed.version !== 1 || typeof parsed.owner !== "string" || parsed.owner.length === 0 || typeof parsed.processId !== "number" || !Number.isInteger(parsed.processId) || parsed.processId <= 0 || typeof parsed.processStartIdentity !== "string" || parsed.processStartIdentity.length === 0 || typeof parsed.baseCredentialHash !== "string" || parsed.baseCredentialHash.length === 0 || (parsed.phase !== undefined && parsed.phase !== "capability" && parsed.phase !== "refresh-started")) throw new Error("rotation reservation 内容非法");
      return parsed as ReservationRecord;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw e;
    }
  };
  const requireReservationOwner = async (owner: RotationReservation): Promise<ReservationRecord> => {
    const reservation = await readReservation();
    if (!reservation) throw new Error("rotation reservation 不存在");
    if (reservation.owner !== owner) throw new Error("rotation reservation owner 不匹配");
    return reservation;
  };
  const isReservationOwnerActive = async (reservation: ReservationRecord): Promise<boolean> => {
    if (reservation.processId === process.pid) {
      if (!ACTIVE_ROTATION_OWNERS.has(reservation.owner)) return false;
      const identity = await processStartIdentity();
      return identity === undefined || identity === reservation.processStartIdentity;
    }
    return evaluateProcessOwnerActivity(
      reservation.processStartIdentity,
      () => {
        try { process.kill(reservation.processId, 0); return "live-or-unknown"; }
        catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM" ? "live-or-unknown" : "dead"; }
      },
      () => processStartIdentity(reservation.processId),
    );
  };
  const requireCurrentBase = async (reservation: ReservationRecord): Promise<StoredCredential> => {
    const current = await readCredential(configPath, "config 凭据路径");
    if (!current || credentialHash(current) !== reservation.baseCredentialHash) throw new Error("durable config 已变化，拒绝继续凭据轮换");
    return current;
  };
  const syncConfigDir = async (): Promise<void> => {
    await guardConfigDir(false);
    const handle = await open(configDir, fsConstants.O_RDONLY);
    try { await handle.sync(); } finally { await handle.close(); }
  };
  const writeReservationRecord = async (record: ReservationRecord): Promise<void> => {
    const tmp = join(configDir, `.${ROTATION_RESERVATION_FILE}.${process.pid}.${randomUUID()}.tmp`);
    const handle = await open(tmp, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    try {
      await handle.writeFile(`${JSON.stringify(record)}\n`, "utf8");
      await handle.chmod(0o600);
      await handle.sync();
    } finally { await handle.close(); }
    const current = await readReservation();
    if (!current || current.owner !== record.owner || current.baseCredentialHash !== record.baseCredentialHash) {
      await unlink(tmp).catch(() => undefined);
      throw new Error("rotation reservation 在阶段更新前发生变化");
    }
    await rename(tmp, rotationReservationPath);
    await chmod(rotationReservationPath, 0o600);
    await syncConfigDir();
  };
  const publishFromFd = async (sourceFd: number, target: string): Promise<void> => {
    if (dependencies.publishFdExclusive) await dependencies.publishFdExclusive(sourceFd, target);
    else await publishFdExclusive(sourceFd, target);
  };
  type CapabilityProcessResult = { code: number | null; signal: NodeJS.Signals | null };
  const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
  const isProcessAlive = (pid: number): boolean => {
    try { process.kill(pid, 0); return true; }
    catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM"; }
  };
  const waitForProcessDeath = async (pid: number, timeoutMs: number): Promise<boolean> => {
    const deadline = Date.now() + timeoutMs;
    do {
      if (!isProcessAlive(pid)) return true;
      await delay(10);
    } while (Date.now() < deadline);
    return !isProcessAlive(pid);
  };
  const isProcessGroupAlive = (leaderPid: number): boolean => {
    if (process.platform === "win32") return isProcessAlive(leaderPid);
    try { process.kill(-leaderPid, 0); return true; }
    catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM"; }
  };
  const waitForProcessGroupDeath = async (leaderPid: number, timeoutMs: number): Promise<boolean> => {
    const deadline = Date.now() + timeoutMs;
    do {
      if (!isProcessGroupAlive(leaderPid)) return true;
      await delay(10);
    } while (Date.now() < deadline);
    return !isProcessGroupAlive(leaderPid);
  };
  let fdPublicationCapability: Promise<void> | undefined;
  const ensureFdPublicationSupported = async (callerSignal?: AbortSignal): Promise<void> => {
    if (fdPublicationCapability) return callerSignal ? raceWithSignal(fdPublicationCapability, callerSignal) : fdPublicationCapability;
    const operation = (async (): Promise<void> => {
    const timeoutSignal = AbortSignal.timeout(capabilityTimeoutMs(env));
    const signal = callerSignal ? AbortSignal.any([callerSignal, timeoutSignal]) : timeoutSignal;
    signal.throwIfAborted();
    const id = randomUUID();
    const probeDir = join(configDir, `.rotation-fd-probe.${id}`);
    const sourcePath = join(probeDir, "source");
    const lifecyclePath = join(probeDir, "lifecycle.json");
    await mkdir(probeDir, { mode: 0o700 });
    const handle = await open(sourcePath, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    try {
      await handle.writeFile("probe\n", "utf8");
      await handle.chmod(0o600);
      await handle.sync();
    } finally { await handle.close(); }
    let childOutput = "";
    let child: ReturnType<typeof spawn> | undefined;
    let terminal: CapabilityProcessResult | Error | undefined;
    let resolveTerminal: ((value: CapabilityProcessResult | Error) => void) | undefined;
    const terminalPromise = new Promise<CapabilityProcessResult | Error>((resolve) => { resolveTerminal = resolve; });
    const settleTerminal = (value: CapabilityProcessResult | Error): void => {
      if (terminal !== undefined) return;
      terminal = value;
      resolveTerminal?.(value);
    };
    const terminateChildBounded = async (): Promise<void> => {
      if (!child) return;
      if (child.pid === undefined) {
        // spawn error-only 路径可能永远没有 exit/close；error 已终态，未到 error 也只等固定 grace。
        if (terminal === undefined) await Promise.race([terminalPromise, delay(100)]);
        return;
      }
      const supervisorPid = child.pid;
      let workerPid: number | undefined;
      try {
        const lifecycle = JSON.parse(await readFile(lifecyclePath, "utf8")) as Record<string, unknown>;
        if (lifecycle.version === 1 && lifecycle.nonce === id && typeof lifecycle.workerPid === "number" && Number.isInteger(lifecycle.workerPid) && lifecycle.workerPid > 0 && typeof lifecycle.workerStartIdentity === "string") {
          const actualIdentity = await processStartIdentity(lifecycle.workerPid);
          if (actualIdentity === lifecycle.workerStartIdentity) workerPid = lifecycle.workerPid;
        }
      } catch { /* supervisor 尚未发布 lifecycle 或已完成清理 */ }
      if (isProcessAlive(supervisorPid)) {
        try { child.kill("SIGTERM"); } catch { /* 继续按 PID 状态收敛 */ }
      }
      if (workerPid && isProcessAlive(workerPid)) {
        try { process.kill(workerPid, "SIGKILL"); } catch { /* supervisor 仍会持续 watchdog */ }
      }
      // supervisor 正常 watchdog 应先收敛；若期限内未完成，再杀整个独立进程组，不能只杀 supervisor 留下 orphan worker。
      if (!await waitForProcessDeath(supervisorPid, 750) || isProcessGroupAlive(supervisorPid)) {
        if (process.platform !== "win32") {
          try { process.kill(-supervisorPid, "SIGKILL"); } catch { /* 下方按进程组确认 */ }
        } else {
          try { child.kill("SIGKILL"); } catch { /* 下方确认 */ }
        }
      }
      if (!await waitForProcessGroupDeath(supervisorPid, 500)) throw new Error("fd capability 隔离进程组无法在期限内终止，保留 probe 证据并拒绝继续");
      if (workerPid && !await waitForProcessDeath(workerPid, 250)) throw new Error("fd capability worker 无法在期限内终止，保留 probe 证据并拒绝继续");
    };
    let safeToCleanup = false;
    try {
      signal.throwIfAborted();
      const mode = dependencies.capabilityProbeMode ?? "native";
      const executable = await requireBunExecutable(env, dependencies.capabilityExecutable);
      const watchdogExecutable = dependencies.capabilityWatchdogExecutable ?? executable;
      const parentIdentity = await processStartIdentity();
      if (!parentIdentity) throw new Error("无法取得 capability parent 启动身份");
      const spawnCapabilityProcess = dependencies.spawnCapabilityProcess ?? spawn;
      child = spawnCapabilityProcess(executable, ["-e", CAPABILITY_SUPERVISOR_SCRIPT, probeDir, mode, dependencies.capabilityProbeReadyPath ?? "", String(process.pid), parentIdentity, id, Buffer.from(CAPABILITY_WORKER_SCRIPT).toString("base64"), Buffer.from(CAPABILITY_WORKER_WATCHDOG_SCRIPT).toString("base64"), Buffer.from(CAPABILITY_EXECUTOR_SCRIPT).toString("base64"), dependencies.capabilitySupervisorReadyPath ?? "", String(dependencies.capabilitySupervisorStartupDelayMs ?? 0), executable, watchdogExecutable, dependencies.capabilityWatchdogMode ?? "normal", dependencies.capabilityNativeStartedPath ?? "", String(dependencies.capabilityProbeWorkDelayMs ?? 0)], {
        stdio: ["ignore", "pipe", "ignore", "ipc"],
        detached: process.platform !== "win32",
      });
      child.stdout?.setEncoding("utf8");
      child.stdout?.on("data", (chunk: string) => { childOutput += chunk; });
      child.once("error", (error) => settleTerminal(error));
      child.once("exit", (code, childSignal) => {
        // 正常实现随后会触发 close；若 stdio/注入实现不再触发 close，也必须在有界 grace 后终态收敛。
        const timer = setTimeout(() => settleTerminal({ code, signal: childSignal }), 50);
        timer.unref();
      });
      child.once("close", (code, childSignal) => settleTerminal({ code, signal: childSignal }));
      const abortPromise = new Promise<never>((_resolve, reject) => {
        const onAbort = () => {
          signal.removeEventListener("abort", onAbort);
          reject(signal.reason ?? new DOMException("Aborted", "AbortError"));
        };
        if (signal.aborted) onAbort(); else signal.addEventListener("abort", onAbort, { once: true });
        terminalPromise.finally(() => signal.removeEventListener("abort", onAbort)).catch(() => undefined);
      });
      const outcome = await Promise.race([terminalPromise, abortPromise]);
      if (outcome instanceof Error) throw outcome;
      if (signal.aborted) throw signal.reason ?? new DOMException("Aborted", "AbortError");
      const resultLines = childOutput.trim().split("\n").filter(Boolean);
      if (outcome.code !== 0) {
        let native: NodeJS.ErrnoException = Object.assign(new Error(`fd capability child 失败（code=${outcome.code}, signal=${outcome.signal ?? "none"}）`), { code: "ECHILD" });
        try {
          const parsedResults = resultLines.map((line) => JSON.parse(line) as { code?: string; errno?: number; spawnError?: string; workerFailure?: boolean; message?: string; nonce?: string });
          const parsed = [...parsedResults].reverse().find((value) => value.nonce === id && value.workerFailure === true)
            ?? [...parsedResults].reverse().find((value) => value.code !== undefined || value.spawnError !== undefined || value.errno !== undefined);
          if (parsed) native = Object.assign(new Error(parsed.message ?? native.message), { code: parsed.code ?? parsed.spawnError ?? native.code, errno: parsed.errno });
        } catch { /* sanitized child output only */ }
        const unsupported = native.code === "ENOTSUP" || native.code === "EXDEV" || native.code === "EOPNOTSUPP" || native.code === "ERRNO_45" || native.errno === 45 || native.errno === 95 || native.errno === 18;
        if (unsupported) throw new Error("当前 config 文件系统不支持安全 fd-bound 凭据发布，拒绝在 refresh 前开始轮换", { cause: native });
        throw native;
      }
      let attestation: { ok?: boolean; nonce?: string } | undefined;
      try { attestation = JSON.parse(resultLines.at(-1) ?? "") as { ok?: boolean; nonce?: string }; } catch { /* 下方 fail closed */ }
      if (attestation?.ok !== true || attestation.nonce !== id) throw new Error("fd capability supervisor 成功证明缺失或 nonce 不匹配");
      safeToCleanup = true;
    } finally {
      await terminateChildBounded();
      if (child?.pid === undefined || terminal !== undefined || !isProcessAlive(child.pid)) safeToCleanup = true;
      if (safeToCleanup) {
        for (const name of ["source", "target", "lifecycle.json"]) {
          try { await unlink(join(probeDir, name)); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
        }
        try { await rmdir(probeDir); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
        await syncConfigDir();
      } else {
        // lifecycle 路径保留用于 fresh-process owner-death 回收；禁止 namespace 重建导致晚发布 ABA。
        await lstat(lifecyclePath).catch(() => undefined);
      }
    }
    })();
    const tracked = operation.catch((error) => {
      if (fdPublicationCapability === tracked) fdPublicationCapability = undefined;
      throw error;
    });
    fdPublicationCapability = tracked;
    // 创建者的 signal 已进入 operation；必须等待其 finally 完成进程/namespace 清理后再返回 abort。
    return tracked;
  };
  const withMutationLock = async <T>(operation: () => Promise<T>): Promise<T> => {
    const startIdentity = await processStartIdentity();
    if (!startIdentity) throw new Error("无法取得当前进程启动身份，拒绝 recovery mutation");
    const nonce = randomUUID();
    const lockRecord = { version: 1, processId: process.pid, processStartIdentity: startIdentity, nonce };
    const tempPath = `${mutationLockPath}.${nonce}.tmp`;
    let lock: Awaited<ReturnType<typeof open>> | undefined;
    let lockIdentity: { dev: number; ino: number } | undefined;
    for (let attempt = 0; attempt < 2; attempt++) {
      let published = false;
      let publishedIdentity: { dev: number; ino: number } | undefined;
      try {
        lock = await open(tempPath, fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
        await lock.writeFile(`${JSON.stringify(lockRecord)}\n`, "utf8");
        await lock.chmod(0o600);
        await lock.sync();
        const tempStat = await lock.stat();
        // 完整记录先 fsync，再以 hard-link 原子 no-replace 发布；create/write 崩溃只留下不具备锁语义的私有 temp。
        await link(tempPath, mutationLockPath);
        published = true;
        publishedIdentity = { dev: tempStat.dev, ino: tempStat.ino };
        lockIdentity = publishedIdentity;
        await unlink(tempPath);
        await syncConfigDir();
        break;
      } catch (error) {
        await lock?.close().catch(() => undefined);
        lock = undefined;
        if (published && publishedIdentity) {
          // acquisition 尚未交付 operation：任何尾部错误都必须 owner-safe 撤销本次已发布 lock。
          const finalStat = await lstat(mutationLockPath);
          const current = JSON.parse(await readFile(mutationLockPath, "utf8")) as Record<string, unknown>;
          if (finalStat.dev !== publishedIdentity.dev || finalStat.ino !== publishedIdentity.ino || current.nonce !== nonce) throw new Error("rotation mutation lock acquisition 回滚时 owner 不匹配", { cause: error });
          await unlink(mutationLockPath);
          await syncConfigDir();
        }
        try { await unlink(tempPath); } catch (cleanupError) { if ((cleanupError as NodeJS.ErrnoException).code !== "ENOENT") throw cleanupError; }
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        const fileStat = await lstat(mutationLockPath);
        if (fileStat.isSymbolicLink() || !fileStat.isFile() || (fileStat.mode & 0o077) !== 0) throw new Error("rotation mutation lock 非法");
        const parsed = JSON.parse(await readFile(mutationLockPath, "utf8")) as Record<string, unknown>;
        if (parsed.version !== 1 || typeof parsed.processId !== "number" || !Number.isInteger(parsed.processId) || parsed.processId <= 0 || typeof parsed.processStartIdentity !== "string" || typeof parsed.nonce !== "string") throw new Error("rotation mutation lock 内容非法");
        const active = await evaluateProcessOwnerActivity(
          parsed.processStartIdentity,
          () => { try { process.kill(parsed.processId as number, 0); return "live-or-unknown"; } catch (probeError) { return (probeError as NodeJS.ErrnoException).code === "EPERM" ? "live-or-unknown" : "dead"; } },
          () => processStartIdentity(parsed.processId as number),
        );
        if (active) throw new Error("已有 rotation mutation 正在进行");
        const rechecked = await lstat(mutationLockPath);
        const current = JSON.parse(await readFile(mutationLockPath, "utf8")) as Record<string, unknown>;
        if (rechecked.dev !== fileStat.dev || rechecked.ino !== fileStat.ino || current.nonce !== parsed.nonce) throw new Error("rotation mutation lock 在回收前发生变化");
        await unlink(mutationLockPath);
        await syncConfigDir();
      }
    }
    if (!lock || !lockIdentity) throw new Error("无法取得 rotation mutation lock");
    try { return await operation(); }
    finally {
      await lock.close();
      const finalStat = await lstat(mutationLockPath);
      const current = JSON.parse(await readFile(mutationLockPath, "utf8")) as Record<string, unknown>;
      if (finalStat.dev !== lockIdentity.dev || finalStat.ino !== lockIdentity.ino || current.nonce !== nonce) throw new Error("rotation mutation lock owner 不匹配");
      await unlink(mutationLockPath);
      await syncConfigDir();
    }
  };
  const clearReservation = async (owner?: RotationReservation): Promise<void> => {
    if (!await guardConfigDir(true)) return;
    const reservation = await readReservation();
    if (!reservation) return;
    if (owner !== undefined && reservation.owner !== owner) throw new Error("rotation reservation owner 不匹配");
    await unlink(rotationReservationPath);
    ACTIVE_ROTATION_OWNERS.delete(reservation.owner);
    await syncConfigDir();
  };
  const cleanupDeadCapabilityProbes = async (): Promise<void> => {
    if (!await guardConfigDir(true)) return;
    const names = (await readdir(configDir)).filter((name) => name.startsWith(".rotation-fd-probe."));
    const snapshots: Array<{ name: string; path: string; dev: number; ino: number; children: Array<{ name: string; dev: number; ino: number }> }> = [];
    for (const name of names) {
      const match = /^\.rotation-fd-probe\.([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/i.exec(name);
      if (!match) throw new Error(`capability probe 名称非法：${name}`);
      const path = join(configDir, name);
      let dirStat = await lstat(path);
      if (dirStat.isSymbolicLink() || !dirStat.isDirectory() || (dirStat.mode & 0o077) !== 0) throw new Error(`capability probe ${name} 不是可信 0700 目录`);
      let childNames = await readdir(path);
      if (!childNames.includes("lifecycle.json")) {
        // supervisor 会在 parent-death 后自行清理；给仍在启动中的 supervisor 一个有界窗口，避免删掉活跃 worker namespace。
        await delay(300);
        try {
          dirStat = await lstat(path);
          childNames = await readdir(path);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
          throw error;
        }
      }
      const children: Array<{ name: string; dev: number; ino: number }> = [];
      for (const child of childNames) {
        if (child !== "source" && child !== "target" && child !== "lifecycle.json") throw new Error(`capability probe ${name} 含未知证据 ${child}`);
        const childPath = join(path, child);
        const fileStat = await lstat(childPath);
        if (fileStat.isSymbolicLink() || !fileStat.isFile() || (fileStat.mode & 0o077) !== 0) throw new Error(`capability probe ${name}/${child} 不是可信 0600 文件`);
        children.push({ name: child, dev: fileStat.dev, ino: fileStat.ino });
      }
      if (childNames.includes("lifecycle.json")) {
        const lifecycle = JSON.parse(await readFile(join(path, "lifecycle.json"), "utf8")) as Record<string, unknown>;
        if (lifecycle.version !== 1 || lifecycle.nonce !== match[1]
          || typeof lifecycle.supervisorPid !== "number" || !Number.isInteger(lifecycle.supervisorPid) || lifecycle.supervisorPid <= 0 || typeof lifecycle.supervisorStartIdentity !== "string" || lifecycle.supervisorStartIdentity.length === 0
          || typeof lifecycle.workerPid !== "number" || !Number.isInteger(lifecycle.workerPid) || lifecycle.workerPid <= 0 || typeof lifecycle.workerStartIdentity !== "string" || lifecycle.workerStartIdentity.length === 0
          || typeof lifecycle.watchdogPid !== "number" || !Number.isInteger(lifecycle.watchdogPid) || lifecycle.watchdogPid <= 0 || typeof lifecycle.watchdogStartIdentity !== "string" || lifecycle.watchdogStartIdentity.length === 0
          || typeof lifecycle.executorPid !== "number" || !Number.isInteger(lifecycle.executorPid) || lifecycle.executorPid <= 0 || typeof lifecycle.executorStartIdentity !== "string" || lifecycle.executorStartIdentity.length === 0) throw new Error(`capability probe ${name} lifecycle 内容非法`);
        for (const [pid, identity] of [
          [lifecycle.supervisorPid, lifecycle.supervisorStartIdentity],
          [lifecycle.workerPid, lifecycle.workerStartIdentity],
          [lifecycle.watchdogPid, lifecycle.watchdogStartIdentity],
          [lifecycle.executorPid, lifecycle.executorStartIdentity],
        ] as Array<[number, string]>) {
          const active = await evaluateProcessOwnerActivity(
            identity,
            () => { try { process.kill(pid, 0); return "live-or-unknown"; } catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM" ? "live-or-unknown" : "dead"; } },
            () => processStartIdentity(pid),
          );
          if (active) throw new Error(`capability probe ${name} 隔离进程仍活跃或身份未知，拒绝清理 namespace`);
        }
      }
      snapshots.push({ name, path, dev: dirStat.dev, ino: dirStat.ino, children });
    }
    // 全量验证后再 mutation；任何恶意/活跃证据均保持零删除。
    for (const snapshot of snapshots) {
      const currentDir = await lstat(snapshot.path);
      const currentNames = (await readdir(snapshot.path)).sort();
      const expectedNames = snapshot.children.map((child) => child.name).sort();
      if (currentDir.dev !== snapshot.dev || currentDir.ino !== snapshot.ino || currentNames.length !== expectedNames.length || currentNames.some((name, index) => name !== expectedNames[index])) throw new Error(`capability probe ${snapshot.name} 在清理前发生变化`);
      for (const child of snapshot.children) {
        const current = await lstat(join(snapshot.path, child.name));
        if (current.dev !== child.dev || current.ino !== child.ino || current.isSymbolicLink() || !current.isFile()) throw new Error(`capability probe ${snapshot.name}/${child.name} 在清理前发生替换`);
      }
    }
    for (const snapshot of snapshots) {
      for (const child of snapshot.children) await unlink(join(snapshot.path, child.name));
      await rmdir(snapshot.path);
    }
    if (snapshots.length > 0) await syncConfigDir();
  };
  const readCredential = async (path: string, label: string): Promise<StoredCredential | undefined> => {
    if (!await guardConfigDir(true)) return undefined;
    try {
      const fileStat = await lstat(path);
      if (fileStat.isSymbolicLink() || !fileStat.isFile()) throw new Error(`${label} 必须是普通文件，不能是符号链接`);
      if ((fileStat.mode & 0o077) !== 0) throw new Error(`${label} 文件权限必须为 0600`);
      return validate(JSON.parse(await readFile(path, "utf8")), machineIdHash);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw e;
    }
  };
  const parseRotationRecord = (value: string, label: string): RotationRecord => {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    if (parsed.version !== 1 || typeof parsed.owner !== "string" || parsed.owner.length === 0 || (parsed.artifactId !== undefined && (typeof parsed.artifactId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(parsed.artifactId))) || (parsed.sourceArtifactId !== undefined && (typeof parsed.sourceArtifactId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(parsed.sourceArtifactId))) || typeof parsed.baseCredentialHash !== "string" || parsed.baseCredentialHash.length === 0 || typeof parsed.targetCredentialHash !== "string" || parsed.targetCredentialHash.length === 0) throw new Error(`${label} 内容非法`);
    const credential = validate(parsed.credential, machineIdHash);
    if (credentialHash(credential) !== parsed.targetCredentialHash) throw new Error(`${label} target hash 不匹配`);
    return { version: 1, owner: parsed.owner, artifactId: parsed.artifactId as string | undefined, sourceArtifactId: parsed.sourceArtifactId as string | undefined, baseCredentialHash: parsed.baseCredentialHash, targetCredentialHash: parsed.targetCredentialHash, credential };
  };
  const readRotationRecord = async (path: string, label: string): Promise<RotationRecord | undefined> => {
    if (!await guardConfigDir(true)) return undefined;
    try {
      const fileStat = await lstat(path);
      if (fileStat.isSymbolicLink() || !fileStat.isFile()) throw new Error(`${label} 必须是普通文件，不能是符号链接`);
      if ((fileStat.mode & 0o077) !== 0) throw new Error(`${label} 文件权限必须为 0600`);
      return parseRotationRecord(await readFile(path, "utf8"), label);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw e;
    }
  };
  const sameRotationTarget = (left: RotationRecord, right: RotationRecord): boolean => left.owner === right.owner
    && left.baseCredentialHash === right.baseCredentialHash
    && left.targetCredentialHash === right.targetCredentialHash;
  const sameRotationRecord = (left: RotationRecord, right: RotationRecord): boolean => sameRotationTarget(left, right)
    && left.artifactId === right.artifactId
    && left.sourceArtifactId === right.sourceArtifactId;
  // 新格式不把 PID 作为可信身份；仍接受旧版带 PID 名称，身份只由结构化 owner/artifact/base/target 绑定。
  const rotationTempPattern = /^\.(auth-cn\.rotation(?:\.emergency)?\.json)(?:\.(\d+))?\.([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.(tmp|claim)$/i;
  type TrustedCleanupSnapshot = { path: string; tempDev: number; tempIno: number; tempUid: number; tempMode: number; tempNlink: number; journalDev: number; journalIno: number; journalNlink: number; record: RotationRecord };
  const validateTrustedRotationTemps = async (journalPath: string, record: RotationRecord): Promise<TrustedCleanupSnapshot[]> => {
    if (!await guardConfigDir(true)) return [];
    const expectedJournalName = basename(journalPath);
    const snapshots: TrustedCleanupSnapshot[] = [];
    for (const name of await readdir(configDir)) {
      const match = rotationTempPattern.exec(name);
      if (!match || match[1] !== expectedJournalName) continue;
      const path = join(configDir, name);
      const artifactId = match[3]!;
      const fileStat = await lstat(path);
      if (fileStat.isSymbolicLink() || !fileStat.isFile()) throw new Error(`rotation temp ${name} 必须是普通文件，不能是符号链接`);
      if (typeof fileStat.uid === "number" && typeof process.getuid === "function" && fileStat.uid !== process.getuid()) throw new Error(`rotation temp ${name} 所有者不是当前用户`);
      if ((fileStat.mode & 0o077) !== 0) throw new Error(`rotation temp ${name} 文件权限必须为 0600`);
      const tempRecord = await readRotationRecord(path, `rotation temp ${name}`);
      const artifactMatches = record.artifactId === undefined ? tempRecord?.artifactId === undefined : artifactId === record.artifactId && tempRecord?.artifactId === record.artifactId;
      if (!tempRecord || !artifactMatches || !sameRotationTarget(tempRecord, record)) throw new Error(`rotation temp ${name} 与当前 owner/artifact/base/target 不匹配`);
      const journalStat = await lstat(journalPath);
      if (journalStat.isSymbolicLink() || !journalStat.isFile()) throw new Error(`rotation temp ${name} 对应 journal 非法`);
      const isHardLinkPublication = fileStat.nlink === 2 && journalStat.nlink === 2 && journalStat.dev === fileStat.dev && journalStat.ino === fileStat.ino;
      const isFdClonePublication = process.platform === "darwin" && fileStat.nlink === 1 && journalStat.nlink === 1 && journalStat.dev === fileStat.dev && journalStat.ino !== fileStat.ino;
      if (!isHardLinkPublication && !isFdClonePublication) throw new Error(`rotation temp ${name} 不是当前 journal 的唯一可信 publication artifact`);
      snapshots.push({ path, tempDev: fileStat.dev, tempIno: fileStat.ino, tempUid: fileStat.uid, tempMode: fileStat.mode, tempNlink: fileStat.nlink, journalDev: journalStat.dev, journalIno: journalStat.ino, journalNlink: journalStat.nlink, record: tempRecord });
    }
    return snapshots;
  };
  const recheckTrustedRotationTemps = async (journalPath: string, snapshots: TrustedCleanupSnapshot[]): Promise<void> => {
    for (const snapshot of snapshots) {
      await dependencies.beforeRotationTempCleanup?.(snapshot.path);
      const tempStat = await lstat(snapshot.path);
      const journalStat = await lstat(journalPath);
      if (tempStat.isSymbolicLink() || !tempStat.isFile() || tempStat.dev !== snapshot.tempDev || tempStat.ino !== snapshot.tempIno || tempStat.uid !== snapshot.tempUid || tempStat.mode !== snapshot.tempMode || tempStat.nlink !== snapshot.tempNlink || journalStat.dev !== snapshot.journalDev || journalStat.ino !== snapshot.journalIno || journalStat.nlink !== snapshot.journalNlink) throw new Error(`rotation temp ${basename(snapshot.path)} 在清理前发生替换`);
      const tempRecord = await readRotationRecord(snapshot.path, `rotation temp ${basename(snapshot.path)}`);
      const journalRecord = await readRotationRecord(journalPath, basename(journalPath));
      if (!tempRecord || !journalRecord || !sameRotationRecord(tempRecord, snapshot.record) || !sameRotationRecord(journalRecord, snapshot.record)) throw new Error(`rotation temp ${basename(snapshot.path)} 在清理前内容发生变化`);
    }
  };
  const mutateTrustedRotationTemps = async (snapshots: TrustedCleanupSnapshot[]): Promise<void> => {
    let removed = false;
    for (const snapshot of snapshots) {
      try { await unlink(snapshot.path); removed = true; }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    }
    if (removed) await syncConfigDir();
  };
  const listRotationTempNames = async (): Promise<string[]> => {
    if (!await guardConfigDir(true)) return [];
    return (await readdir(configDir)).filter((name) => rotationTempPattern.test(name));
  };
  const assertNoRotationTemps = async (): Promise<void> => {
    const remaining = await listRotationTempNames();
    if (remaining.length > 0) throw new Error(`存在未受信任或不匹配的 rotation temp：${remaining.join(",")}`);
  };
  type JournalEvidenceSnapshot = { path: string; label: string; dev: number; ino: number; uid: number; mode: number; nlink: number; record: RotationRecord };
  type RecoveryEvidenceSnapshot = {
    journals: JournalEvidenceSnapshot[];
    journalPresence: [boolean, boolean];
    rotationTemps: TrustedCleanupSnapshot[];
    emergencyTemps: TrustedCleanupSnapshot[];
    tempNames: string[];
  };
  const snapshotJournalEvidence = async (path: string, label: string, record: RotationRecord): Promise<JournalEvidenceSnapshot> => {
    const fileStat = await lstat(path);
    if (fileStat.isSymbolicLink() || !fileStat.isFile() || (fileStat.mode & 0o077) !== 0) throw new Error(`${label} 不是可信 0600 普通文件`);
    if (typeof fileStat.uid === "number" && typeof process.getuid === "function" && fileStat.uid !== process.getuid()) throw new Error(`${label} 所有者不是当前用户`);
    const current = await readRotationRecord(path, label);
    if (!current || !sameRotationRecord(current, record)) throw new Error(`${label} 在恢复验证期间发生变化`);
    return { path, label, dev: fileStat.dev, ino: fileStat.ino, uid: fileStat.uid, mode: fileStat.mode, nlink: fileStat.nlink, record };
  };
  const validateRecoveryEvidence = async (rotation: RotationRecord | undefined, emergency: RotationRecord | undefined): Promise<RecoveryEvidenceSnapshot> => {
    const journals: JournalEvidenceSnapshot[] = [];
    if (rotation) journals.push(await snapshotJournalEvidence(rotationPath, "rotation journal", rotation));
    if (emergency) journals.push(await snapshotJournalEvidence(emergencyRotationPath, "emergency rotation journal", emergency));
    const rotationTemps = rotation ? await validateTrustedRotationTemps(rotationPath, rotation) : [];
    const emergencyTemps = emergency ? await validateTrustedRotationTemps(emergencyRotationPath, emergency) : [];
    const tempNames = (await listRotationTempNames()).sort();
    const accounted = new Set([...rotationTemps, ...emergencyTemps].map((snapshot) => basename(snapshot.path)));
    const unaccounted = tempNames.filter((name) => !accounted.has(name));
    if (unaccounted.length > 0) throw new Error(`rotation recovery 存在无对应可信 journal 的 temp/claim：${unaccounted.join(",")}`);
    return { journals, journalPresence: [rotation !== undefined, emergency !== undefined], rotationTemps, emergencyTemps, tempNames };
  };
  const recheckRecoveryEvidence = async (evidence: RecoveryEvidenceSnapshot): Promise<void> => {
    const currentJournalPresence: [boolean, boolean] = [
      await readRotationRecord(rotationPath, "rotation journal") !== undefined,
      await readRotationRecord(emergencyRotationPath, "emergency rotation journal") !== undefined,
    ];
    if (currentJournalPresence[0] !== evidence.journalPresence[0] || currentJournalPresence[1] !== evidence.journalPresence[1]) throw new Error("rotation recovery journal 集合在 mutation 前发生变化");
    const currentNames = (await listRotationTempNames()).sort();
    if (currentNames.length !== evidence.tempNames.length || currentNames.some((name, index) => name !== evidence.tempNames[index])) throw new Error("rotation recovery 证据集合在 mutation 前发生变化");
    for (const journal of evidence.journals) {
      const fileStat = await lstat(journal.path);
      const record = await readRotationRecord(journal.path, journal.label);
      if (fileStat.isSymbolicLink() || !fileStat.isFile() || fileStat.dev !== journal.dev || fileStat.ino !== journal.ino || fileStat.uid !== journal.uid || fileStat.mode !== journal.mode || fileStat.nlink !== journal.nlink || !record || !sameRotationRecord(record, journal.record)) throw new Error(`${journal.label} 在 mutation 前发生变化`);
    }
    if (evidence.rotationTemps.length > 0) await recheckTrustedRotationTemps(rotationPath, evidence.rotationTemps);
    if (evidence.emergencyTemps.length > 0) await recheckTrustedRotationTemps(emergencyRotationPath, evidence.emergencyTemps);
    // hooks/并发方可能在上述复核期间改变目录；mutation 紧邻前再无 hook 地复核完整集合与 journal identity/content。
    const finalJournalPresence: [boolean, boolean] = [
      await readRotationRecord(rotationPath, "rotation journal") !== undefined,
      await readRotationRecord(emergencyRotationPath, "emergency rotation journal") !== undefined,
    ];
    if (finalJournalPresence[0] !== evidence.journalPresence[0] || finalJournalPresence[1] !== evidence.journalPresence[1]) throw new Error("rotation recovery journal 集合在 mutation 前发生变化");
    const finalNames = (await listRotationTempNames()).sort();
    if (finalNames.length !== evidence.tempNames.length || finalNames.some((name, index) => name !== evidence.tempNames[index])) throw new Error("rotation recovery 证据集合在 mutation 前发生变化");
    for (const journal of evidence.journals) {
      const fileStat = await lstat(journal.path);
      const record = await readRotationRecord(journal.path, journal.label);
      if (fileStat.isSymbolicLink() || !fileStat.isFile() || fileStat.dev !== journal.dev || fileStat.ino !== journal.ino || fileStat.uid !== journal.uid || fileStat.mode !== journal.mode || fileStat.nlink !== journal.nlink || !record || !sameRotationRecord(record, journal.record)) throw new Error(`${journal.label} 在 mutation 前发生变化`);
    }
  };
  const cleanupOwnerOrphanRotationTemps = async (reservation: ReservationRecord, expectedTargetHash?: string): Promise<void> => {
    const snapshots: Array<{ path: string; dev: number; ino: number; uid: number; mode: number; record: RotationRecord }> = [];
    for (const name of await listRotationTempNames()) {
      const match = rotationTempPattern.exec(name);
      if (!match) continue;
      const path = join(configDir, name);
      const fileStat = await lstat(path);
      if (fileStat.isSymbolicLink() || !fileStat.isFile()) throw new Error(`rotation temp ${name} 必须是普通文件，不能是符号链接`);
      if (typeof fileStat.uid === "number" && typeof process.getuid === "function" && fileStat.uid !== process.getuid()) throw new Error(`rotation temp ${name} 所有者不是当前用户`);
      if ((fileStat.mode & 0o077) !== 0) throw new Error(`rotation temp ${name} 文件权限必须为 0600`);
      const tempRecord = await readRotationRecord(path, `rotation temp ${name}`);
      if (!tempRecord || tempRecord.owner !== reservation.owner || tempRecord.baseCredentialHash !== reservation.baseCredentialHash || (expectedTargetHash !== undefined && tempRecord.targetCredentialHash !== expectedTargetHash) || tempRecord.artifactId !== match[3] || fileStat.nlink !== 1) throw new Error(`rotation temp ${name} 不是当前 owner 的可信孤立 temp`);
      snapshots.push({ path, dev: fileStat.dev, ino: fileStat.ino, uid: fileStat.uid, mode: fileStat.mode, record: tempRecord });
    }
    // 完整集合验证成功后，再完整复核 identity+content；复核成功前不删除任何候选。
    for (const snapshot of snapshots) {
      await dependencies.beforeRotationTempCleanup?.(snapshot.path);
      const current = await lstat(snapshot.path);
      const currentRecord = await readRotationRecord(snapshot.path, `rotation temp ${basename(snapshot.path)}`);
      if (current.isSymbolicLink() || !current.isFile() || current.dev !== snapshot.dev || current.ino !== snapshot.ino || current.uid !== snapshot.uid || current.mode !== snapshot.mode || current.nlink !== 1 || !currentRecord || !sameRotationRecord(currentRecord, snapshot.record)) throw new Error(`rotation temp ${basename(snapshot.path)} 在清理前发生替换`);
    }
    let removed = false;
    for (const snapshot of snapshots) {
      try { await unlink(snapshot.path); removed = true; }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    }
    if (removed) await syncConfigDir();
  };
  const promoteOwnerOrphanRotationTemp = async (journalPath: string, label: string, reservation: ReservationRecord, targetHash: string): Promise<boolean> => {
    const expectedJournalName = basename(journalPath);
    type OrphanEntry = { name: string; path: string; kind: "tmp" | "claim"; artifactId: string; record: RotationRecord; dev: number; ino: number; uid: number; mode: number; nlink: number };
    type OrphanCandidate = { name: string; path: string; claimPath: string; detachPath?: string; claimAcquired: boolean; record: RotationRecord; dev: number; ino: number; uid: number; mode: number; expectedNlink: number };
    const grouped = new Map<string, OrphanEntry[]>();
    for (const name of await listRotationTempNames()) {
      const match = rotationTempPattern.exec(name);
      if (!match) continue;
      const path = join(configDir, name);
      const fileStat = await lstat(path);
      if (fileStat.isSymbolicLink() || !fileStat.isFile() || (fileStat.mode & 0o077) !== 0 || (fileStat.nlink !== 1 && fileStat.nlink !== 2)) throw new Error(`rotation temp ${name} 不是可恢复的普通 0600 孤立 temp`);
      if (typeof fileStat.uid === "number" && typeof process.getuid === "function" && fileStat.uid !== process.getuid()) throw new Error(`rotation temp ${name} 所有者不是当前用户`);
      const tempRecord = await readRotationRecord(path, `rotation temp ${name}`);
      const artifactId = match[3]!;
      if (!tempRecord || tempRecord.owner !== reservation.owner || tempRecord.baseCredentialHash !== reservation.baseCredentialHash || tempRecord.targetCredentialHash !== targetHash || tempRecord.artifactId !== artifactId) throw new Error(`rotation temp ${name} 与当前 owner/artifact/base/target 不匹配`);
      const entry: OrphanEntry = { name, path, kind: match[4] as "tmp" | "claim", artifactId, record: tempRecord, dev: fileStat.dev, ino: fileStat.ino, uid: fileStat.uid, mode: fileStat.mode, nlink: fileStat.nlink };
      grouped.set(artifactId, [...(grouped.get(artifactId) ?? []), entry]);
    }
    if (grouped.size === 0) return false;
    const candidates: OrphanCandidate[] = [];
    for (const entries of grouped.values()) {
      if (entries.length === 1) {
        const entry = entries[0]!;
        if (entry.nlink !== 1) throw new Error(`rotation temp ${entry.name} 的 claim 状态不完整`);
        candidates.push({
          name: entry.name,
          path: entry.path,
          claimPath: entry.kind === "claim" ? entry.path : join(configDir, `.${expectedJournalName}.${entry.artifactId}.claim`),
          detachPath: entry.kind === "tmp" ? entry.path : undefined,
          claimAcquired: entry.kind === "claim",
          record: entry.record,
          dev: entry.dev,
          ino: entry.ino,
          uid: entry.uid,
          mode: entry.mode,
          expectedNlink: 1,
        });
        continue;
      }
      const temp = entries.find((entry) => entry.kind === "tmp");
      const claim = entries.find((entry) => entry.kind === "claim");
      if (entries.length !== 2 || !temp || !claim || temp.nlink !== 2 || claim.nlink !== 2 || temp.dev !== claim.dev || temp.ino !== claim.ino || !sameRotationRecord(temp.record, claim.record)) throw new Error("rotation temp/claim 半完成状态存在歧义，拒绝发布");
      candidates.push({ name: temp.name, path: temp.path, claimPath: claim.path, detachPath: temp.path, claimAcquired: true, record: temp.record, dev: temp.dev, ino: temp.ino, uid: temp.uid, mode: temp.mode, expectedNlink: 2 });
    }
    if (candidates.length !== 1) throw new Error("存在多个匹配的孤立 rotation temp，拒绝发布任意候选");
    const candidate = candidates[0]!;
    await dependencies.beforeOrphanPromotionLink?.(candidate.path, journalPath);
    const rechecked = await lstat(candidate.path);
    if (rechecked.isSymbolicLink() || !rechecked.isFile() || rechecked.dev !== candidate.dev || rechecked.ino !== candidate.ino || rechecked.uid !== candidate.uid || rechecked.mode !== candidate.mode || rechecked.nlink !== candidate.expectedNlink) throw new Error(`rotation temp ${candidate.name} 在发布前发生替换`);
    const sourceRecord = await readRotationRecord(candidate.path, `rotation temp ${candidate.name}`);
    if (!sourceRecord || !sameRotationRecord(sourceRecord, candidate.record)) throw new Error(`rotation temp ${candidate.name} 发布前内容发生变化`);
    // claim 获取必须 no-replace：并发/崩溃遗留的同名 claim 永不被覆盖。
    if (!candidate.claimAcquired) {
      try { await link(candidate.path, candidate.claimPath); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        const existingClaim = await readRotationRecord(candidate.claimPath, `rotation claim ${candidate.name}`);
        const claimStat = await lstat(candidate.claimPath);
        if (!existingClaim || !sameRotationRecord(existingClaim, candidate.record) || claimStat.dev !== candidate.dev || claimStat.ino !== candidate.ino || claimStat.nlink !== 2) throw new Error(`已有 rotation claim 与当前候选不一致`);
      }
      candidate.claimAcquired = true;
    }
    await dependencies.afterOrphanClaimAcquire?.(candidate.path, candidate.claimPath);
    if (candidate.detachPath) {
      const sourceAfterClaim = await lstat(candidate.detachPath);
      const claimBeforeDetach = await lstat(candidate.claimPath);
      if (sourceAfterClaim.dev !== candidate.dev || sourceAfterClaim.ino !== candidate.ino || claimBeforeDetach.dev !== candidate.dev || claimBeforeDetach.ino !== candidate.ino || sourceAfterClaim.nlink !== 2 || claimBeforeDetach.nlink !== 2) throw new Error(`rotation temp ${candidate.name} claim 获取后身份不一致`);
      await unlink(candidate.detachPath);
    }
    const claimPath = candidate.claimPath;
    const claimHandle = await open(claimPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    try {
      const claimed = await claimHandle.stat();
      if (!claimed.isFile() || claimed.dev !== candidate.dev || claimed.ino !== candidate.ino || claimed.uid !== candidate.uid || claimed.mode !== candidate.mode || claimed.nlink !== 1) throw new Error(`rotation temp ${candidate.name} claim 完整性校验失败`);
      const claimedRecord = parseRotationRecord(await claimHandle.readFile("utf8"), `rotation claim ${candidate.name}`);
      if (!sameRotationRecord(claimedRecord, candidate.record)) throw new Error(`rotation temp ${candidate.name} claim 内容变化`);
      try {
        if (dependencies.publishFdExclusive) await dependencies.publishFdExclusive(claimHandle.fd, journalPath);
        else await publishFdExclusive(claimHandle.fd, journalPath);
      }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        const existing = await readRotationRecord(journalPath, label);
        if (!existing || !sameRotationRecord(existing, candidate.record)) throw new Error(`已有 ${label} 与孤立 temp 不一致`);
      }
    } finally { await claimHandle.close(); }
    await dependencies.afterOrphanPromotionPublish?.(claimPath, journalPath);
    const finalStat = await lstat(journalPath);
    const finalRecord = await readRotationRecord(journalPath, label);
    if (finalStat.isSymbolicLink() || !finalStat.isFile() || (finalStat.mode & 0o077) !== 0 || !finalRecord || !sameRotationRecord(finalRecord, candidate.record)) throw new Error(`${label} 发布后完整性校验失败`);
    await syncConfigDir();
    const remainingClaim = await lstat(claimPath);
    if (remainingClaim.isSymbolicLink() || !remainingClaim.isFile() || remainingClaim.dev !== candidate.dev || remainingClaim.ino !== candidate.ino || remainingClaim.uid !== candidate.uid || remainingClaim.mode !== candidate.mode || remainingClaim.nlink < 1) throw new Error(`rotation claim ${candidate.name} 发生替换`);
    await unlink(claimPath);
    await syncConfigDir();
    return true;
  };
  const recoverOwnerOrphanRotationTemp = async (reservation: ReservationRecord, config: StoredCredential): Promise<StoredCredential | undefined> => {
    const candidates: Array<{ path: string; record: RotationRecord; dev: number; ino: number; uid: number; mode: number }> = [];
    for (const name of await listRotationTempNames()) {
      const match = rotationTempPattern.exec(name);
      if (!match) continue;
      const path = join(configDir, name);
      const fileStat = await lstat(path);
      if (fileStat.isSymbolicLink() || !fileStat.isFile() || (fileStat.mode & 0o077) !== 0 || fileStat.nlink !== 1) throw new Error(`rotation temp ${name} 不是可恢复的普通 0600 孤立 temp`);
      if (typeof fileStat.uid === "number" && typeof process.getuid === "function" && fileStat.uid !== process.getuid()) throw new Error(`rotation temp ${name} 所有者不是当前用户`);
      const record = await readRotationRecord(path, `rotation temp ${name}`);
      if (!record || record.owner !== reservation.owner || record.baseCredentialHash !== reservation.baseCredentialHash || record.artifactId !== match[3]) throw new Error(`rotation temp ${name} 与当前 reservation 不匹配`);
      candidates.push({ path, record, dev: fileStat.dev, ino: fileStat.ino, uid: fileStat.uid, mode: fileStat.mode });
    }
    if (candidates.length === 0) return undefined;
    if (candidates.length !== 1) throw new Error("存在多个孤立 rotation temp，拒绝猜测恢复目标");
    const candidate = candidates[0]!;
    if (credentialHash(config) !== candidate.record.baseCredentialHash) throw new Error("durable config 已变化，拒绝孤立 temp 恢复");
    // 孤立证据也必须在首次 config mutation 前完成 identity+content 复核。
    await dependencies.beforeRotationTempCleanup?.(candidate.path);
    const rechecked = await lstat(candidate.path);
    const recheckedRecord = await readRotationRecord(candidate.path, `rotation temp ${basename(candidate.path)}`);
    if (rechecked.isSymbolicLink() || !rechecked.isFile() || rechecked.dev !== candidate.dev || rechecked.ino !== candidate.ino || rechecked.uid !== candidate.uid || rechecked.mode !== candidate.mode || rechecked.nlink !== 1 || !recheckedRecord || !sameRotationRecord(recheckedRecord, candidate.record)) throw new Error("孤立 rotation temp 在恢复 mutation 前发生替换");
    await writeAtomic(configPath, candidate.record.credential);
    const cleanupStat = await lstat(candidate.path);
    const cleanupRecord = await readRotationRecord(candidate.path, `rotation temp ${basename(candidate.path)}`);
    if (cleanupStat.isSymbolicLink() || !cleanupStat.isFile() || cleanupStat.dev !== candidate.dev || cleanupStat.ino !== candidate.ino || cleanupStat.uid !== candidate.uid || cleanupStat.mode !== candidate.mode || cleanupStat.nlink !== 1 || !cleanupRecord || !sameRotationRecord(cleanupRecord, candidate.record)) throw new Error("孤立 rotation temp 在清理前发生替换");
    await unlink(candidate.path);
    await syncConfigDir();
    await clearReservation(reservation.owner);
    return candidate.record.credential;
  };
  const publishRotationRecord = async (path: string, label: string, record: RotationRecord): Promise<void> => {
    if (!await guardConfigDir(true)) await mkdir(configDir, { recursive: true, mode: 0o700 });
    await guardConfigDir(false);
    if (!record.artifactId) throw new Error(`${label} 缺少 artifactId`);
    const tmp = join(configDir, `.${basename(path)}.${record.artifactId}.tmp`);
    let cleanupTemp = true;
    let linked = false;
    const notify = async (phase: RotationPublishPhase) => dependencies.onRotationPublishPhase?.(phase, { temp: tmp, target: path });
    try {
      await notify("before-create");
      const handle = await open(tmp, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
      try {
        await notify("after-create");
        await handle.writeFile(`${JSON.stringify(record)}\n`, "utf8");
        await notify("after-write");
        await handle.chmod(0o600);
        await notify("after-chmod");
        await handle.sync();
        await notify("after-file-fsync");
      } finally { await handle.close(); }
      const complete = await readRotationRecord(tmp, `${label} temp`);
      if (!complete || !sameRotationRecord(complete, record)) throw new Error(`${label} temp 完整性校验失败`);
      await notify("before-publish");
      // hard-link 是同目录原子 no-replace 发布点；publish 前的失败只会留下不受信任的唯一 temp。
      try { await link(tmp, path); linked = true; cleanupTemp = false; await notify("after-publish"); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        const existing = await readRotationRecord(path, label);
        if (!existing || !sameRotationTarget(existing, record)) throw new Error(`已有 ${label} 与 owner/base/target 不一致`);
      }
      // final link durable 后才清理 temp；目录 fsync 失败时保留完整 temp，便于诊断且不会污染 final。
      await notify("before-directory-fsync");
      await syncConfigDir();
      await notify("after-directory-fsync");
      cleanupTemp = true;
    } finally {
      if (cleanupTemp) {
        try { await unlink(tmp); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
        if (linked) await syncConfigDir();
      }
    }
  };
  const syncDirectory = async (path: string): Promise<void> => {
    const handle = await open(path, fsConstants.O_RDONLY);
    try { await handle.sync(); } finally { await handle.close(); }
  };
  const writeAtomicBytes = async (path: string, bytes: Uint8Array, replaceExisting = true): Promise<void> => {
    if (bytes.byteLength <= 0 || bytes.byteLength > IMPORT_FILE_MAX_BYTES) throw new Error(`${basename(path)} 内容大小非法`);
    if (!await guardConfigDir(true)) await mkdir(configDir, { recursive: true, mode: 0o700 });
    await guardConfigDir(false);
    const parentDir = dirname(path);
    const parentStat = await lstat(parentDir);
    if (parentStat.isSymbolicLink() || !parentStat.isDirectory()) throw new Error(`${basename(parentDir)} 必须是真实目录`);
    if (typeof parentStat.uid === "number" && typeof process.getuid === "function" && parentStat.uid !== process.getuid()) throw new Error(`${basename(parentDir)} 所有者不是当前用户`);
    if ((parentStat.mode & 0o077) !== 0) throw new Error(`${basename(parentDir)} 权限必须为 0700`);
    try {
      const targetStat = await lstat(path);
      if (targetStat.isSymbolicLink() || !targetStat.isFile()) throw new Error(`${basename(path)} 必须是普通文件，不能是符号链接`);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    }
    const tmp = join(parentDir, `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
    const f = await open(tmp, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    let noReplaceLinked = false;
    try {
      await f.writeFile(bytes);
      await f.chmod(0o600);
      await f.sync();
      if (replaceExisting) await rename(tmp, path);
      else {
        await link(tmp, path);
        noReplaceLinked = true;
        await dependencies.afterImportNoReplaceLink?.({ temp: tmp, target: path });
        await unlink(tmp);
      }
    } catch (error) {
      // no-replace final 已发布后不得在异常路径盲删 hard-link temp；fresh recovery 会按 inode/content 契约清理。
      if (!noReplaceLinked) await removeIfExists(tmp).catch(() => undefined);
      throw error;
    } finally { await f.close(); }
    await chmod(path, 0o600);
    await syncDirectory(parentDir);
    if (parentDir !== configDir) await syncConfigDir();
  };
  const writeAtomic = async (path: string, value: StoredCredential): Promise<void> => {
    await writeAtomicBytes(path, Buffer.from(`${JSON.stringify(validate(value, machineIdHash))}\n`, "utf8"));
  };
  const removeIfExists = async (path: string): Promise<void> => {
    try { await unlink(path); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  };
  const importBackupDir = (backupId: string): string => join(configDir, `${IMPORT_BACKUP_PREFIX}${backupId}`);
  const importReceiptPath = (backupId: string): string => join(importBackupDir(backupId), "receipt.json");
  const importBackupPath = (backupId: string): string => join(importBackupDir(backupId), "previous.bin");
  const importMachineBackupPath = (backupId: string): string => join(importBackupDir(backupId), "machine.bin");
  const importTempPattern = /^\.(receipt\.json|previous\.bin|machine\.bin)\.(\d+)\.([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.tmp$/i;
  const validateBackupId = (backupId: string): void => {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(backupId)) throw new Error("backup ID 非法");
  };
  const parseImportRecord = (raw: string, label: string): ImportRecord => {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (parsed.version !== 1 || typeof parsed.backupId !== "string" || typeof parsed.previousPresent !== "boolean"
      || (parsed.previousPresent ? typeof parsed.previousHash !== "string" || parsed.previousHash.length !== 64 : parsed.previousHash !== undefined)
      || (parsed.machinePreviousPresent !== undefined && typeof parsed.machinePreviousPresent !== "boolean")
      || (parsed.machinePreviousPresent === true && (typeof parsed.machinePreviousHash !== "string" || parsed.machinePreviousHash.length !== 64))
      || (parsed.machinePreviousPresent === false && parsed.machinePreviousHash !== undefined)
      || typeof parsed.targetHash !== "string" || parsed.targetHash.length !== 64
      || (parsed.targetMachineHash !== undefined && (typeof parsed.targetMachineHash !== "string" || parsed.targetMachineHash.length !== 64))
      || (parsed.action !== undefined && parsed.action !== "apply" && parsed.action !== "rollback-cleanup" && parsed.action !== "finalize-cleanup")) throw new Error(`${label} 内容非法`);
    if (parsed.machinePreviousPresent === undefined) parsed.machinePreviousPresent = false;
    validateBackupId(parsed.backupId);
    return parsed as ImportRecord;
  };
  const readSecureBytes = async (path: string, label: string): Promise<Buffer | undefined> => {
    if (!await guardConfigDir(true)) return undefined;
    try {
      const before = await lstat(path);
      if (before.isSymbolicLink() || !before.isFile()) throw new Error(`${label} 必须是普通文件，不能是符号链接`);
      if (typeof before.uid === "number" && typeof process.getuid === "function" && before.uid !== process.getuid()) throw new Error(`${label} 所有者不是当前用户`);
      if ((before.mode & 0o077) !== 0) throw new Error(`${label} 权限必须为 0600`);
      if (before.size <= 0 || before.size > IMPORT_FILE_MAX_BYTES) throw new Error(`${label} 大小非法`);
      const handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
      try {
        const opened = await handle.stat();
        if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) throw new Error(`${label} 在打开前发生替换`);
        const bytes = await handle.readFile();
        const afterHandle = await handle.stat();
        const afterPath = await lstat(path);
        if (afterHandle.dev !== opened.dev || afterHandle.ino !== opened.ino || afterHandle.size !== bytes.length || afterHandle.uid !== before.uid || afterHandle.mode !== before.mode
          || afterPath.isSymbolicLink() || !afterPath.isFile() || afterPath.dev !== opened.dev || afterPath.ino !== opened.ino || afterPath.size !== bytes.length || afterPath.uid !== before.uid || afterPath.mode !== before.mode) {
          bytes.fill(0);
          throw new Error(`${label} 在读取期间发生替换`);
        }
        return bytes;
      } finally { await handle.close(); }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw error;
    }
  };
  const readImportRecord = async (path: string, label: string): Promise<ImportRecord | undefined> => {
    const bytes = await readSecureBytes(path, label);
    if (!bytes) return undefined;
    try { return parseImportRecord(bytes.toString("utf8"), label); }
    finally { bytes.fill(0); }
  };
  const listImportBackupIds = async (): Promise<string[]> => {
    if (!await guardConfigDir(true)) return [];
    const ids: string[] = [];
    for (const name of await readdir(configDir)) {
      if (!name.startsWith(IMPORT_BACKUP_PREFIX)) continue;
      const id = name.slice(IMPORT_BACKUP_PREFIX.length);
      validateBackupId(id);
      const info = await lstat(join(configDir, name));
      if (info.isSymbolicLink() || !info.isDirectory()) throw new Error(`import backup ${id} 必须是真实目录`);
      if (typeof info.uid === "number" && typeof process.getuid === "function" && info.uid !== process.getuid()) throw new Error(`import backup ${id} 所有者不是当前用户`);
      if ((info.mode & 0o077) !== 0) throw new Error(`import backup ${id} 权限必须为 0700`);
      ids.push(id);
    }
    return ids.sort();
  };
  type ImportFileSnapshot = { dev: number; ino: number; uid: number; mode: number; size: number };
  const snapshotImportFile = async (path: string, label: string): Promise<ImportFileSnapshot> => {
    const info = await lstat(path);
    if (info.isSymbolicLink() || !info.isFile()) throw new Error(`${label} 必须是普通文件`);
    if (typeof info.uid === "number" && typeof process.getuid === "function" && info.uid !== process.getuid()) throw new Error(`${label} 所有者不是当前用户`);
    if ((info.mode & 0o077) !== 0) throw new Error(`${label} 权限必须为 0600`);
    return { dev: info.dev, ino: info.ino, uid: info.uid, mode: info.mode, size: info.size };
  };
  const recheckImportFile = async (path: string, label: string, expected: ImportFileSnapshot): Promise<void> => {
    const current = await snapshotImportFile(path, label);
    if (current.dev !== expected.dev || current.ino !== expected.ino || current.uid !== expected.uid || current.mode !== expected.mode || current.size !== expected.size) throw new Error(`${label} 在 mutation 前发生替换`);
  };
  const requireImportTargetUnchanged = async (expected?: ImportFileSnapshot): Promise<void> => {
    if (expected) {
      await recheckImportFile(configPath, "config 凭据路径", expected);
      return;
    }
    try {
      await lstat(configPath);
      throw new Error("config 凭据路径在 import mutation 前被创建");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  };
  const recheckImportTargetContent = async (expected: ImportFileSnapshot, expectedHash: string): Promise<void> => {
    await recheckImportFile(configPath, "config 凭据路径", expected);
    const current = await readSecureBytes(configPath, "config 凭据路径");
    try {
      if (!current || sha256(current) !== expectedHash) throw new Error("config 凭据内容在 import cleanup 前发生变化");
    } finally { current?.fill(0); }
    await recheckImportFile(configPath, "config 凭据路径", expected);
  };
  const recheckMachineTargetContent = async (expected: ImportFileSnapshot, expectedHash: string): Promise<void> => {
    await recheckImportFile(machineIdPath, "machine ID 文件", expected);
    const current = await readSecureBytes(machineIdPath, "machine ID 文件");
    try {
      if (!current || sha256(current) !== expectedHash) throw new Error("machine ID 文件内容在 import cleanup 前发生变化");
    } finally { current?.fill(0); }
    await recheckImportFile(machineIdPath, "machine ID 文件", expected);
  };
  const readMachineHash = async (): Promise<string | undefined> => {
    const current = await readSecureBytes(machineIdPath, "machine ID 文件");
    try { return current ? sha256(current) : undefined; } finally { current?.fill(0); }
  };
  const ensureMachineTarget = async (record: ImportRecord): Promise<void> => {
    if (!record.targetMachineHash) return;
    const currentHash = await readMachineHash();
    if (currentHash === record.targetMachineHash) return;
    if (currentHash !== undefined && currentHash !== record.machinePreviousHash) throw new Error("machine ID 文件内容在 import 恢复时发生变化");
    await writeAtomicBytes(machineIdPath, Buffer.from(`${machineId}\n`, "utf8"));
  };
  const restoreMachinePrevious = async (record: ImportRecord, previousMachine?: Buffer): Promise<void> => {
    if (!record.targetMachineHash) return;
    const currentHash = await readMachineHash();
    if (currentHash === record.machinePreviousHash) return;
    if (currentHash !== record.targetMachineHash) throw new Error("machine ID 文件内容在 import rollback 前发生变化");
    if (record.machinePreviousPresent) {
      if (!previousMachine) throw new Error("import previous machine evidence 缺失");
      await writeAtomicBytes(machineIdPath, previousMachine);
    } else {
      await removeIfExists(machineIdPath);
      await syncConfigDir();
    }
  };
  const sameImportRecord = (left: ImportRecord, right: ImportRecord): boolean => left.backupId === right.backupId
    && left.previousPresent === right.previousPresent && left.previousHash === right.previousHash
    && left.machinePreviousPresent === right.machinePreviousPresent && left.machinePreviousHash === right.machinePreviousHash
    && left.targetHash === right.targetHash && left.targetMachineHash === right.targetMachineHash;
  type ImportTempSnapshot = { name: string; path: string; target: string; targetName: "receipt.json" | "previous.bin" | "machine.bin"; dev: number; ino: number; uid: number; mode: number; size: number; nlink: number; contentHash: string; action: "cleanup" | "promote" };
  const normalizeImportNoReplaceTemps = async (backupId: string): Promise<void> => {
    validateBackupId(backupId);
    const dir = importBackupDir(backupId);
    const names = (await readdir(dir)).sort();
    const allowedFinals = new Set(["receipt.json", "previous.bin", "machine.bin"]);
    const tempNames = names.filter((name) => importTempPattern.test(name));
    const unknown = names.filter((name) => !allowedFinals.has(name) && !importTempPattern.test(name));
    if (unknown.length > 0) throw new Error(`import backup 含未知文件：${unknown.join(",")}`);
    const grouped = new Map<"receipt.json" | "previous.bin" | "machine.bin", string[]>();
    for (const name of tempNames) {
      const match = importTempPattern.exec(name)!;
      const targetName = match[1] as "receipt.json" | "previous.bin" | "machine.bin";
      grouped.set(targetName, [...(grouped.get(targetName) ?? []), name]);
    }
    for (const [targetName, candidates] of grouped) if (candidates.length > 1) throw new Error(`import ${targetName} 存在多个 orphan temp`);

    const receiptFinal = await readImportRecord(importReceiptPath(backupId), "import receipt");
    const receiptTempName = grouped.get("receipt.json")?.[0];
    let receiptTemp: ImportRecord | undefined;
    if (receiptTempName) {
      const bytes = await readSecureBytes(join(dir, receiptTempName), "import receipt temp");
      try { receiptTemp = parseImportRecord(bytes!.toString("utf8"), "import receipt temp"); }
      finally { bytes?.fill(0); }
      if (receiptTemp.backupId !== backupId) throw new Error("import receipt temp backup ID 不匹配");
    }
    if (receiptFinal && receiptTemp && !sameImportRecord(receiptFinal, receiptTemp)) throw new Error("import receipt final/temp 内容冲突");
    const authoritative = receiptFinal ?? receiptTemp;
    const previousFinal = await readSecureBytes(importBackupPath(backupId), "import previous backup");
    const previousTempName = grouped.get("previous.bin")?.[0];
    const previousTemp = previousTempName ? await readSecureBytes(join(dir, previousTempName), "import previous temp") : undefined;
    const machineFinal = await readSecureBytes(importMachineBackupPath(backupId), "import previous machine ID backup");
    const machineTempName = grouped.get("machine.bin")?.[0];
    const machineTemp = machineTempName ? await readSecureBytes(join(dir, machineTempName), "import previous machine ID temp") : undefined;
    try {
      if (!authoritative && (previousFinal || previousTemp || machineFinal || machineTemp)) throw new Error("import previous evidence 缺少可信 receipt");
      if (authoritative?.previousPresent === false && (previousFinal || previousTemp)) throw new Error("import previous evidence 与 receipt 冲突");
      if (authoritative?.machinePreviousPresent !== true && (machineFinal || machineTemp)) throw new Error("import previous machine evidence 与 receipt 冲突");
      for (const bytes of [previousFinal, previousTemp]) if (bytes && sha256(bytes) !== authoritative?.previousHash) throw new Error("import previous evidence hash 不匹配");
      for (const bytes of [machineFinal, machineTemp]) if (bytes && sha256(bytes) !== authoritative?.machinePreviousHash) throw new Error("import previous machine evidence hash 不匹配");
      if (previousFinal && previousTemp && !previousFinal.equals(previousTemp)) throw new Error("import previous final/temp 内容冲突");
      if (machineFinal && machineTemp && !machineFinal.equals(machineTemp)) throw new Error("import previous machine final/temp 内容冲突");
    } finally { previousFinal?.fill(0); previousTemp?.fill(0); machineFinal?.fill(0); machineTemp?.fill(0); }

    const snapshots: ImportTempSnapshot[] = [];
    for (const targetName of ["receipt.json", "previous.bin", "machine.bin"] as const) {
      const tempName = grouped.get(targetName)?.[0];
      if (!tempName) continue;
      const tempPath = join(dir, tempName), targetPath = join(dir, targetName);
      const tempStat = await lstat(tempPath);
      const bytes = await readSecureBytes(tempPath, `import ${targetName} temp`);
      const contentHash = sha256(bytes!);
      bytes?.fill(0);
      let targetStat: Awaited<ReturnType<typeof lstat>> | undefined;
      try { targetStat = await lstat(targetPath); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
      if (targetStat) {
        if (targetStat.isSymbolicLink() || !targetStat.isFile() || targetStat.dev !== tempStat.dev || targetStat.ino !== tempStat.ino || targetStat.nlink !== 2 || tempStat.nlink !== 2) throw new Error(`import ${targetName} temp/final identity 不匹配`);
        snapshots.push({ name: tempName, path: tempPath, target: targetPath, targetName, dev: tempStat.dev, ino: tempStat.ino, uid: tempStat.uid, mode: tempStat.mode, size: tempStat.size, nlink: 2, contentHash, action: "cleanup" });
      } else {
        if (tempStat.nlink !== 1) throw new Error(`import ${targetName} orphan temp link 数非法`);
        snapshots.push({ name: tempName, path: tempPath, target: targetPath, targetName, dev: tempStat.dev, ino: tempStat.ino, uid: tempStat.uid, mode: tempStat.mode, size: tempStat.size, nlink: 1, contentHash, action: "promote" });
      }
    }
    // 全量校验后统一 identity/content recheck，任何异常发生在首次 link/unlink 之前。
    const currentNames = (await readdir(dir)).sort();
    if (currentNames.length !== names.length || currentNames.some((name, index) => name !== names[index])) throw new Error("import temp 集合在恢复前发生变化");
    for (const snapshot of snapshots) {
      const stat = await lstat(snapshot.path);
      const bytes = await readSecureBytes(snapshot.path, `import ${snapshot.targetName} temp`);
      try {
        if (stat.dev !== snapshot.dev || stat.ino !== snapshot.ino || stat.uid !== snapshot.uid || stat.mode !== snapshot.mode || stat.size !== snapshot.size || stat.nlink !== snapshot.nlink || sha256(bytes!) !== snapshot.contentHash) throw new Error(`import ${snapshot.targetName} temp 在恢复前发生替换`);
      } finally { bytes?.fill(0); }
    }
    for (const snapshot of snapshots) {
      if (snapshot.action === "promote") {
        const handle = await open(snapshot.path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
        try {
          const opened = await handle.stat();
          if (opened.dev !== snapshot.dev || opened.ino !== snapshot.ino || opened.uid !== snapshot.uid || opened.mode !== snapshot.mode || opened.size !== snapshot.size || opened.nlink !== 1) throw new Error(`import ${snapshot.targetName} orphan temp 在发布前发生替换`);
          await publishFromFd(handle.fd, snapshot.target);
        } finally { await handle.close(); }
        const published = await readSecureBytes(snapshot.target, `import ${snapshot.targetName} promoted final`);
        try { if (!published || sha256(published) !== snapshot.contentHash) throw new Error(`import ${snapshot.targetName} orphan temp 发布后 hash 不匹配`); }
        finally { published?.fill(0); }
      }
      const beforeCleanup = await lstat(snapshot.path);
      if (beforeCleanup.dev !== snapshot.dev || beforeCleanup.ino !== snapshot.ino || beforeCleanup.uid !== snapshot.uid || beforeCleanup.mode !== snapshot.mode || beforeCleanup.size !== snapshot.size) throw new Error(`import ${snapshot.targetName} temp 在清理前发生替换`);
      await unlink(snapshot.path);
    }
    if (snapshots.length > 0) { await syncDirectory(dir); await syncConfigDir(); }
  };
  const readValidatedImportBundle = async (backupId: string): Promise<{ record: ImportRecord; previous?: Buffer; previousMachine?: Buffer; receiptSnapshot: ImportFileSnapshot; previousSnapshot?: ImportFileSnapshot; previousMachineSnapshot?: ImportFileSnapshot }> => {
    validateBackupId(backupId);
    const record = await readImportRecord(importReceiptPath(backupId), "import receipt");
    if (!record || record.backupId !== backupId) throw new Error("import receipt 不存在或 backup ID 不匹配");
    const names = (await readdir(importBackupDir(backupId))).sort();
    const expected = ["receipt.json", ...(record.previousPresent ? ["previous.bin"] : []), ...(record.machinePreviousPresent ? ["machine.bin"] : [])].sort();
    if (names.length !== expected.length || names.some((name, index) => name !== expected[index])) throw new Error("import backup 文件集合非法");
    const receiptSnapshot = await snapshotImportFile(importReceiptPath(backupId), "import receipt");
    const previous = record.previousPresent ? await readSecureBytes(importBackupPath(backupId), "import previous backup") : undefined;
    const previousSnapshot = record.previousPresent ? await snapshotImportFile(importBackupPath(backupId), "import previous backup") : undefined;
    const previousMachine = record.machinePreviousPresent ? await readSecureBytes(importMachineBackupPath(backupId), "import previous machine ID backup") : undefined;
    const previousMachineSnapshot = record.machinePreviousPresent ? await snapshotImportFile(importMachineBackupPath(backupId), "import previous machine ID backup") : undefined;
    if (record.previousPresent && (!previous || sha256(previous) !== record.previousHash)) {
      previous?.fill(0);
      throw new Error("import previous backup hash 不匹配");
    }
    if (record.machinePreviousPresent && (!previousMachine || sha256(previousMachine) !== record.machinePreviousHash)) {
      previous?.fill(0); previousMachine?.fill(0);
      throw new Error("import previous machine backup hash 不匹配");
    }
    return { record, previous, previousMachine, receiptSnapshot, previousSnapshot, previousMachineSnapshot };
  };
  const cleanupImportBundle = async (backupId: string, expected?: ImportRecord): Promise<void> => {
    validateBackupId(backupId);
    const dir = importBackupDir(backupId);
    let names: string[];
    try {
      const info = await lstat(dir);
      if (info.isSymbolicLink() || !info.isDirectory() || (info.mode & 0o077) !== 0) throw new Error("import backup cleanup 目录非法");
      if (typeof info.uid === "number" && typeof process.getuid === "function" && info.uid !== process.getuid()) throw new Error("import backup cleanup 所有者不是当前用户");
      names = (await readdir(dir)).sort();
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
      throw error;
    }
    if (names.some((name) => name !== "previous.bin" && name !== "machine.bin" && name !== "receipt.json")) throw new Error("import backup cleanup 文件集合非法");
    const receipt = await readImportRecord(importReceiptPath(backupId), "import receipt");
    if (receipt && expected && !sameImportRecord(receipt, expected)) throw new Error("import backup cleanup receipt 不匹配");
    if (!receipt && !expected) throw new Error("import backup cleanup 缺少 receipt");
    const authoritative = expected ?? receipt!;
    if (!receipt && names.includes("previous.bin")) throw new Error("import backup cleanup 缺少 receipt 但仍有 previous evidence");
    const previous = await readSecureBytes(importBackupPath(backupId), "import previous backup");
    const previousMachine = await readSecureBytes(importMachineBackupPath(backupId), "import previous machine ID backup");
    try {
      if (authoritative.previousPresent && !previous && receipt && expected?.action !== "rollback-cleanup" && expected?.action !== "finalize-cleanup") throw new Error("import backup cleanup 缺少 previous evidence");
      if (previous && (!authoritative.previousPresent || sha256(previous) !== authoritative.previousHash)) throw new Error("import backup cleanup previous hash 不匹配");
      if (authoritative.machinePreviousPresent && !previousMachine && receipt && expected?.action !== "rollback-cleanup" && expected?.action !== "finalize-cleanup") throw new Error("import backup cleanup 缺少 previous machine evidence");
      if (previousMachine && (!authoritative.machinePreviousPresent || sha256(previousMachine) !== authoritative.machinePreviousHash)) throw new Error("import backup cleanup previous machine hash 不匹配");
    } finally { previous?.fill(0); previousMachine?.fill(0); }
    const receiptSnapshot = receipt ? await snapshotImportFile(importReceiptPath(backupId), "import receipt") : undefined;
    const previousSnapshot = previous ? await snapshotImportFile(importBackupPath(backupId), "import previous backup") : undefined;
    const previousMachineSnapshot = previousMachine ? await snapshotImportFile(importMachineBackupPath(backupId), "import previous machine ID backup") : undefined;
    if (receiptSnapshot) await recheckImportFile(importReceiptPath(backupId), "import receipt", receiptSnapshot);
    if (previousSnapshot) await recheckImportFile(importBackupPath(backupId), "import previous backup", previousSnapshot);
    if (previousMachineSnapshot) await recheckImportFile(importMachineBackupPath(backupId), "import previous machine ID backup", previousMachineSnapshot);
    await removeIfExists(importBackupPath(backupId));
    await removeIfExists(importMachineBackupPath(backupId));
    await removeIfExists(importReceiptPath(backupId));
    await rmdir(dir);
    await syncConfigDir();
  };
  const removeImportBundle = async (backupId: string): Promise<void> => {
    const bundle = await readValidatedImportBundle(backupId);
    try { await cleanupImportBundle(backupId, bundle.record); }
    finally { bundle.previous?.fill(0); bundle.previousMachine?.fill(0); }
  };
  const assertNoRotationEvidence = async (): Promise<void> => {
    if (await readReservation() || await readRotationRecord(rotationPath, "rotation journal") || await readRotationRecord(emergencyRotationPath, "emergency rotation journal") || (await listRotationTempNames()).length > 0) throw new Error("凭据轮换证据存在，拒绝 import 操作");
  };
  const recoverImportLocked = async (): Promise<void> => {
    const pending = await readImportRecord(importPendingPath, "import pending journal");
    const ids = await listImportBackupIds();
    if (!pending) {
      if (ids.length > 1) throw new Error("存在多个 import backup，拒绝自动恢复");
      if (ids.length === 0) return;
      const backupId = ids[0]!;
      await normalizeImportNoReplaceTemps(backupId);
      const names = (await readdir(importBackupDir(backupId))).sort();
      if (names.length === 0) {
        // mkdir 后、receipt 发布前失败：目录不含凭据副本，可安全撤销。
        await rmdir(importBackupDir(backupId));
        await syncConfigDir();
        return;
      }
      const receipt = await readImportRecord(importReceiptPath(backupId), "import receipt");
      if (!receipt || receipt.backupId !== backupId) throw new Error("孤立 import backup 缺少可信 receipt");
      const current = await readSecureBytes(configPath, "config 凭据路径");
      const currentHash = current && sha256(current);
      current?.fill(0);
      const previousMatches = receipt.previousPresent ? currentHash === receipt.previousHash : currentHash === undefined;
      if (names.length === 1 && names[0] === "receipt.json") {
        if (!receipt.previousPresent && currentHash === receipt.targetHash) {
          await ensureMachineTarget(receipt);
          return;
        } // 首次导入的完整 committed receipt。
        if (!previousMatches) throw new Error("不完整 import backup 与当前 config 不一致");
        const receiptSnapshot = await snapshotImportFile(importReceiptPath(backupId), "import receipt");
        const recheckedReceipt = await readImportRecord(importReceiptPath(backupId), "import receipt");
        if (!recheckedReceipt || !sameImportRecord(recheckedReceipt, receipt)) throw new Error("不完整 import receipt 在清理前发生变化");
        await recheckImportFile(importReceiptPath(backupId), "import receipt", receiptSnapshot);
        await unlink(importReceiptPath(backupId));
        await rmdir(importBackupDir(backupId));
        await syncConfigDir();
        return;
      }
      const bundle = await readValidatedImportBundle(backupId);
      try {
        if (currentHash === bundle.record.targetHash) {
          await ensureMachineTarget(bundle.record);
          return;
        } // 已提交 receipt，等待显式 rollback/finalize。
        if (previousMatches) {
          // backup 已 durable 但 pending 尚未发布：网络/目标均未变化，可幂等撤销孤立备份。
          await restoreMachinePrevious(bundle.record, bundle.previousMachine);
          await removeImportBundle(bundle.record.backupId);
          return;
        }
        throw new Error("孤立 import backup 与当前 config 不一致");
      } finally { bundle.previous?.fill(0); bundle.previousMachine?.fill(0); }
    }
    if ((pending.action === "rollback-cleanup" || pending.action === "finalize-cleanup") && (ids.length === 0 || (ids.length === 1 && ids[0] === pending.backupId))) {
      const current = await readSecureBytes(configPath, "config 凭据路径");
      const currentHash = current && sha256(current);
      current?.fill(0);
      if (pending.action === "finalize-cleanup") {
        if (currentHash !== pending.targetHash) throw new Error("import finalize 恢复时目标 config 已被第三方修改");
        const machineHash = await readMachineHash();
        if (machineHash !== pending.targetMachineHash) throw new Error("import finalize 恢复时 machine ID 已被第三方修改");
      } else {
        const previousMatches = pending.previousPresent ? currentHash === pending.previousHash : currentHash === undefined;
        if (!previousMatches && currentHash !== pending.targetHash) throw new Error("import rollback 恢复时目标 config 已被第三方修改");
        if (!previousMatches) {
          const rollbackBundle = await readValidatedImportBundle(pending.backupId);
          try {
            if (!sameImportRecord(rollbackBundle.record, pending)) throw new Error("import rollback pending 与 receipt 不匹配");
            if (pending.previousPresent) await writeAtomicBytes(configPath, rollbackBundle.previous!);
            else { await unlink(configPath); await syncConfigDir(); }
            await restoreMachinePrevious(rollbackBundle.record, rollbackBundle.previousMachine);
          } finally { rollbackBundle.previous?.fill(0); rollbackBundle.previousMachine?.fill(0); }
        } else {
          const machineHash = await readMachineHash();
          const previousMachineMatches = pending.machinePreviousPresent ? machineHash === pending.machinePreviousHash : machineHash === undefined;
          if (!previousMachineMatches) throw new Error("import rollback 恢复时 machine ID 已被第三方修改");
        }
      }
      await cleanupImportBundle(pending.backupId, pending);
      await removeIfExists(importPendingPath);
      await syncConfigDir();
      return;
    }
    if (ids.length !== 1 || ids[0] !== pending.backupId) throw new Error("import pending 与 backup 集合不匹配");
    await normalizeImportNoReplaceTemps(pending.backupId);
    const bundle = await readValidatedImportBundle(pending.backupId);
    try {
      if (!sameImportRecord(bundle.record, pending)) throw new Error("import pending 与 receipt 不匹配");
      const current = await readSecureBytes(configPath, "config 凭据路径");
      const currentHash = current && sha256(current);
      current?.fill(0);
      if (currentHash === pending.targetHash) {
        await ensureMachineTarget(pending);
        await removeIfExists(importPendingPath);
        await syncConfigDir();
        return;
      }
      if ((pending.previousPresent && currentHash === pending.previousHash) || (!pending.previousPresent && currentHash === undefined)) {
        await restoreMachinePrevious(bundle.record, bundle.previousMachine);
        await removeIfExists(importPendingPath);
        await removeImportBundle(pending.backupId);
        return;
      }
      throw new Error("import 恢复时目标 config 已被第三方修改");
    } finally { bundle.previous?.fill(0); bundle.previousMachine?.fill(0); }
  };
  const recoverImport = async (): Promise<void> => {
    if (!await guardConfigDir(true)) return;
    const pending = await readImportRecord(importPendingPath, "import pending journal");
    const backups = await listImportBackupIds();
    if (!pending && backups.length === 0) return;
    await withMutationLock(recoverImportLocked);
  };
  const assertNoActiveImport = async (): Promise<void> => {
    if (await readImportRecord(importPendingPath, "import pending journal") || (await listImportBackupIds()).length > 0) throw new Error("存在未 finalize 的 import transaction/backup，拒绝凭据轮换或普通写入");
  };
  const cleanupRotationEvidence = async (rotation: RotationRecord | undefined, emergencyRecord: RotationRecord | undefined, reservation?: ReservationRecord): Promise<void> => {
    // 两阶段：全部 journal 的候选先完整验证并复核；任一异常时尚未 unlink，保证零 mutation。
    const rotationSnapshots = rotation ? await validateTrustedRotationTemps(rotationPath, rotation) : [];
    const emergencySnapshots = emergencyRecord ? await validateTrustedRotationTemps(emergencyRotationPath, emergencyRecord) : [];
    if (rotation) await recheckTrustedRotationTemps(rotationPath, rotationSnapshots);
    if (emergencyRecord) await recheckTrustedRotationTemps(emergencyRotationPath, emergencySnapshots);
    await mutateTrustedRotationTemps([...rotationSnapshots, ...emergencySnapshots]);
    if (rotation) await removeIfExists(rotationPath);
    if (emergencyRecord) await removeIfExists(emergencyRotationPath);
    if (reservation) await clearReservation(reservation.owner);
    else await syncConfigDir();
  };
  return {
    async load() {
      await recoverImport();
      const reservation = await readReservation();
      const rotation = await readRotationRecord(rotationPath, "rotation journal");
      const emergencyRecord = await readRotationRecord(emergencyRotationPath, "emergency rotation journal");
      if (reservation && await isReservationOwnerActive(reservation)) throw new Error("凭据轮换 owner 仍活跃，拒绝抢占恢复");
      for (const record of [rotation, emergencyRecord]) {
        if (record && reservation && (record.owner !== reservation.owner || record.baseCredentialHash !== reservation.baseCredentialHash)) throw new Error("rotation journal 与 reservation 不匹配");
      }
      if (rotation && emergencyRecord && !sameRotationTarget(rotation, emergencyRecord)) throw new Error("rotation journals 内容冲突");
      const config = await readCredential(configPath, "config 凭据路径");
      const recovery = rotation ?? emergencyRecord;
      if (recovery) {
        return withMutationLock(async () => {
          // 获得跨进程 mutation lock 后重新读取完整集合；锁外快照只用于尽早拒绝，不能授权 mutation。
          const lockedReservation = await readReservation();
          const lockedRotation = await readRotationRecord(rotationPath, "rotation journal");
          const lockedEmergency = await readRotationRecord(emergencyRotationPath, "emergency rotation journal");
          if (!lockedRotation && !lockedEmergency) throw new Error("rotation recovery 证据在取得 mutation lock 前消失");
          if (lockedRotation && lockedEmergency && !sameRotationTarget(lockedRotation, lockedEmergency)) throw new Error("rotation journals 内容冲突");
          for (const record of [lockedRotation, lockedEmergency]) {
            if (record && lockedReservation && (record.owner !== lockedReservation.owner || record.baseCredentialHash !== lockedReservation.baseCredentialHash)) throw new Error("rotation journal 与 reservation 不匹配");
          }
          const lockedRecovery = lockedRotation ?? lockedEmergency!;
          const evidence = await validateRecoveryEvidence(lockedRotation, lockedEmergency);
          const lockedConfig = await readCredential(configPath, "config 凭据路径");
          const currentHash = lockedConfig && credentialHash(lockedConfig);
          if (currentHash === lockedRecovery.targetCredentialHash) {
            await recheckRecoveryEvidence(evidence);
            await cleanupRotationEvidence(lockedRotation, lockedEmergency, lockedReservation);
            return lockedConfig!;
          }
          if (currentHash !== lockedRecovery.baseCredentialHash) throw new Error(lockedConfig ? "durable config 已变化，拒绝 rotation recovery 回滚" : "durable config 缺失，拒绝无 base 的 rotation recovery");
          await recheckRecoveryEvidence(evidence);
          await writeAtomic(configPath, lockedRecovery.credential);
          await cleanupRotationEvidence(lockedRotation, lockedEmergency, lockedReservation);
          return lockedRecovery.credential;
        });
      }
      if (reservation) {
        return withMutationLock(async () => {
          const lockedReservation = await readReservation();
          if (!lockedReservation || lockedReservation.owner !== reservation.owner) throw new Error("rotation reservation 在取得 mutation lock 前发生变化");
          const lockedRotation = await readRotationRecord(rotationPath, "rotation journal");
          const lockedEmergency = await readRotationRecord(emergencyRotationPath, "emergency rotation journal");
          if (lockedRotation || lockedEmergency) throw new Error("rotation journal 在取得 mutation lock 后出现，拒绝孤立恢复");
          const lockedConfig = await readCredential(configPath, "config 凭据路径");
          // 若 config 已经不再是 reservation 创建时的旧版本，说明提交完成后仅清理 marker 时崩溃；可幂等收尾。
          if (lockedConfig && credentialHash(lockedConfig) !== lockedReservation.baseCredentialHash) {
            await cleanupOwnerOrphanRotationTemps(lockedReservation, credentialHash(lockedConfig));
            await clearReservation(lockedReservation.owner);
            return lockedConfig;
          }
          if (lockedConfig) {
            const recovered = await recoverOwnerOrphanRotationTemp(lockedReservation, lockedConfig);
            if (recovered) return recovered;
          }
          if (lockedReservation.phase === "capability" && lockedConfig && credentialHash(lockedConfig) === lockedReservation.baseCredentialHash) {
            // capability 阶段尚未允许发送 refresh；dead owner 可安全清理隔离 namespace 和 reservation 后继续使用 base。
            await cleanupDeadCapabilityProbes();
            await clearReservation(lockedReservation.owner);
            return lockedConfig;
          }
          throw new Error("检测到未完成的凭据轮换，旧凭据已禁止使用");
        });
      }
      await assertNoRotationTemps();
      return config;
    },
    async isCommitted(v) {
      const current = await readCredential(configPath, "config 凭据路径");
      if (!current || credentialHash(current) !== credentialHash(v)) return false;
      return await readReservation() === undefined
        && await readRotationRecord(rotationPath, "rotation journal") === undefined
        && await readRotationRecord(emergencyRotationPath, "emergency rotation journal") === undefined
        && (await listRotationTempNames()).length === 0;
    },
    async isRotationStaged(v, owner) {
      const reservation = await requireReservationOwner(owner);
      const targetHash = credentialHash(v);
      const rotation = await readRotationRecord(rotationPath, "rotation journal");
      const emergencyRecord = await readRotationRecord(emergencyRotationPath, "emergency rotation journal");
      for (const record of [rotation, emergencyRecord]) {
        if (record && (record.owner !== owner || record.baseCredentialHash !== reservation.baseCredentialHash)) throw new Error("rotation journal owner/base 不匹配");
      }
      return rotation?.targetCredentialHash === targetHash || emergencyRecord?.targetCredentialHash === targetHash;
    },
    async reserveRotation(base, signal) {
      if (!await guardConfigDir(true)) await mkdir(configDir, { recursive: true, mode: 0o700 });
      return withMutationLock(async () => {
      if (!await guardConfigDir(true)) await mkdir(configDir, { recursive: true, mode: 0o700 });
      await guardConfigDir(false);
      await assertNoActiveImport();
      const owner = randomUUID();
      const startIdentity = await processStartIdentity();
      if (!startIdentity) throw new Error("无法取得当前进程启动身份，拒绝凭据轮换");
      const record: ReservationRecord = { version: 1, owner, processId: process.pid, processStartIdentity: startIdentity, baseCredentialHash: credentialHash(base), phase: "capability" };
      try {
        const f = await open(rotationReservationPath, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
        try { await f.writeFile(`${JSON.stringify(record)}\n`, "utf8"); await f.chmod(0o600); await f.sync(); } finally { await f.close(); }
        await syncConfigDir();
        ACTIVE_ROTATION_OWNERS.add(owner);
        try {
          await requireCurrentBase(record);
          if (await readRotationRecord(rotationPath, "rotation journal") || await readRotationRecord(emergencyRotationPath, "emergency rotation journal") || (await listRotationTempNames()).length > 0) throw new Error("存在待恢复的凭据轮换 journal/temp");
          await ensureFdPublicationSupported(signal);
        } catch (error) {
          await clearReservation(owner);
          throw error;
        }
        return owner;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
        await readReservation();
        throw new Error("已有凭据轮换正在进行");
      }
      });
    },
    async markRotationNetworkStarted(owner) {
      await withMutationLock(async () => {
        await assertNoActiveImport();
        const reservation = await requireReservationOwner(owner);
        if (reservation.phase === "refresh-started") return;
        if (reservation.phase !== "capability") throw new Error("旧版或未知 rotation reservation 阶段不可安全开始 refresh");
        await requireCurrentBase(reservation);
        await writeReservationRecord({ ...reservation, phase: "refresh-started" });
      });
    },
    async clearRotationReservation(owner) { await withMutationLock(() => clearReservation(owner)); },
    async stageRotation(v, owner) {
      return withMutationLock(async () => {
      await assertNoActiveImport();
      const reservation = await requireReservationOwner(owner);
      await requireCurrentBase(reservation);
      const record: RotationRecord = { version: 1, owner, artifactId: randomUUID(), baseCredentialHash: reservation.baseCredentialHash, targetCredentialHash: credentialHash(v), credential: v };
      let rotation = await readRotationRecord(rotationPath, "rotation journal");
      if (!rotation && await promoteOwnerOrphanRotationTemp(rotationPath, "rotation journal", reservation, record.targetCredentialHash)) rotation = await readRotationRecord(rotationPath, "rotation journal");
      if (rotation) {
        if (!sameRotationTarget(rotation, record)) throw new Error("rotation journal 与 owner/base/target 不一致");
        return;
      }
      const emergencyRecord = await readRotationRecord(emergencyRotationPath, "emergency rotation journal");
      if (emergencyRecord && !sameRotationTarget(emergencyRecord, record)) throw new Error("emergency rotation journal 与 owner/base/target 不一致");
      await publishRotationRecord(rotationPath, "rotation journal", record);
      if (emergencyRecord) {
        const snapshots = await validateTrustedRotationTemps(emergencyRotationPath, emergencyRecord);
        await recheckTrustedRotationTemps(emergencyRotationPath, snapshots);
        await mutateTrustedRotationTemps(snapshots);
        await removeIfExists(emergencyRotationPath);
        await syncConfigDir();
      }
      });
    },
    async stageEmergencyRotation(v, owner) {
      return withMutationLock(async () => {
      await assertNoActiveImport();
      const reservation = await requireReservationOwner(owner);
      await requireCurrentBase(reservation);
      const record: RotationRecord = { version: 1, owner, artifactId: randomUUID(), baseCredentialHash: reservation.baseCredentialHash, targetCredentialHash: credentialHash(v), credential: v };
      const existing = await readRotationRecord(emergencyRotationPath, "emergency rotation journal");
      if (!existing && await promoteOwnerOrphanRotationTemp(emergencyRotationPath, "emergency rotation journal", reservation, record.targetCredentialHash)) return;
      await publishRotationRecord(emergencyRotationPath, "emergency rotation journal", record);
      });
    },
    async save(v, owner) {
      if (!await guardConfigDir(true)) await mkdir(configDir, { recursive: true, mode: 0o700 });
      return withMutationLock(async () => {
      await assertNoActiveImport();
      const reservation = await readReservation();
      const rotation = await readRotationRecord(rotationPath, "rotation journal");
      const emergencyRecord = await readRotationRecord(emergencyRotationPath, "emergency rotation journal");
      if (reservation || rotation || emergencyRecord) {
        if (owner === undefined) throw new Error("活跃凭据轮换期间禁止无 owner save");
        const ownedReservation = await requireReservationOwner(owner);
        const current = await readCredential(configPath, "config 凭据路径");
        const currentHash = current && credentialHash(current);
        const targetHash = credentialHash(v);
        for (const record of [rotation, emergencyRecord]) {
          if (record && (record.owner !== owner || record.baseCredentialHash !== ownedReservation.baseCredentialHash || record.targetCredentialHash !== targetHash)) throw new Error("rotation journal 与 owner/base/target 不一致");
        }
        if (currentHash === targetHash) {
          // config 已提交但 journal/marker 清理中断：owner retry 只执行幂等 cleanup。
          await cleanupRotationEvidence(rotation, emergencyRecord, ownedReservation);
          return;
        }
        if (currentHash !== ownedReservation.baseCredentialHash) throw new Error("durable config 已变化，拒绝继续凭据轮换");
      } else if (owner !== undefined) {
        throw new Error("rotation reservation 不存在");
      }
      if (!reservation && !rotation && !emergencyRecord) await assertNoRotationTemps();
      await writeAtomic(configPath, v);
      if (rotation || emergencyRecord) await cleanupRotationEvidence(rotation, emergencyRecord, reservation);
      else if (owner !== undefined) await clearReservation(owner);
      else await syncConfigDir();
      });
    },
    async delete(owner) {
      if (!await guardConfigDir(true)) return;
      return withMutationLock(async () => {
      await recoverImportLocked();
      const importIds = await listImportBackupIds();
      if (importIds.length > 0) throw new Error("存在未 finalize 的 import backup，拒绝删除凭据");
      const reservation = await readReservation();
      const rotation = await readRotationRecord(rotationPath, "rotation journal");
      const emergencyRotation = await readRotationRecord(emergencyRotationPath, "emergency rotation journal");
      if (reservation || rotation || emergencyRotation) {
        if (owner === undefined) throw new Error("活跃凭据轮换期间禁止无 owner delete");
        await requireReservationOwner(owner);
      } else if (owner !== undefined) {
        throw new Error("rotation reservation 不存在");
      }
      const evidence = await validateRecoveryEvidence(rotation, emergencyRotation);
      await recheckRecoveryEvidence(evidence);
      await mutateTrustedRotationTemps([...evidence.rotationTemps, ...evidence.emergencyTemps]);
      if (!rotation && !emergencyRotation) {
        if (reservation && owner !== undefined) await cleanupOwnerOrphanRotationTemps(reservation);
        else await assertNoRotationTemps();
      }
      for (const path of [configPath, rotationPath, emergencyRotationPath, rotationReservationPath]) {
        await guardConfigDir(false);
        try {
          const fileStat = await lstat(path);
          if (fileStat.isSymbolicLink() || !fileStat.isFile()) throw new Error(`${basename(path)} 必须是普通文件，不能是符号链接`);
          await unlink(path);
        } catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e; }
      }
      });
    },
    async inspectImportTarget() {
      if (!await guardConfigDir(true)) return { exists: false };
      if (await readImportRecord(importPendingPath, "import pending journal")) throw new Error("存在未完成 import transaction，dry-run 拒绝自动修改");
      await assertNoRotationEvidence();
      const ids = await listImportBackupIds();
      if (ids.length > 0) throw new Error("存在未 finalize 的 import backup");
      return { exists: await readSecureBytes(configPath, "config 凭据路径") !== undefined };
    },
    async importStatus() {
      if (!await guardConfigDir(true)) return [];
      return withMutationLock(async () => {
        await recoverImportLocked();
        const pending = await readImportRecord(importPendingPath, "import pending journal");
        const ids = await listImportBackupIds();
        if (ids.length > 1) throw new Error("存在多个 import backup，状态歧义");
        if (pending && (ids.length !== 1 || ids[0] !== pending.backupId)) throw new Error("import pending 与 backup 集合不匹配");
        if (ids.length === 0) {
          if (pending) throw new Error("import pending 缺少 backup");
          return [];
        }
        await normalizeImportNoReplaceTemps(ids[0]!);
        const bundle = await readValidatedImportBundle(ids[0]!);
        try {
          if (pending && !sameImportRecord(pending, bundle.record)) throw new Error("import pending 与 receipt 不匹配");
          const state: ImportStatus["state"] = pending?.action === "rollback-cleanup" ? "pending-rollback"
            : pending?.action === "finalize-cleanup" ? "pending-finalize"
              : pending ? "pending-apply" : "committed";
          return [{ backupId: bundle.record.backupId, state }];
        } finally { bundle.previous?.fill(0); }
      });
    },
    async applyImport(v, replace) {
      if (!await guardConfigDir(true)) await mkdir(configDir, { recursive: true, mode: 0o700 });
      return withMutationLock(async () => {
        await recoverImportLocked();
        await assertNoRotationEvidence();
        if ((await listImportBackupIds()).length > 0) throw new Error("存在未 finalize 的 import backup");
        const current = await readSecureBytes(configPath, "config 凭据路径");
        const currentSnapshot = current ? await snapshotImportFile(configPath, "config 凭据路径") : undefined;
        const currentMachine = await readSecureBytes(machineIdPath, "machine ID 文件");
        const currentMachineSnapshot = currentMachine ? await snapshotImportFile(machineIdPath, "machine ID 文件") : undefined;
        let canonical: Buffer | undefined;
        let targetMachine: Buffer | undefined;
        try {
          if (current && !replace) throw new Error("目标凭据已存在，必须显式使用 --replace");
          canonical = Buffer.from(`${JSON.stringify(validate(v, machineIdHash))}\n`, "utf8");
          targetMachine = Buffer.from(`${machineId}\n`, "utf8");
          const record: ImportRecord = {
            version: 1,
            backupId: randomUUID(),
            previousPresent: current !== undefined,
            previousHash: current ? sha256(current) : undefined,
            machinePreviousPresent: currentMachine !== undefined,
            machinePreviousHash: currentMachine ? sha256(currentMachine) : undefined,
            targetHash: sha256(canonical),
            targetMachineHash: sha256(targetMachine),
            action: "apply",
          };
          const backupDir = importBackupDir(record.backupId);
          await mkdir(backupDir, { mode: 0o700 });
          await chmod(backupDir, 0o700);
          // 先发布不含秘密的 receipt，再备份旧原始字节；receipt-only 崩溃状态可依据 current==previousHash 安全撤销。
          await writeAtomicBytes(importReceiptPath(record.backupId), Buffer.from(`${JSON.stringify(record)}\n`, "utf8"), false);
          await dependencies.onImportPhase?.("after-receipt");
          if (current) await writeAtomicBytes(importBackupPath(record.backupId), current, false);
          if (currentMachine) await writeAtomicBytes(importMachineBackupPath(record.backupId), currentMachine, false);
          await dependencies.onImportPhase?.("after-backup");
          await writeAtomicBytes(importPendingPath, Buffer.from(`${JSON.stringify(record)}\n`, "utf8"));
          await dependencies.onImportPhase?.("after-pending");
          await requireImportTargetUnchanged(currentSnapshot);
          if (currentMachineSnapshot) await recheckImportFile(machineIdPath, "machine ID 文件", currentMachineSnapshot);
          else {
            try { await lstat(machineIdPath); throw new Error("machine ID 文件在 import mutation 前被创建"); }
            catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
          }
          let machinePublished = false;
          try {
            // 先发布 machine；若 auth 发布失败，立即按 receipt 恢复 machine，避免 auth 新而 machine 旧。
            await writeAtomicBytes(machineIdPath, targetMachine);
            machinePublished = true;
            await writeAtomicBytes(configPath, canonical);
          } catch (error) {
            if (machinePublished) {
              if (currentMachine) await writeAtomicBytes(machineIdPath, currentMachine);
              else { await removeIfExists(machineIdPath); await syncConfigDir(); }
            }
            throw error;
          }
          await dependencies.onImportPhase?.("after-replace");
          await removeIfExists(importPendingPath);
          await syncConfigDir();
          await dependencies.onImportPhase?.("after-pending-cleanup");
          return { backupId: record.backupId, replaced: record.previousPresent };
        } finally { current?.fill(0); currentMachine?.fill(0); canonical?.fill(0); targetMachine?.fill(0); }
      });
    },
    async rollbackImport(backupId) {
      if (!await guardConfigDir(true)) throw new Error("config 目录不存在");
      return withMutationLock(async () => {
        await recoverImportLocked();
        await assertNoRotationEvidence();
        const ids = await listImportBackupIds();
        if (ids.length !== 1 || ids[0] !== backupId) throw new Error("backup ID 不存在或 import evidence 歧义");
        const bundle = await readValidatedImportBundle(backupId);
        try {
          const current = await readSecureBytes(configPath, "config 凭据路径");
          const currentHash = current && sha256(current);
          const currentSnapshot = current ? await snapshotImportFile(configPath, "config 凭据路径") : undefined;
          const currentMachine = await readSecureBytes(machineIdPath, "machine ID 文件");
          const currentMachineHash = currentMachine && sha256(currentMachine);
          const currentMachineSnapshot = currentMachine ? await snapshotImportFile(machineIdPath, "machine ID 文件") : undefined;
          current?.fill(0); currentMachine?.fill(0);
          if (currentHash !== bundle.record.targetHash || !currentSnapshot || currentMachineHash !== bundle.record.targetMachineHash || !currentMachineSnapshot) throw new Error("当前凭据或 machine ID 已变化，拒绝 rollback");
          const cleanupRecord: ImportRecord = { ...bundle.record, action: "rollback-cleanup" };
          await writeAtomicBytes(importPendingPath, Buffer.from(`${JSON.stringify(cleanupRecord)}\n`, "utf8"));
          await dependencies.onImportPhase?.("after-rollback-pending");
          await dependencies.beforeImportTargetRecheck?.("rollback");
          await recheckImportTargetContent(currentSnapshot, bundle.record.targetHash);
          if (!currentMachineSnapshot) throw new Error("machine ID 文件在 rollback mutation 前缺失");
          await recheckMachineTargetContent(currentMachineSnapshot, bundle.record.targetMachineHash!);
          if (bundle.record.previousPresent) await writeAtomicBytes(configPath, bundle.previous!);
          else { await unlink(configPath); await syncConfigDir(); }
          await restoreMachinePrevious(bundle.record, bundle.previousMachine);
          await dependencies.onImportPhase?.("after-rollback-replace");
          await cleanupImportBundle(backupId, cleanupRecord);
          await removeIfExists(importPendingPath);
          await syncConfigDir();
        } finally { bundle.previous?.fill(0); bundle.previousMachine?.fill(0); }
      });
    },
    async finalizeImport(backupId) {
      if (!await guardConfigDir(true)) throw new Error("config 目录不存在");
      return withMutationLock(async () => {
        await recoverImportLocked();
        await assertNoRotationEvidence();
        const ids = await listImportBackupIds();
        if (ids.length !== 1 || ids[0] !== backupId) throw new Error("backup ID 不存在或 import evidence 歧义");
        const bundle = await readValidatedImportBundle(backupId);
        try {
          const current = await readSecureBytes(configPath, "config 凭据路径");
          const currentHash = current && sha256(current);
          const currentSnapshot = current ? await snapshotImportFile(configPath, "config 凭据路径") : undefined;
          const currentMachine = await readSecureBytes(machineIdPath, "machine ID 文件");
          const currentMachineHash = currentMachine && sha256(currentMachine);
          const currentMachineSnapshot = currentMachine ? await snapshotImportFile(machineIdPath, "machine ID 文件") : undefined;
          current?.fill(0); currentMachine?.fill(0);
          if (currentHash !== bundle.record.targetHash || !currentSnapshot || currentMachineHash !== bundle.record.targetMachineHash || !currentMachineSnapshot) throw new Error("当前凭据或 machine ID 已变化，拒绝 finalize");
          const cleanupRecord: ImportRecord = { ...bundle.record, action: "finalize-cleanup" };
          await writeAtomicBytes(importPendingPath, Buffer.from(`${JSON.stringify(cleanupRecord)}\n`, "utf8"));
          await dependencies.onImportPhase?.("after-finalize-pending");
          await dependencies.beforeImportTargetRecheck?.("finalize");
          await recheckImportTargetContent(currentSnapshot, bundle.record.targetHash);
          if (!currentMachineSnapshot) throw new Error("machine ID 文件在 finalize 前缺失");
          await recheckMachineTargetContent(currentMachineSnapshot, bundle.record.targetMachineHash!);
          await cleanupImportBundle(backupId, cleanupRecord);
          await removeIfExists(importPendingPath);
          await syncConfigDir();
        } finally { bundle.previous?.fill(0); bundle.previousMachine?.fill(0); }
      });
    },
  };
}

type PendingPersistence = {
  owner: RotationReservation;
  credential: StoredCredential;
  stageRequired: boolean;
  durableReached?: boolean;
  operation?: Promise<void>;
  durability?: Promise<void>;
  emergencyStore?: CredentialStore;
};
export class PendingPreflightPersistenceError extends Error {
  constructor(readonly pending: PendingPersistence, cause: unknown, private readonly legacyRetryDurability?: () => Promise<void>) {
    const detail = cause instanceof Error && cause.message.length > 0 ? `：${cause.message}` : "";
    super(`preflight 凭据轮换持久化失败；请修复安全存储后在当前进程重试 preflight，禁止重启${detail}`, { cause });
  }

  async drainToDurableJournal(): Promise<void> {
    if (this.pending.durableReached || !this.pending.stageRequired) return;
    if (this.pending.emergencyStore) {
      await startDurabilityOperation(this.pending.emergencyStore, this.pending);
      return;
    }
    if (!this.legacyRetryDurability) throw this.cause;
    await this.legacyRetryDurability();
    this.pending.stageRequired = false;
    this.pending.durableReached = true;
  }

  hasDurableRecoveryPoint(): boolean { return this.pending.durableReached === true || this.pending.stageRequired === false; }

  async stageEmergencyRecovery(): Promise<void> {
    // fallback 不能绕过 owner+credential single-flight；check 与 emergency write 都只在同一 operation 内串行执行。
    await this.drainToDurableJournal();
  }
}
const PENDING_PREFLIGHT_PERSISTENCE = new Map<string, PendingPersistence>();
function preflightPersistenceKey(env: Record<string, string | undefined>, machineId: string): string {
  return `${resolveConfigDir(env)}:${sha256(machineId)}`;
}

function startDurabilityOperation(store: CredentialStore, pending: PendingPersistence): Promise<void> {
  if (pending.durableReached || !pending.stageRequired) return Promise.resolve();
  if (pending.durability) return pending.durability;
  const operation = (async () => {
    // check/write 共享同一 owner+credential operation，不允许 deadline fallback 并发进入。
    if (await store.isRotationStaged?.(pending.credential, pending.owner)) {
      pending.durableReached = true;
      pending.stageRequired = false;
      return;
    }
    if (store.stageEmergencyRotation) await store.stageEmergencyRotation(pending.credential, pending.owner);
    else await store.stageRotation(pending.credential, pending.owner);
    pending.durableReached = true;
    pending.stageRequired = false;
  })();
  const tracked = operation.finally(() => {
    if (pending.durability === tracked) pending.durability = undefined;
  });
  tracked.catch(() => undefined);
  pending.durability = tracked;
  return tracked;
}

function startPersistenceOperation(store: CredentialStore, pending: PendingPersistence): Promise<void> {
  if (pending.operation) return pending.operation;
  const operation = (async () => {
    if (await store.isCommitted(pending.credential)) return;
    await startDurabilityOperation(store, pending);
    await store.save(pending.credential, pending.owner);
  })();
  const tracked = operation.finally(() => {
    if (pending.operation === tracked) pending.operation = undefined;
  });
  // 调用者可提前取消等待，但后台持久化事务仍由 pending owner 持有；永久观察拒绝，避免 unhandledRejection。
  tracked.catch(() => undefined);
  pending.operation = tracked;
  return tracked;
}

async function persistRotatedCredential(store: CredentialStore, pending: PendingPersistence, signal?: AbortSignal): Promise<void> {
  const operation = startPersistenceOperation(store, pending);
  await (signal ? raceWithSignal(operation, signal) : operation);
}

async function refreshWithReservedCommit(env: Record<string, string | undefined>, store: CredentialStore, stored: StoredCredential, signal?: AbortSignal, capabilitySignal?: AbortSignal): Promise<StoredCredential> {
  const owner = await store.reserveRotation(stored, capabilitySignal);
  let refreshed: StoredCredential | undefined;
  try {
    // capability 有独立短 timeout；网络阶段重新开始完整 refresh timeout，避免 probe 开销吞掉请求预算。
    signal?.throwIfAborted();
    await store.markRotationNetworkStarted?.(owner);
    const transactionSignal = signal ? AbortSignal.any([signal, AbortSignal.timeout(refreshTimeoutMs(env))]) : AbortSignal.timeout(refreshTimeoutMs(env));
    refreshed = await refreshStoredCredential(env, stored, transactionSignal);
    const pending: PendingPersistence = { owner, credential: refreshed, stageRequired: true, emergencyStore: store };
    try { await persistRotatedCredential(store, pending, transactionSignal); }
    catch (error) { throw new PendingPreflightPersistenceError(pending, error); }
    return refreshed;
  } catch (error) {
    if (!refreshed && !(error instanceof AmbiguousRefreshOutcomeError)) {
      try { await store.clearRotationReservation(owner); }
      catch { throw new Error("凭据轮换预留清理失败；已进入降级状态"); }
    }
    throw error;
  }
}

function nowSeconds(): number { return Math.floor(Date.now() / 1000); }
function refreshTimeoutMs(env: Record<string, string | undefined>): number {
  const value = env.QODER_PROXY_REFRESH_TIMEOUT_MS;
  if (value === undefined || value.length === 0) return DEFAULT_REFRESH_TIMEOUT_MS;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 && parsed <= MAX_REFRESH_TIMEOUT_MS ? parsed : DEFAULT_REFRESH_TIMEOUT_MS;
}
function capabilityTimeoutMs(env: Record<string, string | undefined>): number {
  const value = env.QODER_PROXY_CAPABILITY_TIMEOUT_MS;
  if (value === undefined || value.length === 0) return DEFAULT_CAPABILITY_TIMEOUT_MS;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 && parsed <= MAX_REFRESH_TIMEOUT_MS ? parsed : DEFAULT_CAPABILITY_TIMEOUT_MS;
}
function modelCatalogTtlMs(env: Record<string, string | undefined>): number {
  const value = env.QODER_PROXY_MODEL_CATALOG_TTL_MS;
  if (value === undefined || value.length === 0) return DEFAULT_MODEL_CATALOG_TTL_MS;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 1_000 && parsed <= MAX_MODEL_CATALOG_TTL_MS ? parsed : DEFAULT_MODEL_CATALOG_TTL_MS;
}
function modelCatalogTimeoutMs(env: Record<string, string | undefined>): number {
  const value = env.QODER_PROXY_MODEL_CATALOG_TIMEOUT_MS;
  if (value === undefined || value.length === 0) return DEFAULT_MODEL_CATALOG_TIMEOUT_MS;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 && parsed <= MAX_REFRESH_TIMEOUT_MS ? parsed : DEFAULT_MODEL_CATALOG_TIMEOUT_MS;
}
function quotaTtlMs(env: Record<string, string | undefined>): number {
  const value = env.QODER_PROXY_QUOTA_TTL_MS;
  if (value === undefined || value.length === 0) return DEFAULT_QUOTA_TTL_MS;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 1_000 && parsed <= MAX_QUOTA_TTL_MS ? parsed : DEFAULT_QUOTA_TTL_MS;
}
function quotaTimeoutMs(env: Record<string, string | undefined>): number {
  const value = env.QODER_PROXY_QUOTA_TIMEOUT_MS;
  if (value === undefined || value.length === 0) return DEFAULT_QUOTA_TIMEOUT_MS;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 && parsed <= MAX_REFRESH_TIMEOUT_MS ? parsed : DEFAULT_QUOTA_TIMEOUT_MS;
}
function canRefresh(stored: StoredCredential, now = nowSeconds()): boolean {
  return typeof stored.refreshToken === "string" && stored.refreshToken.length > 0 && (stored.refreshTokenExpiresAt === undefined || stored.refreshTokenExpiresAt > now);
}
function parseAbsoluteExpiry(value: unknown, field: string): number {
  if (typeof value === "number" && Number.isFinite(value) && value >= 0) return Math.floor(value);
  if (typeof value === "string" && value.length > 0) {
    const numeric = Number(value);
    if (Number.isFinite(numeric) && numeric >= 0) return Math.floor(numeric);
    const timestamp = Date.parse(value);
    if (Number.isFinite(timestamp) && timestamp >= 0) return Math.floor(timestamp / 1000);
  }
  throw new Error(`${field} 必须是有限非负 epoch 或有效时间字符串`);
}

function parseRelativeExpiry(value: unknown, field: string): number {
  if (typeof value === "number" && Number.isFinite(value) && value >= 0) return nowSeconds() + Math.floor(value);
  throw new Error(`${field} 必须是有限非负数`);
}

function parseExpiryFields(payload: Record<string, unknown>, absoluteField: string, relativeField: string): number | undefined {
  const hasAbsolute = Object.hasOwn(payload, absoluteField);
  const hasRelative = Object.hasOwn(payload, relativeField);
  const absolute = hasAbsolute ? parseAbsoluteExpiry(payload[absoluteField], absoluteField) : undefined;
  const relative = hasRelative ? parseRelativeExpiry(payload[relativeField], relativeField) : undefined;
  return absolute ?? relative;
}

class AmbiguousRefreshOutcomeError extends Error {
  constructor(cause: unknown) { super("device token refresh 结果不明确；旧 refresh token 已禁止再次使用", { cause }); }
}

export async function refreshStoredCredential(env: Record<string, string | undefined>, stored: StoredCredential, signal?: AbortSignal): Promise<StoredCredential> {
  const now = nowSeconds();
  if (!canRefresh(stored, now)) throw new Error("config refresh token 不可用或已过期");
  const openapiBase = requireCnAllowedUrl(env.QODER_OPENAPI_BASE ?? "https://openapi.qoder.com.cn", "OpenAPI base");
  let response: Response;
  try {
    response = await fetch(`${openapiBase}/api/v1/deviceToken/refresh`, {
      method: "POST",
      headers: { "content-type": "application/json", Accept: "application/json", "user-agent": `qoder/${requireCosyVersion(env)}` },
      body: JSON.stringify({ refresh_token: stored.refreshToken }), signal,
    });
  } catch (error) {
    throw new AmbiguousRefreshOutcomeError(error);
  }
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error(`device token refresh HTTP ${response.status}`);
  }
  try {
    const bodyPromise = response.text();
    const raw = signal ? await raceWithSignal(bodyPromise, signal) : await bodyPromise;
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error("response root invalid");
    const payload = parsed as Record<string, unknown>;
    if (typeof payload.device_token !== "string" || payload.device_token.length === 0) throw new Error("device_token missing");
    if (typeof payload.refresh_token !== "string" || payload.refresh_token.length === 0) throw new Error("refresh_token 必须是非空字符串");
    const expiresAt = parseExpiryFields(payload, "expires_at", "expires_in");
    const refreshTokenExpiresAt = parseExpiryFields(payload, "refresh_token_expires_at", "refresh_token_expires_in");
    return {
      ...stored,
      token: payload.device_token,
      refreshToken: payload.refresh_token,
      expiresAt,
      refreshTokenExpiresAt: refreshTokenExpiresAt ?? stored.refreshTokenExpiresAt,
    };
  } catch (error) {
    throw new AmbiguousRefreshOutcomeError(error);
  }
}

export async function fetchOpenApiUserInfo(b: Bridge, env: Record<string, string | undefined>, stored: StoredCredential, signal?: AbortSignal): Promise<AuthInputs> {
  const openapiBase = requireCnAllowedUrl(env.QODER_OPENAPI_BASE ?? "https://openapi.qoder.com.cn", "OpenAPI base");
  const resp = await fetch(`${openapiBase}/api/v1/userinfo`, { headers: { Accept: "application/json", Authorization: `Bearer ${stored.token}` }, signal });
  const raw = await resp.text();
  if (resp.status !== 200) { const error = new Error(`userinfo HTTP ${resp.status}`) as Error & { status?: number }; error.status = resp.status; throw error; }
  const openApiUserinfo = JSON.parse(decryptOrPlain(b, raw)) as Record<string, unknown>;
  const uid = openApiUserinfo.id ?? openApiUserinfo.user_id ?? stored.userId ?? "";
  if (typeof uid !== "string" || !uid) throw new Error("userinfo 未提供有效 uid");
  return { uid, organization_id: openApiUserinfo.orgId ?? openApiUserinfo.organizationId ?? (openApiUserinfo.organization as Record<string, unknown> | undefined)?.id ?? "", organization_tags: openApiUserinfo.organizationTags, data_policy_agreed: true };
}

export function createAuthContext(b: Bridge, env: Record<string, string | undefined>, auth: AuthInputs): QoderContext {
  const machineId = requireMachineId(env);
  const runtimeInput = { uid: auth.uid, organization_id: auth.organization_id, organization_tags: auth.organization_tags, data_policy_agreed: auth.data_policy_agreed };
  const runtimeFields = JSON.parse(generateRuntimeAuthFields(b, JSON.stringify(runtimeInput))) as Record<string, unknown>;
  const userInfoForAuth = { uid: auth.uid, encrypt_user_info: runtimeFields.encrypt_user_info, key: runtimeFields.key, organization_id: auth.organization_id, organization_tags: auth.organization_tags, data_policy_agreed: auth.data_policy_agreed };
  return QoderContext.create(b, machineId, requireCosyVersion(env), JSON.stringify(userInfoForAuth), JSON.stringify(CN_WW_CLIENT_CONTEXT));
}

export class CatalogUpstreamError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = "CatalogUpstreamError";
  }
}

export class QuotaUpstreamError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = "QuotaUpstreamError";
  }
}

export function prepareSignedCatalogRequest(context: QoderContext, env: Record<string, string | undefined>): PreparedRequest {
  const gatewayBase = requireCnAllowedUrl(env.QODER_CN_INFER_BASE ?? "https://gateway.qoder.com.cn", "catalog base");
  const result = context.prepareRequest(gatewayBase, MODEL_CATALOG_PATH, "GET", "auth");
  try { return validatePreparedResult(result, "prepareRequest model catalog"); } finally { result.dispose(); }
}

async function readBoundedResponseText(response: Response, signal?: AbortSignal, maxBytes = MAX_MODEL_CATALOG_BYTES, label = "model catalog", upstreamError: (message: string) => Error = (message) => new CatalogUpstreamError(message)): Promise<string> {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    const parsed = Number(declaredLength);
    if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > maxBytes) {
      await response.body?.cancel().catch(() => undefined);
      throw upstreamError(`${label} response size invalid`);
    }
  }
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      signal?.throwIfAborted();
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > maxBytes) throw upstreamError(`${label} response too large`);
      chunks.push(next.value);
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder().decode(bytes);
}

export async function fetchOfficialModelCatalog(context: QoderContext, env: Record<string, string | undefined>, bridge: Bridge, signal?: AbortSignal): Promise<QoderAssistantModel[]> {
  const prepared = prepareSignedCatalogRequest(context, env);
  let response: Response;
  try {
    response = await fetch(prepared.url, { method: "GET", headers: prepared.headers, signal });
  } catch (error) {
    if (signal?.aborted) throw signal.reason ?? error;
    throw new CatalogUpstreamError("model catalog network failure");
  }
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw new CatalogUpstreamError(`model catalog HTTP ${response.status}`, response.status);
  }
  const encryptedOrPlain = await readBoundedResponseText(response, signal);
  let parsed: unknown;
  try {
    parsed = JSON.parse(decryptOrPlain(bridge, encryptedOrPlain));
  } catch {
    throw new CatalogUpstreamError("model catalog response invalid");
  }
  return parseQoderAssistantCatalog(parsed);
}

function quotaResponseObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new QuotaUpstreamError(`quota response ${label} invalid`);
  return value as Record<string, unknown>;
}
function quotaField(source: Record<string, unknown>, snake: string, camel: string, _label: string): unknown {
  // 与官方 normalizer 一致：snake case 优先，camel case 作为兼容回退。
  return source[snake] ?? source[camel];
}
function quotaNumber(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) throw new QuotaUpstreamError(`quota response ${label} invalid`);
  return value;
}
function quotaString(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) throw new QuotaUpstreamError(`quota response ${label} invalid`);
  return value;
}
function quotaBoolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new QuotaUpstreamError(`quota response ${label} invalid`);
  return value;
}
function quotaPercentage(value: unknown, label: string): number {
  const raw = quotaNumber(value, label);
  const percent = raw <= 1 ? raw * 100 : raw;
  return Math.round((percent + Number.EPSILON) * 100) / 100;
}
function quotaExpiresAt(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) throw new QuotaUpstreamError("quota response expires_at invalid");
  return value;
}
function normalizeQuotaBucket(value: unknown, label: string): QoderQuotaBucket {
  const source = quotaResponseObject(value, label);
  return Object.freeze({
    total: quotaNumber(source.total, `${label}.total`),
    used: quotaNumber(source.used, `${label}.used`),
    remaining: quotaNumber(source.remaining, `${label}.remaining`),
    percentage: quotaPercentage(source.percentage, `${label}.percentage`),
    unit: quotaString(source.unit, `${label}.unit`, MAX_QUOTA_UNIT_LENGTH),
  });
}
function normalizeSharedQuota(value: unknown, label: string): NonNullable<QoderQuotaUsage["orgResourcePackage"]> {
  const source = quotaResponseObject(value, label);
  const cap = source.cap ?? source.total;
  return Object.freeze({
    used: quotaNumber(source.used, `${label}.used`),
    cap: quotaNumber(cap, `${label}.cap`),
    remaining: quotaNumber(source.remaining, `${label}.remaining`),
    percentage: quotaPercentage(source.percentage, `${label}.percentage`),
    available: quotaBoolean(source.available, `${label}.available`),
    unit: quotaString(source.unit, `${label}.unit`, MAX_QUOTA_UNIT_LENGTH),
  });
}

export function normalizeQoderQuotaUsage(value: unknown): QoderQuotaUsage {
  const source = quotaResponseObject(value, "root");
  // 仅用作上游响应完整性证明；用户身份不得进入 DTO、缓存或日志。
  quotaString(quotaField(source, "user_id", "userId", "user_id"), "user_id", MAX_QUOTA_IDENTITY_LENGTH);
  quotaString(quotaField(source, "user_type", "userType", "user_type"), "user_type", MAX_QUOTA_IDENTITY_LENGTH);
  const orgResourcePackage = quotaField(source, "org_resource_package", "orgResourcePackage", "org_resource_package");
  const sharedQuota = quotaField(source, "shared_quota", "sharedQuota", "shared_quota");
  if (orgResourcePackage !== undefined && sharedQuota !== undefined) throw new QuotaUpstreamError("quota response shared quota ambiguous");
  const addOnSource = quotaField(source, "add_on_quota", "addOnQuota", "add_on_quota");
  let addOnQuota: QoderQuotaUsage["addOnQuota"];
  if (addOnSource !== undefined) {
    const bucket = normalizeQuotaBucket(addOnSource, "add_on_quota");
    const detailSource = quotaResponseObject(addOnSource, "add_on_quota");
    addOnQuota = Object.freeze({ ...bucket, detailUrl: quotaString(quotaField(detailSource, "detail_url", "detailUrl", "add_on_quota.detail_url"), "add_on_quota.detail_url", MAX_QUOTA_DETAIL_URL_LENGTH) });
  }
  return Object.freeze({
    totalUsagePercentage: quotaPercentage(quotaField(source, "total_usage_percentage", "totalUsagePercentage", "total_usage_percentage"), "total_usage_percentage"),
    expiresAt: quotaExpiresAt(quotaField(source, "expires_at", "expiresAt", "expires_at")),
    userQuota: normalizeQuotaBucket(quotaField(source, "user_quota", "userQuota", "user_quota"), "user_quota"),
    ...(addOnQuota ? { addOnQuota } : {}),
    ...((orgResourcePackage !== undefined || sharedQuota !== undefined) ? { orgResourcePackage: normalizeSharedQuota(orgResourcePackage ?? sharedQuota, orgResourcePackage !== undefined ? "org_resource_package" : "shared_quota") } : {}),
    isQuotaExceeded: quotaBoolean(quotaField(source, "is_quota_exceeded", "isQuotaExceeded", "is_quota_exceeded"), "is_quota_exceeded"),
  });
}

export async function fetchOfficialQoderQuota(env: Record<string, string | undefined>, stored: StoredCredential, bridge: Bridge, signal?: AbortSignal): Promise<QoderQuotaUsage> {
  const openapiBase = requireCnAllowedUrl(env.QODER_OPENAPI_BASE ?? "https://openapi.qoder.com.cn", "OpenAPI base");
  let response: Response;
  try {
    response = await fetch(`${openapiBase}${QUOTA_USAGE_PATH}`, { method: "GET", headers: { Accept: "application/json", Authorization: `Bearer ${stored.token}` }, signal });
  } catch (error) {
    if (signal?.aborted) throw signal.reason ?? error;
    throw new QuotaUpstreamError("quota network failure");
  }
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw new QuotaUpstreamError(`quota HTTP ${response.status}`, response.status);
  }
  const raw = await readBoundedResponseText(response, signal, MAX_QUOTA_BYTES, "quota", (message) => new QuotaUpstreamError(message));
  try { return normalizeQoderQuotaUsage(JSON.parse(decryptOrPlain(bridge, raw))); }
  catch (error) {
    if (error instanceof QuotaUpstreamError) throw error;
    throw new QuotaUpstreamError("quota response invalid");
  }
}

export function prepareSignedInferRequest(context: QoderContext, env: Record<string, string | undefined>, cnBodyJson: string, modelKey: string): PreparedRequest {
  const inferBase = requireCnAllowedUrl(env.QODER_CN_INFER_BASE ?? "https://gateway.qoder.com.cn", "infer base");
  const result = context.prepareInferRequest(inferBase, cnBodyJson, modelKey, env.QODER_CN_INFER_SOURCE);
  try { return validatePreparedResult(result, "prepareInferRequest"); } finally { result.dispose(); }
}

function raceWithSignal<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const cleanup = () => signal.removeEventListener("abort", onAbort);
    const finish = (fn: () => void) => { if (!settled) { settled = true; cleanup(); fn(); } };
    const onAbort = () => finish(() => reject(signal.reason ?? new DOMException("Aborted", "AbortError")));
    // Attach ownership handlers before observing an already-aborted signal.
    promise.then(
      (value) => finish(() => resolve(value)),
      (error) => finish(() => reject(error)),
    );
    if (signal.aborted) onAbort();
    else signal.addEventListener("abort", onAbort, { once: true });
  });
}

function waitForRefresh(promise: Promise<void>, signal?: AbortSignal): Promise<void> {
  if (!signal) return promise;
  return raceWithSignal(promise, signal);
}

// QA attribution 不能影响共享 catalog/refresh single-flight 的产品语义；observer 自身异常被隔离，
// 但 catalog、refresh、签名和网络错误仍照常向调用者传播。
function recordRoutingObserver(observer: RoutingAttestationSessionObserver | undefined, method: "recordCatalogRemoteLoad" | "recordRefresh" | "recordRetry"): void {
  try { observer?.[method](); }
  catch { /* instrumentation-only；禁止 poison shared operation */ }
}

export type AuthSessionDependencies = {
  store?: CredentialStore;
  bridge?: Bridge;
  now?: () => number;
  catalogLoader?: (context: QoderContext, env: Record<string, string | undefined>, bridge: Bridge, signal?: AbortSignal) => Promise<QoderAssistantModel[]>;
  quotaLoader?: (env: Record<string, string | undefined>, stored: StoredCredential, bridge: Bridge, signal?: AbortSignal) => Promise<QoderQuotaUsage>;
};

function immutableCatalogSnapshot(models: readonly QoderAssistantModel[], generation: number): ModelCatalogSnapshot {
  const immutableModels = Object.freeze(models.map((model) => Object.freeze({ ...model })));
  return Object.freeze({ models: immutableModels, generation });
}

export class AuthSession {
  private refreshPromise: Promise<void> | undefined;
  private capabilityController: AbortController | undefined;
  private refreshWaiters = 0;
  private persistenceError: Error | undefined;
  private pendingPersistence: PendingPersistence | undefined;
  private fatalPersistenceError: Error | undefined;
  private modelCatalogCache: { snapshot: ModelCatalogSnapshot; expiresAt: number } | undefined;
  private modelCatalogPromise: Promise<ModelCatalogSnapshot> | undefined;
  private modelCatalogGeneration = 0;
  private quotaUsageCache: { usage: QoderQuotaUsage; expiresAt: number } | undefined;
  private quotaUsagePromise: Promise<QoderQuotaUsage> | undefined;
  private quotaUsageGeneration = 0;
  private constructor(private readonly env: Record<string, string | undefined>, private readonly machineId: string, private readonly store: CredentialStore, private readonly bridge: Bridge, private stored: StoredCredential, private auth: AuthInputs, private readonly dependencies: AuthSessionDependencies = {}) {}

  static async preflight(env: Record<string, string | undefined> = process.env, signal?: AbortSignal, dependencies?: AuthSessionDependencies): Promise<AuthSession> {
    const machineId = requireMachineId(env);
    requireCosyVersion(env);
    const store = dependencies?.store ?? createConfigStore(machineId, env);
    const pendingKey = preflightPersistenceKey(env, machineId);
    const pending = PENDING_PREFLIGHT_PERSISTENCE.get(pendingKey);
    const timeoutSignal = AbortSignal.timeout(refreshTimeoutMs(env));
    const preflightSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;
    let stored: StoredCredential;
    if (pending) {
      try {
        await persistRotatedCredential(store, pending, preflightSignal);
        PENDING_PREFLIGHT_PERSISTENCE.delete(pendingKey);
        stored = pending.credential;
      } catch (error) {
        pending.emergencyStore = store;
        throw new PendingPreflightPersistenceError(pending, error);
      }
    } else {
      const loaded = await store.load();
      if (!loaded) throw new Error("无可用凭据（config store 为空）");
      stored = loaded;
    }
    const bridge = dependencies?.bridge ?? await loadAuthBridge(env);
    if (!pending && stored.expiresAt !== undefined && stored.expiresAt <= nowSeconds()) {
      try { stored = await refreshWithReservedCommit(env, store, stored, signal, signal); }
      catch (error) {
        if (error instanceof PendingPreflightPersistenceError) PENDING_PREFLIGHT_PERSISTENCE.set(pendingKey, error.pending);
        throw error;
      }
    }
    let auth: AuthInputs;
    try { auth = await fetchOpenApiUserInfo(bridge, env, stored, preflightSignal); }
    catch (e) {
      if ((e as { status?: number }).status !== 401 && (e as { status?: number }).status !== 403) throw e;
      if (!canRefresh(stored)) throw e;
      try { stored = await refreshWithReservedCommit(env, store, stored, signal, signal); }
      catch (error) {
        if (error instanceof PendingPreflightPersistenceError) PENDING_PREFLIGHT_PERSISTENCE.set(pendingKey, error.pending);
        throw error;
      }
      auth = await fetchOpenApiUserInfo(bridge, env, stored, preflightSignal);
    }
    return new AuthSession(env, machineId, store, bridge, stored, auth, dependencies);
  }

  private invalidateModelCatalog(): void {
    this.modelCatalogGeneration++;
    this.modelCatalogCache = undefined;
    // 保留当前 promise 作为 single-flight owner；等待者会在 generation 不匹配时统一重载，
    // 避免 refresh 期间出现第二条并发目录请求，也避免旧结果写回新凭据 generation。
  }

  private invalidateQuotaUsage(): void {
    this.quotaUsageGeneration++;
    this.quotaUsageCache = undefined;
  }

  private async loadModelCatalogAttempt(signal: AbortSignal): Promise<QoderAssistantModel[]> {
    if (this.fatalPersistenceError) throw this.fatalPersistenceError;
    if (this.pendingPersistence) throw this.persistenceError ?? new Error("凭据轮换持久化未完成，禁止读取模型目录");
    if (this.dependencies.catalogLoader) return this.dependencies.catalogLoader({} as QoderContext, this.env, this.bridge, signal);
    const context = createAuthContext(this.bridge, this.env, this.auth);
    try { return await fetchOfficialModelCatalog(context, this.env, this.bridge, signal); }
    finally { context.dispose(); }
  }

  private async loadQuotaUsageAttempt(signal: AbortSignal): Promise<QoderQuotaUsage> {
    if (this.fatalPersistenceError) throw this.fatalPersistenceError;
    if (this.pendingPersistence) throw this.persistenceError ?? new Error("凭据轮换持久化未完成，禁止读取 quota");
    return this.dependencies.quotaLoader
      ? this.dependencies.quotaLoader(this.env, this.stored, this.bridge, signal)
      : fetchOfficialQoderQuota(this.env, this.stored, this.bridge, signal);
  }

  async getQuotaUsage(signal?: AbortSignal): Promise<QoderQuotaUsage> {
    while (true) {
      const now = this.dependencies.now?.() ?? Date.now();
      if (this.quotaUsageCache && this.quotaUsageCache.expiresAt > now) return this.quotaUsageCache.usage;
      if (!this.quotaUsagePromise) {
        const loadGeneration = ++this.quotaUsageGeneration;
        this.quotaUsageCache = undefined;
        const operation = (async () => {
          const operationSignal = AbortSignal.timeout(quotaTimeoutMs(this.env));
          let generation = loadGeneration;
          let usage: QoderQuotaUsage;
          try { usage = await this.loadQuotaUsageAttempt(operationSignal); }
          catch (error) {
            if (!(error instanceof QuotaUpstreamError) || error.status !== 401) throw error;
            await this.refreshAndReauthenticate(operationSignal);
            generation = this.quotaUsageGeneration;
            usage = await this.loadQuotaUsageAttempt(operationSignal);
          }
          return { usage, generation };
        })();
        const tracked = operation.then((result) => {
          if (result.generation === this.quotaUsageGeneration) {
            const loadedAt = this.dependencies.now?.() ?? Date.now();
            this.quotaUsageCache = { usage: result.usage, expiresAt: loadedAt + quotaTtlMs(this.env) };
          }
          return result.usage;
        }).finally(() => {
          if (this.quotaUsagePromise === tracked) this.quotaUsagePromise = undefined;
        });
        tracked.catch(() => undefined);
        this.quotaUsagePromise = tracked;
      }
      const shared = this.quotaUsagePromise;
      const usage = signal ? await raceWithSignal(shared, signal) : await shared;
      if (this.quotaUsageCache?.usage === usage) return usage;
      // 读取期间凭据刷新：丢弃旧结果，在同一调用内重新加载。
    }
  }

  async listModels(signal?: AbortSignal, routingAttestation?: RoutingAttestationSessionObserver): Promise<ModelCatalogSnapshot> {
    while (true) {
      const now = this.dependencies.now?.() ?? Date.now();
      if (this.modelCatalogCache && this.modelCatalogCache.expiresAt > now) return this.modelCatalogCache.snapshot;
      if (!this.modelCatalogPromise) {
        // 每次远端目录加载开始时都推进 generation，使旧 snapshot 立即失去签名资格。
        // 这样 TTL 到期后的并发请求不会在新目录即将替换时继续使用旧 entitlement。
        const loadGeneration = ++this.modelCatalogGeneration;
        this.modelCatalogCache = undefined;
        const observer = routingAttestation;
        const operation = (async () => {
          const operationSignal = AbortSignal.timeout(modelCatalogTimeoutMs(this.env));
          let generation = loadGeneration;
          let models: QoderAssistantModel[];
          try {
            recordRoutingObserver(observer, "recordCatalogRemoteLoad");
            models = await this.loadModelCatalogAttempt(operationSignal);
          } catch (error) {
            if (!(error instanceof CatalogUpstreamError) || error.status !== 401) throw error;
            await this.refreshAndReauthenticate(operationSignal, observer);
            generation = this.modelCatalogGeneration;
            recordRoutingObserver(observer, "recordRetry");
            recordRoutingObserver(observer, "recordCatalogRemoteLoad");
            models = await this.loadModelCatalogAttempt(operationSignal);
          }
          return immutableCatalogSnapshot(models, generation);
        })();
        const tracked = operation.then((snapshot) => {
          if (snapshot.generation === this.modelCatalogGeneration) {
            const loadedAt = this.dependencies.now?.() ?? Date.now();
            this.modelCatalogCache = { snapshot, expiresAt: loadedAt + modelCatalogTtlMs(this.env) };
          }
          return snapshot;
        }).finally(() => {
          if (this.modelCatalogPromise === tracked) this.modelCatalogPromise = undefined;
        });
        tracked.catch(() => undefined);
        this.modelCatalogPromise = tracked;
      }
      const shared = this.modelCatalogPromise;
      const snapshot = signal ? await raceWithSignal(shared, signal) : await shared;
      if (snapshot.generation === this.modelCatalogGeneration) return snapshot;
      // 读取过程中凭据发生刷新：丢弃旧 generation 的目录，并在同一调用内重新加载。
    }
  }

  async refreshAndReauthenticate(signal?: AbortSignal, routingAttestation?: RoutingAttestationSessionObserver): Promise<void> {
    if (this.fatalPersistenceError) throw this.fatalPersistenceError;
    this.refreshWaiters++;
    if (!this.refreshPromise) {
      recordRoutingObserver(routingAttestation, "recordRefresh");
      const timeoutMs = refreshTimeoutMs(this.env);
      const operation = (async () => {
        let owner: RotationReservation;
        if (this.pendingPersistence) {
          const pending = this.pendingPersistence;
          // 服务器轮换已经发生：这里只允许重试持久化，不得再次调用 refresh endpoint。
          try {
            await persistRotatedCredential(this.store, pending, AbortSignal.timeout(timeoutMs));
            this.pendingPersistence = undefined;
            this.persistenceError = undefined;
          } catch (error) {
            this.persistenceError = error instanceof Error ? error : new Error("凭据轮换持久化仍失败或等待超时；后台 owner 保留，请修复安全存储后重试，禁止重启或继续推理", { cause: error });
            throw this.persistenceError;
          }
          const userInfoSignal = AbortSignal.timeout(timeoutMs);
          const auth = await fetchOpenApiUserInfo(this.bridge, this.env, pending.credential, userInfoSignal);
          userInfoSignal.throwIfAborted();
          this.auth = auth;
          this.invalidateModelCatalog();
          this.invalidateQuotaUsage();
          return;
        }
        const capabilityController = new AbortController();
        this.capabilityController = capabilityController;
        const capabilitySignal = AbortSignal.any([capabilityController.signal, AbortSignal.timeout(capabilityTimeoutMs(this.env))]);
        try { owner = await this.store.reserveRotation(this.stored, capabilitySignal); }
        finally { if (this.capabilityController === capabilityController) this.capabilityController = undefined; }
        let rotated = false;
        const refreshSignal = AbortSignal.timeout(timeoutMs);
        let refreshed: StoredCredential;
        try {
          await this.store.markRotationNetworkStarted?.(owner);
          refreshed = await refreshStoredCredential(this.env, this.stored, refreshSignal);
          rotated = true;
        } catch (error) {
          if (!rotated && error instanceof AmbiguousRefreshOutcomeError) {
            this.fatalPersistenceError = error;
            throw error;
          }
          if (!rotated) {
            try { await this.store.clearRotationReservation(owner); }
            catch {
              this.fatalPersistenceError = new Error("凭据轮换预留清理失败；会话已进入降级状态");
              throw this.fatalPersistenceError;
            }
          }
          throw error;
        }

        // refresh 响应可能已经使旧 refresh token 失效：新凭据立即成为进程内权威状态。
        // 持久化操作由 pending owner 后台持有；会话等待有界，但超时或调用方取消都不会清除 owner 或重放旧 token。
        this.stored = refreshed;
        this.invalidateModelCatalog();
        this.invalidateQuotaUsage();
        const pending: PendingPersistence = { owner, credential: refreshed, stageRequired: true, emergencyStore: this.store };
        this.pendingPersistence = pending;
        try {
          await persistRotatedCredential(this.store, pending, AbortSignal.timeout(timeoutMs));
          this.pendingPersistence = undefined;
          this.persistenceError = undefined;
        } catch (error) {
          this.persistenceError = pending.stageRequired
            ? new Error("凭据轮换暂存失败或等待超时；后台 owner 保留，请修复安全存储后重试，禁止重启或继续推理", { cause: error })
            : error instanceof Error ? error : new Error("凭据轮换持久化失败或等待超时；后台 owner 保留，请修复安全存储后重试，禁止重启或继续推理", { cause: error });
          throw this.persistenceError;
        }

        const userInfoSignal = AbortSignal.timeout(timeoutMs);
        const auth = await fetchOpenApiUserInfo(this.bridge, this.env, refreshed, userInfoSignal);
        userInfoSignal.throwIfAborted();
        this.auth = auth;
      })();
      const tracked = operation.finally(() => {
        if (this.refreshPromise === tracked) this.refreshPromise = undefined;
      });
      // Install a permanent rejection observer before caller-specific cancellation can return early.
      tracked.catch(() => undefined);
      this.refreshPromise = tracked;
    }
    try { return await waitForRefresh(this.refreshPromise, signal); }
    finally {
      this.refreshWaiters--;
      if (this.refreshWaiters === 0 && this.capabilityController && !this.capabilityController.signal.aborted) {
        this.capabilityController.abort(signal?.reason ?? new DOMException("No active refresh waiters", "AbortError"));
      }
    }
  }

  createSignedAttempt(cnBodyJson: string, modelKey: string, catalogGeneration: number): SignedAttempt {
    if (this.fatalPersistenceError) throw this.fatalPersistenceError;
    if (this.pendingPersistence) throw this.persistenceError ?? new Error("凭据轮换持久化未完成，禁止继续推理");
    if (catalogGeneration !== this.modelCatalogGeneration || !this.modelCatalogCache || this.modelCatalogCache.snapshot.generation !== catalogGeneration || !this.modelCatalogCache.snapshot.models.some((model) => model.key === modelKey)) {
      throw new StaleModelCatalogError();
    }
    // machineId exists solely to make the constructor invariant explicit; context is always fresh.
    if (!this.machineId) throw new Error("machine ID 不得为空");
    const context = createAuthContext(this.bridge, this.env, this.auth);
    try { return { context, prepared: prepareSignedInferRequest(context, this.env, cnBodyJson, modelKey), auth: this.auth }; }
    catch (e) { context.dispose(); throw e; }
  }
}

// 兼容旧调用点与测试；生产路径使用 AuthSession。
export async function buildSignedInferRequest(b: Bridge, env: Record<string, string | undefined>, stored: StoredCredential, cnBodyJson: string, modelKey: string, signal?: AbortSignal): Promise<SignedAttempt> {
  const auth = await fetchOpenApiUserInfo(b, env, stored, signal);
  const context = createAuthContext(b, env, auth);
  try { return { context, prepared: prepareSignedInferRequest(context, env, cnBodyJson, modelKey), auth }; } catch (e) { context.dispose(); throw e; }
}
