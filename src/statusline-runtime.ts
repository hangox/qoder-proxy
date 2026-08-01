// Qoder managed statusline runtime 校验：只返回非秘密 lease 身份，不携带 token。
import { spawnSync } from "node:child_process";
import { lstatSync, realpathSync } from "node:fs";

export type QoderManagedLease = {
  mode: "legacy" | "managed" | "invalid";
  active: boolean;
  runId?: string;
  ownerPid?: number;
  leaseId?: string;
  baseUrl?: string;
  socketPath?: string;
};

type Env = Record<string, string | undefined>;

function validRunId(value: unknown): value is string { return typeof value === "string" && /^[A-Za-z0-9._:-]{1,160}$/.test(value); }
function validLeaseId(value: unknown): value is string { return typeof value === "string" && /^[0-9a-f]{32}$/.test(value); }
function validOwnerPid(value: unknown): value is number { return typeof value === "number" && Number.isInteger(value) && value > 1; }
function safeOrigin(value: string | undefined): string | undefined {
  if (!value) return undefined;
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" || !["127.0.0.1", "localhost", "::1", "[::1]"].includes(url.hostname) || !url.port) return undefined;
    return url.origin;
  } catch { return undefined; }
}
function safeExecutable(path: string): boolean {
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || (stat.mode & 0o111) === 0 || stat.isSymbolicLink()) return false;
    return realpathSync(path).split("/").at(-1) !== "qoderclicn" && path.split("/").at(-1) !== "qoderclicn";
  } catch { return false; }
}
function cliCommand(env: Env): { command: string; args: string[] } | undefined {
  const explicit = env.QODER_PROXY_RUNTIME_CLI || env.QODER_PROXY_BIN;
  if (explicit) {
    if (explicit.includes("/")) return safeExecutable(explicit) ? { command: explicit, args: [] } : undefined;
    for (const directory of (env.PATH || "").split(":")) {
      const candidate = `${directory || "."}/${explicit}`;
      if (safeExecutable(candidate)) return { command: candidate, args: [] };
    }
    return undefined;
  }
  for (const directory of (env.PATH || "").split(":")) {
    const candidate = `${directory || "."}/qoder-proxy`;
    if (safeExecutable(candidate)) return { command: candidate, args: [] };
  }
  const entry = env.QODER_PROXY_RUNTIME_SOURCE_ENTRY;
  const bun = (env.PATH || "").split(":").map((directory) => `${directory || "."}/bun`).find(safeExecutable);
  return entry && bun ? { command: bun, args: [entry] } : undefined;
}
function statusEnv(env: Env, socketPath: string): NodeJS.ProcessEnv {
  return { PATH: env.PATH, HOME: env.HOME, TMPDIR: env.TMPDIR, QODER_PROXY_DIR: env.QODER_PROXY_DIR, QODER_PROXY_RUNTIME_SOCKET: socketPath, QODER_PROXY_RUNTIME_SOURCE_ENTRY: env.QODER_PROXY_RUNTIME_SOURCE_ENTRY };
}

export function readQoderManagedLeaseStatus(env: Env = process.env): QoderManagedLease {
  const runId = env.QODER_PROXY_RUNTIME_RUN_ID;
  const ownerPid = env.QODER_PROXY_RUNTIME_OWNER_PID === undefined ? undefined : Number(env.QODER_PROXY_RUNTIME_OWNER_PID);
  const leaseId = env.QODER_PROXY_RUNTIME_LEASE_ID;
  const socketPath = env.QODER_PROXY_RUNTIME_SOCKET;
  if (runId === undefined && ownerPid === undefined && leaseId === undefined && socketPath === undefined) return { mode: "legacy", active: false };
  if (!validRunId(runId) || !validOwnerPid(ownerPid) || !validLeaseId(leaseId) || typeof socketPath !== "string" || socketPath.length === 0) return { mode: "invalid", active: false };
  const command = cliCommand(env);
  if (!command) return { mode: "managed", active: false, runId, ownerPid, leaseId, socketPath };
  const args = [...command.args, "runtime", "status", runId, String(ownerPid), leaseId];
  const result = spawnSync(command.command, args, { env: statusEnv(env, socketPath), encoding: "utf8", timeout: 700, stdio: ["ignore", "pipe", "ignore"] });
  if (result.status !== 0 || result.error || typeof result.stdout !== "string" || result.stdout.trim().length === 0) return { mode: "managed", active: false, runId, ownerPid, leaseId, socketPath };
  try {
    const value = JSON.parse(result.stdout) as Record<string, unknown>;
    const active = value.active === true && value.runId === runId && value.ownerPid === ownerPid && value.leaseId === leaseId && value.socketPath === socketPath && safeOrigin(value.baseUrl as string | undefined) === safeOrigin(env.ANTHROPIC_BASE_URL);
    return { mode: "managed", active, runId, ownerPid, leaseId, baseUrl: typeof value.baseUrl === "string" ? value.baseUrl : undefined, socketPath };
  } catch { return { mode: "managed", active: false, runId, ownerPid, leaseId, socketPath }; }
}
