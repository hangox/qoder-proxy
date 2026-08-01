// Qoder machine ID 的统一安全读取器。
// 默认只读取 qoder-proxy 自己的 config 目录；不会访问 Qoder 私有凭据目录。
import { constants as fsConstants } from "node:fs";
import { open, lstat } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";

export const MACHINE_ID_MAX_BYTES = 4 * 1024;
export const MACHINE_ID_FILE_NAME = "machine_id";

function currentUid(): number | undefined {
  return typeof process.getuid === "function" ? process.getuid() : undefined;
}

function assertOwner(uid: number, label: string): void {
  const owner = currentUid();
  if (owner !== undefined && uid !== owner) throw new Error(`${label} 所有者不是当前用户`);
}

function parseMachineId(bytes: Buffer): string {
  let raw: string;
  try { raw = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { throw new Error("machine_id 不是合法 UTF-8"); }
  const value = raw.endsWith("\n") ? raw.slice(0, -1) : raw;
  if (value.endsWith("\r") || value.length === 0 || value.includes("\n") || value.includes("\r") || value.trim() !== value) {
    throw new Error("machine_id 必须是单行非空字符串");
  }
  return value;
}

export function proxyConfigDir(env: Record<string, string | undefined> = process.env): string {
  const configured = env.QODER_PROXY_CONFIG_DIR;
  const dir = configured === undefined || configured.length === 0 ? join(env.HOME || homedir(), ".config", "qoder-proxy") : configured;
  if (!isAbsolute(dir)) throw new Error("QODER_PROXY_CONFIG_DIR 必须是绝对路径");
  return dir;
}

export function resolveMachineIdPath(env: Record<string, string | undefined> = process.env): string {
  const direct = env.QODER_CN_MACHINE_ID;
  const explicit = env.QODER_CN_MACHINE_ID_FILE;
  if (direct !== undefined && explicit !== undefined) throw new Error("QODER_CN_MACHINE_ID 与 QODER_CN_MACHINE_ID_FILE 不能同时设置");
  if (explicit !== undefined) {
    if (!isAbsolute(explicit)) throw new Error("QODER_CN_MACHINE_ID_FILE 必须是绝对路径");
    return explicit;
  }
  return join(proxyConfigDir(env), MACHINE_ID_FILE_NAME);
}

/** 验证并读取机器 ID；返回值只供内存中的认证过程使用。 */
export async function readMachineIdFile(path: string): Promise<string> {
  if (!isAbsolute(path)) throw new Error("QODER_CN_MACHINE_ID_FILE 必须是绝对路径");
  let before;
  try { before = await lstat(path); }
  catch { throw new Error("Qoder machine ID 文件不可用或不安全"); }
  if (before.isSymbolicLink()) throw new Error("Qoder machine ID 文件不能是符号链接");
  if (!before.isFile()) throw new Error("Qoder machine ID 文件不可用或不安全");
  assertOwner(before.uid, "Qoder machine ID 文件");
  if ((before.mode & 0o077) !== 0) throw new Error("Qoder machine ID 文件权限不得宽于 0600");
  if (before.size <= 0 || before.size > MACHINE_ID_MAX_BYTES) throw new Error("Qoder machine ID 文件大小非法");
  const handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (opened.isSymbolicLink?.() || !opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) throw new Error("Qoder machine ID 文件在打开前发生替换");
    const bytes = await handle.readFile();
    try {
      const afterHandle = await handle.stat();
      const afterPath = await lstat(path);
      if (!afterHandle.isFile() || afterHandle.dev !== opened.dev || afterHandle.ino !== opened.ino || afterHandle.uid !== before.uid || afterHandle.mode !== before.mode || afterHandle.size !== bytes.length
        || afterPath.isSymbolicLink() || !afterPath.isFile() || afterPath.dev !== opened.dev || afterPath.ino !== opened.ino || afterPath.uid !== before.uid || afterPath.mode !== before.mode || afterPath.size !== bytes.length) {
        throw new Error("Qoder machine ID 文件在读取期间发生替换");
      }
      return parseMachineId(bytes);
    } finally { bytes.fill(0); }
  } finally { await handle.close(); }
}
