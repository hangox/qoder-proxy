// 显式 Qoder 凭据导入：只读取精确 machine_id/user 文件，不访问其他官方私有目录。

import { constants as fsConstants } from "node:fs";
import { open, lstat } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import { decryptCredentialStorage, loadAuthBridge, sha256, type Bridge } from "./bridge.ts";
import { createConfigStore, type CredentialStore, type StoredCredential } from "./session.ts";

const MACHINE_ID_MAX_BYTES = 4 * 1024;
const USER_MAX_BYTES = 4 * 1024 * 1024;
export const DEFAULT_QODER_SOURCE_DIR = join(homedir(), ".qoder-cn", ".auth");

export type PreparedQoderImport = {
  credential: StoredCredential;
  machineId: string;
  sourceDir: string;
  ignoredFields: string[];
};

export type ImportDependencies = {
  loadBridge?: (env: Record<string, string | undefined>) => Promise<Bridge>;
  decrypt?: (bridge: Bridge, ciphertext: string, key: string) => string;
  createStore?: (machineId: string, env: Record<string, string | undefined>) => CredentialStore;
};

function assertCurrentOwner(uid: number, label: string): void {
  if (typeof process.getuid === "function" && uid !== process.getuid()) throw new Error(`${label} 所有者不是当前用户`);
}

type DirectoryIdentity = { dev: number; ino: number; uid: number; mode: number };

async function validateSourceDir(sourceDir: string, expected?: DirectoryIdentity): Promise<DirectoryIdentity> {
  if (!isAbsolute(sourceDir)) throw new Error("Qoder 凭据来源目录必须是绝对路径");
  const info = await lstat(sourceDir);
  if (info.isSymbolicLink() || !info.isDirectory()) throw new Error("Qoder 凭据来源必须是真实目录，不能是符号链接");
  assertCurrentOwner(info.uid, "Qoder 凭据来源目录");
  if ((info.mode & 0o022) !== 0) throw new Error("Qoder 凭据来源目录不能由 group/other 写入");
  if (expected && (info.dev !== expected.dev || info.ino !== expected.ino || info.uid !== expected.uid || info.mode !== expected.mode)) throw new Error("Qoder 凭据来源目录在读取期间发生替换");
  return { dev: info.dev, ino: info.ino, uid: info.uid, mode: info.mode };
}

async function readSecureFile(path: string, label: string, maxBytes: number): Promise<Buffer> {
  const before = await lstat(path);
  if (before.isSymbolicLink() || !before.isFile()) throw new Error(`${label} 必须是普通文件，不能是符号链接`);
  assertCurrentOwner(before.uid, label);
  if ((before.mode & 0o077) !== 0) throw new Error(`${label} 权限不得宽于 0600`);
  if (before.size <= 0 || before.size > maxBytes) throw new Error(`${label} 大小非法`);
  const handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) throw new Error(`${label} 在打开前发生替换`);
    const bytes = await handle.readFile();
    const afterHandle = await handle.stat();
    const afterPath = await lstat(path);
    if (afterHandle.dev !== opened.dev || afterHandle.ino !== opened.ino || afterHandle.size !== bytes.length || afterHandle.uid !== before.uid || afterHandle.mode !== before.mode
      || afterPath.isSymbolicLink() || !afterPath.isFile() || afterPath.dev !== opened.dev || afterPath.ino !== opened.ino || afterPath.size !== bytes.length || afterPath.uid !== before.uid || afterPath.mode !== before.mode) {
      bytes.fill(0);
      throw new Error(`${label} 在读取期间发生替换`);
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

function decodeUtf8(bytes: Buffer, label: string): string {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { throw new Error(`${label} 不是合法 UTF-8`); }
}

function parseMachineId(bytes: Buffer): string {
  const raw = decodeUtf8(bytes, "machine_id");
  const value = raw.endsWith("\n") ? raw.slice(0, -1) : raw;
  if (value.endsWith("\r")) throw new Error("machine_id 必须使用单行 UTF-8 内容");
  if (value.length === 0 || value.includes("\n") || value.includes("\r") || value.trim() !== value) throw new Error("machine_id 必须是单行非空字符串");
  return value;
}

export async function readMachineIdFile(path: string): Promise<string> {
  if (!isAbsolute(path)) throw new Error("QODER_CN_MACHINE_ID_FILE 必须是绝对路径");
  const bytes = await readSecureFile(path, "machine ID 文件", MACHINE_ID_MAX_BYTES);
  try { return parseMachineId(bytes); }
  finally { bytes.fill(0); }
}

function requireOptionalString(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string") throw new Error(`Qoder 凭据字段 ${field} 类型错误`);
  return value;
}

function requireTokenAlias(value: unknown, field: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0 || value.trim().length === 0 || value.trim() !== value) throw new Error(`Qoder 凭据字段 ${field} 必须是非空无首尾空白字符串`);
  return value;
}

function requireExpiry(value: unknown, field: string): number | undefined {
  if (value === undefined || value === null) return undefined;
  const parsed = typeof value === "number" ? value : typeof value === "string" && value.length > 0 ? Number(value) : Number.NaN;
  if (!Number.isFinite(parsed) || parsed <= 0) throw new Error(`Qoder 凭据字段 ${field} 必须是有限正数`);
  return Math.floor(parsed);
}

export function mapDecryptedQoderCredential(machineId: string, decryptedJson: string): { credential: StoredCredential; ignoredFields: string[] } {
  let parsed: unknown;
  try { parsed = JSON.parse(decryptedJson); }
  catch { throw new Error("Qoder 凭据解密结果不是合法 JSON"); }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error("Qoder 凭据解密结果必须是对象");
  const data = parsed as Record<string, unknown>;
  const securityToken = requireTokenAlias(data.security_oauth_token, "security_oauth_token");
  const accessToken = requireTokenAlias(data.access_token, "access_token");
  if (securityToken && accessToken && securityToken !== accessToken) throw new Error("Qoder 凭据中的 access token 字段不一致");
  const token = securityToken ?? accessToken;
  if (!token) throw new Error("Qoder 凭据缺少可用 access token");
  const refreshToken = requireOptionalString(data.refresh_token, "refresh_token");
  const userId = requireOptionalString(data.uid, "uid");
  const userName = requireOptionalString(data.name, "name");
  const credential: StoredCredential = {
    version: 1,
    site: "cn",
    machineIdHash: sha256(machineId),
    token,
    refreshToken,
    expiresAt: requireExpiry(data.expire_time, "expire_time"),
    refreshTokenExpiresAt: requireExpiry(data.refresh_token_expire_time, "refresh_token_expire_time"),
    userId,
    userName,
  };
  const used = new Set(["security_oauth_token", "access_token", "refresh_token", "expire_time", "refresh_token_expire_time", "uid", "name"]);
  return { credential, ignoredFields: Object.keys(data).filter((key) => !used.has(key)).sort() };
}

export async function prepareQoderImport(sourceDir: string, env: Record<string, string | undefined>, dependencies: ImportDependencies = {}): Promise<PreparedQoderImport> {
  const directoryIdentity = await validateSourceDir(sourceDir);
  const machineBytes = await readSecureFile(join(sourceDir, "machine_id"), "Qoder machine_id", MACHINE_ID_MAX_BYTES);
  let userBytes: Buffer | undefined;
  let machineId = "";
  let ciphertext = "";
  try {
    await validateSourceDir(sourceDir, directoryIdentity);
    userBytes = await readSecureFile(join(sourceDir, "user"), "Qoder user", USER_MAX_BYTES);
    await validateSourceDir(sourceDir, directoryIdentity);
    machineId = parseMachineId(machineBytes);
    if (machineId.length < 16) throw new Error("Qoder machine_id 长度不足，无法构造官方存储密钥");
    const rawCiphertext = decodeUtf8(userBytes, "Qoder user");
    ciphertext = rawCiphertext.endsWith("\n") ? rawCiphertext.slice(0, -1) : rawCiphertext;
    if (!ciphertext || ciphertext.includes("\n") || ciphertext.includes("\r") || ciphertext.trim() !== ciphertext) throw new Error("Qoder user 文件必须是单行非空密文");
    const bridge = await (dependencies.loadBridge ?? loadAuthBridge)(env);
    let decrypted: string;
    try { decrypted = (dependencies.decrypt ?? decryptCredentialStorage)(bridge, ciphertext, machineId.slice(0, 16)); }
    catch { throw new Error("Qoder 凭据解密失败"); }
    const mapped = mapDecryptedQoderCredential(machineId, decrypted);
    return { ...mapped, machineId, sourceDir };
  } finally {
    machineBytes.fill(0);
    userBytes?.fill(0);
    ciphertext = "";
  }
}

export function importStore(machineId: string, env: Record<string, string | undefined>, dependencies: ImportDependencies = {}): CredentialStore {
  return (dependencies.createStore ?? createConfigStore)(machineId, env);
}
