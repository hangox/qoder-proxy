// Qoder 中国站官方 Auth WASM 运行时加载 + 签名产物校验。
//
// 迁移自 Gate 0 已验证 PoC（experiments/qoder-cn-auth-bridge-poc.ts，冻结 SHA
// e028d89f0372f3d1231c21895f95f9ca3c1297b28bb82eb6074164d1b3e60352）：
// - WASM 模块边界识别（含 base64 内嵌）
// - wasm-bindgen ABI glue（heap/object/string/memory/crypto/time/random、retptr 解码）
// - RequestResult/QoderContext dispose 契约（幂等释放 + use-after-free 阻断）
// - CN host 白名单校验（一切出站 URL 必须落在白名单内）
//
// 安全边界：不复制官方二进制/WASM 进项目（仅内存加载）；不启动 qoderclicn 子进程；
// 不读 ~/.qoder/.auth、security/ 等私有凭据目录。

import { createHash } from "node:crypto";
import { readFile, access, realpath } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { delimiter, join } from "node:path";
import { homedir } from "node:os";

export function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

export class BridgeAssertionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BridgeAssertionError";
  }
}

function bridgeAssert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new BridgeAssertionError(message);
}

// ---------------------------------------------------------------------------
// CN host 白名单：一切出站 URL（env override 与 prepare* 产物）必须落在白名单内。
// ---------------------------------------------------------------------------

export const CN_ALLOWED_HOSTS = new Set(["qoder.com.cn", "openapi.qoder.com.cn", "gateway.qoder.com.cn", "api2-v2.qoder.com.cn", "api2.qoder.com.cn"]);

export function requireHttpsUrl(value: string, label: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new BridgeAssertionError(`${label} 不是合法 URL`);
  }
  if (parsed.protocol !== "https:" || !parsed.host) throw new BridgeAssertionError(`${label} 必须是 https URL`);
  return value;
}

export function requireCnAllowedUrl(value: string, label: string): string {
  const url = requireHttpsUrl(value, label);
  const host = new URL(url).host;
  if (!CN_ALLOWED_HOSTS.has(host)) throw new BridgeAssertionError(`${label} 主机不在中国站白名单: hostHash=${sha256(host)}`);
  return url;
}

// ---------------------------------------------------------------------------
// 1. 定位本机 qoderclicn（只读文件，不启动子进程）
// ---------------------------------------------------------------------------

export async function locateQoderCli(env: Record<string, string | undefined>): Promise<string> {
  const explicit = env.QODERICN_BIN;
  if (explicit) {
    try {
      await access(explicit, fsConstants.X_OK);
      return await realpath(explicit);
    } catch {
      throw new BridgeAssertionError("QODERICN_BIN 指向的 qoderclicn 不可执行");
    }
  }
  for (const dir of (env.PATH ?? "").split(delimiter).filter(Boolean)) {
    const c = join(dir, "qoderclicn");
    try {
      await access(c, fsConstants.X_OK);
      return await realpath(c);
    } catch {
      /* 继续查 PATH 下一项 */
    }
  }
  const link = join(homedir(), ".local", "bin", "qoderclicn");
  try {
    await access(link, fsConstants.X_OK);
    return await realpath(link);
  } catch {
    throw new BridgeAssertionError("本机未定位到 qoderclicn");
  }
}

// ---------------------------------------------------------------------------
// 2. WASM 模块边界识别（原始 + base64 内嵌）
// ---------------------------------------------------------------------------

const WASM_MAGIC = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
const WASM_MAX_SECTIONS = 4096;
const WASM_MAX_MODULE_BYTES = 64 * 1024 * 1024;

function readLeb128(bytes: Uint8Array, offset: number): { value: number; length: number } | undefined {
  let result = 0, shift = 0, cursor = offset;
  for (let i = 0; i < 5; i++) {
    if (cursor >= bytes.length) return undefined;
    const byte = bytes[cursor]!;
    result |= (byte & 0x7f) << shift;
    cursor++;
    if ((byte & 0x80) === 0) return { value: result >>> 0, length: cursor - offset };
    shift += 7;
  }
  return undefined;
}

type WasmExtraction = { offset: number; bytes: Uint8Array; module: WebAssembly.Module; exportNames: string[] };

function tryExtractModuleAt(binary: Uint8Array, offset: number): WasmExtraction | undefined {
  let cursor = offset + WASM_MAGIC.length;
  let sections = 0, seenExport = false, best: WasmExtraction | undefined;
  while (cursor < binary.length && sections < WASM_MAX_SECTIONS) {
    const id = binary[cursor]!;
    if (id > 13) break;
    const size = readLeb128(binary, cursor + 1);
    if (!size) break;
    const end = cursor + 1 + size.length + size.value;
    if (end > binary.length || end - offset > WASM_MAX_MODULE_BYTES) break;
    cursor = end; sections++;
    if (id === 7) seenExport = true;
    if (!seenExport) continue;
    const candidate = binary.subarray(offset, cursor);
    try {
      const mod = new WebAssembly.Module(candidate as unknown as BufferSource);
      const exports = WebAssembly.Module.exports(mod).map((e) => e.name);
      if (exports.length > 0) best = { offset, bytes: candidate, module: mod, exportNames: exports };
    } catch { /* 继续扩张 */ }
  }
  return best;
}

function extractWasmModules(binary: Uint8Array): WasmExtraction[] {
  const modules: WasmExtraction[] = [];
  for (let i = 0; i + WASM_MAGIC.length <= binary.length; i++) {
    let matched = true;
    for (let j = 0; j < WASM_MAGIC.length; j++) { if (binary[i + j] !== WASM_MAGIC[j]) { matched = false; break; } }
    if (!matched) continue;
    if (modules.some((m) => i >= m.offset && i < m.offset + m.bytes.length)) continue;
    const ext = tryExtractModuleAt(binary, i);
    if (ext) modules.push(ext);
  }
  // base64 嵌入 WASM（真实 qoderclicn 用 base64 编码内嵌）。
  const b64Magic = new TextEncoder().encode("AGFzbQEAAAA");
  const b64Table = (() => { const t = new Int16Array(256).fill(-1); const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; for (let i = 0; i < a.length; i++) t[a.charCodeAt(i)] = i; t["=".charCodeAt(0)] = -2; return t; })();
  for (let i = 0; i + b64Magic.length <= binary.length; i++) {
    let matched = true;
    for (let j = 0; j < b64Magic.length; j++) { if (binary[i + j] !== b64Magic[j]) { matched = false; break; } }
    if (!matched) continue;
    let end = i;
    while (end < binary.length && b64Table[binary[end]!] !== -1) end++;
    const encoded = binary.subarray(i, end);
    if (encoded.length < 4 || encoded.length % 4 === 1) continue;
    const out = new Uint8Array(Math.floor(encoded.length / 4) * 3);
    let w = 0, valid = true;
    for (let off = 0; off < encoded.length && valid; off += 4) {
      const a = b64Table[encoded[off]!]!, b = b64Table[encoded[off + 1]!]!;
      const c = off + 2 < encoded.length ? b64Table[encoded[off + 2]!]! : -2;
      const d = off + 3 < encoded.length ? b64Table[encoded[off + 3]!]! : -2;
      if (a < 0 || b < 0 || c === -1 || d === -1) { valid = false; break; }
      out[w++] = (a << 2) | (b >> 4);
      if (c !== -2) { out[w++] = ((b & 0x0f) << 4) | (c >> 2); if (d !== -2) out[w++] = ((c & 0x03) << 6) | d; }
    }
    if (!valid) continue;
    const decoded = out.subarray(0, w);
    const ext = tryExtractModuleAt(decoded, 0);
    if (ext) modules.push({ ...ext, offset: i });
  }
  return modules;
}

// ---------------------------------------------------------------------------
// 3. 导出角色映射（禁止依赖版本哈希 import 名）
// ---------------------------------------------------------------------------

type ExportRole =
  | "malloc" | "realloc" | "free" | "addToStackPointer" | "handleError"
  | "generateRuntimeAuthFields" | "decryptServerResponse" | "credentialStorageDecrypt"
  | "qodercontextNew" | "qodercontextPrepareRequest" | "qodercontextPrepareInferRequest" | "qodercontextRefreshAuthFields" | "qodercontextFree"
  | "requestresultUrl" | "requestresultBody" | "requestresultHeaders" | "requestresultHeaderCount" | "requestresultFree";

const EXPORT_MATCHERS: Record<ExportRole, RegExp> = {
  malloc: /^(?:__wbindgen_)?malloc$|^__wbindgen_export2$/i,
  realloc: /^__wbindgen_realloc$|^__wbindgen_export3$/i,
  free: /^__wbindgen_free$|^__wbindgen_export4$/i,
  addToStackPointer: /^__wbindgen_add_to_stack_pointer$/i,
  handleError: /^__wbindgen_export$/i,
  generateRuntimeAuthFields: /^generate_?runtime_?auth_?fields$/i,
  decryptServerResponse: /^decrypt_?server_?response$/i,
  credentialStorageDecrypt: /^credential_?storage_?decrypt$/i,
  qodercontextNew: /^qodercontext_?new$/i,
  qodercontextPrepareRequest: /^qodercontext_?prepare_?request$/i,
  qodercontextPrepareInferRequest: /^qodercontext_?prepare_?infer_?request$/i,
  qodercontextRefreshAuthFields: /^qodercontext_?refresh_?auth_?fields$/i,
  qodercontextFree: /^(?:__wbg_)?qodercontext_?free$/i,
  requestresultUrl: /^requestresult_?url$/i,
  requestresultBody: /^requestresult_?body$/i,
  requestresultHeaders: /^requestresult_?headers$/i,
  requestresultHeaderCount: /^requestresult_?header_?count$/i,
  requestresultFree: /^(?:__wbg_)?requestresult_?free$/i,
};
export const REQUIRED_AUTH_EXPORT_ROLES: readonly ExportRole[] = [
  "malloc", "free", "addToStackPointer", "generateRuntimeAuthFields",
  "qodercontextNew", "qodercontextPrepareRequest", "qodercontextPrepareInferRequest", "qodercontextRefreshAuthFields", "qodercontextFree",
  "requestresultUrl", "requestresultBody", "requestresultHeaders", "requestresultHeaderCount", "requestresultFree",
];

export function missingRequiredAuthExportRoles(exportNames: readonly string[]): ExportRole[] {
  return REQUIRED_AUTH_EXPORT_ROLES.filter((role) => !exportNames.some((name) => EXPORT_MATCHERS[role].test(name)));
}

function selectAuthModule(candidates: WasmExtraction[]): WasmExtraction {
  for (const c of candidates) {
    const exportNames = WebAssembly.Module.exports(c.module).map((e) => e.name);
    if (missingRequiredAuthExportRoles(exportNames).length === 0) return c;
  }
  throw new BridgeAssertionError(`未找到具备全部必需导出角色的 WASM 模块: candidates=${candidates.length}`);
}

// ---------------------------------------------------------------------------
// 4. wasm-bindgen glue（最小实现，对齐 PoC 已验证语义）
// ---------------------------------------------------------------------------

export type Bridge = {
  roles: Record<ExportRole, string | undefined>;
  passString: (v: string) => { ptr: number; len: number };
  callRole: (role: ExportRole, args: number[]) => unknown;
  readI32: (addr: number) => number;
  freeWasm: (ptr: number, len: number) => void;
  withStack: <T>(fn: (ret: number) => T) => T;
  getString: (ptr: number, len: number) => string;
  takeObject: (i: number) => unknown;
};

function createBridge(moduleBytes: Uint8Array): Bridge {
  const mod = new WebAssembly.Module(moduleBytes as unknown as BufferSource);
  const exportNames = WebAssembly.Module.exports(mod).map((e) => e.name);
  const roles = Object.fromEntries(Object.keys(EXPORT_MATCHERS).map((r) => [r, exportNames.find((n) => (EXPORT_MATCHERS[r as ExportRole]).test(n))])) as Record<ExportRole, string | undefined>;
  const heap: unknown[] = new Array(128).fill(undefined);
  heap.push(undefined, null, true, false);
  let heapNext = heap.length;
  const addHeap = (v: unknown) => { if (heapNext === heap.length) heap.push(heap.length + 1); const i = heapNext; heapNext = heap[i] as number; heap[i] = v; return i; };
  const getObj = (i: number) => heap[i];
  const dropObj = (i: number) => { if (i < 132) return; heap[i] = heapNext; heapNext = i; };
  const takeObj = (i: number) => { const v = getObj(i); dropObj(i); return v; };
  const textEnc = new TextEncoder(), textDec = new TextDecoder();
  let wasmExports: Record<string, unknown> = {};
  const memBytes = () => new Uint8Array((wasmExports.memory as WebAssembly.Memory).buffer);
  const dv = () => new DataView((wasmExports.memory as WebAssembly.Memory).buffer);
  const readI32 = (a: number) => dv().getInt32(a, true);
  const callRole = (role: ExportRole, args: number[]) => { const fn = wasmExports[roles[role]!]; return (fn as (...a: number[]) => unknown)(...args); };
  const malloc = (size: number, _align?: number) => callRole("malloc", [size, 1]) as number;
  const freeWasm = (ptr: number, len: number) => { if (ptr === 0 || !roles.free) return; callRole("free", [ptr, len, 1]); };
  const passString = (v: string) => {
    const enc = textEnc.encode(v);
    const ptr = malloc(enc.length) >>> 0;
    memBytes().subarray(ptr, ptr + enc.length).set(enc);
    return { ptr, len: enc.length };
  };
  const getString = (ptr: number, len: number) => textDec.decode(memBytes().subarray(ptr >>> 0, (ptr >>> 0) + len));
  const withStack = <T,>(fn: (ret: number) => T) => { const ret = callRole("addToStackPointer", [-16]) as number; try { return fn(ret); } finally { callRole("addToStackPointer", [16]); } };
  const importDescs = WebAssembly.Module.imports(mod);
  const importObj: Record<string, Record<string, unknown>> = {};
  const getArrayU8 = (ptr: number, len: number) => memBytes().subarray(ptr >>> 0, (ptr >>> 0) + len);
  const handleError0 = (fn: () => unknown) => {
    try { return fn(); } catch (e) {
      if (roles.handleError) { callRole("handleError", [addHeap(e)]); return undefined; }
      throw e;
    }
  };
  for (const d of importDescs) {
    importObj[d.module] ??= {};
    const name = d.name;
    let handler: ((...a: number[]) => unknown) | undefined;
    if (/^__wbg_Error_/.test(name)) handler = (ptr, len) => addHeap(new Error(getString(ptr, len)));
    else if (/__wbindgen_is_function/.test(name)) handler = (i) => typeof getObj(i) === "function" ? 1 : 0;
    else if (/__wbindgen_is_object/.test(name)) handler = (i) => { const v = getObj(i); return typeof v === "object" && v !== null ? 1 : 0; };
    else if (/__wbindgen_is_string/.test(name)) handler = (i) => typeof getObj(i) === "string" ? 1 : 0;
    else if (/__wbindgen_is_undefined/.test(name)) handler = (i) => getObj(i) === undefined ? 1 : 0;
    else if (/__wbindgen_throw/.test(name)) handler = (ptr, len) => { throw new Error(getString(ptr, len)); };
    else if (/^__wbg_call_/.test(name)) handler = (a, b, c) => handleError0(() => addHeap((getObj(a) as (...args: unknown[]) => unknown).call(getObj(b), getObj(c))));
    else if (/^__wbg_crypto_/.test(name)) handler = (i) => addHeap((getObj(i) as { crypto?: unknown }).crypto);
    else if (/^__wbg_getRandomValues_/.test(name)) handler = (a, b) => handleError0(() => { const t = getObj(a) as { getRandomValues?: (v: unknown) => void } | undefined; if (t?.getRandomValues) t.getRandomValues(getObj(b)); else globalThis.crypto.getRandomValues(getArrayU8(a, b) as Uint8Array<ArrayBuffer>); });
    else if (/^__wbg_length_/.test(name)) handler = (i) => (getObj(i) as { length?: number }).length ?? 0;
    else if (/^__wbg_msCrypto_/.test(name)) handler = (i) => addHeap((getObj(i) as { msCrypto?: unknown }).msCrypto);
    else if (/^__wbg_new_with_length_/.test(name)) handler = (size) => addHeap(new Uint8Array(size >>> 0));
    else if (/^__wbg_new_/.test(name)) handler = () => addHeap(new Map());
    else if (/^__wbg_node_/.test(name)) handler = (i) => addHeap((getObj(i) as { node?: unknown }).node);
    else if (/^__wbg_now_/.test(name)) handler = () => Date.now();
    else if (/^__wbg_process_/.test(name)) handler = (i) => addHeap((getObj(i) as { process?: unknown }).process);
    else if (/^__wbg_prototypesetcall_/.test(name)) handler = (ptr, len, i) => { getArrayU8(ptr, len).set(getObj(i) as ArrayLike<number>); };
    else if (/^__wbg_randomFillSync_/.test(name)) handler = (a, b) => handleError0(() => { (getObj(a) as { randomFillSync: (v: unknown) => void }).randomFillSync(takeObj(b)); });
    else if (/^__wbg_require_/.test(name)) handler = () => handleError0(() => addHeap((import.meta as { require?: unknown }).require));
    else if (/^__wbg_set_/.test(name)) handler = (a, b, c) => addHeap((getObj(a) as Map<unknown, unknown>).set(getObj(b), getObj(c)));
    else if (/^__wbg_static_accessor_GLOBAL_THIS_/.test(name)) handler = () => addHeap(globalThis);
    else if (/^__wbg_static_accessor_GLOBAL_/.test(name)) handler = () => { const v = (globalThis as Record<string, unknown>).global ?? null; return v === null ? 0 : addHeap(v); };
    else if (/^__wbg_static_accessor_SELF_/.test(name)) handler = () => { const v = typeof self === "undefined" ? null : self; return v === null ? 0 : addHeap(v); };
    else if (/^__wbg_static_accessor_WINDOW_/.test(name)) handler = () => { const v = typeof window === "undefined" ? null : window; return v === null ? 0 : addHeap(v); };
    else if (/^__wbg_subarray_/.test(name)) handler = (i, s, e) => addHeap((getObj(i) as Uint8Array).subarray(s >>> 0, e >>> 0));
    else if (/^__wbg_versions_/.test(name)) handler = (i) => addHeap((getObj(i) as { versions?: unknown }).versions);
    else if (/__wbindgen_cast_0000000000000001$/.test(name)) handler = (ptr, len) => addHeap(getArrayU8(ptr, len));
    else if (/__wbindgen_cast_0000000000000002$/.test(name)) handler = (ptr, len) => addHeap(getString(ptr, len));
    else if (name === "__wbindgen_object_clone_ref") handler = (i) => addHeap(getObj(i));
    else if (name === "__wbindgen_object_drop_ref") handler = (i) => { takeObj(i); };
    // 未知 import 不 shim（fail closed，对齐 PoC 语义）。
    if (handler) importObj[d.module]![d.name] = handler;
  }
  const instance = new WebAssembly.Instance(mod, importObj as never);
  wasmExports = instance.exports as Record<string, unknown>;
  return { roles, passString, callRole, readI32, freeWasm, withStack, getString, takeObject: takeObj };
}

// ---------------------------------------------------------------------------
// 5. RequestResult / QoderContext：幂等 dispose + use-after-free 阻断（PoC 已验证契约）
// ---------------------------------------------------------------------------

export type PreparedRequest = { url: string; headers: Record<string, string>; body: string | undefined };

export class RequestResult {
  private disposed = false;
  constructor(private readonly b: Bridge, private readonly ptr: number) {}

  private assertLive() { bridgeAssert(!this.disposed, "RequestResult 已释放，禁止继续访问"); }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    if (this.b.roles.requestresultFree) this.b.callRole("requestresultFree", [this.ptr, 0]);
  }

  get url(): string {
    this.assertLive();
    return this.b.withStack((ret) => {
      this.b.callRole("requestresultUrl", [ret, this.ptr]);
      const p = this.b.readI32(ret), l = this.b.readI32(ret + 4);
      const v = this.b.getString(p, l);
      this.b.freeWasm(p, l);
      return v;
    });
  }

  get headers(): unknown {
    this.assertLive();
    const handle = this.b.callRole("requestresultHeaders", [this.ptr]) as number;
    return this.b.takeObject(handle);
  }

  get body(): string | undefined {
    this.assertLive();
    return this.b.withStack((ret) => {
      this.b.callRole("requestresultBody", [ret, this.ptr]);
      const p = this.b.readI32(ret), l = this.b.readI32(ret + 4);
      if (p === 0) return undefined;
      const v = this.b.getString(p, l);
      this.b.freeWasm(p, l);
      return v;
    });
  }

  get headerCount(): number {
    this.assertLive();
    return (this.b.callRole("requestresultHeaderCount", [this.ptr]) as number) >>> 0;
  }
}

export class QoderContext {
  private disposed = false;
  private constructor(private readonly b: Bridge, private readonly ptr: number) {}

  private assertLive() { bridgeAssert(!this.disposed, "QoderContext 已释放，禁止继续访问"); }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    if (this.b.roles.qodercontextFree) this.b.callRole("qodercontextFree", [this.ptr, 0]);
  }

  static create(b: Bridge, machineId: string, cosyVersion: string, userInfoJson: string, clientCtxJson: string): QoderContext {
    return b.withStack((ret) => {
      const p0 = b.passString(machineId), p1 = b.passString(cosyVersion), p2 = b.passString(userInfoJson), p3 = b.passString(clientCtxJson);
      b.callRole("qodercontextNew", [ret, p0.ptr, p0.len, p1.ptr, p1.len, p2.ptr, p2.len, p3.ptr, p3.len]);
      const r0 = b.readI32(ret), r1 = b.readI32(ret + 4), r2 = b.readI32(ret + 8);
      if (r2) throw b.takeObject(r1);
      return new QoderContext(b, r0 >>> 0);
    });
  }

  prepareRequest(base: string, path: string, method: string, authMode: string, body?: string, headersJson?: string): RequestResult {
    this.assertLive();
    return this.b.withStack((ret) => {
      const p0 = this.b.passString(base), p1 = this.b.passString(path), p2 = this.b.passString(method), p3 = this.b.passString(authMode);
      const p4 = body === undefined ? { ptr: 0, len: 0 } : this.b.passString(body);
      const p5 = headersJson === undefined ? { ptr: 0, len: 0 } : this.b.passString(headersJson);
      this.b.callRole("qodercontextPrepareRequest", [ret, this.ptr, p0.ptr, p0.len, p1.ptr, p1.len, p2.ptr, p2.len, p3.ptr, p3.len, p4.ptr, p4.len, p5.ptr, p5.len]);
      const r0 = this.b.readI32(ret), r1 = this.b.readI32(ret + 4), r2 = this.b.readI32(ret + 8);
      if (r2) throw this.b.takeObject(r1);
      return new RequestResult(this.b, r0);
    });
  }

  prepareInferRequest(base: string, bodyJson: string, modelKey?: string, source?: string): RequestResult {
    this.assertLive();
    return this.b.withStack((ret) => {
      const p0 = this.b.passString(base), p1 = this.b.passString(bodyJson);
      const p2 = this.b.passString(modelKey ?? ""), p3 = this.b.passString(source ?? "");
      this.b.callRole("qodercontextPrepareInferRequest", [ret, this.ptr, p0.ptr, p0.len, p1.ptr, p1.len, p2.ptr, p2.len, p3.ptr, p3.len]);
      const r0 = this.b.readI32(ret), r1 = this.b.readI32(ret + 4), r2 = this.b.readI32(ret + 8);
      if (r2) throw this.b.takeObject(r1);
      return new RequestResult(this.b, r0);
    });
  }

  refreshAuthFields(userInfoJson: string): void {
    this.assertLive();
    this.b.withStack((ret) => {
      const { ptr, len } = this.b.passString(userInfoJson);
      this.b.callRole("qodercontextRefreshAuthFields", [ret, this.ptr, ptr, len]);
      const r0 = this.b.readI32(ret), r1 = this.b.readI32(ret + 4);
      if (r1) throw this.b.takeObject(r0);
    });
  }
}

// prepare* 产物契约（PoC 已验证）：url 命中 CN 白名单；headers 为 Map（string,string，≤64 且与
// headerCount 一致）；body 为 string|undefined。
export function validatePreparedResult(result: RequestResult, label: string): PreparedRequest {
  const url = requireCnAllowedUrl(result.url, `${label} 产物 url`);
  const rawHeaders = result.headers;
  if (!(rawHeaders instanceof Map)) throw new BridgeAssertionError(`${label} 产物 headers 不是 Map`);
  if (rawHeaders.size > 64) throw new BridgeAssertionError(`${label} 产物 headers 数量超限: ${rawHeaders.size}`);
  if (result.headerCount !== rawHeaders.size) throw new BridgeAssertionError(`${label} 产物 headerCount 与 headers 大小不一致: ${result.headerCount}!=${rawHeaders.size}`);
  const headers: Record<string, string> = {};
  for (const [name, value] of rawHeaders.entries()) {
    if (typeof name !== "string" || typeof value !== "string" || name.length === 0) throw new BridgeAssertionError(`${label} 产物 header 键值非法`);
    headers[name] = value;
  }
  const body = result.body;
  if (body !== undefined && typeof body !== "string") throw new BridgeAssertionError(`${label} 产物 body 不是字符串`);
  return { url, headers, body };
}

// ---------------------------------------------------------------------------
// 6. 官方 Auth WASM 单例加载（Promise 级 single-flight，避免并发首请求重复扫描二进制）
// ---------------------------------------------------------------------------

let bridgeLoadPromise: Promise<Bridge> | undefined;

export function resetBridgeCacheForTest(): void {
  bridgeLoadPromise = undefined;
}

export async function loadAuthBridge(env: Record<string, string | undefined>): Promise<Bridge> {
  if (bridgeLoadPromise) return bridgeLoadPromise;
  const promise = (async () => {
    const cliPath = await locateQoderCli(env);
    const binary = new Uint8Array(await readFile(cliPath));
    const modules = extractWasmModules(binary);
    const selected = selectAuthModule(modules);
    return createBridge(selected.bytes);
  })();
  bridgeLoadPromise = promise.catch((e) => {
    bridgeLoadPromise = undefined;
    throw e;
  });
  return bridgeLoadPromise;
}

// generateRuntimeAuthFields / decryptServerResponse / credentialStorageDecrypt 包装（对齐 wasm-bindgen retptr 契约）。
export function decryptCredentialStorage(b: Bridge, ciphertext: string, key: string): string {
  bridgeAssert(typeof b.roles.credentialStorageDecrypt === "string", "官方 Auth WASM 缺少 credential_storage_decrypt 导出");
  return b.withStack((ret) => {
    const encrypted = b.passString(ciphertext);
    const storageKey = b.passString(key);
    b.callRole("credentialStorageDecrypt", [ret, encrypted.ptr, encrypted.len, storageKey.ptr, storageKey.len]);
    const r0 = b.readI32(ret), r1 = b.readI32(ret + 4), r2 = b.readI32(ret + 8), r3 = b.readI32(ret + 12);
    if (r3) throw b.takeObject(r2);
    let result = "";
    if (r0 !== 0) { result = b.getString(r0, r1); b.freeWasm(r0, r1); }
    return result;
  });
}

export function generateRuntimeAuthFields(b: Bridge, json: string): string {
  return b.withStack((ret) => {
    const { ptr, len } = b.passString(json);
    b.callRole("generateRuntimeAuthFields", [ret, ptr, len]);
    const r0 = b.readI32(ret), r1 = b.readI32(ret + 4), r2 = b.readI32(ret + 8), r3 = b.readI32(ret + 12);
    if (r3) throw b.takeObject(r2);
    let result = "";
    if (r0 !== 0) { result = b.getString(r0, r1); b.freeWasm(r0, r1); }
    return result;
  });
}

function decryptServerResponse(b: Bridge, text: string): string {
  return b.withStack((ret) => {
    const { ptr, len } = b.passString(text);
    b.callRole("decryptServerResponse", [ret, ptr, len]);
    const r0 = b.readI32(ret), r1 = b.readI32(ret + 4), r2 = b.readI32(ret + 8), r3 = b.readI32(ret + 12);
    if (r3) throw b.takeObject(r2);
    let result = "";
    if (r0 !== 0) { result = b.getString(r0, r1); b.freeWasm(r0, r1); }
    return result;
  });
}

// 官方 Bs() 语义：try{decrypt_server_response(x)}catch{return x}（明文回退属正常路径）。
export function decryptOrPlain(b: Bridge, text: string): string {
  if (!b.roles.decryptServerResponse) return text;
  try { return decryptServerResponse(b, text); } catch { return text; }
}
