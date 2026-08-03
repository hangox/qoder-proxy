// npm 发布白名单审计：只允许 bundle、README 与 package.json 进入 tarball。

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export type PackFile = { path: string };
export type PackRecord = { files: PackFile[]; filename?: string };

function isPackRecord(value: unknown): value is PackRecord {
  if (typeof value !== "object" || value === null) return false;
  const files = (value as { files?: unknown }).files;
  if (!Array.isArray(files) || files.length === 0) return false;
  return files.every(
    (file) =>
      typeof file === "object" &&
      file !== null &&
      typeof (file as { path?: unknown }).path === "string" &&
      (file as { path: string }).path.length > 0,
  );
}

export function normalizePackResults(value: unknown): [PackRecord] {
  const candidates = Array.isArray(value)
    ? value
    : typeof value === "object" && value !== null
      ? Object.values(value)
      : null;
  if (candidates === null) throw new Error("npm pack JSON 格式无效：预期数组或包名映射对象");
  if (candidates.length !== 1 || !isPackRecord(candidates[0])) {
    throw new Error("npm pack JSON 必须恰好包含一个合法的非空 pack record");
  }
  return [candidates[0]];
}

export function parsePackRecord(value: unknown): PackRecord {
  const records = normalizePackResults(value);
  const record = records[0];
  if (!record) throw new Error("npm pack JSON 必须恰好包含一个合法的非空 pack record");
  return record;
}

export function packFilename(record: PackRecord): string {
  const filename = record.filename;
  if (typeof filename !== "string" || filename.length === 0 || filename.includes("/") || filename.includes("\\") || filename === "." || filename === "..") {
    throw new Error("npm pack JSON filename 必须是非空 basename");
  }
  return filename;
}

export function verifyPackageFiles(paths: string[]): void {
  const required = new Set(["README.md", "dist/qoder-proxy.js", "dist/qoder-statusline-runtime.js", "dist/install-qoder-statusline.js", "package.json"]);
  const forbidden = [
    /^\.claude(?:\/|$)/,
    /^CLAUDE\.md$/,
    /^docs(?:\/|$)/,
    /^src(?:\/|$)/,
    /^tests(?:\/|$)/,
    /^scripts(?:\/|$)/,
    /^err$/,
    /(?:^|\/)auth-[^/]+\.json$/,
    /(?:^|\/)qoderclicn(?:\/|$)/i,
    /\.wasm$/i,
  ];

  for (const path of paths) {
    if (forbidden.some((pattern) => pattern.test(path))) throw new Error(`npm 包含禁止文件：${path}`);
  }
  for (const path of required) {
    if (!paths.includes(path)) throw new Error(`npm 包缺少必需文件：${path}`);
  }
  if (paths.length !== required.size) throw new Error(`npm 包文件白名单不匹配：${paths.join(", ")}`);
}

export function main(): void {
  const root = fileURLToPath(new URL("../", import.meta.url));
  const result = spawnSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: root, encoding: "utf8" });
  if (result.status !== 0) {
    process.stderr.write(result.stderr);
    process.exit(result.status ?? 1);
  }
  const record = parsePackRecord(JSON.parse(result.stdout));
  const paths = record.files.map((file) => file.path);
  verifyPackageFiles(paths);
  console.log(`npm package audit: pass (${paths.join(", ")})`);
}

if (import.meta.main) main();
