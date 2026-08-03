// npm 发布白名单审计：只允许 bundle、README 与 package.json 进入 tarball。

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

type PackFile = { path?: unknown };
type PackRecord = { files?: PackFile[] };

function isPackRecord(value: unknown): value is PackRecord {
  return typeof value === "object" && value !== null && Array.isArray((value as { files?: unknown }).files);
}

export function normalizePackResults(value: unknown): PackRecord[] {
  const candidates = Array.isArray(value)
    ? value
    : typeof value === "object" && value !== null
      ? Object.values(value)
      : null;
  if (candidates === null) throw new Error("npm pack JSON 格式无效：预期数组或包名映射对象");
  const records = candidates.filter(isPackRecord);
  if (records.length === 0) throw new Error("npm pack JSON 中没有有效文件记录");
  return records;
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
  const packs = normalizePackResults(JSON.parse(result.stdout));
  const paths = packs[0]?.files?.map((file) => file.path).filter((path): path is string => typeof path === "string") ?? [];
  verifyPackageFiles(paths);
  console.log(`npm package audit: pass (${paths.join(", ")})`);
}

if (import.meta.main) main();
