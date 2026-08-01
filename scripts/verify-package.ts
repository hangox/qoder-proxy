// npm 发布白名单审计：只允许 bundle、README 与 package.json 进入 tarball。

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const result = spawnSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
  cwd: root,
  encoding: "utf8",
});

if (result.status !== 0) {
  process.stderr.write(result.stderr);
  process.exit(result.status ?? 1);
}

const packs = JSON.parse(result.stdout) as Array<{
  files?: Array<{ path?: string }>;
}>;
const paths = packs[0]?.files?.map((file) => file.path).filter((path): path is string => typeof path === "string") ?? [];
const required = new Set(["README.md", "dist/qoder-proxy.js", "package.json"]);
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
  if (forbidden.some((pattern) => pattern.test(path))) {
    throw new Error(`npm 包含禁止文件：${path}`);
  }
}
for (const path of required) {
  if (!paths.includes(path)) throw new Error(`npm 包缺少必需文件：${path}`);
}
if (paths.length !== required.size) {
  throw new Error(`npm 包文件白名单不匹配：${paths.join(", ")}`);
}

console.log(`npm package audit: pass (${paths.join(", ")})`);
