// 从 npm 安装包安装 Qoder managed statusline helper，并原子接入 statusline.ts。
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const packageDir = dirname(fileURLToPath(import.meta.url));
const helperSource = join(packageDir, "qoder-statusline-runtime.js");
const helperTarget = process.env.QODER_STATUSLINE_RUNTIME_TARGET;
const hookTarget = process.env.QODER_STATUSLINE_HOOK_TARGET;
if (!helperTarget || !hookTarget) throw new Error("必须显式提供 QODER_STATUSLINE_RUNTIME_TARGET 与 QODER_STATUSLINE_HOOK_TARGET");
function secureTarget(path: string, allowMode: number): void {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`installer 目标必须是普通文件：${path}`);
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) throw new Error(`installer 目标所有者不匹配：${path}`);
  if ((stat.mode & 0o077) !== 0) throw new Error(`installer 目标权限不安全：${path}`);
  if ((stat.mode & 0o777) !== allowMode) throw new Error(`installer 目标权限不符合契约：${path}`);
}
if (!existsSync(helperSource) || !lstatSync(helperSource).isFile() || lstatSync(helperSource).isSymbolicLink()) throw new Error("安装包缺少 qoder statusline helper");
if (!existsSync(hookTarget)) throw new Error("statusline.ts 目标不存在，拒绝修改");
secureTarget(hookTarget, statSync(hookTarget).mode & 0o777);
if (existsSync(helperTarget)) secureTarget(helperTarget, 0o600);
if (dirname(helperTarget) !== dirname(hookTarget)) throw new Error("helper 与 statusline.ts 必须位于同一目录");

const importLine = 'import { readQoderManagedLeaseStatus, type QoderManagedLease } from "./qoder-statusline-runtime.ts";';
const originalHook = readFileSync(hookTarget, "utf8");
const hookWithImport = originalHook.includes("./qoder-statusline-runtime.ts")
  ? originalHook
  : originalHook.replace(/^(#![^\n]*\n)?/, (shebang) => `${shebang}${importLine}\n`);
const hookBackup = `${hookTarget}.bak.${process.pid}`;
const hookTemp = `${hookTarget}.tmp.${process.pid}`;
writeFileSync(hookBackup, originalHook, { mode: statSync(hookTarget).mode & 0o777 });
writeFileSync(hookTemp, hookWithImport, { mode: statSync(hookTarget).mode & 0o777 });
renameSync(hookTemp, hookTarget);

mkdirSync(dirname(helperTarget), { recursive: true, mode: 0o700 });
const helperTemp = `${helperTarget}.tmp.${process.pid}`;
writeFileSync(helperTemp, `// Installed from @hangox/qoder-proxy\n${readFileSync(helperSource, "utf8")}`, { mode: 0o600 });
renameSync(helperTemp, helperTarget);
chmodSync(helperTarget, 0o600);
console.log(JSON.stringify({ ok: true, helper: helperTarget, hook: hookTarget, patched: hookWithImport !== originalHook }));
