// 将版本化 Qoder managed statusline helper 安装到用户显式指定的 hook 目录。
import { chmodSync, existsSync, mkdirSync, renameSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const source = join(root, "..", "src", "statusline-runtime.ts");
const target = process.env.QODER_STATUSLINE_RUNTIME_TARGET;
if (!target) throw new Error("必须显式提供 QODER_STATUSLINE_RUNTIME_TARGET");
if (!existsSync(source)) throw new Error(`statusline source 不存在: ${source}`);
mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
const temp = `${target}.tmp.${process.pid}`;
writeFileSync(temp, `// Generated from qoder-proxy/src/statusline-runtime.ts\n${await Bun.file(source).text()}`, { mode: 0o600 });
renameSync(temp, target);
chmodSync(target, statSync(source).mode & 0o777);
writeFileSync(`${target}.source`, await Bun.file(source).text(), { mode: 0o644 });
console.log(`qoder statusline runtime installed: ${target}`);
