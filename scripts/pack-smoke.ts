// 本地 tarball 黑盒：打包、临时安装并从 PATH 执行 CLI；不会发布到 Registry。

import { spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const temp = await mkdtemp(join(tmpdir(), "qoder-proxy-pack-"));

function run(command: string, args: string[], cwd: string, env?: Record<string, string | undefined>) {
  return spawnSync(command, args, { cwd, encoding: "utf8", env: env ? { ...process.env, ...env } : process.env });
}

try {
  const pack = run("npm", ["pack", "--json", "--ignore-scripts", "--pack-destination", temp], root);
  if (pack.status !== 0) throw new Error(pack.stderr);
  const [{ filename }] = JSON.parse(pack.stdout) as Array<{ filename: string }>;
  const tarball = join(temp, filename);

  const project = join(temp, "consumer");
  await mkdir(project, { recursive: true });
  await writeFile(join(project, "package.json"), JSON.stringify({ private: true }));
  const install = run("npm", ["install", "--ignore-scripts", tarball], project);
  if (install.status !== 0) throw new Error(install.stderr);

  const executable = join(project, "node_modules", ".bin", "qoder-proxy");
  const installer = join(project, "node_modules", ".bin", "qoder-statusline-install");
  const link = await stat(executable);
  const installerLink = await stat(installer);
  if ((!link.isFile() && !link.isSymbolicLink()) || (!installerLink.isFile() && !installerLink.isSymbolicLink())) throw new Error("安装包 bin 缺失");
  const hook = join(temp, "statusline.ts");
  const helper = join(temp, "qoder-statusline-runtime.ts");
  await writeFile(hook, "#!/usr/bin/env bun\nconsole.log('legacy');\n", { mode: 0o700 });
  const installSmoke = run(installer, [], project);
  if (installSmoke.status === 0) throw new Error("缺少显式 installer target 应 fail-closed");
  const installWithTargets = run(installer, [], project, { QODER_STATUSLINE_RUNTIME_TARGET: helper, QODER_STATUSLINE_HOOK_TARGET: hook });
  if (installWithTargets.status !== 0) throw new Error(installWithTargets.stderr || "tarball installer smoke failed");
  const installedHook = await readFile(hook, "utf8");
  const installedHelper = await readFile(helper, "utf8");
  if (!installedHook.includes("qoder-statusline-runtime.ts") || !installedHelper.includes("runtime") || !installedHelper.includes("status")) throw new Error("installer 未接入 managed statusline helper");
  const secondInstall = run(installer, [], project, { QODER_STATUSLINE_RUNTIME_TARGET: helper, QODER_STATUSLINE_HOOK_TARGET: hook });
  if (secondInstall.status !== 0) throw new Error(secondInstall.stderr || "installer 幂等 smoke failed");
  const invocation = run(executable, ["unknown-command"], project);
  if (invocation.status === 0) throw new Error("未知命令应 fail-closed");
  const installedPackage = JSON.parse(await readFile(join(project, "node_modules", "@hangox", "qoder-proxy", "package.json"), "utf8")) as { name?: string };
  if (installedPackage.name !== "@hangox/qoder-proxy") throw new Error("安装后的 package name 不匹配");

  const files = await readdir(join(project, "node_modules", "@hangox", "qoder-proxy"));
  if (files.some((name) => ["src", "tests", "docs", "CLAUDE.md", "err"].includes(name))) {
    throw new Error(`安装目录包含内部文件：${files.join(", ")}`);
  }
  console.log("npm pack install smoke: pass");
} finally {
  await rm(temp, { recursive: true, force: true });
}
