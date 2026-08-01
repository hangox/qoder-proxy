import { appendFile, writeFile } from "node:fs/promises";
import { AuthSession } from "../../src/auth/session.ts";
import type { Bridge } from "../../src/auth/bridge.ts";

const [configDir, bodiesPath, resultPath] = process.argv.slice(2);
if (!configDir || !bodiesPath || !resultPath) throw new Error("缺少测试路径参数");

const env = {
  QODER_CN_MACHINE_ID: "machine-a",
  QODER_PROXY_CONFIG_DIR: configDir,
  QODER_PROXY_REFRESH_TIMEOUT_MS: "1000",
};
const bridge = { roles: {} } as Bridge;
globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
  if (init?.method === "POST") {
    await appendFile(bodiesPath, `${String(init.body)}\n`, "utf8");
    throw new Error("恢复进程不得再次调用 refresh endpoint");
  }
  return new Response(JSON.stringify({ id: "new-user" }), { status: 200 });
}) as typeof fetch;

try {
  const session = await AuthSession.preflight(env, undefined, { bridge });
  const stored = (session as unknown as { stored: { refreshToken?: string } }).stored;
  await writeFile(resultPath, `${stored.refreshToken ?? ""}\n`, "utf8");
  process.exitCode = stored.refreshToken === "new-refresh" ? 0 : 2;
} catch {
  process.exitCode = 1;
}
