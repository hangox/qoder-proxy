import { appendFile, writeFile } from "node:fs/promises";
import { AuthSession, createConfigStore } from "../../src/auth/session.ts";
import type { Bridge } from "../../src/auth/bridge.ts";

const [configDir, readyPath, bodiesPath] = process.argv.slice(2);
if (!configDir || !readyPath || !bodiesPath) throw new Error("缺少 capability parent-kill 测试参数");
const env = {
  QODER_CN_MACHINE_ID: "machine-a",
  QODER_PROXY_CONFIG_DIR: configDir,
  QODER_PROXY_REFRESH_TIMEOUT_MS: "1000",
  QODER_PROXY_CAPABILITY_TIMEOUT_MS: "60000",
};
const baseStore = createConfigStore("machine-a", env);
await baseStore.save({
  version: 1,
  site: "cn",
  machineIdHash: "f9c8c7ddcf3d5f566fd679f65db5dcab4446594cf5d992feead5416cbc13e062",
  token: "old-access",
  refreshToken: "old-refresh",
  expiresAt: 0,
});
await writeFile(bodiesPath, "", "utf8");
const store = createConfigStore("machine-a", env, {
  capabilityProbeMode: "sync-block",
  capabilityProbeReadyPath: readyPath,
});
const bridge = { roles: {} } as Bridge;
globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
  if (init?.method === "POST") await appendFile(bodiesPath, `${String(init.body)}\n`, "utf8");
  return new Response(JSON.stringify({ id: "unused" }), { status: 200 });
}) as typeof fetch;

await AuthSession.preflight(env, undefined, { store, bridge });
process.exitCode = 2;
