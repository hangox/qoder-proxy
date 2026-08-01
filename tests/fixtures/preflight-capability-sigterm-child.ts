import { appendFile, writeFile } from "node:fs/promises";
import { AuthSession, createConfigStore } from "../../src/auth/session.ts";
import { preflightBeforeBind } from "../../src/cli.ts";
import type { Bridge } from "../../src/auth/bridge.ts";

const [configDir, readyPath, bodiesPath, resultPath] = process.argv.slice(2);
if (!configDir || !readyPath || !bodiesPath || !resultPath) throw new Error("缺少 capability SIGTERM 测试参数");
const env = {
  QODER_CN_MACHINE_ID: "machine-a",
  QODER_PROXY_CONFIG_DIR: configDir,
  QODER_PROXY_REFRESH_TIMEOUT_MS: "1000",
  QODER_PROXY_CAPABILITY_TIMEOUT_MS: "1000",
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

const controller = new AbortController();
const stop = () => controller.abort(new Error("SIGTERM during capability probe"));
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
try {
  await preflightBeforeBind(env, (currentEnv, signal) => AuthSession.preflight(currentEnv, signal, { store, bridge }), controller.signal);
  process.exitCode = 2;
} catch (error) {
  const remaining = await baseStore.load();
  await writeFile(resultPath, `${JSON.stringify({
    error: error instanceof Error ? error.message : "unknown",
    refreshToken: remaining?.refreshToken,
  })}\n`, "utf8");
  process.exitCode = controller.signal.aborted ? 0 : 1;
}
