import { appendFile, writeFile } from "node:fs/promises";
import { AuthSession, createConfigStore, type CredentialStore } from "../../src/auth/session.ts";
import type { Bridge } from "../../src/auth/bridge.ts";
import { preflightBeforeBind } from "../../src/cli.ts";

const [configDir, readyPath, bodiesPath, mode = "pre-write-hang", metricsPath] = process.argv.slice(2);
if (!configDir || !readyPath || !bodiesPath) throw new Error("缺少测试路径参数");

const env = {
  QODER_CN_MACHINE_ID: "machine-a",
  QODER_PROXY_CONFIG_DIR: configDir,
  QODER_PROXY_REFRESH_TIMEOUT_MS: "1000",
  QODER_PROXY_PREFLIGHT_RETRY_MS: "1",
  QODER_PROXY_SHUTDOWN_DRAIN_MS: "30",
};
const baseStore = createConfigStore("machine-a", env);
let checkCalls = 0;
let activeChecks = 0;
let maxConcurrentChecks = 0;
let emergencyCalls = 0;
let activeEmergency = 0;
let maxConcurrentEmergency = 0;
let actualWrites = 0;
let signalCount = 0;
let storageRestored = false;
let releaseBlocked!: () => void;
const blocked = new Promise<void>((resolve) => { releaseBlocked = resolve; });
const updateMetrics = async () => {
  if (metricsPath) await writeFile(metricsPath, `${JSON.stringify({ checkCalls, maxConcurrentChecks, emergencyCalls, maxConcurrentEmergency, actualWrites, signalCount })}\n`, "utf8");
};
const store: CredentialStore = {
  load: () => baseStore.load(),
  isCommitted: (value) => baseStore.isCommitted(value),
  isRotationStaged: async (value, owner) => {
    checkCalls++;
    activeChecks++;
    maxConcurrentChecks = Math.max(maxConcurrentChecks, activeChecks);
    await updateMetrics();
    try {
      if (mode === "check-hang" && checkCalls === 1) {
        await writeFile(readyPath, "check-hanging\n", "utf8");
        await blocked;
      }
      return await baseStore.isRotationStaged!(value, owner);
    } finally {
      activeChecks--;
      await updateMetrics();
    }
  },
  reserveRotation: (base) => baseStore.reserveRotation(base),
  clearRotationReservation: (owner) => baseStore.clearRotationReservation(owner),
  stageRotation: (value, owner) => baseStore.stageRotation(value, owner),
  stageEmergencyRotation: async (value, owner) => {
    emergencyCalls++;
    activeEmergency++;
    maxConcurrentEmergency = Math.max(maxConcurrentEmergency, activeEmergency);
    await updateMetrics();
    try {
      if (mode === "pre-write-hang" && emergencyCalls === 1) {
        await writeFile(readyPath, "emergency-pre-write-hanging\n", "utf8");
        await blocked;
      }
      if (mode === "permanent-failure" && !storageRestored) {
        await writeFile(readyPath, "emergency-storage-unavailable\n", "utf8");
        throw new Error("emergency storage unavailable");
      }
      await baseStore.stageEmergencyRotation!(value, owner);
      actualWrites++;
      await updateMetrics();
      if (mode === "after-write-hang" && emergencyCalls === 1) {
        await writeFile(readyPath, "emergency-after-write-hanging\n", "utf8");
        await blocked;
      }
    } finally {
      activeEmergency--;
      await updateMetrics();
    }
  },
  save: (value, owner) => baseStore.save(value, owner),
  delete: (owner) => baseStore.delete(owner),
};
const bridge = { roles: {} } as Bridge;
globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
  if (init?.method === "POST") {
    await appendFile(bodiesPath, `${String(init.body)}\n`, "utf8");
    return new Response(JSON.stringify({ device_token: "new-access", refresh_token: "new-refresh", expires_in: 3600 }), { status: 200 });
  }
  return new Response(JSON.stringify({ id: "new-user" }), { status: 200 });
}) as typeof fetch;

const controller = new AbortController();
const stop = async () => {
  signalCount++;
  if (!controller.signal.aborted) controller.abort(new Error("SIGTERM during preflight durability"));
  if (signalCount >= 2) {
    storageRestored = true;
    releaseBlocked();
  }
  await updateMetrics();
};
process.on("SIGTERM", () => { void stop(); });
process.on("SIGINT", () => { void stop(); });
try {
  await preflightBeforeBind(env, (currentEnv, signal) => AuthSession.preflight(currentEnv, signal, { store, bridge }), controller.signal);
  process.exitCode = 2;
} catch {
  process.exitCode = controller.signal.aborted ? 0 : 1;
}
