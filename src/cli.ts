// qoder-proxy CLI：auth 管理命令与代理启动严格分流；启动前完成 AuthSession preflight。

import { serve } from "@hono/node-server";
import type { ServerType } from "@hono/node-server";
import { createApp } from "./proxy.ts";
import { AuthSession, CatalogUpstreamError, PendingPreflightPersistenceError, type CredentialStore } from "./auth/session.ts";
import { DEFAULT_QODER_SOURCE_DIR, importStore, prepareQoderImport, type ImportDependencies, type PreparedQoderImport } from "./auth/import.ts";
import { readMachineIdFile, resolveMachineIdPath } from "./machine-id.ts";
import { logger } from "./logger.ts";
import { createRoutingAttestation } from "./attestation.ts";
import type { RoutingAttestation } from "./attestation.ts";
import { runRuntimeCommand } from "./runtime-manager.ts";
import { QoderModelUnavailableError } from "./model-registry.ts";

const DEFAULT_PREFLIGHT_RETRY_MS = 1_000;
const DEFAULT_SHUTDOWN_DRAIN_MS = 5_000;
const MANAGEMENT_MACHINE_ID = "qoder-proxy-import-management";

export type CliIo = { stdout(value: string): void; stderr(value: string): void };
export type CliRuntime = { close(): void };
export type CliDependencies = ImportDependencies & {
  prepareImport?: (sourceDir: string, env: Record<string, string | undefined>, dependencies?: ImportDependencies) => Promise<PreparedQoderImport>;
  createImportStore?: (machineId: string, env: Record<string, string | undefined>, dependencies?: ImportDependencies) => CredentialStore;
  preflight?: typeof AuthSession.preflight;
  bind?: (env: Record<string, string | undefined>, session: AuthSession, routingAttestation?: RoutingAttestation) => CliRuntime;
};

function shutdownDrainMs(env: Record<string, string | undefined>): number {
  const parsed = Number(env.QODER_PROXY_SHUTDOWN_DRAIN_MS);
  return Number.isInteger(parsed) && parsed >= 1 && parsed <= 60_000 ? parsed : DEFAULT_SHUTDOWN_DRAIN_MS;
}

function preflightRetryMs(env: Record<string, string | undefined>, attempt: number): number {
  const parsed = Number(env.QODER_PROXY_PREFLIGHT_RETRY_MS);
  const base = Number.isInteger(parsed) && parsed >= 1 && parsed <= 60_000 ? parsed : DEFAULT_PREFLIGHT_RETRY_MS;
  return Math.min(base * 2 ** Math.min(attempt - 1, 5), 60_000);
}
function waitForRetry(delayMs: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { cleanup(); resolve(); }, delayMs);
    const onAbort = () => { cleanup(); reject(signal?.reason ?? new DOMException("Aborted", "AbortError")); };
    const cleanup = () => { clearTimeout(timer); signal?.removeEventListener("abort", onAbort); };
    if (signal?.aborted) onAbort(); else signal?.addEventListener("abort", onAbort, { once: true });
  });
}

async function drainPreflightDurability(error: PendingPreflightPersistenceError, env: Record<string, string | undefined>): Promise<void> {
  let deadline = Date.now() + shutdownDrainMs(env);
  let attempts = 0;
  while (!error.hasDurableRecoveryPoint()) {
    try {
      const remaining = Math.max(1, deadline - Date.now());
      await Promise.race([
        error.drainToDurableJournal(),
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error("durability drain timeout")), remaining)),
      ]);
    } catch {
      attempts++;
      if (Date.now() >= deadline) {
        logger.error("rotated credential recovery storage unavailable; startup remains fail-stop", { attempt: attempts });
        deadline = Date.now() + shutdownDrainMs(env);
      }
      const retryMs = Math.min(preflightRetryMs(env, attempts), Math.max(1, deadline - Date.now()));
      await waitForRetry(retryMs);
    }
  }
}

export async function preflightBeforeBind(env: Record<string, string | undefined> = process.env, preflight: typeof AuthSession.preflight = AuthSession.preflight, signal?: AbortSignal): Promise<AuthSession> {
  let persistenceRetries = 0;
  while (true) {
    try { return await preflight(env, signal); }
    catch (error) {
      if (!(error instanceof PendingPreflightPersistenceError)) throw error;
      if (signal?.aborted) {
        await drainPreflightDurability(error, env);
        throw signal.reason ?? error;
      }
      persistenceRetries++;
      const retryMs = preflightRetryMs(env, persistenceRetries);
      logger.warn("startup credential persistence retry", { attempt: persistenceRetries, retryMs });
      try { await waitForRetry(retryMs, signal); }
      catch (abortError) {
        await drainPreflightDurability(error, env);
        throw abortError;
      }
    }
  }
}

function writeJson(io: CliIo, value: Record<string, unknown>): void {
  io.stdout(`${JSON.stringify(value)}\n`);
}

function requireSingleValue(args: string[], index: number, flag: string): string {
  const value = args[index + 1];
  if (value === undefined || value.startsWith("--")) throw new Error(`${flag} 缺少参数`);
  return value;
}

type ImportArgs = { apply: boolean; replace: boolean; sourceDir: string };
function parseImportArgs(args: string[]): ImportArgs {
  let apply = false, replace = false, sourceDir = DEFAULT_QODER_SOURCE_DIR;
  const seen = new Set<string>();
  for (let index = 0; index < args.length; index++) {
    const flag = args[index]!;
    if (seen.has(flag)) throw new Error(`重复参数：${flag}`);
    seen.add(flag);
    if (flag === "--apply") apply = true;
    else if (flag === "--replace") replace = true;
    else if (flag === "--source-dir") { sourceDir = requireSingleValue(args, index, flag); index++; }
    else throw new Error(`未知参数：${flag}`);
  }
  if (replace && !apply) throw new Error("--replace 只能与 --apply 一起使用");
  return { apply, replace, sourceDir };
}

function parseBackupId(args: string[]): string {
  if (args.length !== 2 || args[0] !== "--backup-id") throw new Error("必须且只能提供 --backup-id <uuid>");
  const value = args[1]!;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) throw new Error("backup ID 非法");
  return value;
}

export async function resolveServeEnvironment(env: Record<string, string | undefined>): Promise<Record<string, string | undefined>> {
  const directDefined = env.QODER_CN_MACHINE_ID !== undefined;
  const fileDefined = env.QODER_CN_MACHINE_ID_FILE !== undefined;
  if (directDefined && fileDefined) throw new Error("QODER_CN_MACHINE_ID 与 QODER_CN_MACHINE_ID_FILE 不能同时设置");
  if (!fileDefined) return { ...env };
  const machineId = await readMachineIdFile(resolveMachineIdPath(env));
  const resolved: Record<string, string | undefined> = { ...env, QODER_CN_MACHINE_ID: machineId };
  delete resolved.QODER_CN_MACHINE_ID_FILE;
  return resolved;
}

function defaultBind(env: Record<string, string | undefined>, session: AuthSession, routingAttestation: RoutingAttestation | undefined): CliRuntime {
  const parsedPort = Number.parseInt(env.PORT ?? "", 10);
  const port = Number.isInteger(parsedPort) && parsedPort > 0 && parsedPort <= 65535 ? parsedPort : 7788;
  const hostname = "127.0.0.1";
  const app = createApp(env, session, routingAttestation);
  const server: ServerType = serve({ fetch: app.fetch, port, hostname }, (info) => console.log(`qoder-proxy listening on http://${hostname}:${info.port}`));
  return { close: () => { server.close(); routingAttestation?.close(); } };
}

export async function runCli(
  args: string[],
  env: Record<string, string | undefined> = process.env,
  io: CliIo = { stdout: (value) => process.stdout.write(value), stderr: (value) => process.stderr.write(value) },
  dependencies: CliDependencies = {},
  signal?: AbortSignal,
): Promise<CliRuntime | undefined> {
  const command = args[0];
  if (command === "runtime") {
    await runRuntimeCommand(args.slice(1), env, io);
    return undefined;
  }
  if (command === undefined || command === "serve") {
    if (args.length > (command === "serve" ? 1 : 0)) throw new Error("serve 不接受额外参数");
    if (!env.QODER_PROXY_API_KEY) throw new Error("QODER_PROXY_API_KEY 未设置");
    const resolvedEnv = await resolveServeEnvironment(env);
    const routingAttestation = createRoutingAttestation(resolvedEnv);
    try {
      signal?.throwIfAborted();
      const session = await preflightBeforeBind(resolvedEnv, dependencies.preflight ?? AuthSession.preflight, signal);
      const routingKey = resolvedEnv.QODER_CN_INFER_MODEL_KEY;
      if (routingKey !== undefined && routingKey.length > 0) {
        try {
          const snapshot = await session.listModels(signal);
          if (!snapshot.models.some((model) => model.key === routingKey)) throw new QoderModelUnavailableError(routingKey);
        } catch (error) {
          if (error instanceof QoderModelUnavailableError) throw error;
          if (error instanceof CatalogUpstreamError) throw error;
          throw new Error("Qoder model catalog unavailable", { cause: error });
        }
      }
      // attestation sink 在 preflight 之前建立，只有 preflight 成功后才计数，确保同一 run 的 record 能证明启动边界。
      routingAttestation?.recordPreflight();
      signal?.throwIfAborted();
      return (dependencies.bind ?? defaultBind)(resolvedEnv, session, routingAttestation);
    } catch (error) {
      routingAttestation?.close();
      throw error;
    }
  }
  if (command !== "auth") throw new Error(`未知命令：${command}`);
  const authCommand = args[1];
  if (!authCommand) throw new Error("缺少 auth 子命令");
  signal?.throwIfAborted();
  if (authCommand === "import-qoder") {
    const parsed = parseImportArgs(args.slice(2));
    const prepared = await (dependencies.prepareImport ?? prepareQoderImport)(parsed.sourceDir, env, dependencies);
    signal?.throwIfAborted();
    const store = (dependencies.createImportStore ?? importStore)(prepared.machineId, env, dependencies);
    if (!store.inspectImportTarget || !store.applyImport) throw new Error("credential store 不支持 import transaction");
    const target = await store.inspectImportTarget();
    if (!parsed.apply) {
      writeJson(io, { ok: true, command: "import-qoder", dryRun: true, canImport: !target.exists, requiresReplace: target.exists, hasRefreshToken: prepared.credential.refreshToken !== undefined, hasExpiry: prepared.credential.expiresAt !== undefined });
      return undefined;
    }
    const result = await store.applyImport(prepared.credential, parsed.replace);
    // durable apply 完成后即使 signal 同时到达，也必须返回 backup ID，避免用户失去 rollback/finalize 句柄。
    writeJson(io, { ok: true, command: "import-qoder", applied: true, replaced: result.replaced, backupId: result.backupId });
    return undefined;
  }
  if (authCommand === "import-status") {
    if (args.length !== 2) throw new Error("auth import-status 不接受额外参数");
    const store = (dependencies.createImportStore ?? importStore)(MANAGEMENT_MACHINE_ID, env, dependencies);
    if (!store.importStatus) throw new Error("credential store 不支持 import status");
    const imports = await store.importStatus();
    writeJson(io, { ok: true, command: "import-status", imports });
    return undefined;
  }
  if (authCommand === "rollback-import" || authCommand === "finalize-import") {
    const backupId = parseBackupId(args.slice(2));
    const store = (dependencies.createImportStore ?? importStore)(MANAGEMENT_MACHINE_ID, env, dependencies);
    if (authCommand === "rollback-import") {
      if (!store.rollbackImport) throw new Error("credential store 不支持 import rollback");
      await store.rollbackImport(backupId);
    } else {
      if (!store.finalizeImport) throw new Error("credential store 不支持 import finalize");
      await store.finalizeImport(backupId);
    }
    writeJson(io, { ok: true, command: authCommand, backupId });
    return undefined;
  }
  throw new Error(`未知 auth 子命令：${authCommand}`);
}

async function main(): Promise<void> {
  const startupController = new AbortController();
  let runtime: CliRuntime | undefined;
  const close = () => {
    if (!startupController.signal.aborted) startupController.abort(new Error("operation cancelled by signal"));
    runtime?.close();
  };
  process.on("SIGINT", close);
  process.on("SIGTERM", close);
  try {
    runtime = await runCli(process.argv.slice(2), process.env, undefined, undefined, startupController.signal);
    if (!runtime) {
      process.off("SIGINT", close);
      process.off("SIGTERM", close);
    }
  } catch (error) {
    process.off("SIGINT", close);
    process.off("SIGTERM", close);
    throw error;
  }
}

if (import.meta.main) {
  main().catch((error) => {
    logger.error("CLI operation failed", { errorClass: error instanceof Error ? error.name : "Error", code: error instanceof Error ? error.name : "Error" });
    process.exitCode = 1;
  });
}
