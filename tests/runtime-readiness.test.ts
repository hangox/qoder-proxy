import { afterEach, describe, expect, it } from "vitest";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { QoderRuntimeManager, runRuntimeCommand } from "../src/runtime-manager.ts";
import { CatalogUpstreamError, type AuthSession, type ModelCatalogSnapshot } from "../src/auth/session.ts";
import { QoderModelUnavailableError } from "../src/model-registry.ts";
import { runCli } from "../src/cli.ts";
import { createApp, type SessionLike } from "../src/proxy.ts";

const managers: QoderRuntimeManager[] = [];
const roots: string[] = [];
afterEach(async () => {
  for (const manager of managers.splice(0)) await manager.stop();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function fakeProxy(mode: "ok" | "identity" | "missing" | "catalog" | "catalog500" | "startup-missing" | "startup-catalog" | "exit"): Promise<{ root: string; bin: string; machine: string; error: string }> {
  const root = await mkdtemp(join(tmpdir(), "qoder-readiness-")); roots.push(root);
  const bin = join(root, "qoder-proxy"); const machine = join(root, "machine_id"); const error = join(root, "startup-error.json");
  await writeFile(machine, "machine\n", { mode: 0o600 });
  await writeFile(bin, `#!/usr/bin/env bun
import { writeFileSync } from "node:fs";
const mode = ${JSON.stringify(mode)};
if (mode === "exit") process.exit(1);
if (mode === "startup-missing" || mode === "startup-catalog") {
  writeFileSync(process.env.QODER_PROXY_STARTUP_ERROR_FILE!, JSON.stringify(mode === "startup-missing" ? { code: "model-unavailable", routingKey: "qmodel_38max" } : { code: "catalog-unavailable" }));
  process.exit(1);
}
const port = Number(process.env.PORT), token = process.env.QODER_PROXY_API_KEY!;
const server = Bun.serve({ hostname: "127.0.0.1", port, fetch(request) {
  if (request.headers.get("authorization") !== "Bearer " + token) return new Response(null, { status: 401 });
  const path = new URL(request.url).pathname;
  if (path === "/internal/quota") return Response.json({ ok: true });
  if (path === "/internal/model-routing") {
    if (mode === "missing") return new Response(null, { status: 404 });
    if (mode === "catalog") return new Response(null, { status: 502 });
    if (mode === "catalog500") return new Response(null, { status: 500 });
    const routingKey = process.env.QODER_CN_INFER_MODEL_KEY;
    const displayName = mode === "identity" ? "Qwen3.7-Plus" : routingKey === "qmodel_38max" ? "Qwen3.8-Max" : routingKey === "qmodel_latest" ? "Qwen3.7-Max" : "Qwen3.6-Flash";
    return Response.json({ ok: true, routingKey, displayName });
  }
  return new Response(null, { status: 404 });
}});
process.on("SIGTERM", () => { server.stop(); process.exit(0); });
`, { mode: 0o700 });
  return { root, bin, machine, error };
}

function envFor(fixture: Awaited<ReturnType<typeof fakeProxy>>, socket: string) {
  return { QODER_PROXY_BIN: fixture.bin, QODER_CN_MACHINE_ID_FILE: fixture.machine, QODER_PROXY_RUNTIME_SOCKET: socket, QODER_PROXY_RUNTIME_DIR: fixture.root, QODER_PROXY_CONFIG_DIR: join(fixture.root, "config"), HOME: fixture.root, TMPDIR: fixture.root, PATH: `${fixture.root}:${process.env.PATH || "/usr/bin:/bin"}` };
}

describe("runtime readiness fail-fast", () => {
  it.each([["identity", "Qoder runtime model unavailable", "qmodel_38max"], ["missing", "Qoder runtime model unavailable", "qmodel_38max"], ["catalog", "Qoder model catalog unavailable", undefined], ["catalog500", "Qoder model catalog unavailable", undefined], ["startup-missing", "Qoder runtime model unavailable", "qmodel_38max"], ["startup-catalog", "Qoder model catalog unavailable", undefined], ["exit", "readiness 前退出", undefined]] as const)("maps %s without waiting for the full timeout", async (mode, message, routingKey) => {
    const fixture = await fakeProxy(mode);
    const manager = new QoderRuntimeManager(envFor(fixture, join(fixture.root, "runtime.sock")));
    managers.push(manager); await manager.listen();
    const started = performance.now();
    await expect(manager.acquire(`run-${mode}`, process.pid, "opus")).rejects.toThrow(message);
    expect(performance.now() - started).toBeLessThan(5_000);
    expect(await readFile(fixture.error, "utf8").catch(() => "")).toBe("");
    if (routingKey) expect(routingKey).toBe("qmodel_38max");
  });

  it("accepts a healthy mapped key and releases cleanly", async () => {
    const fixture = await fakeProxy("ok");
    const manager = new QoderRuntimeManager(envFor(fixture, join(fixture.root, "runtime.sock")));
    managers.push(manager); await manager.listen();
    const lease = await manager.acquire("run-ok", process.pid, "opus");
    expect(lease.routingKey).toBe("qmodel_38max");
    manager.release("run-ok", process.pid, lease.leaseId);
  });

  it.each([
    ["missing", "model-unavailable", "qmodel_38max"],
    ["identity", "model-unavailable", "qmodel_38max"],
    ["catalog", "catalog-unavailable", undefined],
  ] as const)("preserves structured %s failure for the runtime wrapper", async (mode, code, routingKey) => {
    const fixture = await fakeProxy(mode);
    const env = envFor(fixture, join(fixture.root, `runtime-${mode}.sock`));
    const manager = new QoderRuntimeManager(env);
    managers.push(manager); await manager.listen();
    await expect(runRuntimeCommand(["acquire", `run-wrapper-${mode}`, String(process.pid), "opus"], env, { stdout() {}, stderr() {} })).rejects.toMatchObject({ code, ...(routingKey ? { routingKey } : {}) });
  });
});

describe("model routing identity endpoint", () => {
  it("rejects a present registered key whose display name drifts", async () => {
    const session = { listModels: async () => ({ generation: 3, models: [{ key: "qmodel_latest", displayName: "Qwen3.7-Plus" }] }) } as unknown as SessionLike;
    const response = await createApp({ QODER_PROXY_API_KEY: "test-key", QODER_CN_INFER_MODEL_KEY: "qmodel_latest" }, session).request("/internal/model-routing", { headers: { authorization: "Bearer test-key" } });
    expect(response.status).toBe(404);
    expect(await response.json()).toMatchObject({ error: { message: "runtime routing model identity unavailable" } });
  });

  it("accepts a present custom qmodel key without registry identity", async () => {
    const session = { listModels: async () => ({ generation: 4, models: [{ key: "qmodel", displayName: "Qwen3.7-Plus" }] }) } as unknown as SessionLike;
    const response = await createApp({ QODER_PROXY_API_KEY: "test-key", QODER_CN_INFER_MODEL_KEY: "qmodel" }, session).request("/internal/model-routing", { headers: { authorization: "Bearer test-key" } });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ ok: true, routingKey: "qmodel", displayName: "Qwen3.7-Plus" });
  });
});

describe("serve model preflight", () => {
  it("accepts a present custom qmodel key without registry identity", async () => {
    const root = await mkdtemp(join(tmpdir(), "qoder-cli-custom-")); roots.push(root);
    let bound = false;
    const session = { listModels: async (): Promise<ModelCatalogSnapshot> => ({ generation: 7, models: [{ key: "qmodel", displayName: "Qwen3.7-Plus" } as never] }) } as unknown as AuthSession;
    const runtime = await runCli(["serve"], { QODER_PROXY_API_KEY: "test-key", QODER_CN_INFER_MODEL_KEY: "qmodel" }, undefined, {
      preflight: async () => session,
      bind: () => { bound = true; return { close() {} }; },
    });
    expect(bound).toBe(true);
    runtime?.close();
  });

  it.each([
    ["missing", new QoderModelUnavailableError("qmodel_38max"), { code: "model-unavailable", routingKey: "qmodel_38max" }],
    ["identity", new QoderModelUnavailableError("qmodel_38max", "identity-mismatch"), { code: "model-unavailable", routingKey: "qmodel_38max" }],
    ["catalog", new CatalogUpstreamError("upstream unavailable", 502), { code: "catalog-unavailable", status: 502 }],
  ] as const)("writes a protected %s startup error and never binds", async (_name, failure, expected) => {
    const root = await mkdtemp(join(tmpdir(), "qoder-cli-preflight-")); roots.push(root);
    const errorFile = join(root, "startup-error.json");
    let bound = false;
    const session = {
      listModels: async (): Promise<ModelCatalogSnapshot> => { throw failure; },
    } as unknown as AuthSession;
    await expect(runCli(["serve"], {
      QODER_PROXY_API_KEY: "test-key",
      QODER_CN_INFER_MODEL_KEY: "qmodel_38max",
      QODER_PROXY_STARTUP_ERROR_FILE: errorFile,
    }, undefined, {
      preflight: async () => session,
      bind: () => { bound = true; return { close() {} }; },
    })).rejects.toThrow(failure.message);
    expect(bound).toBe(false);
    expect(JSON.parse(await readFile(errorFile, "utf8"))).toMatchObject(expected);
  });
});
