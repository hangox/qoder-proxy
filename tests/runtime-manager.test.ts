import { afterEach, describe, expect, it } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest } from "node:http";
import { createStreamingSecretRedactor, QoderRuntimeManager, runRuntimeCommand } from "../src/runtime-manager.ts";
import { QODER_TIER_REGISTRY } from "../src/model-registry.ts";
import { resolveMachineIdSource } from "../src/machine-id.ts";

const managers: QoderRuntimeManager[] = [];
const tempDirs: string[] = [];
afterEach(async () => {
  for (const manager of managers.splice(0)) await manager.stop();
  await Promise.all(tempDirs.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function createFakeProxy(): Promise<{ directory: string; executable: string; starts: string; routes: string; machineSources: string }> {
  const directory = await mkdtemp(join(tmpdir(), "qoder-runtime-test-"));
  tempDirs.push(directory);
  const executable = join(directory, "qoder-proxy");
  const starts = join(directory, "starts");
  const routes = join(directory, "routes");
  const machineSources = join(directory, "machine-sources");
  await writeFile(executable, `#!/usr/bin/env bun
import { appendFileSync } from "node:fs";

appendFileSync(process.env.QODER_RUNTIME_TEST_STARTS!, String(process.pid) + "\\n");
appendFileSync(process.env.QODER_RUNTIME_TEST_ROUTES!, process.env.QODER_CN_INFER_MODEL_KEY + "\\n");
appendFileSync(process.env.QODER_RUNTIME_TEST_MACHINE_SOURCES!, JSON.stringify({ direct: typeof process.env.QODER_CN_MACHINE_ID === "string", file: typeof process.env.QODER_CN_MACHINE_ID_FILE === "string" }) + "\\n");
if (process.env.QODER_RUNTIME_TEST_SPLIT_STDERR === "1") {
  const secret = process.env.QODER_PROXY_API_KEY!;
  process.stderr.write(secret.slice(0, 17));
  setTimeout(() => process.stderr.write(secret.slice(17) + "\\n"), 100);
}
if (process.env.QODER_RUNTIME_TEST_LARGE_STDERR === "1") {
  let index = 0;
  const writeLarge = () => {
    process.stderr.write("x".repeat(300_000) + process.env.QODER_PROXY_API_KEY! + "\\n");
    index += 1;
    if (index < 5) setTimeout(writeLarge, 15);
  };
  writeLarge();
}
const port = Number(process.env.PORT);
const token = process.env.QODER_PROXY_API_KEY!;
const server = Bun.serve({
  hostname: "127.0.0.1",
  port,
  fetch(request) {
    const pathname = new URL(request.url).pathname;
    if (request.headers.get("authorization") !== "Bearer " + token) return new Response(null, { status: 401 });
    if (pathname === "/internal/quota") return Response.json({ percentage: 12, pid: process.pid });
    if (pathname === "/internal/model-routing") {
      const routingKey = process.env.QODER_CN_INFER_MODEL_KEY!;
      const displayName = routingKey === "qmodel_38max" ? "Qwen3.8-Max" : routingKey === "qmodel_latest" ? "Qwen3.7-Max" : routingKey === "q36fmodel" ? "Qwen3.6-Flash" : undefined;
      return Response.json({ ok: true, routingKey, displayName });
    }
    return new Response(null, { status: 404 });
  },
});
process.on("SIGTERM", () => { server.stop(); process.exit(0); });
`, { mode: 0o700 });
  await writeFile(starts, "");
  await writeFile(routes, "");
  await writeFile(machineSources, "");
  return { directory, executable, starts, routes, machineSources };
}

async function requestStatus(url: string, token: string): Promise<number> {
  return await new Promise((resolve, reject) => {
    const request = httpRequest(new URL(url), { headers: { authorization: `Bearer ${token}` } }, (response) => {
      response.resume();
      response.once("end", () => resolve(response.statusCode || 0));
    });
    request.once("error", reject);
    request.setTimeout(500, () => request.destroy(new Error("request timeout")));
    request.end();
  });
}

function envFor(fake: { executable: string; starts: string; routes: string; machineSources: string; directory: string }, socket: string, machineId: string) {
  return {
    PATH: `${fake.directory}:${process.env.PATH || "/usr/bin:/bin"}`,
    QODER_RUNTIME_TEST_MACHINE_SOURCES: fake.machineSources,
    QODER_RUNTIME_TEST_SPLIT_STDERR: "0",
    QODER_RUNTIME_TEST_LARGE_STDERR: "0",
    QODER_PROXY_BIN: fake.executable,
    QODER_RUNTIME_TEST_STARTS: fake.starts,
    QODER_RUNTIME_TEST_ROUTES: fake.routes,
    QODER_PROXY_RUNTIME_SOCKET: socket,
    QODER_CN_MACHINE_ID_FILE: machineId,
    HOME: fake.directory,
    TMPDIR: fake.directory,
  };
}

describe("Qoder runtime stderr secret redaction", () => {
  it("redacts repeated, overlapping, short-secret, and arbitrary chunk boundaries", () => {
    const secret = "aba";
    const chunks = ["a", "b", "aaba", "xx", "aba", "a"];
    const output: string[] = [];
    const redactor = createStreamingSecretRedactor(secret, (chunk) => output.push(chunk));
    for (const chunk of chunks) redactor.write(chunk);
    redactor.flush();
    const value = output.join("");
    expect(value).not.toContain(secret);
    expect(value).toContain("[redacted]");
    expect(value).toContain("xx");
  });

  it("keeps an arbitrary random-like partition safe through flush", () => {
    const secret = "token-1234567890";
    const payload = `prefix-${secret}-middle-${secret}-${secret}-suffix`;
    const output: string[] = [];
    const redactor = createStreamingSecretRedactor(secret, (chunk) => output.push(chunk));
    for (let index = 0; index < payload.length; index += 3) redactor.write(payload.slice(index, index + 3));
    redactor.flush();
    const value = output.join("");
    expect(value).not.toContain(secret);
    expect(value).toContain("[redacted]");
  });

  it("rejects an empty secret rather than disabling redaction", () => {
    expect(() => createStreamingSecretRedactor("", () => {})).toThrow(/secret/);
  });
});

describe("Qoder runtime machine source", () => {
  it("accepts direct-only machine ID and rejects direct plus file ambiguity", () => {
    expect(resolveMachineIdSource({ QODER_CN_MACHINE_ID: "direct-machine" })).toEqual({ direct: "direct-machine" });
    expect(() => resolveMachineIdSource({ QODER_CN_MACHINE_ID: "direct-machine", QODER_CN_MACHINE_ID_FILE: "/tmp/machine_id" })).toThrow(/不能同时/);
  });
});

describe("Qoder runtime manager lease lifecycle", () => {
  it("acquires direct-only machine ID and passes no file override to the child", async () => {
    const fake = await createFakeProxy();
    const socket = join(fake.directory, "runtime-direct.sock");
    const manager = new QoderRuntimeManager({
      ...envFor(fake, socket, join(fake.directory, "unused-machine-id")),
      QODER_CN_MACHINE_ID: "direct-machine",
      QODER_CN_MACHINE_ID_FILE: undefined,
      QODER_PROXY_CONFIG_DIR: join(fake.directory, "missing-config"),
    });
    managers.push(manager);
    await manager.listen();
    const lease = await manager.acquire("run-direct-only", process.pid);
    expect(await requestStatus(`${lease.baseUrl}/internal/quota`, lease.token)).toBe(200);
    manager.release("run-direct-only", process.pid, lease.leaseId);
    expect(JSON.parse((await readFile(fake.machineSources, "utf8")).trim())).toEqual({ direct: true, file: false });
  });

  it("rejects direct plus file machine source during acquire before starting a child", async () => {
    const fake = await createFakeProxy();
    const manager = new QoderRuntimeManager({
      ...envFor(fake, join(fake.directory, "runtime-conflict.sock"), join(fake.directory, "machine-id")),
      QODER_CN_MACHINE_ID: "direct-machine",
      QODER_CN_MACHINE_ID_FILE: join(fake.directory, "machine-id"),
    });
    managers.push(manager);
    await manager.listen();
    await expect(manager.acquire("run-direct-conflict", process.pid)).rejects.toThrow(/不能同时/);
    expect(await readFile(fake.starts, "utf8")).toBe("");
  });

  it("uses the proxy-owned machine ID after an imported session clears the file override", async () => {
    const fake = await createFakeProxy();
    const configDir = join(fake.directory, "config");
    await mkdir(configDir, { mode: 0o700 });
    await writeFile(join(configDir, "machine_id"), "machine-test\n", { mode: 0o600 });
    const env: Record<string, string | undefined> = { ...envFor(fake, join(fake.directory, "runtime.sock"), join(configDir, "machine_id")), QODER_PROXY_CONFIG_DIR: configDir };
    delete env.QODER_CN_MACHINE_ID_FILE;
    const manager = new QoderRuntimeManager(env);
    managers.push(manager);
    await manager.listen();
    const lease = await manager.acquire("run-proxy-owned-machine", process.pid);
    expect(await requestStatus(`${lease.baseUrl}/internal/quota`, lease.token)).toBe(200);
    manager.release("run-proxy-owned-machine", process.pid, lease.leaseId);
  });

  it("starts independently, reaches readiness, and injects an ephemeral key only in memory", async () => {
    const fake = await createFakeProxy();
    const machineId = join(fake.directory, "machine_id");
    await writeFile(machineId, "machine-test\n", { mode: 0o600 });
    const socket = join(fake.directory, "runtime.sock");
    const manager = new QoderRuntimeManager(envFor(fake, socket, machineId));
    managers.push(manager);
    await manager.listen();

    const lease = await manager.acquire("run-independent", process.pid);
    expect(lease.baseUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    expect(lease.token).toMatch(/^[0-9a-f]{64}$/);
    expect(await requestStatus(`${lease.baseUrl}/internal/quota`, lease.token)).toBe(200);
    for (let attempt = 0; attempt < 20 && !(await readFile(fake.starts, "utf8")).match(/\d+/); attempt++) await new Promise((resolve) => setTimeout(resolve, 25));
    expect(await readFile(fake.starts, "utf8")).toMatch(/\d+/);
    expect(await readFile(fake.starts, "utf8")).not.toContain(lease.token);
  });

  it("deduplicates N=8 acquires into one proxy and releases only after the final owner", async () => {
    const fake = await createFakeProxy();
    const machineId = join(fake.directory, "machine_id");
    await writeFile(machineId, "machine-test\n", { mode: 0o600 });
    const manager = new QoderRuntimeManager(envFor(fake, join(fake.directory, "runtime.sock"), machineId));
    managers.push(manager);
    await manager.listen();

    const ownerChildren: ChildProcess[] = [];
    const owners = Array.from({ length: 8 }, () => {
      const child = spawn(process.execPath, ["-e", "setTimeout(() => {}, 10000)"], { stdio: "ignore" });
      ownerChildren.push(child);
      return child.pid!;
    });
    const leases = await Promise.all(owners.map((owner) => manager.acquire("run-shared", owner)));
    expect(new Set(leases.map((lease) => lease.baseUrl))).toHaveLength(1);
    expect(new Set(leases.map((lease) => lease.token))).toHaveLength(1);
    expect((await readFile(fake.starts, "utf8")).trim().split("\n")).toHaveLength(1);

    for (const owner of owners.slice(0, -1)) manager.release("run-shared", owner);
    expect((await fetch(`${leases[0]!.baseUrl}/internal/quota`, { headers: { authorization: `Bearer ${leases[0]!.token}` } })).status).toBe(200);
    manager.release("run-shared", owners.at(-1)!);
    let stopped = false;
    for (let attempt = 0; attempt < 40 && !stopped; attempt++) {
      try {
        stopped = (await requestStatus(`${leases[0]!.baseUrl}/internal/quota`, leases[0]!.token)) !== 200;
      } catch {
        stopped = true;
      }
      if (!stopped) await new Promise((resolve) => setTimeout(resolve, 50));
    }
    expect(stopped).toBe(true);
    for (const child of ownerChildren) child.kill("SIGTERM");
  });

  it("captures bounded private stderr diagnostics and exposes no secret", async () => {
    const fake = await createFakeProxy();
    const socket = join(fake.directory, "runtime-log.sock");
    const machineId = join(fake.directory, "machine-id");
    await writeFile(machineId, "machine-log\n", { mode: 0o600 });
    const manager = new QoderRuntimeManager({ ...envFor(fake, socket, machineId), QODER_RUNTIME_TEST_SPLIT_STDERR: "1", QODER_RUNTIME_TEST_LARGE_STDERR: "1" });
    managers.push(manager);
    await manager.listen();
    const lease = await manager.acquire("run-log", process.pid);
    const logPath = join(fake.directory, "qoder-proxy.stderr.log");
    await new Promise((resolve) => setTimeout(resolve, 150));
    manager.release("run-log", process.pid, lease.leaseId);
    let diagnosticLog = "";
    for (let attempt = 0; attempt < 20; attempt++) {
      try { diagnosticLog = await readFile(logPath, "utf8"); } catch { diagnosticLog = ""; }
      if (diagnosticLog.includes("[redacted]")) break;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    expect(diagnosticLog).toContain("[redacted]");
    expect(diagnosticLog).not.toContain(lease.token);
    expect((await stat(logPath)).mode & 0o077).toBe(0);
    expect((await stat(logPath)).size).toBeLessThanOrEqual(262144);
    const logFiles = await readdir(fake.directory);
    for (const file of logFiles.filter((entry) => entry.startsWith("qoder-proxy.stderr.log"))) {
      expect(await readFile(join(fake.directory, file), "utf8")).not.toContain(lease.token);
    }
    expect(diagnosticLog.length).toBeGreaterThan(0);
  });

  it("publishes status JSON before and after release without the secret", async () => {
    const fake = await createFakeProxy();
    const machineId = join(fake.directory, "machine_id");
    await writeFile(machineId, "machine-test\n", { mode: 0o600 });
    const socket = join(fake.directory, "runtime.sock");
    const manager = new QoderRuntimeManager(envFor(fake, socket, machineId));
    managers.push(manager);
    await manager.listen();
    const lease = await manager.acquire("run-status", process.pid);
    const outputs: string[] = [];
    const io = { stdout: (value: string) => outputs.push(value), stderr: () => {} };
    await runRuntimeCommand(["status", "run-status", String(process.pid), lease.leaseId], envFor(fake, socket, machineId), io);
    expect(JSON.parse(outputs.pop()!)).toMatchObject({ active: true, runId: "run-status", ownerPid: process.pid, leaseId: lease.leaseId, baseUrl: lease.baseUrl, socketPath: socket, diagnostics: { stderrPath: join(fake.directory, "qoder-proxy.stderr.log"), maxBytes: 262144, rotationFiles: 3 } });
    expect(outputs.join("\n")).not.toContain(lease.token);
    manager.release("run-status", process.pid, lease.leaseId);
    await runRuntimeCommand(["status", "run-status", String(process.pid), lease.leaseId], envFor(fake, socket, machineId), io);
    expect(JSON.parse(outputs.pop()!)).toMatchObject({ active: false, runId: "run-status", ownerPid: process.pid, leaseId: lease.leaseId, socketPath: socket, diagnostics: { stderrPath: join(fake.directory, "qoder-proxy.stderr.log"), maxBytes: 262144, rotationFiles: 3 } });
  });

  it("routes opus sonnet and haiku through one tier registry", async () => {
    const fake = await createFakeProxy();
    const machineId = join(fake.directory, "machine_id");
    await writeFile(machineId, "machine-test\n", { mode: 0o600 });
    const manager = new QoderRuntimeManager(envFor(fake, join(fake.directory, "runtime.sock"), machineId));
    managers.push(manager);
    await manager.listen();
    for (const tier of ["opus", "sonnet", "haiku"] as const) {
      const lease = await manager.acquire(`tier-${tier}`, process.pid, tier);
      expect(lease.tier).toBe(tier);
      expect(lease.routingKey).toBe(({ opus: "qmodel_38max", sonnet: "qmodel_latest", haiku: "q36fmodel" } as const)[tier]);
      manager.release(`tier-${tier}`, process.pid, lease.leaseId);
    }
    expect((await readFile(fake.routes, "utf8")).replace(/\s+/g, " ").trim()).toBe("qmodel_38max qmodel_latest q36fmodel");
  });

  it("uses distinct credentials per run and rejects cross-run keys", async () => {
    const fake = await createFakeProxy();
    const machineId = join(fake.directory, "machine_id");
    await writeFile(machineId, "machine-test\n", { mode: 0o600 });
    const manager = new QoderRuntimeManager(envFor(fake, join(fake.directory, "runtime.sock"), machineId));
    managers.push(manager);
    await manager.listen();

    const first = await manager.acquire("run-one", process.pid);
    const second = await manager.acquire("run-two", process.pid);
    expect(first.token).not.toBe(second.token);
    expect(first.baseUrl).not.toBe(second.baseUrl);
    expect(await requestStatus(`${first.baseUrl}/internal/quota`, first.token)).toBe(200);
    expect(await requestStatus(`${first.baseUrl}/internal/quota`, second.token)).toBe(401);
  });

  it("fails closed and does not leave a child when readiness fails", async () => {
    const fake = await createFakeProxy();
    const machineId = join(fake.directory, "machine_id");
    await writeFile(machineId, "machine-test\n", { mode: 0o600 });
    const manager = new QoderRuntimeManager({ ...envFor(fake, join(fake.directory, "runtime.sock"), machineId), QODER_PROXY_BIN: join(fake.directory, "missing") });
    managers.push(manager);
    await manager.listen();
    await expect(manager.acquire("run-failure", process.pid)).rejects.toThrow(/不可执行|未找到/);
    expect(await readFile(fake.starts, "utf8")).toBe("");
  });
});
