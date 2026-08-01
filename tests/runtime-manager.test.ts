import { afterEach, describe, expect, it } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest } from "node:http";
import { QoderRuntimeManager } from "../src/runtime-manager.ts";

const managers: QoderRuntimeManager[] = [];
const tempDirs: string[] = [];
afterEach(async () => {
  for (const manager of managers.splice(0)) await manager.stop();
  await Promise.all(tempDirs.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function createFakeProxy(): Promise<{ directory: string; executable: string; starts: string }> {
  const directory = await mkdtemp(join(tmpdir(), "qoder-runtime-test-"));
  tempDirs.push(directory);
  const executable = join(directory, "qoder-proxy");
  const starts = join(directory, "starts");
  await writeFile(executable, `#!/usr/bin/env bun
import { appendFileSync } from "node:fs";

appendFileSync(process.env.QODER_RUNTIME_TEST_STARTS!, String(process.pid) + "\\n");
const port = Number(process.env.PORT);
const token = process.env.QODER_PROXY_API_KEY!;
const server = Bun.serve({
  hostname: "127.0.0.1",
  port,
  fetch(request) {
    if (new URL(request.url).pathname !== "/internal/quota") return new Response(null, { status: 404 });
    if (request.headers.get("authorization") !== "Bearer " + token) return new Response(null, { status: 401 });
    return Response.json({ percentage: 12, pid: process.pid });
  },
});
process.on("SIGTERM", () => { server.stop(); process.exit(0); });
`, { mode: 0o700 });
  await writeFile(starts, "");
  return { directory, executable, starts };
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

function envFor(fake: { executable: string; starts: string; directory: string }, socket: string, machineId: string) {
  return {
    PATH: `${fake.directory}:${process.env.PATH || "/usr/bin:/bin"}`,
    QODER_PROXY_BIN: fake.executable,
    QODER_RUNTIME_TEST_STARTS: fake.starts,
    QODER_PROXY_RUNTIME_SOCKET: socket,
    QODER_CN_MACHINE_ID_FILE: machineId,
    HOME: fake.directory,
    TMPDIR: fake.directory,
  };
}

describe("Qoder runtime manager lease lifecycle", () => {
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
