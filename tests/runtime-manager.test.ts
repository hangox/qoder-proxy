import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { spawn, type ChildProcess } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { QoderRuntimeManager } from "../src/runtime-manager.ts";

const managers: QoderRuntimeManager[] = [];
const tempDirs: string[] = [];
const fakeChildren: ChildProcess[] = [];

afterEach(async () => {
  for (const manager of managers.splice(0)) await manager.stop();
  for (const child of fakeChildren.splice(0)) { child.kill("SIGTERM"); await new Promise((resolve) => child.once("exit", resolve)); }
  await Promise.all(tempDirs.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function createFakeProxy(): Promise<{ directory: string; executable: string; starts: string }> {
  const directory = await mkdtemp(join(tmpdir(), "qoder-runtime-test-"));
  tempDirs.push(directory);
  const executable = join(directory, "qoder-proxy");
  const starts = join(directory, "starts");
  await writeFile(executable, `#!/usr/bin/env python3
import json
import os
import signal
from http.server import BaseHTTPRequestHandler, HTTPServer

with open(os.environ["QODER_RUNTIME_TEST_STARTS"], "a") as starts:
    starts.write(str(os.getpid()) + "\\n")
port = int(os.environ["PORT"])
token = os.environ["QODER_PROXY_API_KEY"]
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/internal/quota":
            self.send_response(404); self.end_headers(); return
        if self.headers.get("Authorization") != "Bearer " + token:
            self.send_response(401); self.end_headers(); return
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps({"percentage": 12, "pid": os.getpid()}).encode())
    def log_message(self, *_): pass
server = HTTPServer(("127.0.0.1", port), Handler)
signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
server.serve_forever()
`, { mode: 0o700 });
  await writeFile(starts, "");
  return { directory, executable, starts };
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
    const readyResponse = await fetch(`${lease.baseUrl}/internal/quota`, { headers: { authorization: `Bearer ${lease.token}` } });
    expect(readyResponse.status).toBe(200);
    await readyResponse.arrayBuffer();
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

    const owners = Array.from({ length: 8 }, (_, index) => process.pid + index + 1);
    const leases = await Promise.all(owners.map((owner) => manager.acquire("run-shared", owner)));
    expect(new Set(leases.map((lease) => lease.baseUrl))).toHaveLength(1);
    expect(new Set(leases.map((lease) => lease.token))).toHaveLength(1);
    expect((await readFile(fake.starts, "utf8")).trim().split("\n")).toHaveLength(1);

    for (const owner of owners.slice(0, -1)) manager.release("run-shared", owner);
    expect((await fetch(`${leases[0]!.baseUrl}/internal/quota`, { headers: { authorization: `Bearer ${leases[0]!.token}` } })).status).toBe(200);
    manager.release("run-shared", owners.at(-1)!);
    await new Promise((resolve) => setTimeout(resolve, 150));
    await expect(fetch(`${leases[0]!.baseUrl}/internal/quota`, { headers: { authorization: `Bearer ${leases[0]!.token}` } })).rejects.toThrow();
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
    const firstResponse = await fetch(`${first.baseUrl}/internal/quota`, { headers: { authorization: `Bearer ${first.token}` } });
    expect(firstResponse.status).toBe(200);
    const firstBody = await firstResponse.json() as { pid?: number };
    expect(firstBody.pid).toBeTypeOf("number");
    const crossRunResponse = await fetch(`${first.baseUrl}/internal/quota`, { headers: { authorization: `Bearer ${second.token}` } });
    expect(crossRunResponse.status).toBe(401);
    await crossRunResponse.arrayBuffer();
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
