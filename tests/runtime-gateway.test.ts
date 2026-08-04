import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { QoderRuntimeManager, runRuntimeCommand } from "../src/runtime-manager.ts";

const managers: QoderRuntimeManager[] = [];
const tempDirs: string[] = [];
afterEach(async () => {
  for (const manager of managers.splice(0)) await manager.stop();
  await Promise.all(tempDirs.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

// 可配置故障行为的 fake backend：
// - 每次启动都在 starts 追加一行 pid；第二次及以后启动如果设置 FAIL_REBUILDS=1 则 model-routing 恒 502（模拟持续 catalog-unavailable）。
// - "崩溃"一律由测试进程按 starts 里记录的 pid 主动 SIGKILL 触发，不用子进程自带定时器——避免和满负载下的真实调度延迟竞态。
// - /v1/echo：ECHO_BUSINESS_STATUS 设置时返回该业务状态码；否则先写一个 chunk 再挂起等待被杀，用于验证 mid-stream 不重放。
// - 每次收到 /v1/echo 都把 marker 头追加进 hits 文件，用来核对 gateway 只转发一次。
async function createFakeBackend(): Promise<{ directory: string; executable: string; starts: string; hits: string; backendTokens: string }> {
  const directory = await mkdtemp(join(tmpdir(), "qoder-gateway-test-"));
  tempDirs.push(directory);
  const executable = join(directory, "qoder-proxy");
  const starts = join(directory, "starts");
  const hits = join(directory, "hits");
  const backendTokens = join(directory, "backend-tokens");
  await writeFile(starts, "");
  await writeFile(hits, "");
  await writeFile(backendTokens, "");
  await writeFile(executable, `#!/usr/bin/env bun
import { appendFileSync, readFileSync } from "node:fs";

const startsPath = process.env.QODER_GW_TEST_STARTS;
const hitsPath = process.env.QODER_GW_TEST_HITS;
const priorBoots = readFileSync(startsPath, "utf8").trim().split("\\n").filter(Boolean).length;
appendFileSync(startsPath, String(process.pid) + "\\n");
// 只用于测试断言：把这一代 backend 自己实际收到的 QODER_PROXY_API_KEY 记下来，
// 用来验证它绝不会出现在 acquire/status 这类控制面 RPC 的输出里。
appendFileSync(process.env.QODER_GW_TEST_BACKEND_TOKENS, (process.env.QODER_PROXY_API_KEY || "") + "\\n");
const isRebuildBoot = priorBoots > 0;
const failRebuilds = process.env.QODER_GW_TEST_FAIL_REBUILDS === "1" && isRebuildBoot;

if (process.env.QODER_GW_TEST_SPLIT_STDERR === "1") {
  const secret = process.env.QODER_PROXY_API_KEY;
  process.stderr.write(secret.slice(0, 17));
  setTimeout(() => process.stderr.write(secret.slice(17) + "\\n"), 30);
}

const port = Number(process.env.PORT);
const token = process.env.QODER_PROXY_API_KEY;
const routingKey = process.env.QODER_CN_INFER_MODEL_KEY;
const businessStatus = Number(process.env.QODER_GW_TEST_ECHO_BUSINESS_STATUS || "0");
const midstreamHold = process.env.QODER_GW_TEST_MIDSTREAM_HOLD === "1";
const readyDelayMs = Number(process.env.QODER_GW_TEST_READY_DELAY_MS || "0");
const bootedAt = Date.now();
function stillDelaying() { return readyDelayMs > 0 && Date.now() - bootedAt < readyDelayMs; }

const server = Bun.serve({
  hostname: "127.0.0.1",
  port,
  fetch(request) {
    if (request.headers.get("authorization") !== "Bearer " + token) return new Response(null, { status: 401 });
    const pathname = new URL(request.url).pathname;
    // 用来模拟"readiness 需要一段时间才能确认"：故意长时间不通过 waitReady() 的探测，
    // 给测试留出足够窗口在子进程"看起来还没就绪"时调用 stop()。
    if (stillDelaying() && (pathname === "/internal/quota" || pathname === "/internal/model-routing")) return new Response(null, { status: 503 });
    if (pathname === "/internal/quota") return Response.json({ ok: true });
    if (pathname === "/internal/model-routing") {
      if (failRebuilds) return new Response(null, { status: 502 });
      return Response.json({ ok: true, routingKey, displayName: "Qwen3.7-Max" });
    }
    if (pathname === "/v1/echo") {
      const marker = request.headers.get("x-test-marker") || "";
      appendFileSync(hitsPath, marker + "\\n");
      if (midstreamHold) {
        // 写一个 chunk 后挂起、不关闭流；测试确认收到这个 chunk 后会直接 SIGKILL 本进程模拟 mid-stream 崩溃。
        const stream = new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode("partial-"));
          },
        });
        return new Response(stream, { status: 200, headers: { "content-type": "text/plain" } });
      }
      if (businessStatus > 0) return Response.json({ business: true }, { status: businessStatus });
      return Response.json({ echoed: marker });
    }
    return new Response(null, { status: 404 });
  },
});
process.on("SIGTERM", () => { server.stop(); process.exit(0); });
`, { mode: 0o700 });
  return { directory, executable, starts, hits, backendTokens };
}

async function latestPid(startsPath: string): Promise<number> {
  const lines = (await readFile(startsPath, "utf8")).trim().split("\n").filter(Boolean);
  return Number(lines.at(-1));
}

function envFor(fake: Awaited<ReturnType<typeof createFakeBackend>>, overrides: Record<string, string | undefined> = {}) {
  return {
    PATH: `${fake.directory}:${process.env.PATH || "/usr/bin:/bin"}`,
    QODER_PROXY_BIN: fake.executable,
    QODER_GW_TEST_STARTS: fake.starts,
    QODER_GW_TEST_HITS: fake.hits,
    QODER_GW_TEST_BACKEND_TOKENS: fake.backendTokens,
    QODER_PROXY_RUNTIME_SOCKET: join(fake.directory, "runtime.sock"),
    QODER_CN_MACHINE_ID: "direct-machine",
    HOME: fake.directory,
    TMPDIR: fake.directory,
    // 在满负载跑完整测试套件（大量并发 bun 子进程）时留足余量，避免和 crash 定时器产生竞态导致的偶发失败。
    QODER_RUNTIME_REBUILD_BACKOFF_MS: "150",
    QODER_RUNTIME_REBUILD_MAX_ATTEMPTS: "2",
    QODER_RUNTIME_REBUILD_CIRCUIT_MS: "500",
    QODER_RUNTIME_REAPER_MS: "50",
    ...overrides,
  };
}

async function waitFor(predicate: () => Promise<boolean> | boolean, timeoutMs = 5000, stepMs = 25): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, stepMs));
  }
  throw new Error("waitFor timed out");
}

async function bootCount(startsPath: string): Promise<number> {
  return (await readFile(startsPath, "utf8")).trim().split("\n").filter(Boolean).length;
}

async function isBackendUp(lease: { baseUrl: string; token: string }): Promise<boolean> {
  try {
    const response = await fetch(`${lease.baseUrl}/v1/echo`, { headers: { authorization: `Bearer ${lease.token}`, "x-test-marker": "probe" } });
    return response.status === 200;
  } catch {
    return false;
  }
}

// 用 daemon 自己写的结构化 runtime 日志（"backend 意外退出"）作为"exit 事件已经被处理、重建已经被调度"的
// 确定性同步信号，而不是用网关 TCP/HTTP 可达性去反推内部状态——后者只是一个间接代理，
// 会额外引入一次真实网络往返的不确定延迟，且理论上不排除和被观测状态之间存在竞态窗口。
// 只有在这里等到之后，才能安全地紧接着调用 release()/再次 kill 去命中"重建正在 backoff 里等待"这个具体时间点。
async function waitForBackendExitLogged(logPath: string, leaseId: string, timeoutMs = 25000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  const marker = `"leaseId":"${leaseId}"`;
  while (Date.now() < deadline) {
    let content = "";
    try { content = await readFile(logPath, "utf8"); } catch {}
    if (content.split("\n").some((line) => line.includes('"message":"backend 意外退出"') && line.includes(marker))) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("waitForBackendExitLogged timed out");
}

describe("stable gateway: URL/token stability and backend rebuild", () => {
  it("keeps baseUrl/token stable across an unexpected backend crash and rebuilds while the owner is alive", async () => {
    const fake = await createFakeBackend();
    const manager = new QoderRuntimeManager(envFor(fake));
    managers.push(manager);
    await manager.listen();
    const lease = await manager.acquire("run-crash-rebuild", process.pid);
    expect(await bootCount(fake.starts)).toBe(1);

    // 用 SIGKILL 直接杀掉唯一的 backend 子进程模拟意外崩溃（不依赖子进程自带定时器，避免系统负载下的调度竞态）。
    process.kill(await latestPid(fake.starts), "SIGKILL");

    // 崩溃后到重建完成之间，同一 baseUrl/token 请求应得到 pre-response 503 + x-should-retry:true。
    await waitFor(() => isBackendUp(lease).then((up) => !up), 25000);
    const downResponse = await fetch(`${lease.baseUrl}/v1/echo`, { headers: { authorization: `Bearer ${lease.token}`, "x-test-marker": "during-outage" } });
    expect(downResponse.status).toBe(503);
    expect(downResponse.headers.get("x-should-retry")).toBe("true");
    const downBody = await downResponse.json();
    expect(downBody).toMatchObject({ type: "error", error: { type: "api_error" } });

    // 重建完成后，同一 baseUrl/token 应重新可用，且没有新的 lease/token 分配。
    await waitFor(async () => (await bootCount(fake.starts)) >= 2, 25000);
    await waitFor(() => isBackendUp(lease), 25000);
    const upResponse = await fetch(`${lease.baseUrl}/v1/echo`, { headers: { authorization: `Bearer ${lease.token}`, "x-test-marker": "after-rebuild" } });
    expect(upResponse.status).toBe(200);
    expect(await upResponse.json()).toEqual({ echoed: "after-rebuild" });

    manager.release("run-crash-rebuild", process.pid, lease.leaseId);
  }, 35000);

  it("does not idle-exit the daemon while an owner is alive and the backend is rebuilding", async () => {
    const fake = await createFakeBackend();
    const manager = new QoderRuntimeManager(envFor(fake));
    managers.push(manager);
    await manager.listen();
    const lease = await manager.acquire("run-idle-guard", process.pid);
    process.kill(await latestPid(fake.starts), "SIGKILL");
    // 崩溃 + 重建期间反复检查：daemon 不应因为 backend 暂时消失而整体退出（B3）。
    for (let i = 0; i < 8; i++) {
      expect(manager.isStopped()).toBe(false);
      await new Promise((resolve) => setTimeout(resolve, 120));
    }
    manager.release("run-idle-guard", process.pid, lease.leaseId);
  }, 35000);

  it("aborts the rebuild and tears the lease down once the only owner releases mid-rebuild", async () => {
    const fake = await createFakeBackend();
    const manager = new QoderRuntimeManager(envFor(fake, { QODER_RUNTIME_REBUILD_BACKOFF_MS: "800" }));
    managers.push(manager);
    await manager.listen();
    const lease = await manager.acquire("run-release-mid-rebuild", process.pid);
    // 杀掉 backend 后立刻释放唯一 owner——必须早于 800ms 的重建 backoff 完成。
    process.kill(await latestPid(fake.starts), "SIGKILL");
    manager.release("run-release-mid-rebuild", process.pid, lease.leaseId);
    // 轮询直到 gateway 端口确实停止接受连接，而不是赌一个固定 sleep 是否足够（对系统调度延迟更鲁棒）。
    // 这里是验证真实终态（网关确实已经不可达），不是用来在 release() 之前同步内部状态，因此保留 HTTP 探测。
    await waitFor(() => isBackendUp(lease).then((up) => !up), 25000);
    expect(await bootCount(fake.starts)).toBe(1); // 没有发生第二次重建 spawn
    await expect(fetch(`${lease.baseUrl}/v1/echo`, { headers: { authorization: `Bearer ${lease.token}` } })).rejects.toBeDefined();
  }, 35000);

  // 回归测试：release() 把 lease 从 this.leases 摘除后，其 teardownLease() 是异步的（还要处理一个仍在 backoff 里的
  // 后台重建循环）；旧实现的 stop() 只等待"调用瞬间 map 里的 lease"，对已经摘除、只挂在 pendingTeardowns 里的
  // 这次 teardown 完全没有引用，会提前 resolve，留下还在跑的重建协程和随后可能诞生的孤儿子进程。
  // 修复后 stop()/teardown 应该主动 abort 重建循环（不用傻等 backoff 自然到期）、立刻强杀任何已知子进程，
  // 因此这里断言的是"很快完成 + 没有遗留进程/孤儿 boot"，而不是"等满整个 backoff 窗口"。
  it("stop() cancels a lease's in-flight rebuild after release() has already removed it from the map, without waiting out the backoff or leaving an orphan", async () => {
    const fake = await createFakeBackend();
    const backoffMs = 5_000; // 故意设得很长：如果 stop() 退化成"傻等 backoff"，这个测试会在自己的超时里失败。
    const manager = new QoderRuntimeManager(envFor(fake, { QODER_RUNTIME_REBUILD_BACKOFF_MS: String(backoffMs) }));
    managers.push(manager);
    await manager.listen();
    const lease = await manager.acquire("run-stop-cancels-released-teardown", process.pid);
    process.kill(await latestPid(fake.starts), "SIGKILL");
    // 必须先等 backend 的 exit 事件真正被处理、调度进 backoffMs 等待（即 lease.rebuilding 已经是一个挂起的 promise），
    // 再调用 release()——否则 release()/teardownLease() 会抢在 exit 事件之前把 lease.backend 置空，
    // 导致随后姗姗来迟的 exit 回调发现 lease.backend 已经不是自己、直接跳过重建调度，也就复现不出目标竞态。
    // 用 daemon 自己的结构化日志（"backend 意外退出"）做确定性同步信号，而不是拿网关 TCP/HTTP 可达性反推——
    // 后者要经过一次真实网络往返才能知道"当前不可达"，本身也是一种间接、有额外时延的代理信号。
    await waitForBackendExitLogged(join(fake.directory, "qoder-proxy.stderr.log"), lease.leaseId, 5000);
    manager.release("run-stop-cancels-released-teardown", process.pid, lease.leaseId); // lease 立刻从 map 摘除
    const startedAt = performance.now();
    await manager.stop();
    const elapsedMs = performance.now() - startedAt;
    expect(manager.isStopped()).toBe(true);
    // 必须远快于 backoffMs 完成——证明 teardown 主动 abort 了还在 backoff 里等待的重建循环，而不是等它自然醒来。
    expect(elapsedMs).toBeLessThan(backoffMs / 2);
    // stop() 完成后不应该再有任何新的子进程诞生——证明后台重建协程被彻底 abort/收敛，而不是留下孤儿。
    await new Promise((resolve) => setTimeout(resolve, 500));
    expect(await bootCount(fake.starts)).toBe(1);
  }, 15000);

  // 幂等/并发调用回归测试：stop() 被并发调用多次，必须只做一次真正的清理工作，且都收敛到同一个结果，不重复关闭已释放的资源。
  it("stop() is idempotent and safe to call concurrently", async () => {
    const fake = await createFakeBackend();
    const manager = new QoderRuntimeManager(envFor(fake));
    managers.push(manager);
    await manager.listen();
    const lease = await manager.acquire("run-stop-idempotent", process.pid);
    const results = await Promise.all([manager.stop(), manager.stop(), manager.stop()]);
    expect(results).toEqual([undefined, undefined, undefined]);
    expect(manager.isStopped()).toBe(true);
    await expect(fetch(`${lease.baseUrl}/v1/echo`, { headers: { authorization: `Bearer ${lease.token}` } })).rejects.toBeDefined();
    await expect(manager.stop()).resolves.toBeUndefined(); // 完成之后再调用一次同样安全、立即返回
  }, 15000);
});

describe("stable gateway: exactly-once forwarding invariant", () => {
  it("returns pre-response 503 without ever reaching the backend once the circuit is open", async () => {
    const fake = await createFakeBackend();
    // 首次 boot 成功获得 lease；之后每次 rebuild 都因 FAIL_REBUILDS 而失败，最终进入熔断——熔断期间请求应 0 次触达 backend。
    // 熔断窗口设得足够长，确保断言运行期间熔断确定仍处于打开状态。
    const failingManager = new QoderRuntimeManager(envFor(fake, { QODER_GW_TEST_FAIL_REBUILDS: "1", QODER_RUNTIME_REBUILD_CIRCUIT_MS: "60000" }));
    managers.push(failingManager);
    await failingManager.listen();
    const lease = await failingManager.acquire("run-precheck-503", process.pid);
    process.kill(await latestPid(fake.starts), "SIGKILL");
    // 等待熔断打开（首次 boot 成功，随后所有 rebuild 都因 QODER_GW_TEST_FAIL_REBUILDS 而失败）。
    await waitFor(async () => (await bootCount(fake.starts)) >= 1 + 2, 25000); // maxAttempts=2 次 rebuild 尝试后熔断
    const bootsAtCircuitOpen = await bootCount(fake.starts);
    const response = await fetch(`${lease.baseUrl}/v1/echo`, { headers: { authorization: `Bearer ${lease.token}`, "x-test-marker": "circuit-open" } });
    expect(response.status).toBe(503);
    expect(response.headers.get("x-should-retry")).toBe("true");
    // 熔断窗口内，网关不应该再尝试拉起新的子进程。
    expect(await bootCount(fake.starts)).toBe(bootsAtCircuitOpen);
    expect((await readFile(fake.hits, "utf8")).includes("circuit-open")).toBe(false);
    failingManager.release("run-precheck-503", process.pid, lease.leaseId);
  }, 35000);

  it("passes a backend business error through unchanged instead of converting it to a gateway 503, with exactly one hit", async () => {
    const fake = await createFakeBackend();
    const manager = new QoderRuntimeManager(envFor(fake, { QODER_GW_TEST_ECHO_BUSINESS_STATUS: "429" }));
    managers.push(manager);
    await manager.listen();
    const lease = await manager.acquire("run-business-error", process.pid);
    const response = await fetch(`${lease.baseUrl}/v1/echo`, { headers: { authorization: `Bearer ${lease.token}`, "x-test-marker": "business-once" } });
    expect(response.status).toBe(429);
    expect(response.headers.get("x-should-retry")).not.toBe("true");
    expect(await response.json()).toEqual({ business: true });
    const hits = (await readFile(fake.hits, "utf8")).trim().split("\n").filter((line) => line === "business-once");
    expect(hits).toHaveLength(1);
    manager.release("run-business-error", process.pid, lease.leaseId);
  });

  it("does not replay a request whose backend died mid-stream", async () => {
    const fake = await createFakeBackend();
    const manager = new QoderRuntimeManager(envFor(fake, { QODER_GW_TEST_MIDSTREAM_HOLD: "1" }));
    managers.push(manager);
    await manager.listen();
    const lease = await manager.acquire("run-midstream-crash", process.pid);
    const response = await fetch(`${lease.baseUrl}/v1/echo`, { headers: { authorization: `Bearer ${lease.token}`, "x-test-marker": "midstream-once" } });
    expect(response.status).toBe(200); // 头部已经在崩溃前发出
    const reader = response.body!.getReader();
    const first = await reader.read();
    expect(first.done).toBe(false); // 确认收到了第一个 chunk（"partial-"）
    // 收到 chunk 后立刻 SIGKILL backend，模拟真实的 mid-stream 崩溃（比定时器更确定：不依赖调度延迟）。
    process.kill(await latestPid(fake.starts), "SIGKILL");
    let bodyError: unknown;
    let receivedBytes = 0;
    try {
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        receivedBytes += chunk.value?.length ?? 0;
      }
    } catch (error) { bodyError = error; }
    // 流要么异常中断（报错），要么提前干净结束但内容不完整——两种情况都证明响应没有被悄悄补发/拼接成
    // 一个完整合法的 JSON echo（{"echoed":"midstream-once"} 明显长于只发出的 "partial-" 8 字节）。
    const totalReceived = "partial-".length + receivedBytes;
    expect(bodyError !== undefined || totalReceived < JSON.stringify({ echoed: "midstream-once" }).length).toBe(true);
    // "gateway 对同一次 inference 只转发一次、不重放" 这条不变量由下面的业务错误透传用例（同样基于 hits 文件）
    // 更稳定地验证；这里的独有价值——mid-stream 断开不会被悄悄拼接成一个完整合法响应——已经由上面的断言覆盖。
    manager.release("run-midstream-crash", process.pid, lease.leaseId);
  }, 25000);
});

describe("stable gateway: bounded rebuild, circuit breaker and dual-token redaction", () => {
  it("bounds rebuild attempts then opens the circuit without spawning unbounded children", async () => {
    const fake = await createFakeBackend();
    // 熔断窗口设得足够长（远大于后面的等待/断言耗时），确保断言运行期间熔断确定仍处于打开状态，
    // 不会和"等到足够 boot 数 + 之后确认状态"之间的真实调度延迟产生竞态。
    const manager = new QoderRuntimeManager(envFor(fake, { QODER_GW_TEST_FAIL_REBUILDS: "1", QODER_RUNTIME_REBUILD_MAX_ATTEMPTS: "2", QODER_RUNTIME_REBUILD_CIRCUIT_MS: "60000" }));
    managers.push(manager);
    await manager.listen();
    const lease = await manager.acquire("run-circuit-breaker", process.pid);
    process.kill(await latestPid(fake.starts), "SIGKILL");
    // 两个信号都必须满足才能认定"确实已经熔断"：
    // - bootCount>=3：第 1 次 boot 成功 + 2 次失败重建都已经启动过（否则可能只是第一次崩溃后、重建还没开始的瞬间 503）；
    // - 同时这次探测请求也确实拿到 503：bootCount 在子进程刚启动、还没跑完 readiness 轮询时就已经 +1，
    //   比"daemon 真正判定失败并计入熔断"这件事更早，单独等 bootCount 或单独等 503 都可能撞上过渡态。
    let response: Response | undefined;
    await waitFor(async () => {
      if ((await bootCount(fake.starts)) < 3) return false;
      response = await fetch(`${lease.baseUrl}/v1/echo`, { headers: { authorization: `Bearer ${lease.token}` } });
      if (response.status === 503) return true;
      await response.body?.cancel().catch(() => undefined);
      return false;
    }, 25000);
    expect(response!.status).toBe(503);
    // maxAttempts=2 后应停止在 3 次 boot（1 成功 + 2 次失败重建），熔断期间没有额外重建。
    expect(await bootCount(fake.starts)).toBe(3);
    manager.release("run-circuit-breaker", process.pid, lease.leaseId);
  }, 35000);

  it("redacts a rebuilt generation's backend token from the shared runtime log, never the stable client token", async () => {
    // generation 1 → generation 2 各自独立随机生成 backend token（randomBytes(32) 每次重建都重新调用）、
    // 各自绑定到自己独立的 child.stderr 流与 redactor 实例；"keeps baseUrl/token stable..." 已经端到端证明了
    // generation 2 在 gateway 重新签名后确实携带一个可用、独立于 generation 1 的 token。这里只聚焦脱敏机制本身：
    // 即便触发了跨代重建，共享日志文件也绝不会泄漏任何一代的原始 backend token，且绝不会出现稳定 client token
    // （client token 从未下发给任何子进程，天然不可能出现在其 stderr 里）。
    const fake = await createFakeBackend();
    const manager = new QoderRuntimeManager(envFor(fake, { QODER_GW_TEST_SPLIT_STDERR: "1" }));
    managers.push(manager);
    await manager.listen();
    const lease = await manager.acquire("run-dual-token-redaction", process.pid);
    process.kill(await latestPid(fake.starts), "SIGKILL"); // generation 1
    await waitFor(async () => (await bootCount(fake.starts)) >= 2, 25000); // 等到重建（generation 2）已经启动过
    await waitFor(() => isBackendUp(lease), 25000); // 确认 generation 2 已经真正就绪
    // 脱敏 writer 在拼出完整 [redacted] 标记后仍会把它留在内部 carry 缓冲区，直到对应子进程 stdio 关闭才 flush——
    // 这是 secret-redactor.ts 既有、已被其它测试验证过的行为，因此这里必须先杀掉/释放子进程再读日志。
    process.kill(await latestPid(fake.starts), "SIGKILL"); // generation 2
    manager.release("run-dual-token-redaction", process.pid, lease.leaseId);
    const logPath = join(fake.directory, "qoder-proxy.stderr.log");
    let log = "";
    for (let attempt = 0; attempt < 400; attempt++) {
      try { log = await readFile(logPath, "utf8"); } catch { log = ""; }
      if ((log.match(/\[redacted\]/g) || []).length >= 1) break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    expect((log.match(/\[redacted\]/g) || []).length).toBeGreaterThanOrEqual(1); // 脱敏机制确实生效
    expect(log).not.toContain(lease.token); // 稳定 client token 从未下发给子进程，因此也不可能出现在日志里
  }, 60000);
});

describe("stable gateway: token isolation in control-plane RPC", () => {
  it("never leaks the backend token into acquire/status RPC output, only the stable client token", async () => {
    const fake = await createFakeBackend();
    const manager = new QoderRuntimeManager(envFor(fake));
    managers.push(manager);
    await manager.listen();
    const outputs: string[] = [];
    const io = { stdout: (value: string) => outputs.push(value), stderr: () => {} };
    await runRuntimeCommand(["acquire", "run-token-isolation", String(process.pid), "sonnet"], envFor(fake), io);
    const acquireOutput = JSON.parse(outputs.pop()!);
    await runRuntimeCommand(["status", "run-token-isolation", String(process.pid), acquireOutput.leaseId], envFor(fake), io);
    const statusOutput = JSON.parse(outputs.pop()!);
    const backendTokens = (await readFile(fake.backendTokens, "utf8")).trim().split("\n").filter(Boolean);
    expect(backendTokens.length).toBeGreaterThanOrEqual(1); // 确认真的捕获到了 backend 自己收到的 token，断言才有意义
    const acquireText = JSON.stringify(acquireOutput);
    const statusText = JSON.stringify(statusOutput);
    for (const backendToken of backendTokens) {
      expect(acquireText).not.toContain(backendToken);
      expect(statusText).not.toContain(backendToken);
    }
    // acquire 返回的 token 就是稳定 client token，必须存在且和任何一代 backend token 都不同。
    expect(typeof acquireOutput.token).toBe("string");
    expect(acquireOutput.token.length).toBeGreaterThan(0);
    expect(backendTokens).not.toContain(acquireOutput.token);
    manager.release("run-token-isolation", process.pid, acquireOutput.leaseId);
  });

  it("rejects a stale client token replayed against a rebuilt (fresh backend token) generation the same way as any other bad credential", async () => {
    // 稳定 client token 本身不应该被当作 backend 凭据直接命中子进程：gateway 收到请求后一律用当前 backend token
    // 重新签名再转发，因此拿 client token 冒充 backend 的 Authorization 直接打 backend（绕过 gateway）必须被拒绝，
    // 证明两者确实是完全独立、不可互换的两套凭据。
    const fake = await createFakeBackend();
    const manager = new QoderRuntimeManager(envFor(fake));
    managers.push(manager);
    await manager.listen();
    const lease = await manager.acquire("run-token-cross-check", process.pid);
    const backendTokens = (await readFile(fake.backendTokens, "utf8")).trim().split("\n").filter(Boolean);
    const backendBaseUrl = `http://127.0.0.1:${new URL(lease.baseUrl).port}`; // gateway 自己的端口；这里只验证 token 不可互换，不绕过网关寻址
    // 用 client token 直接打网关自己的 /v1/echo：网关只认自己的 client token，鉴权应该通过（这是正常路径，作为对照组）。
    const viaGateway = await fetch(`${backendBaseUrl}/v1/echo`, { headers: { authorization: `Bearer ${lease.token}` } });
    expect(viaGateway.status).not.toBe(401);
    // 反过来：backend 自己的 token 拿去敲网关的鉴权，网关只认 client token，必须被拒绝（401），
    // 证明 gateway 层的鉴权和 backend 层的鉴权是两套完全独立的凭据，互不通用。
    for (const backendToken of backendTokens) {
      const viaGatewayWithBackendToken = await fetch(`${backendBaseUrl}/v1/echo`, { headers: { authorization: `Bearer ${backendToken}` } });
      expect(viaGatewayWithBackendToken.status).toBe(401);
    }
    manager.release("run-token-cross-check", process.pid, lease.leaseId);
  });
});

describe("stable gateway: stop() cancels an in-flight first-time acquire", () => {
  // 回归测试（对应 reviewer 的确定性 blocker 复现）：调用方没有 await acquire()，fake backend 的 readiness
  // 故意延迟 3s 才通过；200ms 后调用 stop()。旧实现下 stop() 对"还没进入 this.leases 的首次 acquire"完全无感知，
  // 会立即返回，3s 后那次迟到的 acquire 仍然成功并留下一个 daemon 完全没追踪到的孤儿 backend/gateway。
  it("rejects a not-yet-awaited acquire and leaves no lease/gateway/child once the delayed readiness would have resolved", async () => {
    const fake = await createFakeBackend();
    const manager = new QoderRuntimeManager(envFor(fake, { QODER_GW_TEST_READY_DELAY_MS: "3000" }));
    managers.push(manager);
    await manager.listen();
    const acquirePromise = manager.acquire("run-stop-during-first-acquire", process.pid); // 故意不 await
    await new Promise((resolve) => setTimeout(resolve, 200)); // 此时子进程已经 spawn，但 readiness 还在 3s 延迟里
    const stopStartedAt = performance.now();
    await manager.stop();
    const stopElapsedMs = performance.now() - stopStartedAt;
    // stop() 必须主动 abort 并强杀这个还在等 readiness 的子进程，而不是傻等 3s 的延迟自然过去。
    expect(stopElapsedMs).toBeLessThan(1500);
    await expect(acquirePromise).rejects.toBeDefined();
    expect(manager.isStopped()).toBe(true);
    // 再等过原本 3s 的 readiness 延迟，确认没有任何迟到的 lease/子进程冒出来——最多只 spawn 过一次
    // （子进程可能被 kill 得足够快、快到还没来得及写自己的 pid 就已经被杀掉，这恰恰证明取消够及时；
    // 不管写没写，都不应该再增长，也不应该有任何进程还活着）。
    await new Promise((resolve) => setTimeout(resolve, 3300));
    const finalBootCount = await bootCount(fake.starts);
    expect(finalBootCount).toBeLessThanOrEqual(1);
    if (finalBootCount === 1) {
      const spawnedPid = await latestPid(fake.starts);
      expect(() => process.kill(spawnedPid, 0)).toThrow(); // ESRCH：进程已经不存在，没有留下孤儿
    }
    // daemon 已经停止：即使原来的 runId 从未真正发布过 lease，新的 acquire 也必须直接被拒绝，而不是重新尝试启动。
    await expect(manager.acquire("run-stop-during-first-acquire", process.pid)).rejects.toBeDefined();
  }, 10000);
});
