import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdtemp, symlink, rm, chmod, stat, readFile, writeFile, readdir, link, rename, mkdir, open } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile, spawn, type ChildProcess } from "node:child_process";
import { promisify } from "node:util";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import {
  requireHttpsUrl,
  requireCnAllowedUrl,
  BridgeAssertionError,
  RequestResult,
  QoderContext,
  validatePreparedResult,
  missingRequiredAuthExportRoles,
  REQUIRED_AUTH_EXPORT_ROLES,
  sha256,
  type Bridge,
} from "../src/auth/bridge.ts";
import { AuthSession, CatalogUpstreamError, PendingPreflightPersistenceError, QuotaUpstreamError, createConfigStore, evaluateProcessOwnerActivity, fetchOfficialModelCatalog, fetchOfficialQoderQuota, normalizeQoderQuotaUsage, prepareSignedCatalogRequest, requireBunExecutable, requireMachineId, requireCosyVersion, type AuthInputs, type AuthSessionDependencies, type CredentialStore, type QoderQuotaUsage, type StoredCredential } from "../src/auth/session.ts";
import type { QoderAssistantModel } from "../src/models.ts";

async function testBunExecutable(): Promise<string> {
  return process.versions.bun ? process.execPath : requireBunExecutable({ PATH: process.env.PATH });
}
import { preflightBeforeBind } from "../src/cli.ts";

describe("capability Bun runtime resolver", () => {
  it("prefers an explicit Bun executable and rejects a Node executable", async () => {
    const bun = await testBunExecutable();
    expect(await requireBunExecutable({}, bun)).toBeTruthy();
    if (!process.versions.bun) await expect(requireBunExecutable({}, process.execPath)).rejects.toThrow(/Bun capability runtime 不可用/);
  });

  it("prefers BUN_EXEC_PATH over PATH discovery", async () => {
    const bun = await testBunExecutable();
    expect(await requireBunExecutable({ BUN_EXEC_PATH: bun, PATH: "" })).toBeTruthy();
  });

  it("rejects an unavailable explicit executable without falling back", async () => {
    const missing = join(tmpdir(), `qoder-proxy-missing-bun-${Date.now()}`);
    await expect(requireBunExecutable({}, missing)).rejects.toThrow(/runtime 不可用/);
  });
});

describe("required machine identity", () => {
  it("rejects a missing or empty machine ID before config/session use", () => {
    expect(() => requireMachineId({})).toThrow(/QODER_CN_MACHINE_ID/);
    expect(() => requireMachineId({ QODER_CN_MACHINE_ID: "" })).toThrow(/QODER_CN_MACHINE_ID/);
    expect(requireMachineId({ QODER_CN_MACHINE_ID: "machine-a" })).toBe("machine-a");
  });

  it("uses the observed cosy default but rejects an explicit empty override", () => {
    expect(requireCosyVersion({})).toBe("1.1.6");
    expect(() => requireCosyVersion({ QODER_CN_COSY_VERSION: "" })).toThrow(/COSY/);
  });
});

describe("requireHttpsUrl / requireCnAllowedUrl", () => {
  it("rejects non-https URLs", () => {
    expect(() => requireHttpsUrl("http://gateway.qoder.com.cn", "test")).toThrow(BridgeAssertionError);
  });

  it("rejects malformed URLs", () => {
    expect(() => requireHttpsUrl("not a url", "test")).toThrow(BridgeAssertionError);
  });

  it("accepts every CN allowlisted host", () => {
    for (const host of ["qoder.com.cn", "openapi.qoder.com.cn", "gateway.qoder.com.cn", "api2-v2.qoder.com.cn", "api2.qoder.com.cn"]) {
      expect(requireCnAllowedUrl(`https://${host}/x`, "test")).toBe(`https://${host}/x`);
    }
  });

  it("rejects hosts outside the CN allowlist (SSRF guard)", () => {
    expect(() => requireCnAllowedUrl("https://evil.example.com/steal", "test")).toThrow(BridgeAssertionError);
  });
});

// Minimal fake Bridge driving RequestResult's retptr-based getters without a real WASM module.
function fakeResultBridge(data: { url: string; headers: unknown; body?: string; headerCount: number; withFree?: boolean }): Bridge {
  let lastRole: string | undefined;
  return {
    roles: {
      requestresultUrl: "requestresult_url",
      requestresultHeaders: "requestresult_headers",
      requestresultBody: "requestresult_body",
      requestresultHeaderCount: "requestresult_header_count",
      requestresultFree: data.withFree ? "requestresult_free" : undefined,
    } as never,
    passString: () => ({ ptr: 0, len: 0 }),
    callRole: (role) => {
      lastRole = role;
      if (role === "requestresultHeaders") return 1;
      if (role === "requestresultHeaderCount") return data.headerCount;
      return undefined;
    },
    readI32: (addr) => {
      if (lastRole === "requestresultUrl") return addr === 0 ? 1 : data.url.length;
      if (lastRole === "requestresultBody") return data.body === undefined ? 0 : addr === 0 ? 1 : data.body.length;
      return 0;
    },
    freeWasm: () => {},
    withStack: (fn) => fn(0),
    getString: () => (lastRole === "requestresultUrl" ? data.url : (data.body ?? "")),
    takeObject: () => data.headers,
  };
}

describe("Auth WASM required export roles", () => {
  const exportNameByRole = new Map<string, string>([
    ["malloc", "__wbindgen_malloc"], ["free", "__wbindgen_free"], ["addToStackPointer", "__wbindgen_add_to_stack_pointer"],
    ["generateRuntimeAuthFields", "generate_runtime_auth_fields"], ["qodercontextNew", "qodercontext_new"],
    ["qodercontextPrepareRequest", "qodercontext_prepareRequest"], ["qodercontextPrepareInferRequest", "qodercontext_prepareInferRequest"],
    ["qodercontextRefreshAuthFields", "qodercontext_refreshAuthFields"], ["qodercontextFree", "__wbg_qodercontext_free"],
    ["requestresultUrl", "requestresult_url"], ["requestresultBody", "requestresult_body"],
    ["requestresultHeaders", "requestresult_headers"], ["requestresultHeaderCount", "requestresult_headerCount"],
    ["requestresultFree", "__wbg_requestresult_free"],
  ] as const);
  const complete = REQUIRED_AUTH_EXPORT_ROLES.map((role) => exportNameByRole.get(role)!);

  it("accepts a candidate containing every unconditional and disposal-critical role", () => {
    expect(missingRequiredAuthExportRoles(complete)).toEqual([]);
  });

  it.each(REQUIRED_AUTH_EXPORT_ROLES)("fails closed when required role %s is missing", (missingRole) => {
    const exports = complete.filter((name) => name !== exportNameByRole.get(missingRole));
    expect(missingRequiredAuthExportRoles(exports)).toContain(missingRole);
  });
});

describe("validatePreparedResult", () => {
  it("passes undefined optional generic-request inputs as null pointer pairs", () => {
    const calls: Array<{ role: string; args: number[] }> = [];
    let next = 16;
    const bridge: Bridge = {
      roles: { qodercontextPrepareRequest: "qodercontext_prepareRequest" } as never,
      passString: (value) => { const ptr = next; next += value.length + 1; return { ptr, len: value.length }; },
      callRole: (role, args) => { calls.push({ role, args }); },
      readI32: () => 0,
      freeWasm: () => {},
      withStack: (fn) => fn(4),
      takeObject: () => undefined,
      getString: () => "",
    };
    const Context = QoderContext as unknown as { new(bridge: Bridge, ptr: number): QoderContext };
    const context = new Context(bridge, 9);
    context.prepareRequest("https://gateway.qoder.com.cn", "/api/v2/model/list?Encode=1", "GET", "auth");
    expect(calls).toHaveLength(1);
    expect(calls[0]?.role).toBe("qodercontextPrepareRequest");
    expect(calls[0]?.args.slice(-4)).toEqual([0, 0, 0, 0]);
  });

  it("accepts a well-formed prepared request (allowlisted https url + Map headers matching headerCount)", () => {
    const headers = new Map([["content-type", "application/json"], ["x-signature", "abc"]]);
    const b = fakeResultBridge({ url: "https://gateway.qoder.com.cn/infer", headers, headerCount: headers.size, body: '{"a":1}' });
    const result = new RequestResult(b, 1);
    const prepared = validatePreparedResult(result, "test");
    expect(prepared.url).toBe("https://gateway.qoder.com.cn/infer");
    expect(prepared.headers).toEqual({ "content-type": "application/json", "x-signature": "abc" });
    expect(prepared.body).toBe('{"a":1}');
  });

  it("rejects a url outside the CN allowlist", () => {
    const headers = new Map([["a", "b"]]);
    const b = fakeResultBridge({ url: "https://evil.example.com/infer", headers, headerCount: 1 });
    expect(() => validatePreparedResult(new RequestResult(b, 1), "test")).toThrow(BridgeAssertionError);
  });

  it("rejects headers that are not a Map", () => {
    const b = fakeResultBridge({ url: "https://gateway.qoder.com.cn/infer", headers: { a: "b" }, headerCount: 1 });
    expect(() => validatePreparedResult(new RequestResult(b, 1), "test")).toThrow(/不是 Map/);
  });

  it("rejects when headerCount disagrees with the Map size", () => {
    const headers = new Map([["a", "b"]]);
    const b = fakeResultBridge({ url: "https://gateway.qoder.com.cn/infer", headers, headerCount: 2 });
    expect(() => validatePreparedResult(new RequestResult(b, 1), "test")).toThrow(/headerCount/);
  });

  it("rejects more than 64 headers", () => {
    const headers = new Map(Array.from({ length: 65 }, (_, i) => [`h${i}`, "v"]));
    const b = fakeResultBridge({ url: "https://gateway.qoder.com.cn/infer", headers, headerCount: headers.size });
    expect(() => validatePreparedResult(new RequestResult(b, 1), "test")).toThrow(/数量超限/);
  });
});

describe("RequestResult dispose / use-after-free", () => {
  it("dispose() is idempotent and blocks subsequent access", () => {
    const headers = new Map([["a", "b"]]);
    const b = fakeResultBridge({ url: "https://gateway.qoder.com.cn/infer", headers, headerCount: 1 });
    const result = new RequestResult(b, 1);
    expect(() => result.url).not.toThrow();
    result.dispose();
    result.dispose(); // idempotent, must not throw
    expect(() => result.url).toThrow(BridgeAssertionError);
    expect(() => result.headers).toThrow(BridgeAssertionError);
  });
});

function testCredential(token: string, refreshToken: string): StoredCredential {
  return { version: 1, site: "cn", machineIdHash: sha256("machine-a"), token, refreshToken };
}

function testBridge(): Bridge {
  return { roles: {} } as Bridge;
}

function createTestSession(env: Record<string, string | undefined>, store: CredentialStore, stored: StoredCredential, auth: AuthInputs, dependencies: AuthSessionDependencies = {}): AuthSession {
  const Session = AuthSession as unknown as { new(env: Record<string, string | undefined>, machineId: string, store: CredentialStore, bridge: Bridge, stored: StoredCredential, auth: AuthInputs, dependencies?: AuthSessionDependencies): AuthSession };
  return new Session(env, "machine-a", store, testBridge(), stored, auth, dependencies);
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

const execFileAsyncForTest = promisify(execFile);

async function waitUntil(predicate: () => boolean | Promise<boolean>): Promise<void> {
  for (let i = 0; i < 1_000; i++) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("condition not reached");
}

async function waitForCapabilityQuiescence(configDir: string): Promise<void> {
  await waitUntil(async () => {
    try {
      const names = await readdir(configDir);
      return names.every((name) => !name.startsWith(".rotation-fd-probe.") && !name.includes("mutation.lock") && name !== "auth-cn.rotation.pending");
    } catch (error) {
      return (error as NodeJS.ErrnoException).code === "ENOENT";
    }
  });
}

describe("AuthSession refresh state machine", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("keeps persisted and in-memory rotated credentials aligned when userinfo fails", async () => {
    const saved: StoredCredential[] = [];
    const store: CredentialStore = { load: async () => undefined, isCommitted: async () => false, reserveRotation: async () => "owner", clearRotationReservation: async () => {}, stageRotation: async () => {}, save: async (value) => { saved.push(value); }, delete: async () => {} };
    const session = createTestSession({}, store, testCredential("old-access", "old-refresh"), { uid: "old-user", organization_id: "", organization_tags: undefined, data_policy_agreed: true });
    const refreshBodies: string[] = [];
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") {
        refreshBodies.push(String(init.body));
        const index = refreshBodies.length;
        return jsonResponse({ device_token: `access-${index}`, refresh_token: `refresh-${index}` });
      }
      if (refreshBodies.length === 1) return jsonResponse({ message: "userinfo failed" }, 500);
      return jsonResponse({ id: "new-user" });
    }) as unknown as typeof fetch;

    await expect(session.refreshAndReauthenticate()).rejects.toThrow(/userinfo HTTP 500/);
    await session.refreshAndReauthenticate();

    expect(refreshBodies).toEqual([
      JSON.stringify({ refresh_token: "old-refresh" }),
      JSON.stringify({ refresh_token: "refresh-1" }),
    ]);
    expect(saved.map((value) => value.refreshToken)).toEqual(["refresh-1", "refresh-2"]);
    expect((session as unknown as { stored: StoredCredential }).stored.refreshToken).toBe("refresh-2");
    expect((session as unknown as { auth: AuthInputs }).auth.uid).toBe("new-user");
  });

  it("isolates a throwing active refresh observer while completing the product refresh", async () => {
    const store: CredentialStore = { load: async () => undefined, isCommitted: async () => false, reserveRotation: async () => "owner", clearRotationReservation: async () => {}, stageRotation: async () => {}, save: async () => {}, delete: async () => {} };
    const session = createTestSession({}, store, testCredential("old-access", "old-refresh"), { uid: "old-user", organization_id: "", organization_tags: undefined, data_policy_agreed: true });
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => init?.method === "POST"
      ? jsonResponse({ device_token: "new-access", refresh_token: "new-refresh" })
      : jsonResponse({ id: "new-user" })) as unknown as typeof fetch;
    const observer = { recordCatalogRemoteLoad() {}, recordRefresh() { throw new Error("instrumentation failure"); }, recordRetry() {} };
    await expect(session.refreshAndReauthenticate(undefined, observer)).resolves.toBeUndefined();
    expect((session as unknown as { stored: StoredCredential }).stored.refreshToken).toBe("new-refresh");
  });

  it("lets one aborted waiter leave without aborting the session-owned shared refresh", async () => {
    const store: CredentialStore = { load: async () => undefined, isCommitted: async () => false, reserveRotation: async () => "owner", clearRotationReservation: async () => {}, stageRotation: async () => {}, save: async () => {}, delete: async () => {} };
    const session = createTestSession({ QODER_PROXY_REFRESH_TIMEOUT_MS: "1000" }, store, testCredential("old-access", "old-refresh"), { uid: "old-user", organization_id: "", organization_tags: undefined, data_policy_agreed: true });
    let releaseRefresh!: () => void;
    const refreshGate = new Promise<void>((resolve) => { releaseRefresh = resolve; });
    let refreshSignal: AbortSignal | undefined;
    let refreshCalls = 0;
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") {
        refreshCalls++;
        refreshSignal = init.signal ?? undefined;
        await refreshGate;
        return jsonResponse({ device_token: "new-access", refresh_token: "new-refresh" });
      }
      return jsonResponse({ id: "new-user" });
    }) as unknown as typeof fetch;

    const firstController = new AbortController();
    const first = session.refreshAndReauthenticate(firstController.signal);
    const second = session.refreshAndReauthenticate();
    await waitUntil(() => refreshCalls === 1);
    firstController.abort(new Error("first waiter cancelled"));
    await expect(first).rejects.toThrow(/first waiter cancelled/);
    expect(refreshSignal?.aborted).toBe(false);
    releaseRefresh();
    await second;
    expect(refreshCalls).toBe(1);
    expect((session as unknown as { stored: StoredCredential }).stored.refreshToken).toBe("new-refresh");
  });

  it("lets the initiating runtime caller abort a hanging capability probe before any refresh request", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qoder-proxy-runtime-capability-abort-"));
    try {
      const configDir = join(dir, "cfg");
      const readyPath = join(dir, "capability-ready");
      const env = { QODER_PROXY_CONFIG_DIR: configDir, QODER_PROXY_REFRESH_TIMEOUT_MS: "1000", QODER_PROXY_CAPABILITY_TIMEOUT_MS: "1000" };
      const baseStore = createConfigStore("machine-a", env);
      const stored = testCredential("old-access", "old-refresh");
      await baseStore.save(stored);
      const store = createConfigStore("machine-a", env, { capabilityProbeMode: "async-pending", capabilityProbeReadyPath: readyPath });
      const session = createTestSession(env, store, stored, { uid: "old-user", organization_id: "", organization_tags: undefined, data_policy_agreed: true });
      const refreshBodies: string[] = [];
      globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
        if (init?.method === "POST") refreshBodies.push(String(init.body));
        return jsonResponse({ id: "unused" });
      }) as unknown as typeof fetch;
      const controller = new AbortController();
      const refresh = session.refreshAndReauthenticate(controller.signal);
      await waitUntil(async () => { try { return (await readFile(readyPath, "utf8")).startsWith("capability-started\n"); } catch { return false; } });
      controller.abort(new Error("runtime caller cancelled capability"));

      await expect(refresh).rejects.toThrow(/runtime caller cancelled capability/);
      await waitForCapabilityQuiescence(configDir);
      expect(refreshBodies).toEqual([]);
      expect((await readdir(configDir)).filter((name) => name.startsWith(".rotation-fd-probe.") || name.includes("mutation.lock"))).toEqual([]);
      expect((await baseStore.load())?.refreshToken).toBe("old-refresh");
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it("keeps a hanging capability probe alive for another waiter when the initiating caller aborts", async () => {
    let capabilityCalls = 0;
    let releaseCapability!: () => void;
    const capabilityGate = new Promise<void>((resolve) => { releaseCapability = resolve; });
    const store: CredentialStore = {
      load: async () => undefined,
      isCommitted: async () => false,
      reserveRotation: async (_base, signal) => {
        capabilityCalls++;
        await Promise.race([
          capabilityGate,
          new Promise<never>((_, reject) => signal?.addEventListener("abort", () => reject(signal.reason), { once: true })),
        ]);
        return "owner";
      },
      clearRotationReservation: async () => {},
      stageRotation: async () => {},
      save: async () => {},
      delete: async () => {},
    };
    const session = createTestSession({ QODER_PROXY_REFRESH_TIMEOUT_MS: "1000" }, store, testCredential("old-access", "old-refresh"), { uid: "old-user", organization_id: "", organization_tags: undefined, data_policy_agreed: true });
    let refreshCalls = 0;
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") { refreshCalls++; return jsonResponse({ device_token: "new-access", refresh_token: "new-refresh" }); }
      return jsonResponse({ id: "new-user" });
    }) as unknown as typeof fetch;
    const firstController = new AbortController();
    const first = session.refreshAndReauthenticate(firstController.signal);
    await waitUntil(() => capabilityCalls === 1);
    const second = session.refreshAndReauthenticate();
    firstController.abort(new Error("initiating waiter cancelled"));
    await expect(first).rejects.toThrow(/initiating waiter cancelled/);
    releaseCapability();
    await second;
    expect(capabilityCalls).toBe(1);
    expect(refreshCalls).toBe(1);
  });

  it("bounds the session-owned shared refresh with its own timeout", async () => {
    const store: CredentialStore = { load: async () => undefined, isCommitted: async () => false, reserveRotation: async () => "owner", clearRotationReservation: async () => {}, stageRotation: async () => {}, save: async () => {}, delete: async () => {} };
    const session = createTestSession({ QODER_PROXY_REFRESH_TIMEOUT_MS: "10" }, store, testCredential("old-access", "old-refresh"), { uid: "old-user", organization_id: "", organization_tags: undefined, data_policy_agreed: true });
    globalThis.fetch = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
    })) as unknown as typeof fetch;

    await expect(session.refreshAndReauthenticate()).rejects.toThrow(/结果不明确/);
    await expect(session.refreshAndReauthenticate()).rejects.toThrow(/结果不明确/);
  });

  it("keeps single-flight ownership while a non-cancellable save remains permanently pending", async () => {
    let saveCalls = 0;
    const store: CredentialStore = { load: async () => undefined, isCommitted: async () => false, reserveRotation: async () => "owner", clearRotationReservation: async () => {}, stageRotation: async () => {}, save: async () => { saveCalls++; await new Promise(() => {}); }, delete: async () => {} };
    const session = createTestSession({ QODER_PROXY_REFRESH_TIMEOUT_MS: "10" }, store, testCredential("old-access", "old-refresh"), { uid: "old-user", organization_id: "", organization_tags: undefined, data_policy_agreed: true });
    let refreshCalls = 0;
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") { refreshCalls++; return jsonResponse({ device_token: "new-access", refresh_token: "new-refresh" }); }
      return jsonResponse({ id: "new-user" });
    }) as unknown as typeof fetch;

    const firstController = new AbortController();
    const first = session.refreshAndReauthenticate(firstController.signal);
    await waitUntil(() => saveCalls === 1);
    firstController.abort(new Error("caller timeout while committing"));
    await expect(first).rejects.toThrow(/caller timeout while committing/);
    const secondController = new AbortController();
    const second = session.refreshAndReauthenticate(secondController.signal);
    secondController.abort(new Error("second caller timeout"));
    await expect(second).rejects.toThrow(/second caller timeout/);
    expect(refreshCalls).toBe(1);
    expect((session as unknown as { refreshPromise?: Promise<void> }).refreshPromise).toBeDefined();
  });

  it.each(["isCommitted", "stageRotation", "save"] as const)("bounds a hanging %s persistence step while retaining the rotated owner and blocking old-token replay", async (hangingStep) => {
    let stageCalls = 0;
    let saveCalls = 0;
    let committedChecks = 0;
    const never = new Promise<void>(() => {});
    const store: CredentialStore = {
      load: async () => undefined,
      isCommitted: async () => { committedChecks++; if (hangingStep === "isCommitted") await never; return false; },
      reserveRotation: async () => "owner",
      clearRotationReservation: async () => {},
      stageRotation: async () => { stageCalls++; if (hangingStep === "stageRotation") await never; },
      save: async () => { saveCalls++; if (hangingStep === "save") await never; },
      delete: async () => {},
    };
    const session = createTestSession({ QODER_PROXY_REFRESH_TIMEOUT_MS: "15" }, store, testCredential("old-access", "old-refresh"), { uid: "old-user", organization_id: "", organization_tags: undefined, data_policy_agreed: true });
    const pending = { owner: "owner", credential: testCredential("new-access", "new-refresh"), stageRequired: hangingStep === "stageRotation" };
    (session as unknown as { stored: StoredCredential; pendingPersistence: typeof pending; persistenceError: Error }).stored = pending.credential;
    (session as unknown as { pendingPersistence: typeof pending }).pendingPersistence = pending;
    (session as unknown as { persistenceError: Error }).persistenceError = new Error("pending persistence");
    const refreshBodies: string[] = [];
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") { refreshBodies.push(String(init.body)); return jsonResponse({ device_token: "unexpected", refresh_token: "unexpected" }); }
      return jsonResponse({ id: "new-user" });
    }) as unknown as typeof fetch;

    const controller = new AbortController();
    const retry = session.refreshAndReauthenticate(controller.signal);
    await waitUntil(() => hangingStep === "isCommitted" ? committedChecks >= 1 : hangingStep === "stageRotation" ? stageCalls >= 1 : saveCalls >= 1);
    controller.abort(new Error(`caller cancelled during ${hangingStep}`));
    await expect(retry).rejects.toThrow(/caller cancelled/);
    expect(refreshBodies).toEqual([]);
    expect((session as unknown as { stored: StoredCredential }).stored.refreshToken).toBe("new-refresh");
    expect(() => session.createSignedAttempt("{}", "auto", 0)).toThrow(/pending persistence/);
  });

  it("keeps delayed save owned, then aligns memory and avoids old-token replay after commit", async () => {
    let releaseSave!: () => void;
    const saveGate = new Promise<void>((resolve) => { releaseSave = resolve; });
    const saved: StoredCredential[] = [];
    const store: CredentialStore = { load: async () => undefined, isCommitted: async () => false, reserveRotation: async () => "owner", clearRotationReservation: async () => {}, stageRotation: async () => {}, save: async (value) => { await saveGate; saved.push(value); }, delete: async () => {} };
    const session = createTestSession({ QODER_PROXY_REFRESH_TIMEOUT_MS: "1000" }, store, testCredential("old-access", "old-refresh"), { uid: "old-user", organization_id: "", organization_tags: undefined, data_policy_agreed: true });
    const refreshBodies: string[] = [];
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") { refreshBodies.push(String(init.body)); return jsonResponse({ device_token: "new-access", refresh_token: "new-refresh" }); }
      return jsonResponse({ id: "new-user" });
    }) as unknown as typeof fetch;

    const firstController = new AbortController();
    const first = session.refreshAndReauthenticate(firstController.signal);
    await waitUntil(() => refreshBodies.length === 1);
    firstController.abort(new Error("first caller stopped waiting"));
    await expect(first).rejects.toThrow(/first caller stopped waiting/);
    const second = session.refreshAndReauthenticate();
    expect(refreshBodies).toEqual([JSON.stringify({ refresh_token: "old-refresh" })]);
    releaseSave();
    await second;
    expect(saved.map((credential) => credential.refreshToken)).toEqual(["new-refresh"]);
    expect((session as unknown as { stored: StoredCredential }).stored.refreshToken).toBe("new-refresh");
    expect(refreshBodies).toEqual([JSON.stringify({ refresh_token: "old-refresh" })]);
  });

  it("keeps rotated memory authority and retries only persistence after save fails", async () => {
    let saveCalls = 0;
    const store: CredentialStore = {
      load: async () => undefined,
      isCommitted: async () => false,
      reserveRotation: async () => "owner",
      clearRotationReservation: async () => {},
      stageRotation: async () => {},
      save: async () => { saveCalls++; if (saveCalls === 1) throw new Error("disk unavailable"); },
      delete: async () => {},
    };
    const session = createTestSession({ QODER_PROXY_REFRESH_TIMEOUT_MS: "1000" }, store, testCredential("old-access", "old-refresh"), { uid: "old-user", organization_id: "", organization_tags: undefined, data_policy_agreed: true });
    const refreshBodies: string[] = [];
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") {
        refreshBodies.push(String(init.body));
        const index = refreshBodies.length;
        return jsonResponse({ device_token: `access-${index}`, refresh_token: `refresh-${index}` });
      }
      return jsonResponse({ id: "new-user" });
    }) as unknown as typeof fetch;

    await expect(session.refreshAndReauthenticate()).rejects.toThrow(/disk unavailable/);
    expect((session as unknown as { stored: StoredCredential }).stored.refreshToken).toBe("refresh-1");
    expect((session as unknown as { refreshPromise?: Promise<void> }).refreshPromise).toBeUndefined();
    expect(() => session.createSignedAttempt("{}", "auto", 0)).toThrow(/disk unavailable/);
    await session.refreshAndReauthenticate();
    expect(refreshBodies).toEqual([JSON.stringify({ refresh_token: "old-refresh" })]);
    expect((session as unknown as { stored: StoredCredential }).stored.refreshToken).toBe("refresh-1");
    expect(saveCalls).toBe(2);
  });

  it("reconciles a trailing save error when the credential is already durably committed", async () => {
    let committed = false;
    let saveCalls = 0;
    const store: CredentialStore = {
      load: async () => undefined,
      isCommitted: async () => committed,
      reserveRotation: async () => "owner",
      clearRotationReservation: async () => {},
      stageRotation: async () => {},
      save: async () => { saveCalls++; committed = true; if (saveCalls === 1) throw new Error("directory fsync failed after commit"); },
      delete: async () => {},
    };
    const session = createTestSession({ QODER_PROXY_REFRESH_TIMEOUT_MS: "1000" }, store, testCredential("old-access", "old-refresh"), { uid: "old-user", organization_id: "", organization_tags: undefined, data_policy_agreed: true });
    const refreshBodies: string[] = [];
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") { refreshBodies.push(String(init.body)); return jsonResponse({ device_token: "new-access", refresh_token: "new-refresh" }); }
      return jsonResponse({ id: "new-user" });
    }) as unknown as typeof fetch;

    await expect(session.refreshAndReauthenticate()).rejects.toThrow(/fsync failed/);
    expect(() => session.createSignedAttempt("{}", "auto", 0)).toThrow(/fsync failed/);
    await session.refreshAndReauthenticate();
    expect(saveCalls).toBe(1);
    expect(refreshBodies).toEqual([JSON.stringify({ refresh_token: "old-refresh" })]);
  });

  it("retains the owner and retries only stage/save after rotation staging fails", async () => {
    let reserved = false;
    let stageCalls = 0;
    let saveCalls = 0;
    const store: CredentialStore = {
      load: async () => undefined,
      isCommitted: async () => false,
      reserveRotation: async () => { reserved = true; return "owner"; },
      clearRotationReservation: async () => { reserved = false; },
      stageRotation: async () => { stageCalls++; if (stageCalls === 1) throw new Error("stage unavailable"); },
      save: async () => { saveCalls++; reserved = false; },
      delete: async () => {},
    };
    const session = createTestSession({ QODER_PROXY_REFRESH_TIMEOUT_MS: "1000" }, store, testCredential("old-access", "old-refresh"), { uid: "old-user", organization_id: "", organization_tags: undefined, data_policy_agreed: true });
    const refreshBodies: string[] = [];
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") {
        refreshBodies.push(String(init.body));
        return jsonResponse({ device_token: "new-access", refresh_token: "new-refresh" });
      }
      return jsonResponse({ id: "new-user" });
    }) as unknown as typeof fetch;

    await expect(session.refreshAndReauthenticate()).rejects.toThrow(/暂存失败/);
    expect(reserved).toBe(true);
    expect(stageCalls).toBe(1);
    expect((session as unknown as { stored: StoredCredential }).stored.refreshToken).toBe("new-refresh");
    expect(() => session.createSignedAttempt("{}", "auto", 0)).toThrow(/暂存失败/);
    await session.refreshAndReauthenticate();
    expect(refreshBodies).toEqual([JSON.stringify({ refresh_token: "old-refresh" })]);
    expect(stageCalls).toBe(2);
    expect(saveCalls).toBe(1);
    expect(reserved).toBe(false);
  });

  it("enters degraded state when pre-rotation cleanup fails and blocks inference", async () => {
    let clearCalls = 0;
    const store: CredentialStore = {
      load: async () => undefined,
      isCommitted: async () => false,
      reserveRotation: async () => "owner",
      clearRotationReservation: async () => { clearCalls++; throw new Error("cleanup denied"); },
      stageRotation: async () => {},
      save: async () => {},
      delete: async () => {},
    };
    const session = createTestSession({ QODER_PROXY_REFRESH_TIMEOUT_MS: "1000" }, store, testCredential("old-access", "old-refresh"), { uid: "old-user", organization_id: "", organization_tags: undefined, data_policy_agreed: true });
    let refreshCalls = 0;
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") { refreshCalls++; return jsonResponse({}, 500); }
      return jsonResponse({ id: "old-user" });
    }) as unknown as typeof fetch;

    await expect(session.refreshAndReauthenticate()).rejects.toThrow(/预留清理失败.*降级/);
    expect(clearCalls).toBe(1);
    expect(() => session.createSignedAttempt("{}", "auto", 0)).toThrow(/预留清理失败.*降级/);
    await expect(session.refreshAndReauthenticate()).rejects.toThrow(/预留清理失败.*降级/);
    expect(refreshCalls).toBe(1);
  });

  it("retries a failed journal commit without starting another server rotation", async () => {
    let saveCalls = 0;
    let reserveCalls = 0;
    const store: CredentialStore = {
      load: async () => undefined,
      isCommitted: async () => false,
      reserveRotation: async () => { reserveCalls++; return `owner-${reserveCalls}`; },
      clearRotationReservation: async () => {},
      stageRotation: async () => {},
      save: async () => { saveCalls++; if (saveCalls === 1) throw new Error("first commit failed"); },
      delete: async () => {},
    };
    const session = createTestSession({ QODER_PROXY_REFRESH_TIMEOUT_MS: "1000" }, store, testCredential("old-access", "old-refresh"), { uid: "old-user", organization_id: "", organization_tags: undefined, data_policy_agreed: true });
    const refreshBodies: string[] = [];
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") {
        refreshBodies.push(String(init.body));
        const index = refreshBodies.length;
        return jsonResponse({ device_token: `access-${index}`, refresh_token: `refresh-${index}` });
      }
      return jsonResponse({ id: "new-user" });
    }) as unknown as typeof fetch;

    await expect(session.refreshAndReauthenticate()).rejects.toThrow(/first commit failed/);
    await session.refreshAndReauthenticate();
    expect(saveCalls).toBe(2);
    expect(reserveCalls).toBe(1);
    expect(refreshBodies).toEqual([JSON.stringify({ refresh_token: "old-refresh" })]);
  });

  it("fails closed on an ambiguous refresh response and never retries the old token", async () => {
    const store: CredentialStore = {
      load: async () => undefined,
      isCommitted: async () => false,
      reserveRotation: async () => "owner",
      clearRotationReservation: async () => { throw new Error("must retain reservation"); },
      stageRotation: async () => {},
      save: async () => {},
      delete: async () => {},
    };
    const session = createTestSession({ QODER_PROXY_REFRESH_TIMEOUT_MS: "1000" }, store, testCredential("old-access", "old-refresh"), { uid: "old-user", organization_id: "", organization_tags: undefined, data_policy_agreed: true });
    const refreshBodies: string[] = [];
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") { refreshBodies.push(String(init.body)); throw new Error("connection reset after send"); }
      return jsonResponse({ id: "old-user" });
    }) as unknown as typeof fetch;

    await expect(session.refreshAndReauthenticate()).rejects.toThrow(/结果不明确/);
    expect(() => session.createSignedAttempt("{}", "auto", 0)).toThrow(/结果不明确/);
    await expect(session.refreshAndReauthenticate()).rejects.toThrow(/结果不明确/);
    expect(refreshBodies).toEqual([JSON.stringify({ refresh_token: "old-refresh" })]);
  });

  it.each([
    ["missing refresh_token", { device_token: "new-access" }],
    ["empty refresh_token", { device_token: "new-access", refresh_token: "" }],
    ["numeric refresh_token", { device_token: "new-access", refresh_token: 42 }],
    ["negative expires_at", { device_token: "new-access", refresh_token: "new-refresh", expires_at: -1 }],
    ["invalid expires_at string", { device_token: "new-access", refresh_token: "new-refresh", expires_at: "not-a-time" }],
    ["negative expires_in", { device_token: "new-access", refresh_token: "new-refresh", expires_in: -1 }],
    ["string expires_in", { device_token: "new-access", refresh_token: "new-refresh", expires_in: "3600" }],
    ["negative refresh_token_expires_at", { device_token: "new-access", refresh_token: "new-refresh", refresh_token_expires_at: -1 }],
    ["invalid refresh_token_expires_at string", { device_token: "new-access", refresh_token: "new-refresh", refresh_token_expires_at: "never" }],
    ["negative refresh_token_expires_in", { device_token: "new-access", refresh_token: "new-refresh", refresh_token_expires_in: -1 }],
  ])("treats runtime 2xx %s as ambiguous and never replays the old refresh token", async (_label, responseBody) => {
    const store: CredentialStore = {
      load: async () => undefined,
      isCommitted: async () => false,
      reserveRotation: async () => "owner",
      clearRotationReservation: async () => { throw new Error("ambiguous outcome must retain reservation"); },
      stageRotation: async () => {},
      save: async () => {},
      delete: async () => {},
    };
    const session = createTestSession({ QODER_PROXY_REFRESH_TIMEOUT_MS: "1000" }, store, testCredential("old-access", "old-refresh"), { uid: "old-user", organization_id: "", organization_tags: undefined, data_policy_agreed: true });
    const refreshBodies: string[] = [];
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") { refreshBodies.push(String(init.body)); return jsonResponse(responseBody); }
      return jsonResponse({ id: "old-user" });
    }) as unknown as typeof fetch;

    await expect(session.refreshAndReauthenticate()).rejects.toThrow(/结果不明确/);
    await expect(session.refreshAndReauthenticate()).rejects.toThrow(/结果不明确/);
    expect(refreshBodies).toEqual([JSON.stringify({ refresh_token: "old-refresh" })]);
    expect(() => session.createSignedAttempt("{}", "auto", 0)).toThrow(/结果不明确/);
  });

  it("observes a shared refresh rejection even when the starting caller is already aborted", async () => {
    const store: CredentialStore = { load: async () => undefined, isCommitted: async () => false, reserveRotation: async () => "owner", clearRotationReservation: async () => {}, stageRotation: async () => {}, save: async () => {}, delete: async () => {} };
    const session = createTestSession({ QODER_PROXY_REFRESH_TIMEOUT_MS: "1000" }, store, testCredential("old-access", "old-refresh"), { uid: "old-user", organization_id: "", organization_tags: undefined, data_policy_agreed: true });
    let rejectRefresh!: (error: Error) => void;
    globalThis.fetch = vi.fn(() => new Promise<Response>((_resolve, reject) => { rejectRefresh = reject; })) as unknown as typeof fetch;
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => { unhandled.push(reason); };
    process.on("unhandledRejection", onUnhandled);
    try {
      const controller = new AbortController();
      controller.abort(new Error("caller already aborted"));
      const caller = session.refreshAndReauthenticate(controller.signal);
      await expect(caller).rejects.toThrow(/caller already aborted/);
      rejectRefresh(new Error("late shared refresh failure"));
      await new Promise((resolve) => setTimeout(resolve, 10));
      expect(unhandled).toEqual([]);
      await waitUntil(() => (session as unknown as { refreshPromise?: Promise<void> }).refreshPromise === undefined);
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
  });
});

describe("AuthSession model catalog", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  const MODELS: QoderAssistantModel[] = [
    { key: "auto", displayName: "Auto", isDefault: true, isVision: false, isReasoning: false, maxInputTokens: 200000, maxOutputTokens: null, createdAt: "1970-01-01T00:00:00.000Z", format: "openai", source: "system" },
  ];
  const auth: AuthInputs = { uid: "old-user", organization_id: "", organization_tags: undefined, data_policy_agreed: true };
  const store: CredentialStore = { load: async () => undefined, isCommitted: async () => true, reserveRotation: async () => "owner", clearRotationReservation: async () => {}, stageRotation: async () => {}, save: async () => {}, delete: async () => {} };

  it("single-flights concurrent loads and caches until TTL expires", async () => {
    let now = 1_000;
    let calls = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const session = createTestSession({ QODER_PROXY_MODEL_CATALOG_TTL_MS: "1000" }, store, testCredential("access", "refresh"), auth, {
      now: () => now,
      catalogLoader: async () => { calls++; await gate; return MODELS; },
    });
    const first = session.listModels();
    const second = session.listModels();
    release();
    expect((await first).models).toEqual(MODELS);
    expect((await second).models).toEqual(MODELS);
    expect(calls).toBe(1);
    expect((await session.listModels()).models).toEqual(MODELS);
    expect(calls).toBe(1);
    now = 2_001;
    expect((await session.listModels()).models).toEqual(MODELS);
    expect(calls).toBe(2);
  });

  it("retries a catalog 401 exactly once through the existing refresh path", async () => {
    let catalogCalls = 0;
    const session = createTestSession({}, store, testCredential("access", "refresh"), auth, {
      catalogLoader: async () => {
        catalogCalls++;
        if (catalogCalls === 1) throw new CatalogUpstreamError("unauthorized", 401);
        return MODELS;
      },
    });
    const refresh = vi.spyOn(session, "refreshAndReauthenticate").mockResolvedValue(undefined);
    expect((await session.listModels()).models).toEqual(MODELS);
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(catalogCalls).toBe(2);
  });

  it("isolates observer callback errors from a catalog single-flight", async () => {
    const session = createTestSession({}, store, testCredential("access", "refresh"), auth, {
      catalogLoader: async () => MODELS,
    });
    const throwingObserver = { recordCatalogRemoteLoad() { throw new Error("instrumentation failure"); }, recordRefresh() { throw new Error("instrumentation failure"); }, recordRetry() { throw new Error("instrumentation failure"); } };
    expect((await session.listModels(undefined, throwingObserver)).models).toEqual(MODELS);
  });

  it("attributes a catalog single-flight and its 401 refresh only to its initiating observer", async () => {
    let catalogCalls = 0;
    const session = createTestSession({}, store, testCredential("access", "refresh"), auth, {
      catalogLoader: async () => {
        catalogCalls++;
        if (catalogCalls === 1) throw new CatalogUpstreamError("unauthorized", 401);
        return MODELS;
      },
    });
    const owner = { catalog: 0, refresh: 0, retries: 0, recordCatalogRemoteLoad() { this.catalog++; }, recordRefresh() { this.refresh++; }, recordRetry() { this.retries++; } };
    const waiter = { catalog: 0, refresh: 0, retries: 0, recordCatalogRemoteLoad() { this.catalog++; }, recordRefresh() { this.refresh++; }, recordRetry() { this.retries++; } };
    vi.spyOn(session, "refreshAndReauthenticate").mockImplementation(async (_signal, observer) => { observer?.recordRefresh(); });
    await Promise.all([session.listModels(undefined, owner), session.listModels(undefined, waiter)]);
    expect(catalogCalls).toBe(2);
    expect(owner).toMatchObject({ catalog: 2, refresh: 1, retries: 1 });
    expect(waiter).toMatchObject({ catalog: 0, refresh: 0, retries: 0 });
  });

  it("rejects signing with a stale snapshot generation", async () => {
    const session = createTestSession({}, store, testCredential("access", "refresh"), auth, {
      catalogLoader: async () => MODELS,
    });
    const snapshot = await session.listModels();
    (session as unknown as { invalidateModelCatalog(): void }).invalidateModelCatalog();
    expect(() => session.createSignedAttempt("{}", "auto", snapshot.generation)).toThrow(/generation/);
  });

  it("does not retry non-401 catalog failures", async () => {
    let calls = 0;
    const session = createTestSession({}, store, testCredential("access", "refresh"), auth, {
      catalogLoader: async () => { calls++; throw new CatalogUpstreamError("rate", 429); },
    });
    const refresh = vi.spyOn(session, "refreshAndReauthenticate").mockResolvedValue(undefined);
    await expect(session.listModels()).rejects.toMatchObject({ status: 429 });
    expect(refresh).not.toHaveBeenCalled();
    expect(calls).toBe(1);
  });

  it("caller cancellation stops waiting without creating an unhandled shared rejection", async () => {
    let rejectLoad!: (error: Error) => void;
    const session = createTestSession({}, store, testCredential("access", "refresh"), auth, {
      catalogLoader: async () => new Promise<QoderAssistantModel[]>((_resolve, reject) => { rejectLoad = reject; }),
    });
    const controller = new AbortController();
    const waiting = session.listModels(controller.signal);
    controller.abort(new Error("catalog caller aborted"));
    await expect(waiting).rejects.toThrow(/catalog caller aborted/);
    rejectLoad(new Error("late catalog failure"));
    await new Promise((resolve) => setTimeout(resolve, 10));
  });

  it("discards an in-flight old-generation catalog when credentials refresh", async () => {
    let catalogCalls = 0;
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((resolve) => { releaseFirst = resolve; });
    const refreshStore: CredentialStore = {
      load: async () => undefined,
      isCommitted: async () => false,
      reserveRotation: async () => "owner",
      clearRotationReservation: async () => {},
      stageRotation: async () => {},
      save: async () => {},
      delete: async () => {},
    };
    const session = createTestSession({}, refreshStore, testCredential("old-access", "old-refresh"), auth, {
      catalogLoader: async () => {
        catalogCalls++;
        if (catalogCalls === 1) await firstGate;
        return MODELS;
      },
    });
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") return jsonResponse({ device_token: "new-access", refresh_token: "new-refresh" });
      return jsonResponse({ id: "new-user" });
    }) as unknown as typeof fetch;

    const listing = session.listModels();
    await waitUntil(() => catalogCalls === 1);
    await session.refreshAndReauthenticate();
    releaseFirst();
    expect((await listing).models).toEqual(MODELS);
    expect(catalogCalls).toBe(2);
  });

  it("invalidates a populated catalog cache after credential refresh", async () => {
    let catalogCalls = 0;
    const refreshStore: CredentialStore = {
      load: async () => undefined,
      isCommitted: async () => false,
      reserveRotation: async () => "owner",
      clearRotationReservation: async () => {},
      stageRotation: async () => {},
      save: async () => {},
      delete: async () => {},
    };
    const session = createTestSession({}, refreshStore, testCredential("old-access", "old-refresh"), auth, {
      catalogLoader: async () => { catalogCalls++; return MODELS; },
    });
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") return jsonResponse({ device_token: "new-access", refresh_token: "new-refresh" });
      return jsonResponse({ id: "new-user" });
    }) as unknown as typeof fetch;

    await session.listModels();
    await session.listModels();
    expect(catalogCalls).toBe(1);
    await session.refreshAndReauthenticate();
    await session.listModels();
    expect(catalogCalls).toBe(2);
  });
});

describe("Qoder quota usage", () => {
  const originalFetch = globalThis.fetch;
  const auth: AuthInputs = { uid: "old-user", organization_id: "", organization_tags: undefined, data_policy_agreed: true };
  const store: CredentialStore = { load: async () => undefined, isCommitted: async () => true, reserveRotation: async () => "owner", clearRotationReservation: async () => {}, stageRotation: async () => {}, save: async () => {}, delete: async () => {} };
  const response = {
    user_id: "private-user-id",
    user_type: "pro",
    total_usage_percentage: 0.12675,
    expires_at: 1_800_000_000,
    user_quota: { total: 100, used: 12.5, remaining: 87.5, percentage: 0.125, unit: "credits" },
    add_on_quota: { total: 40, used: 5, remaining: 35, percentage: 12.5, unit: "credits", detail_url: "https://qoder.com.cn/private" },
    shared_quota: { total: 20, used: 2, remaining: 18, percentage: 0.1, available: true, unit: "credits" },
    is_quota_exceeded: false,
  };

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("normalizes only the safe quota DTO and preserves percentage precision", () => {
    const usage = normalizeQoderQuotaUsage(response);
    expect(usage).toEqual({
      totalUsagePercentage: 12.68,
      expiresAt: 1_800_000_000,
      userQuota: { total: 100, used: 12.5, remaining: 87.5, percentage: 12.5, unit: "credits" },
      addOnQuota: { total: 40, used: 5, remaining: 35, percentage: 12.5, unit: "credits", detailUrl: "https://qoder.com.cn/private" },
      orgResourcePackage: { cap: 20, used: 2, remaining: 18, percentage: 10, available: true, unit: "credits" },
      isQuotaExceeded: false,
    });
    expect(JSON.stringify(usage)).not.toContain("private-user-id");
    expect(JSON.stringify(usage)).not.toContain("user_type");
    expect(Object.isFrozen(usage)).toBe(true);
    expect(normalizeQoderQuotaUsage({ ...response, total_usage_percentage: 101.234 }).totalUsagePercentage).toBe(101.23);
  });

  it("accepts a UUID-shaped user_id without exposing it in the quota DTO", () => {
    const userId = "123e4567-e89b-12d3-a456-426614174000";
    const usage = normalizeQoderQuotaUsage({ ...response, user_id: userId });
    expect(JSON.stringify(usage)).not.toContain(userId);
    expect(usage.userQuota).toEqual({ total: 100, used: 12.5, remaining: 87.5, percentage: 12.5, unit: "credits" });
  });

  it("accepts the officially supported camel-case root fields without preserving identities", () => {
    const camel = {
      userId: "private-user-id",
      userType: "pro",
      totalUsagePercentage: 12.5,
      expiresAt: 1_800_000_000,
      userQuota: response.user_quota,
      addOnQuota: { ...response.add_on_quota, detailUrl: response.add_on_quota.detail_url },
      orgResourcePackage: { ...response.shared_quota, cap: response.shared_quota.total },
      isQuotaExceeded: false,
    };
    expect(normalizeQoderQuotaUsage(camel)).toMatchObject({ totalUsagePercentage: 12.5, orgResourcePackage: { cap: 20 } });
    expect(JSON.stringify(normalizeQoderQuotaUsage(camel))).not.toContain("private-user-id");
  });

  it.each([
    ["missing identity", { ...response, user_id: undefined }],
    ["overlong identity", { ...response, user_id: "u".repeat(257) }],
    ["bad user quota", { ...response, user_quota: { ...response.user_quota, used: "12" } }],
    ["overlong unit", { ...response, user_quota: { ...response.user_quota, unit: "u".repeat(33) } }],
    ["overlong add-on detail URL", { ...response, add_on_quota: { ...response.add_on_quota, detail_url: "x".repeat(2_049) } }],
    ["ambiguous shared buckets", { ...response, org_resource_package: response.shared_quota }],
    ["data envelope", { data: response }],
  ])("fails closed for %s", (_label, body) => {
    expect(() => normalizeQoderQuotaUsage(body)).toThrow(QuotaUpstreamError);
  });

  it("uses OpenAPI Bearer GET and bounds upstream responses", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(_input).toBe("https://openapi.qoder.com.cn/api/v2/quota/usage");
      expect(init?.method).toBe("GET");
      expect(init?.headers).toEqual({ Accept: "application/json", Authorization: "Bearer access" });
      return jsonResponse(response);
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const usage = await fetchOfficialQoderQuota({}, testCredential("access", "refresh"), testBridge());
    expect(usage.totalUsagePercentage).toBe(12.68);

    let declaredCancelled = false;
    globalThis.fetch = vi.fn(async () => new Response(new ReadableStream({ cancel() { declaredCancelled = true; } }), { status: 200, headers: { "content-length": String(64 * 1024 + 1) } })) as unknown as typeof fetch;
    await expect(fetchOfficialQoderQuota({}, testCredential("access", "refresh"), testBridge())).rejects.toThrow(/size invalid/);
    expect(declaredCancelled).toBe(true);

    let streamedCancelled = false;
    const oversized = new Uint8Array(64 * 1024 + 1);
    globalThis.fetch = vi.fn(async () => new Response(new ReadableStream({ start(controller) { controller.enqueue(oversized); }, cancel() { streamedCancelled = true; } }), { status: 200 })) as unknown as typeof fetch;
    await expect(fetchOfficialQoderQuota({}, testCredential("access", "refresh"), testBridge())).rejects.toThrow(/too large/);
    expect(streamedCancelled).toBe(true);

    globalThis.fetch = vi.fn(async () => new Response(JSON.stringify(response), { status: 200 })) as unknown as typeof fetch;
    await expect(fetchOfficialQoderQuota({ QODER_OPENAPI_BASE: "https://evil.example.com" }, testCredential("access", "refresh"), testBridge())).rejects.toThrow(/白名单/);
  });

  it("single-flights cache loads, retries one 401 after refresh, and invalidates after refresh", async () => {
    let now = 1_000;
    let quotaCalls = 0;
    const session = createTestSession({ QODER_PROXY_QUOTA_TTL_MS: "1000" }, store, testCredential("access", "refresh"), auth, {
      now: () => now,
      quotaLoader: async () => {
        quotaCalls++;
        if (quotaCalls === 1) throw new QuotaUpstreamError("unauthorized", 401);
        return normalizeQoderQuotaUsage(response);
      },
    });
    const refresh = vi.spyOn(session, "refreshAndReauthenticate").mockResolvedValue(undefined);
    const [first, second] = await Promise.all([session.getQuotaUsage(), session.getQuotaUsage()]);
    expect(first).toEqual(second);
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(quotaCalls).toBe(2);
    await session.getQuotaUsage();
    expect(quotaCalls).toBe(2);
    now = 2_001;
    await session.getQuotaUsage();
    expect(quotaCalls).toBe(3);
  });

  it("fails closed when the 401 retry is also unauthorized", async () => {
    let quotaCalls = 0;
    const session = createTestSession({}, store, testCredential("access", "refresh"), auth, {
      quotaLoader: async () => { quotaCalls++; throw new QuotaUpstreamError("unauthorized", 401); },
    });
    const refresh = vi.spyOn(session, "refreshAndReauthenticate").mockResolvedValue(undefined);
    await expect(session.getQuotaUsage()).rejects.toMatchObject({ name: "QuotaUpstreamError", status: 401 });
    expect(quotaCalls).toBe(2);
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it("invalidates a populated quota cache after credential refresh", async () => {
    let quotaCalls = 0;
    const refreshStore: CredentialStore = { load: async () => undefined, isCommitted: async () => false, reserveRotation: async () => "owner", clearRotationReservation: async () => {}, stageRotation: async () => {}, save: async () => {}, delete: async () => {} };
    const session = createTestSession({}, refreshStore, testCredential("old-access", "old-refresh"), auth, {
      quotaLoader: async () => {
        quotaCalls++;
        return normalizeQoderQuotaUsage(response);
      },
    });
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => init?.method === "POST"
      ? jsonResponse({ device_token: "new-access", refresh_token: "new-refresh" })
      : jsonResponse({ id: "new-user" })) as unknown as typeof fetch;
    await session.getQuotaUsage();
    await session.getQuotaUsage();
    expect(quotaCalls).toBe(1);
    await session.refreshAndReauthenticate();
    await session.getQuotaUsage();
    expect(quotaCalls).toBe(2);
  });

  it("lets one cancelled quota waiter leave while the shared load settles for another waiter", async () => {
    let releaseLoad!: () => void;
    let quotaCalls = 0;
    const gate = new Promise<void>((resolve) => { releaseLoad = resolve; });
    const session = createTestSession({}, store, testCredential("access", "refresh"), auth, {
      quotaLoader: async () => { quotaCalls++; await gate; return normalizeQoderQuotaUsage(response); },
    });
    const controller = new AbortController();
    const cancelled = session.getQuotaUsage(controller.signal);
    const surviving = session.getQuotaUsage();
    await waitUntil(() => quotaCalls === 1);
    controller.abort(new Error("quota caller cancelled"));
    await expect(cancelled).rejects.toThrow(/quota caller cancelled/);
    releaseLoad();
    await expect(surviving).resolves.toMatchObject({ totalUsagePercentage: 12.68 });
    expect(quotaCalls).toBe(1);
  });

  it("drops an in-flight old quota result after refresh and reloads with the new credential", async () => {
    let quotaCalls = 0;
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((resolve) => { releaseFirst = resolve; });
    const refreshStore: CredentialStore = { load: async () => undefined, isCommitted: async () => false, reserveRotation: async () => "owner", clearRotationReservation: async () => {}, stageRotation: async () => {}, save: async () => {}, delete: async () => {} };
    const session = createTestSession({}, refreshStore, testCredential("old-access", "old-refresh"), auth, {
      quotaLoader: async () => {
        quotaCalls++;
        if (quotaCalls === 1) await firstGate;
        return normalizeQoderQuotaUsage({ ...response, total_usage_percentage: quotaCalls === 1 ? 0.1 : 0.2 });
      },
    });
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => init?.method === "POST"
      ? jsonResponse({ device_token: "new-access", refresh_token: "new-refresh" })
      : jsonResponse({ id: "new-user" })) as unknown as typeof fetch;
    const first = session.getQuotaUsage();
    await waitUntil(() => quotaCalls === 1);
    await session.refreshAndReauthenticate();
    releaseFirst();
    await expect(first).resolves.toMatchObject({ totalUsagePercentage: 20 });
    expect(quotaCalls).toBe(2);
  });

  it("observes a late shared quota rejection after caller cancellation", async () => {
    let rejectLoad!: (error: Error) => void;
    const session = createTestSession({}, store, testCredential("access", "refresh"), auth, {
      quotaLoader: async () => new Promise<QoderQuotaUsage>((_resolve, reject) => { rejectLoad = reject; }),
    });
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => { unhandled.push(reason); };
    process.on("unhandledRejection", onUnhandled);
    try {
      const controller = new AbortController();
      const waiting = session.getQuotaUsage(controller.signal);
      controller.abort(new Error("quota caller cancelled"));
      await expect(waiting).rejects.toThrow(/quota caller cancelled/);
      rejectLoad(new Error("late quota failure"));
      await new Promise((resolve) => setTimeout(resolve, 10));
      expect(unhandled).toEqual([]);
      await expect((session as unknown as { quotaUsagePromise?: Promise<QoderQuotaUsage> }).quotaUsagePromise).toBeUndefined();
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
  });
});

describe("signed model catalog request", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  function fakeCatalogContext(headers = new Map<string, string>()): QoderContext {
    const bridge = fakeResultBridge({ url: "https://gateway.qoder.com.cn/api/v2/model/list?Encode=1", headers, headerCount: headers.size });
    return { prepareRequest: () => new RequestResult(bridge, 1) } as never;
  }

  it("uses the official gateway path, GET method, and auth source", () => {
    const calls: unknown[][] = [];
    const bridge = fakeResultBridge({ url: "https://gateway.qoder.com.cn/api/v2/model/list?Encode=1", headers: new Map(), headerCount: 0 });
    const result = new RequestResult(bridge, 1);
    const context = {
      prepareRequest: (...args: unknown[]) => { calls.push(args); return result; },
    };
    expect(prepareSignedCatalogRequest(context as never, {})).toEqual({ url: "https://gateway.qoder.com.cn/api/v2/model/list?Encode=1", headers: {}, body: undefined });
    expect(calls).toEqual([["https://gateway.qoder.com.cn", "/api/v2/model/list?Encode=1", "GET", "auth"]]);
    expect(() => result.url).toThrow(/已释放/);
  });

  it("fetches and strictly validates a plain official catalog without real network", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(init?.method).toBe("GET");
      expect(init?.headers).toEqual({ "x-signed": "fixture" });
      return jsonResponse({ assistant: [{ key: "auto", display_name: "Auto", enable: true, max_input_tokens: 200000 }] });
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const models = await fetchOfficialModelCatalog(fakeCatalogContext(new Map([["x-signed", "fixture"]])), {}, testBridge());
    expect(models.map((model) => model.key)).toEqual(["auto"]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["invalid JSON", "not-json", /response invalid/],
    ["invalid schema", JSON.stringify({ assistant: [{ key: "auto", display_name: "Auto", enable: true, max_input_tokens: "bad" }] }), /正整数/],
  ])("fails closed for %s without leaking response content", async (_label, body, expected) => {
    globalThis.fetch = vi.fn(async () => new Response(body, { status: 200, headers: { "content-type": "application/json" } })) as unknown as typeof fetch;
    await expect(fetchOfficialModelCatalog(fakeCatalogContext(), {}, testBridge())).rejects.toThrow(expected);
  });

  it("rejects oversized responses from declared and streamed sizes", async () => {
    let declaredCancelled = false;
    globalThis.fetch = vi.fn(async () => new Response(new ReadableStream({ cancel() { declaredCancelled = true; } }), { status: 200, headers: { "content-length": String(4 * 1024 * 1024 + 1) } })) as unknown as typeof fetch;
    await expect(fetchOfficialModelCatalog(fakeCatalogContext(), {}, testBridge())).rejects.toThrow(/size invalid/);
    expect(declaredCancelled).toBe(true);

    let streamedCancelled = false;
    const oversized = new Uint8Array(4 * 1024 * 1024 + 1);
    globalThis.fetch = vi.fn(async () => new Response(new ReadableStream({ start(controller) { controller.enqueue(oversized); }, cancel() { streamedCancelled = true; } }), { status: 200 })) as unknown as typeof fetch;
    await expect(fetchOfficialModelCatalog(fakeCatalogContext(), {}, testBridge())).rejects.toThrow(/too large/);
    expect(streamedCancelled).toBe(true);
  });

  it("cancels a partially-read catalog body when the caller aborts", async () => {
    let cancelled = false;
    const controller = new AbortController();
    globalThis.fetch = vi.fn(async () => new Response(new ReadableStream({
      start(streamController) {
        streamController.enqueue(new TextEncoder().encode("{"));
        controller.abort(new Error("catalog cancelled"));
      },
      cancel() { cancelled = true; },
    }), { status: 200 })) as unknown as typeof fetch;
    await expect(fetchOfficialModelCatalog(fakeCatalogContext(), {}, testBridge(), controller.signal)).rejects.toThrow(/catalog cancelled/);
    expect(cancelled).toBe(true);
  });

  it("cancels non-success bodies and returns only a sanitized status error", async () => {
    let cancelled = false;
    globalThis.fetch = vi.fn(async () => new Response(new ReadableStream({ cancel() { cancelled = true; } }), { status: 503 })) as unknown as typeof fetch;
    await expect(fetchOfficialModelCatalog(fakeCatalogContext(), {}, testBridge())).rejects.toMatchObject({ name: "CatalogUpstreamError", status: 503, message: "model catalog HTTP 503" });
    expect(cancelled).toBe(true);
  });
});

describe("CLI startup preflight recovery", () => {
  it("retries pending credential persistence before bind", async () => {
    let attempts = 0;
    const session = {} as AuthSession;
    const preflight = vi.fn(async () => {
      attempts++;
      if (attempts === 1) throw new PendingPreflightPersistenceError({ owner: "owner", credential: testCredential("new-access", "new-refresh"), stageRequired: true }, new Error("stage failed"));
      return session;
    }) as unknown as typeof AuthSession.preflight;
    // 等价 CLI 边界：只有 preflightBeforeBind 成功返回后，调用方才允许 bind。
    await expect(preflightBeforeBind({ QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_PREFLIGHT_RETRY_MS: "1" }, preflight)).resolves.toBe(session);
    expect(preflight).toHaveBeenCalledTimes(2);
  });

  it("stays recovery-only until cancellation and never returns a session for binding", async () => {
    const error = new PendingPreflightPersistenceError({ owner: "owner", credential: testCredential("new-access", "new-refresh"), stageRequired: false }, new Error("save failed"));
    let calls = 0;
    const preflight = vi.fn(async () => { calls++; throw error; }) as unknown as typeof AuthSession.preflight;
    const controller = new AbortController();
    const pending = preflightBeforeBind({ QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_PREFLIGHT_RETRY_MS: "1" }, preflight, controller.signal);
    await waitUntil(() => calls >= 3);
    controller.abort(new Error("operator cancelled startup recovery"));
    await expect(pending).rejects.toThrow(/operator cancelled/);
    expect(calls).toBeGreaterThanOrEqual(3);
  });

  it("propagates a pre-bind termination signal instead of binding after preflight", async () => {
    const controller = new AbortController();
    let observedSignal: AbortSignal | undefined;
    const preflight = vi.fn(async (_env, signal) => {
      observedSignal = signal;
      await new Promise<void>((_resolve, reject) => signal?.addEventListener("abort", () => reject(signal.reason), { once: true }));
      throw new Error("unreachable");
    }) as unknown as typeof AuthSession.preflight;
    const pending = preflightBeforeBind({ QODER_PROXY_PREFLIGHT_RETRY_MS: "1" }, preflight, controller.signal);
    await waitUntil(() => observedSignal !== undefined);
    controller.abort(new Error("SIGTERM before bind"));
    await expect(pending).rejects.toThrow(/SIGTERM before bind/);
    expect(observedSignal?.aborted).toBe(true);
    expect(preflight).toHaveBeenCalledTimes(1);
  });

  it("drains a rotated credential to its durable journal before SIGTERM returns", async () => {
    const controller = new AbortController();
    let releaseJournal!: () => void;
    const journalGate = new Promise<void>((resolve) => { releaseJournal = resolve; });
    let journalDurable = false;
    const error = new PendingPreflightPersistenceError(
      { owner: "owner", credential: testCredential("new-access", "new-refresh"), stageRequired: true },
      new Error("stage interrupted"),
      async () => { await journalGate; journalDurable = true; },
    );
    let preflightCalls = 0;
    const preflight = vi.fn(async () => { preflightCalls++; throw error; }) as unknown as typeof AuthSession.preflight;
    const pending = preflightBeforeBind({ QODER_PROXY_PREFLIGHT_RETRY_MS: "1" }, preflight, controller.signal);
    await waitUntil(() => preflightCalls === 1);
    controller.abort(new Error("SIGTERM during stage"));
    let settled = false;
    pending.finally(() => { settled = true; }).catch(() => undefined);
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(settled).toBe(false);
    expect(journalDurable).toBe(false);
    releaseJournal();
    await expect(pending).rejects.toThrow(/SIGTERM during stage/);
    expect(journalDurable).toBe(true);
  });

  it.each([
    ["check-hang"],
    ["pre-write-hang"],
    ["after-write-hang"],
    ["permanent-failure"],
  ] as const)("serializes emergency durability in %s mode and recovers new token without another refresh", async (mode) => {
    const dir = await mkdtemp(join(tmpdir(), "qoder-proxy-sigterm-child-"));
    try {
      const configDir = join(dir, "cfg");
      const readyPath = join(dir, "ready");
      const bodiesPath = join(dir, "refresh-bodies.log");
      const metricsPath = join(dir, "stage-metrics.json");
      const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
      await store.save({ ...testCredential("old-access", "old-refresh"), expiresAt: 0 });
      const child = spawn(await testBunExecutable(), [join(process.cwd(), "tests/fixtures/preflight-sigterm-child.ts"), configDir, readyPath, bodiesPath, mode, metricsPath], { stdio: "ignore" });
      await waitUntil(async () => {
        try { return (await readFile(readyPath, "utf8")).length > 0; }
        catch { return false; }
      });
      child.kill("SIGTERM");
      await new Promise((resolve) => setTimeout(resolve, 10));
      expect(child.exitCode).toBeNull();
      child.kill("SIGTERM");
      const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => child.once("exit", (code, signal) => resolve({ code, signal })));
      expect(exit).toEqual({ code: 0, signal: null });
      const primaryJournal = join(configDir, "auth-cn.rotation.json");
      const emergencyJournal = join(configDir, "auth-cn.rotation.emergency.json");
      const configPath = join(configDir, "auth-cn.json");
      let durablePath = emergencyJournal;
      try { await stat(emergencyJournal); }
      catch {
        durablePath = primaryJournal;
        try { await stat(primaryJournal); } catch { durablePath = configPath; }
      }
      expect((await stat(durablePath)).mode & 0o777).toBe(0o600);

      const resultPath = join(dir, "recovered-token");
      const recoveryChild = spawn(await testBunExecutable(), [join(process.cwd(), "tests/fixtures/preflight-recover-child.ts"), configDir, bodiesPath, resultPath], { stdio: "ignore" });
      const recoveryExit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => recoveryChild.once("exit", (code, signal) => resolve({ code, signal })));
      expect(recoveryExit).toEqual({ code: 0, signal: null });
      expect((await readFile(resultPath, "utf8")).trim()).toBe("new-refresh");
      const bodies = (await readFile(bodiesPath, "utf8")).trim().split("\n");
      expect(bodies).toEqual([JSON.stringify({ refresh_token: "old-refresh" })]);
      const metrics = JSON.parse(await readFile(metricsPath, "utf8")) as Record<string, number>;
      expect(metrics).toMatchObject({ maxConcurrentChecks: 1, maxConcurrentEmergency: 1, actualWrites: 1, signalCount: 2 });
      expect(metrics.emergencyCalls).toBeGreaterThanOrEqual(1);
      for (const path of [primaryJournal, emergencyJournal]) await expect(stat(path)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("AuthSession preflight rotation recovery", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it.each(["isCommitted", "stageRotation", "save"] as const)("lets preflight abort while %s hangs, retains rotated recovery state, and never refreshes old token again", async (hangingStep) => {
    let committedChecks = 0;
    let stageCalls = 0;
    let saveCalls = 0;
    const never = new Promise<void>(() => {});
    const store: CredentialStore = {
      load: async () => ({ ...testCredential("old-access", "old-refresh"), expiresAt: 0 }),
      isCommitted: async () => { committedChecks++; if (hangingStep === "isCommitted") await never; return false; },
      reserveRotation: async () => "owner",
      clearRotationReservation: async () => {},
      stageRotation: async () => { stageCalls++; if (hangingStep === "stageRotation") await never; },
      save: async () => { saveCalls++; if (hangingStep === "save") await never; },
      delete: async () => {},
    };
    const env = { QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_CONFIG_DIR: join(tmpdir(), `qoder-proxy-preflight-hanging-${hangingStep}`), QODER_PROXY_REFRESH_TIMEOUT_MS: "1000" };
    const refreshBodies: string[] = [];
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") { refreshBodies.push(String(init.body)); return jsonResponse({ device_token: "new-access", refresh_token: "new-refresh" }); }
      return jsonResponse({ id: "new-user" });
    }) as unknown as typeof fetch;

    const firstController = new AbortController();
    const first = AuthSession.preflight(env, firstController.signal, { store, bridge: testBridge() });
    await waitUntil(() => hangingStep === "isCommitted" ? committedChecks >= 1 : hangingStep === "stageRotation" ? stageCalls >= 1 : saveCalls >= 1);
    firstController.abort(new Error(`SIGTERM during ${hangingStep}`));
    await expect(first).rejects.toBeInstanceOf(PendingPreflightPersistenceError);

    const secondController = new AbortController();
    const second = AuthSession.preflight(env, secondController.signal, { store, bridge: testBridge() });
    secondController.abort(new Error("second startup cancelled"));
    await expect(second).rejects.toBeInstanceOf(PendingPreflightPersistenceError);
    expect(refreshBodies).toEqual([JSON.stringify({ refresh_token: "old-refresh" })]);
  });

  it.each(["expired", "userinfo-401"])("recovers preflight staging failure without a second refresh request in %s path", async (path) => {
    const dir = await mkdtemp(join(tmpdir(), "qoder-proxy-preflight-stage-failure-"));
    try {
      const env = { QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_CONFIG_DIR: join(dir, "cfg"), QODER_PROXY_CAPABILITY_TIMEOUT_MS: "5000" };
      const baseStore = createConfigStore("machine-a", env);
      await baseStore.save(path === "expired" ? { ...testCredential("old-access", "old-refresh"), expiresAt: 0 } : testCredential("old-access", "old-refresh"));
      let stageCalls = 0;
      const store: CredentialStore = {
        load: () => baseStore.load(),
        isCommitted: (value) => baseStore.isCommitted(value),
        reserveRotation: (base) => baseStore.reserveRotation(base),
        clearRotationReservation: (owner) => baseStore.clearRotationReservation(owner),
        stageRotation: async (value, owner) => { stageCalls++; if (stageCalls === 1) throw new Error("rotation staging failed"); await baseStore.stageRotation(value, owner); },
        save: (value, owner) => baseStore.save(value, owner),
        delete: (owner) => baseStore.delete(owner),
      };
      const refreshBodies: string[] = [];
      let userinfoCalls = 0;
      globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
        if (init?.method === "POST") {
          refreshBodies.push(String(init.body));
          return jsonResponse({ device_token: "new-access", refresh_token: "new-refresh", expires_in: 3600 });
        }
        userinfoCalls++;
        if (path === "userinfo-401" && userinfoCalls === 1) return jsonResponse({}, 401);
        return jsonResponse({ id: "new-user" });
      }) as unknown as typeof fetch;

      const reservationPath = join(env.QODER_PROXY_CONFIG_DIR, "auth-cn.rotation.pending");
      const recovered = await preflightBeforeBind(env, (currentEnv, signal) => AuthSession.preflight(currentEnv, signal, { store, bridge: testBridge() }));
      expect(recovered).toBeInstanceOf(AuthSession);
      expect(stageCalls).toBe(2);
      expect(refreshBodies).toEqual([JSON.stringify({ refresh_token: "old-refresh" })]);
      expect((await baseStore.load())?.refreshToken).toBe("new-refresh");
      await expect(stat(reservationPath)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("reconciles a preflight trailing save error without a second refresh request", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qoder-proxy-preflight-trailing-save-"));
    try {
      const env = { QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_CONFIG_DIR: join(dir, "cfg") };
      const baseStore = createConfigStore("machine-a", env);
      await baseStore.save({ ...testCredential("old-access", "old-refresh"), expiresAt: 0 });
      let saveCalls = 0;
      let committed = false;
      const store: CredentialStore = {
        load: () => baseStore.load(),
        isCommitted: async (value) => committed && await baseStore.isCommitted(value),
        reserveRotation: (base) => baseStore.reserveRotation(base),
        clearRotationReservation: (owner) => baseStore.clearRotationReservation(owner),
        stageRotation: (value, owner) => baseStore.stageRotation(value, owner),
        save: async (value, owner) => {
          saveCalls++;
          await baseStore.save(value, owner);
          committed = true;
          if (saveCalls === 1) throw new Error("directory fsync failed after commit");
        },
        delete: (owner) => baseStore.delete(owner),
      };
      const refreshBodies: string[] = [];
      globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
        if (init?.method === "POST") { refreshBodies.push(String(init.body)); return jsonResponse({ device_token: "new-access", refresh_token: "new-refresh", expires_in: 3600 }); }
        return jsonResponse({ id: "new-user" });
      }) as unknown as typeof fetch;

      const recovered = await preflightBeforeBind(env, (currentEnv, signal) => AuthSession.preflight(currentEnv, signal, { store, bridge: testBridge() }));
      expect(recovered).toBeInstanceOf(AuthSession);
      expect(saveCalls).toBe(1);
      expect(refreshBodies).toEqual([JSON.stringify({ refresh_token: "old-refresh" })]);
      expect((await baseStore.load())?.refreshToken).toBe("new-refresh");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it.each(["body-reset", "invalid-json", "missing-token"])("treats a 200 %s refresh response as ambiguous and retains reservation", async (kind) => {
    const dir = await mkdtemp(join(tmpdir(), "qoder-proxy-preflight-ambiguous-200-"));
    try {
      const env = { QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_CONFIG_DIR: join(dir, "cfg") };
      const store = createConfigStore("machine-a", env);
      await store.save({ ...testCredential("old-access", "old-refresh"), expiresAt: 0 });
      const refreshBodies: string[] = [];
      globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
        if (init?.method === "POST") {
          refreshBodies.push(String(init.body));
          if (kind === "body-reset") return { ok: true, status: 200, text: async () => { throw new Error("body reset"); } } as unknown as Response;
          return new Response(kind === "invalid-json" ? "not-json" : JSON.stringify({ refresh_token: "new-refresh" }), { status: 200 });
        }
        return jsonResponse({ id: "old-user" });
      }) as unknown as typeof fetch;

      await expect(AuthSession.preflight(env, undefined, { store, bridge: testBridge() })).rejects.toThrow(/结果不明确/);
      await expect(AuthSession.preflight(env, undefined, { store, bridge: testBridge() })).rejects.toThrow(/轮换正在进行|owner 仍活跃/);
      expect(refreshBodies).toEqual([JSON.stringify({ refresh_token: "old-refresh" })]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it.each([
    ["missing refresh_token", { device_token: "new-access" }],
    ["empty refresh_token", { device_token: "new-access", refresh_token: "" }],
    ["numeric refresh_token", { device_token: "new-access", refresh_token: 42 }],
    ["negative expires_at", { device_token: "new-access", refresh_token: "new-refresh", expires_at: -1 }],
    ["invalid expires_at string", { device_token: "new-access", refresh_token: "new-refresh", expires_at: "not-a-time" }],
    ["negative expires_in", { device_token: "new-access", refresh_token: "new-refresh", expires_in: -1 }],
    ["string expires_in", { device_token: "new-access", refresh_token: "new-refresh", expires_in: "3600" }],
    ["negative refresh_token_expires_at", { device_token: "new-access", refresh_token: "new-refresh", refresh_token_expires_at: -1 }],
    ["invalid refresh_token_expires_at string", { device_token: "new-access", refresh_token: "new-refresh", refresh_token_expires_at: "never" }],
    ["negative refresh_token_expires_in", { device_token: "new-access", refresh_token: "new-refresh", refresh_token_expires_in: -1 }],
    ["infinite refresh_token_expires_in", { device_token: "new-access", refresh_token: "new-refresh", refresh_token_expires_in: Number.POSITIVE_INFINITY }],
  ])("treats preflight 2xx %s as ambiguous and never replays the old refresh token", async (_label, responseBody) => {
    const dir = await mkdtemp(join(tmpdir(), "qoder-proxy-preflight-invalid-refresh-schema-"));
    try {
      const env = { QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_CONFIG_DIR: join(dir, "cfg") };
      const store = createConfigStore("machine-a", env);
      await store.save({ ...testCredential("old-access", "old-refresh"), expiresAt: 0 });
      const refreshBodies: string[] = [];
      globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
        if (init?.method === "POST") { refreshBodies.push(String(init.body)); return jsonResponse(responseBody); }
        return jsonResponse({ id: "old-user" });
      }) as unknown as typeof fetch;

      await expect(AuthSession.preflight(env, undefined, { store, bridge: testBridge() })).rejects.toThrow(/结果不明确/);
      await expect(AuthSession.preflight(env, undefined, { store, bridge: testBridge() })).rejects.toThrow(/轮换正在进行|owner 仍活跃/);
      expect(refreshBodies).toEqual([JSON.stringify({ refresh_token: "old-refresh" })]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("times out a hanging 200 response body as ambiguous without retrying", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qoder-proxy-preflight-body-timeout-"));
    try {
      const env = { QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_CONFIG_DIR: join(dir, "cfg"), QODER_PROXY_REFRESH_TIMEOUT_MS: "10" };
      const store = createConfigStore("machine-a", env);
      await store.save({ ...testCredential("old-access", "old-refresh"), expiresAt: 0 });
      const refreshBodies: string[] = [];
      globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
        if (init?.method !== "POST") return jsonResponse({ id: "old-user" });
        refreshBodies.push(String(init.body));
        return { ok: true, status: 200, text: async () => await new Promise<string>(() => {}) } as unknown as Response;
      }) as unknown as typeof fetch;

      await expect(AuthSession.preflight(env, undefined, { store, bridge: testBridge() })).rejects.toThrow(/结果不明确/);
      await expect(store.load()).rejects.toThrow(/owner 仍活跃/);
      expect(refreshBodies).toEqual([JSON.stringify({ refresh_token: "old-refresh" })]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("times out a hanging preflight refresh as ambiguous without binding or retrying", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qoder-proxy-preflight-timeout-"));
    try {
      const env = { QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_CONFIG_DIR: join(dir, "cfg"), QODER_PROXY_REFRESH_TIMEOUT_MS: "10" };
      const store = createConfigStore("machine-a", env);
      await store.save({ ...testCredential("old-access", "old-refresh"), expiresAt: 0 });
      const refreshBodies: string[] = [];
      globalThis.fetch = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
        if (init?.method !== "POST") return Promise.resolve(jsonResponse({ id: "old-user" }));
        refreshBodies.push(String(init.body));
        return new Promise<Response>((_resolve, reject) => init.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true }));
      }) as unknown as typeof fetch;

      await expect(AuthSession.preflight(env, undefined, { store, bridge: testBridge() })).rejects.toThrow(/结果不明确/);
      await expect(store.load()).rejects.toThrow(/owner 仍活跃/);
      expect(refreshBodies).toEqual([JSON.stringify({ refresh_token: "old-refresh" })]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("retains the reservation after an ambiguous preflight refresh response", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qoder-proxy-preflight-ambiguous-"));
    try {
      const env = { QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_CONFIG_DIR: join(dir, "cfg") };
      const store = createConfigStore("machine-a", env);
      await store.save({ ...testCredential("old-access", "old-refresh"), expiresAt: 0 });
      const refreshBodies: string[] = [];
      globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
        if (init?.method === "POST") { refreshBodies.push(String(init.body)); throw new Error("connection reset after send"); }
        return jsonResponse({ id: "old-user" });
      }) as unknown as typeof fetch;

      await expect(AuthSession.preflight(env, undefined, { store, bridge: testBridge() })).rejects.toThrow(/结果不明确/);
      await expect(AuthSession.preflight(env, undefined, { store, bridge: testBridge() })).rejects.toThrow(/轮换正在进行|owner 仍活跃/);
      expect(refreshBodies).toEqual([JSON.stringify({ refresh_token: "old-refresh" })]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects a stale preflight reservation before any second refresh request", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qoder-proxy-preflight-cas-"));
    try {
      const env = { QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_CONFIG_DIR: join(dir, "cfg") };
      const firstStore = createConfigStore("machine-a", env);
      const secondStore = createConfigStore("machine-a", env);
      const oldCredential = { ...testCredential("old-access", "old-refresh"), expiresAt: 0 };
      await firstStore.save(oldCredential);
      const stale = await secondStore.load();
      expect(stale?.refreshToken).toBe("old-refresh");
      const refreshBodies: string[] = [];
      globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
        if (init?.method === "POST") {
          refreshBodies.push(String(init.body));
          return jsonResponse({ device_token: "new-access", refresh_token: "new-refresh", expires_in: 3600 });
        }
        return jsonResponse({ id: "new-user" });
      }) as unknown as typeof fetch;

      await AuthSession.preflight(env, undefined, { store: firstStore, bridge: testBridge() });
      const staleStore: CredentialStore = { ...secondStore, load: async () => stale };
      await expect(AuthSession.preflight(env, undefined, { store: staleStore, bridge: testBridge() })).rejects.toThrow(/durable config 已变化|过期凭据/);
      expect(refreshBodies).toEqual([JSON.stringify({ refresh_token: "old-refresh" })]);
      expect((await firstStore.load())?.refreshToken).toBe("new-refresh");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("fails closed when preflight cannot clear a reservation after refresh fails before rotation", async () => {
    const store: CredentialStore = {
      load: async () => ({ ...testCredential("old-access", "old-refresh"), expiresAt: 0 }),
      isCommitted: async () => false,
      reserveRotation: async () => "owner",
      clearRotationReservation: async () => { throw new Error("cleanup denied"); },
      stageRotation: async () => {},
      save: async () => {},
      delete: async () => {},
    };
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") return jsonResponse({}, 500);
      return jsonResponse({ id: "old-user" });
    }) as unknown as typeof fetch;

    await expect(AuthSession.preflight({ QODER_CN_MACHINE_ID: "machine-a" }, undefined, { store, bridge: testBridge() })).rejects.toThrow(/预留清理失败.*降级/);
  });

  it.each(["expired", "userinfo-401"])("recovers staged rotation after config commit failure in %s path", async (path) => {
    const dir = await mkdtemp(join(tmpdir(), "qoder-proxy-preflight-"));
    try {
      const env = { QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_CONFIG_DIR: join(dir, "cfg"), QODER_PROXY_CAPABILITY_TIMEOUT_MS: "5000" };
      const baseStore = createConfigStore("machine-a", env);
      await baseStore.save(path === "expired" ? { ...testCredential("old-access", "old-refresh"), expiresAt: 0 } : testCredential("old-access", "old-refresh"));
      let saveCalls = 0;
      const store: CredentialStore = {
        load: () => baseStore.load(),
        isCommitted: (value) => baseStore.isCommitted(value),
        reserveRotation: (base) => baseStore.reserveRotation(base),
        clearRotationReservation: (owner) => baseStore.clearRotationReservation(owner),
        stageRotation: (value, owner) => baseStore.stageRotation(value, owner),
        save: async (value, owner) => { saveCalls++; if (saveCalls === 1) throw new Error("config commit failed"); await baseStore.save(value, owner); },
        delete: () => baseStore.delete(),
      };
      const refreshBodies: string[] = [];
      let userinfoCalls = 0;
      globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
        if (init?.method === "POST") {
          refreshBodies.push(String(init.body));
          return jsonResponse({ device_token: "new-access", refresh_token: "new-refresh", expires_in: 3600 });
        }
        userinfoCalls++;
        if (path === "userinfo-401" && userinfoCalls === 1) return jsonResponse({}, 401);
        return jsonResponse({ id: "new-user" });
      }) as unknown as typeof fetch;

      const journalPath = join(env.QODER_PROXY_CONFIG_DIR, "auth-cn.rotation.json");
      const recovered = await preflightBeforeBind(env, (currentEnv, signal) => AuthSession.preflight(currentEnv, signal, { store, bridge: testBridge() }));
      expect(recovered).toBeInstanceOf(AuthSession);
      expect(saveCalls).toBe(2);
      expect(refreshBodies).toEqual([JSON.stringify({ refresh_token: "old-refresh" })]);
      expect((await baseStore.load())?.refreshToken).toBe("new-refresh");
      await expect(stat(journalPath)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("reservation owner activity", () => {
  it("fails closed when a live PID start identity cannot be read", async () => {
    await expect(evaluateProcessOwnerActivity("expected", () => "live-or-unknown", async () => undefined)).resolves.toBe(true);
  });

  it("distinguishes a dead owner and a reused PID", async () => {
    await expect(evaluateProcessOwnerActivity("expected", () => "dead", async () => undefined)).resolves.toBe(false);
    await expect(evaluateProcessOwnerActivity("expected", () => "live-or-unknown", async () => "different")).resolves.toBe(false);
  });
});

describe("createConfigStore (safe file store, no real credentials)", () => {
  let dir: string;

  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  it("round-trips a credential with 0700 dir / 0600 file permissions and atomic write", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-test-"));
    const configDir = join(dir, "cfg");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    await saveFixture(store, "machine-a");
    const loaded = await store.load();
    expect(loaded?.token).toBe("fixture-token-not-real");

    const dirStat = await stat(configDir);
    expect(dirStat.mode & 0o777).toBe(0o700);
    const fileStat = await stat(join(configDir, "auth-cn.json"));
    expect(fileStat.mode & 0o777).toBe(0o600);
  });

  it("rejects a stale base credential before granting a rotation reservation", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-test-"));
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: join(dir, "cfg") });
    const oldCredential = testCredential("old-access", "old-refresh");
    await store.save(testCredential("current-access", "current-refresh"));
    await expect(store.reserveRotation(oldCredential)).rejects.toThrow(/durable config 已变化|过期凭据/);
    expect((await store.load())?.refreshToken).toBe("current-refresh");
  });

  it("persists a 0600 rotation reservation, blocks old config, and clears it explicitly", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-test-"));
    const configDir = join(dir, "cfg");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const oldCredential = testCredential("old-access", "old-refresh");
    await store.save(oldCredential);
    const owner = await store.reserveRotation(oldCredential);
    const reservationPath = join(configDir, "auth-cn.rotation.pending");
    expect((await stat(reservationPath)).mode & 0o777).toBe(0o600);
    await expect(store.load()).rejects.toThrow(/owner 仍活跃|旧凭据已禁止使用/);
    await store.clearRotationReservation(owner);
    expect((await store.load())?.refreshToken).toBe("old-refresh");
    await expect(stat(reservationPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("enforces cross-process reservation ownership and only lets the owner clear it", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-test-"));
    const configDir = join(dir, "cfg");
    const first = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const contender = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const oldCredential = testCredential("old-access", "old-refresh");
    await first.save(oldCredential);
    const owner = await first.reserveRotation(oldCredential);

    await expect(contender.reserveRotation(oldCredential)).rejects.toThrow(/轮换正在进行/);
    await expect(contender.clearRotationReservation("not-owner")).rejects.toThrow(/owner 不匹配/);
    await expect(contender.stageRotation(testCredential("new-access", "new-refresh"), "not-owner")).rejects.toThrow(/owner 不匹配/);
    await expect(first.load()).rejects.toThrow(/owner 仍活跃/);

    await first.clearRotationReservation(owner);
    expect((await contender.load())?.refreshToken).toBe("old-refresh");
  });

  it("rechecks the durable base hash before stage and save", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-test-"));
    const configDir = join(dir, "cfg");
    const configPath = join(configDir, "auth-cn.json");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const oldCredential = testCredential("old-access", "old-refresh");
    const foreignCredential = testCredential("foreign-access", "foreign-refresh");
    const newCredential = testCredential("new-access", "new-refresh");
    await store.save(oldCredential);

    const stageOwner = await store.reserveRotation(oldCredential);
    await writeFile(configPath, `${JSON.stringify(foreignCredential)}\n`, { mode: 0o600 });
    await chmod(configPath, 0o600);
    await expect(store.stageRotation(newCredential, stageOwner)).rejects.toThrow(/durable config 已变化/);
    await store.clearRotationReservation(stageOwner);

    await store.save(oldCredential);
    const saveOwner = await store.reserveRotation(oldCredential);
    await store.stageRotation(newCredential, saveOwner);
    await writeFile(configPath, `${JSON.stringify(foreignCredential)}\n`, { mode: 0o600 });
    await chmod(configPath, 0o600);
    await expect(store.save(newCredential, saveOwner)).rejects.toThrow(/durable config 已变化/);
    expect((await stat(join(configDir, "auth-cn.rotation.json"))).mode & 0o777).toBe(0o600);
    await store.clearRotationReservation(saveOwner);
  });

  it("binds emergency recovery to owner/base/target and rejects overwrite attempts", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-emergency-binding-"));
    const configDir = join(dir, "cfg");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    const differentTarget = testCredential("other-access", "other-refresh");
    await store.save(base);
    const owner = await store.reserveRotation(base);

    await store.stageEmergencyRotation!(target, owner);
    const emergencyPath = join(configDir, "auth-cn.rotation.emergency.json");
    const first = await readFile(emergencyPath, "utf8");
    expect((await stat(emergencyPath)).mode & 0o777).toBe(0o600);
    await store.stageEmergencyRotation!(target, owner);
    expect(await readFile(emergencyPath, "utf8")).toBe(first);
    await expect(store.stageEmergencyRotation!(differentTarget, owner)).rejects.toThrow(/owner\/base\/target|不一致/);
    await expect(store.stageEmergencyRotation!(target, "foreign-owner")).rejects.toThrow(/owner 不匹配/);
    expect(await readFile(emergencyPath, "utf8")).toBe(first);

    await store.save(target, owner);
    expect((await store.load())?.refreshToken).toBe("new-refresh");
    await expect(stat(emergencyPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("publishes only complete emergency records and ignores untrusted stale temp artifacts", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-emergency-temp-"));
    const configDir = join(dir, "cfg");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    await store.save(base);
    const owner = await store.reserveRotation(base);
    const staleTemp = join(configDir, ".auth-cn.rotation.emergency.json.crashed.tmp");
    await writeFile(staleTemp, "{\"version\":1", { mode: 0o600 });

    await store.stageEmergencyRotation!(target, owner);
    const emergencyPath = join(configDir, "auth-cn.rotation.emergency.json");
    const published = JSON.parse(await readFile(emergencyPath, "utf8")) as { owner: string; baseCredentialHash: string; targetCredentialHash: string; credential: StoredCredential };
    expect(published.owner).toBe(owner);
    expect(published.baseCredentialHash).toHaveLength(64);
    expect(published.targetCredentialHash).toHaveLength(64);
    expect(published.credential.refreshToken).toBe("new-refresh");
    expect((await stat(emergencyPath)).mode & 0o777).toBe(0o600);
    expect(await readFile(staleTemp, "utf8")).toBe("{\"version\":1");
    expect((await readdir(configDir)).filter((name) => name.includes(".tmp"))).toEqual([".auth-cn.rotation.emergency.json.crashed.tmp"]);

    await store.save(target, owner);
    expect((await store.load())?.refreshToken).toBe("new-refresh");
  });

  it.each([
    "before-create",
    "after-create",
    "after-write",
    "after-chmod",
    "after-file-fsync",
    "before-publish",
  ] as const)("does not expose an emergency final record when %s fails before publish", async (failedPhase) => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-emergency-prepublish-failure-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_PROXY_CONFIG_DIR: configDir };
    const baseStore = createConfigStore("machine-a", env);
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    await baseStore.save(base);
    const owner = await baseStore.reserveRotation(base);
    const failingStore = createConfigStore("machine-a", env, {
      onRotationPublishPhase: (phase) => { if (phase === failedPhase) throw new Error(`injected ${phase}`); },
    });

    await expect(failingStore.stageEmergencyRotation!(target, owner)).rejects.toThrow(new RegExp(failedPhase));
    await expect(stat(join(configDir, "auth-cn.rotation.emergency.json"))).rejects.toMatchObject({ code: "ENOENT" });
    const leftovers = (await readdir(configDir)).filter((name) => name.includes(".tmp"));
    expect(leftovers).toEqual([]);

    await baseStore.stageEmergencyRotation!(target, owner);
    await baseStore.save(target, owner);
    expect((await baseStore.load())?.refreshToken).toBe("new-refresh");
  });

  it("keeps a complete published record recoverable when failure occurs after publish", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-emergency-postpublish-failure-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_PROXY_CONFIG_DIR: configDir };
    const baseStore = createConfigStore("machine-a", env);
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    await baseStore.save(base);
    const owner = await baseStore.reserveRotation(base);
    const failingStore = createConfigStore("machine-a", env, {
      onRotationPublishPhase: (phase) => { if (phase === "after-publish") throw new Error("killed after publish"); },
    });

    await expect(failingStore.stageEmergencyRotation!(target, owner)).rejects.toThrow(/after publish/);
    const emergencyPath = join(configDir, "auth-cn.rotation.emergency.json");
    const published = JSON.parse(await readFile(emergencyPath, "utf8")) as { credential: StoredCredential };
    expect(published.credential.refreshToken).toBe("new-refresh");
    expect((await stat(emergencyPath)).mode & 0o777).toBe(0o600);
    expect((await readdir(configDir)).some((name) => name.includes(".tmp"))).toBe(true);

    const trustedTemps = (await readdir(configDir)).filter((name) => /^\.auth-cn\.rotation\.emergency\.json\..+\.tmp$/.test(name));
    expect(trustedTemps).toHaveLength(1);
    await baseStore.clearRotationReservation(owner);
    expect((await baseStore.load())?.refreshToken).toBe("new-refresh");
    await expect(stat(emergencyPath)).rejects.toMatchObject({ code: "ENOENT" });
    expect((await readdir(configDir)).filter((name) => /^\.auth-cn\.rotation\.emergency\.json\..+\.tmp$/.test(name))).toEqual([]);
  });

  it.each([
    "before-directory-fsync",
    "after-directory-fsync",
  ] as const)("keeps the complete final and safe temp state when %s fails", async (failedPhase) => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-emergency-dir-fsync-failure-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_PROXY_CONFIG_DIR: configDir };
    const baseStore = createConfigStore("machine-a", env);
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    await baseStore.save(base);
    const owner = await baseStore.reserveRotation(base);
    const failingStore = createConfigStore("machine-a", env, {
      onRotationPublishPhase: (phase) => { if (phase === failedPhase) throw new Error(`injected ${phase}`); },
    });

    await expect(failingStore.stageEmergencyRotation!(target, owner)).rejects.toThrow(new RegExp(failedPhase));
    const emergencyPath = join(configDir, "auth-cn.rotation.emergency.json");
    expect((JSON.parse(await readFile(emergencyPath, "utf8")) as { credential: StoredCredential }).credential.refreshToken).toBe("new-refresh");
    expect((await readdir(configDir)).some((name) => name.includes(".tmp"))).toBe(true);
    await baseStore.clearRotationReservation(owner);
    expect((await baseStore.load())?.refreshToken).toBe("new-refresh");
    expect((await readdir(configDir)).filter((name) => /^\.auth-cn\.rotation\.emergency\.json\..+\.tmp$/.test(name))).toEqual([]);
  });

  it.each([
    ["before-publish", false],
    ["after-publish", true],
  ] as const)("recovers safely when a process is killed at %s", async (phase, finalExists) => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-emergency-kill-"));
    const configDir = join(dir, "cfg");
    const readyPath = join(dir, "ready");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    await store.save(base);
    const owner = await store.reserveRotation(base);
    const child = spawn(await testBunExecutable(), [
      join(process.cwd(), "tests/fixtures/rotation-publish-child.ts"),
      configDir,
      owner,
      JSON.stringify(target),
      phase,
      readyPath,
    ], { stdio: "ignore" });
    await waitUntil(async () => {
      try { return (await readFile(readyPath, "utf8")).trim() === phase; }
      catch { return false; }
    });
    child.kill("SIGKILL");
    const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => child.once("exit", (code, signal) => resolve({ code, signal })));
    expect(exit.signal).toBe("SIGKILL");
    const emergencyPath = join(configDir, "auth-cn.rotation.emergency.json");
    if (finalExists) {
      expect((JSON.parse(await readFile(emergencyPath, "utf8")) as { credential: StoredCredential }).credential.refreshToken).toBe("new-refresh");
      expect((await readdir(configDir)).filter((name) => /^\.auth-cn\.rotation\.emergency\.json\..+\.tmp$/.test(name))).toHaveLength(1);
      await store.clearRotationReservation(owner);
      expect((await store.load())?.refreshToken).toBe("new-refresh");
      expect((await readdir(configDir)).filter((name) => /^\.auth-cn\.rotation\.emergency\.json\..+\.tmp$/.test(name))).toEqual([]);
    } else {
      await expect(stat(emergencyPath)).rejects.toMatchObject({ code: "ENOENT" });
      const reservationPath = join(configDir, "auth-cn.rotation.pending");
      const reservation = JSON.parse(await readFile(reservationPath, "utf8")) as Record<string, unknown>;
      reservation.processId = 2_147_483_647;
      reservation.processStartIdentity = "dead-owner";
      await writeFile(reservationPath, `${JSON.stringify(reservation)}\n`, { mode: 0o600 });
      await chmod(reservationPath, 0o600);
      const restarted = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
      expect((await restarted.load())?.refreshToken).toBe("new-refresh");
      expect((await readdir(configDir)).filter((name) => name.includes(".tmp"))).toEqual([]);
    }
  });

  it("rejects mixed trusted and malformed cleanup candidates without deleting the trusted one", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-cleanup-two-phase-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_PROXY_CONFIG_DIR: configDir };
    const store = createConfigStore("machine-a", env);
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    await store.save(base);
    const owner = await store.reserveRotation(base);
    const failingStore = createConfigStore("machine-a", env, {
      onRotationPublishPhase: (phase) => { if (phase === "after-publish") throw new Error("leave trusted temp"); },
    });
    await expect(failingStore.stageEmergencyRotation!(target, owner)).rejects.toThrow(/trusted temp/);
    const trustedPath = join(configDir, (await readdir(configDir)).find((name) => name.endsWith(".tmp"))!);
    const journalPath = join(configDir, "auth-cn.rotation.emergency.json");
    const journal = JSON.parse(await readFile(journalPath, "utf8")) as { artifactId: string };
    const malformedPath = join(configDir, `.auth-cn.rotation.emergency.json.99999.${journal.artifactId}.claim`);
    await writeFile(malformedPath, "{\"version\":1", { mode: 0o600 });
    const trustedBytes = await readFile(trustedPath, "utf8");
    await store.clearRotationReservation(owner);

    await expect(store.load()).rejects.toThrow(/JSON Parse|内容非法/);
    expect(await readFile(trustedPath, "utf8")).toBe(trustedBytes);
    expect(await readFile(malformedPath, "utf8")).toBe("{\"version\":1");
    expect((await stat(journalPath)).mode & 0o777).toBe(0o600);
  });

  it("rejects existing different claim bytes without overwriting them", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-claim-no-replace-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_PROXY_CONFIG_DIR: configDir };
    const store = createConfigStore("machine-a", env);
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    await store.save(base);
    const owner = await store.reserveRotation(base);
    const readyPath = join(dir, "ready");
    const child = spawn(await testBunExecutable(), [join(process.cwd(), "tests/fixtures/rotation-publish-child.ts"), configDir, owner, JSON.stringify(target), "before-publish", readyPath], { stdio: "ignore" });
    await waitUntil(async () => { try { return (await readFile(readyPath, "utf8")).trim() === "before-publish"; } catch { return false; } });
    child.kill("SIGKILL");
    await new Promise<void>((resolve) => child.once("exit", () => resolve()));
    const sourceName = (await readdir(configDir)).find((name) => name.endsWith(".tmp"));
    if (!sourceName) throw new Error("missing orphan");
    const source = JSON.parse(await readFile(join(configDir, sourceName), "utf8")) as { artifactId: string };
    const claimPath = join(configDir, `.auth-cn.rotation.emergency.json.${source.artifactId}.claim`);
    await writeFile(claimPath, "foreign-claim-bytes\n", { mode: 0o600 });

    await expect(store.stageEmergencyRotation!(target, owner)).rejects.toThrow(/rotation temp|claim|JSON Parse/);
    expect(await readFile(claimPath, "utf8")).toBe("foreign-claim-bytes\n");
    await expect(stat(join(configDir, "auth-cn.rotation.emergency.json"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it.each(["timeout", "caller-abort"] as const)("cancels a permanently hanging fd capability probe on %s, cleans probe/reservation, and never refreshes", async (mode) => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-capability-hang-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_CONFIG_DIR: configDir, QODER_PROXY_REFRESH_TIMEOUT_MS: "1000", QODER_PROXY_CAPABILITY_TIMEOUT_MS: "15" };
    const baseStore = createConfigStore("machine-a", env);
    const expired = { ...testCredential("old-access", "old-refresh"), expiresAt: 0 };
    await baseStore.save(expired);
    const hangingStore = createConfigStore("machine-a", env, { capabilityProbeMode: "async-pending" });
    const refreshBodies: string[] = [];
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") refreshBodies.push(String(init.body));
      return jsonResponse({ id: "unused" });
    }) as unknown as typeof fetch;
    const controller = new AbortController();
    const preflight = preflightBeforeBind(
      env,
      (currentEnv, signal) => AuthSession.preflight(currentEnv, signal, { store: hangingStore, bridge: testBridge() }),
      mode === "caller-abort" ? controller.signal : undefined,
    );
    if (mode === "caller-abort") setTimeout(() => controller.abort(new Error("SIGTERM during capability probe")), 5);

    await expect(preflight).rejects.toThrow(mode === "caller-abort" ? /SIGTERM during capability probe/ : /timed out|Timeout|aborted/i);
    await waitForCapabilityQuiescence(configDir);
    expect(refreshBodies).toEqual([]);
    await expect(stat(join(configDir, "auth-cn.rotation.pending"))).rejects.toMatchObject({ code: "ENOENT" });
    expect((await readdir(configDir)).filter((name) => name.startsWith(".rotation-fd-probe."))).toEqual([]);
    expect((await baseStore.load())?.refreshToken).toBe("old-refresh");
    const restarted = createConfigStore("machine-a", env);
    expect((await restarted.load())?.refreshToken).toBe("old-refresh");
  });

  it.each(["sync-block", "late-success", "late-reject"] as const)("terminates isolated %s capability work after an explicit native-start signal and leaves no late publication", async (mode) => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-capability-late-aba-"));
    const configDir = join(dir, "cfg");
    const nativeStartedPath = join(dir, "native-started");
    const env = { QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_CONFIG_DIR: configDir, QODER_PROXY_CAPABILITY_TIMEOUT_MS: "5000" };
    const baseStore = createConfigStore("machine-a", env);
    const expired = { ...testCredential("old-access", "old-refresh"), expiresAt: 0 };
    await baseStore.save(expired);
    const store = createConfigStore("machine-a", env, { capabilityProbeMode: mode, capabilityNativeStartedPath: nativeStartedPath });
    const refreshBodies: string[] = [];
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") refreshBodies.push(String(init.body));
      return jsonResponse({ id: "unused" });
    }) as unknown as typeof fetch;
    const controller = new AbortController();
    const preflight = AuthSession.preflight(env, controller.signal, { store, bridge: testBridge() });
    await waitUntil(async () => { try { return (await readFile(nativeStartedPath, "utf8")).startsWith("native-started\n"); } catch { return false; } });
    const nativeStartedLines = (await readFile(nativeStartedPath, "utf8")).trim().split("\n");
    const oldProbeDir = nativeStartedLines[1];
    if (!oldProbeDir) throw new Error("missing isolated probe namespace");
    controller.abort(new Error("test abort after native start"));

    await expect(preflight).rejects.toThrow(/test abort after native start/);
    await mkdir(oldProbeDir, { mode: 0o700 });
    const recreatedSource = join(oldProbeDir, "source");
    await writeFile(recreatedSource, "unrelated-reused-path\n", { mode: 0o600 });
    await new Promise((resolve) => setTimeout(resolve, 300));

    expect(refreshBodies).toEqual([]);
    expect(await readFile(recreatedSource, "utf8")).toBe("unrelated-reused-path\n");
    await expect(stat(join(oldProbeDir, "target"))).rejects.toMatchObject({ code: "ENOENT" });
    await expect(stat(join(configDir, "auth-cn.rotation.pending"))).rejects.toMatchObject({ code: "ENOENT" });
    expect((await readdir(configDir)).filter((name) => name.includes("mutation.lock"))).toEqual([]);
  });

  it.each([
    ["before-deadline", 1000, 100, true],
    ["after-deadline", 30, 150, false],
  ] as const)("handles slow capability readiness deterministically %s", async (_label, timeoutMs, startupDelayMs, shouldSucceed) => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-capability-readiness-deadline-"));
    const configDir = join(dir, "cfg");
    const readyPath = join(dir, "ready");
    const env = { QODER_PROXY_CONFIG_DIR: configDir, QODER_PROXY_CAPABILITY_TIMEOUT_MS: String(timeoutMs) };
    const baseStore = createConfigStore("machine-a", env);
    const base = testCredential("old-access", "old-refresh");
    await baseStore.save(base);
    const store = createConfigStore("machine-a", env, {
      capabilityProbeMode: "sync-block",
      capabilityProbeReadyPath: readyPath,
      capabilitySupervisorStartupDelayMs: startupDelayMs,
    });

    if (shouldSucceed) {
      const controller = new AbortController();
      const reservation = store.reserveRotation(base, controller.signal);
      await waitUntil(async () => { try { return (await readFile(readyPath, "utf8")).startsWith("capability-started\n"); } catch { return false; } });
      controller.abort(new Error("readiness observed"));
      await expect(reservation).rejects.toThrow(/readiness observed/);
    } else {
      await expect(store.reserveRotation(base)).rejects.toThrow(/timed out|Timeout|aborted/i);
      await expect(stat(readyPath)).rejects.toMatchObject({ code: "ENOENT" });
    }
    expect((await readdir(configDir)).filter((name) => name.startsWith(".rotation-fd-probe.") || name.includes("mutation.lock") || name === "auth-cn.rotation.pending")).toEqual([]);
    expect((await baseStore.load())?.refreshToken).toBe("old-refresh");
  });

  it("never spawns a worker when the parent dies during delayed supervisor startup", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-capability-pre-spawn-kill-"));
    const configDir = join(dir, "cfg");
    const supervisorReadyPath = join(dir, "supervisor-ready");
    const workerReadyPath = join(dir, "worker-ready");
    const bodiesPath = join(dir, "bodies");
    const child = spawn(await testBunExecutable(), [
      join(process.cwd(), "tests/fixtures/preflight-capability-pre-spawn-kill-child.ts"),
      configDir,
      supervisorReadyPath,
      workerReadyPath,
      bodiesPath,
    ], { stdio: "ignore" });
    await waitUntil(async () => { try { return (await readFile(supervisorReadyPath, "utf8")).startsWith("supervisor-started\n"); } catch { return false; } });
    const supervisorLines = (await readFile(supervisorReadyPath, "utf8")).trim().split("\n");
    const supervisorPid = Number(supervisorLines[2]);
    child.kill("SIGKILL");
    await new Promise<void>((resolve) => child.once("exit", () => resolve()));
    const isAlive = (pid: number): boolean => {
      try { process.kill(pid, 0); return true; }
      catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM"; }
    };
    await waitUntil(() => !isAlive(supervisorPid));
    await new Promise((resolve) => setTimeout(resolve, 600));

    await expect(stat(workerReadyPath)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readFile(bodiesPath, "utf8")).toBe("");
    const restarted = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    expect((await restarted.load())?.refreshToken).toBe("old-refresh");
    expect((await readdir(configDir)).filter((name) => name.startsWith(".rotation-fd-probe.") || name.includes("mutation.lock") || name === "auth-cn.rotation.pending")).toEqual([]);
  });

  it("terminates capability supervisor and sync-block worker after parent SIGKILL, then safely recovers pre-network state", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-capability-parent-kill-"));
    const configDir = join(dir, "cfg");
    const readyPath = join(dir, "ready");
    const bodiesPath = join(dir, "bodies");
    const child = spawn(await testBunExecutable(), [
      join(process.cwd(), "tests/fixtures/preflight-capability-parent-kill-child.ts"),
      configDir,
      readyPath,
      bodiesPath,
    ], { stdio: "ignore" });
    await waitUntil(async () => { try { return (await readFile(readyPath, "utf8")).startsWith("capability-started\n"); } catch { return false; } });
    const readyLines = (await readFile(readyPath, "utf8")).trim().split("\n");
    const supervisorPid = Number(readyLines[2]);
    const workerPid = Number(readyLines[3]);
    const watchdogPid = Number(readyLines[4]);
    const executorPid = Number(readyLines[5]);
    expect([supervisorPid, workerPid, watchdogPid, executorPid].every((pid) => Number.isInteger(pid) && pid > 0)).toBe(true);
    child.kill("SIGKILL");
    await new Promise<void>((resolve) => child.once("exit", () => resolve()));
    const isAlive = (pid: number): boolean => {
      try { process.kill(pid, 0); return true; }
      catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM"; }
    };
    await waitUntil(() => [supervisorPid, workerPid, watchdogPid, executorPid].every((pid) => !isAlive(pid)));

    expect(await readFile(bodiesPath, "utf8")).toBe("");
    const restarted = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    expect((await restarted.load())?.refreshToken).toBe("old-refresh");
    expect((await readdir(configDir)).filter((name) => name.startsWith(".rotation-fd-probe.") || name.includes("mutation.lock") || name === "auth-cn.rotation.pending")).toEqual([]);
  });

  it.each([
    ["parent-first", 0],
    ["supervisor-first", 0],
    ["parent-first", 25],
    ["supervisor-first", 25],
  ] as const)("worker watchdog terminates sync-block work when parent and supervisor die (%s, delay=%dms)", async (order, delayMs) => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-capability-double-kill-"));
    const configDir = join(dir, "cfg");
    const readyPath = join(dir, "ready");
    const bodiesPath = join(dir, "bodies");
    const child = spawn(await testBunExecutable(), [
      join(process.cwd(), "tests/fixtures/preflight-capability-parent-kill-child.ts"),
      configDir,
      readyPath,
      bodiesPath,
    ], { stdio: "ignore" });
    await waitUntil(async () => { try { return (await readFile(readyPath, "utf8")).startsWith("capability-started\n"); } catch { return false; } });
    const readyLines = (await readFile(readyPath, "utf8")).trim().split("\n");
    const supervisorPid = Number(readyLines[2]);
    const workerPid = Number(readyLines[3]);
    const watchdogPid = Number(readyLines[4]);
    const executorPid = Number(readyLines[5]);
    expect([supervisorPid, workerPid, watchdogPid, executorPid].every((pid) => Number.isInteger(pid) && pid > 0)).toBe(true);
    const killAndWait = async (pid: number): Promise<void> => {
      try { process.kill(pid, "SIGKILL"); } catch { return; }
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    };
    const childExit = new Promise<void>((resolve) => child.once("exit", () => resolve()));
    if (order === "parent-first") {
      await killAndWait(child.pid!);
      await killAndWait(supervisorPid);
    } else {
      await killAndWait(supervisorPid);
      await killAndWait(child.pid!);
    }
    await childExit;
    const isAlive = (pid: number): boolean => {
      try { process.kill(pid, 0); return true; }
      catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM"; }
    };
    await waitUntil(() => [supervisorPid, workerPid, watchdogPid, executorPid].every((pid) => !isAlive(pid)));
    const { stdout: processPs } = await execFileAsyncForTest("ps", ["-o", "pid=,ppid=,state=,%cpu=", "-p", [workerPid, watchdogPid, executorPid].join(",")]).catch(() => ({ stdout: "" }));
    expect(processPs.trim()).toBe("");
    expect(await readFile(bodiesPath, "utf8")).toBe("");

    const restarted = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    expect((await restarted.load())?.refreshToken).toBe("old-refresh");
    expect((await readdir(configDir)).filter((name) => name.startsWith(".rotation-fd-probe.") || name.includes("mutation.lock") || name === "auth-cn.rotation.pending")).toEqual([]);
  });

  it("bounds a real supervisor spawn ENOENT and cleans reservation/probe state without network", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-capability-spawn-error-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_CONFIG_DIR: configDir, QODER_PROXY_CAPABILITY_TIMEOUT_MS: "100" };
    const baseStore = createConfigStore("machine-a", env);
    const expired = { ...testCredential("old-access", "old-refresh"), expiresAt: 0 };
    await baseStore.save(expired);
    const store = createConfigStore("machine-a", env, { capabilityExecutable: join(dir, "missing-bun") });
    const refreshBodies: string[] = [];
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") refreshBodies.push(String(init.body));
      return jsonResponse({ id: "unused" });
    }) as unknown as typeof fetch;

    await expect(AuthSession.preflight(env, undefined, { store, bridge: testBridge() })).rejects.toMatchObject({ code: "ENOENT" });
    expect(refreshBodies).toEqual([]);
    expect((await readdir(configDir)).filter((name) => name.startsWith(".rotation-fd-probe.") || name.includes("mutation.lock") || name === "auth-cn.rotation.pending")).toEqual([]);
    expect((await baseStore.load())?.refreshToken).toBe("old-refresh");
  });

  it.each([
    ["spawn-enoent", undefined, /watchdog|ENOENT|capability child/i],
    ["spawn-eagain", "spawn-eagain", /EAGAIN|injected watchdog spawn failure/i],
    ["spawn-emfile", "spawn-emfile", /EMFILE|injected watchdog spawn failure/i],
    ["error-only", "error-only", /EAGAIN|injected watchdog error/i],
    ["early-exit", "early-exit", /watchdog|capability child/i],
    ["ready-timeout", "ready-timeout", /watchdog|capability child|timed out/i],
    ["wrong-nonce", "wrong-nonce", /watchdog|capability child/i],
    ["wrong-identity", "wrong-identity", /watchdog|capability child/i],
  ] as const)("fails closed before native work when watchdog readiness fails: %s", async (_label, watchdogMode, expectedError) => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-watchdog-readiness-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_CONFIG_DIR: configDir, QODER_PROXY_CAPABILITY_TIMEOUT_MS: "5000" };
    const baseStore = createConfigStore("machine-a", env);
    const expired = { ...testCredential("old-access", "old-refresh"), expiresAt: 0 };
    await baseStore.save(expired);
    const store = createConfigStore("machine-a", env, {
      capabilityProbeMode: "sync-block",
      capabilityWatchdogExecutable: watchdogMode === undefined ? join(dir, "missing-watchdog") : undefined,
      capabilityWatchdogMode: watchdogMode,
    });
    const refreshBodies: string[] = [];
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") refreshBodies.push(String(init.body));
      return jsonResponse({ id: "unused" });
    }) as unknown as typeof fetch;

    await expect(AuthSession.preflight(env, undefined, { store, bridge: testBridge() })).rejects.toThrow(expectedError);
    await waitForCapabilityQuiescence(configDir);
    expect(refreshBodies).toEqual([]);
    expect((await readdir(configDir)).filter((name) => name.startsWith(".rotation-fd-probe.") || name.includes("mutation.lock") || name === "auth-cn.rotation.pending")).toEqual([]);
    expect((await baseStore.load())?.refreshToken).toBe("old-refresh");
  });

  it.each(["post-ready-exit", "post-ready-error", "post-ready-close", "post-ready-sigterm"] as const)("terminates native executor when watchdog disappears after ready: %s", async (watchdogMode) => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-watchdog-runtime-loss-"));
    const configDir = join(dir, "cfg");
    const readyPath = join(dir, "ready");
    const env = { QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_CONFIG_DIR: configDir, QODER_PROXY_CAPABILITY_TIMEOUT_MS: "1000" };
    const baseStore = createConfigStore("machine-a", env);
    const expired = { ...testCredential("old-access", "old-refresh"), expiresAt: 0 };
    await baseStore.save(expired);
    const store = createConfigStore("machine-a", env, { capabilityProbeMode: "sync-block", capabilityProbeReadyPath: readyPath, capabilityWatchdogMode: watchdogMode });
    const refreshBodies: string[] = [];
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") refreshBodies.push(String(init.body));
      return jsonResponse({ id: "unused" });
    }) as unknown as typeof fetch;

    await expect(AuthSession.preflight(env, undefined, { store, bridge: testBridge() })).rejects.toThrow(/watchdog|capability child/i);
    const readyLines = (await readFile(readyPath, "utf8")).trim().split("\n");
    const pids = readyLines.slice(2).map(Number).filter((pid) => Number.isInteger(pid) && pid > 0);
    const isAlive = (pid: number): boolean => { try { process.kill(pid, 0); return true; } catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM"; } };
    await waitUntil(() => pids.every((pid) => !isAlive(pid)));
    expect(refreshBodies).toEqual([]);
    expect((await readdir(configDir)).filter((name) => name.startsWith(".rotation-fd-probe.") || name.includes("mutation.lock") || name === "auth-cn.rotation.pending")).toEqual([]);
    expect((await baseStore.load())?.refreshToken).toBe("old-refresh");
  });

  it("fails closed and removes every isolated process when the attested watchdog is SIGKILLed after native work starts", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-watchdog-runtime-sigkill-"));
    const configDir = join(dir, "cfg");
    const readyPath = join(dir, "ready");
    const env = { QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_CONFIG_DIR: configDir, QODER_PROXY_CAPABILITY_TIMEOUT_MS: "1000" };
    const baseStore = createConfigStore("machine-a", env);
    const expired = { ...testCredential("old-access", "old-refresh"), expiresAt: 0 };
    await baseStore.save(expired);
    const store = createConfigStore("machine-a", env, { capabilityProbeMode: "sync-block", capabilityProbeReadyPath: readyPath });
    const refreshBodies: string[] = [];
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") refreshBodies.push(String(init.body));
      return jsonResponse({ id: "unused" });
    }) as unknown as typeof fetch;
    const preflight = AuthSession.preflight(env, undefined, { store, bridge: testBridge() });
    await waitUntil(async () => { try { return (await readFile(readyPath, "utf8")).startsWith("capability-started\n"); } catch { return false; } });
    const pids = (await readFile(readyPath, "utf8")).trim().split("\n").slice(2).map(Number);
    const [supervisorPid, workerPid, watchdogPid, executorPid] = pids;
    process.kill(watchdogPid!, "SIGKILL");

    await expect(preflight).rejects.toThrow(/watchdog|capability child/i);
    const isAlive = (pid: number): boolean => { try { process.kill(pid, 0); return true; } catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM"; } };
    await waitUntil(() => pids.every((pid) => !isAlive(pid)));
    const { stdout } = await execFileAsyncForTest("ps", ["-o", "pid=,ppid=,state=,%cpu=", "-p", [supervisorPid, workerPid, watchdogPid, executorPid].join(",")]).catch(() => ({ stdout: "" }));
    expect(stdout.trim()).toBe("");
    expect(refreshBodies).toEqual([]);
    expect((await readdir(configDir)).filter((name) => name.startsWith(".rotation-fd-probe.") || name.includes("mutation.lock") || name === "auth-cn.rotation.pending")).toEqual([]);
    expect((await baseStore.load())?.refreshToken).toBe("old-refresh");
  });

  it.each(["identity-transient", "identity-permanent"] as const)("keeps watchdog ownership on identity lookup %s and still kills worker after owner death", async (watchdogMode) => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-watchdog-identity-"));
    const configDir = join(dir, "cfg");
    const readyPath = join(dir, "ready");
    const env = { QODER_PROXY_CONFIG_DIR: configDir, QODER_PROXY_CAPABILITY_TIMEOUT_MS: "5000" };
    const baseStore = createConfigStore("machine-a", env);
    const base = testCredential("old-access", "old-refresh");
    await baseStore.save(base);
    const store = createConfigStore("machine-a", env, { capabilityProbeMode: "sync-block", capabilityProbeReadyPath: readyPath, capabilityWatchdogMode: watchdogMode });
    const reservation = store.reserveRotation(base);
    await waitUntil(async () => { try { return (await readFile(readyPath, "utf8")).startsWith("capability-started\n"); } catch { return false; } });
    const readyLines = (await readFile(readyPath, "utf8")).trim().split("\n");
    const supervisorPid = Number(readyLines[2]);
    const workerPid = Number(readyLines[3]);
    const watchdogPid = Number(readyLines[4]);
    const executorPid = Number(readyLines[5]);
    try { process.kill(supervisorPid, "SIGKILL"); } catch {}
    const isAlive = (pid: number): boolean => { try { process.kill(pid, 0); return true; } catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM"; } };
    await waitUntil(() => [workerPid, watchdogPid, executorPid].every((pid) => !isAlive(pid)));
    await reservation.catch(() => undefined);
  });

  it.each(["error-only", "kill-false-no-close", "exit-without-close"] as const)("bounds injected capability child lifecycle %s and cleans all pre-network state", async (mode) => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-capability-terminal-state-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_CONFIG_DIR: configDir, QODER_PROXY_CAPABILITY_TIMEOUT_MS: "15" };
    const baseStore = createConfigStore("machine-a", env);
    const expired = { ...testCredential("old-access", "old-refresh"), expiresAt: 0 };
    await baseStore.save(expired);
    const fake = new EventEmitter() as ChildProcess;
    Object.assign(fake, {
      pid: undefined,
      stdout: new PassThrough(),
      stderr: null,
      stdin: null,
      stdio: [null, null, null, null, null],
      connected: false,
      exitCode: null,
      signalCode: null,
      killed: false,
      kill: vi.fn(() => false),
    });
    const store = createConfigStore("machine-a", env, {
      spawnCapabilityProcess: (() => {
        queueMicrotask(() => {
          if (mode === "error-only") fake.emit("error", Object.assign(new Error("spawn resource exhausted"), { code: "EAGAIN" }));
          if (mode === "exit-without-close") fake.emit("exit", 1, null);
        });
        return fake;
      }) as typeof spawn,
    });
    const refreshBodies: string[] = [];
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") refreshBodies.push(String(init.body));
      return jsonResponse({ id: "unused" });
    }) as unknown as typeof fetch;

    await expect(AuthSession.preflight(env, undefined, { store, bridge: testBridge() })).rejects.toThrow(mode === "error-only" ? /spawn resource exhausted/ : /timed out|Timeout|aborted/i);
    expect(refreshBodies).toEqual([]);
    expect((await readdir(configDir)).filter((name) => name.startsWith(".rotation-fd-probe.") || name.includes("mutation.lock") || name === "auth-cn.rotation.pending")).toEqual([]);
    expect((await baseStore.load())?.refreshToken).toBe("old-refresh");
  });

  it("handles a real pre-bind SIGTERM during a hanging capability probe without network or stale probe state", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-capability-sigterm-child-"));
    const configDir = join(dir, "cfg");
    const readyPath = join(dir, "ready");
    const bodiesPath = join(dir, "bodies");
    const resultPath = join(dir, "result");
    const child = spawn(await testBunExecutable(), [
      join(process.cwd(), "tests/fixtures/preflight-capability-sigterm-child.ts"),
      configDir,
      readyPath,
      bodiesPath,
      resultPath,
    ], { stdio: "ignore" });
    await waitUntil(async () => { try { return (await readFile(readyPath, "utf8")).startsWith("capability-started\n"); } catch { return false; } });
    child.kill("SIGTERM");
    const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => child.once("exit", (code, signal) => resolve({ code, signal })));
    expect(exit).toEqual({ code: 0, signal: null });
    const result = JSON.parse(await readFile(resultPath, "utf8")) as { error: string; refreshToken?: string };
    expect(result.error).toMatch(/SIGTERM during capability probe/);
    expect(result.refreshToken).toBe("old-refresh");
    expect(await readFile(bodiesPath, "utf8")).toBe("");
    expect((await readdir(configDir)).filter((name) => name.startsWith(".rotation-fd-probe.") || name === "auth-cn.rotation.pending")).toEqual([]);
  });

  it.each(["late-success", "late-reject"] as const)("kills an isolated %s child before cleanup so namespace recreation cannot be touched late", async (probeMode) => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-capability-late-child-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_PROXY_CONFIG_DIR: configDir, QODER_PROXY_CAPABILITY_TIMEOUT_MS: "15" };
    const baseStore = createConfigStore("machine-a", env);
    const base = testCredential("old-access", "old-refresh");
    await baseStore.save(base);
    const isolated = createConfigStore("machine-a", env, { capabilityProbeMode: probeMode });

    await expect(isolated.reserveRotation(base)).rejects.toThrow(/timed out|Timeout|aborted/i);
    expect((await readdir(configDir)).filter((name) => name.startsWith(".rotation-fd-probe.") || name.includes("mutation.lock") || name === "auth-cn.rotation.pending")).toEqual([]);
    const recreated = join(configDir, ".rotation-fd-probe.recreated");
    await mkdir(recreated, { mode: 0o700 });
    await writeFile(join(recreated, "sentinel"), "untouched\n", { mode: 0o600 });
    const handle = await open(join(configDir, "fd-reuse-sentinel"), "w", 0o600);
    await handle.writeFile("fd reuse safe\n", "utf8");
    await handle.close();
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(await readFile(join(recreated, "sentinel"), "utf8")).toBe("untouched\n");
    expect(await readFile(join(configDir, "fd-reuse-sentinel"), "utf8")).toBe("fd reuse safe\n");
    expect((await readdir(recreated)).sort()).toEqual(["sentinel"]);
    expect((await baseStore.load())?.refreshToken).toBe("old-refresh");
  });

  it("normalizes a native-child errno-only unsupported result before refresh", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-native-errno-unsupported-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_CONFIG_DIR: configDir };
    const baseStore = createConfigStore("machine-a", env);
    await baseStore.save({ ...testCredential("old-access", "old-refresh"), expiresAt: 0 });
    const unsupportedStore = createConfigStore("machine-a", env, { capabilityProbeMode: "unsupported-native" });
    const refreshBodies: string[] = [];
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") refreshBodies.push(String(init.body));
      return jsonResponse({ id: "unused" });
    }) as unknown as typeof fetch;

    await expect(AuthSession.preflight(env, undefined, { store: unsupportedStore, bridge: testBridge() })).rejects.toThrow(/不支持安全 fd-bound.*refresh 前/);
    expect(refreshBodies).toEqual([]);
  });

  it("rejects unsupported fd-bound publication before the refresh endpoint is called", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-unsupported-fs-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_CN_MACHINE_ID: "machine-a", QODER_PROXY_CONFIG_DIR: configDir };
    const baseStore = createConfigStore("machine-a", env);
    await baseStore.save({ ...testCredential("old-access", "old-refresh"), expiresAt: 0 });
    const unsupportedStore = createConfigStore("machine-a", env, { capabilityProbeMode: "unsupported" });
    const refreshBodies: string[] = [];
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") refreshBodies.push(String(init.body));
      return jsonResponse({ id: "unused" });
    }) as unknown as typeof fetch;

    await expect(AuthSession.preflight(env, undefined, { store: unsupportedStore, bridge: testBridge() })).rejects.toThrow(/不支持安全 fd-bound.*refresh 前/);
    expect(refreshBodies).toEqual([]);
    expect((await baseStore.load())?.refreshToken).toBe("old-refresh");
  });

  it("rejects multiple matching orphan temps before publishing or mutating any evidence", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-multiple-orphan-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_PROXY_CONFIG_DIR: configDir };
    const store = createConfigStore("machine-a", env);
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    await store.save(base);
    const owner = await store.reserveRotation(base);
    const readyPath = join(dir, "ready");
    const child = spawn(await testBunExecutable(), [
      join(process.cwd(), "tests/fixtures/rotation-publish-child.ts"),
      configDir,
      owner,
      JSON.stringify(target),
      "before-publish",
      readyPath,
    ], { stdio: "ignore" });
    await waitUntil(async () => {
      try { return (await readFile(readyPath, "utf8")).trim() === "before-publish"; }
      catch { return false; }
    });
    child.kill("SIGKILL");
    await new Promise<void>((resolve) => child.once("exit", () => resolve()));
    const firstTemp = (await readdir(configDir)).find((name) => name.includes("rotation.emergency") && name.endsWith(".tmp"));
    if (!firstTemp) throw new Error("missing first orphan");
    const firstPath = join(configDir, firstTemp);
    const firstRecord = JSON.parse(await readFile(firstPath, "utf8")) as Record<string, unknown>;
    const secondArtifact = "22222222-2222-4222-8222-222222222222";
    const secondRecord = { ...firstRecord, artifactId: secondArtifact };
    const secondPath = join(configDir, `.auth-cn.rotation.emergency.json.${process.pid}.${secondArtifact}.tmp`);
    await writeFile(secondPath, `${JSON.stringify(secondRecord)}\n`, { mode: 0o600 });
    await chmod(secondPath, 0o600);
    const before = new Map(await Promise.all([firstPath, secondPath].map(async (path) => [path, await readFile(path, "utf8")] as const)));

    await expect(store.stageEmergencyRotation!(target, owner)).rejects.toThrow(/多个匹配.*孤立/);
    await expect(stat(join(configDir, "auth-cn.rotation.emergency.json"))).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readFile(firstPath, "utf8")).toBe(before.get(firstPath));
    expect(await readFile(secondPath, "utf8")).toBe(before.get(secondPath));
  });

  it("rejects orphan source replacement between validation and publication", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-orphan-swap-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_PROXY_CONFIG_DIR: configDir };
    const store = createConfigStore("machine-a", env);
    const base = testCredential("old-access", "old-refresh");
    const targetA = testCredential("access-a", "refresh-a");
    const targetB = testCredential("access-b", "refresh-b");
    await store.save(base);
    const owner = await store.reserveRotation(base);
    const readyPath = join(dir, "ready");
    const child = spawn(await testBunExecutable(), [
      join(process.cwd(), "tests/fixtures/rotation-publish-child.ts"),
      configDir,
      owner,
      JSON.stringify(targetA),
      "before-publish",
      readyPath,
    ], { stdio: "ignore" });
    await waitUntil(async () => {
      try { return (await readFile(readyPath, "utf8")).trim() === "before-publish"; }
      catch { return false; }
    });
    child.kill("SIGKILL");
    await new Promise<void>((resolve) => child.once("exit", () => resolve()));
    const originalName = (await readdir(configDir)).find((name) => name.includes("rotation.emergency") && name.endsWith(".tmp"));
    if (!originalName) throw new Error("missing orphan A");
    const originalPath = join(configDir, originalName);
    const originalRecord = JSON.parse(await readFile(originalPath, "utf8")) as Record<string, unknown>;
    const replacementRecord = { ...originalRecord, credential: targetB, targetCredentialHash: sha256(JSON.stringify([
      targetB.version, targetB.site, targetB.machineIdHash, targetB.token, targetB.refreshToken ?? null,
      targetB.expiresAt ?? null, targetB.refreshTokenExpiresAt ?? null, targetB.userId ?? null, targetB.userName ?? null,
    ])) };
    const swapStore = createConfigStore("machine-a", env, {
      beforeOrphanPromotionLink: async (source) => {
        const moved = join(dir, "validated-orphan-a");
        await rename(source, moved);
        await writeFile(source, `${JSON.stringify(replacementRecord)}\n`, { mode: 0o600 });
        await chmod(source, 0o600);
      },
    });

    await expect(swapStore.stageEmergencyRotation!(targetA, owner)).rejects.toThrow(/发布前发生替换/);
    await expect(stat(join(configDir, "auth-cn.rotation.emergency.json"))).rejects.toMatchObject({ code: "ENOENT" });
    expect((JSON.parse(await readFile(originalPath, "utf8")) as { credential: StoredCredential }).credential.refreshToken).toBe("refresh-b");
  });

  it("resumes a claim left after no-replace acquisition before source detach", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-acquired-claim-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_PROXY_CONFIG_DIR: configDir };
    const store = createConfigStore("machine-a", env);
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    await store.save(base);
    const owner = await store.reserveRotation(base);
    const readyPath = join(dir, "ready");
    const child = spawn(await testBunExecutable(), [
      join(process.cwd(), "tests/fixtures/rotation-publish-child.ts"),
      configDir,
      owner,
      JSON.stringify(target),
      "before-publish",
      readyPath,
    ], { stdio: "ignore" });
    await waitUntil(async () => {
      try { return (await readFile(readyPath, "utf8")).trim() === "before-publish"; }
      catch { return false; }
    });
    child.kill("SIGKILL");
    await new Promise<void>((resolve) => child.once("exit", () => resolve()));
    const crashing = createConfigStore("machine-a", env, {
      afterOrphanClaimAcquire: () => { throw new Error("crash after claim acquire"); },
    });
    await expect(crashing.stageEmergencyRotation!(target, owner)).rejects.toThrow(/claim acquire/);
    const orphanNames = (await readdir(configDir)).filter((name) => name.endsWith(".tmp") || name.endsWith(".claim"));
    expect(orphanNames).toHaveLength(2);
    const orphanStats = await Promise.all(orphanNames.map((name) => stat(join(configDir, name))));
    expect(orphanStats.every((entry) => entry.nlink === 2)).toBe(true);
    expect(new Set(orphanStats.map((entry) => `${entry.dev}:${entry.ino}`)).size).toBe(1);

    await store.stageEmergencyRotation!(target, owner);
    await store.save(target, owner);
    expect((await store.load())?.refreshToken).toBe("new-refresh");
    expect((await readdir(configDir)).filter((name) => name.endsWith(".claim") || name.endsWith(".tmp"))).toEqual([]);
  });

  it("recovers and cleans a claim left after fd-bound publication", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-published-claim-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_PROXY_CONFIG_DIR: configDir };
    const store = createConfigStore("machine-a", env);
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    await store.save(base);
    const owner = await store.reserveRotation(base);
    const readyPath = join(dir, "ready");
    const child = spawn(await testBunExecutable(), [
      join(process.cwd(), "tests/fixtures/rotation-publish-child.ts"),
      configDir,
      owner,
      JSON.stringify(target),
      "before-publish",
      readyPath,
    ], { stdio: "ignore" });
    await waitUntil(async () => {
      try { return (await readFile(readyPath, "utf8")).trim() === "before-publish"; }
      catch { return false; }
    });
    child.kill("SIGKILL");
    await new Promise<void>((resolve) => child.once("exit", () => resolve()));
    const crashing = createConfigStore("machine-a", env, {
      afterOrphanPromotionPublish: () => { throw new Error("crash after fd publish"); },
    });
    await expect(crashing.stageEmergencyRotation!(target, owner)).rejects.toThrow(/fd publish/);
    expect((await readdir(configDir)).some((name) => name.endsWith(".claim"))).toBe(true);
    await store.clearRotationReservation(owner);

    expect((await store.load())?.refreshToken).toBe("new-refresh");
    expect((await readdir(configDir)).filter((name) => name.endsWith(".claim") || name.endsWith(".tmp"))).toEqual([]);
  });

  it("loads legacy structured journals without artifactId", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-legacy-journal-"));
    const configDir = join(dir, "cfg");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    await store.save(base);
    const owner = await store.reserveRotation(base);
    await store.stageRotation(target, owner);
    const journalPath = join(configDir, "auth-cn.rotation.json");
    const legacy = JSON.parse(await readFile(journalPath, "utf8")) as Record<string, unknown>;
    delete legacy.artifactId;
    await writeFile(journalPath, `${JSON.stringify(legacy)}\n`, { mode: 0o600 });
    await chmod(journalPath, 0o600);
    await store.clearRotationReservation(owner);

    expect((await store.load())?.refreshToken).toBe("new-refresh");
    await expect(stat(journalPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("fails closed when only an untrusted strict-name orphan temp remains", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-orphan-temp-"));
    const configDir = join(dir, "cfg");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    await store.save(testCredential("old-access", "old-refresh"));
    const orphanPath = join(configDir, ".auth-cn.rotation.emergency.json.99999.11111111-1111-4111-8111-111111111111.tmp");
    await writeFile(orphanPath, "{\"credential\":\"secret\"}\n", { mode: 0o600 });

    await expect(store.load()).rejects.toThrow(/未受信任.*rotation temp/);
    await expect(store.save(testCredential("replacement", "replacement-refresh"))).rejects.toThrow(/未受信任.*rotation temp/);
    await expect(store.reserveRotation(testCredential("old-access", "old-refresh"))).rejects.toThrow(/journal\/temp|待恢复/);
    await expect(store.delete()).rejects.toThrow(/未受信任.*rotation temp|无对应可信 journal/);
    expect(await readFile(orphanPath, "utf8")).toContain("secret");
  });

  it("cleans trusted credential temps during explicit owner delete", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-emergency-delete-temp-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_PROXY_CONFIG_DIR: configDir };
    const baseStore = createConfigStore("machine-a", env);
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    await baseStore.save(base);
    const owner = await baseStore.reserveRotation(base);
    const failingStore = createConfigStore("machine-a", env, {
      onRotationPublishPhase: (phase) => { if (phase === "after-publish") throw new Error("post-publish failure"); },
    });
    await expect(failingStore.stageEmergencyRotation!(target, owner)).rejects.toThrow(/post-publish/);
    expect((await readdir(configDir)).filter((name) => name.includes(".tmp"))).toHaveLength(1);

    await baseStore.delete(owner);
    expect((await readdir(configDir)).filter((name) => name.includes(".tmp"))).toEqual([]);
    expect(await baseStore.load()).toBeUndefined();
  });

  it.each([
    ["malformed", "{\"version\":1", 0o600],
    ["permissive", "copy", 0o644],
    ["mismatched", "copy", 0o600],
  ] as const)("fails closed on a %s internal-looking credential temp without deleting it", async (kind, contentMode, mode) => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-malicious-temp-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_PROXY_CONFIG_DIR: configDir };
    const baseStore = createConfigStore("machine-a", env);
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    await baseStore.save(base);
    const owner = await baseStore.reserveRotation(base);
    await baseStore.stageEmergencyRotation!(target, owner);
    const emergencyPath = join(configDir, "auth-cn.rotation.emergency.json");
    const journal = JSON.parse(await readFile(emergencyPath, "utf8")) as Record<string, unknown>;
    const artifactId = kind === "mismatched" ? "11111111-1111-4111-8111-111111111111" : String(journal.artifactId);
    const maliciousPath = join(configDir, `.auth-cn.rotation.emergency.json.99999.${artifactId}.tmp`);
    const content = contentMode === "copy" ? await readFile(emergencyPath, "utf8") : contentMode;
    await writeFile(maliciousPath, content, { mode });
    await chmod(maliciousPath, mode);
    await baseStore.clearRotationReservation(owner);

    await expect(baseStore.load()).rejects.toThrow(/rotation temp|0600|不匹配|hard-link|JSON Parse/);
    expect(await readFile(maliciousPath, "utf8")).toBe(content);
    expect((await stat(emergencyPath)).mode & 0o777).toBe(0o600);
  });

  it("retries trusted temp cleanup after an injected unlink failure", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-temp-cleanup-retry-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_PROXY_CONFIG_DIR: configDir };
    const baseStore = createConfigStore("machine-a", env);
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    await baseStore.save(base);
    const owner = await baseStore.reserveRotation(base);
    const publishingStore = createConfigStore("machine-a", env, {
      onRotationPublishPhase: (phase) => { if (phase === "after-publish") throw new Error("leave trusted temp"); },
    });
    await expect(publishingStore.stageEmergencyRotation!(target, owner)).rejects.toThrow(/trusted temp/);
    await baseStore.clearRotationReservation(owner);
    let cleanupAttempts = 0;
    const failingCleanupStore = createConfigStore("machine-a", env, {
      beforeRotationTempCleanup: () => { cleanupAttempts++; throw new Error("temp unlink denied"); },
    });

    await expect(failingCleanupStore.load()).rejects.toThrow(/temp unlink denied/);
    expect(cleanupAttempts).toBe(1);
    expect((await readdir(configDir)).filter((name) => name.includes(".tmp"))).toHaveLength(1);
    expect((await stat(join(configDir, "auth-cn.rotation.emergency.json"))).mode & 0o777).toBe(0o600);

    expect((await baseStore.load())?.refreshToken).toBe("new-refresh");
    expect((await readdir(configDir)).filter((name) => name.includes(".tmp"))).toEqual([]);
  });

  it("fails closed on an internal-looking hard-link substitution and preserves the decoy", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-hardlink-temp-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_PROXY_CONFIG_DIR: configDir };
    const baseStore = createConfigStore("machine-a", env);
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    await baseStore.save(base);
    const owner = await baseStore.reserveRotation(base);
    await baseStore.stageEmergencyRotation!(target, owner);
    const emergencyPath = join(configDir, "auth-cn.rotation.emergency.json");
    const journal = JSON.parse(await readFile(emergencyPath, "utf8")) as { artifactId: string };
    const decoy = join(dir, "decoy-hardlink");
    await writeFile(decoy, await readFile(emergencyPath, "utf8"), { mode: 0o600 });
    const tempPath = join(configDir, `.auth-cn.rotation.emergency.json.99999.${journal.artifactId}.tmp`);
    await link(decoy, tempPath);
    await baseStore.clearRotationReservation(owner);

    await expect(baseStore.load()).rejects.toThrow(/hard link|hard-link|publication artifact/);
    expect((await stat(decoy)).nlink).toBe(2);
    expect((await stat(emergencyPath)).mode & 0o777).toBe(0o600);
  });

  it("fails closed on an internal-looking symlink temp and preserves its target", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-symlink-temp-"));
    const configDir = join(dir, "cfg");
    const env = { QODER_PROXY_CONFIG_DIR: configDir };
    const baseStore = createConfigStore("machine-a", env);
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    await baseStore.save(base);
    const owner = await baseStore.reserveRotation(base);
    await baseStore.stageEmergencyRotation!(target, owner);
    const emergencyPath = join(configDir, "auth-cn.rotation.emergency.json");
    const journal = JSON.parse(await readFile(emergencyPath, "utf8")) as { artifactId: string };
    const decoy = join(dir, "decoy-temp");
    await writeFile(decoy, "do-not-delete", { mode: 0o600 });
    const tempPath = join(configDir, `.auth-cn.rotation.emergency.json.99999.${journal.artifactId}.tmp`);
    await symlink(decoy, tempPath);
    await baseStore.clearRotationReservation(owner);

    await expect(baseStore.load()).rejects.toThrow(/rotation temp.*符号链接/);
    expect(await readFile(decoy, "utf8")).toBe("do-not-delete");
    expect((await stat(emergencyPath)).mode & 0o777).toBe(0o600);
  });

  it("allows only one concurrent different-target emergency winner and preserves winning bytes", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-emergency-race-"));
    const configDir = join(dir, "cfg");
    const first = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const second = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const base = testCredential("old-access", "old-refresh");
    const targetA = testCredential("access-a", "refresh-a");
    const targetB = testCredential("access-b", "refresh-b");
    await first.save(base);
    const owner = await first.reserveRotation(base);

    for (let iteration = 0; iteration < 50; iteration++) {
      if (iteration > 0) {
        await first.save(base, owner).catch(() => undefined);
        const freshBase = await first.load();
        if (!freshBase) throw new Error("missing base");
        await first.save(base);
      }
      const activeOwner = iteration === 0 ? owner : await first.reserveRotation(base);
      let release!: () => void;
      const barrier = new Promise<void>((resolve) => { release = resolve; });
      const attemptA = (async () => { await barrier; return first.stageEmergencyRotation!(targetA, activeOwner); })();
      const attemptB = (async () => { await barrier; return second.stageEmergencyRotation!(targetB, activeOwner); })();
      release();
      const results = await Promise.allSettled([attemptA, attemptB]);
      expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
      expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
      const emergencyPath = join(configDir, "auth-cn.rotation.emergency.json");
      const winningBytes = await readFile(emergencyPath, "utf8");
      const winning = JSON.parse(winningBytes) as { credential: StoredCredential };
      expect(["refresh-a", "refresh-b"]).toContain(winning.credential.refreshToken);
      await expect(first.stageEmergencyRotation!(winning.credential.refreshToken === "refresh-a" ? targetB : targetA, activeOwner)).rejects.toThrow(/不一致/);
      expect(await readFile(emergencyPath, "utf8")).toBe(winningBytes);
      await first.save(winning.credential, activeOwner);
      if (iteration < 49) await first.save(base);
    }
  });

  it("applies emergency recovery only for current base, cleans current target, and rejects stale or missing config", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-emergency-recovery-cas-"));
    const configDir = join(dir, "cfg");
    const configPath = join(configDir, "auth-cn.json");
    const reservationPath = join(configDir, "auth-cn.rotation.pending");
    const emergencyPath = join(configDir, "auth-cn.rotation.emergency.json");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    const newer = testCredential("newer-access", "newer-refresh");

    await store.save(base);
    let owner = await store.reserveRotation(base);
    await store.stageEmergencyRotation!(target, owner);
    await store.clearRotationReservation(owner);
    expect((await store.load())?.refreshToken).toBe("new-refresh");
    await expect(stat(emergencyPath)).rejects.toMatchObject({ code: "ENOENT" });

    await store.save(base);
    owner = await store.reserveRotation(base);
    await store.stageEmergencyRotation!(target, owner);
    await writeFile(configPath, `${JSON.stringify(target)}\n`, { mode: 0o600 });
    await chmod(configPath, 0o600);
    await store.clearRotationReservation(owner);
    const targetBytes = await readFile(configPath, "utf8");
    expect((await store.load())?.refreshToken).toBe("new-refresh");
    expect(await readFile(configPath, "utf8")).toBe(targetBytes);

    await store.save(base);
    owner = await store.reserveRotation(base);
    await store.stageEmergencyRotation!(target, owner);
    await writeFile(configPath, `${JSON.stringify(newer)}\n`, { mode: 0o600 });
    await chmod(configPath, 0o600);
    await store.clearRotationReservation(owner);
    await expect(store.load()).rejects.toThrow(/已变化|拒绝.*回滚/);
    expect((JSON.parse(await readFile(configPath, "utf8")) as StoredCredential).refreshToken).toBe("newer-refresh");
    expect((await stat(emergencyPath)).mode & 0o777).toBe(0o600);

    await writeFile(configPath, `${JSON.stringify(base)}\n`, { mode: 0o600 });
    await chmod(configPath, 0o600);
    expect((await store.load())?.refreshToken).toBe("new-refresh");

    await store.save(base);
    owner = await store.reserveRotation(base);
    await store.stageEmergencyRotation!(target, owner);
    await store.clearRotationReservation(owner);
    await rm(configPath);
    await expect(store.load()).rejects.toThrow(/config 缺失/);
    expect((await stat(emergencyPath)).mode & 0o777).toBe(0o600);
    await expect(stat(reservationPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("uses structured primary journals and applies the same base/target recovery CAS", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-primary-recovery-cas-"));
    const configDir = join(dir, "cfg");
    const configPath = join(configDir, "auth-cn.json");
    const journalPath = join(configDir, "auth-cn.rotation.json");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    const newer = testCredential("newer-access", "newer-refresh");

    await store.save(base);
    let owner = await store.reserveRotation(base);
    await store.stageRotation(target, owner);
    const structured = JSON.parse(await readFile(journalPath, "utf8")) as { owner: string; baseCredentialHash: string; targetCredentialHash: string; credential: StoredCredential };
    expect(structured.owner).toBe(owner);
    expect(structured.baseCredentialHash).toHaveLength(64);
    expect(structured.targetCredentialHash).toHaveLength(64);
    expect(structured.credential.refreshToken).toBe("new-refresh");
    expect((await stat(journalPath)).mode & 0o777).toBe(0o600);
    await store.clearRotationReservation(owner);
    expect((await store.load())?.refreshToken).toBe("new-refresh");

    await store.save(base);
    owner = await store.reserveRotation(base);
    await store.stageRotation(target, owner);
    await writeFile(configPath, `${JSON.stringify(target)}\n`, { mode: 0o600 });
    await chmod(configPath, 0o600);
    await store.clearRotationReservation(owner);
    const committedBytes = await readFile(configPath, "utf8");
    expect((await store.load())?.refreshToken).toBe("new-refresh");
    expect(await readFile(configPath, "utf8")).toBe(committedBytes);

    await store.save(base);
    owner = await store.reserveRotation(base);
    await store.stageRotation(target, owner);
    await writeFile(configPath, `${JSON.stringify(newer)}\n`, { mode: 0o600 });
    await chmod(configPath, 0o600);
    await store.clearRotationReservation(owner);
    await expect(store.load()).rejects.toThrow(/已变化|拒绝.*回滚/);
    expect((JSON.parse(await readFile(configPath, "utf8")) as StoredCredential).refreshToken).toBe("newer-refresh");
    expect((await stat(journalPath)).mode & 0o777).toBe(0o600);

    await writeFile(configPath, `${JSON.stringify(base)}\n`, { mode: 0o600 });
    await chmod(configPath, 0o600);
    expect((await store.load())?.refreshToken).toBe("new-refresh");

    await store.save(base);
    owner = await store.reserveRotation(base);
    await store.stageRotation(target, owner);
    await store.clearRotationReservation(owner);
    await rm(configPath);
    await expect(store.load()).rejects.toThrow(/config 缺失/);
    expect((await stat(journalPath)).mode & 0o777).toBe(0o600);
  });

  it("preserves an orphan whose contents change before cleanup and does not clear its reservation", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-orphan-cleanup-content-race-"));
    const configDir = join(dir, "cfg");
    const configPath = join(configDir, "auth-cn.json");
    const reservationPath = join(configDir, "auth-cn.rotation.pending");
    const env = { QODER_PROXY_CONFIG_DIR: configDir };
    const baseStore = createConfigStore("machine-a", env);
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    await baseStore.save(base);
    const owner = await baseStore.reserveRotation(base);
    const readyPath = join(dir, "ready");
    const child = spawn(await testBunExecutable(), [join(process.cwd(), "tests/fixtures/rotation-publish-child.ts"), configDir, owner, JSON.stringify(target), "before-publish", readyPath], { stdio: "ignore" });
    await waitUntil(async () => { try { return (await readFile(readyPath, "utf8")).trim() === "before-publish"; } catch { return false; } });
    child.kill("SIGKILL");
    await new Promise<void>((resolve) => child.once("exit", () => resolve()));
    await writeFile(configPath, `${JSON.stringify(target)}\n`, { mode: 0o600 });
    await chmod(configPath, 0o600);
    const reservation = JSON.parse(await readFile(reservationPath, "utf8")) as Record<string, unknown>;
    await baseStore.clearRotationReservation(owner);
    reservation.processId = 99999999;
    reservation.processStartIdentity = "dead-owner";
    await writeFile(reservationPath, `${JSON.stringify(reservation)}\n`, { mode: 0o600 });
    await chmod(reservationPath, 0o600);
    let changedPath = "";
    const racingStore = createConfigStore("machine-a", env, {
      beforeRotationTempCleanup: async (path) => {
        changedPath = path;
        await writeFile(path, "{\"version\":1}\n", { mode: 0o600 });
        await chmod(path, 0o600);
      },
    });

    await expect(racingStore.load()).rejects.toThrow(/内容非法|发生替换/);
    expect(await readFile(changedPath, "utf8")).toBe("{\"version\":1}\n");
    expect((await stat(reservationPath)).mode & 0o777).toBe(0o600);
    expect((JSON.parse(await readFile(configPath, "utf8")) as StoredCredential).refreshToken).toBe("new-refresh");
  });

  it("rejects a journal that appears during recovery validation before config mutation", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-late-cross-journal-"));
    const configDir = join(dir, "cfg");
    const configPath = join(configDir, "auth-cn.json");
    const primaryPath = join(configDir, "auth-cn.rotation.json");
    const emergencyPath = join(configDir, "auth-cn.rotation.emergency.json");
    const env = { QODER_PROXY_CONFIG_DIR: configDir };
    const baseStore = createConfigStore("machine-a", env);
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    await baseStore.save(base);
    const owner = await baseStore.reserveRotation(base);
    const failingStore = createConfigStore("machine-a", env, { onRotationPublishPhase: (phase) => { if (phase === "after-publish") throw new Error("leave trusted primary temp"); } });
    await expect(failingStore.stageRotation(target, owner)).rejects.toThrow(/trusted primary temp/);
    const reservation = JSON.parse(await readFile(join(configDir, "auth-cn.rotation.pending"), "utf8")) as Record<string, unknown>;
    await baseStore.clearRotationReservation(owner);
    reservation.processId = 99999999;
    reservation.processStartIdentity = "dead-owner";
    await writeFile(join(configDir, "auth-cn.rotation.pending"), `${JSON.stringify(reservation)}\n`, { mode: 0o600 });
    await chmod(join(configDir, "auth-cn.rotation.pending"), 0o600);
    const configBytes = await readFile(configPath, "utf8");
    const primaryBytes = await readFile(primaryPath, "utf8");
    const primaryRecord = JSON.parse(primaryBytes) as Record<string, unknown>;
    let injected = false;
    const racingStore = createConfigStore("machine-a", env, {
      beforeRotationTempCleanup: async () => {
        if (injected) return;
        injected = true;
        const conflicting = { ...primaryRecord, artifactId: "33333333-3333-4333-8333-333333333333", targetCredentialHash: sha256("conflicting-target") };
        await writeFile(emergencyPath, `${JSON.stringify(conflicting)}\n`, { mode: 0o600 });
        await chmod(emergencyPath, 0o600);
      },
    });

    await expect(racingStore.load()).rejects.toThrow(/journal 集合.*发生变化|target hash/);
    expect(await readFile(configPath, "utf8")).toBe(configBytes);
    expect(await readFile(primaryPath, "utf8")).toBe(primaryBytes);
    expect((await stat(emergencyPath)).mode & 0o777).toBe(0o600);
  });

  it("rejects an unaccounted cross-journal claim before config or evidence mutation", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-cross-journal-evidence-"));
    const configDir = join(dir, "cfg");
    const configPath = join(configDir, "auth-cn.json");
    const primaryPath = join(configDir, "auth-cn.rotation.json");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    await store.save(base);
    const owner = await store.reserveRotation(base);
    await store.stageRotation(target, owner);
    const primary = JSON.parse(await readFile(primaryPath, "utf8")) as { artifactId: string };
    const ambiguousClaim = join(configDir, `.auth-cn.rotation.emergency.json.${primary.artifactId}.claim`);
    await writeFile(ambiguousClaim, await readFile(primaryPath, "utf8"), { mode: 0o600 });
    await chmod(ambiguousClaim, 0o600);
    await store.clearRotationReservation(owner);
    const configBytes = await readFile(configPath, "utf8");
    const primaryBytes = await readFile(primaryPath, "utf8");
    const claimBytes = await readFile(ambiguousClaim, "utf8");

    await expect(store.load()).rejects.toThrow(/无对应可信 journal|rotation recovery/);
    expect(await readFile(configPath, "utf8")).toBe(configBytes);
    expect(await readFile(primaryPath, "utf8")).toBe(primaryBytes);
    expect(await readFile(ambiguousClaim, "utf8")).toBe(claimBytes);
    const restarted = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    await expect(restarted.load()).rejects.toThrow(/无对应可信 journal|rotation recovery/);
    expect(await readFile(configPath, "utf8")).toBe(configBytes);
  });

  it("rejects conflicting primary and emergency records without changing either", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-journal-conflict-"));
    const configDir = join(dir, "cfg");
    const primaryPath = join(configDir, "auth-cn.rotation.json");
    const emergencyPath = join(configDir, "auth-cn.rotation.emergency.json");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const base = testCredential("old-access", "old-refresh");
    const targetA = testCredential("access-a", "refresh-a");
    const targetB = testCredential("access-b", "refresh-b");
    await store.save(base);
    const owner = await store.reserveRotation(base);
    await store.stageRotation(targetA, owner);
    const primary = JSON.parse(await readFile(primaryPath, "utf8")) as Record<string, unknown>;
    const conflicting = { ...primary, targetCredentialHash: sha256(JSON.stringify([
      targetB.version, targetB.site, targetB.machineIdHash, targetB.token, targetB.refreshToken ?? null,
      targetB.expiresAt ?? null, targetB.refreshTokenExpiresAt ?? null, targetB.userId ?? null, targetB.userName ?? null,
    ])), credential: targetB };
    await writeFile(emergencyPath, `${JSON.stringify(conflicting)}\n`, { mode: 0o600 });
    await chmod(emergencyPath, 0o600);
    await store.clearRotationReservation(owner);
    const primaryBytes = await readFile(primaryPath, "utf8");
    const emergencyBytes = await readFile(emergencyPath, "utf8");

    await expect(store.load()).rejects.toThrow(/journals 内容冲突/);
    expect(await readFile(primaryPath, "utf8")).toBe(primaryBytes);
    expect(await readFile(emergencyPath, "utf8")).toBe(emergencyBytes);
  });

  it("rejects delete with an unaccounted cross-journal claim before deleting any trusted evidence", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-delete-cross-journal-"));
    const configDir = join(dir, "cfg");
    const configPath = join(configDir, "auth-cn.json");
    const primaryPath = join(configDir, "auth-cn.rotation.json");
    const reservationPath = join(configDir, "auth-cn.rotation.pending");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const base = testCredential("old-access", "old-refresh");
    const target = testCredential("new-access", "new-refresh");
    await store.save(base);
    const owner = await store.reserveRotation(base);
    await store.stageRotation(target, owner);
    const primary = JSON.parse(await readFile(primaryPath, "utf8")) as { artifactId: string };
    const malformedClaim = join(configDir, `.auth-cn.rotation.emergency.json.${primary.artifactId}.claim`);
    await writeFile(malformedClaim, "{\"version\":1}\n", { mode: 0o600 });
    await chmod(malformedClaim, 0o600);
    const configBytes = await readFile(configPath, "utf8");
    const primaryBytes = await readFile(primaryPath, "utf8");
    const reservationBytes = await readFile(reservationPath, "utf8");

    await expect(store.delete(owner)).rejects.toThrow(/无对应可信 journal|rotation recovery/);
    expect(await readFile(configPath, "utf8")).toBe(configBytes);
    expect(await readFile(primaryPath, "utf8")).toBe(primaryBytes);
    expect(await readFile(reservationPath, "utf8")).toBe(reservationBytes);
    expect(await readFile(malformedClaim, "utf8")).toBe("{\"version\":1}\n");
  });

  it("rejects ownerless save and delete while a reservation or journal is active", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-test-"));
    const configDir = join(dir, "cfg");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const oldCredential = testCredential("old-access", "old-refresh");
    const newCredential = testCredential("new-access", "new-refresh");
    await store.save(oldCredential);
    const owner = await store.reserveRotation(oldCredential);

    await expect(store.save(newCredential)).rejects.toThrow(/无 owner save/);
    await expect(store.delete()).rejects.toThrow(/无 owner delete/);
    await store.stageRotation(newCredential, owner);
    await expect(store.save(newCredential)).rejects.toThrow(/无 owner save/);
    await expect(store.delete()).rejects.toThrow(/无 owner delete/);
    await expect(store.delete("foreign-owner")).rejects.toThrow(/owner 不匹配/);
    expect((await stat(join(configDir, "auth-cn.rotation.json"))).mode & 0o777).toBe(0o600);
    await store.save(newCredential, owner);
    expect((await store.load())?.refreshToken).toBe("new-refresh");
  });

  it("treats a reused PID with a different process-start identity as an abandoned owner", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-test-"));
    const configDir = join(dir, "cfg");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const oldCredential = testCredential("old-access", "old-refresh");
    const newCredential = testCredential("new-access", "new-refresh");
    await store.save(oldCredential);
    const owner = await store.reserveRotation(oldCredential);
    await store.stageRotation(newCredential, owner);
    const reservationPath = join(configDir, "auth-cn.rotation.pending");
    const reservation = JSON.parse(await readFile(reservationPath, "utf8")) as Record<string, unknown>;
    reservation.processStartIdentity = "reused-pid-different-start";
    await writeFile(reservationPath, `${JSON.stringify(reservation)}\n`, { mode: 0o600 });
    await chmod(reservationPath, 0o600);

    expect((await store.load())?.refreshToken).toBe("new-refresh");
    await expect(stat(reservationPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("recovers a staged rotation after its owner process is dead", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-test-"));
    const configDir = join(dir, "cfg");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const oldCredential = testCredential("old-access", "old-refresh");
    const newCredential = testCredential("new-access", "new-refresh");
    await store.save(oldCredential);
    const owner = await store.reserveRotation(oldCredential);
    await store.stageRotation(newCredential, owner);
    const reservationPath = join(configDir, "auth-cn.rotation.pending");
    const reservation = JSON.parse(await readFile(reservationPath, "utf8")) as Record<string, unknown>;
    reservation.processId = 2_147_483_647;
    reservation.processStartIdentity = "dead-owner";
    await writeFile(reservationPath, `${JSON.stringify(reservation)}\n`, { mode: 0o600 });
    await chmod(reservationPath, 0o600);

    expect((await store.load())?.refreshToken).toBe("new-refresh");
    expect((await store.load())?.refreshToken).toBe("new-refresh");
  });

  it("does not let another store consume a live owner's staged rotation", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-test-"));
    const configDir = join(dir, "cfg");
    const ownerStore = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const observerStore = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const oldCredential = testCredential("old-access", "old-refresh");
    const newCredential = testCredential("new-access", "new-refresh");
    await ownerStore.save(oldCredential);
    const owner = await ownerStore.reserveRotation(oldCredential);
    await ownerStore.stageRotation(newCredential, owner);

    await expect(observerStore.load()).rejects.toThrow(/owner 仍活跃/);
    await ownerStore.save(newCredential, owner);
    expect((await observerStore.load())?.refreshToken).toBe("new-refresh");
  });

  it("lets the owner finish cleanup when config and journal already equal the target", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-test-"));
    const configDir = join(dir, "cfg");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const oldCredential = testCredential("old-access", "old-refresh");
    const newCredential = testCredential("new-access", "new-refresh");
    await store.save(oldCredential);
    const owner = await store.reserveRotation(oldCredential);
    await store.stageRotation(newCredential, owner);
    // 模拟 config 已提交，但 journal 与 marker 尚未清理。
    await writeFile(join(configDir, "auth-cn.json"), `${JSON.stringify(newCredential)}\n`, { mode: 0o600 });
    await chmod(join(configDir, "auth-cn.json"), 0o600);

    await store.save(newCredential, owner);
    expect((await store.load())?.refreshToken).toBe("new-refresh");
    await expect(stat(join(configDir, "auth-cn.rotation.json"))).rejects.toMatchObject({ code: "ENOENT" });
    await expect(stat(join(configDir, "auth-cn.rotation.pending"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("recovers idempotently when config commit completed before reservation cleanup", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-test-"));
    const configDir = join(dir, "cfg");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const oldCredential = testCredential("old-access", "old-refresh");
    const newCredential = testCredential("new-access", "new-refresh");
    await store.save(oldCredential);
    const owner = await store.reserveRotation(oldCredential);
    // 模拟 config 已原子提交、journal 已删除，但进程在清 marker 前崩溃。
    await writeFile(join(configDir, "auth-cn.json"), `${JSON.stringify(newCredential)}\n`, { mode: 0o600 });
    await chmod(join(configDir, "auth-cn.json"), 0o600);
    await expect(stat(join(configDir, "auth-cn.rotation.json"))).rejects.toMatchObject({ code: "ENOENT" });

    await store.clearRotationReservation(owner);
    expect((await store.load())?.refreshToken).toBe("new-refresh");
    await expect(stat(join(configDir, "auth-cn.rotation.pending"))).rejects.toMatchObject({ code: "ENOENT" });
    expect((await store.load())?.refreshToken).toBe("new-refresh");
  });

  it("recovers an abandoned staged rotation and removes journal and reservation", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-test-"));
    const configDir = join(dir, "cfg");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    const oldCredential = testCredential("old-access", "old-refresh");
    await store.save(oldCredential);
    const owner = await store.reserveRotation(oldCredential);
    await store.stageRotation(testCredential("new-access", "new-refresh"), owner);
    const journalPath = join(configDir, "auth-cn.rotation.json");
    const reservationPath = join(configDir, "auth-cn.rotation.pending");
    expect((await stat(journalPath)).mode & 0o777).toBe(0o600);
    expect((await stat(reservationPath)).mode & 0o777).toBe(0o600);
    await expect(store.load()).rejects.toThrow(/owner 仍活跃/);
    // 模拟 owner 进程已退出；同 PID 的单元测试通过 owner-only clear 释放活性标记，但保留 journal。
    await store.clearRotationReservation(owner);
    expect((await store.load())?.refreshToken).toBe("new-refresh");
    expect((await store.load())?.refreshToken).toBe("new-refresh");
    await expect(stat(journalPath)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(stat(reservationPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rejects a symlink config directory for load, save, staging, and delete", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-test-"));
    const realDir = join(dir, "real-cfg");
    const linkDir = join(dir, "linked-cfg");
    const realStore = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: realDir });
    const oldCredential = testCredential("old-access", "old-refresh");
    await realStore.save(oldCredential);
    const owner = await realStore.reserveRotation(oldCredential);
    await realStore.stageRotation(testCredential("new-access", "new-refresh"), owner);
    await symlink(realDir, linkDir);
    const linkedStore = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: linkDir });
    await expect(linkedStore.load()).rejects.toThrow(/config 目录.*符号链接/);
    await expect(linkedStore.reserveRotation(testCredential("x", "y"))).rejects.toThrow(/config 目录.*符号链接/);
    await expect(linkedStore.save(testCredential("x", "y"))).rejects.toThrow(/config 目录.*符号链接/);
    await expect(linkedStore.stageRotation(testCredential("x", "y"), "owner")).rejects.toThrow(/config 目录.*符号链接/);
    await expect(linkedStore.delete()).rejects.toThrow(/config 目录.*符号链接/);
  });

  it("rejects an overly permissive config directory before credential reads", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-test-"));
    const configDir = join(dir, "cfg");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    await store.save(testCredential("old-access", "old-refresh"));
    await chmod(configDir, 0o777);
    await expect(store.load()).rejects.toThrow(/目录权限必须为 0700/);
    await expect(store.delete()).rejects.toThrow(/目录权限必须为 0700/);
  });

  it("rejects a symlink rotation journal", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-test-"));
    const configDir = join(dir, "cfg");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    await store.save(testCredential("old-access", "old-refresh"));
    const decoy = join(dir, "rotation-decoy.json");
    await writeFile(decoy, JSON.stringify(testCredential("new-access", "new-refresh")), "utf8");
    await symlink(decoy, join(configDir, "auth-cn.rotation.json"));
    await expect(store.load()).rejects.toThrow(/rotation journal.*符号链接/);
    await expect(store.reserveRotation(testCredential("old-access", "old-refresh"))).rejects.toThrow(/rotation journal.*符号链接/);
  });

  it("rejects save() when the credential's machineIdHash does not match the store's machine", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-test-"));
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: join(dir, "cfg") });
    await expect(store.save({ version: 1, site: "cn", machineIdHash: sha256("wrong-machine"), token: "x" })).rejects.toThrow();
  });

  it("returns undefined when no credential file exists", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-test-"));
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: join(dir, "cfg") });
    expect(await store.load()).toBeUndefined();
  });

  it("rejects a config path that is a symlink instead of a regular file", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-test-"));
    const configDir = join(dir, "cfg");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    await saveFixture(store, "machine-a");
    const realPath = join(configDir, "auth-cn.json");
    const decoyTarget = join(dir, "decoy.json");
    await writeFile(decoyTarget, await readFile(realPath, "utf8"), "utf8");
    await rm(realPath);
    await symlink(decoyTarget, realPath);
    await expect(store.load()).rejects.toThrow(/符号链接/);
  });

  it("rejects a credential file with overly permissive mode", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-test-"));
    const configDir = join(dir, "cfg");
    const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    await saveFixture(store, "machine-a");
    await chmod(join(configDir, "auth-cn.json"), 0o644);
    await expect(store.load()).rejects.toThrow(/0600/);
  });

  it("rejects a credential whose machineIdHash does not match the current machine", async () => {
    dir = await mkdtemp(join(tmpdir(), "qoder-proxy-test-"));
    const configDir = join(dir, "cfg");
    const storeA = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir });
    await saveFixture(storeA, "machine-a");
    const storeB = createConfigStore("machine-b", { QODER_PROXY_CONFIG_DIR: configDir });
    await expect(storeB.load()).rejects.toThrow(/machine ID/);
  });
});

// Helpers -------------------------------------------------------------------

// Persists a structurally valid but entirely fake credential (not a real token) through the store,
// using the same machineIdHash derivation (sha256(machineId)) the store itself uses.
async function saveFixture(store: ReturnType<typeof createConfigStore>, machineId: string): Promise<void> {
  const cred: StoredCredential = { version: 1, site: "cn", machineIdHash: sha256(machineId), token: "fixture-token-not-real" };
  await store.save(cred);
}
