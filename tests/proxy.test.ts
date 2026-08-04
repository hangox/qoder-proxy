import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createApp, type SessionLike } from "../src/proxy.ts";
import { createRoutingAttestation, ROUTING_ATTESTATION_FILE } from "../src/attestation.ts";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuthSession, CatalogUpstreamError, QuotaUpstreamError, StaleModelCatalogError, type ModelCatalogSnapshot } from "../src/auth/session.ts";
import type { QoderAssistantModel } from "../src/models.ts";

const ENV = { QODER_PROXY_API_KEY: "test-api-key" };
const MODELS: QoderAssistantModel[] = [
  { key: "auto", displayName: "Auto", isDefault: true, isVision: false, isReasoning: false, maxInputTokens: 200000, maxOutputTokens: null, createdAt: "1970-01-01T00:00:00.000Z", format: "openai", source: "system" },
  { key: "qmodel_38max", displayName: "Qwen3.8-Max", isDefault: false, isVision: false, isReasoning: true, maxInputTokens: 200000, maxOutputTokens: null, createdAt: "1970-01-01T00:00:00.000Z", format: "openai", source: "system" },
];
const HEADERS = { "content-type": "application/json", "x-api-key": ENV.QODER_PROXY_API_KEY };
const MODEL_HEADERS = { "x-api-key": ENV.QODER_PROXY_API_KEY, "anthropic-version": "2023-06-01" };
const SNAPSHOT: ModelCatalogSnapshot = { models: MODELS, generation: 0 };
const disposeCalls: string[] = [];
const refreshCalls: string[] = [];
const signedModelKeys: string[] = [];
const signedBodies: string[] = [];

function streamFrom(chunks: string[]): ReadableStream<Uint8Array> {
  const enc = new TextEncoder(); let i = 0;
  return new ReadableStream({ pull(c) { if (i === chunks.length) c.close(); else c.enqueue(enc.encode(chunks[i++]!)); } });
}
function streamAfter(gate: Promise<void>, chunks: string[]): ReadableStream<Uint8Array> {
  const enc = new TextEncoder();
  let emitted = false;
  return new ReadableStream({
    async pull(controller) {
      await gate;
      if (emitted) { controller.close(); return; }
      emitted = true;
      for (const chunk of chunks) controller.enqueue(enc.encode(chunk));
    },
  });
}
function frame(chunk: unknown) { return `event: message\ndata: ${JSON.stringify({ body: JSON.stringify(chunk) })}\n\n`; }
const HAPPY = [frame({ choices: [{ index: 0, delta: { content: "hi there" } }] }), frame({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 4, completion_tokens: 2 } }), "event: message\ndata: {\"body\":\"[DONE]\"}\n\n"];
function fakeSession(overrides: Partial<SessionLike> = {}): SessionLike {
  return {
    listModels: async () => SNAPSHOT,
    createSignedAttempt: (bodyJson, modelKey) => {
      signedBodies.push(bodyJson);
      signedModelKeys.push(modelKey);
      return { context: { dispose: () => disposeCalls.push("dispose") } as never, prepared: { url: "https://gateway.qoder.com.cn/infer", headers: { "content-type": "application/json" }, body: bodyJson }, auth: { uid: "u" } as never };
    },
    refreshAndReauthenticate: async (_signal, observer) => { refreshCalls.push("refresh"); observer?.recordRefresh(); },
    getQuotaUsage: async () => ({
      totalUsagePercentage: 25,
      expiresAt: 1_800_000_000,
      userQuota: { total: 100, used: 20, remaining: 80, percentage: 20, unit: "credits" },
      isQuotaExceeded: false,
    }),
    ...overrides,
  };
}

describe("proxy HTTP layer", () => {
  const originalFetch = globalThis.fetch;
  const attestationRoots: string[] = [];
  let fetchMock: ReturnType<typeof vi.fn>;
  beforeEach(() => { disposeCalls.length = 0; refreshCalls.length = 0; signedModelKeys.length = 0; signedBodies.length = 0; fetchMock = vi.fn(); globalThis.fetch = fetchMock as unknown as typeof fetch; });
  afterEach(async () => { globalThis.fetch = originalFetch; await Promise.all(attestationRoots.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

  it("returns 500 before auth preflight session exists", async () => {
    const response = await createApp(ENV).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] }) });
    expect(response.status).toBe(500);
  });

  it("returns sanitized 500 when quota session is unavailable", async () => {
    const response = await createApp(ENV).request("/internal/quota", { headers: { "x-api-key": ENV.QODER_PROXY_API_KEY } });
    expect(response.status).toBe(500);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
    expect(JSON.stringify(await response.json())).not.toContain("token");
  });

  it("returns a minimal no-store quota DTO using Bearer authentication", async () => {
    const response = await createApp(ENV, fakeSession({
      getQuotaUsage: async () => ({
        totalUsagePercentage: 42.5,
        expiresAt: 0,
        userQuota: { total: 100.1, used: 20.05, remaining: 80.04, percentage: 20, unit: "credits" },
        addOnQuota: { total: 40.2, used: 10.1, remaining: 30.09, percentage: 25, unit: "credits", detailUrl: "https://private.example/add-on" },
        orgResourcePackage: { cap: 60.3, used: 15.15, remaining: 45.14, percentage: 25, available: true, unit: "credits" },
        isQuotaExceeded: false,
      }),
    })).request("/internal/quota", { headers: { authorization: `Bearer ${ENV.QODER_PROXY_API_KEY}` } });
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
    const body = await response.json();
    expect(body).toMatchObject({ percentage: 42.5, unit: "credits", expiresAt: 0, exceeded: false });
    expect(Object.keys(body).sort()).toEqual(["exceeded", "expiresAt", "percentage", "remaining", "total", "unit", "used"]);
    expect(body.used).toBeCloseTo(45.3);
    expect(body.total).toBeCloseTo(200.6);
    expect(body.remaining).toBeCloseTo(155.27);
    expect(JSON.stringify(body)).not.toMatch(/detailUrl|userId|userType|upgradeUrl|private\.example|raw/i);
  });

  it("returns an over-quota percentage without clamping", async () => {
    const response = await createApp(ENV, fakeSession({
      getQuotaUsage: async () => ({
        totalUsagePercentage: 125.75,
        expiresAt: 0,
        userQuota: { total: 100, used: 125.75, remaining: 0, percentage: 125.75, unit: "credits" },
        isQuotaExceeded: true,
      }),
    })).request("/internal/quota", { headers: { "x-api-key": ENV.QODER_PROXY_API_KEY } });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ percentage: 125.75, used: 125.75, total: 100, remaining: 0, unit: "credits", expiresAt: 0, exceeded: true });
  });

  it("rejects unauthenticated and query-bearing quota requests", async () => {
    const app = createApp(ENV, fakeSession());
    const unauthenticated = await app.request("/internal/quota");
    expect(unauthenticated.status).toBe(401);
    expect(unauthenticated.headers.get("cache-control")).toBe("private, no-store");
    const query = await app.request("/internal/quota?debug=1", { headers: { "x-api-key": ENV.QODER_PROXY_API_KEY } });
    expect(query.status).toBe(400);
    expect(query.headers.get("cache-control")).toBe("private, no-store");
  });

  it("protects unsupported quota methods with the same auth and no-store policy", async () => {
    const app = createApp(ENV, fakeSession());
    const unauthenticated = await app.request("/internal/quota", { method: "POST" });
    expect(unauthenticated.status).toBe(401);
    expect(unauthenticated.headers.get("cache-control")).toBe("private, no-store");
    const authenticated = await app.request("/internal/quota", { method: "POST", headers: { "x-api-key": ENV.QODER_PROXY_API_KEY } });
    expect(authenticated.status).toBe(405);
    expect(authenticated.headers.get("allow")).toBe("GET");
    expect(authenticated.headers.get("cache-control")).toBe("private, no-store");
  });

  it("sanitizes quota upstream failures and preserves expected statuses", async () => {
    for (const [status, expected] of [[401, "authentication_error"], [403, "permission_error"], [429, "rate_limit_error"], [500, "api_error"]] as const) {
      const app = createApp(ENV, fakeSession({ getQuotaUsage: async () => { throw new QuotaUpstreamError("private quota response", status); } }));
      const response = await app.request("/internal/quota", { headers: { "x-api-key": ENV.QODER_PROXY_API_KEY } });
      expect(response.status).toBe(status === 500 ? 502 : status);
      const body = await response.json();
      expect(body.error.type).toBe(expected);
      expect(JSON.stringify(body)).not.toContain("private quota response");
    }
  });

  it("rejects quota while a QA attestation target request is active", async () => {
    const nonce = "0".repeat(32);
    const parent = await mkdtemp(join(tmpdir(), "qoder-proxy-attestation-quota-"));
    attestationRoots.push(parent);
    const dir = join(parent, `qoder-proxy-qa-attestation-${nonce}`);
    const sink = createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: dir, QODER_PROXY_QA_ATTESTATION_NONCE: nonce })!;
    fetchMock.mockResolvedValueOnce(new Response(streamAfter(new Promise<void>(() => {}), HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const app = createApp(ENV, fakeSession(), sink);
    const target = await app.request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ stream: true, model: "qmodel_38max", messages: [{ role: "user", content: "target" }] }) });
    expect(target.status).toBe(200);
    const quota = await app.request("/internal/quota", { headers: { "x-api-key": ENV.QODER_PROXY_API_KEY } });
    expect(quota.status).toBe(503);
    await target.body?.cancel();
    sink.close();
  });

  it("keeps a QA quota auxiliary lease through an aborted caller until the shared load settles", async () => {
    const nonce = "f".repeat(32);
    const parent = await mkdtemp(join(tmpdir(), "qoder-proxy-attestation-quota-abort-"));
    attestationRoots.push(parent);
    const dir = join(parent, `qoder-proxy-qa-attestation-${nonce}`);
    const sink = createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: dir, QODER_PROXY_QA_ATTESTATION_NONCE: nonce })!;
    let releaseQuota!: () => void;
    const quotaGate = new Promise<void>((resolve) => { releaseQuota = resolve; });
    let quotaStarted!: () => void;
    const started = new Promise<void>((resolve) => { quotaStarted = resolve; });
    const quotaUsage = { totalUsagePercentage: 0, expiresAt: 0, userQuota: { total: 1, used: 0, remaining: 1, percentage: 0, unit: "credits" }, isQuotaExceeded: false };
    const app = createApp(ENV, fakeSession({
      getQuotaUsage: async (signal) => {
        quotaStarted();
        await new Promise<void>((resolve, reject) => {
          const onAbort = () => reject(signal?.reason ?? new Error("quota caller cancelled"));
          quotaGate.then(resolve, reject);
          if (signal?.aborted) onAbort(); else signal?.addEventListener("abort", onAbort, { once: true });
        });
        return quotaUsage;
      },
    }), sink);
    const controller = new AbortController();
    const quotaRequest = app.request("/internal/quota", { headers: { "x-api-key": ENV.QODER_PROXY_API_KEY }, signal: controller.signal });
    await started;
    controller.abort(new Error("quota caller cancelled"));
    await Promise.resolve();
    const blocked = await app.request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "qmodel_38max", messages: [{ role: "user", content: "target" }] }) });
    expect(blocked.status).toBe(503);
    releaseQuota();
    await Promise.resolve(quotaRequest).catch(() => undefined);
    fetchMock.mockResolvedValueOnce(new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const target = await app.request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "qmodel_38max", messages: [{ role: "user", content: "target" }] }) });
    expect(target.status).toBe(200);
    sink.close();
  });
  it("streams valid upstream SSE", async () => {
    fetchMock.mockResolvedValueOnce(new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const response = await createApp(ENV, fakeSession()).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ stream: true, messages: [{ role: "user", content: "hi" }] }) });
    expect(response.status).toBe(200); expect(await response.text()).toContain("message_stop"); expect(disposeCalls).toEqual(["dispose"]);
  });
  it("collects non-streaming response", async () => {
    fetchMock.mockResolvedValueOnce(new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const response = await createApp(ENV, fakeSession()).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] }) });
    expect(response.status).toBe(200); expect((await response.json()).content).toEqual([{ type: "text", text: "hi there" }]);
  });
  it("buffers and replays a valid tool response as Anthropic SSE", async () => {
    const toolResponse = [
      frame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "opaque-id", function: { name: "safe_tool", arguments: JSON.stringify({ ok: true }) } }] } }] }),
      frame({ choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] }),
      "event: message\ndata: {\"body\":\"[DONE]\"}\n\n",
    ];
    fetchMock.mockResolvedValueOnce(new Response(streamFrom(toolResponse), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const response = await createApp(ENV, fakeSession()).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ stream: true, tools: [{ name: "safe_tool", input_schema: { type: "object" } }], messages: [{ role: "user", content: "use the tool" }] }) });
    const text = await response.text();
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    expect(text).toContain("event: message_start");
    expect(text).toContain("event: content_block_start");
    expect(text).toContain("safe_tool");
    expect(text).toContain('"stop_reason":"tool_use"');
    expect(text).toContain("event: message_stop");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
  it("buffers a valid non-stream tool response before returning JSON", async () => {
    const toolResponse = [
      frame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "opaque-id", function: { name: "safe_tool", arguments: JSON.stringify({ ok: true }) } }] } }] }),
      frame({ choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] }),
    ];
    fetchMock.mockResolvedValueOnce(new Response(streamFrom(toolResponse), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const response = await createApp(ENV, fakeSession()).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ tools: [{ name: "safe_tool", input_schema: { type: "object" } }], messages: [{ role: "user", content: "use the tool" }] }) });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ stop_reason: "tool_use", content: [{ type: "tool_use", name: "safe_tool", input: { ok: true } }] });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
  it("retries one malformed tool finalize response and replays the valid retry", async () => {
    const malformed = [
      frame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "opaque-id", function: { name: "safe_tool", arguments: "{" } }] } }] }),
      frame({ choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] }),
    ];
    const valid = [
      frame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "opaque-id-2", function: { name: "safe_tool", arguments: "{}" } }] } }] }),
      frame({ choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] }),
    ];
    fetchMock
      .mockResolvedValueOnce(new Response(streamFrom(malformed), { status: 200, headers: { "content-type": "text/event-stream" } }))
      .mockResolvedValueOnce(new Response(streamFrom(valid), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const response = await createApp(ENV, fakeSession()).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ stream: true, tools: [{ name: "safe_tool", input_schema: { type: "object" } }], messages: [{ role: "user", content: "use the tool" }] }) });
    expect(response.status).toBe(200);
    expect(await response.text()).toContain("message_stop");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
  it("returns retryable JSON after two malformed tool finalize responses before any SSE", async () => {
    const malformed = [
      frame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "opaque-id", function: { name: "safe_tool", arguments: "{" } }] } }] }),
      frame({ choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] }),
    ];
    fetchMock
      .mockResolvedValueOnce(new Response(streamFrom(malformed), { status: 200, headers: { "content-type": "text/event-stream" } }))
      .mockResolvedValueOnce(new Response(streamFrom(malformed), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const response = await createApp(ENV, fakeSession()).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ stream: true, tools: [{ name: "safe_tool", input_schema: { type: "object" } }], messages: [{ role: "user", content: "use the tool" }] }) });
    expect(response.status).toBe(503);
    expect(response.headers.get("x-should-retry")).toBe("true");
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(await response.text()).not.toContain("event: message_start");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
  it("maps non-2xx status", async () => {
    fetchMock.mockResolvedValueOnce(new Response("rate", { status: 429 }));
    const response = await createApp(ENV, fakeSession()).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] }) });
    expect(response.status).toBe(429); expect((await response.json()).error.type).toBe("rate_limit_error");
  });
  it("cancels first 401 body, refreshes, re-resolves the new snapshot, and retries once", async () => {
    let cancelled = false;
    let generation = 0;
    const secondModels = MODELS.map((model) => model.key === "auto" ? { ...model, displayName: "Auto v2" } : model);
    const session = fakeSession({
      listModels: async () => ({ models: generation === 0 ? MODELS : secondModels, generation }),
      refreshAndReauthenticate: async () => { refreshCalls.push("refresh"); generation = 1; },
    });
    const first = new Response(new ReadableStream({ cancel() { cancelled = true; } }), { status: 401 });
    fetchMock.mockResolvedValueOnce(first).mockResolvedValueOnce(new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const response = await createApp(ENV, session).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] }) });
    expect(response.status).toBe(200);
    expect(cancelled).toBe(true);
    expect(refreshCalls).toEqual(["refresh"]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(JSON.parse(signedBodies[1]!).model_config.display_name).toBe("Auto v2");
  });
  it("rejects HTTP 200 non-SSE before output", async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ error: "bad" }), { status: 200, headers: { "content-type": "application/json" } }));
    const response = await createApp(ENV, fakeSession()).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ stream: true, messages: [{ role: "user", content: "hi" }] }) });
    expect(response.status).toBe(502); expect((await response.json()).error.type).toBe("api_error");
  });

  it("requires API auth for model list and retrieve", async () => {
    const app = createApp(ENV, fakeSession());
    for (const path of ["/v1/models", "/v1/models/auto"]) {
      const response = await app.request(path);
      const body = await response.json();
      expect(response.status).toBe(401);
      expect(response.headers.get("request-id")).toBe(body.request_id);
      expect(response.headers.get("cache-control")).toBe("private, no-store");
    }
  });

  it("requires the current Anthropic API version for model routes", async () => {
    const app = createApp(ENV, fakeSession());
    const response = await app.request("/v1/models", { headers: { "x-api-key": ENV.QODER_PROXY_API_KEY } });
    const body = await response.json();
    expect(response.status).toBe(400);
    expect(body.request_id).toBe(response.headers.get("request-id"));
    expect(response.headers.get("cache-control")).toBe("private, no-store");
  });

  it("returns Anthropic model list shape and supports cursors", async () => {
    const app = createApp(ENV, fakeSession());
    const first = await app.request("/v1/models?limit=1", { headers: MODEL_HEADERS });
    expect(first.status).toBe(200);
    expect(first.headers.get("request-id")).toMatch(/^req_[0-9a-f]+$/);
    expect(first.headers.get("cache-control")).toBe("private, no-store");
    expect(await first.json()).toMatchObject({ data: [{ id: "auto", type: "model" }], has_more: true, first_id: "auto", last_id: "auto" });
    const next = await app.request("/v1/models?after_id=auto&limit=1", { headers: MODEL_HEADERS });
    expect(await next.json()).toMatchObject({ data: [{ id: "qmodel_38max" }], has_more: false, first_id: "qmodel_38max", last_id: "qmodel_38max" });
  });

  it("shares one session catalog load across concurrent list requests", async () => {
    let calls = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let shared: Promise<ModelCatalogSnapshot> | undefined;
    const app = createApp(ENV, fakeSession({
      listModels: () => {
        if (!shared) shared = (async () => { calls++; await gate; return SNAPSHOT; })();
        return shared;
      },
    }));
    const request = () => app.request("/v1/models", { headers: MODEL_HEADERS });
    const first = request();
    const second = request();
    release();
    const responses = await Promise.all([first, second]);
    expect(responses.map((response) => response.status)).toEqual([200, 200]);
    expect(calls).toBe(1);
  });

  it("retrieves an exact model, URL-decodes once, and returns 404 for aliases or disabled IDs", async () => {
    const app = createApp(ENV, fakeSession());
    const found = await app.request("/v1/models/qmodel%5F38max", { headers: MODEL_HEADERS });
    expect(found.status).toBe(200);
    expect(await found.json()).toMatchObject({ id: "qmodel_38max", display_name: "Qwen3.8-Max", max_input_tokens: 200000, max_tokens: 1024 });
    expect((await app.request("/v1/models/Qwen3.8-Max", { headers: MODEL_HEADERS })).status).toBe(404);
    expect((await app.request("/v1/models/%252F", { headers: MODEL_HEADERS })).status).toBe(404);
  });

  it("rejects unknown, repeated, conflicting, and malformed pagination params", async () => {
    const app = createApp(ENV, fakeSession());
    for (const path of ["/v1/models?x=1", "/v1/models?limit=1&limit=2", "/v1/models?before_id=auto&after_id=auto", "/v1/models?limit=0", "/v1/models/auto?limit=1"]) {
      const response = await app.request(path, { headers: MODEL_HEADERS });
      expect(response.status, path).toBe(400);
      expect((await response.json()).error.type).toBe("invalid_request_error");
    }
  });

  it("sanitizes catalog upstream errors while preserving auth/rate status", async () => {
    const app = createApp(ENV, fakeSession({ listModels: async () => { throw new CatalogUpstreamError("secret raw body", 429); } }));
    const response = await app.request("/v1/models", { headers: MODEL_HEADERS });
    expect(response.status).toBe(429);
    expect(JSON.stringify(await response.json())).not.toContain("secret raw body");
  });

  it("maps catalog upstream request/service failures to sanitized 502", async () => {
    for (const status of [400, 404, 500, 503]) {
      const app = createApp(ENV, fakeSession({ listModels: async () => { throw new CatalogUpstreamError("secret raw body", status); } }));
      const response = await app.request("/v1/models", { headers: MODEL_HEADERS });
      expect(response.status, String(status)).toBe(502);
      const body = await response.json();
      expect(body.error.type).toBe("api_error");
      expect(JSON.stringify(body)).not.toContain("secret raw body");
    }
  });

  it("shares one AuthSession catalog load across concurrent model routes", async () => {
    let loaderCalls = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const store = {
      load: async () => undefined,
      isCommitted: async () => true,
      reserveRotation: async () => "owner",
      clearRotationReservation: async () => {},
      stageRotation: async () => {},
      save: async () => {},
      delete: async () => {},
    };
    const Session = AuthSession as unknown as { new(...args: unknown[]): AuthSession };
    const session = new Session({}, "machine-a", store, { roles: {} }, { version: 1, site: "cn", machineIdHash: "fixture", token: "fixture" }, { uid: "u", organization_id: "", data_policy_agreed: true }, {
      catalogLoader: async () => { loaderCalls++; await gate; return MODELS; },
    });
    const app = createApp(ENV, session);
    const list = app.request("/v1/models", { headers: MODEL_HEADERS });
    const retrieve = app.request("/v1/models/auto", { headers: MODEL_HEADERS });
    release();
    expect((await list).status).toBe(200);
    expect((await retrieve).status).toBe(200);
    expect(loaderCalls).toBe(1);
  });

  it("re-resolves against a fresh catalog when signing detects a stale generation", async () => {
    let generation = 0;
    const refreshedModels = MODELS.map((model) => model.key === "auto" ? { ...model, displayName: "Auto refreshed" } : model);
    const session = fakeSession({
      listModels: async () => ({ models: generation === 0 ? MODELS : refreshedModels, generation }),
      createSignedAttempt: (bodyJson, modelKey, catalogGeneration) => {
        if (catalogGeneration === 0) { generation = 1; throw new StaleModelCatalogError(); }
        signedBodies.push(bodyJson);
        signedModelKeys.push(modelKey);
        return { context: { dispose: () => disposeCalls.push("dispose") } as never, prepared: { url: "https://gateway.qoder.com.cn/infer", headers: { "content-type": "application/json" }, body: bodyJson }, auth: { uid: "u" } as never };
      },
    });
    fetchMock.mockResolvedValueOnce(new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const response = await createApp(ENV, session).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] }) });
    expect(response.status).toBe(200);
    expect(JSON.parse(signedBodies[0]!).model_config.display_name).toBe("Auto refreshed");
  });

  it("routes an exact requested model and returns the resolved ID", async () => {
    fetchMock.mockResolvedValueOnce(new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const response = await createApp(ENV, fakeSession()).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "qmodel_38max", messages: [{ role: "user", content: "hi" }] }) });
    expect(response.status).toBe(200);
    expect((await response.json()).model).toBe("qmodel_38max");
    expect(signedModelKeys).toEqual(["qmodel_38max"]);
    expect(JSON.parse(signedBodies[0]!).model_config).toMatchObject({ key: "qmodel_38max", display_name: "Qwen3.8-Max", is_reasoning: true });
  });

  it("returns 404 for an unknown requested model without inference", async () => {
    const response = await createApp(ENV, fakeSession()).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "not-attested", messages: [{ role: "user", content: "hi" }] }) });
    expect(response.status).toBe(404);
    expect((await response.json()).error.type).toBe("not_found_error");
    expect(fetchMock).not.toHaveBeenCalled();
    expect(signedModelKeys).toEqual([]);
  });

  it("uses a validated configured default, otherwise auto", async () => {
    fetchMock.mockImplementation(async () => new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const configured = await createApp({ ...ENV, QODER_CN_INFER_MODEL_KEY: "qmodel_38max" }, fakeSession()).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] }) });
    expect(configured.status).toBe(200);
    expect(signedModelKeys.at(-1)).toBe("qmodel_38max");
    const automatic = await createApp(ENV, fakeSession()).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] }) });
    expect(automatic.status).toBe(200);
    expect(signedModelKeys.at(-1)).toBe("auto");
  });

  it("fails closed when the configured default is not enabled", async () => {
    const response = await createApp({ ...ENV, QODER_CN_INFER_MODEL_KEY: "disabled" }, fakeSession()).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] }) });
    expect(response.status).toBe(500);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("writes one completed safe attestation for a streamed model request", async () => {
    const nonce = "e".repeat(32);
    const parent = await mkdtemp(join(tmpdir(), "qoder-proxy-attestation-proxy-"));
    attestationRoots.push(parent);
    const dir = join(parent, `qoder-proxy-qa-attestation-${nonce}`);
    const sink = createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: dir, QODER_PROXY_QA_ATTESTATION_NONCE: nonce })!;
    fetchMock.mockResolvedValueOnce(new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const response = await createApp(ENV, fakeSession({ listModels: async (_signal, observer) => { observer?.recordCatalogRemoteLoad(); return SNAPSHOT; } }), sink).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ stream: true, model: "qmodel_38max", messages: [{ role: "user", content: "never-record-this-prompt" }] }) });
    await response.text();
    sink.close();
    const record = JSON.parse(await readFile(join(dir, ROUTING_ATTESTATION_FILE), "utf8"));
    expect(record).toMatchObject({ completed: true, requestModel: "qmodel_38max", resolvedModel: "qmodel_38max", prepareInferModel: "qmodel_38max", responseModel: "qmodel_38max" });
    expect(record.counters).toEqual({ preflight: 0, catalogRemoteLoad: 1, modelsList: 0, modelRetrieve: 0, prompt: 1, inference: 1, response: 1, tools: 0, refresh: 0, retries: 0, extraInference: 0 });
    expect(JSON.stringify(record)).not.toContain("never-record-this-prompt");
  });

  it("attributes the pre-target list remote load and cached retrieve to the target artifact", async () => {
    const nonce = "a".repeat(32);
    const parent = await mkdtemp(join(tmpdir(), "qoder-proxy-attestation-catalog-"));
    attestationRoots.push(parent);
    const dir = join(parent, `qoder-proxy-qa-attestation-${nonce}`);
    const sink = createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: dir, QODER_PROXY_QA_ATTESTATION_NONCE: nonce })!;
    let catalogCalls = 0;
    const app = createApp(ENV, fakeSession({
      listModels: async (_signal, observer) => {
        if (++catalogCalls === 1) observer?.recordCatalogRemoteLoad();
        return SNAPSHOT;
      },
    }), sink);
    expect((await app.request("/v1/models", { headers: MODEL_HEADERS })).status).toBe(200);
    expect((await app.request("/v1/models/qmodel_38max", { headers: MODEL_HEADERS })).status).toBe(200);
    fetchMock.mockResolvedValueOnce(new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    expect((await app.request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "qmodel_38max", messages: [{ role: "user", content: "hi" }] }) })).status).toBe(200);
    sink.close();
    expect(catalogCalls).toBe(3);
    expect(JSON.parse(await readFile(join(dir, ROUTING_ATTESTATION_FILE), "utf8")).counters).toEqual({
      preflight: 0, catalogRemoteLoad: 1, modelsList: 1, modelRetrieve: 1, prompt: 1, inference: 1, response: 1, tools: 0, refresh: 0, retries: 0, extraInference: 0,
    });
  });

  it("attests the accepted prompt and declared tool count", async () => {
    const nonce = "c".repeat(32);
    const parent = await mkdtemp(join(tmpdir(), "qoder-proxy-attestation-tools-"));
    attestationRoots.push(parent);
    const dir = join(parent, `qoder-proxy-qa-attestation-${nonce}`);
    const sink = createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: dir, QODER_PROXY_QA_ATTESTATION_NONCE: nonce })!;
    fetchMock.mockResolvedValueOnce(new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const response = await createApp(ENV, fakeSession(), sink).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "qmodel_38max", messages: [{ role: "user", content: "secret prompt" }], tools: [{ name: "one", input_schema: { type: "object" } }, { name: "two", input_schema: { type: "object" } }] }) });
    expect(response.status).toBe(200);
    sink.close();
    const text = await readFile(join(dir, ROUTING_ATTESTATION_FILE), "utf8");
    expect(JSON.parse(text).counters).toMatchObject({ prompt: 1, tools: 2 });
    expect(text).not.toContain("secret prompt");
  });

  it("rejects target claim while an earlier auxiliary request is in flight without writing polluted evidence", async () => {
    const nonce = "b".repeat(32);
    const parent = await mkdtemp(join(tmpdir(), "qoder-proxy-attestation-isolation-"));
    attestationRoots.push(parent);
    const dir = join(parent, `qoder-proxy-qa-attestation-${nonce}`);
    const sink = createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: dir, QODER_PROXY_QA_ATTESTATION_NONCE: nonce })!;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let catalogCalls = 0;
    const app = createApp(ENV, fakeSession({ listModels: async () => { if (++catalogCalls === 1) await gate; return SNAPSHOT; } }), sink);
    const side = app.request("/v1/models", { headers: MODEL_HEADERS });
    await Promise.resolve();
    const target = await app.request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "qmodel_38max", messages: [{ role: "user", content: "hi" }] }) });
    expect(target.status).toBe(503);
    release();
    expect((await side).status).toBe(200);
    sink.close();
    expect(await readFile(join(dir, ROUTING_ATTESTATION_FILE), "utf8")).toBe("");
  });

  it("lets an aborted auxiliary catalog owner settle a delayed 401 without poisoning target evidence", async () => {
    const nonce = "1".repeat(32);
    const parent = await mkdtemp(join(tmpdir(), "qoder-proxy-attestation-aux-abort-"));
    attestationRoots.push(parent);
    const dir = join(parent, `qoder-proxy-qa-attestation-${nonce}`);
    const sink = createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: dir, QODER_PROXY_QA_ATTESTATION_NONCE: nonce })!;
    let rejectFirst!: (error: Error) => void;
    let catalogCalls = 0;
    let lateOperation!: Promise<ModelCatalogSnapshot>;
    const sharedCatalog = new Promise<ModelCatalogSnapshot>((_resolve, reject) => { rejectFirst = reject; });
    const session = fakeSession({
      listModels: async (signal, observer) => {
        if (++catalogCalls !== 1) return lateOperation;
        lateOperation = (async () => {
          observer?.recordCatalogRemoteLoad();
          try { await sharedCatalog; return SNAPSHOT; }
          catch (error) {
            if (!(error instanceof CatalogUpstreamError) || error.status !== 401) throw error;
            await session.refreshAndReauthenticate(undefined, observer);
            observer?.recordCatalogRemoteLoad();
            return SNAPSHOT;
          }
        })();
        lateOperation.catch(() => undefined);
        if (!signal) return lateOperation;
        return await new Promise<ModelCatalogSnapshot>((resolve, reject) => {
          const onAbort = () => reject(signal.reason ?? new Error("auxiliary caller cancelled"));
          lateOperation.then(resolve, reject);
          if (signal.aborted) onAbort(); else signal.addEventListener("abort", onAbort, { once: true });
        });
      },
      refreshAndReauthenticate: async (_signal, observer) => { refreshCalls.push("refresh"); observer?.recordRefresh(); },
    });
    fetchMock.mockResolvedValueOnce(new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const app = createApp(ENV, session, sink);
    const controller = new AbortController();
    const side = app.request("/v1/models", { headers: { ...MODEL_HEADERS }, signal: controller.signal });
    await Promise.resolve();
    controller.abort(new Error("auxiliary caller cancelled"));
    expect((await side).status).toBe(502);
    const targetPromise = app.request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "qmodel_38max", messages: [{ role: "user", content: "target" }] }) });
    await Promise.resolve();
    rejectFirst(new CatalogUpstreamError("late unauthorized", 401));
    await lateOperation;
    expect((await targetPromise).status).toBe(200);
    expect(refreshCalls).toEqual(["refresh"]);
    sink.close();
    expect(JSON.parse(await readFile(join(dir, ROUTING_ATTESTATION_FILE), "utf8"))).toMatchObject({ completed: true, counters: { catalogRemoteLoad: 0, refresh: 0, prompt: 1, inference: 1, response: 1 } });
  });

  it("holds an admitted non-target stream until terminal completion, then permits an isolated target claim", async () => {
    const nonce = "4".repeat(32);
    const parent = await mkdtemp(join(tmpdir(), "qoder-proxy-attestation-message-lease-"));
    attestationRoots.push(parent);
    const dir = join(parent, `qoder-proxy-qa-attestation-${nonce}`);
    const sink = createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: dir, QODER_PROXY_QA_ATTESTATION_NONCE: nonce })!;
    let releaseStream!: () => void;
    const streamGate = new Promise<void>((resolve) => { releaseStream = resolve; });
    const session = fakeSession({
      listModels: async (_signal, observer) => { observer?.recordCatalogRemoteLoad(); return SNAPSHOT; },
      refreshAndReauthenticate: async (_signal, observer) => { refreshCalls.push("refresh"); observer?.recordRefresh(); },
    });
    fetchMock
      .mockResolvedValueOnce(new Response(streamAfter(streamGate, HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }))
      .mockResolvedValueOnce(new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const app = createApp(ENV, session, sink);
    const automatic = await app.request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ stream: true, model: "auto", messages: [{ role: "user", content: "non-target" }] }) });
    expect(automatic.status).toBe(200);
    const blockedTarget = await app.request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "qmodel_38max", messages: [{ role: "user", content: "target" }] }) });
    expect(blockedTarget.status).toBe(503);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    releaseStream();
    expect(await automatic.text()).toContain("message_stop");
    const target = await app.request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "qmodel_38max", messages: [{ role: "user", content: "target" }] }) });
    expect(target.status).toBe(200);
    sink.close();
    expect(JSON.parse(await readFile(join(dir, ROUTING_ATTESTATION_FILE), "utf8"))).toMatchObject({ completed: true, counters: { catalogRemoteLoad: 1, refresh: 0, prompt: 1, inference: 1, response: 1 } });
  });

  it("keeps target ownership through stream terminal and rejects a later Messages request", async () => {
    const nonce = "5".repeat(32);
    const parent = await mkdtemp(join(tmpdir(), "qoder-proxy-attestation-target-owner-"));
    attestationRoots.push(parent);
    const dir = join(parent, `qoder-proxy-qa-attestation-${nonce}`);
    const sink = createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: dir, QODER_PROXY_QA_ATTESTATION_NONCE: nonce })!;
    let releaseStream!: () => void;
    const streamGate = new Promise<void>((resolve) => { releaseStream = resolve; });
    fetchMock
      .mockResolvedValueOnce(new Response(streamAfter(streamGate, HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }))
      .mockResolvedValueOnce(new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const app = createApp(ENV, fakeSession(), sink);
    const target = await app.request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ stream: true, model: "qmodel_38max", messages: [{ role: "user", content: "target" }] }) });
    expect(target.status).toBe(200);
    const blocked = await app.request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "auto", messages: [{ role: "user", content: "later" }] }) });
    expect(blocked.status).toBe(503);
    releaseStream();
    expect(await target.text()).toContain("message_stop");
    expect((await app.request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "auto", messages: [{ role: "user", content: "after" }] }) })).status).toBe(503);
    sink.close();
  });

  it("does not attribute a completed non-target 401 refresh to a later target artifact", async () => {
    const nonce = "2".repeat(32);
    const parent = await mkdtemp(join(tmpdir(), "qoder-proxy-attestation-refresh-isolation-"));
    attestationRoots.push(parent);
    const dir = join(parent, `qoder-proxy-qa-attestation-${nonce}`);
    const sink = createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: dir, QODER_PROXY_QA_ATTESTATION_NONCE: nonce })!;
    const session = fakeSession({
      listModels: async (_signal, observer) => { observer?.recordCatalogRemoteLoad(); return SNAPSHOT; },
      refreshAndReauthenticate: async (_signal, observer) => { refreshCalls.push("refresh"); observer?.recordRefresh(); },
    });
    fetchMock
      .mockResolvedValueOnce(new Response(new ReadableStream(), { status: 401 }))
      .mockResolvedValueOnce(new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }))
      .mockResolvedValueOnce(new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const app = createApp(ENV, session, sink);
    expect((await app.request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "auto", messages: [{ role: "user", content: "non-target" }] }) })).status).toBe(200);
    expect(refreshCalls).toEqual(["refresh"]);
    expect((await app.request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "qmodel_38max", messages: [{ role: "user", content: "target" }] }) })).status).toBe(200);
    sink.close();
    expect(JSON.parse(await readFile(join(dir, ROUTING_ATTESTATION_FILE), "utf8"))).toMatchObject({ completed: true, counters: { catalogRemoteLoad: 1, refresh: 0, prompt: 1, inference: 1, retries: 0, response: 1 } });
  });

  it("keeps concurrent Messages unrestricted when QA attestation is disabled", async () => {
    let releaseStreams!: () => void;
    const streamGate = new Promise<void>((resolve) => { releaseStreams = resolve; });
    fetchMock
      .mockResolvedValueOnce(new Response(streamAfter(streamGate, HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }))
      .mockResolvedValueOnce(new Response(streamAfter(streamGate, HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const app = createApp(ENV, fakeSession());
    const first = await app.request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ stream: true, messages: [{ role: "user", content: "one" }] }) });
    const second = await app.request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ stream: true, messages: [{ role: "user", content: "two" }] }) });
    expect([first.status, second.status]).toEqual([200, 200]);
    releaseStreams();
    expect((await Promise.all([first.text(), second.text()])).every((body) => body.includes("message_stop"))).toBe(true);
  });

  it("does not claim explicit auto, default auto, unknown, or disabled models before a later target request", async () => {
    const nonce = "7".repeat(32);
    const parent = await mkdtemp(join(tmpdir(), "qoder-proxy-attestation-nonpoison-"));
    attestationRoots.push(parent);
    const dir = join(parent, `qoder-proxy-qa-attestation-${nonce}`);
    const sink = createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: dir, QODER_PROXY_QA_ATTESTATION_NONCE: nonce })!;
    const app = createApp(ENV, fakeSession(), sink);
    fetchMock.mockImplementation(async () => new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    for (const body of [
      { model: "auto", messages: [{ role: "user", content: "hi" }] },
      { messages: [{ role: "user", content: "hi" }] },
      { model: "unknown", messages: [{ role: "user", content: "hi" }] },
    ]) expect((await app.request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify(body) })).status).not.toBe(503);
    const disabled = await createApp({ ...ENV, QODER_CN_INFER_MODEL_KEY: "disabled" }, fakeSession(), sink).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] }) });
    expect(disabled.status).toBe(500);
    fetchMock.mockResolvedValueOnce(new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const target = await app.request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "qmodel_38max", messages: [{ role: "user", content: "hi" }] }) });
    expect(target.status).toBe(200);
    sink.close();
    expect(JSON.parse(await readFile(join(dir, ROUTING_ATTESTATION_FILE), "utf8"))).toMatchObject({ completed: true, requestModel: "qmodel_38max" });
  });

  it("finalizes exactly one failed record when signing throws after a target claim", async () => {
    const nonce = "6".repeat(32);
    const parent = await mkdtemp(join(tmpdir(), "qoder-proxy-attestation-sign-failure-"));
    attestationRoots.push(parent);
    const dir = join(parent, `qoder-proxy-qa-attestation-${nonce}`);
    const sink = createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: dir, QODER_PROXY_QA_ATTESTATION_NONCE: nonce })!;
    const response = await createApp(ENV, fakeSession({ createSignedAttempt: () => { throw new Error("injected signing failure"); } }), sink).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "qmodel_38max", messages: [{ role: "user", content: "hi" }] }) });
    expect(response.status).toBe(500);
    sink.close();
    const raw = await readFile(join(dir, ROUTING_ATTESTATION_FILE), "utf8");
    expect(raw.trim().split("\n")).toHaveLength(1);
    expect(JSON.parse(raw)).toMatchObject({ completed: false, responseModel: null, counters: { prompt: 1, response: 0 } });
  });

  it("writes successful non-stream and failed SSE terminal attestations", async () => {
    const successNonce = "9".repeat(32);
    const failureNonce = "8".repeat(32);
    const successParent = await mkdtemp(join(tmpdir(), "qoder-proxy-attestation-nonstream-"));
    const failureParent = await mkdtemp(join(tmpdir(), "qoder-proxy-attestation-sse-error-"));
    attestationRoots.push(successParent, failureParent);
    const successDir = join(successParent, `qoder-proxy-qa-attestation-${successNonce}`);
    const failureDir = join(failureParent, `qoder-proxy-qa-attestation-${failureNonce}`);
    const successSink = createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: successDir, QODER_PROXY_QA_ATTESTATION_NONCE: successNonce })!;
    const failureSink = createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: failureDir, QODER_PROXY_QA_ATTESTATION_NONCE: failureNonce })!;
    fetchMock.mockResolvedValueOnce(new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const nonStream = await createApp(ENV, fakeSession(), successSink).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "qmodel_38max", messages: [{ role: "user", content: "hi" }] }) });
    expect(nonStream.status).toBe(200);
    successSink.close();
    expect(JSON.parse(await readFile(join(successDir, ROUTING_ATTESTATION_FILE), "utf8"))).toMatchObject({ completed: true, responseModel: "qmodel_38max", counters: { prompt: 1, response: 1 } });

    fetchMock.mockResolvedValueOnce(new Response(streamFrom(["event: error\ndata: boom\n\n"]), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const streamed = await createApp(ENV, fakeSession(), failureSink).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ stream: true, model: "qmodel_38max", messages: [{ role: "user", content: "hi" }] }) });
    expect(await streamed.text()).toContain("event: error");
    failureSink.close();
    expect(JSON.parse(await readFile(join(failureDir, ROUTING_ATTESTATION_FILE), "utf8"))).toMatchObject({ completed: false, responseModel: null, counters: { prompt: 1, response: 0 } });
  });

  it("attributes successful pre-target catalog 401 recovery to the later target", async () => {
    const nonce = "6".repeat(32);
    const parent = await mkdtemp(join(tmpdir(), "qoder-proxy-attestation-pretarget-retry-"));
    attestationRoots.push(parent);
    const dir = join(parent, `qoder-proxy-qa-attestation-${nonce}`);
    const sink = createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: dir, QODER_PROXY_QA_ATTESTATION_NONCE: nonce })!;
    let catalogCalls = 0;
    const session = fakeSession({
      listModels: async (_signal, observer) => {
        if (++catalogCalls === 1) {
          observer?.recordCatalogRemoteLoad();
          observer?.recordRefresh();
          observer?.recordRetry();
          observer?.recordCatalogRemoteLoad();
        }
        return SNAPSHOT;
      },
    });
    const app = createApp(ENV, session, sink);
    expect((await app.request("/v1/models", { headers: MODEL_HEADERS })).status).toBe(200);
    fetchMock.mockResolvedValueOnce(new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    expect((await app.request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "qmodel_38max", messages: [{ role: "user", content: "hi" }] }) })).status).toBe(200);
    sink.close();
    expect(JSON.parse(await readFile(join(dir, ROUTING_ATTESTATION_FILE), "utf8")).counters).toEqual({
      preflight: 0, catalogRemoteLoad: 2, modelsList: 1, modelRetrieve: 0, prompt: 1, inference: 1, response: 1, tools: 0, refresh: 1, retries: 1, extraInference: 0,
    });
  });

  it("attests catalog 401 recovery as an extra catalog operation without extra inference", async () => {
    const nonce = "d".repeat(32);
    const parent = await mkdtemp(join(tmpdir(), "qoder-proxy-attestation-catalog-retry-"));
    attestationRoots.push(parent);
    const dir = join(parent, `qoder-proxy-qa-attestation-${nonce}`);
    const sink = createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: dir, QODER_PROXY_QA_ATTESTATION_NONCE: nonce })!;
    const session = fakeSession({
      listModels: async (_signal, observer) => {
        observer?.recordCatalogRemoteLoad();
        observer?.recordRefresh();
        observer?.recordRetry();
        observer?.recordCatalogRemoteLoad();
        return SNAPSHOT;
      },
    });
    fetchMock.mockResolvedValueOnce(new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const response = await createApp(ENV, session, sink).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "qmodel_38max", messages: [{ role: "user", content: "hi" }] }) });
    expect(response.status).toBe(200);
    sink.close();
    expect(JSON.parse(await readFile(join(dir, ROUTING_ATTESTATION_FILE), "utf8")).counters).toEqual({ preflight: 0, catalogRemoteLoad: 2, modelsList: 0, modelRetrieve: 0, prompt: 1, inference: 1, response: 1, tools: 0, refresh: 1, retries: 1, extraInference: 0 });
  });

  it("attests combined catalog and inference 401 recovery independently", async () => {
    const nonce = "3".repeat(32);
    const parent = await mkdtemp(join(tmpdir(), "qoder-proxy-attestation-mixed-retry-"));
    attestationRoots.push(parent);
    const dir = join(parent, `qoder-proxy-qa-attestation-${nonce}`);
    const sink = createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: dir, QODER_PROXY_QA_ATTESTATION_NONCE: nonce })!;
    let catalogCalls = 0;
    const session = fakeSession({
      listModels: async (_signal, observer) => {
        if (++catalogCalls === 1) {
          observer?.recordCatalogRemoteLoad();
          observer?.recordRefresh();
          observer?.recordRetry();
          observer?.recordCatalogRemoteLoad();
        }
        return SNAPSHOT;
      },
    });
    fetchMock
      .mockResolvedValueOnce(new Response(new ReadableStream(), { status: 401 }))
      .mockResolvedValueOnce(new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const response = await createApp(ENV, session, sink).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "qmodel_38max", messages: [{ role: "user", content: "hi" }] }) });
    expect(response.status).toBe(200);
    sink.close();
    expect(JSON.parse(await readFile(join(dir, ROUTING_ATTESTATION_FILE), "utf8")).counters).toEqual({ preflight: 0, catalogRemoteLoad: 2, modelsList: 0, modelRetrieve: 0, prompt: 1, inference: 2, response: 1, tools: 0, refresh: 2, retries: 2, extraInference: 1 });
  });

  it("attests a 401 refresh retry exactly once", async () => {
    const nonce = "f".repeat(32);
    const parent = await mkdtemp(join(tmpdir(), "qoder-proxy-attestation-retry-"));
    attestationRoots.push(parent);
    const dir = join(parent, `qoder-proxy-qa-attestation-${nonce}`);
    const sink = createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: dir, QODER_PROXY_QA_ATTESTATION_NONCE: nonce })!;
    const first = new Response(new ReadableStream(), { status: 401 });
    fetchMock.mockResolvedValueOnce(first).mockResolvedValueOnce(new Response(streamFrom(HAPPY), { status: 200, headers: { "content-type": "text/event-stream" } }));
    const response = await createApp(ENV, fakeSession(), sink).request("/v1/messages", { method: "POST", headers: HEADERS, body: JSON.stringify({ model: "qmodel_38max", messages: [{ role: "user", content: "hi" }] }) });
    expect(response.status).toBe(200);
    sink.close();
    const record = JSON.parse(await readFile(join(dir, ROUTING_ATTESTATION_FILE), "utf8"));
    expect(record).toMatchObject({ completed: true, responseModel: "qmodel_38max" });
    expect(record.counters).toEqual({ preflight: 0, catalogRemoteLoad: 0, modelsList: 0, modelRetrieve: 0, prompt: 1, inference: 2, response: 1, tools: 0, refresh: 1, retries: 1, extraInference: 1 });
  });
});
