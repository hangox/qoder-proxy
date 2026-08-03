// qoder-proxy Hono 应用（Gate 1）。生产 CLI 只能注入已 preflight 的 AuthSession。

import { randomUUID, timingSafeEqual } from "node:crypto";
import { Hono } from "hono";
import type { Context, Next } from "hono";
import { logger } from "./logger.ts";
import { createRoutingAttestation } from "./attestation.ts";
import type { RoutingAttestation, RoutingAttestationSessionObserver, RoutingMessageLease } from "./attestation.ts";
import { convertAnthropicToCnBody, ConversionError, validateAnthropicRequestEnvelope, type CnConversion } from "./convert.ts";
import { emitAnthropicSseStream, collectAnthropicMessage } from "./sse.ts";
import { AuthSession, CatalogUpstreamError, QuotaUpstreamError, StaleModelCatalogError, type ModelCatalogSnapshot, type QoderQuotaUsage, type SignedAttempt } from "./auth/session.ts";
import { findModelById, ModelPaginationError, paginateModels, toAnthropicModelInfo, type QoderAssistantModel } from "./models.ts";
import { expectedModelForRoutingKey, hasExpectedModelIdentity } from "./model-registry.ts";

const DEFAULT_TIMEOUT_MS = 120_000;
const ANTHROPIC_VERSION = "2023-06-01";
type SessionLike = Pick<AuthSession, "createSignedAttempt"> & {
  listModels(signal?: AbortSignal, routingAttestation?: RoutingAttestationSessionObserver): Promise<ModelCatalogSnapshot>;
  refreshAndReauthenticate(signal?: AbortSignal, routingAttestation?: RoutingAttestationSessionObserver): Promise<void>;
  getQuotaUsage(signal?: AbortSignal): Promise<QoderQuotaUsage>;
};
type ModelRequestContext = Context & { modelRequestId?: string };

function constantTimeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8"), right = Buffer.from(b, "utf8");
  return left.length === right.length && timingSafeEqual(left, right);
}
function parseTimeout(value: string | undefined): number {
  if (value === undefined || value.length === 0) return DEFAULT_TIMEOUT_MS;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 && parsed <= 10 * 60_000 ? parsed : DEFAULT_TIMEOUT_MS;
}
function proxyAuthenticationError(c: Context, env: Record<string, string | undefined>): { type: string; message: string; status: 401 | 500 } | undefined {
  const expected = env.QODER_PROXY_API_KEY;
  if (!expected) {
    logger.error("QODER_PROXY_API_KEY 未配置，拒绝请求", { route: c.req.path });
    return { type: "api_error", message: "server not configured", status: 500 };
  }
  const authorization = c.req.header("authorization");
  const bearer = authorization?.startsWith("Bearer ") ? authorization.slice(7) : undefined;
  const received = c.req.header("x-api-key") ?? bearer;
  return !received || !constantTimeEqual(received, expected) ? { type: "authentication_error", message: "invalid API key", status: 401 } : undefined;
}
function requireApiKey(env: Record<string, string | undefined>, noStore = false) {
  return async (c: Context, next: Next) => {
    if (noStore) c.header("cache-control", "private, no-store");
    const error = proxyAuthenticationError(c, env);
    if (error) return c.json(apiError(error.type, error.message), error.status);
    await next();
  };
}
function modelRequestId(): string { return `req_${randomUUID().replaceAll("-", "")}`; }
function modelHeaders(requestId: string): Record<string, string> { return { "request-id": requestId, "cache-control": "private, no-store" }; }
function modelJson(c: Context, requestId: string, body: unknown, status: number = 200): Response {
  return c.json(body, status as never, modelHeaders(requestId));
}
function modelError(c: Context, requestId: string, type: string, message: string, status: number): Response {
  return modelJson(c, requestId, apiError(type, message, requestId), status);
}
function requireModelsApi(env: Record<string, string | undefined>) {
  return async (c: Context, next: Next) => {
    const requestId = modelRequestId();
    (c as ModelRequestContext).modelRequestId = requestId;
    const authentication = proxyAuthenticationError(c, env);
    if (authentication) return modelError(c, requestId, authentication.type, authentication.message, authentication.status);
    if (c.req.header("anthropic-version") !== ANTHROPIC_VERSION) {
      return modelError(c, requestId, "invalid_request_error", `anthropic-version 必须为 ${ANTHROPIC_VERSION}`, 400);
    }
    await next();
  };
}
function currentModelRequestId(c: Context): string { return (c as ModelRequestContext).modelRequestId ?? modelRequestId(); }
function mapUpstreamStatus(status: number): { httpStatus: 400 | 401 | 403 | 429 | 502; type: string } {
  if (status === 400) return { httpStatus: 400, type: "invalid_request_error" };
  if (status === 401) return { httpStatus: 401, type: "authentication_error" };
  if (status === 403) return { httpStatus: 403, type: "permission_error" };
  if (status === 429) return { httpStatus: 429, type: "rate_limit_error" };
  return { httpStatus: 502, type: "api_error" };
}
function estimateInputTokens(body: Record<string, unknown>): number { return Math.max(1, Math.ceil(JSON.stringify({ system: body.system, messages: body.messages, tools: body.tools }).length / 4)); }
function apiError(type: string, message: string, requestId?: string) {
  return { type: "error", error: { type, message }, ...(requestId === undefined ? {} : { request_id: requestId }) };
}
async function discard(response: Response | undefined): Promise<void> { await response?.body?.cancel().catch(() => undefined); }
function isSse(response: Response): boolean { return response.headers.get("content-type")?.toLowerCase().includes("text/event-stream") === true; }

function parseModelsQuery(c: Context): { beforeId?: string; afterId?: string; limit?: number } {
  const params = new URL(c.req.url).searchParams;
  const allowed = new Set(["before_id", "after_id", "limit"]);
  for (const key of params.keys()) if (!allowed.has(key)) throw new ModelPaginationError(`未知查询参数: ${key}`);
  for (const key of allowed) if (params.getAll(key).length > 1) throw new ModelPaginationError(`${key} 不能重复`);
  const beforeId = params.get("before_id") ?? undefined;
  const afterId = params.get("after_id") ?? undefined;
  if (beforeId !== undefined && beforeId.length === 0) throw new ModelPaginationError("before_id 不能为空");
  if (afterId !== undefined && afterId.length === 0) throw new ModelPaginationError("after_id 不能为空");
  const rawLimit = params.get("limit");
  if (rawLimit !== null && !/^[1-9][0-9]*$/.test(rawLimit)) throw new ModelPaginationError("limit 必须是正整数");
  return { beforeId, afterId, limit: rawLimit === null ? undefined : Number(rawLimit) };
}

function rejectUnexpectedQuery(c: Context): void {
  const params = new URL(c.req.url).searchParams;
  const first = params.keys().next();
  if (!first.done) throw new ModelPaginationError(`未知查询参数: ${first.value}`);
}

type StatuslineQuota = {
  percentage: number;
  used: number;
  total: number;
  remaining: number;
  unit: string;
  expiresAt: number;
  exceeded: boolean;
};

function statuslineQuota(usage: QoderQuotaUsage): StatuslineQuota {
  const buckets = [usage.userQuota, usage.addOnQuota].filter((bucket): bucket is QoderQuotaUsage["userQuota"] => bucket !== undefined);
  const unit = usage.userQuota.unit;
  if (buckets.some((bucket) => bucket.unit !== unit) || (usage.orgResourcePackage?.available && usage.orgResourcePackage.unit !== unit)) throw new Error("quota unit mismatch");
  const used = buckets.reduce((sum, bucket) => sum + bucket.used, 0) + (usage.orgResourcePackage?.available ? usage.orgResourcePackage.used : 0);
  const total = buckets.reduce((sum, bucket) => sum + bucket.total, 0) + (usage.orgResourcePackage?.available ? usage.orgResourcePackage.cap : 0);
  const remaining = buckets.reduce((sum, bucket) => sum + bucket.remaining, 0) + (usage.orgResourcePackage?.available ? usage.orgResourcePackage.remaining : 0);
  if (![used, total, remaining, usage.totalUsagePercentage, usage.expiresAt].every(Number.isFinite) || used < 0 || total < 0 || remaining < 0 || usage.totalUsagePercentage < 0 || usage.expiresAt < 0) {
    throw new Error("quota usage invalid");
  }
  return { percentage: usage.totalUsagePercentage, used, total, remaining, unit, expiresAt: usage.expiresAt, exceeded: usage.isQuotaExceeded };
}

function catalogFailure(c: Context, error: unknown, requestId?: string) {
  const respond = (type: string, status: number) => requestId === undefined
    ? c.json(apiError(type, "model catalog unavailable"), status as never)
    : modelError(c, requestId, type, "model catalog unavailable", status);
  if (error instanceof CatalogUpstreamError && error.status !== undefined) {
    if (error.status === 401) return respond("authentication_error", 401);
    if (error.status === 403) return respond("permission_error", 403);
    if (error.status === 429) return respond("rate_limit_error", 429);
    return respond("api_error", 502);
  }
  logger.error("模型目录读取失败", { errorClass: error instanceof Error ? error.name : "Error" });
  return respond("api_error", 502);
}

function resolveModel(models: readonly QoderAssistantModel[], requestModel: string | undefined, env: Record<string, string | undefined>): { model?: QoderAssistantModel; clientNotFound?: boolean; invalidDefault?: boolean } {
  if (requestModel !== undefined) return { model: findModelById(models, requestModel), clientNotFound: true };
  const configured = env.QODER_CN_INFER_MODEL_KEY;
  if (configured !== undefined && configured.length > 0) return { model: findModelById(models, configured), invalidDefault: true };
  return { model: findModelById(models, "auto") };
}

function createRequestSignal(c: Context, env: Record<string, string | undefined>): { controller: AbortController; signal: AbortSignal } {
  const controller = new AbortController();
  const timeout = AbortSignal.timeout(parseTimeout(env.QODER_PROXY_TIMEOUT_MS));
  for (const source of [c.req.raw.signal, timeout]) {
    if (source.aborted) controller.abort(source.reason);
    else source.addEventListener("abort", () => controller.abort(source.reason), { once: true });
  }
  return { controller, signal: controller.signal };
}

export function createApp(env: Record<string, string | undefined> = process.env, authSession?: SessionLike, routingAttestation: RoutingAttestation | undefined = createRoutingAttestation(env)) {
  const app = new Hono();
  app.get("/health", (c) => c.json({ status: "ok" }));
  app.get("/v1/models", requireModelsApi(env), async (c) => {
    const requestId = currentModelRequestId(c);
    let auxiliary: ReturnType<RoutingAttestation["beginAuxiliary"]> | undefined;
    let auxiliaryCompleted = false;
    try { auxiliary = routingAttestation?.beginAuxiliary(); }
    catch { return modelError(c, requestId, "api_error", "QA attestation target request already active", 503); }
    try {
    if (!authSession) return modelError(c, requestId, "api_error", "server auth session not initialized", 500);
    let query: ReturnType<typeof parseModelsQuery>;
    try { query = parseModelsQuery(c); }
    catch (error) { return modelError(c, requestId, "invalid_request_error", error instanceof Error ? error.message : "invalid query", 400); }
    try {
      const snapshot = await authSession.listModels(c.req.raw.signal, auxiliary);
      auxiliary?.allowCatalogModels(snapshot.models.map((model) => model.key));
      auxiliary?.recordModelsList();
      const response = modelJson(c, requestId, paginateModels(snapshot.models, query));
      auxiliaryCompleted = true;
      return response;
    } catch (error) {
      if (error instanceof ModelPaginationError) return modelError(c, requestId, "invalid_request_error", error.message, 400);
      return catalogFailure(c, error, requestId);
    }
    } finally { auxiliary?.release(auxiliaryCompleted); }
  });
  app.get("/v1/models/:model_id", requireModelsApi(env), async (c) => {
    const requestId = currentModelRequestId(c);
    let auxiliary: ReturnType<RoutingAttestation["beginAuxiliary"]> | undefined;
    let auxiliaryCompleted = false;
    try { auxiliary = routingAttestation?.beginAuxiliary(); }
    catch { return modelError(c, requestId, "api_error", "QA attestation target request already active", 503); }
    try {
    if (!authSession) return modelError(c, requestId, "api_error", "server auth session not initialized", 500);
    try { rejectUnexpectedQuery(c); }
    catch (error) { return modelError(c, requestId, "invalid_request_error", error instanceof Error ? error.message : "invalid query", 400); }
    // Hono 已对单个 path segment 做一次 URL 解码；再次 decodeURIComponent 会把 %252F 错误地解码两次。
    const modelId = c.req.param("model_id") ?? "";
    try {
      const snapshot = await authSession.listModels(c.req.raw.signal, auxiliary);
      auxiliary?.allowCatalogModels(snapshot.models.map((model) => model.key));
      auxiliary?.recordModelRetrieve();
      const model = findModelById(snapshot.models, modelId);
      if (!model) return modelError(c, requestId, "not_found_error", `model not found: ${modelId}`, 404);
      const response = modelJson(c, requestId, toAnthropicModelInfo(model));
      auxiliaryCompleted = true;
      return response;
    } catch (error) { return catalogFailure(c, error, requestId); }
    } finally { auxiliary?.release(auxiliaryCompleted); }
  });
  app.get("/internal/quota", requireApiKey(env, true), async (c) => {
    let auxiliary: ReturnType<RoutingAttestation["beginAuxiliary"]> | undefined;
    let auxiliaryCompleted = false;
    try { auxiliary = routingAttestation?.beginAuxiliary(); }
    catch { return c.json(apiError("api_error", "QA attestation target request already active"), 503); }
    try {
      if (!authSession) return c.json(apiError("api_error", "server auth session not initialized"), 500);
      try { rejectUnexpectedQuery(c); }
      catch { return c.json(apiError("invalid_request_error", "query parameters are not supported"), 400); }
      try {
        // QA auxiliary 必须等共享 quota/refresh operation 终结后才释放，不能让已取消 caller 的 signal 使 lease 提前失活。
        const response = c.json(statuslineQuota(await authSession.getQuotaUsage(routingAttestation ? undefined : c.req.raw.signal)));
        auxiliaryCompleted = true;
        return response;
      } catch (error) {
        const status = error instanceof QuotaUpstreamError ? error.status : undefined;
        if (status === 401) return c.json(apiError("authentication_error", "quota unavailable"), 401);
        if (status === 403) return c.json(apiError("permission_error", "quota unavailable"), 403);
        if (status === 429) return c.json(apiError("rate_limit_error", "quota unavailable"), 429);
        logger.error("配额读取失败", { errorClass: error instanceof Error ? error.name : "Error" });
        return c.json(apiError("api_error", "quota unavailable"), 502);
      }
    } finally { auxiliary?.release(auxiliaryCompleted); }
  });
  app.get("/internal/model-routing", requireApiKey(env, true), async (c) => {
    if (!authSession) return c.json(apiError("api_error", "server auth session not initialized"), 500);
    try { rejectUnexpectedQuery(c); }
    catch { return c.json(apiError("invalid_request_error", "query parameters are not supported"), 400); }
    const routingKey = env.QODER_CN_INFER_MODEL_KEY;
    if (!routingKey) return c.json(apiError("api_error", "runtime routing key is not configured"), 500);
    try {
      const snapshot = await authSession.listModels(c.req.raw.signal);
      const target = findModelById(snapshot.models, routingKey);
      if (!target) {
        return c.json(apiError("not_found_error", "runtime routing key unavailable"), 404);
      }
      if (expectedModelForRoutingKey(routingKey) !== undefined && !hasExpectedModelIdentity(target, routingKey)) {
        return c.json(apiError("not_found_error", "runtime routing model identity unavailable"), 404);
      }
      return c.json({ ok: true, routingKey, displayName: target.displayName, generation: snapshot.generation });
    } catch (error) {
      return catalogFailure(c, error);
    }
  });
  app.all("/internal/quota", requireApiKey(env, true), (c) => {
    c.header("allow", "GET");
    return c.json(apiError("invalid_request_error", "method not allowed"), 405);
  });
  app.post("/v1/messages/count_tokens", requireApiKey(env), async (c) => {
    let auxiliary: ReturnType<RoutingAttestation["beginAuxiliary"]> | undefined;
    try { auxiliary = routingAttestation?.beginAuxiliary(); }
    catch { return c.json(apiError("api_error", "QA attestation target request already active"), 503); }
    try {
      let body: Record<string, unknown>;
      try { body = JSON.parse(await c.req.text()); } catch { return c.json(apiError("invalid_request_error", "invalid JSON body"), 400); }
      return c.json({ input_tokens: estimateInputTokens(body) });
    } finally { auxiliary?.release(); }
  });
  app.post("/v1/messages", requireApiKey(env), async (c) => {
    let messageLease: ReturnType<RoutingAttestation["beginMessage"]> | undefined;
    try { messageLease = routingAttestation?.beginMessage(); }
    catch { return c.json(apiError("api_error", "QA attestation target request already active"), 503); }
    let releasedMessageLease = false;
    const releaseMessageLease = (): void => { if (!releasedMessageLease) { releasedMessageLease = true; messageLease?.release(); } };
    let anthropic: Record<string, unknown>;
    try { anthropic = JSON.parse(await c.req.text()); } catch { releaseMessageLease(); return c.json(apiError("invalid_request_error", "invalid JSON body"), 400); }
    let requestModel: string | undefined;
    try { requestModel = validateAnthropicRequestEnvelope(anthropic); }
    catch (error) { releaseMessageLease(); return c.json(apiError("invalid_request_error", error instanceof Error ? error.message : "invalid model"), 400); }
    if (!authSession) { releaseMessageLease(); return c.json(apiError("api_error", "server auth session not initialized"), 500); }
    const { controller: requestController, signal } = createRequestSignal(c, env);
    let snapshot: ModelCatalogSnapshot;
    try { snapshot = await authSession.listModels(signal, messageLease); }
    catch (error) {
      releaseMessageLease();
      if (signal.aborted) return c.json(apiError("api_error", "request aborted"), 500);
      return catalogFailure(c, error);
    }
    const resolveCurrentModel = (current: ModelCatalogSnapshot): { resolvedModel?: QoderAssistantModel; failure?: Response } => {
      const resolution = resolveModel(current.models, requestModel, env);
      if (resolution.model) return { resolvedModel: resolution.model };
      if (resolution.clientNotFound) return { failure: c.json(apiError("not_found_error", `model not found: ${requestModel}`), 404) };
      if (resolution.invalidDefault) {
        logger.error("配置的默认模型未启用", { configured: true });
        return { failure: c.json(apiError("api_error", "configured default model unavailable"), 500) };
      }
      return { failure: c.json(apiError("api_error", "no enabled default model available"), 500) };
    };
    let resolved = resolveCurrentModel(snapshot);
    if (resolved.failure) { releaseMessageLease(); return resolved.failure; }
    let resolvedModel = resolved.resolvedModel!;
    const tools = Array.isArray(anthropic.tools) ? anthropic.tools.length : 0;
    let attestation: ReturnType<RoutingMessageLease["claim"]> | undefined;
    const isAttestationTarget = requestModel === "qmodel_38max" && resolvedModel.key === "qmodel_38max";
    if (isAttestationTarget) {
      try {
        attestation = messageLease?.claim({ modelProvided: true, requestModel, resolvedModel: resolvedModel.key, tools, catalogModels: snapshot.models.map((model) => model.key) });
      } catch { releaseMessageLease(); return c.json(apiError("api_error", "QA attestation target request unavailable"), 503); }
    }
    let attestationFinalized = false;
    const finalizeAttestation = (completed: boolean): void => {
      try {
        if (attestation && !attestationFinalized) {
          attestationFinalized = true;
          attestation.finalize(completed);
        }
      } finally {
        releaseMessageLease();
      }
    };
    let conversion: CnConversion;
    try { conversion = convertAnthropicToCnBody(anthropic, resolvedModel); }
    catch (error) { finalizeAttestation(false); return c.json(apiError("invalid_request_error", error instanceof ConversionError ? error.message : "conversion failed"), 400); }
    logger.info("请求溯源", { truncated: conversion.provenance.maxTokensTruncated, originalMaxTokens: conversion.provenance.originalMaxTokens, cnMaxTokens: conversion.provenance.cnMaxTokens, ignoredFields: conversion.provenance.ignoredFields, modelProvided: conversion.provenance.requestedModel !== undefined, resolvedModel: resolvedModel.key });

    let bodyJson = JSON.stringify(conversion.body);
    const messageId = `msg_${randomUUID().replaceAll("-", "")}`;
    let attempt: SignedAttempt | undefined;
    let upstream: Response | undefined;
    try {
      try {
        attestation?.setPrepareInferModel(resolvedModel.key);
        attempt = authSession.createSignedAttempt(bodyJson, resolvedModel.key, snapshot.generation);
      } catch (error) {
        if (!(error instanceof StaleModelCatalogError)) throw error;
        snapshot = await authSession.listModels(signal, messageLease);
        resolved = resolveCurrentModel(snapshot);
        if (resolved.failure) { finalizeAttestation(false); return resolved.failure; }
        resolvedModel = resolved.resolvedModel!;
        attestation?.setResolvedModel(resolvedModel.key);
        conversion = convertAnthropicToCnBody(anthropic, resolvedModel);
        bodyJson = JSON.stringify(conversion.body);
        attestation?.setPrepareInferModel(resolvedModel.key);
        attempt = authSession.createSignedAttempt(bodyJson, resolvedModel.key, snapshot.generation);
      }
      attestation?.recordInference();
      upstream = await fetch(attempt.prepared.url, { method: "POST", headers: attempt.prepared.headers, body: attempt.prepared.body ?? bodyJson, signal });
      if (upstream.status === 401) {
        await discard(upstream);
        upstream = undefined;
        attempt.context.dispose();
        attempt = undefined;
        attestation?.recordRetry();
        await authSession.refreshAndReauthenticate(signal, messageLease);
        snapshot = await authSession.listModels(signal, messageLease);
        resolved = resolveCurrentModel(snapshot);
        if (resolved.failure) { finalizeAttestation(false); return resolved.failure; }
        resolvedModel = resolved.resolvedModel!;
        attestation?.setResolvedModel(resolvedModel.key);
        conversion = convertAnthropicToCnBody(anthropic, resolvedModel);
        bodyJson = JSON.stringify(conversion.body);
        attestation?.setPrepareInferModel(resolvedModel.key);
        attempt = authSession.createSignedAttempt(bodyJson, resolvedModel.key, snapshot.generation);
        attestation?.recordInference();
        upstream = await fetch(attempt.prepared.url, { method: "POST", headers: attempt.prepared.headers, body: attempt.prepared.body ?? bodyJson, signal });
      }
      if (!upstream.ok || !upstream.body) {
        const mapped = mapUpstreamStatus(upstream.status);
        await discard(upstream);
        finalizeAttestation(false);
        return c.json(apiError(mapped.type, `upstream HTTP ${upstream.status}`), mapped.httpStatus);
      }
      if (!isSse(upstream)) {
        await discard(upstream);
        finalizeAttestation(false);
        return c.json(apiError("api_error", "upstream returned non-SSE response"), 502);
      }
      attempt.context.dispose();
      attempt = undefined;
      if (anthropic.stream === true) {
        return new Response(emitAnthropicSseStream(upstream.body, messageId, resolvedModel.key, signal, () => requestController.abort(new Error("downstream cancelled")), finalizeAttestation), { headers: { "content-type": "text/event-stream", "cache-control": "no-cache" } });
      }
      const result = await collectAnthropicMessage(upstream.body, messageId, resolvedModel.key, signal);
      if (!result.ok) { finalizeAttestation(false); return c.json(apiError("api_error", "upstream stream error"), 502); }
      finalizeAttestation(true);
      return c.json(result.message);
    } catch (error) {
      await discard(upstream);
      finalizeAttestation(false);
      if (signal.aborted) { logger.warn("请求已取消", { messageId, aborted: true }); return c.json(apiError("api_error", "request aborted"), 500); }
      logger.error("代理请求失败", { errorClass: error instanceof Error ? error.name : "Error" });
      return c.json(apiError("api_error", "internal proxy error"), 500);
    } finally { attempt?.context.dispose(); }
  });
  return app;
}
export type { CnConversion, SessionLike };
