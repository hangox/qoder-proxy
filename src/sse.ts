// CN legacy SSE 帧解析 + Anthropic SSE 发射 / 非流式收集。

export const MAX_PARALLEL_TOOLS = 2;
const MAX_BUFFER_BYTES = 64 * 1024 * 1024;

export class SseProtocolError extends Error {}
export type WireFrame = { event: string; data: string };

function stripField(line: string, prefix: string): string {
  const rest = line.slice(prefix.length);
  return rest.startsWith(" ") ? rest.slice(1) : rest;
}

function decodeWireFrame(frame: string): WireFrame | undefined {
  let event = "message";
  const data: string[] = [];
  for (const line of frame.split("\n")) {
    if (line.startsWith("event:")) event = stripField(line, "event:");
    else if (line.startsWith("data:")) data.push(stripField(line, "data:"));
    else if (line && data.length > 0) data[data.length - 1] += line;
  }
  if (data.length === 0) return undefined;
  return { event, data: data.join("\n") };
}

// Supports delimiter frames and one valid final frame at EOF. Non-empty EOF junk fails closed.
export async function* parseSseFrames(body: ReadableStream<Uint8Array>, signal?: AbortSignal): AsyncGenerator<WireFrame> {
  const reader = body.getReader();
  try {
    const dec = new TextDecoder();
    let buf = "", pendingCr = false;
    while (true) {
      if (signal?.aborted) return;
      const { done, value } = await reader.read();
      let decoded = dec.decode(value, { stream: !done });
      if (pendingCr) { decoded = `\r${decoded}`; pendingCr = false; }
      if (!done && decoded.endsWith("\r")) { decoded = decoded.slice(0, -1); pendingCr = true; }
      buf += decoded.replaceAll("\r\n", "\n").replaceAll("\r", "\n");
      if (Buffer.byteLength(buf, "utf8") > MAX_BUFFER_BYTES) throw new SseProtocolError("SSE 缓冲超过 64 MiB 上限");
      let boundary: number;
      while ((boundary = buf.indexOf("\n\n")) >= 0) {
        const raw = buf.slice(0, boundary);
        buf = buf.slice(boundary + 2);
        const decoded = decodeWireFrame(raw);
        if (decoded) yield decoded;
      }
      if (!done) continue;
      if (pendingCr) { buf += "\n"; pendingCr = false; }
      if (buf.length > 0) {
        const decoded = decodeWireFrame(buf);
        if (!decoded) throw new SseProtocolError("SSE EOF 残余帧没有 data 字段");
        yield decoded;
      }
      break;
    }
  } finally {
    if (body.locked) { await reader.cancel().catch(() => undefined); reader.releaseLock(); }
  }
}

const KNOWN_SSE_EVENTS = new Set(["message", "finish", "error"]);
const SUPPORTED_FINISH_REASONS = new Set(["stop", "tool_calls", "length"]);
const DONE_SENTINEL = Symbol("done");
type LegacyUsage = { prompt_tokens?: number; completion_tokens?: number; total_tokens?: number } & Record<string, unknown>;
type LegacyToolCallDelta = { index: number; id?: string; function?: { name?: string; arguments?: string } };
type LegacyChoice = { index?: number; delta?: { content?: string; tool_calls?: LegacyToolCallDelta[] }; finish_reason?: string | null; usage?: LegacyUsage };
type LegacyChunk = { choices?: LegacyChoice[]; usage?: LegacyUsage; error?: unknown };
type LegacyEnvelope = { body?: string } & LegacyChunk;
export type ToolCallDeltaWithChoice = { choiceIndex: number; delta: LegacyToolCallDelta };
export type ParsedFrame =
  | { kind: "done"; event: string }
  | { kind: "error"; event: string; message: string }
  | { kind: "message" | "finish"; event: string; semanticChoiceIndex?: number; contentDelta?: string; toolCallDeltas?: ToolCallDeltaWithChoice[]; finishReason?: string; usage?: LegacyUsage };

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const keys = Object.keys(value as Record<string, unknown>).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify((value as Record<string, unknown>)[k])}`).join(",")}}`;
}
function extractErrorMessage(data: string, chunkError: unknown): string {
  if (chunkError !== undefined && chunkError !== null) return typeof chunkError === "string" ? chunkError : stableStringify(chunkError);
  try { const parsed = JSON.parse(data); return typeof parsed === "string" ? parsed : stableStringify(parsed); } catch { return data; }
}
function unwrapLegacyChunk(data: string): unknown | typeof DONE_SENTINEL {
  let outer: unknown;
  try { outer = JSON.parse(data); } catch { throw new SseProtocolError("legacy SSE 帧 JSON 解析失败"); }
  if (typeof outer === "object" && outer !== null && !Array.isArray(outer) && Object.prototype.hasOwnProperty.call(outer, "body")) {
    const body = (outer as Record<string, unknown>).body;
    if (typeof body !== "string") throw new SseProtocolError("legacy SSE envelope.body 必须是 string");
    if (body === "[DONE]") return DONE_SENTINEL;
    try { return JSON.parse(body); } catch { throw new SseProtocolError("legacy SSE body 内层 JSON 解析失败"); }
  }
  return outer;
}
function validateUsage(usage: unknown): LegacyUsage | undefined {
  if (usage === undefined) return undefined;
  if (typeof usage !== "object" || usage === null || Array.isArray(usage)) throw new SseProtocolError("legacy SSE usage 不是 object");
  for (const key of ["prompt_tokens", "completion_tokens", "total_tokens"] as const) {
    const value = (usage as Record<string, unknown>)[key];
    if (value !== undefined && !(typeof value === "number" && Number.isInteger(value) && value >= 0)) throw new SseProtocolError(`legacy SSE usage.${key} 必须是非负整数`);
  }
  return usage as LegacyUsage;
}
function validateToolCallDelta(value: unknown): LegacyToolCallDelta {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new SseProtocolError("legacy SSE tool_call delta 不是 object");
  const delta = value as Record<string, unknown>;
  if (!(typeof delta.index === "number" && Number.isInteger(delta.index) && delta.index >= 0)) throw new SseProtocolError("legacy SSE tool_call index 必须是非负整数");
  if (delta.id !== undefined && typeof delta.id !== "string") throw new SseProtocolError("legacy SSE tool_call id 必须是 string");
  if (delta.function !== undefined) {
    if (typeof delta.function !== "object" || delta.function === null || Array.isArray(delta.function)) throw new SseProtocolError("legacy SSE tool_call function 不是 object");
    const fn = delta.function as Record<string, unknown>;
    if (fn.name !== undefined && typeof fn.name !== "string") throw new SseProtocolError("legacy SSE tool_call name 必须是 string");
    if (fn.arguments !== undefined && typeof fn.arguments !== "string") throw new SseProtocolError("legacy SSE tool_call arguments 必须是 string");
  }
  return value as LegacyToolCallDelta;
}
export function parseLegacyFrame(event: string, data: string): ParsedFrame {
  if (!KNOWN_SSE_EVENTS.has(event)) throw new SseProtocolError(`legacy SSE 未知事件类型: ${event}`);
  if (data === "[DONE]") {
    if (event !== "message") throw new SseProtocolError("legacy SSE [DONE] 仅允许 message 事件");
    return { kind: "done", event };
  }
  if (event === "error") return { kind: "error", event, message: extractErrorMessage(data, undefined) };
  const unwrapped = unwrapLegacyChunk(data);
  if (unwrapped === DONE_SENTINEL) {
    if (event !== "message") throw new SseProtocolError("legacy SSE [DONE] 仅允许 message 事件");
    return { kind: "done", event };
  }
  if (typeof unwrapped !== "object" || unwrapped === null || Array.isArray(unwrapped)) throw new SseProtocolError("legacy SSE payload 根必须是 object");
  const chunk = unwrapped as LegacyChunk;
  if (event === "finish") {
    const record = unwrapped as Record<string, unknown>;
    const allowed = new Set(["firstTokenDuration", "serverDuration", "totalDuration"]);
    for (const key of Object.keys(record)) if (!allowed.has(key)) throw new SseProtocolError(`legacy SSE event:finish 字段不受支持: ${key}`);
    for (const key of allowed) { const value = record[key]; if (value !== undefined && !(typeof value === "number" && Number.isFinite(value) && value >= 0)) throw new SseProtocolError(`legacy SSE event:finish ${key} 必须是非负有限数`); }
    return { kind: "finish", event };
  }
  if (chunk.error !== undefined && chunk.error !== null) return { kind: "error", event, message: extractErrorMessage(data, chunk.error) };
  if (chunk.choices !== undefined && !Array.isArray(chunk.choices)) throw new SseProtocolError("legacy SSE choices 不是数组");
  const choices = chunk.choices ?? [];
  let semanticChoices = 0;
  let semanticChoiceIndex: number | undefined;
  let contentDelta: string | undefined;
  let finishReason: string | undefined;
  let usage = validateUsage(chunk.usage);
  const toolCallDeltas: ToolCallDeltaWithChoice[] = [];
  choices.forEach((choice, choiceOffset) => {
    if (typeof choice !== "object" || choice === null || Array.isArray(choice)) throw new SseProtocolError(`legacy SSE choice ${choiceOffset} 不是 object`);
    if (choice.index !== undefined && !(typeof choice.index === "number" && Number.isInteger(choice.index) && choice.index >= 0)) throw new SseProtocolError("legacy SSE choice.index 必须是非负整数");
    if (choice.delta !== undefined && (typeof choice.delta !== "object" || choice.delta === null || Array.isArray(choice.delta))) throw new SseProtocolError("legacy SSE delta 不是 object");
    if (choice.delta?.content !== undefined && typeof choice.delta.content !== "string") throw new SseProtocolError("legacy SSE delta.content 必须是 string");
    if (choice.delta?.tool_calls !== undefined && !Array.isArray(choice.delta.tool_calls)) throw new SseProtocolError("legacy SSE delta.tool_calls 不是数组");
    const rawFinishReason = choice.finish_reason;
    if (rawFinishReason !== undefined && rawFinishReason !== null && typeof rawFinishReason !== "string") throw new SseProtocolError("legacy SSE finish_reason 必须是 string/null");
    if (typeof rawFinishReason === "string" && !SUPPORTED_FINISH_REASONS.has(rawFinishReason)) throw new SseProtocolError(`legacy SSE finish_reason 不受支持: ${rawFinishReason}`);
    const choiceUsage = validateUsage(choice.usage);
    if (choiceUsage) usage = usage ? { ...usage, ...choiceUsage } : choiceUsage;
    const deltas = (choice.delta?.tool_calls ?? []).map((delta) => ({ choiceIndex: choice.index ?? 0, delta: validateToolCallDelta(delta) }));
    const semantic = choice.delta?.content !== undefined || deltas.length > 0 || typeof rawFinishReason === "string";
    if (semantic && ++semanticChoices > 1) throw new SseProtocolError("legacy SSE 单帧包含多个语义 choice");
    if (semantic) {
      semanticChoiceIndex = choice.index ?? 0;
      contentDelta = choice.delta?.content;
      finishReason = rawFinishReason ?? undefined;
      toolCallDeltas.push(...deltas);
    }
  });
  return { kind: finishReason ? "finish" : "message", event, semanticChoiceIndex, contentDelta, toolCallDeltas: toolCallDeltas.length > 0 ? toolCallDeltas : undefined, finishReason, usage };
}

export type CompletedToolCall = { choiceIndex: number; index: number; id: string; name: string; arguments: string; fragmentCount: number };
export function aggregateToolCallDeltas(deltas: ToolCallDeltaWithChoice[] | undefined, calls: Map<string, CompletedToolCall>): void {
  for (const { choiceIndex, delta } of deltas ?? []) {
    if (!Number.isInteger(delta.index) || delta.index < 0) throw new SseProtocolError(`tool_call delta 缺少合法 index: choiceIndex=${choiceIndex}`);
    const key = `${choiceIndex}:${delta.index}`;
    const call = calls.get(key) ?? { choiceIndex, index: delta.index, id: "", name: "", arguments: "", fragmentCount: 0 };
    if (delta.id && call.id && delta.id !== call.id) throw new SseProtocolError(`tool_call id 冲突: ${key}`);
    if (delta.function?.name && call.name && delta.function.name !== call.name) throw new SseProtocolError(`tool_call name 冲突: ${key}`);
    if (delta.id) call.id = delta.id;
    if (delta.function?.name) call.name = delta.function.name;
    call.arguments += delta.function?.arguments ?? "";
    call.fragmentCount++;
    calls.set(key, call);
  }
}
export function finalizeToolCall(call: CompletedToolCall): { id: string; name: string; argumentsJson: string } {
  if (!call.id) throw new SseProtocolError(`完成态 tool_call 缺少非空 id: choiceIndex=${call.choiceIndex}, index=${call.index}`);
  if (!call.name) throw new SseProtocolError(`完成态 tool_call 缺少非空 name: choiceIndex=${call.choiceIndex}, index=${call.index}`);
  if (!call.arguments) return { id: call.id, name: call.name, argumentsJson: "{}" };
  let parsed: unknown;
  try { parsed = JSON.parse(call.arguments); } catch { throw new SseProtocolError(`完成态 tool_call arguments 非合法 JSON: ${call.id}`); }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new SseProtocolError(`完成态 tool_call arguments 不是 JSON object: ${call.id}`);
  return { id: call.id, name: call.name, argumentsJson: call.arguments };
}
function mapUsage(usage: LegacyUsage | undefined) { return { input_tokens: usage?.prompt_tokens ?? 0, output_tokens: usage?.completion_tokens ?? 0 }; }
function mapStopReason(reason: string | undefined): string { return reason === "tool_calls" ? "tool_use" : reason === "length" ? "max_tokens" : "end_turn"; }

type TerminalState = { finishReason?: string; doneObserved: boolean; finishEventObserved: boolean };
type FramePhase = "semantic" | "semantic-finish" | "usage" | "bookkeeping";
function advanceTerminalState(frame: ParsedFrame, state: TerminalState): FramePhase {
  if (state.finishEventObserved) throw new SseProtocolError("legacy SSE event:finish 之后仍有帧");
  if (state.doneObserved) {
    if (frame.kind === "finish" && frame.event === "finish" && frame.finishReason === undefined) {
      state.finishEventObserved = true;
      return "bookkeeping";
    }
    throw new SseProtocolError("legacy SSE [DONE] 之后帧顺序非法");
  }
  if (state.finishReason !== undefined) {
    if (frame.kind === "message" && frame.contentDelta === undefined && frame.toolCallDeltas === undefined && frame.finishReason === undefined && frame.usage !== undefined) return "usage";
    if (frame.kind === "done") { state.doneObserved = true; return "bookkeeping"; }
    throw new SseProtocolError("legacy SSE finish_reason 之后包含非法语义帧");
  }
  if (frame.kind === "done") { state.doneObserved = true; return "bookkeeping"; }
  if (frame.kind === "finish") {
    if (frame.finishReason === undefined) throw new SseProtocolError("legacy SSE event:finish 缺少前置终止帧");
    state.finishReason = frame.finishReason;
    return "semantic-finish";
  }
  return "semantic";
}

export function emitAnthropicSseStream(cnBody: ReadableStream<Uint8Array> | null, messageId: string, model: string, signal?: AbortSignal, abortUpstream?: () => void, onCompleted?: (completed: boolean) => void): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  let cancelled = false;
  let completionReported = false;
  const reportCompletion = (completed: boolean) => {
    if (!completionReported) { completionReported = true; onCompleted?.(completed); }
  };
  return new ReadableStream<Uint8Array>({
    async start(controller) {
      let closed = false;
      const close = () => { if (!closed) { closed = true; try { controller.close(); } catch {} } };
      const emit = (event: string, data: unknown) => { if (!closed && !cancelled) controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)); };
      const abort = () => cancelled || signal?.aborted;
      if (abort()) { reportCompletion(false); close(); return; }
      emit("message_start", { type: "message_start", message: { id: messageId, type: "message", role: "assistant", content: [], model, stop_reason: null, stop_sequence: null, usage: { input_tokens: 0, output_tokens: 0 } } });
      if (!cnBody) { emit("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 0 } }); emit("message_stop", { type: "message_stop" }); reportCompletion(true); close(); return; }
      let contentIndex = 0, textOpen = false, errored = false, semanticChoiceIndex: number | undefined, usage: LegacyUsage | undefined;
      const terminal: TerminalState = { doneObserved: false, finishEventObserved: false };
      const calls = new Map<string, CompletedToolCall>();
      const closeText = () => { if (textOpen) { emit("content_block_stop", { type: "content_block_stop", index: contentIndex++ }); textOpen = false; } };
      try {
        for await (const wire of parseSseFrames(cnBody, signal)) {
          if (abort()) break;
          const frame = parseLegacyFrame(wire.event, wire.data);
          const phase = advanceTerminalState(frame, terminal);
          if (phase === "bookkeeping" || frame.kind === "done") continue;
          if (frame.kind === "error") { closeText(); emit("error", { type: "error", error: { type: "api_error", message: "upstream error" } }); errored = true; break; }
          if (phase === "usage") { usage = usage ? { ...usage, ...frame.usage } : frame.usage; continue; }
          if (frame.semanticChoiceIndex !== undefined) {
            if (semanticChoiceIndex !== undefined && frame.semanticChoiceIndex !== semanticChoiceIndex) throw new SseProtocolError("legacy SSE semantic choice index 发生变化");
            semanticChoiceIndex = frame.semanticChoiceIndex;
          }
          if (frame.contentDelta) { if (!textOpen) { emit("content_block_start", { type: "content_block_start", index: contentIndex, content_block: { type: "text", text: "" } }); textOpen = true; } emit("content_block_delta", { type: "content_block_delta", index: contentIndex, delta: { type: "text_delta", text: frame.contentDelta } }); }
          try { aggregateToolCallDeltas(frame.toolCallDeltas, calls); } catch { closeText(); emit("error", { type: "error", error: { type: "api_error", message: "tool_call 聚合失败" } }); errored = true; break; }
          if (calls.size > MAX_PARALLEL_TOOLS) { closeText(); emit("error", { type: "error", error: { type: "api_error", message: `并行工具超过上限 ${MAX_PARALLEL_TOOLS}` } }); errored = true; break; }
          if (frame.usage) usage = usage ? { ...usage, ...frame.usage } : frame.usage;
          if (phase === "semantic-finish") {
            closeText();
            if (calls.size > 0 && terminal.finishReason !== "tool_calls") { emit("error", { type: "error", error: { type: "api_error", message: "tool_call 缺少 finish_reason=tool_calls" } }); errored = true; break; }
            if (terminal.finishReason === "tool_calls" && calls.size === 0) { emit("error", { type: "error", error: { type: "api_error", message: "finish_reason=tool_calls 但没有 tool_call" } }); errored = true; break; }
          }
        }
      } catch {
        if (!abort()) { closeText(); emit("error", { type: "error", error: { type: "api_error", message: "proxy stream error" } }); errored = true; }
      }
      if (!errored && !abort() && !terminal.doneObserved && terminal.finishReason === undefined) { closeText(); emit("error", { type: "error", error: { type: "api_error", message: "upstream stream truncated" } }); errored = true; }
      if (!errored && !abort() && calls.size > 0 && terminal.finishReason !== "tool_calls") { closeText(); emit("error", { type: "error", error: { type: "api_error", message: "tool_call 缺少 finish_reason=tool_calls" } }); errored = true; }
      if (!errored && !abort() && terminal.finishReason === "tool_calls") {
        for (const call of [...calls.values()].sort((a, b) => a.choiceIndex - b.choiceIndex || a.index - b.index)) {
          let final: { id: string; name: string; argumentsJson: string };
          try { final = finalizeToolCall(call); } catch { emit("error", { type: "error", error: { type: "api_error", message: "tool_call 缺少 id/name 或 arguments 非法" } }); errored = true; break; }
          emit("content_block_start", { type: "content_block_start", index: contentIndex, content_block: { type: "tool_use", id: final.id, name: final.name, input: {} } });
          emit("content_block_delta", { type: "content_block_delta", index: contentIndex, delta: { type: "input_json_delta", partial_json: final.argumentsJson } });
          emit("content_block_stop", { type: "content_block_stop", index: contentIndex++ });
        }
      }
      if (!errored && !abort()) { closeText(); emit("message_delta", { type: "message_delta", delta: { stop_reason: mapStopReason(terminal.finishReason), stop_sequence: null }, usage: mapUsage(usage) }); emit("message_stop", { type: "message_stop" }); reportCompletion(true); }
      else reportCompletion(false);
      close();
    },
    cancel() { cancelled = true; reportCompletion(false); abortUpstream?.(); },
  });
}

export type AnthropicMessageResult = { ok: true; message: Record<string, unknown> } | { ok: false; errorMessage: string };
export async function collectAnthropicMessage(cnBody: ReadableStream<Uint8Array> | null, messageId: string, model: string, signal?: AbortSignal): Promise<AnthropicMessageResult> {
  if (!cnBody) return { ok: true, message: { id: messageId, type: "message", role: "assistant", content: [], model, stop_reason: "end_turn", stop_sequence: null, usage: { input_tokens: 0, output_tokens: 0 } } };
  let text = "", semanticChoiceIndex: number | undefined, usage: LegacyUsage | undefined;
  const terminal: TerminalState = { doneObserved: false, finishEventObserved: false };
  const calls = new Map<string, CompletedToolCall>();
  try {
    for await (const wire of parseSseFrames(cnBody, signal)) {
      if (signal?.aborted) return { ok: false, errorMessage: "aborted" };
      const frame = parseLegacyFrame(wire.event, wire.data);
      const phase = advanceTerminalState(frame, terminal);
      if (phase === "bookkeeping" || frame.kind === "done") continue;
      if (frame.kind === "error") return { ok: false, errorMessage: frame.message };
      if (phase === "usage") { usage = usage ? { ...usage, ...frame.usage } : frame.usage; continue; }
      if (frame.semanticChoiceIndex !== undefined) {
        if (semanticChoiceIndex !== undefined && frame.semanticChoiceIndex !== semanticChoiceIndex) throw new SseProtocolError("legacy SSE semantic choice index 发生变化");
        semanticChoiceIndex = frame.semanticChoiceIndex;
      }
      if (frame.contentDelta) text += frame.contentDelta;
      aggregateToolCallDeltas(frame.toolCallDeltas, calls);
      if (calls.size > MAX_PARALLEL_TOOLS) return { ok: false, errorMessage: `并行工具超过上限 ${MAX_PARALLEL_TOOLS}` };
      if (frame.usage) usage = usage ? { ...usage, ...frame.usage } : frame.usage;
      if (phase === "semantic-finish") {
        if (calls.size > 0 && terminal.finishReason !== "tool_calls") return { ok: false, errorMessage: "tool_call 缺少 finish_reason=tool_calls" };
        if (terminal.finishReason === "tool_calls" && calls.size === 0) return { ok: false, errorMessage: "finish_reason=tool_calls 但没有 tool_call" };
      }
    }
  } catch (e) { return { ok: false, errorMessage: e instanceof Error ? e.message : "proxy stream error" }; }
  if (!terminal.doneObserved && terminal.finishReason === undefined) return { ok: false, errorMessage: "upstream stream truncated" };
  if (calls.size > 0 && terminal.finishReason !== "tool_calls") return { ok: false, errorMessage: "tool_call 缺少 finish_reason=tool_calls" };
  const content: Array<Record<string, unknown>> = text ? [{ type: "text", text }] : [];
  for (const call of [...calls.values()].sort((a, b) => a.choiceIndex - b.choiceIndex || a.index - b.index)) { try { const final = finalizeToolCall(call); content.push({ type: "tool_use", id: final.id, name: final.name, input: JSON.parse(final.argumentsJson) }); } catch (e) { return { ok: false, errorMessage: e instanceof Error ? e.message : "tool_call 非法" }; } }
  return { ok: true, message: { id: messageId, type: "message", role: "assistant", content, model, stop_reason: mapStopReason(terminal.finishReason), stop_sequence: null, usage: mapUsage(usage) } };
}
