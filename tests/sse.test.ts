import { describe, it, expect } from "vitest";
import { parseSseFrames, parseLegacyFrame, SseProtocolError, emitAnthropicSseStream, collectAnthropicMessage } from "../src/sse.ts";

function streamFromChunks(chunks: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  let i = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (i >= chunks.length) { controller.close(); return; }
      controller.enqueue(encoder.encode(chunks[i]!));
      i++;
    },
  });
}

async function collectWireFrames(chunks: string[]) {
  const frames = [];
  for await (const f of parseSseFrames(streamFromChunks(chunks))) frames.push(f);
  return frames;
}

// Builds a CN legacy double-envelope "message" wire frame carrying an OpenAI-style chunk.
function envelopeFrame(chunk: unknown): string {
  return `event: message\ndata: ${JSON.stringify({ body: JSON.stringify(chunk) })}\n\n`;
}

describe("parseSseFrames (wire level)", () => {
  it("parses a simple event/data pair split across chunks (half packet)", async () => {
    const frames = await collectWireFrames(["event: message\ndata: {\"a\":1}", "\n\n"]);
    expect(frames).toEqual([{ event: "message", data: '{"a":1}' }]);
  });

  it("normalizes CRLF line endings", async () => {
    const frames = await collectWireFrames(["event: message\r\ndata: hi\r\n\r\n"]);
    expect(frames).toEqual([{ event: "message", data: "hi" }]);
  });

  it("normalizes CRLF when carriage return and newline split across chunks", async () => {
    const frames = await collectWireFrames(["event: message\r", "\ndata: hi\r", "\n\r", "\n"]);
    expect(frames).toEqual([{ event: "message", data: "hi" }]);
  });

  it("joins multiple data: lines with \\n and handles bare continuation lines", async () => {
    const frames = await collectWireFrames(['data: {"a":1,\ndata: "b":2}\ncontinued\n\n']);
    expect(frames[0]?.data).toBe('{"a":1,\n"b":2}continued');
  });

  it("defaults event to message when no event: line is present", async () => {
    const frames = await collectWireFrames(["data: [DONE]\n\n"]);
    expect(frames).toEqual([{ event: "message", data: "[DONE]" }]);
  });

  it("handles multiple frames packed into one chunk (packet coalescing)", async () => {
    const frames = await collectWireFrames(["data: one\n\ndata: two\n\n"]);
    expect(frames.map((f) => f.data)).toEqual(["one", "two"]);
  });

  it("parses a valid final frame at EOF without a blank-line delimiter", async () => {
    expect(await collectWireFrames(["event: message\ndata: tail"])).toEqual([{ event: "message", data: "tail" }]);
  });

  it("fails closed on malformed nonempty EOF residue", async () => {
    await expect(collectWireFrames(["event: message"])).rejects.toThrow(SseProtocolError);
  });
});

describe("parseLegacyFrame (double-envelope classification)", () => {
  it("classifies [DONE] as done", () => {
    expect(parseLegacyFrame("message", "[DONE]").kind).toBe("done");
  });

  it("unwraps the double envelope and detects [DONE] inside body", () => {
    const frame = parseLegacyFrame("message", JSON.stringify({ body: "[DONE]" }));
    expect(frame.kind).toBe("done");
  });

  it("extracts contentDelta from an envelope-wrapped chunk", () => {
    const frame = parseLegacyFrame("message", JSON.stringify({ body: JSON.stringify({ choices: [{ index: 0, delta: { content: "hi" } }] }) }));
    expect(frame.kind).toBe("message");
    if (frame.kind === "message" || frame.kind === "finish") expect(frame.contentDelta).toBe("hi");
  });

  it("treats a bare event:finish frame with Gate 0 duration fields as finish without a finishReason", () => {
    const frame = parseLegacyFrame("finish", JSON.stringify({ firstTokenDuration: 1, serverDuration: 1.5, totalDuration: 2 }));
    expect(frame.kind).toBe("finish");
    if (frame.kind === "finish") expect(frame.finishReason).toBeUndefined();
  });

  it("classifies a chunk carrying finish_reason as finish with the reason", () => {
    const frame = parseLegacyFrame("message", JSON.stringify({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }));
    expect(frame.kind).toBe("finish");
    if (frame.kind === "finish") expect(frame.finishReason).toBe("stop");
  });

  it("classifies event:error as error", () => {
    const frame = parseLegacyFrame("error", JSON.stringify({ code: 500, message: "boom" }));
    expect(frame.kind).toBe("error");
  });

  it("classifies chunk.error as error even under event:message", () => {
    const frame = parseLegacyFrame("message", JSON.stringify({ error: { message: "boom" } }));
    expect(frame.kind).toBe("error");
  });

  it("fails closed on an unknown wire event, including raw DONE", () => {
    expect(() => parseLegacyFrame("unknown-event", "{}")).toThrow(SseProtocolError);
    expect(() => parseLegacyFrame("unknown-event", "[DONE]")).toThrow(SseProtocolError);
  });

  it("rejects DONE on non-message events", () => {
    expect(() => parseLegacyFrame("error", "[DONE]")).toThrow(/仅允许 message/);
    expect(() => parseLegacyFrame("finish", "[DONE]")).toThrow(/仅允许 message/);
  });

  it.each([[42], [null], [[]]])("rejects non-string envelope body: %j", (body) => {
    expect(() => parseLegacyFrame("message", JSON.stringify({ body }))).toThrow(/envelope.body 必须是 string/);
  });

  it("validates event:finish bookkeeping schema", () => {
    expect(parseLegacyFrame("finish", JSON.stringify({ firstTokenDuration: 1, serverDuration: 1.5, totalDuration: 2 })).kind).toBe("finish");
    for (const payload of [42, [], { choices: [] }, { usage: {} }, { error: "x" }, { body: "x" }, { firstTokenDuration: "1" }, { serverDuration: -1 }, { serverDuration: "1" }, { extra: 1 }]) {
      expect(() => parseLegacyFrame("finish", JSON.stringify(payload))).toThrow(SseProtocolError);
    }
  });

  it("propagates usage from chunk-level or choice-level", () => {
    const chunkLevel = parseLegacyFrame("message", JSON.stringify({ choices: [], usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 } }));
    if (chunkLevel.kind === "message") expect(chunkLevel.usage?.total_tokens).toBe(5);
  });

  it.each(["content_filter", 7])("rejects unsupported or non-string finish_reason: %j", (finish_reason) => {
    expect(() => parseLegacyFrame("message", JSON.stringify({ choices: [{ index: 0, delta: {}, finish_reason }] }))).toThrow(SseProtocolError);
  });

  it("rejects non-object inner roots", () => {
    for (const root of [42, []]) expect(() => parseLegacyFrame("message", JSON.stringify({ body: JSON.stringify(root) }))).toThrow(/根必须是 object/);
  });

  it("rejects non-string content deltas", () => {
    expect(() => parseLegacyFrame("message", JSON.stringify({ choices: [{ index: 0, delta: { content: 42 } }] }))).toThrow(/content/);
  });

  it("validates later choices and rejects multiple semantic choices", () => {
    expect(() => parseLegacyFrame("message", JSON.stringify({ choices: [
      { index: 0, delta: {}, finish_reason: "stop" },
      { index: 1, delta: {}, finish_reason: "content_filter" },
    ] }))).toThrow(/finish_reason/);
    expect(() => parseLegacyFrame("message", JSON.stringify({ choices: [
      { index: 0, delta: {}, finish_reason: "stop" },
      { index: 1, delta: { content: 42 } },
    ] }))).toThrow(/content/);
    expect(() => parseLegacyFrame("message", JSON.stringify({ choices: [
      { index: 0, delta: { content: "a" } },
      { index: 1, delta: { content: "b" } },
    ] }))).toThrow(/多个语义 choice/);
  });

  it("validates malformed usage and tool fields in later choices", () => {
    expect(() => parseLegacyFrame("message", JSON.stringify({ choices: [{ index: 0, delta: {} }, { index: 1, usage: { prompt_tokens: -1 } }] }))).toThrow(/usage/);
    expect(() => parseLegacyFrame("message", JSON.stringify({ choices: [{ index: 0, delta: {} }, { index: 1, delta: { tool_calls: "bad" } }] }))).toThrow(/tool_calls/);
  });

  it.each(["3", -1, Number.NaN])("rejects malformed usage token value: %j", (completion_tokens) => {
    expect(() => parseLegacyFrame("message", JSON.stringify({ choices: [], usage: { completion_tokens } }))).toThrow(/usage/);
  });

  it.each([
    { index: "0", id: "t", function: { name: "a", arguments: "{}" } },
    { index: -1, id: "t", function: { name: "a", arguments: "{}" } },
    { index: 0, id: 7, function: { name: "a", arguments: "{}" } },
    { index: 0, id: "t", function: { name: 7, arguments: "{}" } },
    { index: 0, id: "t", function: { name: "a", arguments: {} } },
  ])("rejects malformed tool_call delta: %j", (toolCall) => {
    expect(() => parseLegacyFrame("message", JSON.stringify({ choices: [{ index: 0, delta: { tool_calls: [toolCall] } }] }))).toThrow(SseProtocolError);
  });
});

describe("emitAnthropicSseStream", () => {
  async function collectAnthropicEvents(body: ReadableStream<Uint8Array> | null, model = "claude-x") {
    const stream = emitAnthropicSseStream(body, "msg_test", model);
    const reader = stream.getReader();
    const decoder = new TextDecoder();
    let text = "";
    while (true) {
      const { done, value } = await reader.read();
      if (value) text += decoder.decode(value);
      if (done) break;
    }
    const events = [...text.matchAll(/^event: (.+)$/gm)].map((m) => m[1]);
    return { text, events };
  }

  it("streams text deltas and ends with message_delta + message_stop on normal completion", async () => {
    const body = streamFromChunks([
      envelopeFrame({ choices: [{ index: 0, delta: { content: "hello" } }] }),
      envelopeFrame({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }),
      `event: message\ndata: ${JSON.stringify({ body: "[DONE]" })}\n\n`,
    ]);
    const { events, text } = await collectAnthropicEvents(body);
    expect(events).toEqual(["message_start", "content_block_start", "content_block_delta", "content_block_stop", "message_delta", "message_stop"]);
    expect(text).toContain('"stop_reason":"end_turn"');
  });

  it.each([
    "event: bogus\ndata: [DONE]\n\n",
    "event: error\ndata: [DONE]\n\n",
    "event: finish\ndata: [DONE]\n\n",
  ])("rejects raw DONE outside the verified message path: %s", async (wire) => {
    const { events } = await collectAnthropicEvents(streamFromChunks([wire]));
    expect(events).toContain("error");
    expect(events).not.toContain("message_delta");
    expect(events).not.toContain("message_stop");
  });

  it("emits event:error and NEVER sends message_stop afterwards", async () => {
    const body = streamFromChunks([`event: error\ndata: ${JSON.stringify({ code: 500, message: "boom" })}\n\n`]);
    const { events } = await collectAnthropicEvents(body);
    expect(events[0]).toBe("message_start");
    expect(events).toContain("error");
    expect(events).not.toContain("message_stop");
    expect(events).not.toContain("message_delta");
  });

  it("fails closed when semantic choice index changes across frames", async () => {
    const body = streamFromChunks([
      envelopeFrame({ choices: [{ index: 0, delta: { content: "a" } }] }),
      envelopeFrame({ choices: [{ index: 1, delta: { content: "b" } }] }),
      envelopeFrame({ choices: [{ index: 1, delta: {}, finish_reason: "stop" }] }),
    ]);
    const { events } = await collectAnthropicEvents(body);
    expect(events).toContain("error");
    expect(events).not.toContain("message_delta");
    expect(events).not.toContain("message_stop");
  });

  it.each([
    42,
    [],
    { choices: [{ index: 0, delta: {}, finish_reason: "content_filter" }] },
    { choices: [{ index: 0, delta: {}, finish_reason: 7 }] },
    { choices: [{ index: 0, delta: { content: 42 } }] },
    { choices: [{ index: 0, delta: {}, finish_reason: "stop" }, { index: 1, delta: {}, finish_reason: "content_filter" }] },
    { choices: [{ index: 0, delta: {}, finish_reason: "stop" }, { index: 1, delta: { content: 42 } }] },
    { choices: [{ index: 0, delta: {} }, { index: 1, usage: { total_tokens: -1 } }] },
    { choices: [{ index: 0, delta: {} }, { index: 1, delta: { tool_calls: "bad" } }] },
    { choices: [], usage: { completion_tokens: -1 } },
    { choices: [{ index: 0, delta: { tool_calls: [{ index: "0", id: "t", function: { name: "a", arguments: "{}" } }] } }] },
  ])("fails closed before normal terminal success for malformed frame: %j", async (chunk) => {
    const { events } = await collectAnthropicEvents(streamFromChunks([envelopeFrame(chunk)]));
    expect(events).toContain("error");
    expect(events).not.toContain("message_delta");
    expect(events).not.toContain("message_stop");
  });

  it("fails closed when EOF follows text deltas without terminal evidence", async () => {
    const body = streamFromChunks([envelopeFrame({ choices: [{ index: 0, delta: { content: "partial" } }] })]);
    const { events, text } = await collectAnthropicEvents(body);
    expect(events).toContain("content_block_delta");
    expect(events).toContain("error");
    expect(events).not.toContain("message_delta");
    expect(events).not.toContain("message_stop");
    expect(text).toContain("upstream stream truncated");
  });

  it("accepts [DONE] as terminal evidence even without finish_reason", async () => {
    const body = streamFromChunks([
      envelopeFrame({ choices: [{ index: 0, delta: { content: "done" } }] }),
      `event: message\ndata: ${JSON.stringify({ body: "[DONE]" })}\n\n`,
    ]);
    const { events } = await collectAnthropicEvents(body);
    expect(events).toContain("message_stop");
    expect(events).not.toContain("error");
  });

  it("fails closed when a tool delta is followed by [DONE] without finish_reason=tool_calls", async () => {
    const body = streamFromChunks([
      envelopeFrame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "t0", function: { name: "a", arguments: "{}" } }] } }] }),
      `event: message\ndata: ${JSON.stringify({ body: "[DONE]" })}\n\n`,
    ]);
    const { events, text } = await collectAnthropicEvents(body);
    expect(events).toContain("error");
    expect(events).not.toContain("content_block_start");
    expect(events).not.toContain("message_delta");
    expect(events).not.toContain("message_stop");
    expect(text).toContain("finish_reason=tool_calls");
  });

  it("fails closed when EOF follows a tool delta without finish_reason=tool_calls", async () => {
    const body = streamFromChunks([
      envelopeFrame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "t0", function: { name: "a", arguments: "{}" } }] } }] }),
    ]);
    const { events } = await collectAnthropicEvents(body);
    expect(events).toContain("error");
    expect(events).not.toContain("content_block_start");
    expect(events).not.toContain("message_delta");
    expect(events).not.toContain("message_stop");
  });

  it("fails closed without emitting tool_use when tool deltas end with finish_reason=stop", async () => {
    const body = streamFromChunks([
      envelopeFrame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "t0", function: { name: "a", arguments: "{}" } }] } }] }),
      envelopeFrame({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }),
    ]);
    const { events } = await collectAnthropicEvents(body);
    expect(events).toContain("error");
    expect(events).not.toContain("content_block_start");
    expect(events).not.toContain("message_stop");
  });

  it.each(["done", "eof"])("fails closed on 3+ parallel tool calls before emitting any tool_use block at %s", async (terminal) => {
    const chunks = [
      envelopeFrame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "t0", function: { name: "a", arguments: "{}" } }] } }] }),
      envelopeFrame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 1, id: "t1", function: { name: "b", arguments: "{}" } }] } }] }),
      envelopeFrame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 2, id: "t2", function: { name: "c", arguments: "{}" } }] } }] }),
    ];
    if (terminal === "done") chunks.push(`event: message\ndata: ${JSON.stringify({ body: "[DONE]" })}\n\n`);
    const { events, text } = await collectAnthropicEvents(streamFromChunks(chunks));
    expect(events).not.toContain("content_block_start");
    expect(events).toContain("error");
    expect(events).not.toContain("message_stop");
    expect(text).toMatch(/并行工具超过上限|上限/);
  });

  it("fails closed when finish_reason=tool_calls has no tool deltas", async () => {
    const body = streamFromChunks([envelopeFrame({ choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] })]);
    const { events, text } = await collectAnthropicEvents(body);
    expect(events).toContain("error");
    expect(events).not.toContain("content_block_start");
    expect(events).not.toContain("message_delta");
    expect(events).not.toContain("message_stop");
    expect(text).toContain("没有 tool_call");
  });

  it("aborts upstream when the downstream reader cancels", async () => {
    let aborted = false;
    const body = new ReadableStream<Uint8Array>({ pull() { /* intentionally remains open */ }, cancel() { aborted = true; } });
    const stream = emitAnthropicSseStream(body, "msg_test", "claude-x", undefined, () => { aborted = true; });
    const reader = stream.getReader();
    await reader.read();
    await reader.cancel();
    expect(aborted).toBe(true);
  });

  it("aggregates a single tool call across fragmented argument deltas", async () => {
    const body = streamFromChunks([
      envelopeFrame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "t0", function: { name: "get_weather", arguments: '{"ci' } }] } }] }),
      envelopeFrame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: 'ty":"sh"}' } }] } }] }),
      envelopeFrame({ choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] }),
    ]);
    const { events, text } = await collectAnthropicEvents(body);
    expect(events).toContain("content_block_start");
    expect(text).toContain('"partial_json":"{\\"city\\":\\"sh\\"}"');
    expect(text).toContain('"stop_reason":"tool_use"');
  });

  it.each([42, []])("rejects invalid event:finish root after stop and DONE: %j", async (payload) => {
    const body = streamFromChunks([
      envelopeFrame({ choices: [{ index: 0, delta: { content: "complete" } }] }),
      envelopeFrame({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }),
      `event: message\ndata: ${JSON.stringify({ body: "[DONE]" })}\n\n`,
      `event: finish\ndata: ${JSON.stringify(payload)}\n\n`,
    ]);
    const { events } = await collectAnthropicEvents(body);
    expect(events).toContain("error");
    expect(events).not.toContain("message_delta");
    expect(events).not.toContain("message_stop");
  });

  it("accepts Gate 0 finish -> usage -> DONE -> event:finish order and includes trailing usage", async () => {
    const body = streamFromChunks([
      envelopeFrame({ choices: [{ index: 0, delta: { content: "complete" } }] }),
      envelopeFrame({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }),
      envelopeFrame({ choices: [], usage: { prompt_tokens: 11, completion_tokens: 7, total_tokens: 18 } }),
      `event: message\ndata: ${JSON.stringify({ body: "[DONE]" })}\n\n`,
      `event: finish\ndata: ${JSON.stringify({ firstTokenDuration: 1, serverDuration: 1.5, totalDuration: 2 })}\n\n`,
    ]);
    const { events, text } = await collectAnthropicEvents(body);
    expect(events.at(-2)).toBe("message_delta");
    expect(events.at(-1)).toBe("message_stop");
    expect(events).not.toContain("error");
    expect(text).toContain('"usage":{"input_tokens":11,"output_tokens":7}');
  });

  it.each(["text-delta", "tool-delta", "duplicate-finish"])("rejects semantic frame after finish before normal terminal events: %s", async (kind) => {
    const chunks = [envelopeFrame({ choices: [{ index: 0, delta: { content: "complete" } }] }), envelopeFrame({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })];
    chunks.push(kind === "text-delta"
      ? envelopeFrame({ choices: [{ index: 0, delta: { content: "late text" } }] })
      : kind === "tool-delta"
        ? envelopeFrame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "late", function: { name: "late_tool", arguments: "{}" } }] } }] })
        : envelopeFrame({ choices: [{ index: 0, delta: {}, finish_reason: "length" }] }));
    const { events, text } = await collectAnthropicEvents(streamFromChunks(chunks));
    expect(events).toContain("error");
    expect(events).not.toContain("message_delta");
    expect(events).not.toContain("message_stop");
    expect(events.filter((event) => event === "content_block_start")).toHaveLength(1);
    expect(text).not.toContain("late_tool");
    expect(text).not.toContain("late text");
  });
});

describe("collectAnthropicMessage (non-streaming)", () => {
  it.each([
    "event: bogus\ndata: [DONE]\n\n",
    "event: error\ndata: [DONE]\n\n",
    "event: finish\ndata: [DONE]\n\n",
  ])("returns non-ok for raw DONE outside the verified message path: %s", async (wire) => {
    const result = await collectAnthropicMessage(streamFromChunks([wire]), "msg_test", "claude-x");
    expect(result.ok).toBe(false);
  });

  it.each([42, []])("returns non-ok for invalid event:finish root after stop and DONE: %j", async (payload) => {
    const body = streamFromChunks([
      envelopeFrame({ choices: [{ index: 0, delta: { content: "complete" } }] }),
      envelopeFrame({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }),
      `event: message\ndata: ${JSON.stringify({ body: "[DONE]" })}\n\n`,
      `event: finish\ndata: ${JSON.stringify(payload)}\n\n`,
    ]);
    const result = await collectAnthropicMessage(body, "msg_test", "claude-x");
    expect(result.ok).toBe(false);
  });

  it("returns non-ok when semantic choice index changes across frames", async () => {
    const body = streamFromChunks([
      envelopeFrame({ choices: [{ index: 0, delta: { content: "a" } }] }),
      envelopeFrame({ choices: [{ index: 1, delta: { content: "b" } }] }),
      envelopeFrame({ choices: [{ index: 1, delta: {}, finish_reason: "stop" }] }),
    ]);
    const result = await collectAnthropicMessage(body, "msg_test", "claude-x");
    expect(result.ok).toBe(false);
  });

  it("returns a single Anthropic Message with aggregated text and usage", async () => {
    const body = streamFromChunks([
      envelopeFrame({ choices: [{ index: 0, delta: { content: "hello " } }] }),
      envelopeFrame({ choices: [{ index: 0, delta: { content: "world" } }] }),
      envelopeFrame({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 5, completion_tokens: 2, total_tokens: 7 } }),
      `event: message\ndata: ${JSON.stringify({ body: "[DONE]" })}\n\n`,
    ]);
    const result = await collectAnthropicMessage(body, "msg_test", "claude-x");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.message.content).toEqual([{ type: "text", text: "hello world" }]);
      expect(result.message.stop_reason).toBe("end_turn");
      expect(result.message.usage).toEqual({ input_tokens: 5, output_tokens: 2 });
    }
  });

  it("surfaces upstream error frames as a non-ok result instead of throwing", async () => {
    const body = streamFromChunks([`event: error\ndata: ${JSON.stringify({ message: "boom" })}\n\n`]);
    const result = await collectAnthropicMessage(body, "msg_test", "claude-x");
    expect(result.ok).toBe(false);
  });

  it.each([
    42,
    [],
    { choices: [{ index: 0, delta: {}, finish_reason: "content_filter" }] },
    { choices: [{ index: 0, delta: {}, finish_reason: 7 }] },
    { choices: [{ index: 0, delta: { content: 42 } }] },
    { choices: [{ index: 0, delta: {}, finish_reason: "stop" }, { index: 1, delta: {}, finish_reason: "content_filter" }] },
    { choices: [{ index: 0, delta: {}, finish_reason: "stop" }, { index: 1, delta: { content: 42 } }] },
    { choices: [{ index: 0, delta: {} }, { index: 1, usage: { completion_tokens: "3" } }] },
    { choices: [{ index: 0, delta: {} }, { index: 1, delta: { tool_calls: {} } }] },
    { choices: [], usage: { prompt_tokens: "3" } },
    { choices: [{ index: 0, delta: { tool_calls: [{ index: -1, id: "t", function: { name: "a", arguments: "{}" } }] } }] },
  ])("returns non-ok for malformed frame: %j", async (chunk) => {
    const result = await collectAnthropicMessage(streamFromChunks([envelopeFrame(chunk)]), "msg_test", "claude-x");
    expect(result.ok).toBe(false);
  });

  it("fails closed when EOF follows text deltas without terminal evidence", async () => {
    const body = streamFromChunks([envelopeFrame({ choices: [{ index: 0, delta: { content: "partial" } }] })]);
    const result = await collectAnthropicMessage(body, "msg_test", "claude-x");
    expect(result).toEqual({ ok: false, errorMessage: "upstream stream truncated" });
  });

  it("accepts a finish_reason as terminal evidence without requiring [DONE]", async () => {
    const body = streamFromChunks([
      envelopeFrame({ choices: [{ index: 0, delta: { content: "complete" } }] }),
      envelopeFrame({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }),
    ]);
    const result = await collectAnthropicMessage(body, "msg_test", "claude-x");
    expect(result.ok).toBe(true);
  });

  it("fails closed when a tool delta is followed by [DONE] without finish_reason=tool_calls", async () => {
    const body = streamFromChunks([
      envelopeFrame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "t0", function: { name: "a", arguments: "{}" } }] } }] }),
      `event: message\ndata: ${JSON.stringify({ body: "[DONE]" })}\n\n`,
    ]);
    const result = await collectAnthropicMessage(body, "msg_test", "claude-x");
    expect(result).toEqual({ ok: false, errorMessage: "tool_call 缺少 finish_reason=tool_calls" });
  });

  it("fails closed when EOF follows a tool delta without finish_reason=tool_calls", async () => {
    const body = streamFromChunks([
      envelopeFrame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "t0", function: { name: "a", arguments: "{}" } }] } }] }),
    ]);
    const result = await collectAnthropicMessage(body, "msg_test", "claude-x");
    expect(result).toEqual({ ok: false, errorMessage: "upstream stream truncated" });
  });

  it("rejects tool deltas terminated by finish_reason=stop", async () => {
    const body = streamFromChunks([
      envelopeFrame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "t0", function: { name: "a", arguments: "{}" } }] } }] }),
      envelopeFrame({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }),
    ]);
    const result = await collectAnthropicMessage(body, "msg_test", "claude-x");
    expect(result).toEqual({ ok: false, errorMessage: "tool_call 缺少 finish_reason=tool_calls" });
  });

  it.each(["done", "eof"])("enforces the parallel tool cap before %s terminal framing", async (terminal) => {
    const chunks = [
      envelopeFrame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "t0", function: { name: "a", arguments: "{}" } }] } }] }),
      envelopeFrame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 1, id: "t1", function: { name: "b", arguments: "{}" } }] } }] }),
      envelopeFrame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 2, id: "t2", function: { name: "c", arguments: "{}" } }] } }] }),
    ];
    if (terminal === "done") chunks.push(`event: message\ndata: ${JSON.stringify({ body: "[DONE]" })}\n\n`);
    const result = await collectAnthropicMessage(streamFromChunks(chunks), "msg_test", "claude-x");
    expect(result).toEqual({ ok: false, errorMessage: "并行工具超过上限 2" });
  });

  it("fails closed when finish_reason=tool_calls has no tool deltas", async () => {
    const body = streamFromChunks([envelopeFrame({ choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] })]);
    const result = await collectAnthropicMessage(body, "msg_test", "claude-x");
    expect(result).toEqual({ ok: false, errorMessage: "finish_reason=tool_calls 但没有 tool_call" });
  });

  it("accepts Gate 0 finish -> usage -> DONE -> event:finish order and includes trailing usage", async () => {
    const body = streamFromChunks([
      envelopeFrame({ choices: [{ index: 0, delta: { content: "complete" } }] }),
      envelopeFrame({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }),
      envelopeFrame({ choices: [], usage: { prompt_tokens: 11, completion_tokens: 7, total_tokens: 18 } }),
      `event: message\ndata: ${JSON.stringify({ body: "[DONE]" })}\n\n`,
      `event: finish\ndata: ${JSON.stringify({ firstTokenDuration: 1, serverDuration: 1.5, totalDuration: 2 })}\n\n`,
    ]);
    const result = await collectAnthropicMessage(body, "msg_test", "claude-x");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.message.content).toEqual([{ type: "text", text: "complete" }]);
      expect(result.message.usage).toEqual({ input_tokens: 11, output_tokens: 7 });
    }
  });

  it.each(["text-delta", "tool-delta", "duplicate-finish"])("rejects semantic frame after finish: %s", async (kind) => {
    const chunks = [envelopeFrame({ choices: [{ index: 0, delta: { content: "complete" } }] }), envelopeFrame({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })];
    chunks.push(kind === "text-delta"
      ? envelopeFrame({ choices: [{ index: 0, delta: { content: "late text" } }] })
      : kind === "tool-delta"
        ? envelopeFrame({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "late", function: { name: "late_tool", arguments: "{}" } }] } }] })
        : envelopeFrame({ choices: [{ index: 0, delta: {}, finish_reason: "length" }] }));
    const result = await collectAnthropicMessage(streamFromChunks(chunks), "msg_test", "claude-x");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errorMessage).toMatch(/finish_reason 之后/);
  });
});
