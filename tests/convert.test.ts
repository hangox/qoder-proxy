import { describe, it, expect } from "vitest";
import { convertAnthropicToCnBody, ConversionError, MAX_CN_MAX_TOKENS } from "../src/convert.ts";
import type { QoderAssistantModel } from "../src/models.ts";

const MODEL: QoderAssistantModel = {
  key: "qmodel_preview",
  displayName: "Qwen3.8-Max-Preview",
  isDefault: false,
  isVision: true,
  isReasoning: true,
  maxInputTokens: 180000,
  maxSelectableInputTokens: 1000000,
  contextTiers: [
    { name: "200K", tokenCount: 200000, isDefault: true },
    { name: "400K", tokenCount: 400000, isDefault: false },
    { name: "1M", tokenCount: 1000000, isDefault: false },
  ],
  maxOutputTokens: 8192,
  createdAt: "1970-01-01T00:00:00.000Z",
  format: "openai",
  source: "system",
};
const convert = (body: Record<string, unknown>) => convertAnthropicToCnBody(body, MODEL);

describe("convertAnthropicToCnBody", () => {
  it("converts system string and plain user/assistant text", () => {
    const { body } = convert({
      system: "be helpful",
      messages: [
        { role: "user", content: "hi" },
        { role: "assistant", content: "hello" },
      ],
    });
    const messages = body.messages as Array<Record<string, unknown>>;
    expect(messages[0]).toEqual({ role: "system", content: "be helpful" });
    expect(messages[1]).toEqual({ role: "user", content: "hi" });
    expect(messages[2]).toEqual({ role: "assistant", content: "hello" });
  });

  it("converts system text blocks by joining with blank lines", () => {
    const { body } = convert({
      system: [{ type: "text", text: "a" }, { type: "text", text: "b" }],
      messages: [{ role: "user", content: "hi" }],
    });
    const messages = body.messages as Array<Record<string, unknown>>;
    expect(messages[0]).toEqual({ role: "system", content: "a\n\nb" });
  });

  it("round-trips tool_use -> tool_result with id->name lookup and reorders tool results before text", () => {
    const { body } = convert({
      messages: [
        { role: "user", content: "run the tool" },
        {
          role: "assistant",
          content: [
            { type: "text", text: "on it" },
            { type: "tool_use", id: "tool_1", name: "get_weather", input: { city: "sh" } },
          ],
        },
        {
          role: "user",
          content: [
            { type: "text", text: "here you go" },
            { type: "tool_result", tool_use_id: "tool_1", content: "sunny" },
          ],
        },
      ],
    });
    const messages = body.messages as Array<Record<string, unknown>>;
    // assistant message keeps text + tool_calls
    const assistantMsg = messages.find((m) => m.role === "assistant");
    expect(assistantMsg?.content).toBe("on it");
    expect((assistantMsg?.tool_calls as Array<Record<string, unknown>>)[0]).toMatchObject({ id: "tool_1", type: "function" });

    // last user message: tool result must come before the plain text, and carry the resolved name.
    const lastTwo = messages.slice(-2);
    expect(lastTwo[0]).toMatchObject({ role: "tool", tool_call_id: "tool_1", name: "get_weather", content: "sunny" });
    expect(lastTwo[1]).toMatchObject({ role: "user", content: "here you go" });
  });

  it("preserves tool_result is_error with the Gate 0 content wrapper", () => {
    const { body } = convert({
      messages: [
        { role: "assistant", content: [{ type: "tool_use", id: "tool_1", name: "get_weather", input: {} }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "tool_1", content: "failed", is_error: true }] },
      ],
    });
    expect((body.messages as Array<Record<string, unknown>>).at(-1)).toMatchObject({ role: "tool", tool_call_id: "tool_1", name: "get_weather", content: JSON.stringify({ is_error: true, content: "failed" }) });
  });

  it("rejects direct role=tool because it cannot establish the CN name contract", () => {
    expect(() => convert({ messages: [{ role: "tool", tool_call_id: "x", content: "result" }] })).toThrow(ConversionError);
  });

  it("fails closed when tool_result references an unknown tool_use_id", () => {
    expect(() =>
      convert({
        messages: [{ role: "user", content: [{ type: "tool_result", tool_use_id: "ghost", content: "x" }] }],
      }),
    ).toThrow(ConversionError);
  });

  it("rejects unknown top-level fields (fail-closed)", () => {
    expect(() => convert({ messages: [{ role: "user", content: "hi" }], made_up: true })).toThrow(ConversionError);
  });

  it("rejects tool_choice type=tool explicitly", () => {
    expect(() =>
      convert({ messages: [{ role: "user", content: "hi" }], tool_choice: { type: "tool", name: "x" } }),
    ).toThrow(/tool_choice type=tool/);
  });

  it("maps tool_choice auto/any/none", () => {
    const auto = convert({ messages: [{ role: "user", content: "hi" }], tool_choice: { type: "auto" } });
    const any = convert({ messages: [{ role: "user", content: "hi" }], tool_choice: { type: "any" } });
    const none = convert({ messages: [{ role: "user", content: "hi" }], tool_choice: { type: "none" } });
    expect(auto.body.tool_choice).toBe("auto");
    expect(any.body.tool_choice).toBe("required");
    expect(none.body.tool_choice).toBe("none");
  });

  it("degrades thinking/metadata into observable provenance instead of silently dropping", () => {
    const { provenance } = convert({
      messages: [{ role: "user", content: "hi" }],
      thinking: { type: "enabled" },
      metadata: { user_id: "abc" },
    });
    expect(provenance.ignoredFields).toContain("thinking");
    expect(provenance.ignoredFields).toContain("metadata");
  });

  it("records max_tokens truncation in provenance and caps the CN body value", () => {
    const { body, provenance } = convert({
      messages: [{ role: "user", content: "hi" }],
      max_tokens: 4096,
    });
    expect(provenance.maxTokensTruncated).toBe(true);
    expect(provenance.originalMaxTokens).toBe(4096);
    expect(provenance.cnMaxTokens).toBe(MAX_CN_MAX_TOKENS);
    expect((body.parameters as Record<string, unknown>).max_tokens).toBe(MAX_CN_MAX_TOKENS);
  });

  it("does not truncate when max_tokens is within range", () => {
    const { provenance } = convert({ messages: [{ role: "user", content: "hi" }], max_tokens: 256 });
    expect(provenance.maxTokensTruncated).toBe(false);
    expect(provenance.cnMaxTokens).toBe(256);
  });

  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])("rejects invalid max_tokens: %s", (max_tokens) => {
    expect(() => convert({ messages: [{ role: "user", content: "hi" }], max_tokens })).toThrow(ConversionError);
  });

  it("records the requested model as provenance while CN body keeps the official top-level model window", () => {
    const { body, provenance } = convert({
      messages: [{ role: "user", content: "hi" }],
      model: "claude-opus-4-20250514",
    });
    expect(provenance.requestedModel).toBe("claude-opus-4-20250514");
    expect(JSON.stringify(body)).not.toContain("claude-opus-4-20250514");
    expect(body.model_config).toMatchObject({ key: "qmodel_preview", max_input_tokens: 180000 });
  });

  it.each(["", "   "])("rejects an empty model value: %j", (model) => {
    expect(() => convert({ messages: [{ role: "user", content: "hi" }], model })).toThrow(/model 必须是非空字符串/);
  });

  it("maps tools input_schema to CN function.parameters", () => {
    const { body } = convert({
      messages: [{ role: "user", content: "hi" }],
      tools: [{ name: "get_weather", description: "d", input_schema: { type: "object" } }],
    });
    const tools = body.tools as Array<Record<string, unknown>>;
    expect(tools[0]).toMatchObject({ type: "function", function: { name: "get_weather", description: "d", parameters: { type: "object" } } });
  });

  it.each([{}, "bad", 1, null])("rejects non-array tools when provided: %j", (tools) => {
    expect(() => convert({ messages: [{ role: "user", content: "hi" }], tools })).toThrow(/tools 必须是数组/);
  });

  it("rejects an array input_schema", () => {
    expect(() => convert({
      messages: [{ role: "user", content: "hi" }],
      tools: [{ name: "bad_schema", input_schema: [] }],
    })).toThrow(/input_schema 类型错误/);
  });

  it("rejects empty messages", () => {
    expect(() => convert({ messages: [] })).toThrow(ConversionError);
  });

  it("rejects user content block arrays that convert to no CN messages", () => {
    expect(() => convert({
      system: "still not a user message",
      messages: [{ role: "user", content: [] }],
    })).toThrow(/转换后为空/);
  });

  it("rejects unsupported content block types (fail-closed)", () => {
    expect(() =>
      convert({ messages: [{ role: "user", content: [{ type: "image" }] }] }),
    ).toThrow(ConversionError);
  });
});
