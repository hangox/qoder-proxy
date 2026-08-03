import { describe, expect, it } from "vitest";
import {
  findModelById,
  ModelCatalogError,
  ModelPaginationError,
  paginateModels,
  parseQoderAssistantCatalog,
  toAnthropicModelInfo,
  UNKNOWN_MODEL_CREATED_AT,
} from "../src/models.ts";

function rawModel(key: string, overrides: Record<string, unknown> = {}) {
  return {
    key,
    display_name: key === "auto" ? "Auto" : "Qwen3.8-Max",
    enable: true,
    is_default: key === "auto",
    is_vl: false,
    is_reasoning: key !== "auto",
    max_input_tokens: 200000,
    source: "system",
    format: "openai",
    ...overrides,
  };
}

describe("Qoder assistant catalog", () => {
  it("只选择 assistant scene、按官方 enable 语义过滤并保持上游权威顺序", () => {
    const { enable: _enable, ...enabledByDefault } = rawModel("qmodel_38max");
    const models = parseQoderAssistantCatalog({
      chat: [rawModel("chat-only")],
      assistant: [enabledByDefault, rawModel("disabled-false", { enable: false }), rawModel("disabled-zero", { enable: 0 }), rawModel("auto")],
    });
    expect(models.map((model) => model.key)).toEqual(["qmodel_38max", "auto"]);
  });

  it("支持 key/model_key 与 display_name/name 回退，并过滤 BYOK enterprise", () => {
    const { key: _key, display_name: _displayName, ...legacyBase } = rawModel("unused");
    const legacy = { ...legacyBase, model_key: "legacy-key", name: "Legacy" };
    const models = parseQoderAssistantCatalog({
      assistant: [legacy, rawModel("enterprise", { server_scene: "byok_enterprise" })],
    });
    expect(models.map((model) => ({ key: model.key, displayName: model.displayName }))).toEqual([{ key: "legacy-key", displayName: "Legacy" }]);
  });

  it("拒绝 malformed root、scene 与 enabled entry", () => {
    expect(() => parseQoderAssistantCatalog([])).toThrow(ModelCatalogError);
    expect(() => parseQoderAssistantCatalog({})).toThrow(/assistant scene/);
    expect(() => parseQoderAssistantCatalog({ assistant: [null] })).toThrow(/必须是对象/);
    expect(() => parseQoderAssistantCatalog({ assistant: [rawModel("", { key: "" })] })).toThrow(/非空字符串/);
    expect(() => parseQoderAssistantCatalog({ assistant: [rawModel("x", { max_input_tokens: "200000" })] })).toThrow(/正整数/);
  });

  it("允许原始 metadata 完全相同的重复 key，但拒绝任意字段冲突", () => {
    expect(parseQoderAssistantCatalog({ assistant: [rawModel("auto"), rawModel("auto")] })).toHaveLength(1);
    expect(() => parseQoderAssistantCatalog({ assistant: [rawModel("auto"), rawModel("auto", { display_name: "Other" })] })).toThrow(/冲突/);
    expect(() => parseQoderAssistantCatalog({ assistant: [rawModel("auto", { tags: ["stable"] }), rawModel("auto", { tags: ["preview"] })] })).toThrow(/冲突/);
  });

  it("ModelInfo 使用 context_config 证明的最大可选窗口，并把输出上限压到 1024", () => {
    const [model] = parseQoderAssistantCatalog({ assistant: [rawModel("qmodel_38max", {
      is_vl: true,
      is_reasoning: true,
      max_output_tokens: 8192,
      created_at: "2026-07-30T12:00:00Z",
      max_input_tokens: 180000,
      context_config: {
        "200K": { token_count: 200000, is_default: true },
        "400K": { token_count: 400000, is_default: false },
        "1M": { token_count: 1000000, is_default: false },
      },
    })] });
    const info = toAnthropicModelInfo(model!);
    expect(model).toMatchObject({
      maxInputTokens: 180000,
      maxSelectableInputTokens: 1000000,
      contextTiers: [
        { name: "200K", tokenCount: 200000, isDefault: true },
        { name: "400K", tokenCount: 400000, isDefault: false },
        { name: "1M", tokenCount: 1000000, isDefault: false },
      ],
    });
    expect(info).toMatchObject({
      id: "qmodel_38max",
      type: "model",
      display_name: "Qwen3.8-Max",
      created_at: UNKNOWN_MODEL_CREATED_AT,
      max_input_tokens: 1000000,
      max_tokens: 1024,
      capabilities: {
        image_input: { supported: false },
        thinking: { supported: false, types: { adaptive: { supported: false }, enabled: { supported: false } } },
        citations: { supported: false },
        structured_outputs: { supported: false },
      },
    });
  });

  it("目录缺少 context_config 与输出上限时回退顶层输入窗口和代理硬上限", () => {
    const [model] = parseQoderAssistantCatalog({ assistant: [rawModel("auto")] });
    const info = toAnthropicModelInfo(model!);
    expect(model).toMatchObject({ maxInputTokens: 200000, maxSelectableInputTokens: 200000, contextTiers: [] });
    expect(info.created_at).toBe(UNKNOWN_MODEL_CREATED_AT);
    expect(info.max_input_tokens).toBe(200000);
    expect(info.max_tokens).toBe(1024);
  });

  it("严格拒绝 malformed context_config、非法 token 与多个默认档", () => {
    expect(() => parseQoderAssistantCatalog({ assistant: [rawModel("x", { context_config: [] })] })).toThrow(/context_config 必须是对象/);
    expect(() => parseQoderAssistantCatalog({ assistant: [rawModel("x", { context_config: { "1M": "bad" } })] })).toThrow(/必须是对象/);
    expect(() => parseQoderAssistantCatalog({ assistant: [rawModel("x", { context_config: { "1M": { token_count: "1000000" } } })] })).toThrow(/正整数/);
    expect(() => parseQoderAssistantCatalog({ assistant: [rawModel("x", { context_config: {
      "200K": { token_count: 200000, is_default: true },
      "1M": { token_count: 1000000, is_default: true },
    } })] })).toThrow(/只能有一个默认档/);
  });

  it("exact lookup 不做大小写、display name 或 alias 匹配", () => {
    const models = parseQoderAssistantCatalog({ assistant: [rawModel("qmodel_38max")] });
    expect(findModelById(models, "qmodel_38max")?.key).toBe("qmodel_38max");
    expect(findModelById(models, "QMODEL_PREVIEW")).toBeUndefined();
    expect(findModelById(models, "Qwen3.8-Max")).toBeUndefined();
  });
});

describe("Anthropic Models pagination", () => {
  const models = parseQoderAssistantCatalog({ assistant: [rawModel("m2"), rawModel("auto"), rawModel("m1"), rawModel("m3")] });

  it("默认正向分页保持非字典序的官方目录顺序", () => {
    expect(paginateModels(models, { limit: 2 })).toMatchObject({
      data: [{ id: "m2" }, { id: "auto" }],
      first_id: "m2",
      last_id: "auto",
      has_more: true,
    });
  });

  it("after_id 返回游标之后的数据", () => {
    expect(paginateModels(models, { afterId: "auto", limit: 2 })).toMatchObject({
      data: [{ id: "m1" }, { id: "m3" }],
      first_id: "m1",
      last_id: "m3",
      has_more: false,
    });
  });

  it("before_id 返回紧邻游标之前的数据并保持官方目录顺序", () => {
    expect(paginateModels(models, { beforeId: "m3", limit: 2 })).toMatchObject({
      data: [{ id: "auto" }, { id: "m1" }],
      first_id: "auto",
      last_id: "m1",
      has_more: true,
    });
  });

  it("空页使用 null cursor", () => {
    expect(paginateModels(models, { afterId: "m3" })).toEqual({ data: [], first_id: null, last_id: null, has_more: false });
  });

  it("拒绝双游标、未知游标和越界 limit", () => {
    expect(() => paginateModels(models, { beforeId: "m2", afterId: "m1" })).toThrow(ModelPaginationError);
    expect(() => paginateModels(models, { afterId: "missing" })).toThrow(/不存在/);
    expect(() => paginateModels(models, { limit: 0 })).toThrow(/limit/);
    expect(() => paginateModels(models, { limit: 1001 })).toThrow(/limit/);
  });
});
