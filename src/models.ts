// 官方 Qoder assistant catalog 的严格领域模型与 Anthropic Models API 映射。
//
// 公开 model id 只能使用 catalog 已证明的 Qoder routing key；不得构造 provider/canonical id。

export const DEFAULT_MODEL_PAGE_LIMIT = 20;
export const MAX_MODEL_PAGE_LIMIT = 1000;
export const UNKNOWN_MODEL_CREATED_AT = "1970-01-01T00:00:00.000Z";
export const MAX_PROXY_OUTPUT_TOKENS = 1024;

export class ModelCatalogError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ModelCatalogError";
  }
}

export class ModelPaginationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ModelPaginationError";
  }
}

export type QoderContextTier = {
  name: string;
  tokenCount: number;
  isDefault: boolean;
};

export type QoderAssistantModel = {
  key: string;
  displayName: string;
  isDefault: boolean;
  isVision: boolean;
  isReasoning: boolean;
  /** 官方顶层值，CN legacy model_config 必须继续原样使用。 */
  maxInputTokens: number;
  /** context_config 证明的最大可选窗口；缺失时等于 maxInputTokens。 */
  maxSelectableInputTokens?: number;
  contextTiers?: readonly QoderContextTier[];
  maxOutputTokens: number | null;
  createdAt: string;
  format: string;
  source: string;
};

type CapabilitySupport = { supported: boolean };

export type AnthropicModelInfo = {
  id: string;
  type: "model";
  display_name: string;
  created_at: string;
  max_input_tokens: number;
  max_tokens: number | null;
  capabilities: {
    batch: CapabilitySupport;
    citations: CapabilitySupport;
    code_execution: CapabilitySupport;
    context_management: {
      supported: boolean;
      clear_thinking_20251015: CapabilitySupport;
      clear_tool_uses_20250919: CapabilitySupport;
      compact_20260112: CapabilitySupport;
    };
    effort: {
      supported: boolean;
      low: CapabilitySupport;
      medium: CapabilitySupport;
      high: CapabilitySupport;
      xhigh: CapabilitySupport;
      max: CapabilitySupport;
    };
    image_input: CapabilitySupport;
    pdf_input: CapabilitySupport;
    structured_outputs: CapabilitySupport;
    thinking: {
      supported: boolean;
      types: {
        adaptive: CapabilitySupport;
        enabled: CapabilitySupport;
      };
    };
  };
};

export type ModelPage = {
  data: AnthropicModelInfo[];
  has_more: boolean;
  first_id: string | null;
  last_id: string | null;
};

export type ModelPageParams = {
  beforeId?: string;
  afterId?: string;
  limit?: number;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireNonEmptyString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim().length === 0) throw new ModelCatalogError(`${field} 必须是非空字符串`);
  return value.trim();
}

function optionalBoolean(value: unknown, field: string): boolean {
  if (value === undefined) return false;
  if (typeof value !== "boolean") throw new ModelCatalogError(`${field} 必须是 boolean`);
  return value;
}

function requirePositiveInteger(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) throw new ModelCatalogError(`${field} 必须是正整数`);
  return value as number;
}

function optionalPositiveInteger(value: unknown, field: string): number | null {
  if (value === undefined || value === null) return null;
  return requirePositiveInteger(value, field);
}

function isUnsupportedEnterpriseByok(raw: Record<string, unknown>): boolean {
  return raw.server_scene === "byok_enterprise";
}

function contextTiers(value: unknown, prefix: string): readonly QoderContextTier[] {
  if (value === undefined || value === null) return [];
  if (!isRecord(value)) throw new ModelCatalogError(`${prefix}.context_config 必须是对象`);

  const tiers: QoderContextTier[] = [];
  let defaultCount = 0;
  for (const [name, tierValue] of Object.entries(value)) {
    const tierPrefix = `${prefix}.context_config.${name}`;
    if (!isRecord(tierValue)) throw new ModelCatalogError(`${tierPrefix} 必须是对象`);
    const isDefault = optionalBoolean(tierValue.is_default, `${tierPrefix}.is_default`);
    if (isDefault) defaultCount++;
    tiers.push({
      name: requireNonEmptyString(name, `${tierPrefix}.name`),
      tokenCount: requirePositiveInteger(tierValue.token_count, `${tierPrefix}.token_count`),
      isDefault,
    });
  }
  if (defaultCount > 1) throw new ModelCatalogError(`${prefix}.context_config 只能有一个默认档`);
  return tiers;
}

function normalizedEntry(raw: Record<string, unknown>, index: number): QoderAssistantModel | undefined {
  if (raw.enable === false || raw.enable === 0 || isUnsupportedEnterpriseByok(raw)) return undefined;
  const prefix = `assistant[${index}]`;
  const maxInputTokens = requirePositiveInteger(raw.max_input_tokens, `${prefix}.max_input_tokens`);
  const tiers = contextTiers(raw.context_config, prefix);
  return {
    key: requireNonEmptyString(raw.key ?? raw.model_key, `${prefix}.key`),
    displayName: requireNonEmptyString(raw.display_name ?? raw.name, `${prefix}.display_name`),
    isDefault: optionalBoolean(raw.is_default, `${prefix}.is_default`),
    isVision: optionalBoolean(raw.is_vl, `${prefix}.is_vl`),
    isReasoning: optionalBoolean(raw.is_reasoning, `${prefix}.is_reasoning`),
    maxInputTokens,
    maxSelectableInputTokens: Math.max(maxInputTokens, ...tiers.map((tier) => tier.tokenCount)),
    contextTiers: tiers,
    maxOutputTokens: optionalPositiveInteger(raw.max_output_tokens, `${prefix}.max_output_tokens`),
    createdAt: UNKNOWN_MODEL_CREATED_AT,
    format: raw.format === undefined ? "openai" : requireNonEmptyString(raw.format, `${prefix}.format`),
    source: raw.source === undefined ? "system" : requireNonEmptyString(raw.source, `${prefix}.source`),
  };
}

function stableCatalogValue(value: unknown, seen = new Set<object>()): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new ModelCatalogError("catalog metadata 含非有限数字");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new ModelCatalogError("catalog metadata 不得循环引用");
    seen.add(value);
    const result = `[${value.map((item) => stableCatalogValue(item, seen)).join(",")}]`;
    seen.delete(value);
    return result;
  }
  if (isRecord(value)) {
    if (seen.has(value)) throw new ModelCatalogError("catalog metadata 不得循环引用");
    seen.add(value);
    const fields = Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableCatalogValue(value[key], seen)}`);
    seen.delete(value);
    return `{${fields.join(",")}}`;
  }
  throw new ModelCatalogError("catalog metadata 含非 JSON 值");
}

export function parseQoderAssistantCatalog(value: unknown): QoderAssistantModel[] {
  if (!isRecord(value)) throw new ModelCatalogError("catalog root 必须是对象");
  if (!Array.isArray(value.assistant)) throw new ModelCatalogError("catalog assistant scene 必须是数组");

  const output: QoderAssistantModel[] = [];
  const fingerprintByKey = new Map<string, string>();
  for (let index = 0; index < value.assistant.length; index++) {
    const raw = value.assistant[index];
    if (!isRecord(raw)) throw new ModelCatalogError(`assistant[${index}] 必须是对象`);
    const entry = normalizedEntry(raw, index);
    if (!entry) continue;
    const fingerprint = stableCatalogValue(raw);
    const existing = fingerprintByKey.get(entry.key);
    if (existing !== undefined) {
      if (existing !== fingerprint) throw new ModelCatalogError(`assistant model key 冲突: ${entry.key}`);
      continue;
    }
    fingerprintByKey.set(entry.key, fingerprint);
    output.push(entry);
  }
  return output;
}

const unsupported = (): CapabilitySupport => ({ supported: false });

export function toAnthropicModelInfo(model: QoderAssistantModel): AnthropicModelInfo {
  return {
    id: model.key,
    type: "model",
    display_name: model.displayName,
    created_at: UNKNOWN_MODEL_CREATED_AT,
    max_input_tokens: model.maxSelectableInputTokens ?? model.maxInputTokens,
    max_tokens: Math.min(model.maxOutputTokens ?? MAX_PROXY_OUTPUT_TOKENS, MAX_PROXY_OUTPUT_TOKENS),
    capabilities: {
      batch: unsupported(),
      citations: unsupported(),
      code_execution: unsupported(),
      context_management: {
        supported: false,
        clear_thinking_20251015: unsupported(),
        clear_tool_uses_20250919: unsupported(),
        compact_20260112: unsupported(),
      },
      effort: {
        supported: false,
        low: unsupported(),
        medium: unsupported(),
        high: unsupported(),
        xhigh: unsupported(),
        max: unsupported(),
      },
      image_input: unsupported(),
      pdf_input: unsupported(),
      structured_outputs: unsupported(),
      thinking: {
        supported: false,
        types: { adaptive: unsupported(), enabled: unsupported() },
      },
    },
  };
}

export function findModelById(models: readonly QoderAssistantModel[], id: string): QoderAssistantModel | undefined {
  return models.find((model) => model.key === id);
}

export function paginateModels(models: readonly QoderAssistantModel[], params: ModelPageParams = {}): ModelPage {
  if (params.beforeId !== undefined && params.afterId !== undefined) throw new ModelPaginationError("before_id 与 after_id 不能同时提供");
  const limit = params.limit ?? DEFAULT_MODEL_PAGE_LIMIT;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_MODEL_PAGE_LIMIT) {
    throw new ModelPaginationError(`limit 必须是 ${1}-${MAX_MODEL_PAGE_LIMIT} 的整数`);
  }

  let start = 0;
  let end = models.length;
  let hasMore = false;
  if (params.afterId !== undefined) {
    const cursor = models.findIndex((model) => model.key === params.afterId);
    if (cursor < 0) throw new ModelPaginationError("after_id 不存在");
    start = cursor + 1;
    end = Math.min(models.length, start + limit);
    hasMore = end < models.length;
  } else if (params.beforeId !== undefined) {
    const cursor = models.findIndex((model) => model.key === params.beforeId);
    if (cursor < 0) throw new ModelPaginationError("before_id 不存在");
    end = cursor;
    start = Math.max(0, end - limit);
    hasMore = start > 0;
  } else {
    end = Math.min(models.length, limit);
    hasMore = end < models.length;
  }

  const data = models.slice(start, end).map(toAnthropicModelInfo);
  return {
    data,
    has_more: hasMore,
    first_id: data[0]?.id ?? null,
    last_id: data.at(-1)?.id ?? null,
  };
}
