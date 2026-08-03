// Qoder tier 与官方 routing key 的唯一映射源。
// Claude Code 的 [1m] 只是客户端能力标记；发送给 Qoder 的 key 永不带后缀。

export const QODER_TIER_REGISTRY = {
  opus: { claudeModel: "qmodel_38max[1m]", routingKey: "qmodel_38max", displayName: "Qwen3.8-Max" },
  sonnet: { claudeModel: "qmodel_latest[1m]", routingKey: "qmodel_latest", displayName: "Qwen3.7-Max" },
  haiku: { claudeModel: "q36fmodel[1m]", routingKey: "q36fmodel", displayName: "Qwen3.6-Flash" },
} as const;

export type QoderTier = keyof typeof QODER_TIER_REGISTRY;
export type QoderRoutingKey = (typeof QODER_TIER_REGISTRY)[QoderTier]["routingKey"];

export const QODER_ROUTING_KEYS = Object.freeze(
  Object.values(QODER_TIER_REGISTRY).map((entry) => entry.routingKey),
);

export class QoderModelCatalogUnavailableError extends Error {
  constructor(cause?: unknown) {
    super("Qoder model catalog unavailable", cause === undefined ? undefined : { cause });
    this.name = "QoderModelCatalogUnavailableError";
  }
}

export class QoderModelUnavailableError extends Error {
  readonly routingKey: string;
  constructor(routingKey: string) {
    super(`Qoder runtime model unavailable: ${routingKey}`);
    this.name = "QoderModelUnavailableError";
    this.routingKey = routingKey;
  }
}
