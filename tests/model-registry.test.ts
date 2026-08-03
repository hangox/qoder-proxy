import { describe, expect, it } from "vitest";
import { QODER_ROUTING_KEYS, QODER_TIER_REGISTRY, QoderModelUnavailableError } from "../src/model-registry.ts";

describe("Qoder model registry", () => {
  it("keeps the three client mappings and strips [1m] from upstream keys", () => {
    expect(QODER_TIER_REGISTRY).toEqual({
      opus: { claudeModel: "qmodel_38max[1m]", routingKey: "qmodel_38max", displayName: "Qwen3.8-Max" },
      sonnet: { claudeModel: "qmodel_latest[1m]", routingKey: "qmodel_latest", displayName: "Qwen3.7-Max" },
      haiku: { claudeModel: "q36fmodel[1m]", routingKey: "q36fmodel", displayName: "Qwen3.6-Flash" },
    });
    expect(QODER_ROUTING_KEYS).toEqual(["qmodel_38max", "qmodel_latest", "q36fmodel"]);
    expect(QODER_ROUTING_KEYS.every((key) => !key.includes("[1m]"))).toBe(true);
  });

  it("uses a distinct error for a missing catalog key", () => {
    expect(new QoderModelUnavailableError("old-key")).toMatchObject({ name: "QoderModelUnavailableError", routingKey: "old-key" });
  });
});
