import { describe, expect, it } from "vitest";
import { expectedModelForRoutingKey, hasExpectedModelIdentity, QODER_ROUTING_KEYS, QODER_TIER_REGISTRY, QoderModelUnavailableError } from "../src/model-registry.ts";

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

  it("validates the registered key identity, including the qmodel_latest display name", () => {
    expect(expectedModelForRoutingKey("qmodel_38max")).toEqual({ key: "qmodel_38max", displayName: "Qwen3.8-Max" });
    expect(expectedModelForRoutingKey("qmodel_latest")).toEqual({ key: "qmodel_latest", displayName: "Qwen3.7-Max" });
    expect(expectedModelForRoutingKey("q36fmodel")).toEqual({ key: "q36fmodel", displayName: "Qwen3.6-Flash" });
    expect(hasExpectedModelIdentity({ key: "qmodel_latest", displayName: "Qwen3.7-Max" }, "qmodel_latest")).toBe(true);
    expect(hasExpectedModelIdentity({ key: "qmodel_latest", displayName: "Qwen3.7-Plus" }, "qmodel_latest")).toBe(false);
    expect(hasExpectedModelIdentity({ key: "qmodel_latest", displayName: "" }, "qmodel_latest")).toBe(false);
  });

  it("uses a distinct error for missing and identity-drift catalog entries", () => {
    expect(new QoderModelUnavailableError("old-key")).toMatchObject({ name: "QoderModelUnavailableError", routingKey: "old-key", reason: "missing" });
    expect(new QoderModelUnavailableError("qmodel_latest", "identity-mismatch")).toMatchObject({ name: "QoderModelUnavailableError", routingKey: "qmodel_latest", reason: "identity-mismatch" });
  });
});
