import { describe, expect, it } from "vitest";
// @ts-expect-error 持久 QA verifier 保持 .mjs，Vitest 运行时按 ESM 加载。
import { verifyRoutingAttestation } from "./verify-routing-attestation.mjs";

const VALID = {
  schema: "qoder-proxy-live-attestation/v1", message: "请求溯源", modelProvided: true,
  requestModel: "qmodel_preview", resolvedModel: "qmodel_preview", prepareInferModel: "qmodel_preview", responseModel: "qmodel_preview", completed: true,
  counters: { preflight: 1, catalogRemoteLoad: 1, modelsList: 1, modelRetrieve: 1, prompt: 1, inference: 1, response: 1, tools: 0, refresh: 0, retries: 0, extraInference: 0 },
};

describe("routing attestation verifier", () => {
  it("accepts a single ANSI decorated exact record", () => {
    const raw = `\x1b]8;;https://example.invalid\x07\x1b[32m${JSON.stringify(VALID)}\x1b[0m\x1b]8;;\x07\n`;
    expect(verifyRoutingAttestation(raw, VALID)).toEqual(VALID);
  });
  it("accepts catalog recovery without an extra inference", () => {
    const recovered = { ...VALID, counters: { ...VALID.counters, catalogRemoteLoad: 2, refresh: 1, retries: 1 } };
    expect(verifyRoutingAttestation(`${JSON.stringify(recovered)}\n`, recovered)).toEqual(recovered);
  });
  it("accepts mixed catalog and inference recovery", () => {
    const recovered = { ...VALID, counters: { ...VALID.counters, catalogRemoteLoad: 2, refresh: 2, retries: 2, inference: 2, extraInference: 1 } };
    expect(verifyRoutingAttestation(`${JSON.stringify(recovered)}\n`, recovered)).toEqual(recovered);
  });
  for (const [name, raw] of [
    ["duplicate", `${JSON.stringify(VALID)}\n${JSON.stringify(VALID)}\n`],
    ["malformed", '{"schema":"qoder-proxy-live-attestation/v1"\n'],
    ["missing field", `${JSON.stringify({ ...VALID, responseModel: undefined })}\n`],
    ["unterminated OSC", `\x1b]8;;unterminated${JSON.stringify(VALID)}\n`],
    ["counter mismatch", `${JSON.stringify({ ...VALID, counters: { ...VALID.counters, extraInference: 1 } })}\n`],
    ["non-allowlisted-looking model", `${JSON.stringify({ ...VALID, requestModel: "opaque-secret" })}\n`],
    ["success routing mismatch", `${JSON.stringify({ ...VALID, requestModel: "auto" })}\n`],
  ] as const) {
    it(`fails closed for ${name}`, () => expect(() => verifyRoutingAttestation(raw)).toThrow());
  }
});
