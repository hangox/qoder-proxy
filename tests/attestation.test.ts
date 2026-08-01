import { mkdtemp, lstat, readFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../src/cli.ts";
import type { AuthSession } from "../src/auth/session.ts";
import { createRoutingAttestation, ROUTING_ATTESTATION_FILE, ROUTING_ATTESTATION_SCHEMA } from "../src/attestation.ts";

const cleanupRoots: string[] = [];
afterEach(async () => { await Promise.all(cleanupRoots.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

function nonce(seed: string): string { return seed.repeat(32).slice(0, 32); }
async function fixtureEnv(seed: string): Promise<{ dir: string; env: Record<string, string> }> {
  const parent = await mkdtemp(join(tmpdir(), "qoder-attestation-test-"));
  cleanupRoots.push(parent);
  const value = nonce(seed);
  const dir = join(parent, `qoder-proxy-qa-attestation-${value}`);
  return { dir, env: { QODER_PROXY_QA_ATTESTATION_DIR: dir, QODER_PROXY_QA_ATTESTATION_NONCE: value } };
}
function claimTarget(sink: NonNullable<ReturnType<typeof createRoutingAttestation>>, tools = 0) {
  const lease = sink.beginMessage();
  return lease.claim({ modelProvided: true, requestModel: "qmodel_preview", resolvedModel: "qmodel_preview", tools, catalogModels: ["qmodel_preview"] });
}
function successfulRecord(sink: NonNullable<ReturnType<typeof createRoutingAttestation>>) {
  sink.recordPreflight();
  const auxiliary = sink.beginAuxiliary();
  auxiliary.allowCatalogModels(["qmodel_preview"]);
  auxiliary.recordCatalogRemoteLoad();
  auxiliary.recordModelsList();
  auxiliary.recordModelRetrieve();
  auxiliary.release(true);
  const lease = sink.beginMessage();
  const request = lease.claim({ modelProvided: true, requestModel: "qmodel_preview", resolvedModel: "qmodel_preview", tools: 0, catalogModels: ["qmodel_preview"] });
  request.setPrepareInferModel("qmodel_preview");
  request.recordInference();
  request.finalize(true);
}

describe("routing QA attestation", () => {
  it("is disabled unless both opt-in variables exist", () => {
    expect(createRoutingAttestation({})).toBeUndefined();
    expect(() => createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: "/tmp/x" })).toThrow(/目录与 nonce/);
  });

  it("creates a private exclusive JSONL sink with exact successful schema", async () => {
    const { dir, env } = await fixtureEnv("a");
    const sink = createRoutingAttestation(env)!;
    successfulRecord(sink);
    sink.close();
    const dirStat = await lstat(dir);
    const file = join(dir, ROUTING_ATTESTATION_FILE);
    const fileStat = await lstat(file);
    expect(dirStat.isDirectory()).toBe(true);
    expect(dirStat.mode & 0o077).toBe(0);
    expect(fileStat.isFile()).toBe(true);
    expect(fileStat.mode & 0o077).toBe(0);
    expect(JSON.parse(await readFile(file, "utf8"))).toEqual({
      schema: ROUTING_ATTESTATION_SCHEMA, message: "请求溯源", modelProvided: true,
      requestModel: "qmodel_preview", resolvedModel: "qmodel_preview", prepareInferModel: "qmodel_preview", responseModel: "qmodel_preview", completed: true,
      counters: { preflight: 1, catalogRemoteLoad: 1, modelsList: 1, modelRetrieve: 1, prompt: 1, inference: 1, response: 1, tools: 0, refresh: 0, retries: 0, extraInference: 0 },
    });
  });

  it("counts successful preflight in the same CLI run sink", async () => {
    const { dir, env } = await fixtureEnv("e");
    const runtime = await runCli(["serve"], { ...env, QODER_PROXY_API_KEY: "test-key" }, undefined, {
      preflight: async () => ({}) as AuthSession,
      bind: (_env, _session, sink) => {
        const request = claimTarget(sink!);
        request.setPrepareInferModel("qmodel_preview"); request.recordInference(); request.finalize(true);
        return { close: () => sink!.close() };
      },
    });
    runtime!.close();
    expect(JSON.parse(await readFile(join(dir, ROUTING_ATTESTATION_FILE), "utf8")).counters.preflight).toBe(1);
  });

  it("does not let invalid/default targets poison the sink", async () => {
    const { dir, env } = await fixtureEnv("b");
    const sink = createRoutingAttestation(env)!;
    for (const input of [
      { modelProvided: true, requestModel: "auto", resolvedModel: "auto" },
      { modelProvided: false, requestModel: undefined, resolvedModel: "auto" },
      { modelProvided: true, requestModel: "unknown", resolvedModel: "unknown" },
    ]) {
      const lease = sink.beginMessage();
      expect(() => lease.claim({ ...input, tools: 0, catalogModels: ["auto", "qmodel_preview"] })).toThrow(/claim|目标模型/);
      lease.release();
    }
    const request = claimTarget(sink);
    request.setPrepareInferModel("qmodel_preview"); request.recordInference(); request.finalize(true);
    sink.close();
    expect(JSON.parse(await readFile(join(dir, ROUTING_ATTESTATION_FILE), "utf8")).completed).toBe(true);
  });

  it("rejects a pre-existing symlink target and emits a single failed terminal record", async () => {
    const { dir, env } = await fixtureEnv("c");
    await symlink(tmpdir(), dir);
    expect(() => createRoutingAttestation(env)).toThrow(/必须不存在/);
    const second = await fixtureEnv("d");
    const sink = createRoutingAttestation(second.env)!;
    const request = claimTarget(sink);
    request.finalize(false);
    expect(() => request.finalize(false)).toThrow(/重复终结/);
    sink.close();
    expect(JSON.parse(await readFile(join(second.dir, ROUTING_ATTESTATION_FILE), "utf8"))).toMatchObject({ completed: false, responseModel: null, counters: { prompt: 1, response: 0 } });
  });

  it("makes released auxiliary observer callbacks inert while active lease APIs remain fail-closed", () => {
    const sink = createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: join(tmpdir(), `qoder-proxy-qa-attestation-${nonce("9")}`), QODER_PROXY_QA_ATTESTATION_NONCE: nonce("9") })!;
    cleanupRoots.push(join(tmpdir(), `qoder-proxy-qa-attestation-${nonce("9")}`));
    const auxiliary = sink.beginAuxiliary();
    auxiliary.release();
    expect(() => auxiliary.recordCatalogRemoteLoad()).not.toThrow();
    expect(() => auxiliary.recordRefresh()).not.toThrow();
    expect(() => auxiliary.recordModelsList()).toThrow(/失效/);
    expect(() => auxiliary.allowCatalogModels(["qmodel_preview"])).toThrow(/失效/);
    sink.close();
  });

  it("commits only successful pre-target auxiliary counters into the claimed artifact", async () => {
    const { dir, env } = await fixtureEnv("8");
    const sink = createRoutingAttestation(env)!;
    const failed = sink.beginAuxiliary();
    failed.recordCatalogRemoteLoad();
    failed.recordRefresh();
    failed.recordRetry();
    failed.recordModelsList();
    failed.release(false);
    const completed = sink.beginAuxiliary();
    completed.recordCatalogRemoteLoad();
    completed.recordRefresh();
    completed.recordRetry();
    completed.recordCatalogRemoteLoad();
    completed.recordModelsList();
    completed.recordModelRetrieve();
    completed.allowCatalogModels(["qmodel_preview"]);
    completed.release(true);
    const request = claimTarget(sink);
    request.setPrepareInferModel("qmodel_preview");
    request.recordInference();
    request.finalize(true);
    failed.recordCatalogRemoteLoad();
    completed.recordCatalogRemoteLoad();
    sink.close();
    expect(JSON.parse(await readFile(join(dir, ROUTING_ATTESTATION_FILE), "utf8")).counters).toEqual({
      preflight: 0, catalogRemoteLoad: 2, modelsList: 1, modelRetrieve: 1, prompt: 1, inference: 1, response: 1, tools: 0, refresh: 1, retries: 1, extraInference: 0,
    });
  });

  it("blocks target claim while auxiliary leases run and releases after error-safe completion", () => {
    const sink = createRoutingAttestation({ QODER_PROXY_QA_ATTESTATION_DIR: join(tmpdir(), `qoder-proxy-qa-attestation-${nonce("f")}`), QODER_PROXY_QA_ATTESTATION_NONCE: nonce("f") })!;
    cleanupRoots.push(join(tmpdir(), `qoder-proxy-qa-attestation-${nonce("f")}`));
    const first = sink.beginAuxiliary();
    const second = sink.beginAuxiliary();
    const rejectedFirst = sink.beginMessage();
    expect(() => rejectedFirst.claim({ modelProvided: true, requestModel: "qmodel_preview", resolvedModel: "qmodel_preview", tools: 0, catalogModels: ["qmodel_preview"] })).toThrow(/claim/);
    rejectedFirst.release();
    first.release();
    const rejectedSecond = sink.beginMessage();
    expect(() => rejectedSecond.claim({ modelProvided: true, requestModel: "qmodel_preview", resolvedModel: "qmodel_preview", tools: 0, catalogModels: ["qmodel_preview"] })).toThrow(/claim/);
    rejectedSecond.release();
    second.release();
    const target = claimTarget(sink);
    expect(() => sink.beginAuxiliary()).toThrow(/绑定/);
    target.finalize(false);
    sink.close();
  });
});
