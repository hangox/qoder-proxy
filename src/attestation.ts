// 仅供显式本地 QA 启用的路由证明 sink。默认关闭，且不复用普通 logger 白名单。
// 唯一允许的落盘内容是已验证 catalog routing key、完成态与固定计数；绝不写 header、token、body、prompt 内容、catalog、UID、machine ID、URL 或 API key。

import { closeSync, constants as fsConstants, fchmodSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, writeSync } from "node:fs";
import { basename, isAbsolute, join } from "node:path";

const SCHEMA = "qoder-proxy-live-attestation/v1" as const;
const MESSAGE = "请求溯源" as const;
const RECORD_FILE = "routing-attestation.jsonl";
const NONCE_RE = /^[a-f0-9]{32}$/;
const MODEL_RE = /^[A-Za-z0-9._-]{1,128}$/;
const TARGET_MODEL = "qmodel_preview";

type AttestedModel = string | null;

export type RoutingCounters = {
  preflight: number;
  catalogRemoteLoad: number;
  modelsList: number;
  modelRetrieve: number;
  prompt: number;
  inference: number;
  response: number;
  tools: number;
  refresh: number;
  retries: number;
  extraInference: number;
};

export type AttestationRecord = {
  schema: typeof SCHEMA;
  message: typeof MESSAGE;
  modelProvided: boolean;
  requestModel: AttestedModel;
  resolvedModel: AttestedModel;
  prepareInferModel: AttestedModel;
  responseModel: AttestedModel;
  completed: boolean;
  counters: RoutingCounters;
};

function emptyCounters(): RoutingCounters {
  return { preflight: 0, catalogRemoteLoad: 0, modelsList: 0, modelRetrieve: 0, prompt: 0, inference: 0, response: 0, tools: 0, refresh: 0, retries: 0, extraInference: 0 };
}
function cloneCounters(counters: RoutingCounters): RoutingCounters {
  for (const value of Object.values(counters)) if (!Number.isSafeInteger(value) || value < 0) throw new Error("QA attestation counter 非法");
  return { ...counters };
}
function validToolsCount(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("QA attestation tool counter 非法");
  return value;
}

export type RoutingMessageAttestation = {
  setResolvedModel(model: string): void;
  setPrepareInferModel(model: string): void;
  recordInference(): void;
  recordRetry(): void;
  finalize(completed: boolean): void;
};
export type RoutingAuxiliaryLease = RoutingAttestationSessionObserver & {
  allowCatalogModels(models: readonly string[]): void;
  recordModelsList(): void;
  recordModelRetrieve(): void;
  release(completed?: boolean): void;
};
export type RoutingMessageLease = RoutingAttestationSessionObserver & {
  claim(input: { modelProvided: boolean; requestModel: string | undefined; resolvedModel: string; tools: number; catalogModels: readonly string[] }): RoutingMessageAttestation;
  release(): void;
};
export type RoutingAttestationSessionObserver = { recordCatalogRemoteLoad(): void; recordRefresh(): void; recordRetry(): void };
export type RoutingAttestation = {
  recordPreflight(): void;
  beginAuxiliary(): RoutingAuxiliaryLease;
  beginMessage(): RoutingMessageLease;
  close(): void;
};

class LocalRoutingAttestation implements RoutingAttestation {
  private readonly counters = emptyCounters();
  private readonly preTargetCounters = emptyCounters();
  private readonly allowedModels = new Set<string>();
  private activeAuxiliaries = 0;
  private activeMessages = 0;
  private auxiliaryGeneration = 0;
  private messageClaimed = false;
  private targetActive = false;
  private written = false;
  constructor(private readonly fd: number) {}
  recordPreflight(): void { this.counters.preflight++; }
  recordCatalogRemoteLoad(): void { if (this.targetActive) this.counters.catalogRemoteLoad++; }
  recordRefresh(): void { if (this.targetActive) this.counters.refresh++; }
  private assertTargetModel(value: string | undefined): string {
    if (value !== TARGET_MODEL || !MODEL_RE.test(value)) throw new Error("QA attestation 只接受 qmodel_preview 目标模型");
    return value;
  }
  beginAuxiliary(): RoutingAuxiliaryLease {
    if (this.messageClaimed) throw new Error("QA attestation 已绑定目标 Messages 请求，拒绝并发非目标请求");
    const generation = this.auxiliaryGeneration;
    const pending = emptyCounters();
    const pendingModels = new Set<string>();
    this.activeAuxiliaries++;
    let released = false;
    const isLive = (): boolean => !released && !this.messageClaimed && generation === this.auxiliaryGeneration;
    const assertLive = (): void => {
      if (!isLive()) throw new Error("QA attestation auxiliary lease 已失效");
    };
    // AuthSession single-flight 可在路由 finally 释放后才完成；后台计数钩子必须是可安全失活的 attribution，不能把已释放 lease 的状态带入共享 promise。
    const recordLateSafe = (key: "catalogRemoteLoad" | "refresh" | "retries"): void => {
      if (isLive()) pending[key]++;
    };
    return {
      recordCatalogRemoteLoad: () => recordLateSafe("catalogRemoteLoad"),
      recordRefresh: () => recordLateSafe("refresh"),
      recordRetry: () => recordLateSafe("retries"),
      allowCatalogModels: (models) => {
        assertLive();
        for (const model of models) if (MODEL_RE.test(model)) pendingModels.add(model);
      },
      recordModelsList: () => { assertLive(); pending.modelsList++; },
      recordModelRetrieve: () => { assertLive(); pending.modelRetrieve++; },
      release: (completed = false) => {
        if (released) return;
        const commit = completed && isLive();
        released = true;
        this.activeAuxiliaries--;
        if (this.activeAuxiliaries < 0) throw new Error("QA attestation auxiliary lease 计数非法");
        if (!commit) return;
        this.preTargetCounters.catalogRemoteLoad += pending.catalogRemoteLoad;
        this.preTargetCounters.modelsList += pending.modelsList;
        this.preTargetCounters.modelRetrieve += pending.modelRetrieve;
        this.preTargetCounters.refresh += pending.refresh;
        this.preTargetCounters.retries += pending.retries;
        for (const model of pendingModels) this.allowedModels.add(model);
      },
    };
  }
  beginMessage(): RoutingMessageLease {
    if (this.messageClaimed) throw new Error("QA attestation 已绑定目标 Messages 请求，拒绝并发请求");
    this.activeMessages++;
    let released = false;
    let claimed = false;
    let pendingCatalogLoads = 0;
    let pendingRefreshes = 0;
    let pendingRetries = 0;
    // 与 auxiliary 一样，后台 single-flight 在 reservation 释放后可继续 settle；失活回调只忽略，不得向共享 promise 抛错。
    const recordTargetCatalog = (): void => {
      if (released) return;
      if (claimed && this.targetActive) this.counters.catalogRemoteLoad++;
      else pendingCatalogLoads++;
    };
    const recordTargetRefresh = (): void => {
      if (released) return;
      if (claimed && this.targetActive) this.counters.refresh++;
      else pendingRefreshes++;
    };
    const recordTargetRetry = (): void => {
      if (released) return;
      if (claimed && this.targetActive) this.counters.retries++;
      else pendingRetries++;
    };
    const release = (): void => {
      if (released) return;
      released = true;
      this.activeMessages--;
      if (this.activeMessages < 0) throw new Error("QA attestation message lease 计数非法");
    };
    return {
      recordCatalogRemoteLoad: recordTargetCatalog,
      recordRefresh: recordTargetRefresh,
      recordRetry: recordTargetRetry,
      claim: (input) => {
        const tools = validToolsCount(input.tools);
        // 所有拒绝检查先完成，确保无效/默认/disabled 请求不会占用一次性 target artifact。
        const requestModel = this.assertTargetModel(input.requestModel);
        const resolvedModel = this.assertTargetModel(input.resolvedModel);
        if (released || claimed || !input.modelProvided || requestModel !== resolvedModel || !input.catalogModels.includes(TARGET_MODEL) || this.messageClaimed || this.activeAuxiliaries !== 0 || this.activeMessages !== 1) {
          throw new Error("QA attestation target claim 被拒绝");
        }
        claimed = true;
        this.allowedModels.add(TARGET_MODEL);
        this.messageClaimed = true;
        this.targetActive = true;
        this.auxiliaryGeneration++;
        this.counters.prompt++;
        this.counters.tools += tools;
        this.counters.catalogRemoteLoad += this.preTargetCounters.catalogRemoteLoad + pendingCatalogLoads;
        this.counters.modelsList += this.preTargetCounters.modelsList;
        this.counters.modelRetrieve += this.preTargetCounters.modelRetrieve;
        this.counters.refresh += this.preTargetCounters.refresh + pendingRefreshes;
        this.counters.retries += this.preTargetCounters.retries + pendingRetries;
        pendingCatalogLoads = 0;
        pendingRefreshes = 0;
        pendingRetries = 0;
        let resolved = resolvedModel;
        let prepared: AttestedModel = null;
        let finalized = false;
        let inferenceAttempts = 0;
        return {
          setResolvedModel: (model) => { resolved = this.assertTargetModel(model); },
          setPrepareInferModel: (model) => { prepared = this.assertTargetModel(model); },
          recordInference: () => { inferenceAttempts++; this.counters.inference++; if (inferenceAttempts > 1) this.counters.extraInference++; },
          recordRetry: () => { this.counters.retries++; },
          finalize: (completed) => {
            if (finalized) throw new Error("QA attestation 重复终结");
            finalized = true;
            if (this.written) throw new Error("QA attestation 只允许一条 record");
            const isCompleted = completed === true;
            if (isCompleted && prepared !== TARGET_MODEL) throw new Error("QA attestation 成功记录缺少已验证模型边界");
            if (isCompleted) this.counters.response++;
            const record: AttestationRecord = {
              schema: SCHEMA,
              message: MESSAGE,
              modelProvided: input.modelProvided,
              requestModel,
              resolvedModel: resolved,
              prepareInferModel: prepared,
              responseModel: isCompleted ? prepared : null,
              completed: isCompleted,
              counters: cloneCounters(this.counters),
            };
            writeSync(this.fd, Buffer.from(`${JSON.stringify(record)}\n`, "utf8"));
            fsyncSync(this.fd);
            this.written = true;
            this.targetActive = false;
            release();
          },
        };
      },
      release,
    };
  }
  close(): void { closeSync(this.fd); }
}

// 启用必须同时提供随机 nonce 与一个尚不存在的专用目录。目录由本进程创建为 0700，
// sink 文件 O_EXCL|O_NOFOLLOW 创建且为 0600；不会把证明写入普通生产日志或攻击者预置路径。
export function createRoutingAttestation(env: Record<string, string | undefined>): RoutingAttestation | undefined {
  const dir = env.QODER_PROXY_QA_ATTESTATION_DIR;
  const nonce = env.QODER_PROXY_QA_ATTESTATION_NONCE;
  if (dir === undefined && nonce === undefined) return undefined;
  if (!dir || !nonce) throw new Error("QA attestation 必须同时设置目录与 nonce");
  if (!NONCE_RE.test(nonce)) throw new Error("QA attestation nonce 必须是 32 位小写十六进制随机值");
  if (!isAbsolute(dir) || basename(dir) !== `qoder-proxy-qa-attestation-${nonce}`) throw new Error("QA attestation 目录必须是新的绝对专用目录");
  try { mkdirSync(dir, { mode: 0o700 }); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new Error("QA attestation 目录必须不存在");
    throw error;
  }
  const dirStat = lstatSync(dir);
  if (dirStat.isSymbolicLink() || !dirStat.isDirectory() || (dirStat.mode & 0o077) !== 0) throw new Error("QA attestation 目录不安全");
  if (typeof process.getuid === "function" && typeof dirStat.uid === "number" && dirStat.uid !== process.getuid()) throw new Error("QA attestation 目录所有者不匹配");
  const fd = openSync(join(dir, RECORD_FILE), fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
  const fileStat = fstatSync(fd);
  if (!fileStat.isFile() || (fileStat.mode & 0o077) !== 0 || (typeof process.getuid === "function" && typeof fileStat.uid === "number" && fileStat.uid !== process.getuid())) {
    closeSync(fd);
    throw new Error("QA attestation 文件不安全");
  }
  fchmodSync(fd, 0o600);
  return new LocalRoutingAttestation(fd);
}

export const ROUTING_ATTESTATION_SCHEMA = SCHEMA;
export const ROUTING_ATTESTATION_FILE = RECORD_FILE;
