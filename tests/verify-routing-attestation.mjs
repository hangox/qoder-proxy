// 本地 QA routing attestation verifier；不启动 proxy、不访问网络、不读取凭据。
import { readFileSync } from "node:fs";

const TOP_LEVEL_KEYS = ["completed", "counters", "message", "modelProvided", "prepareInferModel", "requestModel", "resolvedModel", "responseModel", "schema"];
const COUNTER_KEYS = ["catalogRemoteLoad", "extraInference", "inference", "modelRetrieve", "modelsList", "preflight", "prompt", "refresh", "response", "retries", "tools"];
const MODEL_RE = /^[A-Za-z0-9._-]{1,128}$/;
const TARGET_MODEL = "qmodel_38max";
function sameKeys(value, expected) { return value !== null && typeof value === "object" && !Array.isArray(value) && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort()); }
export function stripTerminalControls(line) {
  let clean = line.replace(/\x1b\][^\x07\x1b\r\n]*(?:\x07|\x1b\\)/g, "");
  clean = clean.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "").replace(/[0-?]*[ -/]*[@-~]/g, "");
  if (/[\x1b]/.test(clean)) throw new Error("terminal-control-residue");
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(clean)) throw new Error("unexpected-control-character");
  return clean;
}
function isModelOrNull(value) { return value === null || (typeof value === "string" && MODEL_RE.test(value)); }
function verifyRecord(record) {
  if (!sameKeys(record, TOP_LEVEL_KEYS)) throw new Error("top-level-schema");
  if (record.schema !== "qoder-proxy-live-attestation/v1" || record.message !== "请求溯源" || typeof record.modelProvided !== "boolean" || typeof record.completed !== "boolean") throw new Error("schema-shape");
  for (const key of ["requestModel", "resolvedModel", "prepareInferModel", "responseModel"]) if (!isModelOrNull(record[key])) throw new Error(`model-shape:${key}`);
  if (!sameKeys(record.counters, COUNTER_KEYS)) throw new Error("counter-schema");
  for (const [key, value] of Object.entries(record.counters)) if (!Number.isSafeInteger(value) || value < 0) throw new Error(`counter-shape:${key}`);
  // retries 统计恢复导致的额外 operation attempt：额外推理 + catalog 401 后第二次目录加载；
  // extraInference 只统计额外 infer。目录可命中缓存，因此 catalogRemoteLoad 不要求有固定 baseline。
  if (record.counters.extraInference !== Math.max(0, record.counters.inference - 1)
    || record.counters.retries < record.counters.extraInference
    || record.counters.refresh > record.counters.retries
    || record.counters.retries - record.counters.extraInference > record.counters.catalogRemoteLoad) throw new Error("counter-invariant");
  if (record.completed) {
    for (const key of ["requestModel", "resolvedModel", "prepareInferModel", "responseModel"]) if (!(typeof record[key] === "string" && MODEL_RE.test(record[key]) && record[key] === TARGET_MODEL)) throw new Error(`completed-model:${key}`);
    if (record.requestModel !== record.resolvedModel || record.resolvedModel !== record.prepareInferModel || record.responseModel !== record.prepareInferModel) throw new Error("completed-routing-mismatch");
    if (record.counters.prompt !== 1 || record.counters.response !== 1 || record.counters.inference < 1) throw new Error("completed-counter-invariant");
  } else {
    if (record.responseModel !== null || record.counters.response !== 0 || record.counters.prompt !== 1) throw new Error("failed-terminal-invariant");
    if (!record.modelProvided && record.requestModel !== null) throw new Error("missing-model-invariant");
  }
}
export function verifyRoutingAttestation(raw, expected) {
  const records = [];
  for (const physicalLine of raw.split(/\r?\n/)) {
    if (!physicalLine) continue;
    const line = stripTerminalControls(physicalLine);
    if (!line.trim()) continue;
    let record; try { record = JSON.parse(line); } catch { throw new Error("malformed-json"); }
    verifyRecord(record); records.push(record);
  }
  if (records.length !== 1) throw new Error("attestation-count");
  if (expected !== undefined && JSON.stringify(records[0]) !== JSON.stringify(expected)) throw new Error("expected-mismatch");
  return records[0];
}
if (import.meta.main) {
  const [file, expectedText] = process.argv.slice(2);
  if (!file || !expectedText) throw new Error("usage: verify-routing-attestation.mjs <jsonl-file> <expected-json>");
  const record = verifyRoutingAttestation(readFileSync(file, "utf8"), JSON.parse(expectedText));
  process.stdout.write(`PASS request=${record.requestModel} routing=${record.prepareInferModel} counters=exact\n`);
}
