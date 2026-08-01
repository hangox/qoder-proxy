// Anthropic Messages → CN legacy body 纯转换器（零 IO）。
//
// 迁移自 Gate 0 已验证 PoC 的 CN body 字段集，禁止新增未经验证字段。未知顶层字段/消息角色/
// content block 一律 fail-closed。thinking/metadata/context_management/output_config/
// stop_sequences/model/stream 等已知但不支持的字段记录到 provenance（不进上游 body）。

import { randomUUID } from "node:crypto";
import type { QoderAssistantModel } from "./models.ts";

export const MAX_CN_MAX_TOKENS = 1024;

type AnthropicBlock = { type?: string; text?: string; id?: string; name?: string; input?: unknown; tool_use_id?: string; content?: unknown; is_error?: boolean };

const ANTHROPIC_KNOWN = new Set(["model", "system", "messages", "tools", "max_tokens", "tool_choice", "stream", "metadata", "stop_sequences", "thinking", "context_management", "output_config"]);
// 已知但首版不支持：显式降级进 provenance.ignoredFields，不静默丢弃，不进上游 body。
const ANTHROPIC_IGNORED = new Set(["metadata", "stop_sequences", "thinking", "context_management", "output_config", "stream"]);

export class ConversionError extends Error {}

function fail(message: string): never {
  throw new ConversionError(message);
}

function anthropicSystemToString(system: unknown): string {
  if (typeof system === "string") return system;
  if (system === undefined || system === null) return "";
  if (!Array.isArray(system)) fail("Anthropic system 不是 string/text blocks");
  return system.map((b, i) => { const r = b as AnthropicBlock; if (r.type !== "text" || typeof r.text !== "string") fail(`system block ${i} 不是 text`); return r.text as string; }).join("\n\n");
}

function anthropicContentToText(content: unknown, label: string): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) fail(`${label} 不是 string/blocks`);
  return content.map((b, i) => { const r = b as AnthropicBlock; if (r.type !== "text" || typeof r.text !== "string") fail(`${label} block ${i} 不是 text`); return r.text as string; }).join("\n");
}

// role=tool 消息按 CN legacy 契约需要携带原 tool_call_id 对应的 name（回查前序 assistant tool_use）。
function convertAnthropicMessage(record: Record<string, unknown>, idx: number, toolNameById: Map<string, string>): Array<Record<string, unknown>> {
  const role = String(record.role ?? "");
  if (!["system", "user", "assistant", "tool"].includes(role)) fail(`message ${idx} role 不受支持: ${role}`);
  // Anthropic Messages 的工具结果必须以 user.tool_result block 传入，以便回查前序 tool_use 的原 id/name。
  // 直接 role=tool 无法保证 CN legacy 所需的 name 契约，因此明确拒绝。
  if (role === "tool") fail(`message ${idx} 直接 role=tool 不受支持；请使用 user.tool_result`);

  if (typeof record.content === "string") return [{ role, content: record.content }];
  if (!Array.isArray(record.content)) fail(`message ${idx} content 不是 string/blocks`);
  const blocks = record.content as AnthropicBlock[];

  if (role === "assistant") {
    const texts: string[] = [], toolCalls: Array<Record<string, unknown>> = [];
    for (const b of blocks) {
      if (b.type === "text" && typeof b.text === "string") { texts.push(b.text); continue; }
      if (b.type === "tool_use") {
        if (typeof b.id !== "string" || !b.id) fail(`assistant tool_use block 缺少 id (message ${idx})`);
        if (typeof b.name !== "string" || !b.name) fail(`assistant tool_use block 缺少 name (message ${idx})`);
        toolNameById.set(b.id, b.name);
        toolCalls.push({ id: b.id, type: "function", function: { name: b.name, arguments: JSON.stringify(b.input ?? {}) } });
        continue;
      }
      fail(`assistant block type 不受支持: ${b.type ?? "missing"}`);
    }
    const c: Record<string, unknown> = { role: "assistant", content: texts.length > 0 ? texts.join("\n") : null };
    if (toolCalls.length > 0) c.tool_calls = toolCalls;
    return [c];
  }

  if (role === "user") {
    // 同一 user 消息内：全部 role=tool（tool_result）先输出，普通文本随后合并输出一条（顺序修正）。
    const toolMessages: Array<Record<string, unknown>> = [];
    const textParts: string[] = [];
    for (const b of blocks) {
      if (b.type === "text" && typeof b.text === "string") { textParts.push(b.text); continue; }
      if (b.type === "tool_result") {
        if (typeof b.tool_use_id !== "string" || !b.tool_use_id) fail(`user tool_result block 缺少 tool_use_id (message ${idx})`);
        const name = toolNameById.get(b.tool_use_id);
        if (!name) fail(`user tool_result 引用了未知 tool_use_id: ${b.tool_use_id} (message ${idx})`);
        const content = anthropicContentToText(b.content ?? "", "tool_result");
        toolMessages.push({ role: "tool", tool_call_id: b.tool_use_id, name, content: b.is_error === true ? JSON.stringify({ is_error: true, content }) : content });
        continue;
      }
      fail(`user block type 不受支持: ${b.type ?? "missing"}`);
    }
    const out: Array<Record<string, unknown>> = [...toolMessages];
    if (textParts.length > 0) out.push({ role: "user", content: textParts.join("\n") });
    if (out.length === 0) fail(`user message ${idx} content blocks 转换后为空`);
    return out;
  }

  return [{ role: "system", content: anthropicContentToText(record.content, `system ${idx}`) }];
}

function convertToolChoice(tc: unknown): string {
  if (tc === undefined || tc === null) return "auto";
  if (typeof tc === "object" && !Array.isArray(tc)) {
    const type = (tc as { type?: string }).type;
    if (type === "auto") return "auto";
    if (type === "any" || type === "required") return "required";
    if (type === "none") return "none";
    if (type === "tool") fail("tool_choice type=tool 不支持");
  }
  fail("tool_choice 不受支持");
}

export type Provenance = {
  originalMaxTokens: number;
  cnMaxTokens: number;
  maxTokensTruncated: boolean;
  ignoredFields: string[];
  requestedModel: string | undefined;
};

export type CnConversion = { body: Record<string, unknown>; provenance: Provenance };

export function validateAnthropicRequestEnvelope(anthropic: Record<string, unknown>): string | undefined {
  for (const key of Object.keys(anthropic)) if (!ANTHROPIC_KNOWN.has(key)) fail(`Anthropic 未知字段: ${key}`);
  if (anthropic.model === undefined) return undefined;
  if (typeof anthropic.model !== "string" || anthropic.model.trim().length === 0) fail("model 必须是非空字符串");
  return anthropic.model;
}

export function convertAnthropicToCnBody(anthropic: Record<string, unknown>, resolvedModel: QoderAssistantModel): CnConversion {
  const requestedModel = validateAnthropicRequestEnvelope(anthropic);
  const system = anthropicSystemToString(anthropic.system);
  const msgs = Array.isArray(anthropic.messages) ? anthropic.messages as Array<Record<string, unknown>> : [];
  if (msgs.length === 0) fail("messages 为空");

  const toolNameById = new Map<string, string>();
  const messages: Array<Record<string, unknown>> = [];
  if (system) messages.push({ role: "system", content: system });
  msgs.forEach((m, i) => messages.push(...convertAnthropicMessage(m, i, toolNameById)));
  if (messages.length === 0) fail("messages 转换后为空");

  if (anthropic.tools !== undefined && !Array.isArray(anthropic.tools)) fail("tools 必须是数组");
  const tools = Array.isArray(anthropic.tools) ? anthropic.tools.map((t, i) => {
    const r = t as Record<string, unknown>;
    if (typeof r.name !== "string" || !r.name) fail(`tool ${i} name 缺失`);
    if (r.description !== undefined && typeof r.description !== "string") fail(`tool ${i} description 类型错误`);
    if (r.input_schema !== undefined && (typeof r.input_schema !== "object" || r.input_schema === null || Array.isArray(r.input_schema))) fail(`tool ${i} input_schema 类型错误`);
    return { type: "function", function: { name: r.name, description: r.description ?? "", parameters: r.input_schema ?? {} } };
  }) : [];

  const toolChoice = convertToolChoice(anthropic.tool_choice);
  if (anthropic.max_tokens !== undefined && (!Number.isInteger(anthropic.max_tokens) || (anthropic.max_tokens as number) <= 0)) fail("max_tokens 必须是正整数");
  const origMax = typeof anthropic.max_tokens === "number" ? anthropic.max_tokens : 1024;
  const cnMax = Math.min(origMax, MAX_CN_MAX_TOKENS);
  const id = randomUUID();
  const body: Record<string, unknown> = {
    request_id: id, request_set_id: id, chat_record_id: id, session_id: randomUUID(),
    stream: true, chat_task: "FREE_INPUT", is_reply: true, is_retry: false, source: 1, version: "3",
    agent_id: "agent_common", task_id: "common", session_type: "qoderclicn", aliyun_user_type: "",
    model_config: { key: resolvedModel.key, display_name: resolvedModel.displayName, model: "", format: resolvedModel.format, is_vl: resolvedModel.isVision, is_reasoning: resolvedModel.isReasoning, api_key: "", url: "", source: resolvedModel.source, max_input_tokens: resolvedModel.maxInputTokens },
    system: "", messages, tools, tool_choice: toolChoice, parameters: { max_tokens: cnMax },
  };
  if (Object.keys(body).some((k) => k.startsWith("_"))) fail("body 含 _ 前缀字段");

  return {
    body,
    provenance: {
      originalMaxTokens: origMax,
      cnMaxTokens: cnMax,
      maxTokensTruncated: origMax > MAX_CN_MAX_TOKENS,
      ignoredFields: [...ANTHROPIC_IGNORED].filter((f) => f in anthropic),
      requestedModel,
    },
  };
}
