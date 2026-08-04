// 极简日志：永不打印 token/正文/凭据。只输出结构化非敏感字段，且字段名必须在白名单内。

type LogLevel = "debug" | "info" | "warn" | "error";

// 白名单字段：只允许布尔值/数值/字符串（字符串值本身也不得是原始 token/正文，调用方负责传入
// 已脱敏的值，例如 errorClass、status、hash、字段名列表、计数）。
const ALLOWED_FIELDS = new Set([
  "errorClass", "status", "bodyHash", "errorHash",
  "host", "route", "method", "durationMs", "port", "hostname",
  "truncated", "originalMaxTokens", "cnMaxTokens", "ignoredFields", "modelProvided",
  "toolCount", "reason", "attempt", "apiKeyPresent", "configDir", "via", "code",
  "aborted", "timeoutMs", "messageId", "exitPath", "doneObserved", "finishEventObserved", "finishReason", "blockCount", "toolCallCount", "stderrPath", "maxBytes", "rotationFiles", "toolFinalizeReason", "toolChoiceIndex", "toolIndex", "toolArgumentBytes", "toolFragmentCount",
]);

function sanitizeFields(fields?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!fields) return undefined;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields)) {
    if (!ALLOWED_FIELDS.has(k)) continue;
    out[k] = v;
  }
  return out;
}

function log(level: LogLevel, message: string, fields?: Record<string, unknown>): void {
  const entry = { level, message, ...sanitizeFields(fields), ts: new Date().toISOString() };
  // stderr 输出，不污染 stdout（stdout 留给代理响应）。
  console.error(JSON.stringify(entry));
}

export const logger = {
  debug: (msg: string, fields?: Record<string, unknown>) => log("debug", msg, fields),
  info: (msg: string, fields?: Record<string, unknown>) => log("info", msg, fields),
  warn: (msg: string, fields?: Record<string, unknown>) => log("warn", msg, fields),
  error: (msg: string, fields?: Record<string, unknown>) => log("error", msg, fields),
};
