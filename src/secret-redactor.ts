import { StringDecoder } from "node:string_decoder";

export type StreamingSecretRedactor = {
  write(chunk: Buffer | string): void;
  flush(): void;
};

export function createStreamingSecretRedactor(secret: string, sink: (chunk: string) => void): StreamingSecretRedactor {
  if (secret.length === 0) throw new Error("脱敏 secret 不能为空");
  const replacement = secret.includes("[redacted]") || secret.includes("[REDACTED]") ? "" : "[redacted]";
  const decoder = new StringDecoder("utf8");
  let carry = "";
  let flushed = false;

  const processText = (text: string): void => {
    if (text.length === 0) return;
    const combined = carry + text;
    const safe = combined.split(secret).join(replacement);
    const cutoff = Math.max(0, safe.length - secret.length + 1);
    sink(safe.slice(0, cutoff));
    carry = safe.slice(cutoff);
  };

  const write = (chunk: Buffer | string): void => {
    if (flushed) return;
    processText(Buffer.isBuffer(chunk) ? decoder.write(chunk) : chunk);
  };

  const flush = (): void => {
    if (flushed) return;
    flushed = true;
    processText(decoder.end());
    sink(carry.split(secret).join(replacement));
    carry = "";
  };

  return { write, flush };
}
