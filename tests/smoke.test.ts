import { describe, it, expect } from "vitest";
import { createApp } from "../src/proxy.ts";

const ENV = { QODER_PROXY_API_KEY: "test-api-key" };
const AUTH_HEADERS = { "content-type": "application/json", "x-api-key": ENV.QODER_PROXY_API_KEY };

describe("smoke", () => {
  it("health route returns ok and is anonymous", async () => {
    const app = createApp(ENV);
    const res = await app.request("/health");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe("ok");
  });

  it("count_tokens returns a conservative estimate when authenticated", async () => {
    const app = createApp(ENV);
    const res = await app.request("/v1/messages/count_tokens", {
      method: "POST",
      headers: AUTH_HEADERS,
      body: JSON.stringify({ messages: [{ role: "user", content: "hello world" }] }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.input_tokens).toBeGreaterThan(0);
  });

  it("count_tokens without API key returns 401", async () => {
    const app = createApp(ENV);
    const res = await app.request("/v1/messages/count_tokens", {
      method: "POST",
      body: JSON.stringify({ messages: [] }),
    });
    expect(res.status).toBe(401);
  });

  it("messages without configured QODER_PROXY_API_KEY fails closed with 500", async () => {
    const app = createApp({});
    const res = await app.request("/v1/messages", {
      method: "POST",
      body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(500);
  });

  it("invalid JSON body returns 400", async () => {
    const app = createApp(ENV);
    const res = await app.request("/v1/messages", {
      method: "POST",
      headers: AUTH_HEADERS,
      body: "not-json",
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.type).toBe("error");
  });

  it("unknown Anthropic field returns 400", async () => {
    const app = createApp(ENV);
    const res = await app.request("/v1/messages", {
      method: "POST",
      headers: AUTH_HEADERS,
      body: JSON.stringify({ messages: [{ role: "user", content: "hi" }], unknown_field: "x" }),
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error.type).toBe("invalid_request_error");
  });

  it("missing credential store fails with 500, not a crash", async () => {
    const app = createApp({ ...ENV, QODER_PROXY_CONFIG_DIR: "/tmp/qoder-proxy-smoke-test-nonexistent" });
    const res = await app.request("/v1/messages", {
      method: "POST",
      headers: AUTH_HEADERS,
      body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.type).toBe("error");
  });
});
