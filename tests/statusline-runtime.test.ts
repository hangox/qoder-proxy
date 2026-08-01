import { describe, expect, it } from "vitest";
import { readQoderManagedLeaseStatus } from "../src/statusline-runtime.ts";

const leaseId = "0123456789abcdef0123456789abcdef";
const base = "http://127.0.0.1:7788";

function env(extra: Record<string, string | undefined> = {}) {
  return { PATH: process.env.PATH, HOME: process.env.HOME, TMPDIR: process.env.TMPDIR, ANTHROPIC_BASE_URL: base, ...extra };
}

describe("Qoder managed statusline live lease", () => {
  it("preserves legacy mode when managed identity is absent", () => {
    expect(readQoderManagedLeaseStatus(env())).toEqual({ mode: "legacy", active: false });
  });
  it("rejects partial managed identity without legacy fallback", () => {
    expect(readQoderManagedLeaseStatus(env({ QODER_PROXY_RUNTIME_RUN_ID: "run" }))).toMatchObject({ mode: "invalid", active: false });
  });
  it("fails closed when status CLI is unavailable", () => {
    expect(readQoderManagedLeaseStatus(env({ QODER_PROXY_RUNTIME_RUN_ID: "run", QODER_PROXY_RUNTIME_OWNER_PID: String(process.pid), QODER_PROXY_RUNTIME_LEASE_ID: leaseId, QODER_PROXY_RUNTIME_SOCKET: "/tmp/missing-runtime.sock", QODER_PROXY_RUNTIME_CLI: "/tmp/missing-qoder-proxy" }))).toMatchObject({ mode: "managed", active: false, runId: "run" });
  });
  it("rejects qoderclicn resolver", () => {
    expect(readQoderManagedLeaseStatus(env({ QODER_PROXY_RUNTIME_RUN_ID: "run", QODER_PROXY_RUNTIME_OWNER_PID: String(process.pid), QODER_PROXY_RUNTIME_LEASE_ID: leaseId, QODER_PROXY_RUNTIME_SOCKET: "/tmp/runtime.sock", QODER_PROXY_RUNTIME_CLI: "/tmp/qoderclicn" }))).toMatchObject({ mode: "managed", active: false });
  });
});
