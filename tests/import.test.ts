import { afterEach, describe, expect, it, vi } from "vitest";
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decryptCredentialStorage, sha256, type Bridge } from "../src/auth/bridge.ts";
import { mapDecryptedQoderCredential, prepareQoderImport, readMachineIdFile, type PreparedQoderImport } from "../src/auth/import.ts";
import { createConfigStore, type CredentialStore, type StoredCredential } from "../src/auth/session.ts";
import { resolveServeEnvironment, runCli } from "../src/cli.ts";

const roots: string[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "qoder-proxy-import-"));
  roots.push(root);
  return root;
}

async function sourceFixture(root: string, machineId = "0123456789abcdef-machine"): Promise<string> {
  const source = join(root, "source");
  await mkdir(source, { mode: 0o700 });
  await writeFile(join(source, "machine_id"), `${machineId}\n`, { mode: 0o600 });
  await writeFile(join(source, "user"), "encrypted-payload\n", { mode: 0o600 });
  return source;
}

function importedCredential(machineId = "0123456789abcdef-machine", token = "imported-access"): StoredCredential {
  return { version: 1, site: "cn", machineIdHash: sha256(machineId), token, refreshToken: "imported-refresh", expiresAt: 123, refreshTokenExpiresAt: 456, userId: "uid", userName: "name" };
}

function prepared(machineId = "0123456789abcdef-machine"): PreparedQoderImport {
  return { credential: importedCredential(machineId), machineId, sourceDir: "/safe/source", ignoredFields: ["extra"] };
}

function fakeDecryptBridge(): Bridge {
  return { roles: { credentialStorageDecrypt: "credential_storage_decrypt" } } as Bridge;
}

describe("official credential_storage_decrypt bridge", () => {
  it("uses the retptr ABI and frees the returned string", () => {
    const calls: Array<{ role: string; args: number[] }> = [];
    const freed: Array<[number, number]> = [];
    const bridge: Bridge = {
      roles: { credentialStorageDecrypt: "credential_storage_decrypt" } as never,
      passString: (value) => value === "cipher" ? { ptr: 10, len: 6 } : { ptr: 20, len: 16 },
      callRole: (role, args) => { calls.push({ role, args }); },
      readI32: (address) => address === 100 ? 300 : address === 104 ? 7 : 0,
      freeWasm: (ptr, len) => { freed.push([ptr, len]); },
      withStack: (fn) => fn(100),
      getString: () => "decoded",
      takeObject: () => new Error("wasm error"),
    };
    expect(decryptCredentialStorage(bridge, "cipher", "0123456789abcdef")).toBe("decoded");
    expect(calls).toEqual([{ role: "credentialStorageDecrypt", args: [100, 10, 6, 20, 16] }]);
    expect(freed).toEqual([[300, 7]]);
  });

  it("fails closed when the optional decrypt role is absent", () => {
    expect(() => decryptCredentialStorage({ roles: {} } as Bridge, "cipher", "key")).toThrow(/credential_storage_decrypt/);
  });
});

describe("Qoder source and schema mapping", () => {
  it("maps the verified fields and derives machineIdHash from the full machine ID", () => {
    const machineId = "0123456789abcdef-full-machine-id";
    const result = mapDecryptedQoderCredential(machineId, JSON.stringify({
      security_oauth_token: "access",
      access_token: "access",
      refresh_token: "refresh",
      expire_time: "123",
      refresh_token_expire_time: 456,
      uid: "u",
      name: "n",
      extra: { secret: "ignored" },
    }));
    expect(result.credential).toEqual({ version: 1, site: "cn", machineIdHash: sha256(machineId), token: "access", refreshToken: "refresh", expiresAt: 123, refreshTokenExpiresAt: 456, userId: "u", userName: "n" });
    expect(result.ignoredFields).toEqual(["extra"]);
  });

  it("rejects conflicting, null, empty or whitespace token aliases and invalid expiry", () => {
    expect(() => mapDecryptedQoderCredential("0123456789abcdef", JSON.stringify({ security_oauth_token: "a", access_token: "b" }))).toThrow(/不一致/);
    for (const value of [null, "", "   ", " token "]) {
      expect(() => mapDecryptedQoderCredential("0123456789abcdef", JSON.stringify({ security_oauth_token: value, access_token: "valid" }))).toThrow(/security_oauth_token/);
    }
    expect(() => mapDecryptedQoderCredential("0123456789abcdef", JSON.stringify({ uid: "u" }))).toThrow(/access token/);
    expect(() => mapDecryptedQoderCredential("0123456789abcdef", JSON.stringify({ security_oauth_token: "a", expire_time: -1 }))).toThrow(/有限正数/);
  });

  it("reads only the exact secure source files and passes the first 16 machine-id characters as key", async () => {
    const root = await temporaryRoot();
    const machineId = "0123456789abcdef-full-machine-id";
    const source = await sourceFixture(root, machineId);
    const decrypt = vi.fn(() => JSON.stringify({ security_oauth_token: "access", refresh_token: "refresh" }));
    const result = await prepareQoderImport(source, {}, { loadBridge: async () => fakeDecryptBridge(), decrypt });
    expect(result.machineId).toBe(machineId);
    expect(decrypt).toHaveBeenCalledWith(expect.anything(), "encrypted-payload", "0123456789abcdef");
    expect(result.credential.token).toBe("access");
  });

  it("rejects source directory/file symlinks and broad permissions", async () => {
    const root = await temporaryRoot();
    const source = await sourceFixture(root);
    const sourceLink = join(root, "source-link");
    await symlink(source, sourceLink);
    await expect(prepareQoderImport(sourceLink, {}, { loadBridge: async () => fakeDecryptBridge(), decrypt: () => "{}" })).rejects.toThrow(/符号链接/);

    await chmod(source, 0o777);
    await expect(prepareQoderImport(source, {}, { loadBridge: async () => fakeDecryptBridge(), decrypt: () => "{}" })).rejects.toThrow(/group\/other/);
    await chmod(source, 0o700);

    await chmod(join(source, "user"), 0o644);
    await expect(prepareQoderImport(source, {}, { loadBridge: async () => fakeDecryptBridge(), decrypt: () => "{}" })).rejects.toThrow(/0600/);
  });

  it("rejects invalid UTF-8 before decryption", async () => {
    const root = await temporaryRoot();
    const source = await sourceFixture(root);
    await writeFile(join(source, "machine_id"), Buffer.from([0xff, 0xfe]), { mode: 0o600 });
    await expect(prepareQoderImport(source, {}, { loadBridge: async () => fakeDecryptBridge(), decrypt: () => "{}" })).rejects.toThrow(/UTF-8/);
  });

  it("rejects oversized source files before decryption", async () => {
    const root = await temporaryRoot();
    const source = await sourceFixture(root);
    await writeFile(join(source, "machine_id"), Buffer.alloc(4097, 0x61), { mode: 0o600 });
    const decrypt = vi.fn(() => "{}");
    await expect(prepareQoderImport(source, {}, { loadBridge: async () => fakeDecryptBridge(), decrypt })).rejects.toThrow(/大小非法/);
    expect(decrypt).not.toHaveBeenCalled();
  });

  it("rejects multiline machine IDs and ciphertext without exposing ciphertext", async () => {
    const root = await temporaryRoot();
    const source = await sourceFixture(root);
    await writeFile(join(source, "machine_id"), "0123456789abcdef\nsecond\n", { mode: 0o600 });
    await expect(prepareQoderImport(source, {}, { loadBridge: async () => fakeDecryptBridge(), decrypt: () => "{}" })).rejects.toThrow(/单行/);
    await writeFile(join(source, "machine_id"), "0123456789abcdef-machine\n", { mode: 0o600 });
    await writeFile(join(source, "user"), "secret-line\nsecond\n", { mode: 0o600 });
    let failure: Error | undefined;
    try { await prepareQoderImport(source, {}, { loadBridge: async () => fakeDecryptBridge(), decrypt: () => "{}" }); }
    catch (error) { failure = error as Error; }
    expect(failure).toBeInstanceOf(Error);
    expect(failure!.message).not.toContain("secret-line");
    expect(failure!.message).toMatch(/单行非空密文/);
  });
});

describe("crash-safe import transaction", () => {
  it("imports into an empty store, then rollback removes the newly-created target", async () => {
    const root = await temporaryRoot();
    const configDir = join(root, "config");
    const store = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir });
    expect(await store.inspectImportTarget!()).toEqual({ exists: false });
    const result = await store.applyImport!(importedCredential(), false);
    expect(result.replaced).toBe(false);
    expect((await lstat(configDir)).mode & 0o777).toBe(0o700);
    expect((await lstat(join(configDir, "auth-cn.json"))).mode & 0o777).toBe(0o600);
    expect((await store.load())?.token).toBe("imported-access");
    await store.rollbackImport!(result.backupId);
    await expect(lstat(join(configDir, "auth-cn.json"))).rejects.toMatchObject({ code: "ENOENT" });
    expect((await readdir(configDir)).filter((name) => name.includes("import"))).toEqual([]);
  });

  it("requires replace, preserves opaque old bytes, and rollback restores them exactly", async () => {
    const root = await temporaryRoot();
    const configDir = join(root, "config");
    await mkdir(configDir, { mode: 0o700 });
    const oldBytes = Buffer.from('{"version":1,"site":"cn","machineIdHash":"other-machine","token":"old"}\n');
    await writeFile(join(configDir, "auth-cn.json"), oldBytes, { mode: 0o600 });
    const store = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir });
    await expect(store.applyImport!(importedCredential(), false)).rejects.toThrow(/--replace/);
    expect(await readFile(join(configDir, "auth-cn.json"))).toEqual(oldBytes);
    const result = await store.applyImport!(importedCredential(), true);
    expect(result.replaced).toBe(true);
    await store.rollbackImport!(result.backupId);
    expect(await readFile(join(configDir, "auth-cn.json"))).toEqual(oldBytes);
  });

  it("finalize deletes only the backup receipt and keeps imported credentials", async () => {
    const root = await temporaryRoot();
    const configDir = join(root, "config");
    const store = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir });
    const result = await store.applyImport!(importedCredential(), false);
    await store.finalizeImport!(result.backupId);
    expect((await store.load())?.token).toBe("imported-access");
    expect((await readdir(configDir)).filter((name) => name.includes("import"))).toEqual([]);
    await expect(store.finalizeImport!(result.backupId)).rejects.toThrow(/不存在/);
  });

  it("removes a receipt-only crash state before old credential bytes are copied", async () => {
    const root = await temporaryRoot();
    const configDir = join(root, "config");
    const base = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir });
    await base.save(importedCredential("0123456789abcdef-machine", "old-access"));
    const crashing = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir }, { onImportPhase: (phase) => { if (phase === "after-receipt") throw new Error("crash-after-receipt"); } });
    await expect(crashing.applyImport!(importedCredential(), true)).rejects.toThrow(/crash-after-receipt/);
    expect((await readdir(configDir)).some((name) => name.startsWith(".auth-cn.import."))).toBe(true);
    expect((await base.load())?.token).toBe("old-access");
    expect((await readdir(configDir)).some((name) => name.startsWith(".auth-cn.import."))).toBe(false);
  });

  it("removes a durable backup when failure occurs before pending publication", async () => {
    const root = await temporaryRoot();
    const configDir = join(root, "config");
    const base = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir });
    await base.save(importedCredential("0123456789abcdef-machine", "old-access"));
    const crashing = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir }, { onImportPhase: (phase) => { if (phase === "after-backup") throw new Error("crash-after-backup"); } });
    await expect(crashing.applyImport!(importedCredential(), true)).rejects.toThrow(/crash-after-backup/);
    expect((await readdir(configDir)).some((name) => name.startsWith(".auth-cn.import."))).toBe(true);
    expect((await base.load())?.token).toBe("old-access");
    expect((await readdir(configDir)).some((name) => name.startsWith(".auth-cn.import."))).toBe(false);
  });

  it("recovers deterministically before and after target replacement", async () => {
    const root = await temporaryRoot();
    for (const phase of ["after-pending", "after-replace"] as const) {
      const configDir = join(root, phase);
      await mkdir(configDir, { mode: 0o700 });
      const old = importedCredential("0123456789abcdef-machine", "old-access");
      const base = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir });
      await base.save(old);
      const crashing = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir }, { onImportPhase: (observed) => { if (observed === phase) throw new Error(`crash-${phase}`); } });
      await expect(crashing.applyImport!(importedCredential(), true)).rejects.toThrow(`crash-${phase}`);
      const fresh = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir });
      expect((await fresh.load())?.token).toBe(phase === "after-pending" ? "old-access" : "imported-access");
      expect((await readdir(configDir)).some((name) => name === "auth-cn.import.pending")).toBe(false);
    }
  });

  it("recovers rollback after target restoration but before backup cleanup", async () => {
    const root = await temporaryRoot();
    const configDir = join(root, "config");
    const base = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir });
    await base.save(importedCredential("0123456789abcdef-machine", "old-access"));
    const applied = await base.applyImport!(importedCredential(), true);
    const crashing = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir }, { onImportPhase: (phase) => { if (phase === "after-rollback-replace") throw new Error("rollback-crash"); } });
    await expect(crashing.rollbackImport!(applied.backupId)).rejects.toThrow(/rollback-crash/);
    const fresh = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir });
    expect((await fresh.load())?.token).toBe("old-access");
    expect((await readdir(configDir)).filter((name) => name.includes("import"))).toEqual([]);
  });

  it("recovers finalize cleanup without changing imported credentials", async () => {
    const root = await temporaryRoot();
    const configDir = join(root, "config");
    const base = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir });
    const applied = await base.applyImport!(importedCredential(), false);
    const crashing = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir }, { onImportPhase: (phase) => { if (phase === "after-finalize-pending") throw new Error("finalize-crash"); } });
    await expect(crashing.finalizeImport!(applied.backupId)).rejects.toThrow(/finalize-crash/);
    const fresh = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir });
    expect((await fresh.load())?.token).toBe("imported-access");
    expect((await readdir(configDir)).filter((name) => name.includes("import"))).toEqual([]);
  });

  it("keeps committed backup discoverable and blocks every rotation/write entry point", async () => {
    const root = await temporaryRoot();
    const configDir = join(root, "config");
    const store = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir });
    const applied = await store.applyImport!(importedCredential(), false);
    expect(await store.importStatus!()).toEqual([{ backupId: applied.backupId, state: "committed" }]);
    const loaded = await store.load();
    expect(loaded?.token).toBe("imported-access");
    await expect(store.reserveRotation(loaded!)).rejects.toThrow(/import/);
    await expect(store.markRotationNetworkStarted!("foreign-owner")).rejects.toThrow(/import/);
    await expect(store.stageRotation(importedCredential("0123456789abcdef-machine", "other"), "foreign-owner")).rejects.toThrow(/import/);
    await expect(store.stageEmergencyRotation!(importedCredential("0123456789abcdef-machine", "other"), "foreign-owner")).rejects.toThrow(/import/);
    await expect(store.save(importedCredential("0123456789abcdef-machine", "other"))).rejects.toThrow(/import/);
  });

  it("recovers no-replace link-before-detach orphan temps without losing backup bytes", async () => {
    const root = await temporaryRoot();
    for (const crashTarget of ["receipt.json", "previous.bin"] as const) {
      const configDir = join(root, crashTarget);
      const base = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir });
      await base.save(importedCredential("0123456789abcdef-machine", "old-access"));
      let crashed = false;
      const crashing = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir }, {
        afterImportNoReplaceLink: ({ target }) => {
          if (!crashed && target.endsWith(crashTarget)) { crashed = true; throw new Error(`crash-${crashTarget}`); }
        },
      });
      await expect(crashing.applyImport!(importedCredential(), true)).rejects.toThrow(`crash-${crashTarget}`);
      const fresh = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir });
      expect(await fresh.importStatus!()).toEqual([]);
      expect((await fresh.load())?.token).toBe("old-access");
      const nested = await readdir(configDir, { recursive: true });
      expect(nested.some((name) => name.endsWith(".tmp"))).toBe(false);
    }
  });

  it("rejects import while a rotation reservation is active", async () => {
    const root = await temporaryRoot();
    const configDir = join(root, "config");
    const base = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir });
    const old = importedCredential("0123456789abcdef-machine", "old-access");
    await base.save(old);
    const owner = await base.reserveRotation(old);
    await expect(base.applyImport!(importedCredential(), true)).rejects.toThrow(/轮换证据/);
    await base.clearRotationReservation(owner);
  });

  it("rollback/finalize recheck target after cleanup intent and preserve evidence on replacement", async () => {
    const root = await temporaryRoot();
    for (const operation of ["rollback", "finalize"] as const) {
      const configDir = join(root, operation);
      const base = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir });
      await base.save(importedCredential("0123456789abcdef-machine", "old-access"));
      const applied = await base.applyImport!(importedCredential(), true);
      const thirdParty = Buffer.from(`${JSON.stringify(importedCredential("0123456789abcdef-machine", `third-${operation}`))}\n`);
      const racing = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir }, {
        beforeImportTargetRecheck: async (observed) => { if (observed === operation) await writeFile(join(configDir, "auth-cn.json"), thirdParty, { mode: 0o600 }); },
      });
      const evidenceBefore = (await readdir(configDir)).filter((name) => name.includes("import")).sort();
      const action = operation === "rollback" ? racing.rollbackImport!(applied.backupId) : racing.finalizeImport!(applied.backupId);
      await expect(action).rejects.toThrow(/发生替换|内容/);
      expect(await readFile(join(configDir, "auth-cn.json"))).toEqual(thirdParty);
      const evidenceAfter = (await readdir(configDir)).filter((name) => name.includes("import")).sort();
      expect(evidenceAfter).toEqual(expect.arrayContaining(evidenceBefore));
      expect(evidenceAfter).toContain("auth-cn.import.pending");
    }
  });

  it("fails closed without modifying evidence when a pending import sees a third-party target", async () => {
    const root = await temporaryRoot();
    const configDir = join(root, "config");
    await mkdir(configDir, { mode: 0o700 });
    const base = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir });
    await base.save(importedCredential("0123456789abcdef-machine", "old-access"));
    const crashing = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir }, { onImportPhase: (phase) => { if (phase === "after-pending") throw new Error("crash"); } });
    await expect(crashing.applyImport!(importedCredential(), true)).rejects.toThrow(/crash/);
    const thirdParty = Buffer.from(`${JSON.stringify(importedCredential("0123456789abcdef-machine", "third-party"))}\n`);
    await writeFile(join(configDir, "auth-cn.json"), thirdParty, { mode: 0o600 });
    const before = (await readdir(configDir)).sort();
    await expect(base.load()).rejects.toThrow(/第三方修改/);
    expect(await readFile(join(configDir, "auth-cn.json"))).toEqual(thirdParty);
    expect((await readdir(configDir)).sort()).toEqual(before);
  });
});

describe("auth CLI and machine-id file", () => {
  it("dry-run needs no API key, performs no apply, and emits only redacted status", async () => {
    const output: string[] = [];
    const applyImport = vi.fn();
    const store = { inspectImportTarget: async () => ({ exists: true }), applyImport } as unknown as CredentialStore;
    await runCli(["auth", "import-qoder", "--source-dir", "/safe/source"], {}, { stdout: (value) => output.push(value), stderr: () => {} }, { prepareImport: async () => prepared(), createImportStore: () => store });
    expect(applyImport).not.toHaveBeenCalled();
    const text = output.join("");
    expect(text).toContain('"dryRun":true');
    expect(text).toContain('"requiresReplace":true');
    for (const secret of ["imported-access", "imported-refresh", "0123456789abcdef-machine", "uid", "name"]) expect(text).not.toContain(secret);
  });

  it("apply requires explicit replace and reports only backup ID/status", async () => {
    const output: string[] = [];
    const applyImport = vi.fn(async () => ({ backupId: "11111111-1111-4111-8111-111111111111", replaced: true }));
    const store = { inspectImportTarget: async () => ({ exists: true }), applyImport } as unknown as CredentialStore;
    await runCli(["auth", "import-qoder", "--apply", "--replace", "--source-dir", "/safe/source"], {}, { stdout: (value) => output.push(value), stderr: () => {} }, { prepareImport: async () => prepared(), createImportStore: () => store });
    expect(applyImport).toHaveBeenCalledWith(expect.objectContaining({ token: "imported-access" }), true);
    expect(output.join("")).toContain("11111111-1111-4111-8111-111111111111");
    expect(output.join("")).not.toContain("imported-access");
  });

  it("rejects unknown, duplicate and conflicting CLI flags before mutation", async () => {
    const deps = { prepareImport: async () => prepared(), createImportStore: () => ({}) as CredentialStore };
    await expect(runCli(["auth", "import-qoder", "--unknown"], {}, undefined, deps)).rejects.toThrow(/未知参数/);
    await expect(runCli(["auth", "import-qoder", "--apply", "--apply"], {}, undefined, deps)).rejects.toThrow(/重复参数/);
    await expect(runCli(["auth", "import-qoder", "--replace"], {}, undefined, deps)).rejects.toThrow(/--apply/);
  });

  it("lists committed import status after apply output failure", async () => {
    const root = await temporaryRoot();
    const configDir = join(root, "config");
    const realStore = createConfigStore("0123456789abcdef-machine", { QODER_PROXY_CONFIG_DIR: configDir });
    let durableBackupId = "";
    const applyStore = {
      inspectImportTarget: () => realStore.inspectImportTarget!(),
      applyImport: async (credential: StoredCredential, replace: boolean) => {
        const result = await realStore.applyImport!(credential, replace);
        durableBackupId = result.backupId;
        return result;
      },
    } as unknown as CredentialStore;
    await expect(runCli(["auth", "import-qoder", "--apply", "--source-dir", "/safe/source"], { QODER_PROXY_CONFIG_DIR: configDir }, { stdout: () => { throw Object.assign(new Error("broken pipe"), { code: "EPIPE" }); }, stderr: () => {} }, { prepareImport: async () => prepared(), createImportStore: () => applyStore })).rejects.toThrow(/broken pipe/);
    const output: string[] = [];
    await runCli(["auth", "import-status"], { QODER_PROXY_CONFIG_DIR: configDir }, { stdout: (value) => output.push(value), stderr: () => {} });
    expect(output.join("")).toContain(durableBackupId);
    expect(output.join("")).toContain('"state":"committed"');
    expect(output.join("")).not.toContain("imported-access");
  });

  it("routes rollback/finalize without API key or network", async () => {
    const rollbackImport = vi.fn(async () => {}), finalizeImport = vi.fn(async () => {});
    const store = { rollbackImport, finalizeImport } as unknown as CredentialStore;
    const id = "11111111-1111-4111-8111-111111111111";
    const io = { stdout: () => {}, stderr: () => {} };
    await runCli(["auth", "rollback-import", "--backup-id", id], {}, io, { createImportStore: () => store });
    await runCli(["auth", "finalize-import", "--backup-id", id], {}, io, { createImportStore: () => store });
    expect(rollbackImport).toHaveBeenCalledWith(id);
    expect(finalizeImport).toHaveBeenCalledWith(id);
  });

  it("reads a secure machine-id file into a cloned serve environment", async () => {
    const root = await temporaryRoot();
    const path = join(root, "machine_id");
    await writeFile(path, "machine-file-value\n", { mode: 0o600 });
    expect(await readMachineIdFile(path)).toBe("machine-file-value");
    const original = { QODER_CN_MACHINE_ID_FILE: path, QODER_PROXY_API_KEY: "local-key" };
    const resolved = await resolveServeEnvironment(original);
    expect(resolved.QODER_CN_MACHINE_ID).toBe("machine-file-value");
    expect(resolved.QODER_CN_MACHINE_ID_FILE).toBeUndefined();
    expect(original.QODER_CN_MACHINE_ID_FILE).toBe(path);
  });

  it("rejects machine-id env ambiguity, relative files, symlinks, broad mode and multiline input", async () => {
    const root = await temporaryRoot();
    const path = join(root, "machine_id");
    await writeFile(path, "machine\n", { mode: 0o600 });
    await expect(resolveServeEnvironment({ QODER_CN_MACHINE_ID: "direct", QODER_CN_MACHINE_ID_FILE: path })).rejects.toThrow(/不能同时/);
    await expect(readMachineIdFile("relative-machine-id")).rejects.toThrow(/绝对路径/);
    const linkPath = join(root, "machine-link");
    await symlink(path, linkPath);
    await expect(readMachineIdFile(linkPath)).rejects.toThrow(/符号链接/);
    await chmod(path, 0o644);
    await expect(readMachineIdFile(path)).rejects.toThrow(/0600/);
    await chmod(path, 0o600);
    await writeFile(path, "one\ntwo\n", { mode: 0o600 });
    await expect(readMachineIdFile(path)).rejects.toThrow(/单行/);
  });
});
