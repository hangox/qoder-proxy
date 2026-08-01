import { writeFile } from "node:fs/promises";
import { createConfigStore, type StoredCredential } from "../../src/auth/session.ts";

const [configDir, owner, targetJson, phase, readyPath] = process.argv.slice(2);
if (!configDir || !owner || !targetJson || !phase || !readyPath) throw new Error("缺少 rotation publish 测试参数");
const target = JSON.parse(targetJson) as StoredCredential;
const store = createConfigStore("machine-a", { QODER_PROXY_CONFIG_DIR: configDir }, {
  onRotationPublishPhase: async (currentPhase) => {
    if (currentPhase !== phase) return;
    await writeFile(readyPath, `${currentPhase}\n`, "utf8");
    await new Promise<void>(() => {});
  },
});

await store.stageEmergencyRotation!(target, owner);
process.exitCode = 2;
