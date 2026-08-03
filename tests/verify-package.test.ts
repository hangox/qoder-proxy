import { describe, expect, it } from "vitest";
import { normalizePackResults, verifyPackageFiles } from "../scripts/verify-package.ts";

const requiredFiles = [
  "README.md",
  "dist/qoder-proxy.js",
  "dist/qoder-statusline-runtime.js",
  "dist/install-qoder-statusline.js",
  "package.json",
];

describe("npm package verifier", () => {
  it("兼容 npm 11 数组与 npm 12 包名映射 JSON", () => {
    const record = { files: requiredFiles.map((path) => ({ path })) };
    expect(normalizePackResults([record])).toEqual([record]);
    expect(normalizePackResults({ "@hangox/qoder-proxy": record })).toEqual([record]);
  });

  it("拒绝无有效 pack 记录的 JSON", () => {
    expect(() => normalizePackResults(null)).toThrow("npm pack JSON 格式无效");
    expect(() => normalizePackResults({ "@hangox/qoder-proxy": { name: "@hangox/qoder-proxy" } })).toThrow("npm pack JSON 中没有有效文件记录");
  });

  it("保持五文件发布白名单与禁止路径校验", () => {
    expect(() => verifyPackageFiles(requiredFiles)).not.toThrow();
    expect(() => verifyPackageFiles([...requiredFiles, "README.md"])).toThrow("文件白名单不匹配");
    expect(() => verifyPackageFiles(requiredFiles.slice(0, -1))).toThrow("缺少必需文件");
    expect(() => verifyPackageFiles([...requiredFiles, "auth-cn.json"])).toThrow("禁止文件");
  });
});
