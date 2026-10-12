import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { ClaudeDriver, readClaudeModelCatalog, STATIC_CLAUDE_MODELS } from "./claude.ts";

const scratchDirs: string[] = [];

afterEach(() => {
  for (const dir of scratchDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("readClaudeModelCatalog", () => {
  it("returns the official subscription catalog when settings are missing", () => {
    expect(readClaudeModelCatalog({ HOME: join(tmpdir(), "omb-claude-missing-home") })).toEqual(STATIC_CLAUDE_MODELS);
  });

  it.each(["claude-sonnet-5-5", "claude-haiku-5-5"])(
    "keeps native subscription model %s out of Custom without changing the default",
    (model) => {
      const home = mkdtempSync(join(tmpdir(), "omb-claude-native-model-"));
      scratchDirs.push(home);
      const dir = join(home, ".claude");
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "settings.json"), JSON.stringify({
        availableModels: [model],
        env: { ANTHROPIC_MODEL: model },
      }));
      const catalog = readClaudeModelCatalog({ HOME: home });
      const selected = catalog.options.filter((option) => option.id === model);
      expect(selected).toHaveLength(1);
      expect(selected[0].custom).toBeUndefined();
      expect(catalog.default).toBe("claude-sonnet-5");
      expect(catalog.options.some((option) => option.id === "claude-haiku-4-5")).toBe(true);
    },
  );

  it("tags extra settings models as custom and leaves official rows untagged", () => {
    const home = mkdtempSync(join(tmpdir(), "omb-claude-catalog-"));
    scratchDirs.push(home);
    const dir = join(home, ".claude");
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, "settings.json"),
      JSON.stringify({
        model: "claude-sonnet-5",
        availableModels: [{ id: "my-local-opus", name: "Local Opus" }],
        env: { ANTHROPIC_MODEL: "hosted-qwen" },
      }),
    );

    expect(readClaudeModelCatalog({ HOME: home })).toEqual({
      default: "claude-sonnet-5",
      options: [
        ...STATIC_CLAUDE_MODELS.options,
        { id: "my-local-opus", label: "Local Opus", custom: true },
        { id: "hosted-qwen", label: "hosted-qwen", custom: true },
      ],
    });
  });

  it("does not list settings.model as a Custom leftover", () => {
    const home = mkdtempSync(join(tmpdir(), "omb-claude-leftover-"));
    scratchDirs.push(home);
    const dir = join(home, ".claude");
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, "settings.json"),
      JSON.stringify({ model: "orcarouter/Qwen3.8-27B-Uncensored-GGUF" }),
    );

    expect(readClaudeModelCatalog({ HOME: home })).toEqual(STATIC_CLAUDE_MODELS);
  });
});

describe("ClaudeDriver catalog", () => {
  it("loads extras when the instance is created", async () => {
    const home = mkdtempSync(join(tmpdir(), "omb-claude-instance-"));
    scratchDirs.push(home);
    const dir = join(home, ".claude");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "settings.json"), JSON.stringify({ customModels: ["local-glm"] }));
    const instance = await ClaudeDriver.create({
      instanceId: "claude-catalog",
      displayName: "Claude",
      environment: { HOME: home },
      enabled: true,
      config: ClaudeDriver.defaultConfig(),
    });
    try {
      expect(instance.models.options.some((option) => option.id === "local-glm" && option.custom)).toBe(true);
      expect(instance.refreshModels).toEqual(expect.any(Function));
    } finally {
      await instance.dispose();
    }
  });
});
