import { describe, expect, it } from "vitest";

import { readClaudeApiKey } from "./claude-api-key-helper.ts";

describe("Claude bare-mode API key helper", () => {
  it("accepts only logical CredVault aliases and never falls back to host OAuth files", () => {
    for (const value of [undefined, "", "../../credential", "alias with spaces", "alias\nnext"]) {
      expect(() => readClaudeApiKey(value)).toThrow(/alias is invalid/);
    }
  });
});
