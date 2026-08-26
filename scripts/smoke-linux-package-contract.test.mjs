import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("Linux package smoke network isolation", () => {
  it("treats every optional broker request as a failure", () => {
    const electronMain = fs.readFileSync(path.join(root, "electron", "main.mjs"), "utf8");
    const packageSmoke = fs.readFileSync(path.join(root, "scripts", "smoke-linux-package.mjs"), "utf8");

    expect(electronMain).toContain("if (!SMOKE_TEST) void hostedAccount.restore()");
    expect(electronMain).toContain("if (!SMOKE_TEST && app.isPackaged && composioBrokerUrl()");
    expect(packageSmoke).toContain("if (brokerRequests !== 0)");
    expect(packageSmoke).not.toContain("brokerRequests > 0");
  });
});
