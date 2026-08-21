import { mkdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { clearProcessRegistry, configureProcessRegistry, killCliTree, spawnCli } from "./procs.ts";

const IDLE = "setInterval(() => {}, 1000)";

async function eventually(assertion: () => void, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      assertion();
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
  assertion();
}

afterEach(() => clearProcessRegistry());

describe("owned process registry", () => {
  it("records an owned process group and removes it when the turn tree closes", async () => {
    const directory = join(process.env.HOME!, ".openmausbot", "process-registry-test");
    mkdirSync(directory, { recursive: true });
    configureProcessRegistry(directory);

    const registry = join(directory, `${process.pid}.json`);
    const child = spawnCli(process.execPath, ["-e", IDLE], { stdio: ["pipe", "pipe", "pipe"] });
    try {
      await eventually(() => {
        const value = JSON.parse(readFileSync(registry, "utf8")) as { children: Array<{ pid: number }> };
        expect(value.children).toEqual([{ pid: child.pid, executable: expect.any(String), startIdentity: expect.any(String) }]);
      });
      if (process.platform !== "win32") expect(statSync(registry).mode & 0o077).toBe(0);
    } finally {
      killCliTree(child);
      await Promise.race([
        new Promise<void>((resolve) => child.once("close", () => resolve())),
        new Promise<void>((resolve) => setTimeout(resolve, 5_000)),
      ]);
    }

    await eventually(() => {
      const value = JSON.parse(readFileSync(registry, "utf8")) as { children: unknown[] };
      expect(value.children).toEqual([]);
    });
  });
});
