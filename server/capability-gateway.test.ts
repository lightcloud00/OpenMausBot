import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

import { createCapabilityProfileManifest } from "./access-profile.ts";
import { CapabilityGateway } from "./capability-gateway.ts";
import type { HostMcpCatalog } from "./host-mcp.ts";

const FAKE = join(dirname(fileURLToPath(import.meta.url)), "testing", "fake-capability-mcp.ts");
const TOKEN = "turn-token-123456789012345678901234";

function catalog(): HostMcpCatalog {
  return {
    servers: {
      test: {
        type: "stdio",
        command: process.execPath,
        args: [FAKE],
        env: { TEST_GATEWAY_SECRET: "arbitrary-canary-value-987654" },
      },
    },
    manifest: createCapabilityProfileManifest({ toolInventory: ["test"] }),
    sources: { claude: "loaded", codex: "loaded" },
  };
}

describe("CapabilityGateway", () => {
  const open: CapabilityGateway[] = [];
  const temporary: string[] = [];

  afterEach(() => {
    for (const gateway of open.splice(0)) gateway.shutdown();
    for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true });
  });

  it("requires a live turn token and rejects it immediately after settlement", () => {
    const gateway = new CapabilityGateway(catalog());
    open.push(gateway);
    gateway.beginTurn(TOKEN, { botId: "bot", threadId: "thread" });
    expect(gateway.inventory(TOKEN).manifest.profile).toBe("full-task-scoped");
    gateway.endTurn(TOKEN);
    expect(() => gateway.inventory(TOKEN)).toThrow(/no longer active/);
  });

  it("starts a backend lazily, reuses it, and redacts arbitrary protected values", async () => {
    chmodSync(FAKE, 0o755);
    const gateway = new CapabilityGateway(catalog(), { idleTimeoutMs: 2_000 });
    open.push(gateway);
    gateway.beginTurn(TOKEN, { botId: "bot", threadId: "thread" });
    expect(gateway.stats().activeBackends).toEqual([]);

    const first = await gateway.callTool(TOKEN, "test", "echo", { value: "first" });
    const second = await gateway.callTool(TOKEN, "test", "echo", { value: "second" });
    const rendered = JSON.stringify([first, second]);
    expect(rendered).not.toContain("arbitrary-canary-value-987654");
    expect(rendered).toContain("redacted");
    const marker = (value: any) => JSON.parse(value.content[0].text).marker;
    expect(marker(first)).toBe(marker(second));
    expect(gateway.stats().activeBackends).toEqual(["test"]);
  });

  it("adds task-owned integrations to the effective manifest and closes them at turn end", async () => {
    chmodSync(FAKE, 0o755);
    const gateway = new CapabilityGateway({
      servers: { "openmaus-host": { type: "builtin" } },
      manifest: createCapabilityProfileManifest({ toolInventory: ["openmaus-host:shell_execute"] }),
      sources: { claude: "missing", codex: "missing" },
    }, { idleTimeoutMs: 60_000 });
    open.push(gateway);
    gateway.beginTurn(TOKEN, { botId: "bot", threadId: "thread" });
    gateway.extendTurn(TOKEN, {
      "openmaus-computer": { type: "stdio", command: process.execPath, args: [FAKE], env: {} },
    });

    const inventory = gateway.inventory(TOKEN);
    expect(inventory.manifest.toolInventory).toContain("openmaus-computer");
    expect(inventory.manifest.sha256).not.toBe(gateway.catalog.manifest.sha256);
    await gateway.callTool(TOKEN, "openmaus-computer", "echo", { value: "screen" });
    expect(gateway.stats().activeBackends).toEqual(["openmaus-computer"]);

    gateway.endTurn(TOKEN);
    expect(gateway.stats()).toEqual({ activeTurns: 0, activeBackends: [] });
  });

  it("enforces denials across split computer input and withholds credential-store screens", async () => {
    chmodSync(FAKE, 0o755);
    const gateway = new CapabilityGateway({
      servers: {},
      manifest: createCapabilityProfileManifest(),
      sources: { claude: "missing", codex: "missing" },
    });
    open.push(gateway);
    gateway.beginTurn(TOKEN, {
      botId: "bot",
      threadId: "thread",
      servers: {
        "openmaus-computer": { type: "stdio", command: process.execPath, args: [FAKE], env: {} },
      },
    });

    const prefix = await gateway.callTool(TOKEN, "openmaus-computer", "type_text", { text: "rm -" });
    expect(prefix?.isError).not.toBe(true);
    const splitDenied = await gateway.callTool(TOKEN, "openmaus-computer", "type_text", { text: "rf /" });
    expect(splitDenied).toMatchObject({ isError: true });
    expect(JSON.stringify(splitDenied)).toContain("catastrophic-destruction");

    const credentialDenied = await gateway.callTool(TOKEN, "openmaus-computer", "credential-screen", {});
    expect(credentialDenied).toMatchObject({ isError: true });
    expect(JSON.stringify(credentialDenied)).toContain("credential-value-disclosure");
    expect(JSON.stringify(credentialDenied)).not.toContain("arbitrary-unclassified-secret");
  });

  it("blocks catastrophic MCP calls before a backend starts", async () => {
    const gateway = new CapabilityGateway(catalog());
    open.push(gateway);
    gateway.beginTurn(TOKEN, { botId: "bot", threadId: "thread" });
    const result = await gateway.callTool(TOKEN, "test", "delete_project", { project: "production" });
    expect(result).toMatchObject({ isError: true });
    expect(JSON.stringify(result)).toContain("catastrophic-destruction");
    expect(gateway.stats().activeBackends).toEqual([]);
  });

  it("removes binary payloads and closes idle backends", async () => {
    chmodSync(FAKE, 0o755);
    const gateway = new CapabilityGateway(catalog(), { idleTimeoutMs: 25 });
    open.push(gateway);
    gateway.beginTurn(TOKEN, { botId: "bot", threadId: "thread" });
    const result = await gateway.callTool(TOKEN, "test", "binary", {});
    expect(JSON.stringify(result)).not.toContain("A".repeat(100));
    expect(JSON.stringify(result)).toContain("binary capability output omitted");
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(gateway.stats().activeBackends).toEqual([]);
  });

  it("preserves bounded computer screenshots while still blocking credential screens", async () => {
    chmodSync(FAKE, 0o755);
    const gateway = new CapabilityGateway({
      servers: {
        "openmaus-computer": { type: "stdio", command: process.execPath, args: [FAKE], env: {} },
      },
      manifest: createCapabilityProfileManifest({ toolInventory: ["openmaus-computer"] }),
      sources: { claude: "missing", codex: "missing" },
    });
    open.push(gateway);
    gateway.beginTurn(TOKEN, { botId: "bot", threadId: "thread" });

    const screenshot = await gateway.callTool(TOKEN, "openmaus-computer", "binary", {});
    expect(JSON.stringify(screenshot)).toContain("A".repeat(100));
    expect(JSON.stringify(screenshot)).not.toContain("binary capability output omitted");
  });

  it("lists and selects logical aliases without resolving values", async () => {
    const gateway = new CapabilityGateway(catalog(), {
      listAliases: async () => ["sentry-readonly", "langfuse_secret", "bad alias"],
    });
    open.push(gateway);
    gateway.beginTurn(TOKEN, { botId: "bot", threadId: "thread" });
    expect(await gateway.aliases(TOKEN)).toEqual(["langfuse_secret", "sentry-readonly"]);
    await expect(
      gateway.selectCredentialAlias(TOKEN, "test", "sentry-readonly", "SENTRY_ACCESS_TOKEN"),
    ).resolves.toBeUndefined();
    await expect(
      gateway.selectCredentialAlias(TOKEN, "test", "not-present", "TOKEN"),
    ).rejects.toThrow(/unknown credential alias/);
  });

  it("provides the same task-scoped host baseline to non-provider clients", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "omb-host-core-"));
    temporary.push(cwd);
    const hostCatalog: HostMcpCatalog = {
      servers: { "openmaus-host": { type: "builtin" } },
      manifest: createCapabilityProfileManifest({ toolInventory: ["openmaus-host:shell_execute"] }),
      sources: { claude: "missing", codex: "missing" },
    };
    const gateway = new CapabilityGateway(hostCatalog);
    open.push(gateway);
    gateway.beginTurn(TOKEN, { botId: "manus", threadId: "task", cwd });

    const tools = await gateway.listTools(TOKEN, "openmaus-host");
    expect(tools.tools.map((tool: { name: string }) => tool.name)).toContain("shell_execute");
    await gateway.callTool(TOKEN, "openmaus-host", "filesystem_write", { path: "fixture.txt", content: "hello" });
    const read = await gateway.callTool(TOKEN, "openmaus-host", "filesystem_read", { path: "fixture.txt" });
    expect(read).toMatchObject({ content: "hello" });
    const shell = await gateway.callTool(TOKEN, "openmaus-host", "shell_execute", { command: "pwd" });
    expect(shell).toMatchObject({ exitCode: 0 });
    await gateway.callTool(TOKEN, "openmaus-host", "filesystem_delete", { path: "fixture.txt" });
    expect(() => readFileSync(join(cwd, "fixture.txt"))).toThrow();
  });

  it("rejects whole-repository deletion and scrubs exact canaries before host execution", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "omb-host-core-"));
    temporary.push(cwd);
    mkdirSync(join(cwd, ".git"));
    const canary = "gateway-canary-exact-927364";
    process.env.GATEWAY_TEST_SECRET = canary;
    try {
      const hostCatalog: HostMcpCatalog = {
        servers: { "openmaus-host": { type: "builtin" } },
        manifest: createCapabilityProfileManifest({ toolInventory: ["openmaus-host:shell_execute"] }),
        sources: { claude: "missing", codex: "missing" },
      };
      const gateway = new CapabilityGateway(hostCatalog);
      open.push(gateway);
      gateway.beginTurn(TOKEN, { botId: "hermes", threadId: "task", cwd });
      const denied = await gateway.callTool(TOKEN, "openmaus-host", "filesystem_delete", { path: cwd, recursive: true });
      expect(denied).toMatchObject({ isError: true });
      const echoed = await gateway.callTool(TOKEN, "openmaus-host", "shell_execute", { command: `printf '%s' '${canary}'` });
      expect(JSON.stringify(echoed)).not.toContain(canary);
      expect(JSON.stringify(echoed)).toContain("redacted");
    } finally {
      delete process.env.GATEWAY_TEST_SECRET;
    }
  });
});
