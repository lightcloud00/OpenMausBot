import { describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadHostMcpCatalog, parseClaudeMcpServers, parseCodexMcpList, writeHostMcpManifest } from "./host-mcp.ts";

describe("host MCP catalog", () => {
  it("loads stdio and HTTP Claude servers while excluding CredVault", () => {
    expect(
      parseClaudeMcpServers({
        mcpServers: {
          sentry: { command: "/bin/sentry-wrapper", args: ["mcp"] },
          memory: { type: "http", url: "http://127.0.0.1:8767/mcp" },
          credvault: { command: "/bin/credvault-mcp", args: [] },
        },
      }),
    ).toEqual({
      sentry: { type: "stdio", command: "/bin/sentry-wrapper", args: ["mcp"], env: {} },
      memory: { type: "http", url: "http://127.0.0.1:8767/mcp", headers: {} },
    });
  });

  it("keeps authenticated HTTP values inside the host catalog", () => {
    expect(
      parseCodexMcpList(
        [{
          name: "fleet",
          enabled: true,
          transport: {
            type: "streamable_http",
            url: "http://127.0.0.1:8768/mcp",
            bearer_token_env_var: "FLEET_TOKEN",
            env_http_headers: { "x-extra": "EXTRA_TOKEN" },
          },
        }],
        { FLEET_TOKEN: "host-only", EXTRA_TOKEN: "also-host-only" },
      ),
    ).toEqual({
      fleet: {
        type: "http",
        url: "http://127.0.0.1:8768/mcp",
        headers: { Authorization: "Bearer host-only", "x-extra": "also-host-only" },
      },
    });
  });

  it("loads enabled Codex transports using environment names, not manifest values", () => {
    expect(
      parseCodexMcpList(
        [
          {
            name: "langfuse",
            enabled: true,
            transport: { type: "stdio", command: "/bin/langfuse", args: [], env_vars: ["LANGFUSE_HOST"] },
          },
          { name: "off", enabled: false, transport: { type: "stdio", command: "/bin/off", args: [] } },
        ],
        { LANGFUSE_HOST: "http://127.0.0.1:3000" },
      ),
    ).toEqual({
      langfuse: {
        type: "stdio",
        command: "/bin/langfuse",
        args: [],
        env: { LANGFUSE_HOST: "http://127.0.0.1:3000" },
      },
    });
  });

  it("merges the two intentional inventories and hashes names only", () => {
    const catalog = loadHostMcpCatalog({
      home: "/does/not/exist",
      runCodexList: () =>
        JSON.stringify([
          { name: "sentry", enabled: true, transport: { type: "stdio", command: "/bin/sentry", args: [] } },
          { name: "credvault", enabled: true, transport: { type: "stdio", command: "/bin/credvault-mcp", args: [] } },
        ]),
    });
    expect(catalog.manifest.toolInventory).toEqual([
      "openmaus-host:filesystem_delete",
      "openmaus-host:filesystem_read",
      "openmaus-host:filesystem_stat",
      "openmaus-host:filesystem_write",
      "openmaus-host:shell_execute",
      "sentry",
    ]);
    expect(catalog.servers["openmaus-host"]).toEqual({ type: "builtin" });
    expect(JSON.stringify(catalog.manifest)).not.toContain("/bin/sentry");
    expect(catalog.sources).toEqual({ claude: "missing", codex: "loaded" });
  });

  it("persists only the value-free manifest and source states", () => {
    const dataDir = mkdtempSync(join(tmpdir(), "omb-profile-"));
    const catalog = loadHostMcpCatalog({
      home: "/does/not/exist",
      runCodexList: () =>
        JSON.stringify([
          { name: "sentry", enabled: true, transport: { type: "stdio", command: "/secret/path", args: [] } },
        ]),
    });
    const path = writeHostMcpManifest(dataDir, catalog);
    const saved = readFileSync(path, "utf8");
    expect(saved).toContain('"schema": "openmaus.capability-profile.v1"');
    expect(saved).not.toContain("/secret/path");
  });
});
