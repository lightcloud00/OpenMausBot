import { EventEmitter } from "node:events";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";

import { afterEach, describe, expect, it } from "vitest";

import type { RuntimeEvent } from "./contracts.ts";
import {
  TelemetryManager,
  telemetrySinkRuntimeConfig,
  telemetrySinkSpawnSpec,
} from "./telemetry.ts";

const dirs: string[] = [];
afterEach(() => {
  delete process.env.TEST_API_KEY;
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function fakeSink() {
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const child = Object.assign(new EventEmitter(), {
    stdin,
    stdout,
    stderr,
    pid: undefined,
    exitCode: null,
    signalCode: null,
  }) as any;
  const lines: string[] = [];
  let buffer = "";
  stdin.setEncoding("utf8");
  stdin.on("data", (chunk) => {
    buffer += String(chunk);
    let newline: number;
    while ((newline = buffer.indexOf("\n")) >= 0) {
      lines.push(buffer.slice(0, newline));
      buffer = buffer.slice(newline + 1);
    }
  });
  return { child, lines, ready: (kind: string) => stdout.write(`${JSON.stringify({ kind: "ready", sink: kind })}\n`) };
}

function event(type: RuntimeEvent["type"], extra: Record<string, unknown> = {}): RuntimeEvent {
  return {
    type,
    eventId: crypto.randomUUID(),
    provider: "codex",
    threadId: "thread-1",
    turnId: "turn-1",
    createdAt: new Date().toISOString(),
    ...extra,
  } as RuntimeEvent;
}

describe("TelemetryManager", () => {
  it("uses one multi-binding CredVault stdio broker and restores packaged Node mode", () => {
    const env = {
      PATH: "/safe/bin",
      HOME: "/safe/home",
      OMB_LANGFUSE_PUBLIC_KEY_ALIAS: "langfuse-public-alias",
      OMB_LANGFUSE_SECRET_KEY_ALIAS: "langfuse-secret-alias",
      OMB_TELEMETRY_ENVIRONMENT: "acceptance",
      OMB_LANGFUSE_BASE_URL: "http://127.0.0.1:3030",
      SHOULD_NOT_PASS: "forbidden",
    };
    const spec = telemetrySinkSpawnSpec("langfuse", "/app/server/telemetry-sink.cjs", "/private/sink-langfuse.json", {
      platform: "darwin",
      executable: "/app/OpenMausBot Helper",
      env,
    });
    expect(spec.cli).toBe("cv");
    expect(spec.args.slice(0, 3)).toEqual(["--source", "main", "stdio-exec"]);
    expect(spec.args).toContain("LANGFUSE_PUBLIC_KEY=langfuse-public-alias");
    expect(spec.args).toContain("LANGFUSE_SECRET_KEY=langfuse-secret-alias");
    expect(spec.args.filter((arg) => arg === "stdio-exec")).toHaveLength(1);
    expect(spec.args).not.toContain("exec");
    expect(spec.args).toContain("/usr/bin/env");
    expect(spec.args).toContain("ELECTRON_RUN_AS_NODE=1");
    expect(spec.args).not.toContain("OMB_TELEMETRY_KIND=langfuse");
    expect(spec.args).not.toContain("OMB_TELEMETRY_ENVIRONMENT=acceptance");
    expect(spec.args.join(" ")).not.toContain("127.0.0.1");
    expect(spec.args.slice(-3)).toEqual([
      "/app/OpenMausBot Helper",
      "/app/server/telemetry-sink.cjs",
      "/private/sink-langfuse.json",
    ]);
    expect(spec.env).not.toHaveProperty("SHOULD_NOT_PASS");
    expect(spec.args.join(" ")).not.toContain("forbidden");
  });

  it("uses the fixed Windows launcher without putting credential values in argv", () => {
    const spec = telemetrySinkSpawnSpec("sentry", "C:\\OpenMaus\\server\\telemetry-sink.cjs", "C:\\private\\sink-sentry.json", {
      platform: "win32",
      executable: "C:\\OpenMaus\\OpenMausBot Helper.exe",
      env: {
        COMSPEC: "C:\\Windows\\System32\\cmd.exe",
        OMB_SENTRY_DSN_ALIAS: "sentry-logical-alias",
        OMB_LANGFUSE_BASE_URL: "https://user:secret@example.test/path",
      },
    });
    expect(spec.args).toContain("SENTRY_DSN=sentry-logical-alias");
    expect(spec.args).toContain("C:\\OpenMaus\\server\\telemetry-node-launcher.cmd");
    expect(spec.args.join(" ")).not.toContain("user:secret");
  });

  it("stores only bounded non-secret runtime metadata outside broker argv", () => {
    expect(
      telemetrySinkRuntimeConfig("langfuse", "bad release & value", {
        OMB_TELEMETRY_ENVIRONMENT: "acceptance",
        OMB_LANGFUSE_BASE_URL: "https://user:secret@example.test/path",
      }),
    ).toEqual({
      schema: "openmaus.telemetry-sink-runtime.v1",
      kind: "langfuse",
      release: "unknown",
      environment: "acceptance",
      langfuseBaseUrl: "http://127.0.0.1:3030",
    });
  });

  it("emits one sanitized trace per turn with generation, tool, usage, and correlation metadata", () => {
    const dir = mkdtempSync(join(tmpdir(), "omb-telemetry-"));
    dirs.push(dir);
    const canary = "canary-secret-value-928374";
    process.env.TEST_API_KEY = canary;
    const sinks = { sentry: fakeSink(), langfuse: fakeSink() };
    const manager = new TelemetryManager({
      dataDir: dir,
      sinkPath: "/unused",
      sourceSha: "a".repeat(40),
      release: "1.2.3",
      spawnSink: (kind) => sinks[kind].child,
    });
    sinks.sentry.ready("sentry");
    sinks.langfuse.ready("langfuse");

    manager.registerTurn({
      botId: "finch",
      botName: "Finch",
      threadId: "thread-1",
      engine: "codex",
      model: "gpt-5",
      prompt: `inspect ${canary}`,
    });
    manager.handleRuntimeEvent(event("turn.started"));
    manager.handleRuntimeEvent(event("item.started", { itemId: "tool-1", itemType: "tool", title: `shell ${canary}` }));
    manager.handleRuntimeEvent(event("item.completed", { itemId: "tool-1", itemType: "tool", ok: true }));
    manager.handleRuntimeEvent(event("item.completed", { itemType: "assistant_text", text: `done ${canary}` }));
    manager.handleRuntimeEvent(event("turn.completed", { ok: true, usage: { input: 12, output: 8 } }));

    expect(sinks.langfuse.lines).toHaveLength(1);
    const trace = JSON.parse(sinks.langfuse.lines[0]!);
    expect(trace).toMatchObject({
      kind: "trace",
      application: "openmausbot",
      botId: "finch",
      threadId: "thread-1",
      turnId: "turn-1",
      engine: "codex",
      model: "gpt-5",
      sourceSha: "a".repeat(40),
      usage: { input: 12, output: 8 },
      outcome: "completed",
      tools: [{ id: "tool-1", ok: true }],
    });
    expect(sinks.langfuse.lines[0]).not.toContain(canary);
    const journal = readFileSync(join(dir, "telemetry", "turns.ndjson"), "utf8");
    expect(journal).not.toContain(canary);
    expect(journal).toContain("redacted");
    expect(manager.health().langfuse.degraded).toBe(false);
    manager.shutdown();
  });

  it("sends full sanitized runtime errors to Sentry without conversational prompts", () => {
    const dir = mkdtempSync(join(tmpdir(), "omb-telemetry-"));
    dirs.push(dir);
    const sinks = { sentry: fakeSink(), langfuse: fakeSink() };
    const manager = new TelemetryManager({
      dataDir: dir,
      sinkPath: "/unused",
      sourceSha: "b".repeat(40),
      release: "dev",
      spawnSink: (kind) => sinks[kind].child,
    });
    manager.registerTurn({
      botId: "cogs",
      botName: "Cogs",
      threadId: "thread-1",
      engine: "claudeAgent",
      model: "sonnet",
      prompt: "conversation that must not reach sentry",
    });
    manager.handleRuntimeEvent(event("runtime.error", { message: "driver exploded" }));

    expect(sinks.sentry.lines).toHaveLength(1);
    expect(sinks.sentry.lines[0]).toContain("driver exploded");
    expect(sinks.sentry.lines[0]).not.toContain("conversation that must not reach sentry");
    expect(JSON.parse(sinks.sentry.lines[0]!)).toMatchObject({
      kind: "error",
      component: "driver",
      botId: "cogs",
      threadId: "thread-1",
    });
    manager.shutdown();
  });

  it("stays nonblocking and reports degraded health when a sink is unavailable", () => {
    const dir = mkdtempSync(join(tmpdir(), "omb-telemetry-"));
    dirs.push(dir);
    const manager = new TelemetryManager({
      dataDir: dir,
      sinkPath: "/unused",
      sourceSha: "unknown",
      release: "dev",
      spawnSink: () => null,
    });
    expect(() => manager.captureError(new Error("boom"), { component: "server" })).not.toThrow();
    expect(manager.health().sentry).toMatchObject({ running: false, degraded: true });
    expect(manager.health().langfuse).toMatchObject({ running: false, degraded: true });
  });
});
