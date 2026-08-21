import { EventEmitter } from "node:events";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";

import { afterEach, describe, expect, it } from "vitest";

import type { RuntimeEvent } from "./contracts.ts";
import { TelemetryManager } from "./telemetry.ts";

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
