import { randomUUID } from "node:crypto";
import { appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

import type { ChildProcessByStdio } from "node:child_process";
import type { Readable, Writable } from "node:stream";

import type { RuntimeEvent } from "./contracts.ts";
import { augmentedPath } from "./env-path.ts";
import { killCliTree, spawnCli } from "./procs.ts";
import { protectedEnvironmentValues, redactKnownValues, redactSecrets } from "./redact.ts";
import type { TelemetryEnvelope, TelemetryErrorEnvelope, TelemetryToolSpan, TelemetryTraceEnvelope } from "./telemetry-protocol.ts";

const SUMMARY_CHARS = 4_000;

type SinkKind = "sentry" | "langfuse";
type SinkChild = ChildProcessByStdio<Writable, Readable, Readable>;

export interface TelemetryHealth {
  configured: boolean;
  running: boolean;
  degraded: boolean;
  lastError?: string;
  lastSuccess?: string;
}

export interface RegisterTurnInput {
  botId: string;
  botName: string;
  threadId: string;
  engine: string;
  model: string;
  prompt: string;
}

interface TurnState extends RegisterTurnInput {
  correlationId: string;
  traceId: string;
  turnId: string;
  startedAt: string;
  promptSummary: string;
  responseSummary: string;
  tools: Map<string, Omit<TelemetryToolSpan, "endedAt" | "ok">>;
  completedTools: TelemetryToolSpan[];
  usage?: { input: number; output: number };
  errorSummary?: string;
}

export interface TelemetryOptions {
  dataDir: string;
  sinkPath: string;
  sourceSha: string;
  release: string;
  now?: () => Date;
  spawnSink?: (kind: SinkKind) => SinkChild | null;
}

function summary(value: string, max = SUMMARY_CHARS): string {
  return value.replace(/\s+/g, " ").trim().slice(0, max);
}

function sinkAliases(kind: SinkKind): Array<{ alias: string; env: string }> {
  if (kind === "sentry") {
    return [{ alias: process.env.OMB_SENTRY_DSN_ALIAS ?? "sentry_dsn_gusdigital_ios", env: "SENTRY_DSN" }];
  }
  return [
    { alias: process.env.OMB_LANGFUSE_PUBLIC_KEY_ALIAS ?? "langfuse_local_init_project_public_key", env: "LANGFUSE_PUBLIC_KEY" },
    { alias: process.env.OMB_LANGFUSE_SECRET_KEY_ALIAS ?? "langfuse_local_init_project_secret_key", env: "LANGFUSE_SECRET_KEY" },
  ];
}

function cleanEnvironment(kind: SinkKind, release: string): NodeJS.ProcessEnv {
  const keep = ["HOME", "USERPROFILE", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "SHELL"] as const;
  const env: NodeJS.ProcessEnv = {
    PATH: augmentedPath(),
    ELECTRON_RUN_AS_NODE: "1",
    OMB_TELEMETRY_KIND: kind,
    OMB_RELEASE: release,
    OMB_TELEMETRY_ENVIRONMENT: process.env.OMB_TELEMETRY_ENVIRONMENT ?? "production",
  };
  if (kind === "langfuse") env.LANGFUSE_BASE_URL = process.env.OMB_LANGFUSE_BASE_URL ?? "http://127.0.0.1:3030";
  for (const name of keep) if (process.env[name]) env[name] = process.env[name];
  return env;
}

/** Sanitized, non-blocking telemetry fan-out. Credentials are injected into
 * dedicated sink children by CredVault and never enter this process, agent
 * environments, argv, journals, or tool results. */
export class TelemetryManager {
  private readonly options: TelemetryOptions;
  private readonly turns = new Map<string, TurnState>();
  private readonly sinks = new Map<SinkKind, SinkChild>();
  private readonly protectedValues = protectedEnvironmentValues();
  private readonly healthState: Record<SinkKind, TelemetryHealth> = {
    sentry: { configured: true, running: false, degraded: false },
    langfuse: { configured: true, running: false, degraded: false },
  };
  private readonly now: () => Date;
  private readonly journalPath: string;

  constructor(options: TelemetryOptions) {
    this.options = options;
    this.now = options.now ?? (() => new Date());
    const directory = join(options.dataDir, "telemetry");
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    this.journalPath = join(directory, "turns.ndjson");
    for (const kind of ["sentry", "langfuse"] as const) this.startSink(kind);
  }

  private spawnDefault(kind: SinkKind): SinkChild {
    const credentials = sinkAliases(kind);
    let command = process.execPath;
    let args = [this.options.sinkPath];
    for (let i = credentials.length - 1; i >= 0; i--) {
      const next = credentials[i]!;
      args = ["exec", next.alias, next.env, "--", command, ...args];
      command = "credvault";
    }
    return spawnCli(command, args, {
      env: cleanEnvironment(kind, this.options.release),
      stdio: ["pipe", "pipe", "pipe"],
    });
  }

  private startSink(kind: SinkKind): void {
    try {
      const child = this.options.spawnSink ? this.options.spawnSink(kind) : this.spawnDefault(kind);
      if (!child) {
        this.healthState[kind] = { configured: false, running: false, degraded: true, lastError: "telemetry sink is disabled" };
        return;
      }
      this.sinks.set(kind, child);
      let buffer = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (chunk) => {
        buffer += String(chunk);
        let newline: number;
        while ((newline = buffer.indexOf("\n")) >= 0) {
          const line = buffer.slice(0, newline);
          buffer = buffer.slice(newline + 1);
          try {
            const frame = JSON.parse(line) as { kind?: string; message?: string };
            if (frame.kind === "ready") this.healthState[kind] = { ...this.healthState[kind], running: true, degraded: false, lastError: undefined };
            if (frame.kind === "sent") this.healthState[kind].lastSuccess = this.now().toISOString();
            if (frame.kind === "error") this.degrade(kind, frame.message ?? "telemetry export failed");
          } catch {
            // CredVault wrappers may emit benign status lines. Never retain them.
          }
        }
      });
      child.stderr.resume();
      child.on("error", () => this.degrade(kind, "telemetry sink could not start"));
      child.on("close", () => {
        this.sinks.delete(kind);
        this.degrade(kind, "telemetry sink stopped");
      });
    } catch {
      this.degrade(kind, "telemetry sink could not start");
    }
  }

  private degrade(kind: SinkKind, message: string): void {
    this.healthState[kind] = {
      ...this.healthState[kind],
      running: false,
      degraded: true,
      lastError: summary(String(redactSecrets(message)), 300),
    };
  }

  private sanitize<T>(input: T): T {
    return redactKnownValues(redactSecrets(input), this.protectedValues) as T;
  }

  health(): Record<SinkKind, TelemetryHealth> {
    return structuredClone(this.healthState);
  }

  registerTurn(input: RegisterTurnInput): string {
    const correlationId = randomUUID();
    this.turns.set(input.threadId, {
      ...input,
      correlationId,
      traceId: randomUUID(),
      turnId: "pending",
      startedAt: this.now().toISOString(),
      promptSummary: summary(String(this.sanitize(input.prompt))),
      responseSummary: "",
      tools: new Map(),
      completedTools: [],
    });
    return correlationId;
  }

  handleRuntimeEvent(event: RuntimeEvent): void {
    const state = this.turns.get(event.threadId);
    if (state && event.turnId) state.turnId = event.turnId;
    if (event.type === "runtime.error") {
      if (state) state.errorSummary = summary(String(this.sanitize(event.message)), 1_000);
      this.captureError(event.message, { component: "driver", state, turnId: event.turnId });
    }
    if (!state) return;
    const at = event.createdAt || this.now().toISOString();
    if (event.type === "item.started" && event.itemType === "tool") {
      const id = event.itemId ?? randomUUID();
      state.tools.set(id, { id, name: summary(event.title ?? "tool", 256), startedAt: at });
    } else if (event.type === "item.completed" && event.itemType === "tool") {
      const id = event.itemId ?? "unknown";
      const open = state.tools.get(id) ?? { id, name: "tool", startedAt: at };
      state.tools.delete(id);
      state.completedTools.push({ ...open, endedAt: at, ok: event.ok });
    } else if (event.type === "item.completed" && event.itemType === "assistant_text") {
      state.responseSummary = summary(`${state.responseSummary} ${String(this.sanitize(event.text))}`);
    } else if (event.type === "thread.token-usage.updated") {
      state.usage = { input: event.input, output: event.output };
    } else if (event.type === "turn.completed") {
      if (event.usage) state.usage = event.usage;
      const cancelled = /cancel|interrupt|abort/i.test(event.stopReason ?? "");
      this.finishTurn(event.threadId, event.ok ? "completed" : cancelled ? "cancelled" : "failed", event.stopReason ?? undefined);
    }
  }

  failTurn(threadId: string, error: unknown): void {
    const state = this.turns.get(threadId);
    const message = error instanceof Error ? error.message : String(error);
    if (state) state.errorSummary = summary(String(this.sanitize(message)), 1_000);
    this.captureError(error, { component: "driver", state });
    this.finishTurn(threadId, "failed", message);
  }

  private finishTurn(threadId: string, outcome: TelemetryTraceEnvelope["outcome"], error?: string): void {
    const state = this.turns.get(threadId);
    if (!state) return;
    this.turns.delete(threadId);
    const endedAt = this.now().toISOString();
    for (const open of state.tools.values()) {
      state.completedTools.push({ ...open, endedAt, ok: false });
    }
    const envelope: TelemetryTraceEnvelope = this.sanitize({
      kind: "trace",
      application: "openmausbot",
      correlationId: state.correlationId,
      traceId: state.traceId,
      botId: state.botId,
      botName: state.botName,
      threadId: state.threadId,
      turnId: state.turnId,
      engine: state.engine,
      model: state.model,
      release: this.options.release,
      sourceSha: this.options.sourceSha,
      startedAt: state.startedAt,
      endedAt,
      promptSummary: state.promptSummary,
      responseSummary: state.responseSummary,
      tools: state.completedTools.slice(0, 200),
      usage: state.usage,
      outcome,
      errorSummary: error ? summary(String(this.sanitize(error)), 1_000) : state.errorSummary,
    });
    this.writeJournal(envelope);
    this.send("langfuse", envelope);
  }

  captureError(
    error: unknown,
    context: {
      component: TelemetryErrorEnvelope["component"];
      state?: TurnState;
      turnId?: string;
      botId?: string;
      botName?: string;
      threadId?: string;
      engine?: string;
      model?: string;
      correlationId?: string;
    },
  ): void {
    const original = error instanceof Error ? error : new Error(String(error));
    const state = context.state;
    const envelope: TelemetryErrorEnvelope = this.sanitize({
      kind: "error",
      application: "openmausbot",
      correlationId: context.correlationId ?? state?.correlationId ?? randomUUID(),
      traceId: state?.traceId,
      botId: context.botId ?? state?.botId,
      botName: context.botName ?? state?.botName,
      threadId: context.threadId ?? state?.threadId,
      turnId: context.turnId ?? state?.turnId,
      engine: context.engine ?? state?.engine,
      model: context.model ?? state?.model,
      release: this.options.release,
      sourceSha: this.options.sourceSha,
      component: context.component,
      name: original.name,
      message: summary(original.message, 1_000),
      stack: original.stack ? summary(original.stack, 4_000) : undefined,
      at: this.now().toISOString(),
    });
    this.send("sentry", envelope);
  }

  private writeJournal(envelope: TelemetryTraceEnvelope): void {
    try {
      appendFileSync(this.journalPath, `${JSON.stringify(this.sanitize(envelope))}\n`, { mode: 0o600 });
    } catch {
      this.degrade("langfuse", "sanitized telemetry journal could not be written");
    }
  }

  private send(kind: SinkKind, envelope: TelemetryEnvelope): void {
    const child = this.sinks.get(kind);
    if (!child || child.stdin.destroyed) {
      this.degrade(kind, "telemetry sink is unavailable");
      return;
    }
    try {
      child.stdin.write(`${JSON.stringify(this.sanitize(envelope))}\n`);
    } catch {
      this.degrade(kind, "telemetry sink write failed");
    }
  }

  shutdown(): void {
    for (const threadId of [...this.turns.keys()]) this.finishTurn(threadId, "cancelled", "application shutdown");
    for (const child of this.sinks.values()) {
      try { child.stdin.end(); } catch {}
      killCliTree(child);
    }
    this.sinks.clear();
  }
}
