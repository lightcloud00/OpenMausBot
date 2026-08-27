// Durable async peer handoff (delegate_bot).
//
// A delegation waits for the source turn to settle, then dispatches once the
// chosen target is idle. Busy capacity is an event-driven queue condition,
// not a cancellation: target turn.completed events wake eligible records.
// Stable task ids and terminal receipts make retries idempotent across both
// HTTP retries and process restarts.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { writeFileAtomic } from "./atomic.ts";
import { getOrCreateChannel, mirrorExchange, type CommsBus } from "./comms-visibility.ts";
import { DATA_DIR } from "./config.ts";
import { requestPeerApproval, type ApprovalBus } from "./peer-approval.ts";
import type { BotRecord, GroupRecord } from "./store.ts";

export interface DelegationItem {
  toBotId: string;
  message: string;
  reason?: string;
  /** The source bot's comms depth (0 for a user-initiated turn). The
   * delegated-to bot runs at depth + 1. The caller still enforces the
   * one-hop ceiling before anything is persisted. */
  depth: number;
}

export type DelegationState = "completed" | "queued" | "failed";
export type DelegationReason =
  | "accepted"
  | "dispatch_accepted"
  | "self"
  | "too_deep"
  | "no_target"
  | "too_many"
  | "queue_persist_failed"
  | "source_run_invalid"
  | "source_missing"
  | "target_missing"
  | "target_busy"
  | "target_busy_retry_limit"
  | "retry_limit_exceeded"
  | "max_age_exceeded"
  | "approval_denied"
  | "approval_unavailable"
  | "dispatch_failed"
  | "source_turn_failed"
  | "dispatch_outcome_unknown_after_restart";

export interface QueueResult {
  state: DelegationState;
  taskId: string;
  duplicate: boolean;
  reason?: DelegationReason;
}

export interface DelegationDispatchOutcome {
  state: "completed" | "queued" | "failed";
  reason?: DelegationReason;
}

export type RunDelegatedTarget = (
  toBotId: string,
  message: string,
  commsDepth: number,
  sourceThreadId: string,
  channel?: GroupRecord,
) => void | DelegationDispatchOutcome | Promise<void | DelegationDispatchOutcome>;

type PendingStatus = "waiting_source" | "queued" | "dispatching";

interface PendingDelegationItem extends DelegationItem {
  taskId: string;
  sourceBotId: string;
  sourceThreadId: string;
  sourceRunId: string;
  createdAt: string;
  updatedAt: string;
  attemptCount: number;
  maxDepth: number;
  status: PendingStatus;
  waitingForTarget: boolean;
  lastReason?: DelegationReason;
}

interface TerminalDelegationOutcome {
  taskId: string;
  sourceThreadId: string;
  targetBotId: string;
  state: "completed" | "failed";
  reason: DelegationReason;
  attemptCount: number;
  completedAt: string;
}

interface DelegationStoreV2 {
  schema: typeof STORE_SCHEMA;
  pending: Record<string, PendingDelegationItem[]>;
  outcomes: Record<string, TerminalDelegationOutcome>;
}

interface DrainOptions {
  now?: () => number;
}

const STORE_SCHEMA = "openmaus.delegations.v2" as const;
const DELEGATIONS_FILE = join(DATA_DIR, "delegations.json");
const TASK_ID = /^[0-9a-f]{64}$/;
const SOURCE_RUN_ID = /^[A-Za-z0-9_-]{16,120}$/;
const MAX_QUEUED_PER_THREAD = 4;
export const MAX_DELEGATION_ATTEMPTS = 3;
export const MAX_DELEGATION_AGE_MS = 24 * 60 * 60 * 1_000;
const TERMINAL_RETENTION_MS = 7 * 24 * 60 * 60 * 1_000;
const MAX_TERMINAL_OUTCOMES = 2_048;
const DELEGATION_REASONS = new Set<DelegationReason>([
  "accepted",
  "dispatch_accepted",
  "self",
  "too_deep",
  "no_target",
  "too_many",
  "queue_persist_failed",
  "source_run_invalid",
  "source_missing",
  "target_missing",
  "target_busy",
  "target_busy_retry_limit",
  "retry_limit_exceeded",
  "max_age_exceeded",
  "approval_denied",
  "approval_unavailable",
  "dispatch_failed",
  "source_turn_failed",
  "dispatch_outcome_unknown_after_restart",
]);

const pendingDelegations = new Map<string, PendingDelegationItem[]>();
const terminalOutcomes = new Map<string, TerminalDelegationOutcome>();
const drainingThreads = new Set<string>();
const pendingCandidates = new Map<string, Set<string>>();
const activeTargets = new Set<string>();

const nowIso = (nowMs: number) => new Date(nowMs).toISOString();
const isDelegationReason = (value: unknown): value is DelegationReason =>
  typeof value === "string" && DELEGATION_REASONS.has(value as DelegationReason);

function stableTaskId(
  sourceBotId: string,
  sourceThreadId: string,
  sourceRunId: string,
  item: DelegationItem,
): string {
  const identity = JSON.stringify({
    sourceBotId,
    sourceThreadId,
    sourceRunId,
    toBotId: item.toBotId,
    message: item.message,
    reason: item.reason ?? "",
    depth: item.depth,
  });
  return createHash("sha256").update(`openmaus-delegation-v1:${identity}`).digest("hex");
}

function pruneTerminal(nowMs: number): void {
  for (const [taskId, outcome] of terminalOutcomes) {
    const completed = Date.parse(outcome.completedAt);
    if (!Number.isFinite(completed) || nowMs - completed > TERMINAL_RETENTION_MS) {
      terminalOutcomes.delete(taskId);
    }
  }
  const overflow = terminalOutcomes.size - MAX_TERMINAL_OUTCOMES;
  if (overflow <= 0) return;
  const oldest = [...terminalOutcomes.values()]
    .sort((left, right) => left.completedAt.localeCompare(right.completedAt))
    .slice(0, overflow);
  for (const outcome of oldest) terminalOutcomes.delete(outcome.taskId);
}

function saveState(nowMs = Date.now()): void {
  pruneTerminal(nowMs);
  const payload: DelegationStoreV2 = {
    schema: STORE_SCHEMA,
    pending: Object.fromEntries(
      [...pendingDelegations].filter(([, items]) => items.length > 0),
    ),
    outcomes: Object.fromEntries(terminalOutcomes),
  };
  writeFileAtomic(DELEGATIONS_FILE, JSON.stringify(payload, null, 2), { mode: 0o600 });
}

function record(
  bus: CommsBus,
  item: Pick<PendingDelegationItem, "taskId" | "sourceThreadId" | "toBotId" | "attemptCount">,
  state: DelegationState,
  reason: DelegationReason,
  duplicate = false,
): void {
  try {
    bus.recordDelegation?.({
      type: "delegation.status",
      threadId: item.sourceThreadId,
      taskId: item.taskId,
      targetBotId: item.toBotId,
      state,
      reason,
      attemptCount: item.attemptCount,
      ...(duplicate ? { duplicate: true } : {}),
    });
  } catch {
    /* observability never changes the queue decision */
  }
}

function appendActivity(bus: CommsBus, threadId: string, name: string, ok?: boolean): void {
  try {
    bus.store.appendMessage(threadId, {
      role: "bot",
      kind: "activity",
      tool: { name, ...(ok === undefined ? {} : { ok }) },
    });
  } catch {
    /* the durable outcome and turn ledger remain authoritative */
  }
}

function pendingItem(threadId: string, taskId: string): PendingDelegationItem | undefined {
  return pendingDelegations.get(threadId)?.find((item) => item.taskId === taskId);
}

function validationFailure(
  bus: CommsBus,
  sourceBotId: string,
  sourceThreadId: string,
  sourceRunId: string,
  item: DelegationItem,
  reason: DelegationReason,
): QueueResult {
  const taskId = stableTaskId(sourceBotId, sourceThreadId, sourceRunId, item);
  record(bus, { taskId, sourceThreadId, toBotId: item.toBotId, attemptCount: 0 }, "failed", reason);
  return { state: "failed", taskId, duplicate: false, reason };
}

/** Load the crash-safe queue and its bounded idempotency receipts. Legacy
 * per-thread maps are migrated in memory. A record that was already marked
 * dispatching is never replayed after a crash: whether the child accepted it
 * is unknowable, so the safe terminal receipt is an explicit failure. */
export function _loadPending(): void {
  pendingDelegations.clear();
  terminalOutcomes.clear();
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(DELEGATIONS_FILE, "utf8"));
  } catch {
    return;
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return;
  const root = raw as Record<string, unknown>;
  const v2 = root.schema === STORE_SCHEMA;
  const rawPending = v2 && root.pending && typeof root.pending === "object" && !Array.isArray(root.pending)
    ? root.pending as Record<string, unknown>
    : root;
  const rawOutcomes = v2 && root.outcomes && typeof root.outcomes === "object" && !Array.isArray(root.outcomes)
    ? root.outcomes as Record<string, unknown>
    : {};
  const loadedAt = Date.now();
  let migrated = !v2;

  for (const [taskId, value] of Object.entries(rawOutcomes)) {
    if (!TASK_ID.test(taskId) || !value || typeof value !== "object" || Array.isArray(value)) continue;
    const outcome = value as Partial<TerminalDelegationOutcome>;
    if (
      (outcome.state !== "completed" && outcome.state !== "failed") ||
      !isDelegationReason(outcome.reason) ||
      typeof outcome.sourceThreadId !== "string" ||
      typeof outcome.targetBotId !== "string" ||
      typeof outcome.completedAt !== "string"
    ) continue;
    terminalOutcomes.set(taskId, {
      taskId,
      sourceThreadId: outcome.sourceThreadId,
      targetBotId: outcome.targetBotId,
      state: outcome.state,
      reason: outcome.reason,
      attemptCount: Number.isFinite(outcome.attemptCount) ? Math.max(0, Math.trunc(outcome.attemptCount!)) : 0,
      completedAt: outcome.completedAt,
    });
  }

  for (const [threadId, value] of Object.entries(rawPending)) {
    if (threadId === "schema" || threadId === "pending" || threadId === "outcomes" || !Array.isArray(value)) continue;
    const items: PendingDelegationItem[] = [];
    for (const candidate of value) {
      if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) continue;
      const item = candidate as Partial<PendingDelegationItem> & { id?: unknown };
      if (
        typeof item.toBotId !== "string" ||
        typeof item.message !== "string" ||
        !Number.isSafeInteger(item.depth) ||
        item.depth! < 0
      ) continue;
      const normalized: DelegationItem = {
        toBotId: item.toBotId,
        message: item.message,
        ...(typeof item.reason === "string" ? { reason: item.reason } : {}),
        depth: item.depth!,
      };
      const sourceBotId = typeof item.sourceBotId === "string" ? item.sourceBotId : "";
      const sourceRunId = typeof item.sourceRunId === "string" && SOURCE_RUN_ID.test(item.sourceRunId)
        ? item.sourceRunId
        : `legacy_${createHash("sha256").update(`${sourceBotId}:${threadId}:${item.taskId ?? ""}`).digest("hex").slice(0, 32)}`;
      const computedTaskId = stableTaskId(sourceBotId, threadId, sourceRunId, normalized);
      const taskId = typeof item.taskId === "string" && TASK_ID.test(item.taskId) && item.taskId === computedTaskId
        ? item.taskId
        : computedTaskId;
      if (item.sourceRunId !== sourceRunId || item.taskId !== taskId) migrated = true;
      if (terminalOutcomes.has(taskId) || items.some((existing) => existing.taskId === taskId)) {
        migrated = true;
        continue;
      }
      const createdAt = typeof item.createdAt === "string" && Number.isFinite(Date.parse(item.createdAt))
        ? item.createdAt
        : nowIso(loadedAt);
      const status: PendingStatus = item.status === "queued" || item.status === "dispatching"
        ? item.status
        : "waiting_source";
      const attemptCount = Number.isFinite(item.attemptCount)
        ? Math.max(0, Math.trunc(item.attemptCount!))
        : 0;
      const maxDepth = Number.isSafeInteger(item.maxDepth) && item.maxDepth! > 0
        ? item.maxDepth!
        : 1;
      if (status === "dispatching") {
        terminalOutcomes.set(taskId, {
          taskId,
          sourceThreadId: threadId,
          targetBotId: normalized.toBotId,
          state: "failed",
          reason: "dispatch_outcome_unknown_after_restart",
          attemptCount,
          completedAt: nowIso(loadedAt),
        });
        migrated = true;
        continue;
      }
      items.push({
        ...normalized,
        taskId,
        sourceBotId,
        sourceThreadId: threadId,
        sourceRunId,
        createdAt,
        updatedAt: typeof item.updatedAt === "string" ? item.updatedAt : createdAt,
        attemptCount,
        maxDepth,
        status,
        waitingForTarget: item.waitingForTarget === true,
        ...(isDelegationReason(item.lastReason) ? { lastReason: item.lastReason } : {}),
      });
    }
    if (items.length) pendingDelegations.set(threadId, items);
  }
  pruneTerminal(loadedAt);
  if (migrated) {
    try {
      saveState(loadedAt);
    } catch (error) {
      console.error("delegations: could not persist migrated queue", error);
    }
  }
}

/** Source threads with active queued work. */
export function pendingThreads(): string[] {
  return [...pendingDelegations].filter(([, items]) => items.length > 0).map(([threadId]) => threadId);
}

/** Read-only metadata for the local Team Map. Task prompts stay private;
 * the UI only needs to know who handed work to whom and the optional label. */
export function pendingDelegationSnapshot(): Array<{
  sourceThreadId: string;
  toBotId: string;
  reason?: string;
}> {
  return [...pendingDelegations.entries()].flatMap(([sourceThreadId, items]) =>
    items.map((item) => ({
      sourceThreadId,
      toBotId: item.toBotId,
      ...(item.reason ? { reason: item.reason } : {}),
    })),
  );
}

/** Validate and enqueue one stable task. Repeated identical requests return
 * the existing queued or terminal receipt and never append another item. */
export function queueDelegation(
  bus: CommsBus,
  from: BotRecord,
  item: DelegationItem,
  maxDepth: number,
  sourceRunId: string,
  sourceThreadId = from.threadId,
  options: { nowMs?: number } = {},
): QueueResult {
  const taskId = stableTaskId(from.id, sourceThreadId, sourceRunId, item);
  if (!SOURCE_RUN_ID.test(sourceRunId)) {
    return validationFailure(bus, from.id, sourceThreadId, sourceRunId, item, "source_run_invalid");
  }
  if (item.toBotId === from.id) {
    return validationFailure(bus, from.id, sourceThreadId, sourceRunId, item, "self");
  }
  if (
    !Number.isSafeInteger(item.depth) ||
    item.depth < 0 ||
    !Number.isSafeInteger(maxDepth) ||
    maxDepth < 1 ||
    item.depth >= maxDepth
  ) return validationFailure(bus, from.id, sourceThreadId, sourceRunId, item, "too_deep");

  const terminal = terminalOutcomes.get(taskId);
  if (terminal) {
    record(
      bus,
      { taskId, sourceThreadId, toBotId: item.toBotId, attemptCount: terminal.attemptCount },
      terminal.state,
      terminal.reason,
      true,
    );
    return { state: terminal.state, taskId, duplicate: true, reason: terminal.reason };
  }
  const list = pendingDelegations.get(sourceThreadId) ?? [];
  const existing = list.find((candidate) => candidate.taskId === taskId);
  if (existing) {
    record(bus, existing, "queued", existing.lastReason ?? "accepted", true);
    return {
      state: "queued",
      taskId,
      duplicate: true,
      reason: existing.lastReason ?? "accepted",
    };
  }
  if (!bus.store.bot(item.toBotId)) {
    return validationFailure(bus, from.id, sourceThreadId, sourceRunId, item, "no_target");
  }
  if (list.length >= MAX_QUEUED_PER_THREAD) {
    return validationFailure(bus, from.id, sourceThreadId, sourceRunId, item, "too_many");
  }

  const nowMs = options.nowMs ?? Date.now();
  const createdAt = nowIso(nowMs);
  const queued: PendingDelegationItem = {
    ...item,
    taskId,
    sourceBotId: from.id,
    sourceThreadId,
    sourceRunId,
    createdAt,
    updatedAt: createdAt,
    attemptCount: 0,
    maxDepth,
    status: "waiting_source",
    waitingForTarget: false,
  };
  list.push(queued);
  pendingDelegations.set(sourceThreadId, list);
  try {
    saveState(nowMs);
  } catch {
    const remaining = list.filter((candidate) => candidate.taskId !== taskId);
    if (remaining.length) pendingDelegations.set(sourceThreadId, remaining);
    else pendingDelegations.delete(sourceThreadId);
    return validationFailure(bus, from.id, sourceThreadId, sourceRunId, item, "queue_persist_failed");
  }

  const target = bus.store.bot(item.toBotId)!;
  appendActivity(
    bus,
    sourceThreadId,
    `Delegated to @${target.name}${item.reason ? `: ${item.reason}` : ""}`,
  );
  record(bus, queued, "queued", "accepted");
  return { state: "queued", taskId, duplicate: false, reason: "accepted" };
}

function removePending(threadId: string, taskId: string): void {
  const current = pendingDelegations.get(threadId);
  if (!current) return;
  const remaining = current.filter((item) => item.taskId !== taskId);
  if (remaining.length) pendingDelegations.set(threadId, remaining);
  else pendingDelegations.delete(threadId);
}

function settle(
  bus: CommsBus,
  item: PendingDelegationItem,
  state: "completed" | "failed",
  reason: DelegationReason,
  nowMs: number,
): void {
  removePending(item.sourceThreadId, item.taskId);
  terminalOutcomes.set(item.taskId, {
    taskId: item.taskId,
    sourceThreadId: item.sourceThreadId,
    targetBotId: item.toBotId,
    state,
    reason,
    attemptCount: item.attemptCount,
    completedAt: nowIso(nowMs),
  });
  try {
    saveState(nowMs);
  } catch (error) {
    // Keep the in-process receipt so a caller retry still deduplicates. The
    // last durable state is dispatching, which load converts to an explicit
    // unknown-outcome failure rather than replaying it.
    console.error("delegations: could not persist terminal receipt", error);
  }
  record(bus, item, state, reason);
}

function deferBusy(bus: CommsBus, item: PendingDelegationItem, targetName: string, nowMs: number): void {
  if (item.attemptCount >= MAX_DELEGATION_ATTEMPTS) {
    settle(bus, item, "failed", "target_busy_retry_limit", nowMs);
    appendActivity(
      bus,
      item.sourceThreadId,
      `Delegation to @${targetName} failed — busy retry limit reached`,
      false,
    );
    return;
  }
  const firstDeferral = item.lastReason !== "target_busy";
  item.status = "queued";
  item.waitingForTarget = true;
  item.lastReason = "target_busy";
  item.updatedAt = nowIso(nowMs);
  try {
    saveState(nowMs);
  } catch {
    settle(bus, item, "failed", "queue_persist_failed", nowMs);
    return;
  }
  record(bus, item, "queued", "target_busy");
  if (firstDeferral) {
    appendActivity(
      bus,
      item.sourceThreadId,
      `Delegation to @${targetName} queued — target is busy; it will retry after that turn completes`,
    );
  }
}

function dispatchOutcome(value: unknown): DelegationDispatchOutcome {
  if (!value || typeof value !== "object") return { state: "completed", reason: "dispatch_accepted" };
  const candidate = value as Partial<DelegationDispatchOutcome>;
  if (candidate.state === "queued") return { state: "queued", reason: candidate.reason ?? "target_busy" };
  if (candidate.state === "failed") return { state: "failed", reason: candidate.reason ?? "dispatch_failed" };
  return { state: "completed", reason: "dispatch_accepted" };
}

async function processOne(
  bus: CommsBus,
  approvalBus: ApprovalBus,
  threadId: string,
  taskId: string,
  runTarget: RunDelegatedTarget,
  clock: () => number,
): Promise<void> {
  const item = pendingItem(threadId, taskId);
  if (!item || item.status === "dispatching") return;
  const nowMs = clock();
  const created = Date.parse(item.createdAt);
  if (!Number.isFinite(created) || nowMs - created > MAX_DELEGATION_AGE_MS) {
    settle(bus, item, "failed", "max_age_exceeded", nowMs);
    appendActivity(bus, threadId, "Delegation expired — maximum queue age exceeded", false);
    return;
  }
  if (item.depth >= item.maxDepth) {
    settle(bus, item, "failed", "too_deep", nowMs);
    return;
  }
  if (item.attemptCount >= MAX_DELEGATION_ATTEMPTS) {
    settle(bus, item, "failed", "retry_limit_exceeded", nowMs);
    appendActivity(bus, threadId, "Delegation failed — retry limit reached", false);
    return;
  }
  const from = bus.store.botByThread(threadId);
  if (
    !from ||
    (item.sourceBotId && from.id !== item.sourceBotId) ||
    !bus.store.taskByThread(from.id, threadId)
  ) {
    settle(bus, item, "failed", "source_missing", nowMs);
    return;
  }
  let target = bus.store.bot(item.toBotId);
  if (!target) {
    settle(bus, item, "failed", "target_missing", nowMs);
    appendActivity(bus, threadId, "Delegation failed — target bot no longer exists", false);
    return;
  }

  item.attemptCount += 1;
  item.updatedAt = nowIso(nowMs);
  try {
    saveState(nowMs);
  } catch {
    settle(bus, item, "failed", "queue_persist_failed", nowMs);
    return;
  }
  if (target.busy || activeTargets.has(target.id)) {
    deferBusy(bus, item, target.name, nowMs);
    return;
  }

  let sender = from;
  if (sender.approvePeerComms) {
    let verdict: "allow" | "deny";
    try {
      verdict = await requestPeerApproval(
        approvalBus,
        sender,
        target,
        item.message,
        "delegate_bot",
        threadId,
      );
    } catch {
      settle(bus, item, "failed", "approval_unavailable", clock());
      return;
    }
    if (verdict !== "allow") {
      settle(bus, item, "failed", "approval_denied", clock());
      appendActivity(bus, threadId, `Delegation to @${target.name} denied by user`, false);
      return;
    }
    const current = bus.store.bot(item.toBotId);
    const currentSender = bus.store.bot(from.id);
    if (!current || !currentSender || !bus.store.taskByThread(currentSender.id, threadId)) {
      settle(bus, item, "failed", current ? "source_missing" : "target_missing", clock());
      return;
    }
    sender = currentSender;
    target = current;
    if (target.busy || activeTargets.has(target.id)) {
      deferBusy(bus, item, target.name, clock());
      return;
    }
  }

  activeTargets.add(target.id);
  try {
    item.status = "dispatching";
    item.waitingForTarget = false;
    item.updatedAt = nowIso(clock());
    try {
      saveState(clock());
    } catch {
      settle(bus, item, "failed", "queue_persist_failed", clock());
      return;
    }
    const channel = getOrCreateChannel(bus.store, sender, target);
    const reasonLine = item.reason ? `\n\n[Reason: ${item.reason}]` : "";
    const prefixed = `[Delegated by @${sender.name}, another bot in this OpenMausBot workspace. Do the work and reply directly.]\n\n${item.message}${reasonLine}`;
    let outcome: DelegationDispatchOutcome;
    try {
      outcome = dispatchOutcome(
        await runTarget(item.toBotId, prefixed, item.depth + 1, threadId, channel),
      );
    } catch (error) {
      const status = (error as { status?: unknown } | null)?.status;
      const message = error instanceof Error ? error.message : String(error);
      outcome = status === 409 && /busy|already working/i.test(message)
        ? { state: "queued", reason: "target_busy" }
        : { state: "failed", reason: "dispatch_failed" };
    }
    if (outcome.state === "queued") {
      deferBusy(bus, item, target.name, clock());
      return;
    }
    if (outcome.state === "failed") {
      try {
        // A non-busy dispatch attempt still belongs in the shared channel:
        // runTarget may already have mirrored its terminal failure there,
        // and the source needs the channel link to make that record visible.
        // Busy races return above without producing a misleading exchange.
        mirrorExchange(bus, sender, target, item.message, channel, threadId);
      } catch (error) {
        console.error("delegations: could not mirror failed dispatch", error);
      }
      settle(bus, item, "failed", outcome.reason ?? "dispatch_failed", clock());
      appendActivity(bus, threadId, `Delegation to @${target.name} failed to start`, false);
      return;
    }
    try {
      mirrorExchange(bus, sender, target, item.message, channel, threadId);
    } catch (error) {
      // Provider submission and harness ownership are already accepted.
      // A visibility write must not downgrade that durable dispatch receipt.
      console.error("delegations: could not mirror accepted dispatch", error);
    }
    settle(bus, item, "completed", "dispatch_accepted", clock());
  } finally {
    activeTargets.delete(target.id);
  }
}

function scheduleDrain(
  bus: CommsBus,
  approvalBus: ApprovalBus,
  threadId: string,
  taskIds: Iterable<string>,
  runTarget: RunDelegatedTarget,
  options: DrainOptions,
): void {
  const candidates = pendingCandidates.get(threadId) ?? new Set<string>();
  for (const taskId of taskIds) candidates.add(taskId);
  if (!candidates.size) return;
  pendingCandidates.set(threadId, candidates);
  if (drainingThreads.has(threadId)) return;
  drainingThreads.add(threadId);
  const clock = options.now ?? Date.now;
  void (async () => {
    for (;;) {
      const pending = pendingCandidates.get(threadId);
      if (!pending?.size) break;
      const batch = [...pending];
      pending.clear();
      for (const taskId of batch) {
        try {
          await processOne(bus, approvalBus, threadId, taskId, runTarget, clock);
        } catch (error) {
          // A store/channel/observer failure must be scoped to this exact
          // task. Keep draining the batch and consume the rejection so the
          // fire-and-forget scheduler can never become an unhandled promise.
          const item = pendingItem(threadId, taskId);
          if (item) {
            let failedAt: number;
            try {
              failedAt = clock();
            } catch {
              failedAt = Date.now();
            }
            settle(bus, item, "failed", "dispatch_failed", failedAt);
            appendActivity(bus, threadId, "Delegation failed during queue dispatch", false);
          }
          console.error("delegations: contained drain failure", error);
        }
      }
    }
  })().finally(() => {
    drainingThreads.delete(threadId);
    if (!pendingCandidates.get(threadId)?.size) pendingCandidates.delete(threadId);
    else scheduleDrain(bus, approvalBus, threadId, [], runTarget, options);
  });
}

/** Mark one source turn's handoffs ready and attempt every active item once.
 * A busy result remains durable and is not re-added to this drain cycle. */
export function drainDelegations(
  bus: CommsBus,
  approvalBus: ApprovalBus,
  threadId: string,
  runTarget: RunDelegatedTarget,
  options: DrainOptions = {},
): void {
  const list = pendingDelegations.get(threadId);
  if (!list?.length) return;
  const nowMs = (options.now ?? Date.now)();
  let changed = false;
  for (const item of list) {
    if (item.status === "waiting_source") {
      item.status = "queued";
      item.updatedAt = nowIso(nowMs);
      changed = true;
    }
  }
  if (changed) {
    try {
      saveState(nowMs);
    } catch {
      for (const item of [...list]) settle(bus, item, "failed", "queue_persist_failed", nowMs);
      return;
    }
  }
  scheduleDrain(
    bus,
    approvalBus,
    threadId,
    list.filter((item) => item.status === "queued").map((item) => item.taskId),
    runTarget,
    options,
  );
}

/** Wake busy-deferred work from a target's turn.completed transition. With
 * an exact target id the event is authoritative; without one (room turns do
 * not retain their speaker after folding) every now-idle target is scanned.
 * This is event-driven only: there is no timer or polling loop. */
export function drainReadyDelegations(
  bus: CommsBus,
  approvalBus: ApprovalBus,
  runTarget: RunDelegatedTarget,
  targetBotId?: string,
  options: DrainOptions = {},
): void {
  const byThread = new Map<string, string[]>();
  for (const [threadId, items] of pendingDelegations) {
    for (const item of items) {
      if (item.status !== "queued" || !item.waitingForTarget) continue;
      if (targetBotId && item.toBotId !== targetBotId) continue;
      if (!targetBotId && bus.store.bot(item.toBotId)?.busy) continue;
      const ids = byThread.get(threadId) ?? [];
      ids.push(item.taskId);
      byThread.set(threadId, ids);
    }
  }
  for (const [threadId, taskIds] of byThread) {
    scheduleDrain(bus, approvalBus, threadId, taskIds, runTarget, options);
  }
}

/** A failed/interrupted source turn terminalizes its own not-yet-dispatched
 * fan-out. User words queued from other source threads are untouched. */
export function discardDelegations(bus: CommsBus, threadId: string): void {
  const list = [...(pendingDelegations.get(threadId) ?? [])];
  if (!list.length) return;
  const nowMs = Date.now();
  for (const item of list) {
    removePending(threadId, item.taskId);
    terminalOutcomes.set(item.taskId, {
      taskId: item.taskId,
      sourceThreadId: threadId,
      targetBotId: item.toBotId,
      state: "failed",
      reason: "source_turn_failed",
      attemptCount: item.attemptCount,
      completedAt: nowIso(nowMs),
    });
    record(bus, item, "failed", "source_turn_failed");
  }
  try {
    saveState(nowMs);
  } catch (error) {
    console.error("delegations: could not persist discarded queue", error);
  }
  appendActivity(
    bus,
    threadId,
    `${list.length} queued delegation${list.length > 1 ? "s" : ""} dropped — the source turn did not finish`,
    false,
  );
}

/** Test helper: how many active items remain for a source thread. */
export function _pendingCount(threadId: string): number {
  return pendingDelegations.get(threadId)?.length ?? 0;
}

/** Test helper: a copy of the persisted active record. */
export function _pendingItems(threadId: string): ReadonlyArray<Readonly<PendingDelegationItem>> {
  return (pendingDelegations.get(threadId) ?? []).map((item) => ({ ...item }));
}

/** Test helper: read an idempotency receipt without exposing task content. */
export function _terminalOutcome(taskId: string): Readonly<TerminalDelegationOutcome> | undefined {
  const outcome = terminalOutcomes.get(taskId);
  return outcome ? { ...outcome } : undefined;
}

/** Test helper: simulate a fresh process. */
export function _resetPending(): void {
  pendingDelegations.clear();
  terminalOutcomes.clear();
  pendingCandidates.clear();
  drainingThreads.clear();
  activeTargets.clear();
}
