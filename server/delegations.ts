// Async peer handoff (delegate_bot).
//
// A bot that finishes one task can hand the NEXT task to a peer without
// blocking its own turn — the source bot's turn.completed fires after it
// settles, and the queued delegation runs then. The peer gets a fresh
// depth-1 turn (depth cap still blocks A→B→C chains, see index.ts).
//
// Visiblity rides on the same comms-visibility helpers ask_bot uses
// (channel mirror + 1:1 chips) so a delegated exchange looks like an
// exchanged one. The optional approval gate (A2) is checked at drain
// time, never at queue time, because the user might have just turned
// approvePeerComms on between queueing and draining.

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
   * delegated-to bot runs at `depth + 1`, which equals MAX_COMMS_DEPTH
   * (= 1) for a user turn — so the peer has no agents integration, and
   * recursive delegation is structurally impossible. */
  depth: number;
}

type PendingPhase = "awaiting_source" | "waiting_target";

interface PendingDelegationItem extends DelegationItem {
  /** Stable task key used for both crash-safe acknowledgement and dedup. */
  id: string;
  queuedAt: string;
  attempts: number;
  phase: PendingPhase;
  lastReason?: DelegationReason;
}

export type QueueFailureReason = "no_target" | "self" | "too_deep" | "too_many";
export type DelegationReason =
  | "source_turn_active"
  | "duplicate"
  | "target_busy"
  | "expired"
  | "retry_limit"
  | "target_missing"
  | "source_missing"
  | "source_turn_failed"
  | "user_denied"
  | "dispatch_failed";

export interface DelegationOutcome {
  state: "completed" | "queued" | "failed";
  taskId: string;
  sourceThreadId: string;
  toBotId: string;
  attempts: number;
  reason?: DelegationReason;
}

export type DelegationRecorder = (outcome: DelegationOutcome) => void;

export type QueueResult =
  | { state: "queued"; taskId: string; duplicate: boolean }
  | { state: "failed"; reason: QueueFailureReason };

/** Per source-thread queue. Persisted to delegations.json on every change
 * and reloaded at boot: a handoff queued right before a restart runs after
 * it. (Provider PERMISSIONS still die with the process — nobody can answer
 * for an unattended bot — but queued work is not a permission; the target
 * and approvePeerComms are re-checked at drain time as always.) */
const pendingDelegations = new Map<string, PendingDelegationItem[]>();
const drainingThreads = new Set<string>();
const DELEGATIONS_FILE = join(DATA_DIR, "delegations.json");
const MAX_TARGET_BUSY_ATTEMPTS = 3;
const MAX_DELEGATION_AGE_MS = 15 * 60 * 1000;

function taskIdFor(sourceThreadId: string, item: DelegationItem): string {
  const digest = createHash("sha256")
    .update(JSON.stringify([
      sourceThreadId,
      item.toBotId,
      item.message,
      item.reason ?? "",
      Math.max(0, Math.trunc(item.depth)),
    ]))
    .digest("hex");
  return `delegation-${digest.slice(0, 32)}`;
}

function recordOutcome(record: DelegationRecorder | undefined, outcome: DelegationOutcome): void {
  try {
    record?.(outcome);
  } catch (error) {
    console.error("delegations: could not record outcome", error);
  }
}

function isExpired(item: PendingDelegationItem, now = Date.now()): boolean {
  const queuedAt = Date.parse(item.queuedAt);
  return !Number.isFinite(queuedAt) || now - queuedAt >= MAX_DELEGATION_AGE_MS;
}

function savePending(): void {
  try {
    writeFileAtomic(DELEGATIONS_FILE, JSON.stringify(Object.fromEntries(pendingDelegations), null, 2), { mode: 0o600 });
  } catch (error) {
    console.error("delegations: could not persist queue", error);
  }
}

/** Load what a previous process left queued. Missing or corrupt → empty. */
export function _loadPending(): void {
  pendingDelegations.clear();
  try {
    const raw = JSON.parse(readFileSync(DELEGATIONS_FILE, "utf8")) as Record<string, unknown>;
    for (const [threadId, list] of Object.entries(raw)) {
      if (!Array.isArray(list)) continue;
      const seen = new Set<string>();
      const items = list.flatMap((value): PendingDelegationItem[] => {
        if (!value || typeof value !== "object") return [];
        const item = value as Partial<PendingDelegationItem>;
        if (
          typeof item.toBotId !== "string" ||
          typeof item.message !== "string" ||
          !Number.isFinite(item.depth)
        ) return [];
        const normalized: DelegationItem = {
          toBotId: item.toBotId,
          message: item.message,
          ...(typeof item.reason === "string" ? { reason: item.reason } : {}),
          depth: Math.max(0, Math.trunc(item.depth!)),
        };
        // Older files used a random acknowledgement id. Re-derive every id
        // from the task itself so the first retry after an upgrade dedupes too.
        const id = taskIdFor(threadId, normalized);
        if (seen.has(id)) return [];
        seen.add(id);
        const queuedAt =
          typeof item.queuedAt === "string" && Number.isFinite(Date.parse(item.queuedAt))
            ? item.queuedAt
            : new Date().toISOString();
        const phase: PendingPhase = item.phase === "waiting_target" ? "waiting_target" : "awaiting_source";
        return [{
          ...normalized,
          id,
          queuedAt,
          attempts: Number.isFinite(item.attempts) ? Math.max(0, Math.trunc(item.attempts!)) : 0,
          phase,
          ...(typeof item.lastReason === "string" ? { lastReason: item.lastReason as DelegationReason } : {}),
        }];
      });
      if (items.length) pendingDelegations.set(threadId, items);
    }
  } catch {
    /* fresh install, or unreadable — start empty */
  }
}

/** Source threads with something queued — what a boot drain iterates. */
export function pendingThreads(): string[] {
  return [...pendingDelegations.keys()];
}

/** How many handoffs one turn may queue. Small on purpose: this is the only
 * thing standing between a confused bot and a fan-out of real turns. */
const MAX_QUEUED_PER_THREAD = 4;

/** Validate and enqueue a delegation. Pushes a "Delegated to @B: reason"
 * chip to the source thread so the user can see what was queued. */
export function queueDelegation(
  bus: CommsBus,
  from: BotRecord,
  item: DelegationItem,
  maxDepth: number,
  sourceThreadId = from.threadId,
  record?: DelegationRecorder,
): QueueResult {
  if (item.toBotId === from.id) return { state: "failed", reason: "self" };
  if (item.depth >= maxDepth) return { state: "failed", reason: "too_deep" };
  const target = bus.store.bot(item.toBotId);
  if (!target) return { state: "failed", reason: "no_target" };
  const list = pendingDelegations.get(sourceThreadId) ?? [];
  const id = taskIdFor(sourceThreadId, item);
  if (list.some((pending) => pending.id === id)) {
    return { state: "queued", taskId: id, duplicate: true };
  }
  // Async handoff removes the backpressure that ask_bot got for free by
  // making the caller wait. Without a cap, one turn can queue unboundedly
  // and fan out into as many real turns on the next settle.
  if (list.length >= MAX_QUEUED_PER_THREAD) return { state: "failed", reason: "too_many" };
  const pending: PendingDelegationItem = {
    ...item,
    id,
    queuedAt: new Date().toISOString(),
    attempts: 0,
    phase: "awaiting_source",
  };
  list.push(pending);
  pendingDelegations.set(sourceThreadId, list);
  savePending();
  const label = `Delegated to @${target.name}${item.reason ? `: ${item.reason}` : ""}`;
  bus.store.appendMessage(sourceThreadId, {
    role: "bot",
    kind: "activity",
    tool: { name: label },
  });
  recordOutcome(record, {
    state: "queued",
    taskId: id,
    sourceThreadId,
    toBotId: item.toBotId,
    attempts: 0,
    reason: "source_turn_active",
  });
  return { state: "queued", taskId: id, duplicate: false };
}

/** Drain queued delegations for a source thread (called on its
 * turn.completed). Each item is processed independently: a deny, a busy
 * target, or an error in one does not stop the rest. The actual start
 * of the target turn is delegated to `runTarget` so delegations.ts
 * stays free of harness-level concerns (commsDepth is the only thing
 * the caller needs). */
export function drainDelegations(
  bus: CommsBus,
  approvalBus: ApprovalBus,
  threadId: string,
  runTarget: (
    toBotId: string,
    message: string,
    commsDepth: number,
    sourceThreadId: string,
    channel?: GroupRecord,
  ) => void | Promise<void>,
  record?: DelegationRecorder,
): void {
  drainMatching(bus, approvalBus, threadId, runTarget, record, () => true);
}

/** Drain busy-target work only when an event says some turn completed. This
 * scans persisted waits for targets that are now idle; it never polls and it
 * never touches work whose source turn has not settled yet. */
export function drainReadyDelegations(
  bus: CommsBus,
  approvalBus: ApprovalBus,
  runTarget: Parameters<typeof drainDelegations>[3],
  record?: DelegationRecorder,
): void {
  const now = Date.now();
  for (const [threadId, list] of pendingDelegations) {
    const ready = list.some((item) =>
      item.phase === "waiting_target" &&
      (isExpired(item, now) || !bus.store.bot(item.toBotId)?.busy),
    );
    if (!ready) continue;
    drainMatching(
      bus,
      approvalBus,
      threadId,
      runTarget,
      record,
      (item) => item.phase === "waiting_target" &&
        (isExpired(item, now) || !bus.store.bot(item.toBotId)?.busy),
    );
  }
}

function drainMatching(
  bus: CommsBus,
  approvalBus: ApprovalBus,
  threadId: string,
  runTarget: Parameters<typeof drainDelegations>[3],
  record: DelegationRecorder | undefined,
  include: (item: PendingDelegationItem) => boolean,
): void {
  if (drainingThreads.has(threadId)) return;
  const list = pendingDelegations.get(threadId);
  if (!list?.length) return;
  const snapshot = list.filter(include);
  if (!snapshot.length) return;
  const from = bus.store.botByThread(threadId);
  if (!from) {
    for (const item of snapshot) {
      acknowledgeDelegation(threadId, item.id);
      recordOutcome(record, outcome(item, threadId, "failed", "source_missing"));
    }
    return;
  }
  drainingThreads.add(threadId);
  void (async () => {
    for (const item of snapshot) {
      let result: DelegationOutcome;
      try {
        result = await processOne(bus, approvalBus, from, threadId, item, runTarget);
      } catch (error) {
        const why = error instanceof Error ? error.message : String(error);
        try {
          bus.store.appendMessage(threadId, {
            role: "bot",
            kind: "activity",
            tool: { name: `error: delegation failed — ${why.slice(0, 120)}`, ok: false },
          });
        } catch (reportError) {
          console.error("delegation failed and could not be reported", reportError);
        }
        result = outcome(item, threadId, "failed", "dispatch_failed");
      }
      if (result.state !== "queued") {
        acknowledgeDelegation(threadId, item.id);
      }
      recordOutcome(record, result);
    }
  })().finally(() => {
    drainingThreads.delete(threadId);
    // A later turn may have queued and settled while this thread was
    // waiting for approval. Its items were not in our snapshot, so start a
    // fresh drain instead of leaving them parked until another restart.
    if (pendingDelegations.get(threadId)?.some((item) => item.phase === "awaiting_source")) {
      drainDelegations(bus, approvalBus, threadId, runTarget, record);
    }
  });
}

function outcome(
  item: PendingDelegationItem,
  sourceThreadId: string,
  state: DelegationOutcome["state"],
  reason?: DelegationReason,
): DelegationOutcome {
  return {
    state,
    taskId: item.id,
    sourceThreadId,
    toBotId: item.toBotId,
    attempts: item.attempts,
    ...(reason ? { reason } : {}),
  };
}

/** Remove one terminal handoff only after approval/dispatch has settled. */
function acknowledgeDelegation(threadId: string, itemId: string): void {
  const current = pendingDelegations.get(threadId);
  if (!current) return;
  const remaining = current.filter((item) => item.id !== itemId);
  if (remaining.length) pendingDelegations.set(threadId, remaining);
  else pendingDelegations.delete(threadId);
  savePending();
}

/** Drop a thread's queued handoffs without running them, telling the user
 * they were dropped. Used when the queueing turn failed or was interrupted. */
export function discardDelegations(
  bus: CommsBus,
  threadId: string,
  record?: DelegationRecorder,
  includeWaiting = false,
): void {
  const list = pendingDelegations.get(threadId);
  if (!list?.length) return;
  const discarded = includeWaiting ? list : list.filter((item) => item.phase === "awaiting_source");
  if (!discarded.length) return;
  const discardedIds = new Set(discarded.map((item) => item.id));
  const retained = list.filter((item) => !discardedIds.has(item.id));
  if (retained.length) pendingDelegations.set(threadId, retained);
  else pendingDelegations.delete(threadId);
  savePending();
  const from = bus.store.botByThread(threadId);
  if (!from) return;
  bus.store.appendMessage(threadId, {
    role: "bot",
    kind: "activity",
    tool: { name: `${discarded.length} queued delegation${discarded.length > 1 ? "s" : ""} dropped — the turn did not finish`, ok: false },
  });
  for (const item of discarded) {
    recordOutcome(record, outcome(item, threadId, "failed", "source_turn_failed"));
  }
}

async function processOne(
  bus: CommsBus,
  approvalBus: ApprovalBus,
  from: BotRecord,
  sourceThreadId: string,
  item: PendingDelegationItem,
  runTarget: (
    toBotId: string,
    message: string,
    commsDepth: number,
    sourceThreadId: string,
    channel?: GroupRecord,
  ) => void | Promise<void>,
): Promise<DelegationOutcome> {
  if (isExpired(item)) {
    reportFailure(bus, sourceThreadId, item.toBotId, "expired", "the queued delegation expired");
    return outcome(item, sourceThreadId, "failed", "expired");
  }
  let sender = from;
  let target = bus.store.bot(item.toBotId);
  if (!target) {
    reportFailure(bus, sourceThreadId, item.toBotId, "target_missing", "no such bot");
    return outcome(item, sourceThreadId, "failed", "target_missing");
  }
  if (target.busy) {
    return deferForBusyTarget(bus, sourceThreadId, item, target.name);
  }
  if (sender.approvePeerComms) {
    const verdict = await requestPeerApproval(
      approvalBus,
      sender,
      target,
      item.message,
      "delegate_bot",
      sourceThreadId,
    );
    if (verdict !== "allow") {
      bus.store.appendMessage(sourceThreadId, {
        role: "bot",
        kind: "activity",
        tool: { name: `Delegation to @${target.name} denied by user`, ok: false },
      });
      return outcome(item, sourceThreadId, "failed", "user_denied");
    }
    // The approval could have been sitting for up to 15 minutes. Everything
    // checked above is a stale snapshot now: re-read both bots and re-check
    // busy, or an allow can start a second turn on a bot that is mid-turn —
    // and mirror a "Messaged @X" chip for an exchange that never happens.
    const current = bus.store.bot(item.toBotId);
    const currentSender = bus.store.bot(from.id);
    if (!current || !currentSender || !bus.store.taskByThread(currentSender.id, sourceThreadId)) {
      reportFailure(bus, sourceThreadId, item.toBotId, "source_missing", "the source task no longer exists");
      return outcome(item, sourceThreadId, "failed", "source_missing");
    }
    if (current.busy) {
      return deferForBusyTarget(bus, sourceThreadId, item, current.name);
    }
    sender = currentSender;
    target = current;
  }
  const channel = getOrCreateChannel(bus.store, sender, target);
  const reasonLine = item.reason ? `\n\n[Reason: ${item.reason}]` : "";
  const prefixed = `[Delegated by @${sender.name}, another bot in this OpenMausBot workspace. Do the work and reply directly.]\n\n${item.message}${reasonLine}`;
  try {
    await runTarget(item.toBotId, prefixed, item.depth + 1, sourceThreadId, channel);
  } catch (error) {
    if (isBusyError(error)) return deferForBusyTarget(bus, sourceThreadId, item, target.name);
    const why = error instanceof Error ? error.message : String(error);
    // A permanent start failure is still part of the handoff record: show
    // the attempted request beside its terminal failure. Busy races are the
    // exception above because they remain eligible and must not look sent.
    mirrorExchange(bus, sender, target, item.message, channel, sourceThreadId);
    reportFailure(bus, sourceThreadId, target.name, "dispatch_failed", `could not start — ${why.slice(0, 120)}`);
    return outcome(item, sourceThreadId, "failed", "dispatch_failed");
  }
  // Do not mirror a handoff until the target has actually accepted the turn.
  // A busy race must remain retryable without showing a false exchange.
  mirrorExchange(bus, sender, target, item.message, channel, sourceThreadId);
  return outcome(item, sourceThreadId, "completed");
}

function isBusyError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  // 409 is also used for permanent configuration failures (for example a
  // missing provider instance), so status alone must never make work retry.
  return /already working|\bis busy\b/i.test(message);
}

function deferForBusyTarget(
  bus: CommsBus,
  sourceThreadId: string,
  item: PendingDelegationItem,
  targetName: string,
): DelegationOutcome {
  const attempts = item.attempts + 1;
  if (attempts >= MAX_TARGET_BUSY_ATTEMPTS) {
    reportFailure(bus, sourceThreadId, targetName, "retry_limit", "the target stayed busy across the retry limit");
    return { ...outcome(item, sourceThreadId, "failed", "retry_limit"), attempts };
  }
  const firstWait = item.phase !== "waiting_target" || item.lastReason !== "target_busy";
  item.phase = "waiting_target";
  item.attempts = attempts;
  item.lastReason = "target_busy";
  savePending();
  if (firstWait) {
    bus.store.appendMessage(sourceThreadId, {
      role: "bot",
      kind: "activity",
      tool: { name: `Delegation queued [target_busy] — @${targetName} will pick it up when the active turn completes` },
    });
  }
  return outcome(item, sourceThreadId, "queued", "target_busy");
}

function reportFailure(
  bus: CommsBus,
  sourceThreadId: string,
  targetName: string,
  reason: DelegationReason,
  detail: string,
): void {
  try {
    bus.store.appendMessage(sourceThreadId, {
      role: "bot",
      kind: "activity",
      tool: { name: `error: delegation failed [${reason}] — @${targetName}: ${detail}`, ok: false },
    });
  } catch {
    /* the source task may have been deleted; the structured recorder remains */
  }
}

/** Test helper: how many items remain queued for a thread. */
export function _pendingCount(threadId: string): number {
  return pendingDelegations.get(threadId)?.length ?? 0;
}

/** Test helper: forget the in-memory queue (a simulated restart). */
export function _resetPending(): void {
  pendingDelegations.clear();
  drainingThreads.clear();
}
