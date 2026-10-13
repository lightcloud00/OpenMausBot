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

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { writeFileAtomic } from "./atomic.ts";
import { getOrCreateChannel, mirrorExchange, type CommsBus } from "./comms-visibility.ts";
import { DATA_DIR } from "./config.ts";
import { newId } from "./contracts.ts";
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

interface PendingDelegationItem extends DelegationItem {
  /** Stable acknowledgement key for crash-safe removal from the queue. */
  id: string;
  /** Epoch ms when a drain first found the target busy. Set means the item
   * is parked: it waits for the target to go idle instead of being dropped. */
  parkedAt?: number;
  /** How many drains have found the target busy so far. */
  busyChecks?: number;
}

export type QueueResult = "ok" | "duplicate" | "no_target" | "self" | "too_deep" | "too_many";

/** How long a parked handoff may wait for a busy target, and how many busy
 * drains it may survive, before it expires with a reason. Waiting forever is
 * the failure this bound replaces: work queued for a bot that never frees up
 * would otherwise sit in delegations.json indefinitely. */
export const MAX_PARK_MS = 30 * 60_000;
export const MAX_BUSY_CHECKS = 10;

/** Per source-thread queue. Persisted to delegations.json on every change
 * and reloaded at boot: a handoff queued right before a restart runs after
 * it. (Provider PERMISSIONS still die with the process — nobody can answer
 * for an unattended bot — but queued work is not a permission; the target
 * and approvePeerComms are re-checked at drain time as always.) */
const pendingDelegations = new Map<string, PendingDelegationItem[]>();
const drainingThreads = new Set<string>();
const DELEGATIONS_FILE = join(DATA_DIR, "delegations.json");

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
      const items = list.flatMap((value): PendingDelegationItem[] => {
        if (!value || typeof value !== "object") return [];
        const item = value as Partial<PendingDelegationItem>;
        if (
          typeof item.toBotId !== "string" ||
          typeof item.message !== "string" ||
          !Number.isFinite(item.depth)
        ) return [];
        const loaded: PendingDelegationItem = {
          id: typeof item.id === "string" && item.id ? item.id : newId(),
          toBotId: item.toBotId,
          message: item.message,
          ...(typeof item.reason === "string" ? { reason: item.reason } : {}),
          depth: Math.max(0, Math.trunc(item.depth!)),
        };
        // Parking state survives a restart, so a parked handoff keeps its
        // age and busy count instead of starting a fresh window.
        const { parkedAt, busyChecks } = item;
        if (parkedAt !== undefined && Number.isFinite(parkedAt)) loaded.parkedAt = parkedAt;
        if (busyChecks !== undefined && Number.isFinite(busyChecks)) loaded.busyChecks = Math.max(0, Math.trunc(busyChecks));
        return [loaded];
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
): QueueResult {
  if (item.toBotId === from.id) return "self";
  if (item.depth >= maxDepth) return "too_deep";
  const target = bus.store.bot(item.toBotId);
  if (!target) return "no_target";
  const list = pendingDelegations.get(sourceThreadId) ?? [];
  // A retried tool call must not become a second piece of work: the same
  // target, message and reason from the same source thread is one task.
  if (list.some((queued) =>
    queued.toBotId === item.toBotId && queued.message === item.message && queued.reason === item.reason
  )) return "duplicate";
  // Async handoff removes the backpressure that ask_bot got for free by
  // making the caller wait. Without a cap, one turn can queue unboundedly
  // and fan out into as many real turns on the next settle.
  if (list.length >= MAX_QUEUED_PER_THREAD) return "too_many";
  list.push({ ...item, id: newId() });
  pendingDelegations.set(sourceThreadId, list);
  savePending();
  const label = `Delegated to @${target.name}${item.reason ? `: ${item.reason}` : ""}`;
  bus.store.appendMessage(sourceThreadId, {
    role: "bot",
    kind: "activity",
    tool: { name: label },
  });
  return "ok";
}

type RunTarget = (
  toBotId: string,
  message: string,
  commsDepth: number,
  sourceThreadId: string,
  channel?: GroupRecord,
) => void | Promise<void>;

/** Drain queued delegations for a source thread (called on its
 * turn.completed). Each item is processed independently: a deny, a busy
 * target, or an error in one does not stop the rest. A busy target parks
 * its item instead of dropping it (see drainParkedDelegations). The actual
 * start of the target turn is delegated to `runTarget` so delegations.ts
 * stays free of harness-level concerns (commsDepth is the only thing
 * the caller needs). */
export function drainDelegations(
  bus: CommsBus,
  approvalBus: ApprovalBus,
  threadId: string,
  runTarget: RunTarget,
): void {
  drainThread(bus, approvalBus, threadId, runTarget, () => true, true);
}

/** Retry parked handoffs whose target has gone idle. Called on EVERY
 * turn.completed, like the steer-queue drain: the target settles on its
 * own thread, so this matches on "the parked item's target is free now"
 * rather than on the settling thread. Only parked items are touched — a
 * handoff still waiting on its own source turn keeps waiting for that. */
export function drainParkedDelegations(
  bus: CommsBus,
  approvalBus: ApprovalBus,
  runTarget: RunTarget,
): void {
  const isReady = parkedAndFree(bus);
  for (const [threadId, list] of pendingDelegations) {
    if (list.some(isReady)) drainThread(bus, approvalBus, threadId, runTarget, isReady, false);
  }
}

/** A parked handoff whose target is no longer busy (or no longer exists,
 * which processOne then reports). */
function parkedAndFree(bus: CommsBus): (item: PendingDelegationItem) => boolean {
  return (item) => item.parkedAt !== undefined && bus.store.bot(item.toBotId)?.busy !== true;
}

function drainThread(
  bus: CommsBus,
  approvalBus: ApprovalBus,
  threadId: string,
  runTarget: RunTarget,
  select: (item: PendingDelegationItem) => boolean,
  redrainNewWork: boolean,
): void {
  if (drainingThreads.has(threadId)) return;
  const list = pendingDelegations.get(threadId);
  if (!list?.length) return;
  const from = bus.store.botByThread(threadId);
  if (!from) {
    pendingDelegations.delete(threadId);
    savePending();
    return;
  }
  const seenIds = new Set(list.map((item) => item.id));
  const snapshot = list.filter(select);
  if (!snapshot.length) return;
  drainingThreads.add(threadId);
  void (async () => {
    for (const item of snapshot) {
      let outcome: DrainOutcome = "settled";
      try {
        outcome = await processOne(bus, approvalBus, from, threadId, item, runTarget);
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
      } finally {
        if (outcome === "settled") acknowledgeDelegation(threadId, item.id);
      }
    }
  })().finally(() => {
    drainingThreads.delete(threadId);
    // A later turn may have queued and settled while this thread was
    // waiting for approval. Its items were not in our snapshot, so start a
    // fresh drain instead of leaving them until another restart. Items that
    // were already here — parked ones included — are not new work, and
    // re-draining them would spin on a target that is still busy.
    const remaining = pendingDelegations.get(threadId) ?? [];
    if (redrainNewWork && remaining.some((item) => !seenIds.has(item.id))) {
      drainDelegations(bus, approvalBus, threadId, runTarget);
    } else if (remaining.some(parkedAndFree(bus))) {
      // A parked item's target may have gone idle while this drain held the
      // thread: its turn.completed found the drain lock taken and moved on.
      // Retry now rather than wait for some other bot to settle. This cannot
      // spin — a free target either runs the item or expires it.
      drainThread(bus, approvalBus, threadId, runTarget, parkedAndFree(bus), false);
    }
  });
}

/** Replace one queued item's parking state in place, and persist it. */
function updatePending(threadId: string, itemId: string, patch: Pick<PendingDelegationItem, "parkedAt" | "busyChecks">): void {
  const current = pendingDelegations.get(threadId);
  if (!current) return;
  pendingDelegations.set(threadId, current.map((item) => (item.id === itemId ? { ...item, ...patch } : item)));
  savePending();
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
 * they were dropped. Used when the queueing turn failed or was interrupted.
 * Parked handoffs are kept: they came from an EARLIER turn that finished,
 * and only wait for their target, so this turn's Stop is not about them. */
export function discardDelegations(bus: CommsBus, threadId: string): void {
  const all = pendingDelegations.get(threadId);
  const list = all?.filter((item) => item.parkedAt === undefined);
  if (!all || !list?.length) return;
  const parked = all.filter((item) => item.parkedAt !== undefined);
  if (parked.length) pendingDelegations.set(threadId, parked);
  else pendingDelegations.delete(threadId);
  savePending();
  const from = bus.store.botByThread(threadId);
  if (!from) return;
  bus.store.appendMessage(threadId, {
    role: "bot",
    kind: "activity",
    tool: { name: `${list.length} queued delegation${list.length > 1 ? "s" : ""} dropped — the turn did not finish`, ok: false },
  });
}

/** `settled`: the item reached a terminal state (ran, denied, expired or
 * failed) and leaves the queue. `parked`: its target is busy, so it stays
 * queued and drainParkedDelegations retries it when the target is free. */
type DrainOutcome = "settled" | "parked";

function reportExpired(bus: CommsBus, sourceThreadId: string, target: BotRecord): DrainOutcome {
  bus.store.appendMessage(sourceThreadId, {
    role: "bot",
    kind: "activity",
    tool: { name: `Delegation to @${target.name} expired — @${target.name} stayed busy (target_busy_expired)`, ok: false },
  });
  return "settled";
}

/** A busy target parks the handoff, unless it has already waited too long or
 * through too many busy drains — then it expires, saying why. The chip names
 * a fixed reason code so a reader (or a test) can tell expiry from denial. */
function parkOrExpire(
  bus: CommsBus,
  sourceThreadId: string,
  item: PendingDelegationItem,
  target: BotRecord,
  now = Date.now(),
): DrainOutcome {
  const parkedAt = item.parkedAt ?? now;
  const busyChecks = (item.busyChecks ?? 0) + 1;
  if (now - parkedAt >= MAX_PARK_MS || busyChecks > MAX_BUSY_CHECKS) return reportExpired(bus, sourceThreadId, target);
  updatePending(sourceThreadId, item.id, { parkedAt, busyChecks });
  if (item.parkedAt === undefined) {
    bus.store.appendMessage(sourceThreadId, {
      role: "bot",
      kind: "activity",
      tool: { name: `Delegation to @${target.name} waiting — @${target.name} is busy; it runs when @${target.name} is free` },
    });
  }
  return "parked";
}

async function processOne(
  bus: CommsBus,
  approvalBus: ApprovalBus,
  from: BotRecord,
  sourceThreadId: string,
  item: PendingDelegationItem,
  runTarget: RunTarget,
): Promise<DrainOutcome> {
  let sender = from;
  let target = bus.store.bot(item.toBotId);
  if (!target) {
    bus.store.appendMessage(sourceThreadId, {
      role: "bot",
      kind: "activity",
      tool: { name: `error: delegation to ${item.toBotId} failed — no such bot`, ok: false },
    });
    return "settled";
  }
  // A handoff that waited out its whole window does not run late, even if
  // the target is free now: the work it describes may no longer be wanted.
  if (item.parkedAt !== undefined && Date.now() - item.parkedAt >= MAX_PARK_MS) {
    return reportExpired(bus, sourceThreadId, target);
  }
  if (target.busy) return parkOrExpire(bus, sourceThreadId, item, target);
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
      return "settled";
    }
    // The approval could have been sitting for up to 15 minutes. Everything
    // checked above is a stale snapshot now: re-read both bots and re-check
    // busy, or an allow can start a second turn on a bot that is mid-turn —
    // and mirror a "Messaged @X" chip for an exchange that never happens.
    const current = bus.store.bot(item.toBotId);
    const currentSender = bus.store.bot(from.id);
    if (!current || !currentSender || !bus.store.taskByThread(currentSender.id, sourceThreadId)) return "settled";
    if (current.busy) return parkOrExpire(bus, sourceThreadId, item, current);
    sender = currentSender;
    target = current;
  }
  const channel = getOrCreateChannel(bus.store, sender, target);
  mirrorExchange(bus, sender, target, item.message, channel, sourceThreadId);
  const reasonLine = item.reason ? `\n\n[Reason: ${item.reason}]` : "";
  const prefixed = `[Delegated by @${sender.name}, another bot in this OpenMausBot workspace. Do the work and reply directly.]\n\n${item.message}${reasonLine}`;
  await runTarget(item.toBotId, prefixed, item.depth + 1, sourceThreadId, channel);
  return "settled";
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
