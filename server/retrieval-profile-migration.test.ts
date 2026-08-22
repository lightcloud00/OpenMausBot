import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  applyRetrievalProfileMigration,
  previewRetrievalProfileMigration,
  rollbackRetrievalProfileMigration,
} from "./retrieval-profile-migration.ts";

const digest = (value: string): string =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;

function fixture() {
  const dataDir = mkdtempSync(join(tmpdir(), "openmaus-profile-migration-"));
  const botsPath = join(dataDir, "bots.json");
  const original = JSON.stringify([
    { id: "bot-ada", name: "Ada", modelSelection: { instanceId: "qwen", model: "qwen-model" } },
    { id: "bot-same-name", name: "Ada", modelSelection: { instanceId: "claude", model: "claude-model" } },
    { id: "bot-codex", name: "Builder", retrievalProfile: "task-scoped" },
  ], null, 2);
  writeFileSync(botsPath, original);
  return { dataDir, botsPath, original };
}

describe("retrieval-profile bot-id migration", () => {
  it("previews without writing, then snapshots and atomically applies only exact bot ids", () => {
    const { dataDir, botsPath, original } = fixture();
    const preview = previewRetrievalProfileMigration({
      dataDir,
      botIds: ["bot-ada"],
      profile: "task-scoped",
    });
    expect(preview).toMatchObject({
      before_digest: digest(original),
      changed_bot_ids: ["bot-ada"],
      unchanged_bot_ids: [],
    });
    expect(readFileSync(botsPath, "utf8")).toBe(original);

    const receipt = applyRetrievalProfileMigration({
      dataDir,
      botIds: ["bot-ada"],
      profile: "task-scoped",
      expectedDigest: preview.before_digest,
      now: new Date("2026-08-22T06:00:00Z"),
    });
    expect(receipt.applied).toBe(true);
    expect(receipt.backup_path).not.toBeNull();
    expect(readFileSync(receipt.backup_path!, "utf8")).toBe(original);
    expect(digest(readFileSync(botsPath, "utf8"))).toBe(receipt.after_digest);
    const bots = JSON.parse(readFileSync(botsPath, "utf8"));
    expect(bots.find((bot: { id: string }) => bot.id === "bot-ada").retrievalProfile).toBe("task-scoped");
    expect(bots.find((bot: { id: string }) => bot.id === "bot-same-name")).not.toHaveProperty("retrievalProfile");
  });

  it("is idempotent and does not create another backup for an already-applied profile", () => {
    const { dataDir } = fixture();
    const preview = previewRetrievalProfileMigration({ dataDir, botIds: ["bot-codex"], profile: "task-scoped" });
    const receipt = applyRetrievalProfileMigration({
      dataDir,
      botIds: ["bot-codex"],
      profile: "task-scoped",
      expectedDigest: preview.before_digest,
    });
    expect(receipt).toMatchObject({
      applied: false,
      changed_bot_ids: [],
      unchanged_bot_ids: ["bot-codex"],
      backup_path: null,
      receipt_path: null,
    });
  });

  it("refuses stale previews and unknown ids without changing bots.json", () => {
    const { dataDir, botsPath, original } = fixture();
    expect(() => applyRetrievalProfileMigration({
      dataDir,
      botIds: ["bot-ada"],
      profile: "task-scoped",
      expectedDigest: "sha256:" + "0".repeat(64),
    })).toThrow(/changed after preview/);
    expect(readFileSync(botsPath, "utf8")).toBe(original);
    expect(() => previewRetrievalProfileMigration({
      dataDir,
      botIds: ["missing-bot"],
      profile: "task-scoped",
    })).toThrow(/unknown bot id/);
    expect(readFileSync(botsPath, "utf8")).toBe(original);
  });

  it("restores exact original bot bytes from the receipt-bound backup without touching messages", () => {
    const { dataDir, botsPath, original } = fixture();
    const messagesPath = join(dataDir, "messages.db");
    writeFileSync(messagesPath, "MESSAGE DATABASE SENTINEL");
    const preview = previewRetrievalProfileMigration({ dataDir, botIds: ["bot-ada"], profile: "task-scoped" });
    const applied = applyRetrievalProfileMigration({
      dataDir,
      botIds: ["bot-ada"],
      profile: "task-scoped",
      expectedDigest: preview.before_digest,
      now: new Date("2026-08-22T06:00:00Z"),
    });
    const rollback = rollbackRetrievalProfileMigration({
      receiptPath: applied.receipt_path!,
      now: new Date("2026-08-22T08:00:00Z"),
    });

    expect(readFileSync(botsPath, "utf8")).toBe(original);
    expect(readFileSync(messagesPath, "utf8")).toBe("MESSAGE DATABASE SENTINEL");
    expect(rollback).toMatchObject({
      schema: "openmaus.retrieval-profile-rollback-receipt.v1",
      before_digest: preview.before_digest,
      restored_digest: preview.before_digest,
      rolled_back_at: "2026-08-22T08:00:00.000Z",
    });
    expect(JSON.parse(readFileSync(rollback.rollback_receipt_path, "utf8"))).toEqual(rollback);
  });

  it("refuses rollback after bot-state drift and leaves both state and backup unchanged", () => {
    const { dataDir, botsPath, original } = fixture();
    const preview = previewRetrievalProfileMigration({ dataDir, botIds: ["bot-ada"], profile: "task-scoped" });
    const applied = applyRetrievalProfileMigration({
      dataDir,
      botIds: ["bot-ada"],
      profile: "task-scoped",
      expectedDigest: preview.before_digest,
      now: new Date("2026-08-22T06:30:00Z"),
    });
    const drift = `${readFileSync(botsPath, "utf8")}\n`;
    writeFileSync(botsPath, drift);

    expect(() => rollbackRetrievalProfileMigration({ receiptPath: applied.receipt_path! })).toThrow(/drifted after migration/);
    expect(readFileSync(botsPath, "utf8")).toBe(drift);
    expect(readFileSync(applied.backup_path!, "utf8")).toBe(original);
  });

  it("refuses a copied receipt and backup outside the bound data-directory migration root", () => {
    const { dataDir, botsPath, original } = fixture();
    const preview = previewRetrievalProfileMigration({ dataDir, botIds: ["bot-ada"], profile: "task-scoped" });
    const applied = applyRetrievalProfileMigration({
      dataDir,
      botIds: ["bot-ada"],
      profile: "task-scoped",
      expectedDigest: preview.before_digest,
      now: new Date("2026-08-22T09:00:00Z"),
    });
    const outside = mkdtempSync(join(tmpdir(), "openmaus-profile-forged-receipt-"));
    const outsideBackup = join(outside, "bots.json.original");
    const outsideReceipt = join(outside, "receipt.json");
    writeFileSync(outsideBackup, original);
    const forged = JSON.parse(readFileSync(applied.receipt_path!, "utf8"));
    forged.backup_path = outsideBackup;
    forged.receipt_path = outsideReceipt;
    writeFileSync(outsideReceipt, JSON.stringify(forged));
    const beforeAttempt = readFileSync(botsPath, "utf8");

    expect(() => rollbackRetrievalProfileMigration({ receiptPath: outsideReceipt }))
      .toThrow(/outside its data-directory migration root/);
    expect(readFileSync(botsPath, "utf8")).toBe(beforeAttempt);
    expect(readFileSync(outsideBackup, "utf8")).toBe(original);
  });
});
