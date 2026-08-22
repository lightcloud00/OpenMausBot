import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { z } from "zod";

import { retrievalProfileSchema, type RetrievalProfile } from "../shared/retrieval-profile.ts";
import { writeFileAtomic } from "./atomic.ts";
import { parseJson, schemaIssue } from "./schema.ts";

const storedBotSchema = z.object({
  id: z.string(),
  retrievalProfile: retrievalProfileSchema.optional(),
}).loose();
const storedBotsSchema = z.array(storedBotSchema);
type StoredBot = z.output<typeof storedBotSchema>;

export interface RetrievalProfileMigrationPreview {
  schema: "openmaus.retrieval-profile-migration-preview.v1";
  data_dir: string;
  bots_path: string;
  bot_ids: string[];
  profile: RetrievalProfile;
  before_digest: string;
  after_digest: string;
  changed_bot_ids: string[];
  unchanged_bot_ids: string[];
}

export interface RetrievalProfileMigrationReceipt extends Omit<RetrievalProfileMigrationPreview, "schema"> {
  schema: "openmaus.retrieval-profile-migration-receipt.v1";
  applied: boolean;
  backup_path: string | null;
  receipt_path: string | null;
}

export interface RetrievalProfileRollbackReceipt {
  schema: "openmaus.retrieval-profile-rollback-receipt.v1";
  source_receipt_path: string;
  bots_path: string;
  backup_path: string;
  before_digest: string;
  after_digest: string;
  restored_digest: string;
  rollback_receipt_path: string;
  rolled_back_at: string;
}

const digestSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const appliedReceiptSchema = z.object({
  schema: z.literal("openmaus.retrieval-profile-migration-receipt.v1"),
  data_dir: z.string(),
  bots_path: z.string(),
  bot_ids: z.array(z.string()),
  profile: retrievalProfileSchema,
  before_digest: digestSchema,
  after_digest: digestSchema,
  changed_bot_ids: z.array(z.string()),
  unchanged_bot_ids: z.array(z.string()),
  applied: z.literal(true),
  backup_path: z.string(),
  receipt_path: z.string(),
});

const digest = (value: string): string =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;

function parsedBots(raw: string): StoredBot[] {
  let parsed;
  try {
    parsed = storedBotsSchema.safeParse(parseJson(raw));
  } catch {
    throw new Error("bots.json is not valid JSON");
  }
  if (!parsed.success) throw new Error(schemaIssue(parsed.error, "bots.json must contain bot records"));
  return parsed.data;
}

function exactBotIds(botIds: string[]): string[] {
  const unique = [...new Set(botIds)];
  if (!unique.length || unique.some((id) => !/^[\w-]+$/.test(id))) {
    throw new Error("at least one exact bot id is required");
  }
  return unique;
}

function candidate(previewInput: { dataDir: string; botIds: string[]; profile: RetrievalProfile }) {
  const ids = exactBotIds(previewInput.botIds);
  const botsPath = join(previewInput.dataDir, "bots.json");
  const before = readFileSync(botsPath, "utf8");
  const bots = parsedBots(before);
  const byId = new Map(bots.map((bot) => [bot.id, bot]));
  const missing = ids.filter((id) => !byId.has(id));
  if (missing.length) throw new Error(`unknown bot id(s): ${missing.join(", ")}`);

  const changed: string[] = [];
  const unchanged: string[] = [];
  for (const id of ids) {
    const bot = byId.get(id)!;
    if (bot.retrievalProfile === previewInput.profile) unchanged.push(id);
    else {
      bot.retrievalProfile = previewInput.profile;
      changed.push(id);
    }
  }
  const after = changed.length ? JSON.stringify(bots, null, 2) : before;
  return { botsPath, ids, before, after, changed, unchanged };
}

export function previewRetrievalProfileMigration(input: {
  dataDir: string;
  botIds: string[];
  profile: RetrievalProfile;
}): RetrievalProfileMigrationPreview {
  const result = candidate(input);
  return {
    schema: "openmaus.retrieval-profile-migration-preview.v1",
    data_dir: input.dataDir,
    bots_path: result.botsPath,
    bot_ids: result.ids,
    profile: input.profile,
    before_digest: digest(result.before),
    after_digest: digest(result.after),
    changed_bot_ids: result.changed,
    unchanged_bot_ids: result.unchanged,
  };
}

export function applyRetrievalProfileMigration(input: {
  dataDir: string;
  botIds: string[];
  profile: RetrievalProfile;
  expectedDigest: string;
  now?: Date;
}): RetrievalProfileMigrationReceipt {
  const result = candidate(input);
  const beforeDigest = digest(result.before);
  const afterDigest = digest(result.after);
  if (input.expectedDigest !== beforeDigest) {
    throw new Error(`bots.json changed after preview: expected ${input.expectedDigest}, found ${beforeDigest}`);
  }
  const base = {
    data_dir: input.dataDir,
    bots_path: result.botsPath,
    bot_ids: result.ids,
    profile: input.profile,
    before_digest: beforeDigest,
    after_digest: afterDigest,
    changed_bot_ids: result.changed,
    unchanged_bot_ids: result.unchanged,
  };
  if (!result.changed.length) {
    return {
      schema: "openmaus.retrieval-profile-migration-receipt.v1",
      ...base,
      applied: false,
      backup_path: null,
      receipt_path: null,
    };
  }

  const stamp = (input.now ?? new Date()).toISOString().replace(/[:.]/g, "-");
  const directory = join(input.dataDir, "migrations", "retrieval-profile", `${stamp}-${beforeDigest.slice(-12)}`);
  const backupPath = join(directory, "bots.json.original");
  const receiptPath = join(directory, "receipt.json");
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  if (existsSync(backupPath)) {
    const existingBackup = readFileSync(backupPath, "utf8");
    if (digest(existingBackup) !== beforeDigest) throw new Error("migration backup path already contains different state");
  } else {
    writeFileAtomic(backupPath, result.before, { mode: 0o600 });
  }

  // Compare again after the backup write: no edit may slip between preview
  // and the atomic replacement.
  const atApply = readFileSync(result.botsPath, "utf8");
  if (digest(atApply) !== beforeDigest) {
    throw new Error("bots.json changed while the migration backup was being created");
  }

  const receipt: RetrievalProfileMigrationReceipt = {
    schema: "openmaus.retrieval-profile-migration-receipt.v1",
    ...base,
    applied: true,
    backup_path: backupPath,
    receipt_path: receiptPath,
  };
  try {
    writeFileAtomic(result.botsPath, result.after, { mode: 0o600 });
    const readback = readFileSync(result.botsPath, "utf8");
    if (digest(readback) !== afterDigest) throw new Error("migration readback digest did not match the candidate");
    writeFileAtomic(receiptPath, JSON.stringify(receipt, null, 2), { mode: 0o600 });
    return receipt;
  } catch (error) {
    try {
      if (digest(readFileSync(result.botsPath, "utf8")) === afterDigest) {
        writeFileAtomic(result.botsPath, result.before, { mode: 0o600 });
      }
    } catch (rollbackError) {
      throw new AggregateError([error, rollbackError], "retrieval-profile migration and rollback both failed");
    }
    throw error;
  }
}

function canonicalExistingPath(path: string, label: string): string {
  if (!isAbsolute(path)) throw new Error(`${label} must be an absolute path`);
  try {
    return realpathSync(resolve(path));
  } catch {
    throw new Error(`${label} does not exist`);
  }
}

export function rollbackRetrievalProfileMigration(input: {
  receiptPath: string;
  now?: Date;
}): RetrievalProfileRollbackReceipt {
  const sourceReceiptPath = canonicalExistingPath(input.receiptPath, "migration receipt");
  let parsed;
  try {
    parsed = appliedReceiptSchema.safeParse(parseJson(readFileSync(sourceReceiptPath, "utf8")));
  } catch {
    throw new Error("migration receipt is not valid JSON");
  }
  if (!parsed.success) throw new Error(schemaIssue(parsed.error, "migration receipt is invalid"));
  const source = parsed.data;
  const receiptDirectory = dirname(sourceReceiptPath);
  const dataDir = canonicalExistingPath(source.data_dir, "migration data directory");
  const migrationRoot = canonicalExistingPath(
    join(dataDir, "migrations", "retrieval-profile"),
    "retrieval migration root",
  );
  const botsPath = canonicalExistingPath(source.bots_path, "migration bots path");
  const backupPath = canonicalExistingPath(source.backup_path, "migration backup");
  if (canonicalExistingPath(source.receipt_path, "recorded migration receipt") !== sourceReceiptPath) {
    throw new Error("migration receipt path does not match the canonical source receipt");
  }
  if (botsPath !== canonicalExistingPath(join(dataDir, "bots.json"), "data-directory bots path")) {
    throw new Error("migration receipt points outside its data-directory bots.json");
  }
  if (dirname(receiptDirectory) !== migrationRoot || basename(sourceReceiptPath) !== "receipt.json") {
    throw new Error("migration receipt is outside its data-directory migration root");
  }
  if (backupPath !== canonicalExistingPath(join(receiptDirectory, "bots.json.original"), "receipt-bound backup")) {
    throw new Error("migration backup is not bound to the receipt directory");
  }

  const current = readFileSync(botsPath, "utf8");
  const currentDigest = digest(current);
  if (currentDigest !== source.after_digest) {
    throw new Error(`bots.json drifted after migration: expected ${source.after_digest}, found ${currentDigest}`);
  }
  const original = readFileSync(backupPath, "utf8");
  const originalDigest = digest(original);
  if (originalDigest !== source.before_digest) {
    throw new Error(`migration backup digest mismatch: expected ${source.before_digest}, found ${originalDigest}`);
  }

  writeFileAtomic(botsPath, original, { mode: 0o600 });
  const restoredDigest = digest(readFileSync(botsPath, "utf8"));
  if (restoredDigest !== source.before_digest) {
    throw new Error("retrieval-profile rollback readback did not match the original digest");
  }
  const rollbackReceiptPath = join(receiptDirectory, "rollback-receipt.json");
  const rollback: RetrievalProfileRollbackReceipt = {
    schema: "openmaus.retrieval-profile-rollback-receipt.v1",
    source_receipt_path: sourceReceiptPath,
    bots_path: botsPath,
    backup_path: backupPath,
    before_digest: source.before_digest,
    after_digest: source.after_digest,
    restored_digest: restoredDigest,
    rollback_receipt_path: rollbackReceiptPath,
    rolled_back_at: (input.now ?? new Date()).toISOString(),
  };
  writeFileAtomic(rollbackReceiptPath, JSON.stringify(rollback, null, 2), { mode: 0o600 });
  return rollback;
}
