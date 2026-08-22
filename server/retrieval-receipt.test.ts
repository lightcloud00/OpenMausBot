import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { describe, expect, it } from "vitest";

import type { OpenMausRetrievalReceipt } from "./retrieval.ts";
import { recordRetrievalReceipt, retrievalReceiptPath } from "./retrieval-receipt.ts";

const receipt = (botId: string, threadId: string, taskId: string): OpenMausRetrievalReceipt => ({
  schema: "openmaus.retrieval-receipt.v1",
  automatic_retrieval_active: true,
  windows_served: false,
  generation_identity: null,
  fallback_path: "fts5-current-source",
  skip_reason: null,
  accepted_hits: 1,
  native_session_proof: { botId, threadId, taskId },
});

describe("retrieval receipt persistence", () => {
  it("atomically records metadata-only direct and group receipts under hash-safe identities", () => {
    const dataDir = mkdtempSync(join(tmpdir(), "openmaus-retrieval-receipts-"));
    const direct = receipt("bot-ada", "thread-ada", "task-ada");
    const group = receipt("bot-ada", "group-thread", "group-thread");
    const directPath = recordRetrievalReceipt(dataDir, direct, new Date("2026-08-22T07:00:00Z"));
    const groupPath = recordRetrievalReceipt(dataDir, group, new Date("2026-08-22T07:01:00Z"));

    expect(directPath).toBe(retrievalReceiptPath(dataDir, direct));
    expect(groupPath).toBe(retrievalReceiptPath(dataDir, group));
    expect(directPath).not.toBe(groupPath);
    expect(basename(directPath!)).toMatch(/^[a-f0-9]{64}\.json$/);
    const readback = JSON.parse(readFileSync(directPath!, "utf8"));
    expect(readback).toMatchObject({
      schema: "openmaus.retrieval-receipt-record.v1",
      recorded_at: "2026-08-22T07:00:00.000Z",
      receipt: direct,
    });
    expect(JSON.stringify(readback)).not.toMatch(/query|snippet|context/i);
    expect(statSync(directPath!).mode & 0o777).toBe(0o600);
    expect(statSync(join(dataDir, "retrieval-receipts")).mode & 0o777).toBe(0o700);
  });

  it("fails open when the receipt directory cannot be created", () => {
    const dataDir = join(mkdtempSync(join(tmpdir(), "openmaus-retrieval-receipts-")), "not-a-directory");
    writeFileSync(dataDir, "occupied");
    expect(recordRetrievalReceipt(dataDir, receipt("bot", "thread", "task"))).toBeNull();
  });
});
