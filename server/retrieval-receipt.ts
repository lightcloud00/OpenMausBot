import { createHash } from "node:crypto";
import { chmodSync, mkdirSync } from "node:fs";
import { join } from "node:path";

import { writeFileAtomic } from "./atomic.ts";
import type { OpenMausRetrievalReceipt } from "./retrieval.ts";

export interface StoredRetrievalReceipt {
  schema: "openmaus.retrieval-receipt-record.v1";
  recorded_at: string;
  receipt: OpenMausRetrievalReceipt;
}

function identityDigest(receipt: OpenMausRetrievalReceipt): string {
  const proof = receipt.native_session_proof;
  return createHash("sha256")
    .update(proof.botId)
    .update("\0")
    .update(proof.threadId)
    .update("\0")
    .update(proof.taskId)
    .digest("hex");
}

export function retrievalReceiptPath(dataDir: string, receipt: OpenMausRetrievalReceipt): string {
  return join(dataDir, "retrieval-receipts", `${identityDigest(receipt)}.json`);
}

/** Persist only bounded receipt metadata. Retrieval queries and excerpts are
 * deliberately absent, and an unavailable receipt sink must never block a
 * model turn. */
export function recordRetrievalReceipt(
  dataDir: string,
  receipt: OpenMausRetrievalReceipt,
  now: Date = new Date(),
): string | null {
  try {
    const directory = join(dataDir, "retrieval-receipts");
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    chmodSync(directory, 0o700);
    const path = retrievalReceiptPath(dataDir, receipt);
    const record: StoredRetrievalReceipt = {
      schema: "openmaus.retrieval-receipt-record.v1",
      recorded_at: now.toISOString(),
      receipt: {
        schema: receipt.schema,
        automatic_retrieval_active: receipt.automatic_retrieval_active,
        windows_served: receipt.windows_served,
        generation_identity: receipt.generation_identity,
        fallback_path: receipt.fallback_path,
        skip_reason: receipt.skip_reason,
        accepted_hits: receipt.accepted_hits,
        native_session_proof: { ...receipt.native_session_proof },
      },
    };
    writeFileAtomic(path, JSON.stringify(record, null, 2), { mode: 0o600 });
    return path;
  } catch {
    return null;
  }
}
