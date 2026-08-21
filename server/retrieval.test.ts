import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { OpenMausRetriever, PRIOR_TURN_CHUNK_LIMIT, RETRIEVAL_CONTEXT_CHAR_LIMIT, SOURCE_CHUNK_LIMIT } from "./retrieval.ts";

function tmpDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

describe("OpenMausRetriever", () => {
  it("deduplicates and caps committed source plus sanitized prior turns", async () => {
    const dataDir = tmpDir("retrieval-");
    mkdirSync(join(dataDir, "telemetry"), { recursive: true });
    const journal = Array.from({ length: 8 }, (_, index) => JSON.stringify({
      kind: "trace",
      application: "openmausbot",
      sourceSha: "source-sha",
      traceId: `trace-${index}`,
      threadId: `thread-${index}`,
      promptSummary: `OpenMaus gateway request ${index} sk-abcdefghijklmnop`,
      responseSummary: `sanitized answer ${index}`,
    })).join("\n");
    writeFileSync(join(dataDir, "telemetry", "turns.ndjson"), journal + "\n");
    const retriever = new OpenMausRetriever({
      dataDir,
      sourceSha: "source-sha",
      sourceRetrieve: async () => ({ results: Array.from({ length: 10 }, (_, index) => ({
        text: index === 1 ? "same source" : index === 2 ? "same source" : `source chunk ${index}`,
        repository_id: "openmausbot",
        repository_relative_path: `server/file-${index}.ts`,
        source_sha: "source-sha",
      })) }),
    });
    const result = await retriever.retrieve("OpenMaus gateway request");
    expect(result.sourceCount).toBeLessThanOrEqual(SOURCE_CHUNK_LIMIT);
    expect(result.priorTurnCount).toBeLessThanOrEqual(PRIOR_TURN_CHUNK_LIMIT);
    expect(result.charCount).toBeLessThanOrEqual(RETRIEVAL_CONTEXT_CHAR_LIMIT);
    expect(new Set(result.chunks.map((chunk) => chunk.text.toLowerCase())).size).toBe(result.chunks.length);
    expect(JSON.stringify(result)).not.toContain("sk-abcdefghijklmnop");
    expect(result.chunks.some((chunk) => chunk.sourceSha === "source-sha")).toBe(true);
    expect(retriever.format(result)).toContain("<untrusted-retrieval");
  });

  it("returns prior turns when project retrieval is degraded", async () => {
    const dataDir = tmpDir("retrieval-degraded-");
    mkdirSync(join(dataDir, "telemetry"), { recursive: true });
    writeFileSync(join(dataDir, "telemetry", "turns.ndjson"), JSON.stringify({
      kind: "trace",
      application: "openmausbot",
      sourceSha: "abc",
      traceId: "trace-prior",
      threadId: "thread-prior",
      promptSummary: "prior prompt",
      responseSummary: "prior response",
    }) + "\n");
    const retriever = new OpenMausRetriever({
      dataDir,
      sourceSha: "abc",
      sourceRetrieve: async () => { throw new Error("Windows AutoRAG unavailable"); },
    });
    const result = await retriever.retrieve("prior prompt");
    expect(result.degraded).toBe(true);
    expect(result.sourceCount).toBe(0);
    expect(result.priorTurnCount).toBe(1);
  });
});
