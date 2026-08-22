import { createHash } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import type { AgentGraphRunReceipt } from "./agent-graphs.ts";
import { redactSecretsInText } from "./redact.ts";

export const IMPROVEMENT_OBSERVATION_SCHEMA = "improvement_observation.v1" as const;

export function writeVerifiedAgentGraphObservation(
  receipt: AgentGraphRunReceipt,
  options: { directory?: string } = {},
): string | null {
  if (
    receipt.status !== "completed" || receipt.verification_status !== "verified" ||
    typeof receipt.verified_at !== "string" || !receipt.evidence_manifest_hash ||
    receipt.nodes.some((node) =>
      node.status !== "completed" || node.evidence_status !== "verified" || !node.verified_evidence.length)
  ) return null;
  const directory = options.directory ?? process.env.AOS_IMPROVEMENT_OBSERVATIONS_DIR ??
    join(homedir(), ".local", "state", "self-improve-recs", "observations");
  mkdirSync(directory, { recursive: true });
  const directoryInfo = lstatSync(directory);
  if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) {
    throw new Error("improvement observation directory must be a real directory");
  }
  const receiptHash = `sha256:${createHash("sha256").update(JSON.stringify(receipt)).digest("hex")}`;
  const at = new Date(receipt.verified_at).toISOString();
  if (at !== receipt.verified_at) throw new Error("verified graph receipt timestamp is invalid");
  const identity = createHash("sha256").update(`${receipt.graph_id}:${receiptHash}`).digest("hex").slice(0, 32);
  const dedupeKey = `sha256:${createHash("sha256").update(JSON.stringify({
    graph_hash: receipt.graph_hash,
    proposal_ids: receipt.proposal_ids,
  })).digest("hex")}`;
  // The free-form objective may contain private project context. Observation
  // transport needs identity and proof hashes, not a copy of that prose.
  const rawSummary = `Verified OpenMaus agent graph ${receipt.graph_id} (${receipt.graph_hash})`;
  const sanitizedSummary = redactSecretsInText(rawSummary);
  if (sanitizedSummary !== rawSummary) return null;
  const summary = rawSummary.trim().slice(0, 500);
  if (!summary) return null;
  const observation = {
    schema: IMPROVEMENT_OBSERVATION_SCHEMA,
    observation_id: `observation-${identity}`,
    surface: "openmaus",
    project: "openmausbot",
    category: "verified_agent_graph",
    summary,
    evidence_refs: [...new Set([
      receipt.graph_hash,
      receiptHash,
      receipt.evidence_manifest_hash,
      ...receipt.nodes.flatMap((node) => node.proof_refs),
      ...receipt.nodes.flatMap((node) => node.verified_evidence.map((item) => item.sha256)),
    ])].slice(0, 12),
    dedupe_key: dedupeKey,
    sensitivity: "restricted",
    timestamp: at,
  };
  const path = join(directory, `${observation.observation_id}.json`);
  const serialized = JSON.stringify(observation, null, 2) + "\n";
  if (typeof fsConstants.O_NOFOLLOW !== "number") {
    throw new Error("improvement observations require O_NOFOLLOW support");
  }
  let fd: number | null = null;
  try {
    fd = openSync(
      path,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600,
    );
    writeFileSync(fd, serialized, { encoding: "utf8" });
    fsyncSync(fd);
    return path;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    const info = lstatSync(path);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > 2 * 1024 * 1024) {
      throw new Error("existing improvement observation is not a bounded single-link regular file");
    }
    if (readFileSync(path, "utf8") === serialized) return null;
    throw new Error("deterministic improvement observation identity already contains different content");
  } finally {
    if (fd !== null) closeSync(fd);
  }
}
