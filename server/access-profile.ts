import { createHash } from "node:crypto";

export const ACCESS_PROFILES = ["standard", "full-task-scoped"] as const;
export type AccessProfile = (typeof ACCESS_PROFILES)[number];

export const FULL_TASK_SCOPED_HARD_DENIES = [
  "catastrophic-destruction",
  "credential-value-disclosure",
] as const;

export type FullTaskScopedHardDeny = (typeof FULL_TASK_SCOPED_HARD_DENIES)[number];
export type TelemetryCaptureMode = "off" | "metadata" | "sanitized-content";

export interface CapabilityProfileManifest {
  schema: "openmaus.capability-profile.v1";
  profile: "full-task-scoped";
  taskScoped: true;
  hardDenies: FullTaskScopedHardDeny[];
  toolInventory: string[];
  telemetryMode: TelemetryCaptureMode;
  sha256: string;
}

export function isAccessProfile(value: unknown): value is AccessProfile {
  return typeof value === "string" && (ACCESS_PROFILES as readonly string[]).includes(value);
}

export function normalizeAccessProfile(value: unknown): AccessProfile {
  return isAccessProfile(value) ? value : "standard";
}

export function isFullTaskScoped(value: unknown): value is "full-task-scoped" {
  return value === "full-task-scoped";
}

function stableManifestPayload(input: {
  toolInventory: string[];
  telemetryMode: TelemetryCaptureMode;
}) {
  return {
    schema: "openmaus.capability-profile.v1" as const,
    profile: "full-task-scoped" as const,
    taskScoped: true as const,
    hardDenies: [...FULL_TASK_SCOPED_HARD_DENIES],
    toolInventory: [...new Set(input.toolInventory)].sort(),
    telemetryMode: input.telemetryMode,
  };
}

export function createCapabilityProfileManifest(input: {
  toolInventory?: string[];
  telemetryMode?: TelemetryCaptureMode;
} = {}): CapabilityProfileManifest {
  const payload = stableManifestPayload({
    toolInventory: input.toolInventory ?? [],
    telemetryMode: input.telemetryMode ?? "sanitized-content",
  });
  const sha256 = createHash("sha256").update(JSON.stringify(payload)).digest("hex");
  return { ...payload, sha256 };
}

export const FULL_TASK_SCOPED_SYSTEM_PROMPT =
  "Operate autonomously on the user's current task. You may use the host filesystem, shell, local computer, browser, MCP tools, Git, deployment, messaging, and external-write capabilities when the task calls for them. Enumerate and invoke app and host integrations through the openmaus_capabilities gateway. Ask only when the user's intent is materially ambiguous. Two actions are unavailable: catastrophic destruction of a machine, volume, broad filesystem root, repository, account, project, organization, or production datastore; and reading, returning, logging, or exporting raw credential values. Credential aliases and host-side credential use are available without exposing their values.";
