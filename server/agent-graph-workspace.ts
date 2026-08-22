import { createHash } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";

const MAX_GITDIR_POINTER_BYTES = 4 * 1024;

interface DirectoryIdentity {
  path: string;
  dev: string;
  ino: string;
}

interface MarkerIdentity {
  kind: "directory" | "file";
  path: string;
  dev: string;
  ino: string;
  contentSha256?: string;
}

function hash(value: unknown): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(value)).digest("hex")}`;
}

function exactDirectoryIdentity(path: string, label: string): DirectoryIdentity {
  const absolute = resolve(path);
  const info = lstatSync(absolute);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error(`${label} must be a real non-symlink directory`);
  }
  // Ancestor aliases such as macOS /var -> /private/var do not make the
  // selected directory itself a symlink. Bind the canonical target path while
  // still rejecting a final-component symlink chosen by the caller.
  return { path: realpathSync(absolute), dev: String(info.dev), ino: String(info.ino) };
}

function readGitdirPointer(marker: string): { marker: MarkerIdentity; target: string } {
  const noFollow = fsConstants.O_NOFOLLOW;
  if (typeof noFollow !== "number" || noFollow === 0) {
    throw new Error("agent graph workspace identity requires O_NOFOLLOW support");
  }
  const fd = openSync(marker, fsConstants.O_RDONLY | noFollow);
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.nlink !== 1 || before.size < 1 || before.size > MAX_GITDIR_POINTER_BYTES) {
      throw new Error("linked-worktree .git marker must be a bounded single-link file");
    }
    const body = readFileSync(fd);
    const after = fstatSync(fd);
    if (
      before.dev !== after.dev || before.ino !== after.ino || before.nlink !== after.nlink ||
      before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs
    ) {
      throw new Error("linked-worktree .git marker changed while its identity was captured");
    }
    const match = body.toString("utf8").trim().match(/^gitdir:\s*(.+)$/i);
    if (!match) throw new Error("linked-worktree .git marker is invalid");
    return {
      marker: {
        kind: "file",
        path: marker,
        dev: String(after.dev),
        ino: String(after.ino),
        contentSha256: hash(body.toString("base64")),
      },
      target: resolve(dirname(marker), match[1]!),
    };
  } finally {
    closeSync(fd);
  }
}

/** Resolve an existing ancestor without treating a missing configured suffix
 * as authority. Callers must still require graphWorkspaceReady before use. */
export function realWorkspaceRoot(path: string): string {
  const absolute = resolve(path);
  let current = absolute;
  const suffix: string[] = [];
  while (true) {
    try {
      return resolve(realpathSync(current), ...suffix);
    } catch {
      const parent = dirname(current);
      if (parent === current) return absolute;
      suffix.unshift(current.slice(parent.length + (parent.endsWith("/") ? 0 : 1)));
      current = parent;
    }
  }
}

/** Bind a route to the exact workspace/repository filesystem objects, not
 * merely to path strings that can be replaced between preview and dispatch. */
export function graphWorkspaceIdentity(workspaceRoot: string): string {
  const root = exactDirectoryIdentity(workspaceRoot, "agent graph workspace root");
  let current = root.path;
  let repository: DirectoryIdentity | null = null;
  let marker: MarkerIdentity | null = null;
  let gitDirectory: DirectoryIdentity | null = null;
  while (true) {
    const markerPath = join(current, ".git");
    try {
      const metadata = lstatSync(markerPath);
      repository = exactDirectoryIdentity(current, "agent graph repository root");
      if (metadata.isSymbolicLink()) throw new Error("repository .git marker cannot be a symlink");
      if (metadata.isDirectory()) {
        gitDirectory = exactDirectoryIdentity(markerPath, "agent graph git directory");
        marker = {
          kind: "directory",
          path: markerPath,
          dev: String(metadata.dev),
          ino: String(metadata.ino),
        };
      } else if (metadata.isFile()) {
        const pointer = readGitdirPointer(markerPath);
        marker = pointer.marker;
        gitDirectory = exactDirectoryIdentity(realpathSync(pointer.target), "agent graph linked git directory");
      } else {
        throw new Error("repository .git marker has an unsupported type");
      }
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      const parent = dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
  return hash({ schema: "openmaus.agent-graph-workspace.v2", root, repository, marker, gitDirectory });
}

export function graphWorkspaceReady(workspaceRoot: string): boolean {
  try {
    graphWorkspaceIdentity(workspaceRoot);
    return true;
  } catch {
    return false;
  }
}

export function graphWorkspaceIdentityMatches(workspaceRoot: string, expected: string): boolean {
  try {
    return graphWorkspaceIdentity(workspaceRoot) === expected;
  } catch {
    return false;
  }
}
