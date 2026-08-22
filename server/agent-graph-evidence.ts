import { createHash } from "node:crypto";
import { constants as fsConstants, type Stats } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";

export const AGENT_GRAPH_MAX_FILE_BYTES = 1024 * 1024;

export interface StableAgentGraphFileRead {
  absolutePath: string;
  relativePath: string;
  body: Buffer;
  sha256: string;
  info: Stats;
}

function noFollowFlag(): number {
  const flag = fsConstants.O_NOFOLLOW;
  if (typeof flag !== "number" || flag === 0) {
    throw new Error("agent graph filesystem access requires O_NOFOLLOW support");
  }
  return flag;
}

function stableFile(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.nlink === 1 && right.nlink === 1 &&
    left.size === right.size && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

function stableWorkspace(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.isDirectory() && right.isDirectory() &&
    !left.isSymbolicLink() && !right.isSymbolicLink();
}

/**
 * Read one exact file through the same fail-closed boundary used by graph
 * capability turns. Parent and final symlinks, hard links, oversized files,
 * workspace replacement, and in-read owner drift are rejected.
 */
export async function readStableAgentGraphFile(
  workspaceRoot: string,
  rawPath: string,
  maximumBytes = AGENT_GRAPH_MAX_FILE_BYTES,
  hooks: { afterPathValidation?: () => void | Promise<void> } = {},
): Promise<StableAgentGraphFileRead> {
  if (
    typeof workspaceRoot !== "string" || !workspaceRoot.trim() ||
    typeof rawPath !== "string" || !rawPath.trim() || rawPath.includes("\0") ||
    /^~(?:[\\/]|$)/.test(rawPath.trim()) || !Number.isSafeInteger(maximumBytes) || maximumBytes < 1
  ) throw new Error("agent graph evidence path is invalid");

  const root = resolve(workspaceRoot);
  const supplied = rawPath.trim();
  const candidate = isAbsolute(supplied) ? resolve(supplied) : resolve(root, supplied);
  const relativePath = relative(root, candidate);
  if (!relativePath || relativePath === ".." || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) {
    throw new Error("agent graph evidence path is outside the approved workspace");
  }

  const rootBefore = await lstat(root);
  if (!rootBefore.isDirectory() || rootBefore.isSymbolicLink() || await realpath(root) !== root) {
    throw new Error("agent graph workspace root must be a real non-symlink directory");
  }

  let current = root;
  const components = relativePath.split(sep);
  for (const [index, component] of components.entries()) {
    current = resolve(current, component);
    const info = await lstat(current);
    if (info.isSymbolicLink()) throw new Error("agent graph evidence paths cannot traverse symlinks");
    if (index < components.length - 1 && !info.isDirectory()) {
      throw new Error("agent graph evidence path has a non-directory parent");
    }
  }

  // Component checks alone are not enough: a writable parent can be renamed
  // and replaced with a symlink between the final lstat above and open().
  // Bind the canonical target on both sides of the descriptor read. The
  // descriptor/path inode comparison below then rejects a parent restored to
  // a different in-workspace file after an outside target was opened.
  if (await realpath(candidate) !== candidate) {
    throw new Error("agent graph evidence paths cannot traverse symlinks");
  }
  await hooks.afterPathValidation?.();

  const handle = await open(candidate, fsConstants.O_RDONLY | noFollowFlag());
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1) {
      throw new Error("agent graph evidence requires a regular single-link file");
    }
    if (before.size > maximumBytes) throw new Error("agent graph evidence exceeds the bounded file size");
    const body = await handle.readFile();
    const after = await handle.stat();
    const canonicalAfter = await realpath(candidate);
    const pathAfter = await lstat(candidate);
    const rootAfter = await lstat(root);
    if (
      !stableFile(before, after) || !stableFile(after, pathAfter) ||
      canonicalAfter !== candidate ||
      !stableWorkspace(rootBefore, rootAfter) || await realpath(root) !== root ||
      body.byteLength !== after.size
    ) throw new Error("agent graph evidence changed while it was being read");
    return {
      absolutePath: candidate,
      relativePath: relativePath.split(sep).join("/"),
      body,
      sha256: `sha256:${createHash("sha256").update(body).digest("hex")}`,
      info: after,
    };
  } finally {
    await handle.close();
  }
}
