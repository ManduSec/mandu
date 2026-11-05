/**
 * fs-bridge — OpenClaw's file tools (read, write, edit, ls, apply_patch…)
 * through Mandu's box (docs/design/agents/openclaw-plugin.md §10.4).
 * Mandu-new (no reference origin).
 *
 * Without a bridge of the backend's own, OpenClaw's default bridge reads a
 * file with the Gateway's own `fs` on the host: a labelled file's real bytes
 * would go to the model (masked only by the model proxy, after the fact),
 * and an `edit` would write a text patched from those real bytes into the
 * box, where it lands in the placeholder copy with the values in it. So the
 * backend brings its own, and every operation runs IN THE BOX, by the box
 * host (box/host.mjs `fs`): a read of a labelled file is its placeholder
 * copy, exactly what `cat` in the box prints; a write of an unprotected file
 * lands on it; Mandu's own folder is not there to read or write.
 *
 * One operation runs outside: a write to a PROTECTED file (the box reads a
 * placeholder copy that differs from the real bytes). The model wrote a text
 * derived from the placeholder copy, so writing it as is would put
 * placeholders over the user's values, and writing it into the copy alone
 * would lose the change. The bridge writes the real file instead, with the
 * file's own values put back line by line (write-back.ts; refused when a
 * value would move into a line of the model's making), atomically and only
 * inside a writable mount, then writes the model's text into the copy, so
 * the box keeps reading what the model wrote. The values never leave their
 * file, and nothing of them reaches the model.
 *
 * Paths: `workspaceAccess: "rw"` (what `mandu openclaw install --sandbox`
 * writes) keeps every path what it is on the host, so a container path IS a
 * host path. The mounts are OpenClaw's own (the workspace, the agent's
 * workspace, the skills and resources read-only); a path outside them is
 * refused, as OpenClaw's own bridges refuse it.
 */
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync, renameSync, unlinkSync, writeSync, fsyncSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { basename, dirname, join, posix, resolve } from "node:path";

import { isInside } from "../../box/policy.mjs";
import { BoxError, type BoxClient } from "./box-client.js";
import { planWriteBack, WRITE_BACK_MAX } from "./write-back.js";

/** The sandbox context OpenClaw hands `createFsBridge` (subset, 2026.7 to 2026.10). */
export interface BridgeSandboxContext {
  workspaceDir: string;
  agentWorkspaceDir: string;
  skillsWorkspaceDir?: string;
  workspaceAccess: "none" | "ro" | "rw";
  readOnlyResourceMounts?: Array<{ hostPath: string; containerPath: string }>;
}

export interface BridgeMount {
  hostRoot: string;
  containerRoot: string;
  writable: boolean;
  source: "workspace" | "agent" | "resource";
}

export interface ResolvedTarget {
  hostPath: string;
  containerPath: string;
  relativePath: string;
  mount: BridgeMount;
}

/** The host side of a protected write (injectable for tests). */
export interface HostFs {
  /** The real bytes of `path`, read without following a final symlink; at most `max` bytes. */
  readReal(path: string, max: number): Buffer;
  /** Replace `path` (a regular file with one link) atomically with `bytes`, keeping its mode. */
  replaceReal(path: string, bytes: Buffer): void;
  /** The host's canonical spelling of `p` (realpath). */
  realpath(p: string): string;
}

export interface BridgeDeps {
  host?: HostFs;
  log?: (level: "info" | "warn" | "error", msg: string) => void;
}

/** OpenClaw's mounts for a sandbox context (the remote-shell bridge's rule). Pure. */
export function bridgeMounts(ctx: BridgeSandboxContext): BridgeMount[] {
  const ws = resolve(ctx.workspaceDir);
  const agent = resolve(ctx.agentWorkspaceDir);
  const mounts: BridgeMount[] = [{ hostRoot: ws, containerRoot: ws, writable: ctx.workspaceAccess !== "ro", source: "workspace" }];
  if (ctx.workspaceAccess !== "none" && agent !== ws) {
    mounts.push({ hostRoot: agent, containerRoot: agent, writable: ctx.workspaceAccess === "rw", source: "agent" });
  }
  if (ctx.skillsWorkspaceDir) {
    const s = resolve(ctx.skillsWorkspaceDir);
    if (s !== ws && s !== agent) mounts.push({ hostRoot: s, containerRoot: s, writable: false, source: "resource" });
  }
  for (const r of ctx.readOnlyResourceMounts ?? []) {
    mounts.push({ hostRoot: resolve(r.hostPath), containerRoot: posix.normalize(r.containerPath), writable: false, source: "resource" });
  }
  return mounts;
}

/** Resolve a tool's path against the mounts (the longest container root wins). Pure. */
export function resolveBridgePath(mounts: readonly BridgeMount[], filePath: string, cwd: string | undefined, workspaceDir: string): ResolvedTarget {
  const input = filePath.trim();
  if (input === "") throw new Error("Sandbox path is empty");
  const from = cwd && cwd.startsWith("/") ? cwd : resolve(workspaceDir);
  const containerPath = posix.normalize(input.startsWith("/") ? input : posix.join(from, input));
  const sorted = [...mounts].sort((a, b) => b.containerRoot.length - a.containerRoot.length);
  const mount = sorted.find((m) => isInside(m.containerRoot, containerPath));
  if (!mount) throw Object.assign(new Error(`Sandbox path escapes allowed mounts; cannot access: ${filePath}`), { code: "EACCES" });
  const rel = posix.relative(mount.containerRoot, containerPath);
  const hostPath = rel === "" ? mount.hostRoot : join(mount.hostRoot, ...rel.split("/"));
  return { hostPath, containerPath, relativePath: rel, mount };
}

export const realHostFs: HostFs = {
  readReal(path, max) {
    const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const st = fstatSync(fd);
      if (!st.isFile()) throw Object.assign(new Error(`${path} is not a regular file`), { code: "EISDIR" });
      if (st.size > max) throw Object.assign(new Error(`${path} is over ${max} bytes`), { code: "EFBIG" });
      const buf = Buffer.alloc(st.size);
      let off = 0;
      while (off < buf.length) {
        const n = readSync(fd, buf, off, buf.length - off, off);
        if (n === 0) break;
        off += n;
      }
      return buf.subarray(0, off);
    } finally {
      closeSync(fd);
    }
  },
  replaceReal(path, bytes) {
    const st = lstatSync(path);
    if (!st.isFile()) throw Object.assign(new Error(`${path} is not a regular file`), { code: "EISDIR" });
    if (st.nlink !== 1) throw Object.assign(new Error(`${path} has other hard links`), { code: "EMLINK" });
    const tmp = join(dirname(path), `.${basename(path)}.mandu-${randomBytes(6).toString("hex")}`);
    const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, st.mode & 0o7777);
    try {
      let off = 0;
      while (off < bytes.length) off += writeSync(fd, bytes, off, bytes.length - off);
      fsyncSync(fd);
    } catch (e) {
      closeSync(fd);
      try { unlinkSync(tmp); } catch { /* gone */ }
      throw e;
    }
    closeSync(fd);
    try {
      renameSync(tmp, path);
    } catch (e) {
      try { unlinkSync(tmp); } catch { /* gone */ }
      throw e;
    }
  },
  realpath: (p) => realpathSync(p),
};

function errCode(e: unknown): string | undefined {
  return (e as { code?: string } | null)?.code;
}

/** The bridge. Its methods are OpenClaw's SandboxFsBridge (2026.7 to 2026.10). */
export class ManduFsBridge {
  readonly mounts: BridgeMount[];
  private readonly host: HostFs;
  private readonly log: NonNullable<BridgeDeps["log"]>;

  constructor(private readonly ctx: BridgeSandboxContext, private readonly box: () => Promise<BoxClient>, deps: BridgeDeps = {}) {
    this.mounts = bridgeMounts(ctx);
    this.host = deps.host ?? realHostFs;
    this.log = deps.log ?? (() => {});
  }

  get pathMappings(): Array<{ hostRoot: string; containerRoot: string }> {
    return this.mounts.map((m) => ({ hostRoot: m.hostRoot, containerRoot: m.containerRoot }));
  }

  private target(p: { filePath: string; cwd?: string }): ResolvedTarget {
    return resolveBridgePath(this.mounts, p.filePath, p.cwd, this.ctx.workspaceDir);
  }

  private writable(t: ResolvedTarget, action: string): void {
    if (!t.mount.writable) throw Object.assign(new Error(`Sandbox path is read-only; cannot ${action}: ${t.containerPath}`), { code: "EROFS" });
  }

  private async op(fsOp: string, t: ResolvedTarget, extra: Record<string, unknown> = {}, opts: { data?: Buffer; signal?: AbortSignal } = {}) {
    const client = await this.box();
    return client.fs({ fsOp, path: t.hostPath, root: t.mount.hostRoot, ...extra }, opts);
  }

  resolvePath(p: { filePath: string; cwd?: string }): { hostPath: string; relativePath: string; containerPath: string } {
    const t = this.target(p);
    return { hostPath: t.hostPath, relativePath: t.relativePath, containerPath: t.containerPath };
  }

  async resolveReadPolicyPath(p: { filePath: string; cwd?: string; signal?: AbortSignal }): Promise<string> {
    const t = this.target(p);
    const r = await this.op("realpath", t, {}, { signal: p.signal });
    return String(r.answer["path"]);
  }

  async resolvePinnedMutationTarget(p: { filePath: string; cwd?: string; action: string; signal?: AbortSignal }): Promise<{ policyPath: string; pinnedPath: string }> {
    const t = this.target(p);
    if (p.action === "mkdir") {
      const r = await this.op("realpath", t, {}, { signal: p.signal });
      const path = String(r.answer["path"]);
      return { policyPath: path, pinnedPath: path };
    }
    const parent = { ...t, hostPath: dirname(t.hostPath) };
    const r = await this.op("realpath", parent, {}, { signal: p.signal });
    const path = join(String(r.answer["path"]), basename(t.hostPath));
    return { policyPath: path, pinnedPath: path };
  }

  async readFile(p: { filePath: string; cwd?: string; signal?: AbortSignal; maxBytes?: number }): Promise<Buffer> {
    return (await this.readFileWithSource(p)).data;
  }

  async readFileWithSource(p: { filePath: string; cwd?: string; signal?: AbortSignal; maxBytes?: number }): Promise<{ data: Buffer; canonicalPath: string; workspaceRelativePath?: string }> {
    const t = this.target(p);
    const r = await this.op("read", t, p.maxBytes !== undefined ? { maxBytes: p.maxBytes } : {}, { signal: p.signal });
    const canonicalPath = String(r.answer["path"]);
    return {
      data: r.data,
      canonicalPath,
      ...(t.mount.source === "workspace" ? { workspaceRelativePath: posix.relative(t.mount.containerRoot, canonicalPath) } : {}),
    };
  }

  async readDirectory(p: { filePath: string; cwd?: string; signal?: AbortSignal }): Promise<Array<{ name: string; isDirectory: boolean; isFile?: boolean; size?: number; mtimeMs?: number }>> {
    const t = this.target(p);
    const r = await this.op("readdir", t, {}, { signal: p.signal });
    return (r.answer["entries"] as Array<{ name: string; isDirectory: boolean; isFile?: boolean; size?: number; mtimeMs?: number }>) ?? [];
  }

  async stat(p: { filePath: string; cwd?: string; signal?: AbortSignal }): Promise<{ type: "file" | "directory" | "other"; size: number; mtimeMs: number } | null> {
    const t = this.target(p);
    const r = await this.op("stat", t, {}, { signal: p.signal });
    const st = r.answer["stat"] as { type: "file" | "directory" | "other"; size: number; mtimeMs: number } | null;
    return st ? { type: st.type, size: st.size, mtimeMs: st.mtimeMs } : null;
  }

  async mkdirp(p: { filePath: string; cwd?: string; signal?: AbortSignal }): Promise<void> {
    const t = this.target(p);
    this.writable(t, "create directories");
    await this.op("mkdirp", t, {}, { signal: p.signal });
  }

  async remove(p: { filePath: string; cwd?: string; recursive?: boolean; force?: boolean; signal?: AbortSignal }): Promise<void> {
    const t = this.target(p);
    this.writable(t, "remove files");
    await this.op("remove", t, { recursive: p.recursive === true, force: p.force !== false }, { signal: p.signal });
  }

  async rename(p: { from: string; to: string; cwd?: string; signal?: AbortSignal }): Promise<void> {
    const from = this.target({ filePath: p.from, cwd: p.cwd });
    const to = this.target({ filePath: p.to, cwd: p.cwd });
    this.writable(from, "rename files");
    this.writable(to, "rename files");
    await this.op("rename", from, { to: to.hostPath, toRoot: to.mount.hostRoot }, { signal: p.signal });
  }

  async copyFile(p: { sourcePath: string; destinationPath: string; cwd?: string; mkdir?: boolean; signal?: AbortSignal }): Promise<void> {
    const from = this.target({ filePath: p.sourcePath, cwd: p.cwd });
    const to = this.target({ filePath: p.destinationPath, cwd: p.cwd });
    this.writable(to, "copy files");
    await this.op("copy", from, { to: to.hostPath, toRoot: to.mount.hostRoot, mkdir: p.mkdir !== false }, { signal: p.signal });
  }

  async createFileExclusive(p: { filePath: string; cwd?: string; data: Buffer | string; encoding?: BufferEncoding; mkdir?: boolean; signal?: AbortSignal }): Promise<"created" | "exists"> {
    const t = this.target(p);
    this.writable(t, "create files");
    const data = Buffer.isBuffer(p.data) ? p.data : Buffer.from(p.data, p.encoding ?? "utf8");
    const r = await this.op("write", t, { exclusive: true, mkdir: p.mkdir !== false }, { data, signal: p.signal });
    return r.answer["created"] === true ? "created" : "exists";
  }

  async writeFile(p: { filePath: string; cwd?: string; data: Buffer | string; encoding?: BufferEncoding; mkdir?: boolean; signal?: AbortSignal }): Promise<void> {
    const t = this.target(p);
    this.writable(t, "write files");
    const data = Buffer.isBuffer(p.data) ? p.data : Buffer.from(p.data, p.encoding ?? "utf8");
    const inBox = (): Promise<unknown> => this.op("write", t, { mkdir: p.mkdir !== false }, { data, signal: p.signal });

    // What the box reads there now (a placeholder copy for a protected file).
    let twin: Buffer;
    let canonical: string;
    try {
      const r = await this.op("read", t, { maxBytes: WRITE_BACK_MAX + 1 }, { signal: p.signal });
      twin = r.data;
      canonical = String(r.answer["path"]);
    } catch (e) {
      if (errCode(e) === "ENOENT") { await inBox(); return; }
      if (errCode(e) === "EFBIG") { await inBox(); return; }
      throw e;
    }
    // And what the file really holds, read on the host.
    // The canonical path came from the box; on the host it must still be
    // inside the writable mount with no folder above it swapped for a link
    // since (checked again right before the write).
    const hostChecks = (): void => {
      if (!isInside(this.host.realpath(t.mount.hostRoot), canonical)) throw Object.assign(new Error(`${canonical} is outside ${t.mount.hostRoot}`), { code: "EACCES" });
      if (this.host.realpath(dirname(canonical)) !== dirname(canonical)) throw Object.assign(new Error(`a folder above ${canonical} changed`), { code: "ELOOP" });
    };
    let real: Buffer;
    try {
      hostChecks();
      real = this.host.readReal(canonical, WRITE_BACK_MAX + 1);
    } catch (e) {
      throw new BoxError(`Mandu kept ${p.filePath} as it was: it could not compare the file with its protected form (${(e as Error).message})`, errCode(e));
    }
    const plan = planWriteBack(twin, real, data);
    if (plan.kind === "plain") { await inBox(); return; }
    if (plan.kind === "unchanged") return;
    if (plan.kind === "refuse") {
      throw new BoxError(
        `Mandu kept ${p.filePath} as it was: the file holds protected values, and ${plan.reason}. ` +
          "Edit the lines without placeholders, or ask the person to change the protected values themselves.",
        "EPERM",
      );
    }
    try {
      hostChecks();
      this.host.replaceReal(canonical, plan.bytes);
    } catch (e) {
      throw new BoxError(`Mandu kept ${p.filePath} as it was: the write to the real file failed (${(e as Error).message})`, errCode(e));
    }
    this.log("info", `[mandu-inspect] wrote ${canonical} with its ${plan.restoredLines} protected line(s) put back`);
    try {
      await inBox();
    } catch (e) {
      this.log("warn", `[mandu-inspect] ${canonical} was written, but its placeholder copy in the box was not updated (${(e as Error).message})`);
    }
  }
}
