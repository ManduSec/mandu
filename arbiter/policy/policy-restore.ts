/**
 * policy-restore — policy.yaml always holds the law in force
 * (sandbox-security-review-2026-09-28 finding 2's residual; decision
 * 2026-09-28: DENY RESTORES THE FILE). Mandu-new.
 *
 * A disk edit that relaxes the law is held for a human (policy-document-
 * store.ts, policy-surface.md §8.4.6). Before this module, a DENIED edit
 * stayed in the file, and the next arbiter start loaded the file as the law:
 * the human's "no" lasted only until a restart. Now:
 *
 *   - on deny, the arbiter writes the content in force back to policy.yaml
 *     (atomic: a temp file in the same directory, the file's mode kept, then
 *     a rename), so the file matches what is enforced. The Inbox row keeps
 *     the declined text (`diskText`), so the hand edit can be recovered;
 *   - it restores only while the file still holds the declined bytes: a newer
 *     edit that landed meanwhile is judged as a fresh edit, never clobbered;
 *   - the arbiter persists the content in force (per policy file path, in
 *     mandu.db); at start, a file that differs from it and that a DENIED row
 *     names is restored before it is loaded, and one a PENDING row names stays
 *     held (the persisted content is the law until the human decides).
 *
 * A file that differs from the persisted content and that no row names (an
 * edit made while the arbiter was down) is still the law at start, as before.
 *
 * `decideDenyRestore` and `decideStartupLaw` are pure; `atomicReplace` and
 * `reconcilePolicyFileAtStart` do the I/O.
 */
import { closeSync, fchmodSync, fstatSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { createHash } from "node:crypto";

/** The content hash that stands for "no file" (policy-document-store.ts). */
const ABSENT = "absent";

/** The law in force as the file held it: its sha256 (or `absent`) and its
 *  text (null: the law is the built-ins, no file). */
export interface EnforcedPolicy {
  hash: string;
  text: string | null;
}

export type DenyRestoreDecision =
  | { restore: true }
  | {
    restore: false;
    /** `moved-on`: the file no longer holds the declined bytes (a newer edit
     *  is judged as a fresh one); `matches-law`: the declined bytes are the
     *  law in force (nothing to restore); `no-law`: the law did not come from
     *  a file this arbiter read, so there is nothing to write back. */
    why: "moved-on" | "matches-law" | "no-law";
  };

/** A human declined the held change `deniedHash`: write the law back? Pure. */
export function decideDenyRestore(p: { diskHash: string | null; deniedHash: string; inForceHash: string | null }): DenyRestoreDecision {
  if (p.inForceHash === null) return { restore: false, why: "no-law" };
  if (p.inForceHash === p.deniedHash) return { restore: false, why: "matches-law" };
  if (p.diskHash !== p.deniedHash) return { restore: false, why: "moved-on" };
  return { restore: true };
}

export type StartupLawDecision =
  | { law: "file" }
  | {
    /** The persisted content is the law, not the file. */
    law: "enforced";
    /** Write it back to the file (a DENIED row names the file's bytes). */
    restoreFile: boolean;
    proposalId: string;
    status: "denied" | "pending";
  };

/** What becomes the law at arbiter start. Pure. A denied row wins over a
 *  pending one naming the same bytes. */
export function decideStartupLaw(p: {
  diskHash: string;
  enforced: EnforcedPolicy | null;
  diskRows: ReadonlyArray<{ id: string; status: string; diskHash: string | null }>;
}): StartupLawDecision {
  if (p.enforced === null || p.enforced.hash === p.diskHash) return { law: "file" };
  const rows = p.diskRows.filter((r) => r.diskHash === p.diskHash);
  const denied = rows.find((r) => r.status === "denied");
  if (denied) return { law: "enforced", restoreFile: true, proposalId: denied.id, status: "denied" };
  const pending = rows.find((r) => r.status === "pending");
  if (pending) return { law: "enforced", restoreFile: false, proposalId: pending.id, status: "pending" };
  return { law: "file" };
}

export function hashText(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** The file's bytes now: its hash (`absent` when there is none) and text. */
export function readPolicyBytes(path: string): { hash: string; text: string | null } {
  try {
    const text = readFileSync(path, "utf8");
    return { hash: hashText(text), text };
  } catch {
    return { hash: ABSENT, text: null };
  }
}

export interface ReplaceResult {
  /** The file was replaced (or removed, for `text: null`). */
  replaced: boolean;
  /** The file's stat identity right after (null: no file). */
  identity: { mtimeMs: number; size: number; ino: number } | null;
}

/**
 * Replace `path` with `text` (null: remove it), but only while it still
 * holds the bytes `expectHash`: temp file in the same directory, the old
 * file's permission bits kept (0644 for a file that was absent), the hash
 * checked again right before the rename. The window between that check and
 * the rename is a few system calls; an edit that lands inside it is lost to
 * the restore, and its bytes are what the declined row keeps only if they
 * were the declined ones (docs/design/architecture/write-protection.md §6).
 */
export function atomicReplace(path: string, text: string | null, expectHash: string): ReplaceResult {
  if (readPolicyBytes(path).hash !== expectHash) return { replaced: false, identity: null };
  if (text === null) {
    unlinkSync(path);
    return { replaced: true, identity: null };
  }
  let mode = 0o644;
  try {
    mode = statSync(path).mode & 0o7777;
  } catch { /* absent: a removal was declined; the file comes back */ }
  const tmp = join(dirname(path), `.${basename(path)}.${process.pid}.restore.tmp`);
  const fd = openSync(tmp, "w", mode);
  let identity: ReplaceResult["identity"];
  try {
    writeSync(fd, text, null, "utf8");
    fchmodSync(fd, mode);
    const st = fstatSync(fd);
    identity = { mtimeMs: st.mtimeMs, size: st.size, ino: st.ino };
  } finally {
    closeSync(fd);
  }
  if (readPolicyBytes(path).hash !== expectHash) {
    try { unlinkSync(tmp); } catch { /* ignore */ }
    return { replaced: false, identity: null };
  }
  renameSync(tmp, path);
  return { replaced: true, identity };
}

export interface StartupReconcile {
  decision: StartupLawDecision;
  /** The law in force, when it is NOT the file (`law: "enforced"`); the
   *  caller compiles this document instead of reading the file. */
  inForce: EnforcedPolicy | null;
  /** The file was written back to the law in force. */
  restored: boolean;
  /** Hashes of declined disk contents: seen again, they are restored, with
   *  no new Inbox card. */
  declined: string[];
  /** One line for the log (null: nothing to say). */
  note: string | null;
}

/**
 * At arbiter start (before the law is loaded): decide, and for a DENIED row
 * write the persisted content back to the file. A failed restore still keeps
 * the declined content out of force (`inForce` is set; the store keeps
 * trying on every poll).
 */
export function reconcilePolicyFileAtStart(p: {
  path: string;
  enforced: EnforcedPolicy | null;
  diskRows: ReadonlyArray<{ id: string; status: string; diskHash: string | null }>;
}): StartupReconcile {
  const disk = readPolicyBytes(p.path);
  const declined = [...new Set(p.diskRows.filter((r) => r.status === "denied" && r.diskHash !== null).map((r) => r.diskHash as string))];
  const decision = decideStartupLaw({ diskHash: disk.hash, enforced: p.enforced, diskRows: p.diskRows });
  if (decision.law === "file") return { decision, inForce: null, restored: false, declined, note: null };
  const enforced = p.enforced as EnforcedPolicy;
  if (decision.restoreFile) {
    try {
      if (atomicReplace(p.path, enforced.text, disk.hash).replaced) {
        return {
          decision, inForce: null, restored: true, declined,
          note: `policy.yaml held the change ${decision.proposalId} that a human declined; it was restored to the law in force before loading (the declined text stays on its card in Approvals)`,
        };
      }
    } catch (err) {
      return {
        decision, inForce: enforced, restored: false, declined,
        note: `WARNING: policy.yaml holds the change ${decision.proposalId} that a human declined, and writing the law in force back failed (${(err as Error).message}); the declined change is NOT loaded, the last approved content is the law`,
      };
    }
    // The file changed between the read and the write: load what is there now
    // as the law would have been loaded before (it is not the declined bytes).
    return { decision: { law: "file" }, inForce: null, restored: false, declined, note: null };
  }
  return {
    decision, inForce: enforced, restored: false, declined,
    note: `policy.yaml holds the change ${decision.proposalId} that still waits for a human; it stays held and the last approved content is the law`,
  };
}
