/**
 * policy-document-store — the arbiter as the single writer of `policy.yaml`
 * (docs/design/ui/policy-surface.md §2.1, stage 5a).
 *
 * The document is the operator's law on disk. Three things may change it:
 *   1. the dashboard, over the ADMIN channel (`applyPolicyDocument`,
 *      `mintUserRule`, `exportDbLabels`, `movePageLabels`), and the arbiter's
 *      own reader pins — validated here, written atomically (tmp + rename),
 *      then compiled and swapped in via the server's rebuild callback, then
 *      audited (`policy_change` on the arbiter-admin stream). These go
 *      through `apply`, the same guarded path as (3): a hand edit that
 *      landed inside the poll window is loaded first and the write refused
 *      as stale, and while a relaxing hand edit is held the change is made
 *      to it as well, item by item (`layerItems`), never written over it.
 *      The whole document of `applyPolicyDocument` (`applyDocument`) names
 *      the law it was built from ({@link lawHashOf}) and is refused as
 *      stale once the law in force is another one;
 *   2. a hand edit — picked up by an mtime poll (2 s, unref'd) and JUDGED
 *      before it is applied (policy-surface.md §8.4.6): a change that
 *      only tightens, or changes nothing the law means (comments, layout),
 *      goes through the SAME validate → rebuild path; a change with ANY
 *      relaxation (by `policyDelta`, fail closed) is HELD: the law in force
 *      stays, and the change waits as a proposal a human approves in the
 *      Inbox. The file is writable from the agent's process tree on a host
 *      where the agent is not confined, so a write to it is not a human's
 *      word. Approving loads exactly the content that was held (checked by
 *      its hash); a file that moved on since is judged afresh. DECLINING
 *      writes the law in force back to the file (policy-restore.ts), so the
 *      file always matches what is enforced; the Inbox row keeps the
 *      declined text. Only CHANGES seen while the arbiter runs are judged: at
 *      start the file is the law, unless it holds content a human declined
 *      (restored before loading) or content still waiting for a human (held
 *      again; the content in force, persisted in mandu.db, is the law). A
 *      relaxing edit made while the arbiter is down, that no Inbox row names,
 *      applies at next start;
 *   3. the policy surface (policy-surface.md §8.4.2): a data-plane client's
 *      `policyPropose` (a TIGHTENING the confined agent asked for), an
 *      applied suggestion (`mandu policy suggest`, the dashboard), a human's
 *      approval of a proposal, an Undo. These go through `applyGuarded`: a
 *      hand edit that landed since the last load (inside the poll window) is
 *      loaded first and the write is refused with {@link StalePolicyError}, so
 *      an agent's write can never silently overwrite a human's edit. While a
 *      relaxing hand edit is held, such a change is made to the law and to
 *      the held content alike (`applyUnderHold`, first-session tour item 17),
 *      and the file is judged again: the hand edit stays held, not lost;
 *   4. nothing else: the arbiter rewrites the file on its own only to
 *      restore the law in force over content a human declined.
 *
 * Failure semantics (§2.1): an INVALID document — from the wire or from disk —
 * is refused and the law in force is kept (last-known-good); the problems are
 * recorded on {@link PolicyDocumentStore.status} so the snapshot can show a
 * banner. Never a silent fall-back to the built-ins.
 *
 * Comments: every write (1, 3) is written INTO the person's text
 * (policy-yaml-splice.ts), so their comments and layout stay, the held hand
 * edit's included; the bytes are used only when they read back as exactly
 * the document judged, else the file is dumped whole. `mintUserRule`
 * appends to `user_rules` with a fresh `r-<n>` id (free in the held edit
 * too).
 */
import { createHash, createHmac, randomBytes } from "node:crypto";
import { closeSync, existsSync, fstatSync, mkdirSync, openSync, readFileSync, renameSync, statSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";
import yaml from "js-yaml";

import { compilePolicy, getCurrentPolicy } from "./compiled-policy.js";
import type { PathLabelEntry, PolicyFileConfig, UserRuleEntry } from "./load-policy.js";
import { policyDelta, type PolicyDelta } from "./policy-delta.js";
import { getAdminLayer } from "./admin-layer.js";
import { PolicyFileError, validatePolicyDocument, type ValidateOptions } from "./policy-file-validate.js";
import { atomicReplace, decideDenyRestore, type EnforcedPolicy } from "./policy-restore.js";
import { canonicalJson, diffItems, itemValue, itemValues, layerItems, pathIdentity } from "./policy-edit.js";
import { POLICY_DUMP_OPTIONS, spliceYaml } from "./policy-yaml-splice.js";

export interface PolicyFileStatus {
  /** The resolved path (always known); null when the law is an in-memory document. */
  path: string | null;
  /** The file existed at the last load. */
  found: boolean;
  /** The last load/apply validated (true) or was refused (false → problems). */
  valid: boolean;
  problems: string[];
  /** Epoch millis of the last successful load into the law in force. */
  loadedAt: number | null;
  /** Epoch millis of the last refused load (disk or wire); null if none. */
  refusedAt: number | null;
}

export interface PolicyDocumentStoreOptions {
  /** The file the law is read from and written to; null = in-memory law (writes refused). */
  path: string | null;
  /** Called with a validated document to compile + swap the law in force. */
  rebuild: (document: PolicyFileConfig | null) => void;
  /** Audit hook: one call per applied change (best-effort, never throws),
   *  with the document before and after it, so the caller can record which
   *  items the change touched (dashboard.md §4.25j). */
  audit?: (change: PolicyChange, docs: { before: PolicyFileConfig | null; after: PolicyFileConfig | null }) => void;
  log?: (msg: string) => void;
  now?: () => number;
  /** Hand-edit poll interval (ms); 0 disables the watcher (tests). */
  pollMs?: number;
  /** Classify a disk change against the law in force (default: compile both
   *  under the boot spec in force and run `policyDelta`). A judge that throws
   *  counts as a relaxation (fail closed). */
  judge?: (before: PolicyFileConfig | null, after: PolicyFileConfig | null) => PolicyDelta;
  /** Told the content in force every time it changes (and once at
   *  construction), so the arbiter can persist it (policy-restore.ts): the
   *  next start restores it over content a human declined. Best-effort. */
  persistEnforced?: (enforced: EnforcedPolicy) => void;
}

/** A disk change with at least one relaxation, held out of force until a
 *  human approves it (policy-surface.md §8.4.6). */
export interface DiskHold {
  /** sha256 of the file's bytes (or {@link ABSENT_HASH} for a removed file). */
  hash: string;
  /** The file existed (false: the change is the file's removal). */
  found: boolean;
  /** The document the file holds, validated (null for a removed file). */
  document: PolicyFileConfig | null;
  /** The file's text (null for a removed file): the Inbox row keeps it, so a
   *  declined hand edit can be recovered after the file is restored. */
  text: string | null;
  /** The delta against the law in force when it was held. */
  delta: PolicyDelta;
  heldAt: number;
}

/** Told when a hold starts or ends (the policy surface files and closes the
 *  Inbox proposal). `next` is the new hold, if any; `previous` the one it
 *  replaces or that ended (the file moved on, or the arbiter wrote over it). */
export type DiskHoldListener = (next: DiskHold | null, previous: DiskHold | null) => void;

/** The content hash that stands for "no file". */
export const ABSENT_HASH = "absent";

/** sha256 of a file's text: the identity a held change is approved by. */
export function contentHash(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** The key of {@link lawHashOf}: random per arbiter process, so a law hash
 *  read on the data socket (where a prompt exception's pattern is hidden,
 *  plan 15 §13.7) cannot be used to test a guess of the pattern offline. */
const LAW_HASH_KEY = randomBytes(32);

/** The version of a law in force (policy-surface.md §8.4.6 "A whole-file
 *  apply names the law it was built from"): a keyed hash of the document as
 *  canonical JSON, so the same law reads the same however its keys are
 *  ordered, and a comment-only hand edit does not move it. Not stable across
 *  arbiter restarts: a document read before one is refused as stale. */
export function lawHashOf(document: PolicyFileConfig | null): string {
  return createHmac("sha256", LAW_HASH_KEY).update(canonicalJson(document ?? {})).digest("hex").slice(0, 32);
}

/** The version of ONE item of the law (policy-surface.md §8.4.6 "An
 *  item-level version"): the same keyed hash as {@link lawHashOf}, of the
 *  item's value as canonical JSON (null = absent). A typed edit built from
 *  an item read earlier (Settings › Models' update) names it, and is refused
 *  as stale once that item changed; a change to any other item does not
 *  refuse it. */
export function itemVersionOf(value: unknown): string {
  return createHmac("sha256", LAW_HASH_KEY).update(canonicalJson(value ?? null)).digest("hex").slice(0, 32);
}

/** How many laws in force the store remembers by hash, to name what changed
 *  when a whole-file apply built from one of them is refused as stale. */
const RECENT_LAWS = 32;
/** At most this many changed items are named in a stale refusal. */
const NAMED_CHANGES = 8;

/** The file's text parsed and validated like `loadPolicyFileStrict`, from the
 *  bytes already read (so the hash and the document are of the same bytes). */
function parsePolicyText(path: string, text: string, tolerate: ValidateOptions["tolerate"]): PolicyFileConfig {
  let doc: unknown;
  try {
    doc = yaml.load(text);
  } catch (err) {
    throw new PolicyFileError(path, [`YAML parse error: ${(err as Error).message.split("\n")[0]}`]);
  }
  const problems = validatePolicyDocument(doc, getAdminLayer(), { tolerate });
  if (problems.length > 0) throw new PolicyFileError(path, problems);
  return (doc ?? {}) as PolicyFileConfig;
}

/** The content in force recorded in mandu.db, as the law at start
 *  (policy-restore.ts), validated like the file. A record that no longer
 *  validates (a newer arbiter refuses what an older one accepted) refuses the
 *  start rather than load the file a human declined or has not decided; any
 *  edit of the file gives it a new hash, and it then loads as the law. */
export function parseEnforcedAtStart(path: string, enforced: EnforcedPolicy): PolicyFileConfig | null {
  if (enforced.text === null) return null;
  try {
    // The law at start: the administrator wins a conflict (plan 12 D5).
    return parsePolicyText(path, enforced.text, "all");
  } catch (err) {
    const problems = err instanceof PolicyFileError ? err.problems : [String((err as Error).message ?? err)];
    throw new PolicyFileError(path, [
      "policy.yaml holds a change a human declined or has not decided yet, and the content approved before it (recorded in mandu.db) no longer validates; " +
        "edit policy.yaml (any change) so the file is loaded as the law, then start again",
      ...problems,
    ]);
  }
}

function defaultJudge(before: PolicyFileConfig | null, after: PolicyFileConfig | null): PolicyDelta {
  const specId = getCurrentPolicy().specId;
  return policyDelta(compilePolicy({ specId, document: before }), compilePolicy({ specId, document: after }));
}

interface FileIdentity {
  mtimeMs: number;
  size: number;
  ino: number;
}

export interface PolicyChange {
  /** How the change arrived. `agent-tighten` = a data-plane tightening
   *  (policy-surface.md §8.3.5: the agent's `policyPropose`, or a scan
   *  suggestion applied with `applySuggestion` on the data socket); `proposal` = a human approved a proposal;
   *  `undo` = a human reverted a recorded change; `admin` = the
   *  administrator's layer was read again (plan 12 D5; the user's document
   *  did not change). */
  via: "apply" | "mint-rule" | "export-labels" | "move-labels" | "disk" | "pin-reader" | "agent-tighten" | "tighten" | "proposal" | "undo" | "restore" | "admin" | "prompt-pack";
  requestedBy?: string;
  /** One-line summary for the audit stream. */
  summary: string;
}

export interface ApplyResult {
  path: string;
  /** The document as written (post-normalization). */
  document: PolicyFileConfig;
}

/** A write refused as stale: the file on disk changed since the store last
 *  loaded it (the new file is now the law, is held, or was refused as
 *  invalid), or, for a whole-file apply, the law in force is no longer the
 *  one the document was built from (`lawMoved`). The write did not happen. */
export class StalePolicyError extends Error {
  readonly stale = true;
  /** `conflicts`: the items (`section key`) the held change changes too,
   *  when that is why this change cannot be made to it as well. `changed`
   *  (with `lawMoved`): the items the law changed since the document was
   *  read (`section key` each; empty when that law is not remembered). */
  constructor(
    readonly path: string,
    readonly held = false,
    readonly conflicts: readonly string[] = [],
    readonly lawMoved = false,
    readonly changed: readonly string[] = [],
  ) {
    super(lawMoved
      ? `policy file ${path}: the law in force changed since this document was read from it (${changed.length > 0 ? `changed: ${changed.join(", ")}` : "the law it was read from is not known any more"}), and writing it would undo that change; nothing was written. Read the law again and make the change to it.`
      : held
      ? `policy file ${path} holds a change made on disk that waits for a human in Approvals, and this change cannot be made to it as well (${conflicts.length > 0 ? `that change changes the same rule: ${conflicts.join(", ")}` : "it names something that change removes or changes too"}); nothing was written. Decide that change first, then try again.`
      : `policy file ${path} changed on disk since it was last loaded; the change on disk was loaded (or, if it relaxes the law, is waiting in Approvals) and nothing was written. Re-read the law and try again.`);
    this.name = "StalePolicyError";
  }
}

/** What approving a held disk change did. */
export type ApproveHoldResult =
  | { applied: true; before: PolicyFileConfig | null; after: PolicyFileConfig | null }
  /** The file no longer holds the approved content (or the law moved): it was
   *  judged afresh, which applied it, held it anew, or refused it as invalid. */
  | { applied: false };

/** What declining a held disk change did to the file. */
export interface DeclineHoldResult {
  /** The law in force was written back over the declined content. */
  restored: boolean;
  /** Why not, when not: the file had moved on (the newer content was judged
   *  as a fresh edit), or writing failed (the declined content still stays
   *  out of force; the next poll tries again). */
  why?: "moved-on" | "matches-law" | "no-law" | "write-failed";
}

/** What the law in force is at construction, when it is NOT the file's
 *  current bytes (policy-restore.ts `reconcilePolicyFileAtStart`). */
export interface InitialLaw {
  document: PolicyFileConfig | null;
  found: boolean;
  /** The content in force, when the file holds something else (a change that
   *  still waits for a human, or declined content the start could not
   *  restore). The store then judges the file's bytes against it. */
  inForce?: EnforcedPolicy | null;
  /** Hashes of contents a human declined before this start. */
  declined?: readonly string[];
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export class PolicyDocumentStore {
  readonly path: string | null;
  private readonly rebuild: (document: PolicyFileConfig | null) => void;
  private readonly audit: (change: PolicyChange, docs: { before: PolicyFileConfig | null; after: PolicyFileConfig | null }) => void;
  /** The arbiter's log (public so the policy surface can note a start-time
   *  reconciliation of held changes in the same place). */
  readonly log: (msg: string) => void;
  private readonly now: () => number;
  private readonly judge: (before: PolicyFileConfig | null, after: PolicyFileConfig | null) => PolicyDelta;
  private timer: NodeJS.Timeout | null = null;
  /** The stat identity of the file as last seen (null: no file). A changed
   *  identity makes the poll read the file; only a changed HASH is a change. */
  private lastIdentity: FileIdentity | null = null;
  /** Hash of the content last seen on disk: loaded, written by the arbiter,
   *  held, or declined. A poll that reads the same bytes sees no change, so
   *  the arbiter's own writes are never judged as a foreign edit. */
  private diskHashSeen: string | null = null;
  /** The content hash of the law in force as the file held it (null when the
   *  law did not come from a file this store read or wrote). */
  private inForceHash: string | null = null;
  /** The text of the law in force as the file held it (null: no file, the
   *  built-ins): what a decline writes back. */
  private inForceText: string | null = null;
  private readonly persistEnforced: (enforced: EnforcedPolicy) => void;
  /** A relaxing disk change waiting for a human (§4.6); at most one. */
  private held: DiskHold | null = null;
  /** Contents a human declined: seen again, they are kept out of force
   *  without a new Inbox card. */
  private readonly declined = new Set<string>();
  private holdListener: DiskHoldListener | null = null;
  /** The document in force (as last loaded/applied); null = built-ins only.
   *  Set only through `setCurrent`, which keeps its hash. */
  private current: PolicyFileConfig | null = null;
  private currentHash = lawHashOf(null);
  /** The last laws in force by {@link lawHashOf} (oldest first), so a stale
   *  whole-file apply can name what changed since it was read. */
  private readonly recentLaws = new Map<string, PolicyFileConfig | null>();
  private _status: PolicyFileStatus;

  constructor(opts: PolicyDocumentStoreOptions, initial: InitialLaw) {
    this.path = opts.path;
    this.rebuild = opts.rebuild;
    this.audit = opts.audit ?? (() => {});
    this.log = opts.log ?? (() => {});
    this.now = opts.now ?? (() => Date.now());
    this.judge = opts.judge ?? defaultJudge;
    this.persistEnforced = opts.persistEnforced ?? (() => {});
    for (const h of initial.declined ?? []) this.declined.add(h);
    this.setCurrent(initial.document);
    this._status = {
      path: this.path,
      found: initial.found,
      valid: true,
      problems: [],
      loadedAt: this.now(),
      refusedAt: null,
    };
    // At start the file IS the law (it was loaded by the caller); remember its
    // bytes so only a later CHANGE is judged. When the caller says the law is
    // other content (`inForce`: a change still waiting for a human, or
    // declined content a start-time restore could not overwrite), the file's
    // bytes are judged against that at once, as a poll would.
    const seen = this.readDisk();
    this.lastIdentity = seen.identity;
    this.diskHashSeen = seen.hash;
    const inForce = initial.inForce ?? null;
    if (this.path && inForce && inForce.hash !== seen.hash) {
      this.inForceHash = inForce.hash;
      this.inForceText = inForce.text;
      this.notePersist();
      this.judgeDisk(seen.text, seen.hash ?? ABSENT_HASH);
    } else {
      this.inForceHash = seen.hash;
      this.inForceText = seen.text;
      this.notePersist();
    }
    const pollMs = opts.pollMs ?? 2000;
    if (this.path && pollMs > 0) {
      this.timer = setInterval(() => this.pollDisk(), pollMs);
      this.timer.unref();
    }
  }

  get status(): PolicyFileStatus {
    return { ...this._status, problems: [...this._status.problems] };
  }

  /** The document in force, as last loaded/applied (null = built-ins). */
  get document(): PolicyFileConfig | null {
    return this.current;
  }

  /** The version of the law in force ({@link lawHashOf}): what a client
   *  that builds a whole document from it sends back (`applyDocument`'s
   *  `basedOn`), so a change that lands in between is not undone. */
  get lawHash(): string {
    return this.currentHash;
  }

  /** The version of one item of the law in force ({@link itemVersionOf}),
   *  by `itemValue`'s identity (`models` + a name, `user_rules` + an id, ...). */
  itemVersion(section: string, key: string): string {
    return itemVersionOf(itemValue(this.current, section, key));
  }

  /** The version an ABSENT item has ({@link itemVersionOf} of null): a
   *  writer that creates an item where its read found none names it with
   *  this, and is refused as stale once someone else made that item
   *  (policy-surface.md §8.4.6 "An item-level version"). Keyed like every
   *  version, so it says nothing about the law. */
  get absentVersion(): string {
    return itemVersionOf(null);
  }

  /** The version of every item of the law in force, `section → key →
   *  version` (what `policyDocument` answers as `itemVersions`). */
  itemVersions(): Record<string, Record<string, string>> {
    const out: Record<string, Record<string, string>> = {};
    for (const [section, items] of itemValues(this.current)) {
      const m: Record<string, string> = {};
      for (const [key, value] of items) m[key] = itemVersionOf(value);
      out[section] = m;
    }
    return out;
  }

  /** Make `document` the law in force's document, and remember it by hash. */
  private setCurrent(document: PolicyFileConfig | null): void {
    this.current = document;
    this.currentHash = lawHashOf(document);
    this.recentLaws.delete(this.currentHash);
    this.recentLaws.set(this.currentHash, document === null ? null : structuredClone(document));
    while (this.recentLaws.size > RECENT_LAWS) this.recentLaws.delete(this.recentLaws.keys().next().value as string);
  }

  /** Refuse a whole document built from the law `basedOn` when the law in
   *  force is another one (policy-surface.md §8.4.6): writing it would undo
   *  whatever changed in between (an agent's tightening, a hand edit the
   *  poll already loaded, an approved proposal, a reader pin), and undoing
   *  a tightening without a word is a loosening. Names the items that
   *  changed when the law it was read from is still remembered. */
  private checkBase(basedOn: string): void {
    if (basedOn === this.currentHash) return;
    let changed: string[] = [];
    if (this.recentLaws.has(basedOn)) {
      const items = diffItems(this.recentLaws.get(basedOn) ?? null, this.current).map((it) => `${it.section} ${it.key.replace("\0", " ")}`);
      changed = items.length > NAMED_CHANGES ? [...items.slice(0, NAMED_CHANGES), `${items.length - NAMED_CHANGES} more`] : items;
    }
    this.log(`policy file ${this.path}: a whole-document apply was built from an earlier law (${basedOn}; in force ${this.currentHash}) and was refused as stale${changed.length > 0 ? ` (changed since: ${changed.join(", ")})` : ""}`);
    throw new StalePolicyError(this.path as string, false, [], true, changed);
  }

  /** The relaxing disk change waiting for a human, if any. */
  get heldChange(): DiskHold | null {
    return this.held;
  }

  /** Hash of the bytes last seen on disk (null: no file path). */
  get diskHash(): string | null {
    return this.diskHashSeen;
  }

  /** Tell the arbiter the content in force (best-effort). */
  private notePersist(): void {
    if (!this.path || this.inForceHash === null) return;
    try {
      this.persistEnforced({ hash: this.inForceHash, text: this.inForceText });
    } catch (err) {
      this.log(`recording the policy content in force failed (ignored; a declined change is still restored while the arbiter runs): ${(err as Error).message}`);
    }
  }

  /** One listener: the policy surface, which files and closes the Inbox card. */
  setDiskHoldListener(listener: DiskHoldListener | null): void {
    this.holdListener = listener;
  }

  close(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** Stat, then read: the identity is taken BEFORE the bytes, so a write that
   *  lands in between changes the identity again and is read on the next poll. */
  private readDisk(): { identity: FileIdentity | null; text: string | null; hash: string | null } {
    if (!this.path) return { identity: null, text: null, hash: null };
    let identity: FileIdentity | null;
    try {
      const st = statSync(this.path);
      identity = { mtimeMs: st.mtimeMs, size: st.size, ino: st.ino };
    } catch {
      return { identity: null, text: null, hash: ABSENT_HASH };
    }
    try {
      const text = readFileSync(this.path, "utf8");
      return { identity, text, hash: contentHash(text) };
    } catch {
      // Vanished between stat and read: seen as absent; the next poll re-stats.
      return { identity: null, text: null, hash: ABSENT_HASH };
    }
  }

  private static sameIdentity(a: FileIdentity | null, b: FileIdentity | null): boolean {
    if (a === null || b === null) return a === b;
    return a.mtimeMs === b.mtimeMs && a.size === b.size && a.ino === b.ino;
  }

  /** End the pending hold (the file moved on) and tell the listener. */
  private setHold(next: DiskHold | null): void {
    const previous = this.held;
    // The same bytes judged again (`rejudgeHold`) that give up nothing the
    // card did not show: the same hold and the same card. One that now gives
    // up more is a new hold, and the card is filed again with the larger
    // delta (an approval never covers more than the human was shown).
    if (previous !== null && next !== null && previous.hash === next.hash) {
      const shown = new Set(previous.delta.relaxations.map((r) => `${r.facet}\0${r.subject}`));
      if (next.delta.relaxations.every((r) => shown.has(`${r.facet}\0${r.subject}`))) return;
    }
    this.held = next;
    if (previous === null && next === null) return;
    try {
      this.holdListener?.(next, previous);
    } catch (err) {
      this.log(`policy hold listener failed (ignored; the law in force is unchanged): ${(err as Error).message}`);
    }
  }

  /** Hand-edit pickup: a changed identity reads the file; changed BYTES are
   *  judged (§4.6). Returns true when a change was seen (applied, held,
   *  declined again, or refused as invalid). */
  pollDisk(): boolean {
    if (!this.path) return false;
    let identity: FileIdentity | null;
    try {
      const st = statSync(this.path);
      identity = { mtimeMs: st.mtimeMs, size: st.size, ino: st.ino };
    } catch {
      identity = null;
    }
    if (PolicyDocumentStore.sameIdentity(identity, this.lastIdentity)) return false;
    const seen = this.readDisk();
    this.lastIdentity = seen.identity;
    if (seen.hash === this.diskHashSeen) return false; // a touch, or our own bytes
    this.diskHashSeen = seen.hash;
    this.judgeDisk(seen.text, seen.hash ?? ABSENT_HASH);
    return true;
  }

  /** Judge bytes read from disk against the law in force: apply a change
   *  without relaxations, hold one with any, keep the law on an invalid file. */
  private judgeDisk(text: string | null, hash: string): void {
    const path = this.path as string;
    const found = text !== null;
    let document: PolicyFileConfig | null;
    try {
      // A hand edit may keep the conflicts with the administrator's layer
      // the law in force has; one it adds is refused (plan 12 D5).
      document = found ? parsePolicyText(path, text, this.current) : null;
    } catch (err) {
      const problems = err instanceof PolicyFileError ? err.problems : [String((err as Error).message ?? err)];
      this._status = { ...this._status, valid: false, problems, refusedAt: this.now() };
      this.log(`policy file changed on disk but is INVALID — keeping the law in force:\n  - ${problems.join("\n  - ")}`);
      this.setHold(null);
      return;
    }
    if (hash === this.inForceHash) {
      // Back to the bytes in force (e.g. a held edit was reverted by hand).
      this._status = { ...this._status, found, valid: true, problems: [] };
      this.setHold(null);
      return;
    }
    if (this.declined.has(hash)) {
      this.log(`policy file ${path} changed on disk to content a human already declined; the law in force stays (no new card in Approvals) and the file is restored`);
      this.setHold(null);
      this.restoreOver(hash, "policy.yaml changed on disk to content a human already declined; it was restored to the law in force");
      return;
    }
    const before = this.current;
    let delta: PolicyDelta;
    try {
      delta = this.judge(before, document);
    } catch (err) {
      delta = {
        relaxations: [{ facet: "law", direction: "relax", subject: "policy.yaml", detail: `the change could not be compared with the law in force (${(err as Error).message}), so it counts as a relaxation` }],
        tightenings: [],
      };
    }
    if (delta.relaxations.length > 0) {
      this._status = { ...this._status, valid: true, problems: [] };
      this.log(
        `policy file ${path} changed on disk and would RELAX the law (${delta.relaxations.length} relaxation(s): ` +
          `${delta.relaxations.map((r) => `${r.facet} ${r.subject}`).join(", ")}); NOT applied, the law in force stays until a human approves it in Approvals`,
      );
      this.setHold({ hash, found, document, text, delta, heldAt: this.now() });
      return;
    }
    this.setHold(null);
    this.load(document, found, hash, text, {
      via: "disk",
      summary: found ? "policy.yaml changed on disk and was reloaded" : "policy.yaml was removed; the built-ins are the law",
    });
  }

  /** Make a validated document from disk the law in force, and audit it. */
  private load(document: PolicyFileConfig | null, found: boolean, hash: string, text: string | null, change: PolicyChange): { before: PolicyFileConfig | null; after: PolicyFileConfig | null } {
    const before = this.current;
    this.rebuild(document);
    this.setCurrent(document);
    this.inForceHash = hash;
    this.inForceText = text;
    this.notePersist();
    this._status = { ...this._status, found, valid: true, problems: [], loadedAt: this.now() };
    this.log(`policy file reloaded from disk: ${this.path}${found ? "" : " (removed — built-ins are the law)"} (${change.summary})`);
    this.audit(change, { before, after: document });
    return { before, after: document };
  }

  /**
   * A human approved the held change `hash` (§4.6). If the file still holds
   * exactly those bytes and the law has not moved since it was held, load it
   * and audit it as `change`. Otherwise the file (as it is now) is judged
   * afresh, which applies it, holds it anew or refuses it; the caller reads
   * the outcome from the listener.
   */
  approveDiskHold(hash: string, change: PolicyChange): ApproveHoldResult {
    if (!this.path) throw new Error("the law in force is an in-memory document (no policy file path)");
    const seen = this.readDisk();
    this.lastIdentity = seen.identity;
    const held = this.held;
    if (held && held.hash === hash && seen.hash === hash) {
      // The same bytes that were held (so they parse as they did then). The
      // law moves under a pending hold only through `applyUnderHold`, which
      // writes new bytes and so ends this hold, or ends it outright; but
      // check: approving must never give up more than the human was shown.
      const document = held.document;
      let grew = true;
      try {
        const shown = new Set(held.delta.relaxations.map((r) => `${r.facet}\0${r.subject}`));
        grew = this.judge(this.current, document).relaxations.some((r) => !shown.has(`${r.facet}\0${r.subject}`));
      } catch {
        grew = true;
      }
      if (!grew) {
        this.held = null; // resolved by the caller, not superseded
        this.diskHashSeen = hash;
        return { applied: true, ...this.load(document, held.found, hash, held.text, change) };
      }
    }
    // The file moved on (or would now relax more than the human was shown):
    // judge the bytes on disk now, as a poll would.
    this.diskHashSeen = seen.hash;
    this.judgeDisk(seen.text, seen.hash ?? ABSENT_HASH);
    return { applied: false };
  }

  /**
   * A human declined the held change `hash`: the law stays, these bytes are
   * not held again, and the file is RESTORED to the law in force (policy-
   * restore.ts), so a restart cannot load the declined content. Only while
   * the file still holds those bytes: a newer edit is judged as a fresh one
   * (applied, held anew, or refused), never overwritten.
   */
  declineDiskHold(hash: string): DeclineHoldResult {
    this.declined.add(hash);
    if (this.held?.hash === hash) this.held = null; // resolved by the caller
    if (!this.path) return { restored: false, why: "no-law" };
    const seen = this.readDisk();
    const d = decideDenyRestore({ diskHash: seen.hash, deniedHash: hash, inForceHash: this.inForceHash });
    if (!d.restore) {
      this.lastIdentity = seen.identity;
      if (d.why === "moved-on") {
        this.log(`a policy.yaml change on disk was declined, but ${this.path} has changed again since; the newer content is judged as a fresh edit and the file is not restored`);
        if (seen.hash !== this.diskHashSeen) {
          this.diskHashSeen = seen.hash;
          this.judgeDisk(seen.text, seen.hash ?? ABSENT_HASH);
        }
      }
      return { restored: false, why: d.why };
    }
    return this.restoreOver(hash, "a human declined a policy.yaml change made on disk; the file was restored to the law in force")
      ? { restored: true }
      : { restored: false, why: "write-failed" };
  }

  /** Write the law in force back over the declined bytes `declinedHash`
   *  (only while the file still holds them), and audit it as `restore`. The
   *  restore is not a change of the law, so the arbiter's own write is
   *  remembered and never judged as a foreign edit. */
  private restoreOver(declinedHash: string, summary: string): boolean {
    if (!this.path || this.inForceHash === null || this.inForceHash === declinedHash) return false;
    let r: ReturnType<typeof atomicReplace>;
    try {
      r = atomicReplace(this.path, this.inForceText, declinedHash);
    } catch (err) {
      this.log(`WARNING: restoring ${this.path} to the law in force failed (${(err as Error).message}); the declined content stays out of force and the next poll tries again`);
      // Forget the bytes so the next poll sees them again and retries.
      this.lastIdentity = null;
      this.diskHashSeen = null;
      return false;
    }
    if (!r.replaced) {
      // A newer edit landed: the next poll reads and judges it.
      this.lastIdentity = null;
      return false;
    }
    this.lastIdentity = r.identity;
    this.diskHashSeen = this.inForceHash;
    this._status = { ...this._status, found: this.inForceText !== null, valid: true, problems: [] };
    this.log(`policy file restored: ${this.path} (${summary})`);
    this.audit({ via: "restore", requestedBy: "arbiter", summary }, { before: this.current, after: this.current });
    return true;
  }

  /**
   * The developer view's whole-document apply (`applyPolicyDocument`): `doc`
   * replaces the law, and was built by the client from the law whose
   * {@link lawHash} it read, `basedOn`. A hand edit the poll had not read
   * yet is read first; then, if the law in force is not `basedOn` any more
   * (a change landed between the client's read and this apply: an agent's
   * tightening, a hand edit, an approved proposal, a reader pin), the apply
   * is refused as stale (StalePolicyError `lawMoved`, naming the items that
   * changed), because writing the document would undo that change without a
   * word. A hand edit just read that leaves the law as it was (one held, or
   * one refused as invalid) refuses it as stale too, as `apply` always did.
   * Otherwise it is `apply`.
   */
  applyDocument(doc: unknown, basedOn: string, change: Omit<PolicyChange, "summary"> & { summary?: string }): ApplyResult {
    if (!this.path) {
      throw new Error("the law in force is an in-memory document (no policy file path) — nothing to write");
    }
    const moved = this.pollDisk();
    this.checkBase(basedOn);
    if (moved) throw new StalePolicyError(this.path);
    return this.apply(doc, change);
  }

  /**
   * A write from outside the policy surface (1): the developer view's whole
   * document (through `applyDocument`), a minted rule, a label migration, a
   * reader pin. `doc` is the
   * law in force with the change. Validate, then the guarded write
   * (`applyGuarded`): a hand edit that landed since the last load is loaded
   * first and the write refused as stale; with no hold the change is written
   * into the person's text (comments kept); while a relaxing hand edit is
   * held, the items the change touched (`layerItems`: the Undo's revert run
   * forwards) are made to the held document too, so the hand edit stays in
   * the file and stays held, judged again against the new law. A change to
   * an item the held edit changes too is refused (StalePolicyError, `held`,
   * naming the items) until the hold is decided: it is never written over
   * the held edit, and nothing the held edit relaxes takes effect.
   * `opts.mayLayer` refuses the layering for a held document the caller's
   * change was not computed for (a reader pin that copies a label the held
   * edit may have changed). Throws PolicyFileError on an invalid document.
   */
  apply(doc: unknown, change: Omit<PolicyChange, "summary"> & { summary?: string }, opts: { mayLayer?: (held: PolicyFileConfig | null) => boolean } = {}): ApplyResult {
    if (!this.path) {
      throw new Error("the law in force is an in-memory document (no policy file path) — nothing to write");
    }
    const after = this.validated(doc);
    const before = this.current;
    let conflicts: string[] = [];
    try {
      return this.applyGuarded(after, change, (held) => {
        if (opts.mayLayer && !opts.mayLayer(held)) return null;
        const r = layerItems(held, before, after);
        if (r.ok) return r.document;
        conflicts = r.conflicts;
        return null;
      });
    } catch (err) {
      if (err instanceof StalePolicyError && err.held && conflicts.length > 0) throw new StalePolicyError(this.path, true, conflicts);
      throw err;
    }
  }

  /**
   * The write of the policy surface (policy-surface.md §8.4.2): an agent's
   * tightening, an approved proposal or suggestion, an applied suggestion
   * (`mandu policy suggest`, the dashboard), an Undo. `after` is the law in
   * force with the change, already judged by the caller.
   *
   *   - A hand edit that landed since the last load is loaded (or held, or
   *     refused) first, and the write is refused as stale.
   *   - With no hold, the file is the law: the change is written INTO the
   *     person's text (`spliceYaml`), so their comments stay.
   *   - While a relaxing hand edit is held (§8.4.6; first-session tour item
   *     17), the change does not wait on it: `layer` makes the same change to
   *     the held document, the law gets `after`, and the file gets the held
   *     edit with the change (`applyUnderHold`), judged again against the new
   *     law. Nothing the held edit relaxes takes effect. A change `layer`
   *     cannot make to the held document (null) is refused as stale until the
   *     hold is decided.
   */
  applyGuarded(
    after: unknown,
    change: Omit<PolicyChange, "summary"> & { summary?: string },
    layer: (held: PolicyFileConfig | null) => PolicyFileConfig | null,
  ): ApplyResult {
    if (!this.path) {
      throw new Error("the law in force is an in-memory document (no policy file path) — nothing to write");
    }
    if (this.pollDisk()) throw new StalePolicyError(this.path);
    const held = this.held;
    if (held === null) return this.write(this.validated(after), change);
    const onHeld = layer(held.document);
    if (onHeld === null) throw new StalePolicyError(this.path, true);
    return this.applyUnderHold(after, onHeld, held.hash, change);
  }

  /** The text for `document` written over `text` (which reads as `from`):
   *  the person's comments and layout kept where the splice can (§8.4.6
   *  "Comments are kept"), else the plain dump. */
  private textFor(document: PolicyFileConfig, text: string | null, from: PolicyFileConfig | null): string {
    if (text !== null) {
      const spliced = spliceYaml(text, from ?? {}, document);
      if (spliced !== null) return spliced;
      this.log(`policy file ${this.path}: the change could not be written into the file as it is (comments kept), so the file is written whole`);
    }
    return PolicyDocumentStore.render(document);
  }

  private write(document: PolicyFileConfig, change: Omit<PolicyChange, "summary"> & { summary?: string }): ApplyResult {
    const path = this.path as string;
    // Only over the bytes in force: a file that holds anything else is
    // never the base of an edit.
    const base = this.inForceHash !== null && this.diskHashSeen === this.inForceHash ? this.inForceText : null;
    const { bytes, identity } = this.writeText(this.textFor(document, base, this.current));
    const before = this.current;
    this.rebuild(document);
    this.setCurrent(document);
    const hash = contentHash(bytes);
    this.lastIdentity = identity;
    this.diskHashSeen = hash;
    this.inForceHash = hash;
    this.inForceText = bytes;
    this.notePersist();
    // Reached with no hold pending (`applyGuarded` layers over one).
    this.setHold(null);
    this._status = { ...this._status, found: true, valid: true, problems: [], loadedAt: this.now() };
    const summary = change.summary ?? `policy.yaml applied (${change.via})`;
    this.log(`policy file written: ${path} — ${summary}`);
    this.audit({ ...change, summary }, { before, after: document });
    return { path, document };
  }

  /**
   * A change made through the policy surface while a relaxing disk change
   * waits for a human (§4.6; first-session tour item 17: the agent's own lock
   * waited on an unrelated held edit). `law` is the law in force with the
   * change (already judged by the caller: an agent's tightening, or a
   * proposal a human approved) and becomes the law; `held` is the held
   * content with the same change, and is what the file gets, so the hand
   * edit is kept, not overwritten. The written file is then judged against
   * the new law as a poll would: one that still relaxes stays held (the card
   * is filed again for the new bytes, the old one superseded by it), one that
   * no longer relaxes is loaded. Nothing the held edit relaxes takes effect.
   * Refused as stale when the file moved since the last read or the hold is
   * no longer `heldHash`.
   */
  applyUnderHold(law: unknown, held: unknown, heldHash: string, change: Omit<PolicyChange, "summary"> & { summary?: string }): ApplyResult {
    if (!this.path) {
      throw new Error("the law in force is an in-memory document (no policy file path) — nothing to write");
    }
    if (this.pollDisk()) throw new StalePolicyError(this.path);
    if (!this.held || this.held.hash !== heldHash) throw new StalePolicyError(this.path, this.held !== null);
    const hold = this.held;
    const document = this.validated(law);
    const heldDocument = this.validated(held);
    // Both texts keep the person's comments where the splice can: the file
    // (their held edit, re-saved with the change) and the content in force
    // (what a decline writes back over it).
    const lawBytes = this.textFor(document, this.inForceText, this.current);
    const { bytes, identity } = this.writeText(this.textFor(heldDocument, hold.text, hold.document));
    const before = this.current;
    this.rebuild(document);
    this.setCurrent(document);
    this.lastIdentity = identity;
    this.diskHashSeen = contentHash(bytes);
    // The law in force is content the file does not hold (as at a start with
    // a pending card): its text is what a decline writes back.
    this.inForceHash = contentHash(lawBytes);
    this.inForceText = lawBytes;
    this.notePersist();
    this._status = { ...this._status, found: true, valid: true, problems: [], loadedAt: this.now() };
    const summary = change.summary ?? `policy.yaml applied (${change.via})`;
    this.log(`policy file written: ${this.path} — ${summary} (the change waiting in Approvals is kept in the file and judged again)`);
    this.audit({ ...change, summary }, { before, after: document });
    this.judgeDisk(bytes, this.diskHashSeen);
    return { path: this.path, document };
  }

  /**
   * Judge the held change again against the law in force, as a poll that saw
   * it for the first time would (tour item 17): the law can come to say what
   * the held bytes say by another way (an approved proposal, a change of the
   * administrator's layer), and a hold that no longer relaxes anything is
   * loaded and its card closed. Returns true when the hold ended.
   */
  rejudgeHold(): boolean {
    if (!this.path || !this.held) return false;
    const seen = this.readDisk();
    this.lastIdentity = seen.identity;
    this.diskHashSeen = seen.hash;
    this.judgeDisk(seen.text, seen.hash ?? ABSENT_HASH);
    return this.held === null;
  }

  /** Validate a document for writing; throws PolicyFileError (recorded on
   *  the status) when it is invalid. */
  private validated(doc: unknown): PolicyFileConfig {
    const problems = validatePolicyDocument(doc, getAdminLayer(), { tolerate: this.current });
    if (problems.length > 0) {
      this._status = { ...this._status, valid: false, problems, refusedAt: this.now() };
      throw new PolicyFileError(this.path as string, problems);
    }
    return (doc ?? {}) as PolicyFileConfig;
  }

  /** The bytes the arbiter writes for `document`. */
  private static render(document: PolicyFileConfig): string {
    const text = yaml.dump(document, POLICY_DUMP_OPTIONS);
    const header =
      "# Mandu policy — the operator's law (docs/design/ui/policy-surface.md §2.1).\n" +
      "# Written by the arbiter on an apply from the dashboard; hand edits are picked up within seconds\n" +
      "# (one that loosens a rule waits for your approval on the dashboard's Approvals page).\n";
    return header + text;
  }

  /** Write `bytes` to the file atomically (tmp + rename). */
  private writeText(bytes: string): { bytes: string; identity: FileIdentity } {
    const path = this.path as string;
    const dir = dirname(path);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const tmp = join(dir, `.policy.yaml.${process.pid}.tmp`);
    // The identity is taken from the tmp file before the rename (a rename
    // keeps inode, size and mtime), so a foreign write that lands right after
    // the rename is a different identity and is read and judged.
    const fd = openSync(tmp, "w", 0o666);
    let identity: FileIdentity;
    try {
      writeSync(fd, bytes, null, "utf8");
      const st = fstatSync(fd);
      identity = { mtimeMs: st.mtimeMs, size: st.size, ino: st.ino };
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, path);
    return { bytes, identity };
  }

  /** Append a user rule with a fresh id (`r-<n>`); returns the id. */
  mintUserRule(entry: Omit<UserRuleEntry, "id"> & { id?: string }, requestedBy?: string): { id: string; result: ApplyResult } {
    const base: PolicyFileConfig = this.current ? structuredClone(this.current) : {};
    const rules = [...(base.user_rules ?? [])];
    // A minted id is free in a held hand edit too, so the rule can be made
    // to it as well (one the caller names is refused by the layering then).
    const taken = new Set([...rules, ...(this.held?.document?.user_rules ?? [])].map((r) => r.id));
    let id = entry.id;
    if (!id) {
      let n = rules.length + 1;
      while (taken.has(`r-${String(n).padStart(4, "0")}`)) n++;
      id = `r-${String(n).padStart(4, "0")}`;
    } else if (rules.some((r) => r.id === id)) {
      throw new Error(`user rule id '${id}' already exists`);
    }
    const rule: UserRuleEntry = { ...entry, id, added: entry.added ?? new Date(this.now()).toISOString() };
    rules.push(rule);
    base.version ??= 1;
    base.user_rules = rules;
    const result = this.apply(base, {
      via: "mint-rule",
      requestedBy,
      summary: `user rule ${id} added: ${rule.mode} ${rule.from?.host ?? "any origin"} → ${rule.to.host}`,
    });
    return { id, result };
  }

  /** Copy DB-only secret-file labels into `paths:` (the migration §2.1 promised). */
  exportDbLabels(labels: readonly PathLabelEntry[], requestedBy?: string): { added: number; result: ApplyResult } {
    const base: PolicyFileConfig = this.current ? structuredClone(this.current) : {};
    const have = new Set((base.paths ?? []).map((p) => p.path));
    const added: PathLabelEntry[] = [];
    for (const l of labels) {
      if (have.has(l.path)) continue;
      added.push({ path: l.path, level: l.level, ...(l.bindings?.length ? { bindings: [...l.bindings] } : {}), ...(l.recursive === false ? { recursive: false } : {}) });
    }
    base.version ??= 1;
    base.paths = [...(base.paths ?? []), ...added];
    const result = this.apply(base, {
      via: "export-labels",
      requestedBy,
      summary: `${added.length} secret-file label(s) exported from mandu.db into policy.yaml paths:`,
    });
    return { added: added.length, result };
  }

  /** MOVE the page store's labels into `paths:` (dashboard.md §4.25m): each
   *  row replaces any `paths:` entry for the same path (by identity), because
   *  the row is what decides there today (mandu.db wins on the same path).
   *  The caller deletes the rows once this returns, so what is enforced does
   *  not change. Recorded as `move-labels`, which Undo refuses. */
  moveDbLabels(labels: readonly PathLabelEntry[], requestedBy?: string): { moved: number; result: ApplyResult } {
    const base: PolicyFileConfig = this.current ? structuredClone(this.current) : {};
    const ids = new Set(labels.map((l) => pathIdentity(l.path)));
    const kept = (base.paths ?? []).filter((p) => !ids.has(pathIdentity(p.path)));
    const moved = labels.map((l) => ({ path: l.path, level: l.level, ...(l.bindings?.length ? { bindings: [...l.bindings] } : {}), ...(l.recursive === false ? { recursive: false } : {}) }));
    base.version ??= 1;
    base.paths = [...kept, ...moved];
    const result = this.apply(base, {
      via: "move-labels",
      requestedBy,
      summary: `${moved.length} rule(s) made on the dashboard moved from mandu.db into policy.yaml paths:, unchanged`,
    });
    return { moved: moved.length, result };
  }

  /** Read the file as it is on disk right now (for the editor), parsed leniently
   *  so an invalid file can still be shown. */
  readRaw(): { path: string | null; text: string | null; parsed: unknown; problems: string[] } {
    if (!this.path || !existsSync(this.path)) return { path: this.path, text: null, parsed: null, problems: [] };
    const text = readFileSync(this.path, "utf8");
    let parsed: unknown = null;
    let problems: string[] = [];
    try {
      parsed = yaml.load(text);
      problems = validatePolicyDocument(parsed, getAdminLayer(), { tolerate: this.current });
    } catch (err) {
      problems = [`YAML parse error: ${(err as Error).message.split("\n")[0]}`];
    }
    if (parsed !== null && parsed !== undefined && !isPlainObject(parsed)) problems.unshift("policy: the document must be a mapping");
    return { path: this.path, text, parsed, problems };
  }
}
