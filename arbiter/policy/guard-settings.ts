/**
 * guard-settings — policy.yaml keys for the whole-agent guard's host lists
 * (sandbox-security-review-2026-09-28, items 5 and 6 of the fix session's
 * ledger). Mandu-new.
 *
 *   unix_sockets:
 *     allow: [...]      Unix sockets the agent's tree may connect to, beyond
 *                       the built-in list (launcher/src/unix-policy.ts): a
 *                       socket file, a directory of sockets, or `@name` for
 *                       an abstract socket (a trailing `*` is a prefix). The
 *                       same syntax as MANDU_UNIX_ALLOW, which stays and is
 *                       unioned. Adding one RELAXES the law.
 *   write_protect:
 *     deny: [...]       more paths the agent's tree may not change (refused,
 *                       like Mandu's own files): a tightening;
 *     ask: [...]        more paths whose change waits for the human in the
 *                       Inbox (like the files that run later): a tightening;
 *     unprotect: [...]  entries removed from the built-in "runs later" list
 *                       (launcher/src/write-protect.ts): a RELAXATION, so a
 *                       disk edit adding one is held for a human like every
 *                       relaxation. Mandu's own files (anything in the
 *                       Mandu home, on-disk-layout.md §4) cannot be named here:
 *                       the validator refuses the value, and the launcher
 *                       never removes an own-files entry whatever the value.
 *   remote_mounts:
 *     trust_lookups:    network or FUSE mounts whose servers may see what a
 *       - mount: /home  program holding a secret looks up there (plan 13
 *         type: nfs4    §4.9, 2026-10-07): while an untrusted, unbound one
 *                       is visible, the guard serves a reader the
 *                       placeholder instead of the real file. By mount point
 *                       (absolute or `~/`) and file-system type, as
 *                       `/proc/self/mountinfo` names them. A RELAXATION
 *                       (the server sees every name a holder looks up);
 *                       writes there are still refused unless bound.
 *
 * The file is the human's law: these keys come from policy.yaml only (admin
 * writes and hand edits); no edit op of the policy agent's grammar or the
 * Describe box names them (policy-edit.ts), so a model cannot propose them.
 * The launcher reads the compiled lists through the `guardSettings` op and
 * expands `~` against the launching user's HOME.
 *
 * Pure.
 */
import { posix } from "node:path";
import type { PolicyFileConfig } from "./load-policy.js";

/** The top-level keys this module owns (policy-file-validate.ts accepts
 *  them; policy-delta.ts has a tightening proof for them). */
export const GUARD_SETTINGS_KEYS: readonly string[] = ["unix_sockets", "write_protect", "remote_mounts"];

/** One `remote_mounts.trust_lookups` entry. */
export interface TrustLookup {
  /** The mount point, absolute or `~/`, trailing `/` trimmed. */
  mount: string;
  /** The file-system type as mountinfo names it (`nfs4`, `fuse.sshfs`). */
  type: string;
}

export interface GuardSettings {
  /** Socket paths (absolute or `~/`) and `@abstract` names, as written. */
  unixAllow: string[];
  /** Absolute or `~/` paths, trailing `/` trimmed. */
  writeDeny: string[];
  writeAsk: string[];
  writeUnprotect: string[];
  /** `remote_mounts.trust_lookups`, as written (`~` unexpanded). */
  trustLookups: TrustLookup[];
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function trimSlash(p: string): string {
  return p.length > 1 ? p.replace(/\/+$/, "") || "/" : p;
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? [...new Set(v.filter((x): x is string => typeof x === "string").map((x) => (x.startsWith("@") ? x : trimSlash(x))))] : [];
}

/** The compiled lists (a document that failed validation never reaches the
 *  law, so this only normalizes). */
export function guardSettingsOf(doc: PolicyFileConfig | null | undefined): GuardSettings {
  const d = (doc ?? {}) as Record<string, unknown>;
  const u = isPlainObject(d.unix_sockets) ? d.unix_sockets : {};
  const w = isPlainObject(d.write_protect) ? d.write_protect : {};
  const r = isPlainObject(d.remote_mounts) ? d.remote_mounts : {};
  return { unixAllow: strings(u.allow), writeDeny: strings(w.deny), writeAsk: strings(w.ask), writeUnprotect: strings(w.unprotect), trustLookups: trustLookupsOf(r.trust_lookups) };
}

/** The trust entries, normalized and deduplicated (by point and type). */
function trustLookupsOf(v: unknown): TrustLookup[] {
  if (!Array.isArray(v)) return [];
  const out: TrustLookup[] = [];
  for (const e of v) {
    if (!isPlainObject(e) || typeof e.mount !== "string" || typeof e.type !== "string") continue;
    const t = { mount: trimSlash(e.mount), type: e.type };
    if (!out.some((o) => trustKey(o) === trustKey(t))) out.push(t);
  }
  return out;
}

/** An entry's identity: the point, and the type case-folded (the guard
 *  compares types case-insensitively). */
function trustKey(t: TrustLookup): string {
  return `${t.mount} (${t.type.toLowerCase()})`;
}

/** A file-system type as mountinfo prints it. */
const FSTYPE = /^[A-Za-z0-9][A-Za-z0-9._+-]*$/;

const isPathSpelling = (p: string): boolean => p.startsWith("/") || p === "~" || p.startsWith("~/");

/** Where Mandu keeps its own files, as parent directories of a `mandu`
 *  directory: the data home and the install locations. The one home is any
 *  `.mandu` segment (on-disk-layout.md §3). */
const OWN_PARENTS: readonly (readonly string[])[] = [
  [".local", "share"], ["usr", "lib"], ["usr", "local", "lib"], ["opt"], ["etc"], ["var", "lib"],
];
const OWN_NAMES = new Set(["mandu"]);
const OWN_FILE = /^(?:(?:mandu|mandu-test)\.db(?:-wal|-shm|-journal)?|arbiter\.sock)$/;

function endsWith(segs: readonly string[], tail: readonly string[]): boolean {
  if (tail.length > segs.length) return false;
  return tail.every((t, i) => segs[segs.length - tail.length + i] === t);
}

/**
 * Does `p` (absolute or `~/`, as written) name Mandu's own files: the one
 * home (anything under `.mandu`: config, `state/`, `events/`, `cache/`, the
 * symbol DB), the relocated home `env.MANDU_HOME`, the install directory
 * (or something inside one), a symbol DB or arbiter socket by name, or a
 * directory ABOVE one of them (`~/.local/share`, `~`, `/`)? Used to refuse
 * an opt-out: the launcher never removes such an entry anyway, and a value
 * that names one is a mistake or an attempt worth saying no to. A custom
 * install prefix spelled out is caught by its `mandu` directory name when
 * the parent is one of the usual ones; the launcher's structural rule
 * covers the rest.
 */
export function namesManduOwnFiles(p: string, env: Readonly<Record<string, string | undefined>> = process.env): boolean {
  const norm = posix.normalize(p.startsWith("~") ? `/~HOME${p.slice(1)}` : p);
  const relocated = env["MANDU_HOME"];
  if (relocated && relocated.startsWith("/")) {
    const abs = p.startsWith("~") ? (env["HOME"] ? posix.normalize(`${env["HOME"]}${p.slice(1)}`) : null) : norm;
    const h = trimSlash(posix.normalize(relocated));
    if (abs !== null) {
      const a = trimSlash(abs);
      if (a === h || a.startsWith(`${h}/`) || h.startsWith(`${a}/`) || a === "/") return true;
    }
  }
  const segs = norm.split("/").filter((s) => s !== "");
  if (segs.length === 0) return true; // `/`
  if (segs.length === 1 && segs[0] === "~HOME") return true; // `~`
  for (let i = 0; i < segs.length; i++) {
    if (OWN_NAMES.has(segs[i]!) && OWN_PARENTS.some((parent) => endsWith(segs.slice(0, i), parent))) return true;
    // /run/user/<uid>/mandu: the runtime dir (arbiter sockets, scopes).
    if (OWN_NAMES.has(segs[i]!) && i >= 3 && segs[i - 3] === "run" && segs[i - 2] === "user" && /^\d+$/.test(segs[i - 1]!)) return true;
    if (segs[i] === ".mandu") return true;
  }
  if (OWN_FILE.test(segs[segs.length - 1]!)) return true;
  // A directory above an own location: `~/.local`, `~/.local/share`, …
  const last = segs[segs.length - 1]!;
  if (last === ".local" || endsWith(segs, [".local", "share"])) return true;
  if (norm === "/run" || norm === "/run/user" || /^\/run\/user\/\d+$/.test(norm) || norm === "/usr" || norm === "/usr/lib" || norm === "/opt" || norm === "/etc") return true;
  return false;
}

/** Validate the three keys (the caller has already accepted them as keys). */
export function checkGuardSettings(doc: Record<string, unknown>, out: string[]): void {
  checkRemoteMounts(doc, out);
  if ("unix_sockets" in doc) {
    const u = doc.unix_sockets;
    if (!isPlainObject(u)) {
      out.push("unix_sockets: must be a mapping with 'allow' (a list of socket paths or @abstract names)");
    } else {
      for (const k of Object.keys(u)) if (k !== "allow") out.push(`unix_sockets: unknown key '${k}' (allowed: allow)`);
      if ("allow" in u) {
        if (!Array.isArray(u.allow)) out.push("unix_sockets.allow: must be a list of socket paths (absolute or ~/) or @abstract names");
        else (u.allow as unknown[]).forEach((v, i) => {
          const at = `unix_sockets.allow[${i}]`;
          if (typeof v !== "string" || v.trim() !== v || v === "") out.push(`${at}: must be a socket path (absolute or ~/) or an @abstract name (got ${JSON.stringify(v)})`);
          else if (v.startsWith("@")) {
            const name = v.slice(1);
            if (name === "" || name === "*") out.push(`${at}: ${v} names every abstract socket; list the names (MANDU_UNIX_POLICY=0 turns the list off)`);
            else if (name.indexOf("*") !== -1 && name.indexOf("*") !== name.length - 1) out.push(`${at}: '*' is allowed only at the end of an abstract name (a prefix)`);
          } else if (!isPathSpelling(v)) out.push(`${at}: must be a socket path (absolute or ~/) or an @abstract name (got ${JSON.stringify(v)})`);
          else if (trimSlash(v) === "/" || v === "~" || v === "~/") out.push(`${at}: ${v} would allow every socket below it, host services included; name the sockets (MANDU_UNIX_POLICY=0 turns the list off)`);
        });
      }
    }
  }
  if ("write_protect" in doc) {
    const w = doc.write_protect;
    if (!isPlainObject(w)) {
      out.push("write_protect: must be a mapping with 'deny', 'ask' and/or 'unprotect' (lists of absolute or ~/ paths)");
      return;
    }
    for (const k of Object.keys(w)) if (!["deny", "ask", "unprotect"].includes(k)) out.push(`write_protect: unknown key '${k}' (allowed: deny, ask, unprotect)`);
    for (const k of ["deny", "ask", "unprotect"] as const) {
      if (!(k in w)) continue;
      const list = w[k];
      if (!Array.isArray(list)) {
        out.push(`write_protect.${k}: must be a list of absolute or ~/ paths`);
        continue;
      }
      list.forEach((v: unknown, i: number) => {
        const at = `write_protect.${k}[${i}]`;
        if (typeof v !== "string" || !isPathSpelling(v)) out.push(`${at}: must be an absolute or ~/ path (got ${JSON.stringify(v)})`);
        else if (k !== "unprotect" && (trimSlash(v) === "/" || v === "~" || v === "~/")) out.push(`${at}: ${v} would stop the agent from changing any file; name the files or folders`);
        else if (k === "unprotect" && namesManduOwnFiles(v)) {
          out.push(`${at}: ${v} is (or holds) Mandu's own files (the Mandu home, its install directory, the symbol database, the arbiter socket); they are always protected and cannot be unprotected`);
        }
      });
    }
  }
}

/** Validate `remote_mounts:` (the caller has accepted it as a key). */
function checkRemoteMounts(doc: Record<string, unknown>, out: string[]): void {
  if (!("remote_mounts" in doc)) return;
  const r = doc.remote_mounts;
  if (!isPlainObject(r)) {
    out.push("remote_mounts: must be a mapping with 'trust_lookups' (a list of { mount, type })");
    return;
  }
  for (const k of Object.keys(r)) if (k !== "trust_lookups") out.push(`remote_mounts: unknown key '${k}' (allowed: trust_lookups)`);
  if (!("trust_lookups" in r)) return;
  if (!Array.isArray(r.trust_lookups)) {
    out.push("remote_mounts.trust_lookups: must be a list of { mount: <mount point>, type: <file-system type> }");
    return;
  }
  (r.trust_lookups as unknown[]).forEach((e, i) => {
    const at = `remote_mounts.trust_lookups[${i}]`;
    if (!isPlainObject(e)) {
      out.push(`${at}: must be { mount: <mount point>, type: <file-system type> } (got ${JSON.stringify(e)})`);
      return;
    }
    for (const k of Object.keys(e)) if (k !== "mount" && k !== "type") out.push(`${at}: unknown key '${k}' (allowed: mount, type)`);
    if (typeof e.mount !== "string" || !isPathSpelling(e.mount)) out.push(`${at}.mount: must be the mount point, an absolute or ~/ path (got ${JSON.stringify(e.mount)})`);
    if (typeof e.type !== "string" || !FSTYPE.test(e.type)) out.push(`${at}.type: must be the file-system type as /proc/self/mountinfo names it, e.g. nfs4 or fuse.sshfs (got ${JSON.stringify(e.type)})`);
  });
}

type Emit = (subject: string, detail: string) => void;

/** The relax / tighten proof for the three keys (policy-delta.ts facet `env`,
 *  beside `protect:` and `ssh_agent:`). Pure. */
export function compareGuardSettings(before: PolicyFileConfig | null, after: PolicyFileConfig | null, relax: Emit, tighten: Emit): void {
  const b = guardSettingsOf(before);
  const a = guardSettingsOf(after);
  for (const s of a.unixAllow) if (!b.unixAllow.includes(s)) relax(`unix_sockets ${s}`, `programs in the agent's tree may connect to the Unix socket ${s}`);
  for (const s of b.unixAllow) if (!a.unixAllow.includes(s)) tighten(`unix_sockets ${s}`, `the Unix socket ${s} is no longer on the allow-list`);
  // Per path, the strongest answer: deny > ask > none.
  const rank = (g: GuardSettings, p: string): number => (g.writeDeny.includes(p) ? 2 : g.writeAsk.includes(p) ? 1 : 0);
  const words = ["may be changed by the agent's programs without asking", "changes wait for your OK in Approvals", "may not be changed by the agent's programs"];
  for (const p of new Set([...b.writeDeny, ...b.writeAsk, ...a.writeDeny, ...a.writeAsk])) {
    const rb = rank(b, p), ra = rank(a, p);
    if (ra > rb) tighten(`write_protect ${p}`, `${p}: ${words[ra]}`);
    else if (ra < rb) relax(`write_protect ${p}`, `${p}: ${words[ra]}`);
  }
  for (const p of a.writeUnprotect) if (!b.writeUnprotect.includes(p)) relax(`write_protect.unprotect ${p}`, `${p} is no longer held for your OK when the agent's programs change it`);
  for (const p of b.writeUnprotect) if (!a.writeUnprotect.includes(p)) tighten(`write_protect.unprotect ${p}`, `${p} is held for your OK again when the agent's programs change it`);
  const bt = new Set(b.trustLookups.map(trustKey));
  const at = new Set(a.trustLookups.map(trustKey));
  for (const k of at) if (!bt.has(k)) relax(`remote_mounts.trust_lookups ${k}`, `programs may read a secret's real file while ${k} is visible: its server sees every name such a program looks up there`);
  for (const k of bt) if (!at.has(k)) tighten(`remote_mounts.trust_lookups ${k}`, `while ${k} is visible, programs get the placeholder instead of a secret's real file`);
}
