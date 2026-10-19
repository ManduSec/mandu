/**
 * remote-mounts — the launcher's half of "refuse raw if visible"
 * (confidentiality plan 13 §4.9, decided 2026-10-07).
 *
 * A program holding a secret sends every name it LOOKS UP on a network or
 * FUSE mount to the mount's server (a `stat`, an `open` of a missing name),
 * and the offsets of its reads there; no trap judges every path walk. So
 * the guard (net-supervisor `visible_mounts.rs`) serves a reader the
 * placeholder copy instead of the real file while such a mount is visible
 * in its mount namespace, unless the secret is bound to the mount or
 * policy.yaml trusts it for lookups:
 *
 *   remote_mounts:
 *     trust_lookups:
 *       - { mount: /home, type: nfs4 }
 *
 * This module (1) hands the trusted entries to the guard (the policy file's
 * `trustLookups`, `~` expanded), and (2) names the visible mounts at launch
 * and in `mandu doctor`, so a user whose home is on NFS knows why programs
 * get the placeholder. The classification is the guard's, kept in step by a
 * shared table (`interceptors/net-supervisor/src/visible_mounts.json`, read
 * by both test suites). Pure, but `applyTrustLookups`.
 */
import { expandHome, mergeGuardPolicy, type GuardPolicyDeps } from "./guard-policy-file.js";
import { ndjsonCall } from "./secret-setup.js";
import { parseMountinfo, type MountEntry } from "./wsl.js";

/** One `remote_mounts.trust_lookups` entry, as the arbiter compiled it. */
export interface TrustLookup {
  mount: string;
  type: string;
}

/** A mount that would see a holder's lookups. */
export interface VisibleMount {
  mount: string;
  type: string;
  source: string;
}

/** systemd's automount points of local file systems. */
const LOCAL_AUTOMOUNTS = new Set(["/proc/sys/fs/binfmt_misc", "/boot", "/efi", "/boot/efi"]);

/** The network and FUSE types (net-supervisor `local_exits::remote_fstype`). */
const REMOTE_NAMES = new Set([
  "cifs", "9p", "afs", "coda", "ncpfs", "ncp", "lustre", "beegfs", "gpfs", "orangefs", "pvfs2", "ocfs2", "gfs2",
  "glusterfs", "davfs", "vboxsf", "vmhgfs", "hostfs", "drvfs", "sshfs", "s3fs",
]);

function remoteFstype(t: string): boolean {
  if (t === "fuse" || t === "fuseblk" || t.startsWith("fuse.") || t === "virtiofs") return true;
  if (t.startsWith("nfs") || t.startsWith("smb") || t.startsWith("ceph")) return true;
  return REMOTE_NAMES.has(t);
}

/** The last value of a super option (mountinfo's comma list). */
function superOpt(opts: string, key: string): string | null {
  let v: string | null = null;
  for (const o of opts.split(",")) {
    const i = o.indexOf("=");
    if (i > 0 && o.slice(0, i) === key) v = o.slice(i + 1);
  }
  return v;
}

/** Does a mount of this type see the lookups made under it from another
 *  machine or a user-space server? The guard's `counts_for_lookups`: every
 *  network and FUSE type and an automount point; not a host share of the
 *  machine's own hypervisor or of WSL (virtiofs, 9p over virtio, xen or fd,
 *  drvfs), nor systemd's local automount points. */
export function countsForLookups(fstype: string, superOptions: string, mountPoint: string): boolean {
  const t = fstype.toLowerCase();
  if (t === "autofs") return !LOCAL_AUTOMOUNTS.has(mountPoint.length > 1 ? mountPoint.replace(/\/+$/, "") : mountPoint);
  if (t === "virtiofs" || t === "drvfs") return false;
  if (t === "9p") {
    const trans = superOpt(superOptions, "trans")?.toLowerCase() ?? null;
    return !(trans === "virtio" || trans === "xen" || trans === "fd");
  }
  return remoteFstype(t);
}

/** The mounts of a mountinfo text that see lookups, one per mount point
 *  and type. */
export function visibleRemoteMounts(mountinfo: string): VisibleMount[] {
  const out: VisibleMount[] = [];
  for (const m of parseMountinfo(mountinfo) as MountEntry[]) {
    if (!countsForLookups(m.fstype, m.superOptions, m.mountPoint)) continue;
    if (out.some((o) => o.mount === m.mountPoint && o.type === m.fstype)) continue;
    out.push({ mount: m.mountPoint, type: m.fstype, source: m.source });
  }
  return out;
}

const trimMount = (p: string): string => (p.length > 1 ? p.replace(/\/+$/, "") : p);

/** Is this mount trusted for lookups (point exact, type case-insensitive)?
 *  `trust` with `~` already expanded. */
export function isTrusted(m: VisibleMount, trust: readonly TrustLookup[]): boolean {
  return trust.some((t) => trimMount(t.mount) === trimMount(m.mount) && t.type.toLowerCase() === m.type.toLowerCase());
}

/** The entries with `~` expanded; one that cannot be (no HOME) is dropped. */
export function expandTrust(trust: readonly TrustLookup[], home: string | undefined): TrustLookup[] {
  const out: TrustLookup[] = [];
  for (const t of trust) {
    const m = expandHome(t.mount, home);
    if (m !== null) out.push({ mount: trimMount(m), type: t.type });
  }
  return out;
}

/** The destination a mount is bound by (`mount:<fstype>:<source>`). */
export function mountDestination(m: VisibleMount): string {
  return `mount:${m.type}:${m.source}`;
}

/** The launch's lines: the untrusted mounts (raw reads withheld while they
 *  are visible, and how to allow them), then the trusted ones. Empty when
 *  no such mount is visible. Pure. */
export function remoteMountNotes(visible: readonly VisibleMount[], trust: readonly TrustLookup[]): string[] {
  const untrusted = visible.filter((m) => !isTrusted(m, trust));
  const trusted = visible.filter((m) => isTrusted(m, trust));
  const lines: string[] = [];
  if (untrusted.length > 0) {
    const names = untrusted.map((m) => `${m.mount} (${m.type} from ${m.source})`).join(", ");
    const yaml = untrusted.map((m) => `{ mount: ${m.mount}, type: ${m.type} }`).join(", ");
    lines.push(
      `mandu: network or FUSE mount${untrusted.length === 1 ? "" : "s"} visible to the AI's programs: ${names}. ` +
        "While one is visible, a program you named as a reader of a secret gets the placeholder copy instead of the real file: " +
        "the mount's server would see every name that program looks up there. To allow real reads anyway, trust the mount in " +
        `policy.yaml (remote_mounts: trust_lookups: [${yaml}]), or bind the secret to it (${untrusted.map(mountDestination).join(", ")}). ` +
        "Writes there stay refused unless bound. `mandu doctor` lists them.",
    );
  }
  if (trusted.length > 0) {
    lines.push(`mandu: trusted for lookups (policy.yaml remote_mounts): ${trusted.map((m) => `${m.mount} (${m.type})`).join(", ")}; programs holding a secret may look names up there`);
  }
  return lines;
}

/** What `mandu doctor` reports: the visible mounts, and the trusted
 *  entries (`~` expanded), or null when policy.yaml could not be read
 *  (the Mandu service is not running). */
export interface RemoteMountFacts {
  visible: VisibleMount[];
  trusted: TrustLookup[] | null;
}

/** `remote_mounts.trust_lookups` from the arbiter (`guardSettings`), or
 *  null when it cannot be asked. */
export async function readTrustLookups(
  sock: string,
  call: (sock: string, op: string) => Promise<unknown> = (s, op) => ndjsonCall(s, op, {}, 1_500),
): Promise<TrustLookup[] | null> {
  try {
    const r = (await call(sock, "guardSettings")) as { trustLookups?: unknown };
    const v = Array.isArray(r?.trustLookups) ? (r.trustLookups as unknown[]) : [];
    return v
      .filter((x): x is TrustLookup => typeof x === "object" && x !== null && typeof (x as TrustLookup).mount === "string" && typeof (x as TrustLookup).type === "string")
      .map((x) => ({ mount: x.mount, type: x.type }));
  } catch {
    return null;
  }
}

/** Hand the trusted entries to the guard (`trustLookups` in its policy
 *  file), only where a policy file with secrets exists (no secret, no raw
 *  open to withhold, and a new policy file would make the guard trap every
 *  open). Returns whether it was written. */
export function applyTrustLookups(trust: readonly TrustLookup[], mutEnv: Record<string, string>, deps: GuardPolicyDeps & { home: string | undefined }): boolean {
  if (!mutEnv["MANDU_NET_GUARD_SECRETS"]) return false;
  const expanded = expandTrust(trust, deps.home);
  if (expanded.length === 0) return false;
  mergeGuardPolicy(mutEnv, deps, { trustLookups: expanded.map((t) => ({ mount: t.mount, type: t.type })) });
  return true;
}
