/**
 * bwrap-grant.test — Mandu's own bubblewrap (src/bwrap-grant.ts;
 * rootless-confinement-ubuntu-2404.md §12.3): when the launch trusts the copy,
 * when it is stale, which old grants are still ours, and the doctor wording.
 * Pure over injected file facts; the real profile is VM-verified (§12.3).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ADMIN_BWRAP_FIX,
  adminBwrapRefusedReason,
  agentBwrapDir,
  bwrapLaunchNotes,
  type BwrapLaunchDeps,
  isOurs,
  legacyGrantWarning,
  MANDU_BWRAP,
  MANDU_BWRAP_DIR,
  MANDU_BWRAP_PROBE_ARGV,
  manduBwrapInForce,
  manduBwrapInstalled,
  manduBwrapStale,
  resolveWrapBwrap,
  staleLegacyProfiles,
  SYSTEM_BWRAP,
  type BwrapGrantDeps,
  type FileStat,
} from "../../src/bwrap-grant.js";
import { bwrapGrantRows } from "../../src/doctor.js";

const root = (mode: number, isFile = false): FileStat => ({ uid: 0, mode, isFile });
function host(o: { files?: Record<string, FileStat | null>; bytes?: Record<string, string>; probe?: boolean } = {}) {
  const files: Record<string, FileStat | null> = {
    "/usr/lib/mandu": root(0o40755), [MANDU_BWRAP_DIR]: root(0o40755), [MANDU_BWRAP]: root(0o100755, true), ...o.files,
  };
  const ran: Array<[string, readonly string[]]> = [];
  const deps: BwrapGrantDeps = {
    stat: (p) => files[p] ?? null,
    readFile: (p) => (o.bytes?.[p] !== undefined ? Buffer.from(o.bytes[p]!) : null),
    run: (cmd, args) => { ran.push([cmd, args]); return o.probe ?? true; },
  };
  return { deps, ran };
}

test("in force: a root-owned copy in root-owned dirs whose grant is loaded (the probe passes)", () => {
  const h = host();
  assert.equal(manduBwrapInForce(h.deps), true);
  assert.deepEqual(h.ran, [[MANDU_BWRAP, MANDU_BWRAP_PROBE_ARGV]]);
  assert.equal(manduBwrapInForce(host({ probe: false }).deps), false, "profile not loaded");
  assert.equal(manduBwrapInForce(host({ files: { [MANDU_BWRAP]: null } }).deps), false, "not installed");
});

test("never trusted when anyone but root could replace it: a grant on a writable path is anyone's grant", () => {
  const cases: Array<[string, FileStat]> = [
    [MANDU_BWRAP, { uid: 1000, mode: 0o100755, isFile: true }],
    [MANDU_BWRAP, root(0o100775, true)],
    [MANDU_BWRAP_DIR, root(0o40777)],
    ["/usr/lib/mandu", { uid: 1000, mode: 0o40755, isFile: false }],
  ];
  for (const [path, st] of cases) {
    const h = host({ files: { [path]: st } });
    assert.equal(manduBwrapInstalled(h.deps), false, `${path} ${st.uid}:${st.mode.toString(8)}`);
    assert.equal(manduBwrapInForce(h.deps), false);
    assert.equal(h.ran.length, 0, "the untrusted copy is never even run");
  }
});

test("stale: the copy's bytes differ from the system bwrap (a bubblewrap update since mandu setup)", () => {
  assert.equal(manduBwrapStale(host({ bytes: { [MANDU_BWRAP]: "v1", [SYSTEM_BWRAP]: "v1" } }).deps), false);
  assert.equal(manduBwrapStale(host({ bytes: { [MANDU_BWRAP]: "v1", [SYSTEM_BWRAP]: "v2" } }).deps), true);
  assert.equal(manduBwrapStale(host({ bytes: { [MANDU_BWRAP]: "v1" } }).deps), false, "no system bwrap: nothing to compare");
});

test("resolveWrapBwrap: the copy when in force, else the distribution's by absolute path, else none (never a bare `bwrap`)", () => {
  assert.equal(resolveWrapBwrap(true, () => "/usr/bin/bwrap"), MANDU_BWRAP);
  assert.equal(resolveWrapBwrap(false, () => "/usr/bin/bwrap"), "/usr/bin/bwrap");
  assert.equal(resolveWrapBwrap(false, () => null), null);
  // The real resolver: absolute or nothing.
  const real = resolveWrapBwrap(false);
  assert.ok(real === null || real.startsWith("/"), `got ${real}`);
});

test("launch notes: an administrator's bwrap_path that cannot be used is one WARNING naming why; Mandu runs no other", () => {
  const d = { ...launchDeps({ copy: null, sys: "ELF-A" }), admin: () => ({ kind: "refused" as const, file: "/etc/mandu/policy.d/10.yaml", why: "/opt/bw/bwrap (bwrap_path in /etc/mandu/policy.d/10.yaml) does not exist" }) };
  const notes = bwrapLaunchNotes(d);
  assert.equal(notes.length, 1);
  assert.match(notes[0]!, /^mandu: WARNING — your administrator's bubblewrap cannot be used: \/opt\/bw\/bwrap .*does not exist; Mandu runs no other bubblewrap in its place/);
  // One wording for the launch, doctor and `mandu setup`.
  const why = "/opt/bw/bwrap (bwrap_path in /etc/mandu/policy.d/10.yaml) does not exist";
  assert.equal(notes[0], `mandu: WARNING — ${adminBwrapRefusedReason(why)}; fix: ${ADMIN_BWRAP_FIX}`);
  assert.deepEqual(bwrapLaunchNotes({ ...launchDeps({ copy: null, sys: "ELF-A" }), admin: () => ({ kind: "path" as const, path: "/opt/bw/bwrap", file: "/etc/mandu/policy.d/10.yaml" }) }), [], "a usable one says nothing at launch");
});

test("agentBwrapDir: the agent's PATH gets the copy's directory, else the administrator's, else none; a refused one adds nothing", () => {
  const never = (): never => { throw new Error("not asked when the copy is in force"); };
  assert.equal(agentBwrapDir(true, never), MANDU_BWRAP_DIR);
  // The command box takes the first bwrap on PATH outside the workspace
  // (exec-supervisor resolve_bwrap; kernel_integration.rs
  // exec_box_bin_runs_only_the_resolved_system_bwrap), so this directory
  // ahead of the system one is how it runs the administrator's.
  assert.equal(agentBwrapDir(false, () => ({ bin: "/opt/bw/bin/bwrap", source: "admin" })), "/opt/bw/bin");
  assert.equal(agentBwrapDir(false, () => ({ bin: "/usr/bin/bwrap", source: "path" })), undefined, "the distribution's is on PATH already");
  assert.equal(agentBwrapDir(false, () => ({ bin: null, source: null, refused: "not root's alone" })), undefined);
  assert.equal(agentBwrapDir(false, () => ({ bin: null, source: null })), undefined);
});

test("doctor rows: an administrator's bwrap_path in use is a ✓ naming it; one that cannot be used is a ✗ with the fix", () => {
  const base = { inForce: false, stale: false, legacy: [], distroBwrap: false };
  const used = bwrapGrantRows({ ...base, admin: { kind: "path", path: "/opt/bw/bwrap", file: "/etc/mandu/policy.d/10.yaml" } });
  assert.match(used.join("\n"), /✓ bubblewrap: your administrator's \(\/opt\/bw\/bwrap, bwrap_path in \/etc\/mandu\/policy\.d\/10\.yaml\)/);
  const refused = bwrapGrantRows({ ...base, admin: { kind: "refused", file: "/etc/mandu/policy.d/10.yaml", why: "it is not root's alone" } });
  assert.match(refused.join("\n"), /✗ your administrator's bubblewrap cannot be used: it is not root's alone; Mandu runs no other bubblewrap in its place/);
  assert.match(refused.join("\n"), /fix: ask your administrator/);
  // The copy's staleness names what the copy is made from.
  const stale = bwrapGrantRows({ ...base, inForce: true, stale: true, admin: { kind: "path", path: "/opt/bw/bwrap", file: "/x.yaml" } });
  assert.match(stale.join("\n"), /it is older than \/opt\/bw\/bwrap/);
});

test("staleLegacyProfiles: only the Mandu-marked old files, never a site's own", () => {
  const files: Record<string, string> = {
    "/etc/apparmor.d/bwrap": "# Mandu: grant …\nprofile bwrap /usr/bin/bwrap flags=(unconfined) {\n}\n",
    "/etc/apparmor.d/unshare": "profile unshare /usr/bin/unshare {\n}\n",
  };
  assert.deepEqual(staleLegacyProfiles((p) => files[p] ?? null), ["bwrap"]);
  assert.equal(isOurs(files["/etc/apparmor.d/unshare"]!), false);
});

test("legacyGrantWarning + doctor rows: name the host-wide override where Ubuntu's own bwrap profile exists (fork H req. 4)", () => {
  assert.equal(legacyGrantWarning([], true), null);
  assert.match(legacyGrantWarning(["bwrap"], true)!, /shares the name of Ubuntu's own `bwrap` profile.*every program on this machine.*fix: mandu setup/);
  assert.match(legacyGrantWarning(["unshare"], false)!, /every program on this machine create a user namespace through unshare/);
  // Both files: each names its own danger. The unshare one is live whichever
  // `bwrap` profile won (a real do-release-upgrade kept Ubuntu's bwrap and
  // Mandu's unshare, os-test-matrix.md §10.15).
  const both = legacyGrantWarning(["bwrap", "unshare"], true)!;
  assert.match(both, /\(\/etc\/apparmor\.d\/bwrap and \/etc\/apparmor\.d\/unshare\): the bwrap one shares the name of Ubuntu's own `bwrap` profile.*, and the unshare one lets every program on this machine create a user namespace through unshare; fix: mandu setup/);
  assert.match(legacyGrantWarning(["bwrap", "unshare"], false)!, /the bwrap one lets every program .* through bwrap, and the unshare one lets every program .* through unshare; fix/);
  assert.match(legacyGrantWarning(["bwrap"], false)!, /\): it lets every program on this machine create a user namespace through bwrap; fix/);
  const rows = bwrapGrantRows({ inForce: true, stale: true, legacy: ["bwrap", "unshare"], distroBwrap: true });
  assert.match(rows[0]!, /^ {2}✗ an older Mandu grant is still installed \(\/etc\/apparmor\.d\/bwrap and \/etc\/apparmor\.d\/unshare\)/);
  assert.match(rows[1]!, /^ {2}✓ Mandu's own bubblewrap: installed \(\/usr\/lib\/mandu\/bin\/bwrap\)/);
  assert.match(rows[2]!, /older than \/usr\/bin\/bwrap .*run `mandu setup` to refresh/);
  assert.deepEqual(bwrapGrantRows({ inForce: false, stale: false, legacy: [], distroBwrap: false }), []);
  assert.deepEqual(bwrapGrantRows(undefined), []);
});

// ---- every launch: the copy vs the system bwrap, and old grants ----------
function launchDeps(o: { copy?: string | null; sys?: string | null; versions?: Record<string, string | null>; texts?: Record<string, string>; exists?: string[] }): BwrapLaunchDeps & { versionCalls: string[] } {
  const versionCalls: string[] = [];
  const files: Record<string, string | null | undefined> = { [MANDU_BWRAP]: o.copy, [SYSTEM_BWRAP]: o.sys };
  return {
    versionCalls,
    readFile: (p) => (typeof files[p] === "string" ? Buffer.from(files[p] as string) : null),
    readText: (p) => o.texts?.[p] ?? null,
    exists: (p) => (o.exists ?? []).includes(p),
    version: (b) => { versionCalls.push(b); return o.versions?.[b] ?? null; },
  };
}

test("launch notes: an identical copy says nothing and never runs --version", () => {
  const d = launchDeps({ copy: "ELF-A", sys: "ELF-A" });
  assert.deepEqual(bwrapLaunchNotes(d), []);
  assert.deepEqual(d.versionCalls, [], "the version is read only when the bytes differ");
});

test("launch notes: no copy installed (no mandu setup) says nothing", () => {
  assert.deepEqual(bwrapLaunchNotes(launchDeps({ copy: null, sys: "ELF-A" })), []);
});

test("launch notes: a copy left behind by a bubblewrap update names both versions and the fix", () => {
  const d = launchDeps({ copy: "ELF-A", sys: "ELF-B", versions: { [MANDU_BWRAP]: "bubblewrap 0.9.0", [SYSTEM_BWRAP]: "bubblewrap 0.11.1" } });
  const [line, ...rest] = bwrapLaunchNotes(d);
  assert.equal(rest.length, 0);
  assert.match(line!, /WARNING/, "an attention line: shown without --verbose");
  assert.match(line!, /bubblewrap 0\.9\.0/);
  assert.match(line!, /bubblewrap 0\.11\.1/);
  assert.match(line!, /fix: mandu setup/);
  assert.doesNotMatch(line!, /same version string/);
});

test("launch notes: a patched build with the same version string still warns", () => {
  const d = launchDeps({ copy: "ELF-A", sys: "ELF-B", versions: { [MANDU_BWRAP]: "bubblewrap 0.9.0", [SYSTEM_BWRAP]: "bubblewrap 0.9.0" } });
  assert.match(bwrapLaunchNotes(d)[0]!, /same version string, a different build/);
});

test("launch notes: an old Mandu grant is flagged, naming the host-wide override where Ubuntu's profile exists", () => {
  const texts = { "/etc/apparmor.d/bwrap": "# Mandu: old grant\nprofile bwrap /usr/bin/bwrap flags=(unconfined) { userns, }\n" };
  const on2604 = bwrapLaunchNotes(launchDeps({ texts, exists: ["/etc/apparmor.d/bwrap-userns-restrict"] }));
  assert.equal(on2604.length, 1);
  assert.match(on2604[0]!, /WARNING.*older Mandu grant.*every program on this machine/);
  const foreign = bwrapLaunchNotes(launchDeps({ texts: { "/etc/apparmor.d/bwrap": "profile bwrap /usr/bin/bwrap {}\n" } }));
  assert.deepEqual(foreign, [], "a profile Mandu did not write is not ours to flag");
});
