/**
 * setup.test — `mandu setup` (rootless-confinement-ubuntu-2404.md §3.2, §12.3):
 * the unprivileged half (plan, print, detect) + the executor against a fake
 * sudo. Mandu's own bubblewrap replaces the pre-2026-09-27 `/usr/bin/bwrap` +
 * `unshare` grants, which setup MIGRATES away from without ever unloading a
 * profile name Ubuntu's own file also defines. The real install is the
 * fresh-install VM suite (steps 5-9 and 5m).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  filesDefiningProfile,
  installCommands,
  isOurs,
  legacyRemovalCommands,
  planSetup,
  renderPrint,
  runSetup,
  uninstallCommands,
  type SetupDeps,
  type SetupFacts,
} from "../../src/setup.js";
import { ADMIN_BWRAP_FIX, adminBwrapRefusedReason, MANDU_BWRAP, MANDU_PROFILE_FILE } from "../../src/bwrap-grant.js";
import { bwrapGrantRows } from "../../src/doctor.js";
import { ASSET_SOURCES, Layout } from "../../src/services/layout.js";
import { tmpDir } from "../lib/tmp-dir.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const PROFILE = readFileSync(resolve(repoRoot, "scripts/apparmor/mandu-bwrap"), "utf8");
const PROFILE_SRC = "/pkg/dist/apparmor/mandu-bwrap";
/** A pre-2026-09-27 Mandu grant, as it sat in /etc/apparmor.d. */
const OLD_BWRAP = "# Mandu: grant bubblewrap …\nabi <abi/4.0>,\nprofile bwrap /usr/bin/bwrap flags=(unconfined) {\n  userns,\n}\n";
const OLD_UNSHARE = "# Mandu: grant unshare …\nprofile unshare /usr/bin/unshare flags=(unconfined) {\n  userns,\n}\n";
const DISTRO = "/etc/apparmor.d/bwrap-userns-restrict";

/** A stock 24.04 with bubblewrap installed: restricted, nothing granted. */
const stock2404 = (o: Partial<SetupFacts> = {}): SetupFacts => ({
  platform: "linux", systemBwrap: "/usr/bin/bwrap", usernsOk: false, nestingOk: false,
  apparmorRestricted: true, apparmorParser: true, copy: "absent", profileFile: null,
  legacy: { bwrap: null, unshare: null }, sameName: { bwrap: [], unshare: [] },
  usernsHint: "the probe failed", ...o,
});
/** A stock 26.04: the distro profile grants userns but forbids nesting. */
const stock2604 = (o: Partial<SetupFacts> = {}): SetupFacts =>
  stock2404({ usernsOk: true, nestingOk: false, sameName: { bwrap: [DISTRO], unshare: [] }, ...o });
/** Either, after `mandu setup`. */
const done = (base: SetupFacts): SetupFacts => ({ ...base, usernsOk: true, nestingOk: true, copy: "current", profileFile: PROFILE, legacy: { bwrap: null, unshare: null } });

// ── planSetup ────────────────────────────────────────────────────────────────

test("planSetup: installs Mandu's bubblewrap on a stock 24.04 AND on a stock 26.04 (userns there, but no nesting)", () => {
  assert.deepEqual(planSetup(stock2404(), PROFILE), { kind: "apply", install: true, removeLegacy: [] });
  assert.deepEqual(planSetup(stock2604(), PROFILE), { kind: "apply", install: true, removeLegacy: [] });
});

test("planSetup: nothing to do once installed, off Linux, or where the host needs no grant", () => {
  assert.equal(planSetup(done(stock2404()), PROFILE).kind, "nothing");
  assert.equal(planSetup(done(stock2604()), PROFILE).kind, "nothing");
  assert.equal(planSetup(stock2404({ platform: "darwin" }), PROFILE).kind, "nothing");
  // no AppArmor restriction (Debian, Fedora…): any bwrap works
  assert.equal(planSetup(stock2404({ apparmorRestricted: false, usernsOk: true, nestingOk: true }), PROFILE).kind, "nothing");
  // a site profile already lets the system bwrap nest: decided by the probes
  assert.equal(planSetup(stock2404({ usernsOk: true, nestingOk: true }), PROFILE).kind, "nothing");
});

test("planSetup: refreshes a stale copy or a changed profile", () => {
  assert.equal((planSetup({ ...done(stock2404()), copy: "stale" }, PROFILE) as { install: boolean }).install, true);
  assert.equal((planSetup({ ...done(stock2404()), profileFile: PROFILE + "\n# older\n" }, PROFILE) as { install: boolean }).install, true);
  // installed but its grant is not in force (nesting fails): re-install + reload
  assert.equal((planSetup({ ...done(stock2604()), nestingOk: false }, PROFILE) as { install: boolean }).install, true);
});

test("planSetup: an old Mandu grant is removed even where nothing else is needed (fork H: it silently disables Ubuntu's restriction after an upgrade)", () => {
  // 26.04 after an upgrade from 24.04: Mandu's leftover wins, so the probes PASS. Still migrate.
  const upgraded = stock2604({ usernsOk: true, nestingOk: true, legacy: { bwrap: OLD_BWRAP, unshare: OLD_UNSHARE } });
  assert.deepEqual(planSetup(upgraded, PROFILE), { kind: "apply", install: true, removeLegacy: ["bwrap", "unshare"] });
  // already on the new grant, legacy left over: remove it, install nothing
  assert.deepEqual(planSetup({ ...done(stock2404()), legacy: { bwrap: OLD_BWRAP, unshare: null } }, PROFILE),
    { kind: "apply", install: false, removeLegacy: ["bwrap"] });
  // a site's own /etc/apparmor.d/bwrap is never touched
  assert.deepEqual((planSetup(stock2404({ legacy: { bwrap: "profile bwrap /usr/bin/bwrap {}", unshare: null } }), PROFILE) as { removeLegacy: string[] }).removeLegacy, []);
});

test("planSetup: blocked where setup cannot help, with the fix", () => {
  const noBwrap = planSetup(stock2404({ systemBwrap: null }), PROFILE);
  assert.equal(noBwrap.kind, "blocked");
  assert.match((noBwrap as { fix: string }).fix, /apt install bubblewrap/);
  const other = planSetup(stock2404({ apparmorRestricted: false, usernsHint: "kernel.unprivileged_userns_clone=0" }), PROFILE);
  assert.equal(other.kind, "blocked");
  assert.match((other as { reason: string }).reason, /unprivileged_userns_clone=0/);
  assert.equal(planSetup(stock2404({ apparmorParser: false }), PROFILE).kind, "blocked");
  // a foreign file at Mandu's profile path is never overwritten
  const foreign = planSetup(stock2404({ profileFile: "profile x {}" }), PROFILE);
  assert.equal(foreign.kind, "blocked");
  assert.match((foreign as { reason: string }).reason, /not created by Mandu/);
  // no bubblewrap, but an old grant to remove: remove it, say why nothing is installed
  const half = planSetup(stock2404({ systemBwrap: null, legacy: { bwrap: null, unshare: OLD_UNSHARE } }), PROFILE);
  assert.deepEqual(half, { kind: "apply", install: false, removeLegacy: ["unshare"], note: "bubblewrap (`bwrap`) is not installed, and Mandu's copy is made from it" });
});

// ── the commands ─────────────────────────────────────────────────────────────

test("installCommands: root-owned copy at Mandu's path, profile, load; nothing named or attached like a distro profile", () => {
  const c = installCommands({ bwrap: "/usr/bin/bwrap", profile: PROFILE_SRC });
  assert.deepEqual(c, [
    ["install", "-d", "-m", "0755", "-o", "root", "-g", "root", "/usr/lib/mandu", "/usr/lib/mandu/bin"],
    ["install", "-m", "0755", "-o", "root", "-g", "root", "/usr/bin/bwrap", MANDU_BWRAP],
    ["install", "-m", "0644", "-o", "root", "-g", "root", PROFILE_SRC, MANDU_PROFILE_FILE],
    ["apparmor_parser", "-r", MANDU_PROFILE_FILE],
  ]);
  assert.ok(!c.flat().some((a) => a === "/etc/apparmor.d/bwrap" || a === "/etc/apparmor.d/unshare"));
  // the shipped profile names only Mandu profiles and attaches to Mandu's path only
  const names = [...PROFILE.matchAll(/^profile\s+(\S+)(?:\s+(\/\S+))?/gm)].map((m) => [m[1], m[2]]);
  assert.deepEqual(names, [["mandu_bwrap", MANDU_BWRAP], ["mandu_child", undefined]]);
});

test("legacyRemovalCommands: a name Ubuntu's file shares is never unloaded by name: delete ours, reload theirs (fork H req. 3)", () => {
  assert.deepEqual(legacyRemovalCommands("bwrap", [DISTRO]), [["rm", "-f", "/etc/apparmor.d/bwrap"], ["apparmor_parser", "-r", DISTRO]]);
  assert.deepEqual(legacyRemovalCommands("unshare", []), [["apparmor_parser", "-R", "/etc/apparmor.d/unshare"], ["rm", "-f", "/etc/apparmor.d/unshare"]]);
});

test("filesDefiningProfile: finds the other files that define a profile name, not ours, not a prefix", () => {
  const dir = tmpDir("aa-");
  writeFileSync(join(dir, "bwrap"), OLD_BWRAP);
  writeFileSync(join(dir, "bwrap-userns-restrict"), "abi <abi/5.0>,\nprofile bwrap /usr/bin/bwrap flags=(attach_disconnected) {\n}\nprofile unpriv_bwrap {\n}\n");
  writeFileSync(join(dir, "glycin.bwrap"), "profile glycin_bwrap /usr/bin/bwrap {\n}\n");
  mkdirSync(join(dir, "local"));
  assert.deepEqual(filesDefiningProfile("bwrap", join(dir, "bwrap"), dir), [join(dir, "bwrap-userns-restrict")]);
  assert.deepEqual(filesDefiningProfile("unshare", join(dir, "unshare"), dir), []);
});

// ── the shipped asset ────────────────────────────────────────────────────────

test("assets: Layout.asset resolves the in-tree profile (dev) / dist/ (installed); sources mirror the bundle manifest", () => {
  const manifest = JSON.parse(readFileSync(resolve(repoRoot, "launcher/bundle-manifest.json"), "utf8")) as { assets: Record<string, string> };
  assert.deepEqual(manifest.assets, ASSET_SOURCES);
  assert.equal(Layout.dev(repoRoot).asset("apparmor/mandu-bwrap"), resolve(repoRoot, "scripts/apparmor/mandu-bwrap"));
  assert.equal(Layout.installed("/opt/pkg").asset("apparmor/mandu-bwrap"), "/opt/pkg/dist/apparmor/mandu-bwrap");
  assert.throws(() => Layout.dev(repoRoot).asset("apparmor/bwrap"), "the old grant is no longer shipped");
  assert.ok(PROFILE.startsWith("# Mandu:"), "the ownership marker --uninstall relies on");
});

test("--print: the profile byte for byte, the manual commands, the old grants' removal when present; the sysctl only as the non-preferred alternative", () => {
  const out = renderPrint({ path: PROFILE_SRC, text: PROFILE }, [{ name: "bwrap", sameName: [DISTRO] }]);
  assert.ok(out.includes(PROFILE.replace(/\n$/, "")), "profile text is not verbatim");
  for (const c of installCommands({ bwrap: "/usr/bin/bwrap", profile: PROFILE_SRC })) assert.ok(out.includes(`sudo ${c.join(" ")}`));
  assert.ok(out.includes(`sudo rm -f /etc/apparmor.d/bwrap`) && out.includes(`sudo apparmor_parser -r ${DISTRO}`));
  for (const c of uninstallCommands()) assert.ok(out.includes(`sudo ${c.join(" ")}`));
  assert.match(out, /NOT preferred.*apparmor_restrict_unprivileged_userns=0/);
  assert.equal(out.match(/sysctl -w/g)?.length, 1);
  assert.ok(!renderPrint({ path: PROFILE_SRC, text: PROFILE }).includes("older Mandu grants"));
});

// ── runSetup against a fake sudo ─────────────────────────────────────────────

function harness(facts: SetupFacts, o: { confirm?: boolean; isTTY?: boolean; sudoStatus?: number; afterInstallOk?: boolean } = {}) {
  const ran: string[][] = [];
  let out = "", err = "";
  const deps: SetupDeps = {
    facts: () => (ran.length > 0 && o.afterInstallOk !== false ? done(facts) : facts),
    profile: () => ({ path: PROFILE_SRC, text: PROFILE }),
    sudo: (argv) => { ran.push(argv); return o.sudoStatus ?? 0; },
    confirm: async () => o.confirm ?? true,
    isTTY: o.isTTY ?? true,
    out: (s) => { out += s; },
    err: (s) => { err += s; },
  };
  return { deps, ran, text: () => ({ out, err }) };
}

test("runSetup: explains, shows the exact profile + commands, installs on yes, re-probes, reports confined with the mount layer", async () => {
  const h = harness(stock2604());
  assert.equal(await runSetup([], h.deps), 0);
  assert.deepEqual(h.ran, installCommands({ bwrap: "/usr/bin/bwrap", profile: PROFILE_SRC }));
  const { out } = h.text();
  assert.match(out, /profile mandu_bwrap \/usr\/lib\/mandu\/bin\/bwrap/);
  assert.match(out, /sudo apparmor_parser -r \/etc\/apparmor\.d\/mandu-bwrap/);
  assert.match(out, /the mount layer is on; with Mandu's file guard, secrets are `confined`/);
});

test("runSetup: the migration installs the new grant FIRST, then removes the old ones the safe way", async () => {
  const h = harness(stock2604({ usernsOk: true, nestingOk: true, legacy: { bwrap: OLD_BWRAP, unshare: OLD_UNSHARE } }));
  assert.equal(await runSetup(["--yes"], h.deps), 0);
  assert.deepEqual(h.ran, [
    ...installCommands({ bwrap: "/usr/bin/bwrap", profile: PROFILE_SRC }),
    ["rm", "-f", "/etc/apparmor.d/bwrap"], ["apparmor_parser", "-r", DISTRO],
    ["apparmor_parser", "-R", "/etc/apparmor.d/unshare"], ["rm", "-f", "/etc/apparmor.d/unshare"],
  ]);
  assert.match(h.text().out, /overrides Ubuntu's own bwrap profile/);
});

test("runSetup: a no answers nothing runs; a non-TTY without --yes refuses; --yes skips the prompt", async () => {
  const no = harness(stock2404(), { confirm: false });
  assert.equal(await runSetup([], no.deps), 1);
  assert.equal(no.ran.length, 0);
  const pipe = harness(stock2404(), { isTTY: false });
  assert.equal(await runSetup([], pipe.deps), 1);
  assert.equal(pipe.ran.length, 0);
  assert.match(pipe.text().err, /--yes/);
  const yes = harness(stock2404(), { isTTY: false, confirm: false });
  assert.equal(await runSetup(["--yes"], yes.deps), 0);
  assert.equal(yes.ran.length, 4);
});

test("runSetup: nothing-to-do is exit 0 and runs nothing; blocked is exit 1 with the fix; bad flag is 2", async () => {
  const ok = harness(done(stock2404()));
  assert.equal(await runSetup([], ok.deps), 0);
  assert.match(ok.text().out, /nothing to do/);
  assert.equal(ok.ran.length, 0);
  const blocked = harness(stock2404({ systemBwrap: null }));
  assert.equal(await runSetup([], blocked.deps), 1);
  assert.match(blocked.text().err, /apt install bubblewrap/);
  assert.equal(await runSetup(["--frob"], harness(stock2404()).deps), 2);
});

test("runSetup: an administrator's bwrap_path that cannot be used is named in doctor's words, never \"not installed\"", async () => {
  const why = "/opt/bw/bwrap (bwrap_path in /etc/mandu/policy.d/10.yaml) is not root's alone (it, or a directory above it, is not root-owned or is writable by others)";
  const refused = stock2404({ systemBwrap: null, adminRefused: why });
  const plan = planSetup(refused, PROFILE);
  assert.deepEqual(plan, { kind: "blocked", reason: adminBwrapRefusedReason(why), fix: ADMIN_BWRAP_FIX });
  // The same where AppArmor restricts nothing: the probe fails for want of a
  // bubblewrap Mandu may run, not for a kernel setting.
  assert.deepEqual(planSetup(stock2404({ ...refused, apparmorRestricted: false }), PROFILE), plan);
  // An old grant to remove still goes, with the administrator's reason as the note.
  const half = planSetup(stock2404({ ...refused, legacy: { bwrap: null, unshare: OLD_UNSHARE } }), PROFILE);
  assert.deepEqual(half, { kind: "apply", install: false, removeLegacy: ["unshare"], note: adminBwrapRefusedReason(why) });

  const h = harness(refused);
  assert.equal(await runSetup([], h.deps), 1);
  assert.equal(h.ran.length, 0);
  const err = h.text().err;
  assert.doesNotMatch(err, /not installed|apt install/);
  // Word for word what `mandu doctor` shows (bwrapGrantRows).
  const doctor = bwrapGrantRows({ inForce: false, stale: false, legacy: [], distroBwrap: false, admin: { kind: "refused", file: "/etc/mandu/policy.d/10.yaml", why } });
  assert.equal(err, `mandu setup: cannot upgrade this host: ${adminBwrapRefusedReason(why)}.\n  fix: ${ADMIN_BWRAP_FIX}\n`);
  assert.equal(doctor[0], `  ✗ ${adminBwrapRefusedReason(why)}`);
  assert.equal(doctor[1], `    fix: ${ADMIN_BWRAP_FIX}`);
  assert.match(err, /your administrator's bubblewrap cannot be used: \/opt\/bw\/bwrap .*is not root's alone/);
});

test("runSetup: a failing sudo stops at once; a still-failing probe after install is reported, not papered over", async () => {
  const fail = harness(stock2404(), { sudoStatus: 1 });
  assert.equal(await runSetup(["--yes"], fail.deps), 1);
  assert.equal(fail.ran.length, 1);
  const still = harness(stock2404(), { afterInstallOk: false });
  assert.equal(await runSetup(["--yes"], still.deps), 1);
  assert.match(still.text().err, /still cannot create a user namespace/);
});

test("isOurs: the Mandu marker is ours; a foreign file is not", () => {
  assert.equal(isOurs(PROFILE), true);
  assert.equal(isOurs("profile bwrap /usr/bin/bwrap {}"), false);
  assert.equal(isOurs(null), false);
});

test("runSetup --uninstall: removes Mandu's bwrap + profile and any old grant, never a foreign file", async () => {
  const h = harness({ ...done(stock2604()), legacy: { bwrap: OLD_BWRAP, unshare: "profile unshare /usr/bin/unshare {}" } });
  assert.equal(await runSetup(["--uninstall", "--yes"], h.deps), 0);
  assert.deepEqual(h.ran, [...uninstallCommands(), ["rm", "-f", "/etc/apparmor.d/bwrap"], ["apparmor_parser", "-r", DISTRO]]);
  assert.match(h.text().out, /unshare was not created by Mandu: left untouched/);
  // Mandu's profile names are its own, so unloading by file is safe
  assert.deepEqual(uninstallCommands()[0], ["apparmor_parser", "-R", MANDU_PROFILE_FILE]);
  const none = harness(stock2404());
  assert.equal(await runSetup(["--uninstall"], none.deps), 0);
  assert.equal(none.ran.length, 0);
  assert.match(none.text().out, /nothing to remove/);
});
