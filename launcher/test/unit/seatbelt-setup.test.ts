/**
 * seatbelt-setup.test — assembling and applying the macOS whole-agent
 * Seatbelt profile (seatbelt-setup.ts): which component comes from where,
 * what is left out and said, the wrap carrying the profile's text, where its
 * copy lands, and what refuses the launch. The profile's rules run in
 * test/darwin/; here only the wrap's argv[0] is spawned, to show a PATH entry
 * cannot stand in for it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { applySeatbelt, manduStatePaths, profileSealsHome, writeProfileCopy, type HomeSealFacts, type SeatbeltSetupInput } from "../../src/seatbelt-setup.js";
import { emptyMutation } from "../../src/backend/types.js";
import { unixPolicy } from "../../src/unix-policy.js";
import { writeProtectList } from "../../src/write-protect.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the profile's secrets-mode components; no arbiter here

const HOME = "/Users/u";
const NOFS = { exists: () => false, isDir: () => false, read: () => null };

function input(over: Partial<SeatbeltSetupInput> = {}): SeatbeltSetupInput {
  return {
    plan: { eventDir: "/rt/sid/events", arbiterSock: "/sock/arbiter.sock", arbiterRuntimeBase: "/rt", humanCwd: "/Users/u/proj", cwd: "/Users/u/proj" },
    env: { HOME },
    scopeRunDir: "/rt/sid",
    secrets: { secrets: ["/Users/u/.aws/credentials"], noDelete: [] },
    runtimeRegistry: false,
    sealState: true,
    writeProtect: null,
    net: null,
    unix: null,
    available: true,
    ...over,
  };
}

function run(inp: SeatbeltSetupInput, extra: { realpath?: (p: string) => string | null; accountHome?: string | null } = {}) {
  const logs: string[] = [];
  const written: Array<{ dir: string; path: string; text: string }> = [];
  const mut = emptyMutation();
  const r = applySeatbelt(inp, mut, {
    log: (m) => logs.push(m),
    realpath: extra.realpath ?? (() => null),
    writeProfile: (dir, path, text) => { written.push({ dir, path, text }); },
    uid: 501,
    // Pinned: this host's own account must not decide the home seal.
    accountHome: extra.accountHome === undefined ? null : extra.accountHome,
  });
  return { r, logs, written, mut };
}

test("no sandbox-exec ⇒ nothing applied, nothing said (the secret setup and the network rung already said GATED / WITHOUT)", () => {
  const { r, logs, mut } = run(input({ available: false }));
  assert.equal(r, null);
  assert.deepEqual(mut.launchPrefix, []);
  assert.deepEqual(logs, []);
});

test("nothing to carry ⇒ no wrap (mode off with --no-landlock-net)", () => {
  const { r, mut } = run(input({ secrets: undefined, sealState: false }));
  assert.equal(r, null);
  assert.deepEqual(mut.launchPrefix, []);
});

test("sandbox-exec wraps INSIDE whatever came before and carries the profile's TEXT (-p); its copy for reading is named <scope run dir>/seatbelt/agent.sb", () => {
  const inp = input({ net: { connect: [{ host: "localhost", port: 8788 }], bind: [] } });
  const logs: string[] = [];
  const mut = emptyMutation();
  mut.launchPrefix = ["outer-wrap", "--"];
  const r = applySeatbelt(inp, mut, { log: (m) => logs.push(m), realpath: () => null, writeProfile: () => {}, uid: 501 })!;
  assert.equal(r.profilePath, "/rt/sid/seatbelt/agent.sb");
  // Nothing is read back by path (review 2026-09-30): the agent of another
  // session could swap a profile file between its write and sandbox-exec's read.
  assert.deepEqual(mut.launchPrefix, ["outer-wrap", "--", "/usr/bin/sandbox-exec", "-p", r.profile]);
  assert.ok(!mut.launchPrefix.includes("-f") && !mut.launchPrefix.includes(r.profilePath));
  assert.deepEqual(r.components, ["credential files", "Mandu's state", "network"]);
  assert.equal(logs[0], "mandu: seatbelt LIVE — the macOS profile around the whole agent: credential files, Mandu's state, network (copy: /rt/sid/seatbelt/agent.sb)");
  assert.ok(r.profile.includes('(subpath "/rt/sid/seatbelt/agent.sb")'), "the copy itself is not writable from inside");
});

test("the copy: 0600 in a fresh 0700 directory, never written through a link planted at the directory's or the file's name", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mandu-sb-")));
  try {
    const mut = emptyMutation();
    const r = applySeatbelt(input({ scopeRunDir: dir }), mut, { log: () => {} })!;
    assert.equal(statSync(r.profilePath).mode & 0o777, 0o600);
    assert.equal(statSync(join(dir, "seatbelt")).mode & 0o777, 0o700);
    assert.equal(readFileSync(r.profilePath, "utf8"), r.profile);
    // What the agent of another session could leave there: `seatbelt/` a
    // link to someone's folder, or a link at agent.sb in a real one.
    const victimDir = join(dir, "victim-dir");
    mkdirSync(victimDir);
    writeFileSync(join(victimDir, "agent.sb"), "keep me\n");
    const victim = join(dir, "victim.rc");
    writeFileSync(victim, "keep me too\n");
    rmSync(join(dir, "seatbelt"), { recursive: true });
    symlinkSync(victimDir, join(dir, "seatbelt"));
    writeProfileCopy(join(dir, "seatbelt"), join(dir, "seatbelt", "agent.sb"), "(version 1)\n");
    assert.ok(!lstatSync(join(dir, "seatbelt")).isSymbolicLink(), "the link was replaced by a directory of our own");
    assert.equal(readFileSync(join(victimDir, "agent.sb"), "utf8"), "keep me\n", "nothing written into the linked folder");
    rmSync(join(dir, "seatbelt"), { recursive: true });
    mkdirSync(join(dir, "seatbelt"));
    symlinkSync(victim, join(dir, "seatbelt", "agent.sb"));
    writeProfileCopy(join(dir, "seatbelt"), join(dir, "seatbelt", "agent.sb"), "(version 1)\n");
    assert.equal(readFileSync(victim, "utf8"), "keep me too\n", "nothing written through the link");
    assert.deepEqual(readdirSync(join(dir, "seatbelt")), ["agent.sb"]);
    assert.ok(lstatSync(join(dir, "seatbelt", "agent.sb")).isFile());
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a `sandbox-exec` planted first on the agent's PATH never runs: the wrap names /usr/bin/sandbox-exec (review 2026-09-29, docs-tests-11)", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mandu-sbpath-")));
  try {
    const bin = join(dir, "bin");
    mkdirSync(bin);
    const marker = join(dir, "shim-ran");
    // What an agent could write to ~/.local/bin in one session: the next
    // session's agent would run with no profile.
    writeFileSync(join(bin, "sandbox-exec"), `#!/bin/sh\necho ran > '${marker}'\nshift 2\nexec "$@"\n`, { mode: 0o755 });
    const mut = emptyMutation();
    const r = applySeatbelt(input({ scopeRunDir: join(dir, "run") }), mut, { log: () => {} })!;
    assert.deepEqual(mut.launchPrefix, ["/usr/bin/sandbox-exec", "-p", r.profile]);
    // Spawned as a launch spawns the chain: the agent env, the planted
    // directory first on PATH. On macOS the real sandbox-exec runs (or, nested
    // in another sandbox, refuses); elsewhere the absolute path is absent.
    // Either way the shim is never found.
    const argv = [...mut.launchPrefix, "/bin/sh", "-c", "exit 0"];
    const res = spawnSync(argv[0]!, argv.slice(1), { env: { PATH: `${bin}:/usr/bin:/bin` }, stdio: "ignore", timeout: 15_000 });
    assert.equal(existsSync(marker), false, `the PATH shim ran (status ${res.status}, ${res.error?.message ?? "no spawn error"})`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("2. Mandu's state: the Mandu home (one rule) and the session's event dir; the install dir and an explicit policy file write-only", () => {
  const st = manduStatePaths({ eventDir: "/rt/sid/events" }, { HOME, MANDU_POLICY_FILE: "/p/law.yaml" }, HOME);
  assert.deepEqual(st.dirs, ["/Users/u/.mandu", "/rt/sid/events"]);
  assert.deepEqual(st.files, []);
  assert.deepEqual(st.writeOnly, ["/Users/u/.local/share/mandu", "/p/law.yaml"]);
  // MANDU_HOME moves the home; MANDU_PREFIX adds the install dir it names.
  const x = manduStatePaths({ eventDir: "/e" }, { HOME, MANDU_HOME: "/m", MANDU_PREFIX: "/opt/mandu", XDG_STATE_HOME: "/s" }, HOME);
  assert.deepEqual(x.dirs, ["/m", "/e"]);
  assert.deepEqual(x.writeOnly, ["/Users/u/.local/share/mandu", "/opt/mandu"]);
});

test("2. Mandu's state is sealed only when asked (secrets mode), and a state dir holding the workspace is left readable, said", () => {
  const off = run(input({ sealState: false }));
  assert.ok(!off.r!.profile.includes(".mandu"), "integrity ON / confidentiality OFF: the AgentView lives under ~/.mandu");
  const inside = run(input({ plan: { ...input().plan, humanCwd: "/Users/u/.mandu/work", cwd: "/Users/u/.mandu/work" } }));
  assert.ok(!inside.r!.profile.includes('(subpath "/Users/u/.mandu")'));
  assert.ok(inside.logs.some((l) => /^WARNING: mandu: \/Users\/u\/\.mandu \(Mandu's own state\) stays readable to the agent: \/Users\/u\/\.mandu\/work is inside it$/.test(l)), inside.logs.join("\n"));
  assert.ok(inside.r!.profile.includes('(subpath "/rt/sid/events")'), "the rest stays sealed");
});

test("2. Mandu's own stores of originals (secret-setup.ts ownStoresHidden) are sealed whatever the axes, with or without secrets; one covering the workspace is left out, said", () => {
  const stores = ["/Users/u/.mandu/mandu.db", "/Users/u/.mandu/mandu.db-wal", "/Users/u/.local/state/mandu/events", "/rt/sid/egress-mitm-ca/mandu-egress-ca.key"];
  // integrity ON (full): the state base is not sealed, the stores are
  const full = run(input({ sealState: false, secrets: { secrets: [], noDelete: [], ownStores: stores } }));
  assert.ok(full.r !== null, "a profile for the stores alone");
  for (const p of stores) assert.ok(full.r!.profile.includes(`(subpath "${p}")`), p);
  assert.ok(!full.r!.profile.includes('(subpath "/Users/u/.mandu")'), "never the whole base in full mode");
  assert.ok(full.r!.components.includes("Mandu's state"));
  // a store that holds the workspace stays readable, said
  const inside = run(input({ sealState: false, secrets: { secrets: [], noDelete: [], ownStores: ["/Users/u/proj-state"] }, plan: { ...input().plan, humanCwd: "/Users/u/proj-state/w", cwd: "/Users/u/proj-state/w" } }));
  assert.ok(inside.logs.some((l) => /Mandu's own store\) stays readable to the agent/.test(l)), inside.logs.join("\n"));
});

test("3. write-protect: every entry refused (ask included; said); the arbiter socket's links literal; an entry covering the workspace left out, said", () => {
  const env = { HOME };
  const sock = "/tmp/rt/current/arbiter.sock";
  const wp = writeProtectList(env, "/Users/u/proj", NOFS, sock, { deny: ["~"], ask: [], unprotect: [] }, () => {}, [], "darwin");
  // What arbiterSocketFiles adds on macOS, pinned whatever this host's /tmp
  // is: the links on the socket's way, /tmp itself among them.
  for (const link of ["/tmp", "/tmp/rt/current"]) if (!wp.some((e) => e.path === link)) wp.push({ path: link, answer: "deny", label: "Mandu's own files" });
  const macReal = (p: string): string | null => (p === "/tmp" ? "/private/tmp" : p.startsWith("/tmp/") ? `/private${p}` : null);
  const { r, logs } = run(input({ writeProtect: wp, plan: { ...input().plan, arbiterSock: sock } }), { realpath: macReal });
  const prof = r!.profile;
  assert.ok(prof.includes('(subpath "/Users/u/Library/LaunchAgents")'), "the macOS later-run file");
  assert.ok(prof.includes('(subpath "/Users/u/.zshrc")'), "an `ask` entry is refused on macOS");
  for (const lit of ['(literal "/tmp")', '(literal "/tmp/rt/current")', '(literal "/private/tmp/rt/current")', '(literal "/tmp/rt/current/arbiter.sock")']) {
    assert.ok(prof.includes(lit), `a link on the socket's way names itself: ${lit}`);
  }
  assert.ok(!prof.includes('(subpath "/private/tmp")') && !prof.includes('(subpath "/tmp")'), "never seal /private/tmp through the /tmp link");
  assert.ok(!prof.includes('(subpath "/tmp/rt/current")'), "nor the promoted instance through `current`");
  assert.ok(!prof.includes('(subpath "/Users/u")'), "policy.yaml deny: ~ would seal the workspace: left out");
  assert.ok(logs.includes("WARNING: mandu: write-protect entry /Users/u is not applied on macOS: /Users/u/proj is inside it and must stay writable"), logs.join("\n"));
  assert.ok(logs.some((l) => /file\(s\) that run later .* are REFUSED on macOS/.test(l)), logs.join("\n"));
});

test("5 + 6. Unix sockets: the macOS list, the host-service refusals, the human's extras over them; host-service programs with them", () => {
  const env = { HOME, SSH_AUTH_SOCK: "/private/tmp/com.apple.launchd.x/Listeners", MANDU_UNIX_ALLOW: "~/.docker/run/docker.sock" };
  const unix = unixPolicy(env, { platform: "darwin", arbiterSock: "/rt/current/arbiter.sock", scopeRunDir: "/rt/sid", runtimeBase: "/rt", cwd: "/Users/u/proj", extra: [] });
  const { r } = run(input({ env, unix }));
  const prof = r!.profile;
  const refuse = prof.indexOf('(remote unix-socket (subpath "/Users/u/.docker"))');
  const extra = prof.indexOf('(remote unix-socket (subpath "/Users/u/.docker/run/docker.sock"))');
  assert.ok(refuse > 0 && extra > refuse, "an explicit MANDU_UNIX_ALLOW entry wins over the docker refusal");
  for (const s of ["/rt/instances", "/rt/sid", "/private/var/run/mDNSResponder", "/private/var/run/syslog", "/Users/u/proj", "/private/tmp/com.apple.launchd.x/Listeners"]) {
    assert.ok(prof.includes(`(remote unix-socket (subpath "${s}"))`), s);
  }
  assert.ok(prof.includes('(remote unix-socket (subpath "/private/tmp/tmux-501"))'), "a host tmux server is refused");
  assert.ok(prof.includes("(deny appleevent-send)"), "host services come with the socket list");
  assert.deepEqual(r!.components.slice(-2), ["unix sockets", "host services"]);
});

test("a copy that cannot be written costs one note, never the profile: the wrap carries the text, with or without credential files", () => {
  const boom = { realpath: () => null, writeProfile: () => { throw new Error("EROFS"); } };
  for (const inp of [input(), input({ secrets: undefined, sealState: false, net: { connect: [], bind: [] } })]) {
    const logs: string[] = [];
    const mut = emptyMutation();
    const r = applySeatbelt(inp, mut, { ...boom, log: (m) => logs.push(m) })!;
    assert.ok(r !== null);
    assert.deepEqual(mut.launchPrefix, ["/usr/bin/sandbox-exec", "-p", r.profile]);
    assert.ok(logs[0]!.startsWith("mandu: seatbelt LIVE") && logs[0]!.endsWith("(its copy could not be written: EROFS)"), logs.join("\n"));
    assert.ok(!logs.some((l) => l.includes("WITHOUT")), logs.join("\n"));
  }
});

test("the runtime registries (runtimeRegistry): their own component under plan.arbiterRuntimeBase, both spellings, `current` itself never followed; the base stays writable, unrenameable", () => {
  const macReal = (p: string): string | null =>
    p === "/tmp" ? "/private/tmp" : p === "/tmp/rt/current" ? "/private/tmp/rt/instances/i1" : p.startsWith("/tmp/rt") ? `/private${p}` : null;
  const plan = { ...input().plan, arbiterRuntimeBase: "/tmp/rt", eventDir: "/tmp/rt/sid/events", arbiterSock: "/tmp/rt/current/arbiter.sock" };
  const { r, logs } = run(input({ secrets: undefined, sealState: false, runtimeRegistry: true, plan, scopeRunDir: "/tmp/rt/sid" }), { realpath: macReal });
  // Alone it still makes a profile; the base's human/ wall comes with it
  // (the human plane under every registry base).
  assert.deepEqual(r!.components, ["human plane", "runtime registry"], "alone it still makes a profile");
  const prof = r!.profile;
  for (const want of [
    '(subpath "/private/tmp/rt/instances")', '(subpath "/tmp/rt/instances")',
    '(subpath "/private/tmp/rt/dashboards")', '(subpath "/tmp/rt/logs")', '(subpath "/tmp/rt/test")', '(subpath "/tmp/rt/vm-guests")',
    '(literal "/private/tmp/rt/current")', '(literal "/tmp/rt/current")',
    '(literal "/private/tmp/rt/arbiter.sock")', '(literal "/tmp/rt/arbiter.sock")',
    '(literal "/private/tmp/rt/dashboard.log")', '(literal "/tmp/rt/dashboard.log")',
    '(prefix "/private/tmp/rt/.current.tmp-")', '(prefix "/tmp/rt/.current.tmp-")',
    '(prefix "/private/tmp/rt/dashboard-")', '(prefix "/tmp/rt/dashboard-")',
  ]) assert.ok(prof.includes(want), `${want}\n${prof}`);
  assert.ok(!prof.includes('"/private/tmp/rt/instances/i1"'), "`current` names the link, never the instance it points to");
  for (const open of ["/tmp/rt", "/private/tmp/rt", "/tmp/rt/sid", "/private/tmp/rt/sid"]) {
    assert.ok(!prof.includes(`(subpath "${open}")`), `the base and the session's dir stay writable: ${open}`);
  }
  assert.ok(prof.includes('  (literal "/private/tmp/rt")') && prof.includes('  (literal "/tmp/rt")'), "a renamed base would let the agent build a fresh registry");
  assert.deepEqual(logs.filter((l) => l.startsWith("WARNING")), []);
  // Off (mode `off`): nothing rendered for it.
  const off = run(input({ secrets: undefined, sealState: false, runtimeRegistry: false, plan }), { realpath: macReal });
  assert.equal(off.r, null);
});

test("the runtime registries: one that holds what the agent must keep writable REFUSES the launch, never drops the rule (review 2026-09-30)", () => {
  // parse.ts refuses such a scope id first (`--id logs`); this is the second
  // line, and the one for a workspace or a runtime dir inside a registry.
  const refused = (over: Partial<SeatbeltSetupInput>, re: RegExp): void => {
    assert.throws(() => run(input({ secrets: undefined, sealState: false, runtimeRegistry: true, ...over })), re);
  };
  refused({ plan: { ...input().plan, eventDir: "/rt/logs/events" }, scopeRunDir: "/rt/logs" },
    /^Error: mandu: refusing to launch: \/rt\/logs lies in \/rt\/logs, one of Mandu's runtime registries, which the agent may never write/);
  refused({ plan: { ...input().plan, eventDir: "/rt/.current.tmp-x/events" }, scopeRunDir: "/rt/.current.tmp-x" }, /\/rt\/\.current\.tmp-x lies in \/rt\/\.current\.tmp-\*/);
  refused({ plan: { ...input().plan, eventDir: "/rt/dashboard-1.port/events" }, scopeRunDir: "/rt/dashboard-1.port" }, /lies in \/rt\/dashboard-\*/);
  refused({ plan: { ...input().plan, humanCwd: "/rt/instances/x/w", cwd: "/rt/instances/x/w" } }, /\/rt\/instances\/x\/w lies in \/rt\/instances/);
  // The same launch with its registry component off (mode `off`) is not refused.
  assert.doesNotThrow(() => run(input({ secrets: undefined, sealState: false, runtimeRegistry: false, net: { connect: [], bind: [] }, scopeRunDir: "/rt/logs" })));
});

test("the runtime registries under the account's default base and rendezvous too (registryBases), both spellings; a repeat of the launch's own base is one set of rules", () => {
  const macReal = (p: string): string | null =>
    p === "/tmp" ? "/private/tmp" : p.startsWith("/tmp/") ? `/private${p}` : p === "/private/tmp" || p.startsWith("/private/tmp/") ? p : null;
  // This launch has its own MANDU_RUNTIME_DIR; the user's resident stack lives
  // in the default /tmp/mandu-501 (the rendezvous too, spelled canonically).
  const plan = { ...input().plan, arbiterRuntimeBase: "/tmp/own", eventDir: "/tmp/own/sid/events", arbiterSock: "/tmp/own/current/arbiter.sock" };
  const { r } = run(input({
    secrets: undefined, sealState: false, runtimeRegistry: true, plan, scopeRunDir: "/tmp/own/sid",
    registryBases: ["/tmp/mandu-501", "/private/tmp/mandu-501", "relative/ignored", "/tmp/own"],
  }), { realpath: macReal });
  const prof = r!.profile;
  for (const b of ["/tmp/own", "/private/tmp/own", "/tmp/mandu-501", "/private/tmp/mandu-501"]) {
    for (const want of [`(subpath "${b}/instances")`, `(subpath "${b}/dashboards")`, `(literal "${b}/current")`, `(literal "${b}/dashboard.log")`, `(prefix "${b}/dashboard-")`]) {
      assert.ok(prof.includes(want), `${want}\n${prof}`);
    }
    assert.ok(!prof.includes(`(subpath "${b}")`), `the base itself stays writable: ${b}`);
    assert.ok(prof.includes(`  (literal "${b}")`), `and unrenameable: ${b}`);
  }
  assert.ok(!prof.includes("relative/ignored"));
  assert.equal(prof.split('(subpath "/tmp/mandu-501/instances")').length, 2, "one rule per spelling, however often a base is named");
  // A default base whose registry holds this launch's own base refuses.
  const nested = { ...plan, arbiterRuntimeBase: "/tmp/mandu-501/logs/x", eventDir: "/tmp/mandu-501/logs/x/sid/events" };
  assert.throws(
    () => run(input({ secrets: undefined, sealState: false, runtimeRegistry: true, plan: nested, scopeRunDir: "/tmp/mandu-501/logs/x/sid", registryBases: ["/tmp/mandu-501"] }), { realpath: macReal }),
    /refusing to launch: .* lies in \/tmp\/mandu-501\/logs/,
  );
  // The keep-check folds case (the default macOS volume does): a base whose
  // `Logs` IS `logs/` refuses too.
  const folded = { ...plan, arbiterRuntimeBase: "/tmp/mandu-501/Logs/x", eventDir: "/tmp/mandu-501/Logs/x/sid/events" };
  assert.throws(
    () => run(input({ secrets: undefined, sealState: false, runtimeRegistry: true, plan: folded, scopeRunDir: "/tmp/mandu-501/Logs/x/sid", registryBases: ["/tmp/mandu-501"] }), { realpath: macReal }),
    /refusing to launch: .* lies in \/tmp\/mandu-501\/logs/,
  );
  // The human plane under EVERY registry base is walled off, not only the
  // launch's own: the resident stack's human/ under the default base too.
  for (const b of ["/tmp/own", "/private/tmp/own", "/tmp/mandu-501", "/private/tmp/mandu-501"]) {
    assert.ok(prof.includes(`(remote unix-socket (subpath "${b}/human"))`), `${b}/human: no connect\n${prof}`);
    assert.ok(prof.includes(`  (subpath "${b}/human")`), `${b}/human: no read or write`);
  }
  assert.ok(r!.components.includes("human plane"));
});

test("the human plane (plan.humanPlaneDirs): its own component, rendered with nothing else to apply; the own stores' carve-outs allowed back", () => {
  const alone = run(input({ secrets: undefined, sealState: false, humanDirs: ["/rt/human", "relative/ignored"] }));
  assert.ok(alone.r !== null, "the wall alone still makes a profile");
  assert.deepEqual(alone.r!.components, ["human plane"]);
  assert.ok(alone.r!.profile.includes('(remote unix-socket (subpath "/rt/human"))'), alone.r!.profile);
  assert.ok(!alone.r!.profile.includes("relative/ignored"));
  assert.equal(alone.r!.humanPlaneWalled, false, "a dropped directory prevents a wall claim");
  const walled = run(input({ secrets: undefined, sealState: false, humanDirs: ["/rt/human"] }));
  assert.equal(walled.r!.humanPlaneWalled, true, "the actual applied profile denies every requested directory");
  assert.equal(walled.r!.homeSealed, false, "the human wall does not require a home/cache seal");
  assert.equal(run(input()).r!.humanPlaneWalled, false, "no requested human directory makes no wall claim");
  const av = "/Users/u/.mandu/state/workspaces/w/agentview";
  const carved = run(input({ sealState: false, secrets: { secrets: [], noDelete: [], ownStores: ["/Users/u/.mandu"], carveOuts: [av] } }));
  const text = carved.r!.profile;
  assert.ok(text.indexOf(`(allow file-read* file-write*\n  (subpath "${av}"))`) > text.indexOf('(subpath "/Users/u/.mandu")'), text);
});

// ── plan 14 §11.2: does the profile seal the Mandu home? ─────────────────────

/** The input a secrets-mode launch in /Users/u/proj renders (run.ts wiring):
 *  every component the home seal needs. */
function sealedInput(over: Partial<SeatbeltSetupInput> = {}): SeatbeltSetupInput {
  const env = { HOME };
  return input({
    env,
    secrets: { secrets: ["/Users/u/.aws/credentials"], noDelete: [], ownStores: ["/Users/u/.mandu", "/rt/sid/events"] },
    sealState: true,
    writeProtect: writeProtectList(env, "/Users/u/proj", NOFS, "/sock/arbiter.sock", undefined, () => {}, [], "darwin"),
    unix: unixPolicy(env, { platform: "darwin", arbiterSock: "/sock/arbiter.sock", scopeRunDir: "/rt/sid", runtimeBase: "/rt", cwd: "/Users/u/proj", extra: [] }),
    humanDirs: ["/rt/human"],
    ...over,
  });
}

test("home seal: a secrets-mode profile with every part (home read+write denied, write-protected, human plane, sockets and host services) seals the home", () => {
  const { r } = run(sealedInput());
  assert.equal(r!.homeSealed, true, r!.components.join(", "));
  assert.ok(r!.profile.includes('(subpath "/Users/u/.mandu")'));
  // `full`-mode shape: no state seal of its own, the home through the own
  // stores, its AgentView and repo.git carved out (inside state/workspaces).
  const av = "/Users/u/.mandu/state/workspaces/w/agentview";
  const full = run(sealedInput({ sealState: false, secrets: { secrets: [], noDelete: [], ownStores: ["/Users/u/.mandu"], carveOuts: [av, "/Users/u/.mandu/state/workspaces/w/repo.git"] } }));
  assert.equal(full.r!.homeSealed, true, "a carve-out inside state/workspaces reaches no enforcement store");
});

test("home seal, fail closed: each missing part makes it false", () => {
  const cases: Array<[string, Partial<SeatbeltSetupInput>, { accountHome?: string | null }?]> = [
    ["no Unix-socket list / host services (MANDU_UNIX_POLICY=0)", { unix: null }],
    ["no human-plane wall", { humanDirs: [] }],
    ["write-protect off (MANDU_WRITE_PROTECT=0)", { writeProtect: null }],
    ["no state seal and no own stores", { sealState: false, secrets: { secrets: [], noDelete: [] } }],
    ["a carve-out re-allowing state/ (the walks, mandu.db)", { secrets: { secrets: [], noDelete: [], ownStores: ["/Users/u/.mandu"], carveOuts: ["/Users/u/.mandu/state"] } }],
    ["a carve-out inside the pack cache", { secrets: { secrets: [], noDelete: [], ownStores: ["/Users/u/.mandu"], carveOuts: ["/Users/u/.mandu/cache/object-twins/k"] } }],
    ["a carve-out above the home", { secrets: { secrets: [], noDelete: [], ownStores: ["/Users/u/.mandu"], carveOuts: ["/Users/u"] } }],
    ["the account's own ~/.mandu left out", {}, { accountHome: "/Users/acct" }],
  ];
  for (const [what, over, extra] of cases) {
    const { r } = run(sealedInput(over), extra ?? {});
    assert.ok(r !== null, what);
    assert.equal(r!.homeSealed, false, what);
  }
  // The account's home counts once the profile covers it (the launch's own
  // stores name it: secret-setup.ts manduHomes).
  const acctWp = [...sealedInput().writeProtect!, { path: "/Users/acct/.mandu", answer: "deny" as const, label: "Mandu's own files" }];
  const acct = run(sealedInput({ secrets: { secrets: [], noDelete: [], ownStores: ["/Users/u/.mandu", "/Users/acct/.mandu"] }, writeProtect: acctWp }), { accountHome: "/Users/acct" });
  assert.equal(acct.r!.homeSealed, true);
  const acctUnprotected = run(sealedInput({ secrets: { secrets: [], noDelete: [], ownStores: ["/Users/u/.mandu", "/Users/acct/.mandu"] }, writeProtect: sealedInput().writeProtect!.filter((e) => e.path !== "/Users/acct/.mandu") }), { accountHome: "/Users/acct" });
  assert.equal(acctUnprotected.r!.homeSealed, false, "denied but not write-protected");
  // A home left readable because a directory the agent keeps lies inside it
  // (said, as before) is not sealed.
  const inside = run(sealedInput({ plan: { ...input().plan, humanCwd: "/Users/u/.mandu/work", cwd: "/Users/u/.mandu/work" } }));
  assert.equal(inside.r!.homeSealed, false);
  // MANDU_HOME moves the home: the default ~/.mandu must be covered too.
  const moved = { HOME, MANDU_HOME: "/m" };
  const wpMoved = writeProtectList(moved, "/Users/u/proj", NOFS, "/sock/arbiter.sock", undefined, () => {}, [], "darwin");
  const both = run(sealedInput({ env: moved, secrets: { secrets: [], noDelete: [], ownStores: ["/m", "/Users/u/.mandu"] }, writeProtect: wpMoved }));
  assert.equal(both.r!.homeSealed, true);
  const onlyMoved = run(sealedInput({ env: moved, sealState: false, secrets: { secrets: [], noDelete: [], ownStores: ["/m"] }, writeProtect: wpMoved }));
  assert.equal(onlyMoved.r!.homeSealed, false, "~/.mandu readable beside a moved home");
});

test("home seal: judged in canonical spellings (a home behind a symlink is covered by its real path)", () => {
  const real = (p: string): string | null => (p === "/Users/u/.mandu" ? "/Volumes/d/mandu" : p.startsWith("/Users/u/.mandu/") ? `/Volumes/d/mandu${p.slice("/Users/u/.mandu".length)}` : null);
  const { r } = run(sealedInput({ sealState: false, secrets: { secrets: [], noDelete: [], ownStores: ["/Volumes/d/mandu"] } }), { realpath: real });
  assert.equal(r!.homeSealed, true);
});

test("profileSealsHome is pure over its facts", () => {
  const f: HomeSealFacts = {
    homes: ["/h/.mandu"], stateDirs: ["/h/.mandu"], carveOuts: [], writeProtect: ["/h/.mandu"], writeExcept: [], humanDirs: ["/rt/human"], unixAndHostServices: true,
  };
  assert.equal(profileSealsHome(f), true);
  assert.equal(profileSealsHome({ ...f, homes: [] }), false, "no home named: nothing to vouch for");
  assert.equal(profileSealsHome({ ...f, stateDirs: ["/h"] }), true, "a deny above the home covers it");
  assert.equal(profileSealsHome({ ...f, stateDirs: ["/h/.mandu/state"] }), false, "part of the home is not the home");
  assert.equal(profileSealsHome({ ...f, stateDirs: ["/h/.mandux"] }), false, "a whole path component");
  assert.equal(profileSealsHome({ ...f, writeProtect: [] }), false);
  assert.equal(profileSealsHome({ ...f, writeExcept: ["/h/.mandu/cache"] }), false, "a write-protect exception outside state/workspaces");
  assert.equal(profileSealsHome({ ...f, writeExcept: ["/h/.mandu/state/workspaces/w/agentview"] }), true);
  assert.equal(profileSealsHome({ ...f, carveOuts: ["/elsewhere/agentview"] }), true, "a carve-out outside every home touches none");
  assert.equal(profileSealsHome({ ...f, carveOuts: ["/h/.mandu/state/workspaces"] }), false, "strictly inside state/workspaces");
  assert.equal(profileSealsHome({ ...f, humanDirs: [] }), false);
  assert.equal(profileSealsHome({ ...f, unixAndHostServices: false }), false);
});

test("home seal, fail closed on spellings the renderer drops: a relative MANDU_HOME is not sealed (no rule is rendered for it)", () => {
  const rel = { HOME, MANDU_HOME: "rel/mandu" };
  const wpRel = writeProtectList(rel, "/Users/u/proj", NOFS, "/sock/arbiter.sock", undefined, () => {}, [], "darwin");
  const { r } = run(sealedInput({ env: rel, secrets: { secrets: [], noDelete: [], ownStores: ["rel/mandu", "/Users/u/.mandu"] }, writeProtect: wpRel }));
  assert.ok(r !== null);
  assert.ok(!r!.profile.includes('"rel/mandu"'), "the renderer drops the relative spelling");
  assert.equal(r!.homeSealed, false, "a relative home resolves against each process's own cwd: no rule covers it");
  // The same facts, pure: every list holding the same relative string was
  // enough for the old lexical check.
  const f: HomeSealFacts = {
    homes: ["h/.mandu"], stateDirs: ["h/.mandu"], carveOuts: [], writeProtect: ["h/.mandu"], writeExcept: [], humanDirs: ["/rt/human"], unixAndHostServices: true,
  };
  assert.equal(profileSealsHome(f), false, "a relative home");
  assert.equal(profileSealsHome({ ...f, homes: ["/h/.mandu"] }), false, "a relative state deny and write-protect entry render nothing");
  assert.equal(profileSealsHome({ ...f, homes: ["/"], stateDirs: ["/"], writeProtect: ["/"] }), false, "`/` is never rendered");
  assert.equal(profileSealsHome({ ...f, homes: ["/h/.mandu"], stateDirs: ["/h/.mandu"], writeProtect: ["/h/.mandu"], humanDirs: ["rel/human"] }), false, "a relative human-plane dir walls off nothing");
});

test("home seal: judged on the renderer's spellings (normalized `..`, the canonical one), case-insensitively for what re-allows", () => {
  const f: HomeSealFacts = {
    homes: ["/h/.mandu"], stateDirs: ["/h/.mandu"], carveOuts: [], writeProtect: ["/h/.mandu"], writeExcept: [], humanDirs: ["/rt/human"], unixAndHostServices: true,
  };
  assert.equal(profileSealsHome({ ...f, homes: ["/h/x/../.mandu"], stateDirs: ["/h/./y/../.mandu/"] }), true, "`..` and `.` normalized as the renderer does");
  assert.equal(profileSealsHome({ ...f, carveOuts: ["/h/.mandu/state/workspaces/w/../../object-walks"] }), false, "a carve-out that normalizes into state/object-walks");
  assert.equal(profileSealsHome({ ...f, carveOuts: ["rel/cache"] }), true, "a relative carve-out renders nothing, so re-allows nothing");
  // The default macOS volume ignores case, and so does Seatbelt's match there:
  // an allow spelled in another case re-allows the store.
  assert.equal(profileSealsHome({ ...f, carveOuts: ["/h/.MANDU/cache/object-twins"] }), false, "a carve-out in another case");
  assert.equal(profileSealsHome({ ...f, writeExcept: ["/H/.mandu/State/object-walks"] }), false, "a write-protect exception in another case");
  assert.equal(profileSealsHome({ ...f, carveOuts: ["/h/.MANDU/state/WORKSPACES/w/agentview"] }), true, "inside state/workspaces in any case");
  // The deny must name the home exactly (fail closed: on a case-sensitive
  // volume `.MANDU` is another directory).
  assert.equal(profileSealsHome({ ...f, homes: ["/h/.MANDU"] }), false);
  // The canonical spelling decides the deny; every spelling decides what re-allows.
  const canonical = (p: string): string => p.replace(/^\/link/, "/real");
  const linked: HomeSealFacts = { ...f, homes: ["/link/.mandu"], stateDirs: ["/real/.mandu"], writeProtect: ["/link/.mandu"], canonical };
  assert.equal(profileSealsHome(linked), true, "a home behind a symlink, denied and write-protected by its real path");
  assert.equal(profileSealsHome({ ...linked, carveOuts: ["/link/.mandu/cache"] }), false, "a carve-out through the link reaches the cache");
  assert.equal(profileSealsHome({ ...linked, canonical: undefined }), false, "without the canonical spelling nothing covers /link/.mandu");
});
