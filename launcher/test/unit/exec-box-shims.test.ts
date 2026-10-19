/**
 * exec-box-shims.test — the box shim dir + shim body, and applyExecBox's
 * write / graceful-degrade behavior (docs/design/integrity/exec-routing.md §7).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, readFileSync, realpathSync, statSync, existsSync, symlinkSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { homedir, tmpdir } from "node:os";
import { disableProbeCache, enableProbeCache } from "../../src/probe-cache.js";
import { join } from "node:path";
import { writeExecBoxShims } from "../../src/services/exec-box-shims.js";
import {
  applyExecBox, boxWorkspaceWritable, bwrapHelpSupports, fileSha256, isUnderDir, keptBwrapDisableUserns, stagingDirFor,
} from "../../src/exec-box-setup.js";
import type { LaunchPlan } from "../../src/types.js";

test("writeExecBoxShims: one executable shim per command, routing through the box bin", () => {
  const scope = mkdtempSync(join(tmpdir(), "box-shim-"));
  const dir = writeExecBoxShims(["cat", "grep"], "/opt/mandu-exec-box", "/run/b.sock", scope);
  assert.equal(dir, join(scope, "exec-box-shims"));
  for (const cmd of ["cat", "grep"]) {
    const p = join(dir, cmd);
    assert.ok(existsSync(p), `${cmd} shim exists`);
    assert.ok((statSync(p).mode & 0o111) !== 0, `${cmd} shim is executable`);
    const body = readFileSync(p, "utf8");
    // the exec line routes through the box bin with --cwd "$PWD" and `-- <cmd> "$@"`.
    assert.match(body, new RegExp(`exec "/opt/mandu-exec-box" --cwd "\\$PWD" -- "${cmd}" "\\$@"`));
    // default-preserving arbiter sock + the shim-dir env (bin de-shims PATH).
    assert.match(body, /MANDU_ARBITER_SOCK="\$\{MANDU_ARBITER_SOCK:-\/run\/b\.sock\}"/);
    assert.match(body, new RegExp(`MANDU_EXEC_BOX_SHIM_DIR="${dir.replace(/\//g, "\\/")}"`));
  }
  rmSync(scope, { recursive: true, force: true });
});

test("writeExecBoxShims: skips empty entries and throws on an empty set", () => {
  const scope = mkdtempSync(join(tmpdir(), "box-shim-"));
  const dir = writeExecBoxShims(["cat", "", "  "], "/box", "/s", scope);
  assert.ok(existsSync(join(dir, "cat")));
  assert.throws(() => writeExecBoxShims(["", "  "], "/box", "/s", scope), /no commands/i);
  rmSync(scope, { recursive: true, force: true });
});

test("writeExecBoxShims: a view pair is baked UNCONDITIONALLY (per-session identity); absent without one", () => {
  const scope = mkdtempSync(join(tmpdir(), "box-shim-"));
  // With the fs-view pair: both ViewConfig env vars are hard exports (an
  // ambient override could point a boxed write into another session's view).
  const dir = writeExecBoxShims(["cat"], "/box", "/s", scope, {
    agentViewRoot: "/dv/ws/agentview", workspace: "/home/u/project",
  });
  const body = readFileSync(join(dir, "cat"), "utf8");
  assert.match(body, /export MANDU_AGENTVIEW_ROOT="\/dv\/ws\/agentview"\n/);
  assert.match(body, /export MANDU_WORKSPACE="\/home\/u\/project"\n/);
  rmSync(scope, { recursive: true, force: true });

  // Without a pair (non-git workspace): no ViewConfig env → the box stays
  // RO-root + /tmp (the bin treats unset/empty as absent).
  const scope2 = mkdtempSync(join(tmpdir(), "box-shim-"));
  const dir2 = writeExecBoxShims(["cat"], "/box", "/s", scope2);
  const body2 = readFileSync(join(dir2, "cat"), "utf8");
  assert.doesNotMatch(body2, /MANDU_AGENTVIEW_ROOT/);
  assert.doesNotMatch(body2, /MANDU_WORKSPACE/);
  rmSync(scope2, { recursive: true, force: true });
});

// ── applyExecBox: wiring + graceful degrade ──────────────────────────────────

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return {
    target: "claude", argv: ["claude"], scopeId: "sid", tenant: "live", arbiterSock: "/b.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu", eventDir: "/e",
    cwd: "/w", humanCwd: "/w", noContextProxy: true, fsSync: false, basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: false, netProxyMitm: false, execWrap: false },
    execWrapCmds: [], execBox: true, execBoxCmds: ["cat", "grep"],
    ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: false, writeMcp: true, bestEffort: false, replyFilter: true, ...over,
  };
}

/** deps where everything the box needs is present; writeShims is a spy. */
function okDeps(written: string[]) {
  return {
    resolveBin: () => "/box",
    commandExists: () => true,
    usernsOk: () => true,
    arbiterSockExists: () => true,
    writeShims: (cmds: string[]) => { written.push(...cmds); return "/run/sid/exec-box-shims"; },
    bwrapKept: () => undefined,
    log: () => {},
  };
}

test("applyExecBox: off → no-op (plan.execBoxShimDir stays unset)", () => {
  const p = plan({ execBox: false });
  assert.equal(applyExecBox(p, "/run/sid", okDeps([])), null);
  assert.equal(p.execBoxShimDir, undefined);
});

test("applyExecBox: all present → writes shims + sets plan.execBoxShimDir", () => {
  const p = plan();
  const written: string[] = [];
  const dir = applyExecBox(p, "/run/sid", okDeps(written));
  assert.equal(dir, "/run/sid/exec-box-shims");
  assert.equal(p.execBoxShimDir, "/run/sid/exec-box-shims");
  assert.deepEqual(written, ["cat", "grep"]);
});

test("applyExecBox: default-on (execBox undefined) boxes too; the banner reflects the view", () => {
  // undefined = the default-on posture (non-root principle) — same as true.
  const p = plan({ execBox: undefined });
  const logs: string[] = [];
  const dir = applyExecBox(p, "/run/sid", { ...okDeps([]), log: (m) => logs.push(m) });
  assert.equal(dir, "/run/sid/exec-box-shims");
  assert.ok(logs.some((l) => /exec-box LIVE/.test(l) && /RO root/.test(l)), JSON.stringify(logs));
});

test("applyExecBox: the fs-view pair reaches the shims (writable AgentView) and the banner says so", () => {
  const p = plan({ viewMap: [{ human: "/home/u/project", agent: "/dv/ws/agentview" }] });
  const logs: string[] = [];
  const views: Array<unknown> = [];
  const deps = {
    ...okDeps([]),
    writeShims: (cmds: string[], _bin: string, _sock: string, _dir: string, view?: unknown) => {
      views.push(view);
      return "/run/sid/exec-box-shims";
    },
    log: (m: string) => logs.push(m),
  };
  const dir = applyExecBox(p, "/run/sid", deps);
  assert.equal(dir, "/run/sid/exec-box-shims");
  assert.deepEqual(views, [{ agentViewRoot: "/dv/ws/agentview", workspace: "/home/u/project" }]);
  assert.ok(logs.some((l) => /exec-box LIVE/.test(l) && /writes land in the AgentView/.test(l)), JSON.stringify(logs));
});

test("applyExecBox: default-on degrade wording does not claim the user asked for it", () => {
  const p = plan({ execBox: undefined });
  const logs: string[] = [];
  applyExecBox(p, "/run/sid", { ...okDeps([]), resolveBin: () => null, log: (m) => logs.push(m) });
  assert.ok(logs.some((l) => /on by default/.test(l) && /--no-exec-box/.test(l)), JSON.stringify(logs));
  const p2 = plan({ execBox: true });
  const logs2: string[] = [];
  applyExecBox(p2, "/run/sid", { ...okDeps([]), resolveBin: () => null, log: (m) => logs2.push(m) });
  assert.ok(logs2.some((l) => /--exec-box asked/.test(l)), JSON.stringify(logs2));
});

test("applyExecBox: bin missing → degrade (warn, no shim dir, never throws)", () => {
  const p = plan();
  const logs: string[] = [];
  const r = applyExecBox(p, "/run/sid", { ...okDeps([]), resolveBin: () => null, log: (m) => logs.push(m) });
  assert.equal(r, null);
  assert.equal(p.execBoxShimDir, undefined);
  assert.ok(logs.some((l) => /not built/.test(l) && /WITHOUT/.test(l)));
});

test("writeExecBoxShims: the Landlock applier pin is a hard export when given, absent otherwise", () => {
  const scope = mkdtempSync(join(tmpdir(), "box-shim-"));
  const dir = writeExecBoxShims(["cat"], "/box", "/s", scope, undefined, "/run/sid/bin/mandu-landlock-apply");
  const body = readFileSync(join(dir, "cat"), "utf8");
  assert.match(body, /export MANDU_LANDLOCK_APPLY="\/run\/sid\/bin\/mandu-landlock-apply"\n/);
  rmSync(scope, { recursive: true, force: true });

  const scope2 = mkdtempSync(join(tmpdir(), "box-shim-"));
  const dir2 = writeExecBoxShims(["cat"], "/box", "/s", scope2);
  assert.doesNotMatch(readFileSync(join(dir2, "cat"), "utf8"), /MANDU_LANDLOCK_APPLY/);
  rmSync(scope2, { recursive: true, force: true });
});

test("writeExecBoxShims: the clean-box posture is a HARD export (\"1\" / \"0\"), absent when undecided", () => {
  // exec-routing.md §8.5: the launcher decides the posture; a hard export
  // keeps ambient MANDU_EXEC_CLEAN_BOX from flipping a session either way.
  const on = mkdtempSync(join(tmpdir(), "box-shim-"));
  const dOn = writeExecBoxShims(["cat"], "/box", "/s", on, undefined, undefined, true);
  assert.match(readFileSync(join(dOn, "cat"), "utf8"), /\nexport MANDU_EXEC_CLEAN_BOX="1"\n/);
  rmSync(on, { recursive: true, force: true });

  const off = mkdtempSync(join(tmpdir(), "box-shim-"));
  const dOff = writeExecBoxShims(["cat"], "/box", "/s", off, undefined, undefined, false);
  assert.match(readFileSync(join(dOff, "cat"), "utf8"), /\nexport MANDU_EXEC_CLEAN_BOX="0"\n/);
  rmSync(off, { recursive: true, force: true });

  const none = mkdtempSync(join(tmpdir(), "box-shim-"));
  const dNone = writeExecBoxShims(["cat"], "/box", "/s", none);
  assert.doesNotMatch(readFileSync(join(dNone, "cat"), "utf8"), /MANDU_EXEC_CLEAN_BOX/);
  rmSync(none, { recursive: true, force: true });
});

test("applyExecBox: the clean box is OFF by default (execCleanBox undefined), on only on an explicit true; the banner says so", () => {
  // Opt-in since 2026-09-28 (exec-routing.md §8.5.3): the arbiter does not
  // honor the in-tree box's verdict, so the attempt buys nothing by default.
  const seen: Array<boolean | undefined> = [];
  const deps = {
    ...okDeps([]),
    writeShims: (
      _c: string[], _b: string, _s: string, _d: string, _v?: unknown, _a?: string, cleanBox?: boolean,
    ) => { seen.push(cleanBox); return "/run/sid/exec-box-shims"; },
  };
  const logs: string[] = [];
  const log = (m: string) => logs.push(m);
  applyExecBox(plan({}), "/run/sid", { ...deps, log });
  applyExecBox(plan({ execCleanBox: true }), "/run/sid", { ...deps, log });
  applyExecBox(plan({ execCleanBox: false }), "/run/sid", { ...deps, log });
  assert.deepEqual(seen, [false, true, false]);
  const cleanBanners = logs.filter((l) => /CLEAN BOX first/.test(l));
  assert.equal(cleanBanners.length, 1, "the clean-box banner prints for the one ON launch only");
  assert.ok(cleanBanners.every((l) => /reruns in the ordinary box/.test(l) && /does not honor the box's verdict/.test(l)),
    "the banner tells the fallback-rerun cost and that no output is un-masked by it today");
});

test("writeExecBoxShims: the guard's clean-run socket is a hard export when hosted, unset otherwise (§5.3)", () => {
  const on = mkdtempSync(join(tmpdir(), "box-shim-"));
  const dOn = writeExecBoxShims(["cat"], "/box", "/s", on, undefined, undefined, true, undefined, "/run/sid/clean.sock");
  assert.match(readFileSync(join(dOn, "cat"), "utf8"), /\nexport MANDU_EXEC_CLEAN_SOCK="\/run\/sid\/clean.sock"\n/);
  rmSync(on, { recursive: true, force: true });
  // Unset, not absent: an ambient value must not point the box at a socket
  // this launch did not name.
  const off = mkdtempSync(join(tmpdir(), "box-shim-"));
  const dOff = writeExecBoxShims(["cat"], "/box", "/s", off, undefined, undefined, true);
  assert.match(readFileSync(join(dOff, "cat"), "utf8"), /\nunset MANDU_EXEC_CLEAN_SOCK\n/);
  rmSync(off, { recursive: true, force: true });
});

test("applyExecBox: an offered reporter makes the guard host the clean box, ON by default; --no-exec-clean-box still wins (§5.3)", () => {
  // Axes: the offer exists only under the integrity axis (clean-host.test
  // pins cleanReporterWanted); here it is given.
  const seen: Array<{ cleanBox?: boolean; cleanSock?: string }> = [];
  const deps = {
    ...okDeps([]),
    resolveBin: (name: string) => (name === "mandu-landlock-apply" ? "/usr/lib/mandu/mandu-landlock-apply" : "/usr/lib/mandu/mandu-exec-box"),
    writeShims: (
      _c: string[], _b: string, _s: string, _d: string, _v?: unknown, _a?: string, cleanBox?: boolean, _p?: string, cleanSock?: string,
    ) => { seen.push({ cleanBox, cleanSock }); return "/run/sid/exec-box-shims"; },
    hostEnv: { PATH: "/usr/bin:/bin", HOME: "/home/u", ANTHROPIC_API_KEY: "sk-must-not-cross", LANG: "C.UTF-8" },
  };
  const logs: string[] = [];
  const hosted = plan({ cleanReporterOffered: true, viewMap: [{ agent: "/av", human: "/w" }] });
  applyExecBox(hosted, "/run/sid", { ...deps, log: (m) => logs.push(m) });
  assert.deepEqual(seen[0], { cleanBox: true, cleanSock: "/run/sid/clean.sock" });
  assert.equal(hosted.cleanHost?.socket, "/run/sid/clean.sock");
  assert.equal(hosted.cleanHost?.boxBin, "/usr/lib/mandu/mandu-exec-box");
  const env = Object.fromEntries(hosted.cleanHost?.env ?? []);
  assert.deepEqual(env, {
    PATH: "/usr/bin:/bin", HOME: "/home/u", LANG: "C.UTF-8",
    MANDU_ARBITER_SOCK: "/b.sock", MANDU_AGENTVIEW_ROOT: "/av", MANDU_WORKSPACE: "/w",
    MANDU_LANDLOCK_APPLY: "/usr/lib/mandu/mandu-landlock-apply",
  }, "only the launch's named variables and the box's own configuration");
  assert.ok(logs.some((l) => /CLEAN BOX first/.test(l) && /guard runs the attempt and vouches for it/.test(l)), logs.join("\n"));

  const refused = plan({ cleanReporterOffered: true, execCleanBox: false });
  applyExecBox(refused, "/run/sid", deps);
  assert.deepEqual(seen[1], { cleanBox: false, cleanSock: undefined });
  assert.equal(refused.cleanHost, undefined);

  const notOffered = plan({});
  applyExecBox(notOffered, "/run/sid", deps);
  assert.deepEqual(seen[2], { cleanBox: false, cleanSock: undefined });
  assert.equal(notOffered.cleanHost, undefined);
});

// ── applyExecBox: the in-workspace applier is staged out of the AgentView shadow ──

/** deps capturing the applier writeShims receives; resolveBin is per-name. */
function applierDeps(
  applierPath: string | null,
  seen: { applier: Array<string | undefined>; staged: string[][] },
  stageBin?: (src: string, destDir: string) => string,
) {
  return {
    ...okDeps([]),
    resolveBin: (name: string) => (name === "mandu-landlock-apply" ? applierPath : "/box"),
    writeShims: (
      _c: string[], _b: string, _s: string, _d: string, _v?: unknown, landlockApply?: string,
    ) => { seen.applier.push(landlockApply); return "/run/sid/exec-box-shims"; },
    stageBin: stageBin ?? ((src: string, destDir: string) => { seen.staged.push([src, destDir]); return join(destDir, "mandu-landlock-apply"); }),
  };
}

test("applyExecBox: an applier UNDER the workspace is staged into the scope run dir (the bwrap-ENOENT class)", () => {
  const p = plan({ viewMap: [{ human: "/home/u/project", agent: "/dv/ws/agentview" }] });
  const seen = { applier: [] as Array<string | undefined>, staged: [] as string[][] };
  const dir = applyExecBox(p, "/run/sid", applierDeps("/home/u/project/interceptors/target/debug/mandu-landlock-apply", seen));
  assert.equal(dir, "/run/sid/exec-box-shims");
  // staged from the in-workspace path into <scopeRunDir>/bin, and the STAGED
  // path (not the shadowed one) is what the shims pin.
  assert.deepEqual(seen.staged, [["/home/u/project/interceptors/target/debug/mandu-landlock-apply", "/run/sid/bin"]]);
  assert.deepEqual(seen.applier, ["/run/sid/bin/mandu-landlock-apply"]);
});

test("applyExecBox: a /tmp-fallback run dir stages into the per-user cache (the box tmpfs-mounts /tmp)", () => {
  const p = plan({ viewMap: [{ human: "/home/u/project", agent: "/dv/ws/agentview" }] });
  const seen = { applier: [] as Array<string | undefined>, staged: [] as string[][] };
  const deps = {
    ...applierDeps("/home/u/project/interceptors/target/debug/mandu-landlock-apply", seen),
    writeShims: () => "/tmp/mandu/sid/exec-box-shims",
    hostEnv: { PATH: "/usr/bin:/bin" },
  };
  applyExecBox(p, "/tmp/mandu/sid", deps);
  assert.equal(seen.staged.length, 1);
  assert.equal(seen.staged[0]![1], join(homedir(), ".local", "share", "mandu", "exec-box", "bin"));
});

test("stagingDirFor: the path table's exec-box-cache, under the install prefix — never in the Mandu home, which the agent cannot open", () => {
  assert.equal(stagingDirFor("/tmp/mandu/sid", { MANDU_HOME: "/mh" }, "/home/u"), "/home/u/.local/share/mandu/exec-box/bin");
  assert.equal(stagingDirFor("/tmp/mandu/sid", { MANDU_PREFIX: "/opt/mandu" }, "/home/u"), "/opt/mandu/exec-box/bin");
  assert.equal(stagingDirFor("/run/user/1/mandu/sid", { MANDU_HOME: "/mh" }, "/home/u"), "/run/user/1/mandu/sid/bin");
  const p = plan({ viewMap: [{ human: "/home/u/project", agent: "/dv/ws/agentview" }] });
  const seen = { applier: [] as Array<string | undefined>, staged: [] as string[][] };
  applyExecBox(p, "/tmp/mandu/sid", {
    ...applierDeps("/home/u/project/interceptors/target/debug/mandu-landlock-apply", seen),
    writeShims: () => "/tmp/mandu/sid/exec-box-shims",
    hostEnv: { PATH: "/usr/bin:/bin", MANDU_PREFIX: "/opt/mandu" },
  });
  assert.equal(seen.staged[0]![1], "/opt/mandu/exec-box/bin");
});

test("isUnderDir: symmetric through symlinks, including a path that does not exist yet (darwin: /tmp → /private/tmp)", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "box-under-")));
  try {
    const real = join(root, "private-tmp");
    mkdirSync(real);
    symlinkSync(real, join(root, "tmp"));
    const link = join(root, "tmp");
    // The /tmp-fallback run dir is not created yet when stagingDirFor asks.
    assert.equal(isUnderDir(join(link, "mandu", "sid", "bin"), link), true, "a not-yet-created dir under the symlinked root");
    assert.equal(isUnderDir(join(link, "mandu", "sid", "bin"), real), true, "…against the root's real spelling");
    assert.equal(isUnderDir(join(real, "mandu", "sid", "bin"), link), true, "…and the real spelling against the link");
    assert.equal(isUnderDir(link, real), true, "the root itself");
    assert.equal(isUnderDir(join(root, "elsewhere", "bin"), link), false);
    assert.equal(isUnderDir(join(root, "tmpfoo", "bin"), link), false, "a sibling sharing the prefix is not under it");
    assert.equal(isUnderDir("/nonexistent-mandu-root/a/b", "/nonexistent-mandu-root"), true, "nothing resolvable: the literal paths decide");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("applyExecBox: an applier OUTSIDE the workspace is pinned as-is (no staging)", () => {
  const p = plan({ viewMap: [{ human: "/home/u/project", agent: "/dv/ws/agentview" }] });
  const seen = { applier: [] as Array<string | undefined>, staged: [] as string[][] };
  applyExecBox(p, "/run/sid", applierDeps("/usr/lib/mandu/mandu-landlock-apply", seen));
  assert.deepEqual(seen.staged, []);
  assert.deepEqual(seen.applier, ["/usr/lib/mandu/mandu-landlock-apply"]);
});

test("applyExecBox: no view pair → no shadowing possible → pinned as-is even under the workspace", () => {
  const p = plan(); // no viewMap
  const seen = { applier: [] as Array<string | undefined>, staged: [] as string[][] };
  applyExecBox(p, "/run/sid", applierDeps("/w/interceptors/target/debug/mandu-landlock-apply", seen));
  assert.deepEqual(seen.staged, []);
  assert.deepEqual(seen.applier, ["/w/interceptors/target/debug/mandu-landlock-apply"]);
});

test("applyExecBox: applier not built → shims get no pin (the box degrades its LSM leg, not the launch)", () => {
  const p = plan();
  const seen = { applier: [] as Array<string | undefined>, staged: [] as string[][] };
  const dir = applyExecBox(p, "/run/sid", applierDeps(null, seen));
  assert.equal(dir, "/run/sid/exec-box-shims");
  assert.deepEqual(seen.applier, [undefined]);
});

test("applyExecBox: a shadowed applier whose staging FAILS degrades the whole box (every boxed exec would ENOENT)", () => {
  const p = plan({ viewMap: [{ human: "/home/u/project", agent: "/dv/ws/agentview" }] });
  const seen = { applier: [] as Array<string | undefined>, staged: [] as string[][] };
  const logs: string[] = [];
  const deps = {
    ...applierDeps("/home/u/project/interceptors/target/debug/mandu-landlock-apply", seen,
      () => { throw new Error("tmpfs full"); }),
    log: (m: string) => logs.push(m),
  };
  const r = applyExecBox(p, "/run/sid", deps);
  assert.equal(r, null);
  assert.equal(p.execBoxShimDir, undefined);
  assert.deepEqual(seen.applier, [], "no shims written");
  assert.ok(logs.some((l) => /shadow/.test(l) && /staging a copy failed/.test(l) && /tmpfs full/.test(l)), JSON.stringify(logs));
});

test("applyExecBox: no userns → the degrade line carries the cause+fix hint AND the legacy phrase", () => {
  const p = plan();
  const logs: string[] = [];
  const deps = { ...okDeps([]), usernsOk: () => false, usernsHint: () => "HINT: knob X is shut", log: (m: string) => logs.push(m) };
  assert.equal(applyExecBox(p, "/run/sid", deps), null);
  assert.equal(p.execBoxShimDir, undefined);
  const line = logs.find((l) => /user namespaces/.test(l));
  assert.ok(line, JSON.stringify(logs));
  assert.match(line!, /unprivileged user namespaces are unavailable \(HINT: knob X is shut\), so the box cannot run/);
});

test("applyExecBox: no bwrap / no userns / no arbiter socket each degrade (no throw)", () => {
  for (const [key, needle] of [
    ["commandExists", /bwrap/],
    ["usernsOk", /user namespaces/],
    ["arbiterSockExists", /arbiter socket/],
  ] as const) {
    const p = plan();
    const logs: string[] = [];
    const deps = { ...okDeps([]), log: (m: string) => logs.push(m) } as Record<string, unknown>;
    deps[key] = key === "commandExists" ? () => false : () => false;
    const r = applyExecBox(p, "/run/sid", deps as never);
    assert.equal(r, null, `${key} unavailable → degrade`);
    assert.equal(p.execBoxShimDir, undefined);
    assert.ok(logs.some((l) => needle.test(l)), `${key} warns: ${JSON.stringify(logs)}`);
  }
});

test("applyExecBox: OFF by default for target codex (its own sandbox forbids a nested bwrap net namespace); --exec-box still forces it", () => {
  // Measured 2026-09-05 with the developer's real config: every boxed command
  // under codex's workspace-write sandbox died with
  // `bwrap: loopback: Failed to create NETLINK_ROUTE socket`.
  const logs: string[] = [];
  const written: string[] = [];
  const off = applyExecBox(plan({ target: "codex", argv: ["codex"], execBox: undefined }), "/run/sid", { ...okDeps(written), log: (m) => logs.push(m) });
  assert.equal(off, null, "no shim dir for codex by default");
  assert.equal(written.length, 0, "no shims written");
  assert.ok(logs.some((l) => /exec-box OFF for codex by default/.test(l) && /NETLINK_ROUTE/.test(l)), "the banner says why");
  // An explicit --exec-box (danger-full-access codex) still boxes.
  const forced = applyExecBox(plan({ target: "codex", argv: ["codex"], execBox: true }), "/run/sid", okDeps(written));
  assert.ok(forced, "forced box for codex");
  assert.ok(written.length > 0);
});

test("applyExecBox: a STALE bin (older than its source) is WARNED about, for the box AND the applier, and the box still comes up", () => {
  // 2026-09-17: a fixed sandbox.rs + a never-rebuilt target/debug bin looked
  // healthy and failed every boxed command; the note must be an attention
  // line (WARNING) so the compact launch display prints it.
  const p = plan();
  const logs: string[] = [];
  const asked: string[] = [];
  const dir = applyExecBox(p, "/run/sid", {
    ...okDeps([]),
    log: (m) => logs.push(m),
    staleNote: (name, path) => { asked.push(`${name}@${path}`); return `mandu: WARNING — ${name} at ${path} is STALE`; },
  });
  assert.equal(dir, "/run/sid/exec-box-shims", "stale is a warning, not a degrade");
  assert.deepEqual(asked.map((a) => a.split("@")[0]), ["mandu-exec-box", "mandu-landlock-apply"]);
  assert.equal(logs.filter((l) => /WARNING/.test(l) && /is STALE/.test(l)).length, 2, JSON.stringify(logs));
  // Fresh (null) → silent.
  const quiet: string[] = [];
  applyExecBox(plan(), "/run/sid", { ...okDeps([]), log: (m) => quiet.push(m), staleNote: () => null });
  assert.ok(!quiet.some((l) => /STALE/.test(l)));
});

// ── a project under /tmp (open-source-release checklist a7) ──────────────────

test("writeExecBoxShims: with NO view pair the project root is baked alone as MANDU_WORKSPACE (and an ambient MANDU_AGENTVIEW_ROOT unset); a view pair wins", () => {
  const scope = mkdtempSync(join(tmpdir(), "box-shim-"));
  const dir = writeExecBoxShims(["cat"], "/box", "/s", scope, undefined, undefined, undefined, "/tmp/x/proj");
  const body = readFileSync(join(dir, "cat"), "utf8");
  assert.match(body, /\nunset MANDU_AGENTVIEW_ROOT\nexport MANDU_WORKSPACE="\/tmp\/x\/proj"\n/);
  // the unset precedes the exec line (the bin sees only the project, never a stray pair)
  assert.ok(body.indexOf("unset MANDU_AGENTVIEW_ROOT") < body.indexOf("exec "));
  rmSync(scope, { recursive: true, force: true });

  const scope2 = mkdtempSync(join(tmpdir(), "box-shim-"));
  const dir2 = writeExecBoxShims(["cat"], "/box", "/s", scope2, { agentViewRoot: "/dv/av", workspace: "/tmp/x/proj" }, undefined, undefined, "/ignored");
  const body2 = readFileSync(join(dir2, "cat"), "utf8");
  assert.match(body2, /export MANDU_WORKSPACE="\/tmp\/x\/proj"\n/);
  assert.doesNotMatch(body2, /ignored|unset MANDU_AGENTVIEW_ROOT/);
  rmSync(scope2, { recursive: true, force: true });
});

test("applyExecBox: no view pair → the launch's project (realpath of humanCwd) reaches the shims; a view pair → none", () => {
  const base = mkdtempSync(join(tmpdir(), "box-proj-"));
  try {
    const real = join(base, "real-proj");
    mkdirSync(real);
    const link = join(base, "link-proj");
    symlinkSync(real, link);
    const seen: Array<string | undefined> = [];
    const deps = {
      ...okDeps([]),
      writeShims: (_c: string[], _b: string, _s: string, _d: string, _v?: unknown, _l?: string, _cb?: boolean, projectRoot?: string) => {
        seen.push(projectRoot);
        return "/run/sid/exec-box-shims";
      },
    };
    applyExecBox(plan({ humanCwd: link, cwd: link }), "/run/sid", deps);
    applyExecBox(plan({ humanCwd: "/does/not/exist" }), "/run/sid", deps);
    applyExecBox(plan({ viewMap: [{ human: "/home/u/project", agent: "/dv/ws/agentview" }] }), "/run/sid", deps);
    assert.deepEqual(seen, [realpathSync(real), "/does/not/exist", undefined]);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

// ── the workspace without an AgentView (exec-routing.md §7.2) ────────────────
// Axes are explicit here (plan.effectiveAxes): no arbiter is built.

const SECRETS = { integrity: false, confidentiality: true };
const OFF = { integrity: false, confidentiality: false };
const FULL = { integrity: true, confidentiality: true };
const PAIR = { agentViewRoot: "/dv/ws/agentview", workspace: "/home/u/project" };

test("boxWorkspaceWritable: only integrity OFF, no view pair, a known project", () => {
  assert.equal(boxWorkspaceWritable({ effectiveAxes: SECRETS }, undefined, "/home/u/p"), true, "secrets");
  assert.equal(boxWorkspaceWritable({ effectiveAxes: OFF }, undefined, "/home/u/p"), true, "off");
  assert.equal(boxWorkspaceWritable({ effectiveAxes: FULL }, undefined, "/home/u/p"), false, "integrity ON keeps it read-only");
  assert.equal(boxWorkspaceWritable({ effectiveAxes: { integrity: true, confidentiality: false } }, undefined, "/home/u/p"), false, "injection");
  assert.equal(boxWorkspaceWritable({}, undefined, "/home/u/p"), false, "an unknown axis keeps the old read-only box");
  assert.equal(boxWorkspaceWritable({ effectiveAxes: SECRETS }, PAIR, "/home/u/p"), false, "a view pair wins");
  assert.equal(boxWorkspaceWritable({ effectiveAxes: SECRETS }, undefined, undefined), false, "no project, nothing to bind");
});

test("writeExecBoxShims: the writable workspace is a HARD export with no pair, a HARD unset otherwise", () => {
  const rw = mkdtempSync(join(tmpdir(), "box-shim-"));
  const body = readFileSync(join(writeExecBoxShims(["sed"], "/box", "/s", rw, undefined, undefined, false, "/home/u/p", undefined, true), "sed"), "utf8");
  assert.match(body, /\nunset MANDU_AGENTVIEW_ROOT\nexport MANDU_WORKSPACE="\/home\/u\/p"\nexport MANDU_EXEC_BOX_WORKSPACE_RW="1"\n/);
  assert.ok(body.indexOf("MANDU_EXEC_BOX_WORKSPACE_RW") < body.indexOf("exec "));
  rmSync(rw, { recursive: true, force: true });
  // Not asked, asked with a view pair, asked with no project: unset — an
  // ambient value never makes a box's workspace writable.
  for (const [view, project, asked] of [
    [undefined, "/home/u/p", false],
    [PAIR, "/home/u/p", true],
    [undefined, undefined, true],
  ] as const) {
    const d = mkdtempSync(join(tmpdir(), "box-shim-"));
    const b = readFileSync(join(writeExecBoxShims(["sed"], "/box", "/s", d, view, undefined, false, project, undefined, asked), "sed"), "utf8");
    assert.match(b, /\nunset MANDU_EXEC_BOX_WORKSPACE_RW\n/, JSON.stringify({ view, project, asked }));
    assert.doesNotMatch(b, /export MANDU_EXEC_BOX_WORKSPACE_RW/);
    rmSync(d, { recursive: true, force: true });
  }
});

test("applyExecBox: integrity OFF with no pair → the shims get a writable workspace and the banner says so; integrity ON or a pair → read-only", () => {
  const seen: Array<boolean | undefined> = [];
  const logs: string[] = [];
  const deps = {
    ...okDeps([]),
    writeShims: (
      _c: string[], _b: string, _s: string, _d: string, _v?: unknown, _a?: string, _cb?: boolean, _p?: string, _cs?: string,
      workspaceWritable?: boolean,
    ) => { seen.push(workspaceWritable); return "/run/sid/exec-box-shims"; },
    log: (m: string) => logs.push(m),
  };
  applyExecBox(plan({ effectiveAxes: SECRETS }), "/run/sid", deps);
  applyExecBox(plan({ effectiveAxes: FULL }), "/run/sid", deps);
  applyExecBox(plan({ effectiveAxes: SECRETS, viewMap: [{ human: "/home/u/project", agent: "/dv/ws/agentview" }] }), "/run/sid", deps);
  applyExecBox(plan({}), "/run/sid", deps);
  assert.deepEqual(seen, [true, false, false, false]);
  const live = logs.filter((l) => /exec-box LIVE/.test(l));
  // exec-routing.md §7.2: integrity off, the box shows the agent's own /tmp
  assert.match(live[0]!, /RW = the project directory and the agent's own \/tmp \(its sockets masked\)/);
  assert.match(live[1]!, /RO root, only a fresh private \/tmp writable/);
  assert.match(live[2]!, /writes land in the AgentView/);
});

// ── The box's `bwrap --help`, kept by content (exec-routing.md §4) ───────────

const sha = (b: string | Buffer): string => createHash("sha256").update(b).digest("hex");

test("bwrapHelpSupports: whitespace-token-exact, as the box's own parser", () => {
  assert.equal(bwrapHelpSupports("usage:\n    --disable-userns   Disable further use of user namespaces\n", "--disable-userns"), true);
  assert.equal(bwrapHelpSupports("    --assert-userns-disabled  Fail unless\n", "--disable-userns"), false);
  assert.equal(bwrapHelpSupports("", "--disable-userns"), false);
});

test("fileSha256: the bytes of a regular file; null for a directory or an absent path", () => {
  const d = mkdtempSync(join(tmpdir(), "box-sha-"));
  writeFileSync(join(d, "f"), "bubblewrap bytes");
  assert.equal(fileSha256(join(d, "f")), sha("bubblewrap bytes"));
  writeFileSync(join(d, "empty"), "");
  assert.equal(fileSha256(join(d, "empty")), sha(""));
  assert.equal(fileSha256(d), null);
  assert.equal(fileSha256(join(d, "absent")), null);
  rmSync(d, { recursive: true, force: true });
});

test("keptBwrapDisableUserns: the box's bubblewrap's hash only when its --help advertises --disable-userns", () => {
  const asked: string[] = [];
  const deps = (help: string | null) => ({
    system: () => "/usr/bin/bwrap",
    realpath: (p: string) => `/real${p}`,
    sha256: (p: string) => sha(p),
    help: (bin: string) => { asked.push(bin); return help; },
  });
  // bwrap ≥ 0.8: kept, the hash of the REAL path's bytes, the real path asked.
  assert.equal(keptBwrapDisableUserns(undefined, deps("  --disable-userns  x\n")), sha("/real/usr/bin/bwrap"));
  assert.deepEqual(asked, ["/real/usr/bin/bwrap"]);
  // bwrapDir wins over the distribution's (Mandu's copy / the admin's).
  assert.equal(keptBwrapDisableUserns("/usr/lib/mandu/bin", deps("--disable-userns")), sha("/real/usr/lib/mandu/bin/bwrap"));
  // bwrap < 0.8, a probe that did not run, no bubblewrap, an unresolvable
  // one, an unhashable one: nothing is baked (the box probes for itself).
  assert.equal(keptBwrapDisableUserns(undefined, deps("  --assert-userns-disabled\n")), undefined);
  assert.equal(keptBwrapDisableUserns(undefined, deps(null)), undefined);
  assert.equal(keptBwrapDisableUserns(undefined, { ...deps("--disable-userns"), system: () => null }), undefined);
  assert.equal(keptBwrapDisableUserns(undefined, { ...deps("--disable-userns"), realpath: () => { throw new Error("ENOENT"); } }), undefined);
  assert.equal(keptBwrapDisableUserns(undefined, { ...deps("--disable-userns"), sha256: () => null }), undefined);
});

test("keptBwrapDisableUserns: a real bubblewrap stand-in is run and hashed by its real path", () => {
  const d = mkdtempSync(join(tmpdir(), "box-kept-"));
  const newer = join(d, "new");
  const older = join(d, "old");
  mkdirSync(newer);
  mkdirSync(older);
  const newBody = "#!/bin/sh\necho '    --disable-userns  Disable further use of user namespaces'\n";
  const oldBody = "#!/bin/sh\necho '    --unshare-user  Create new user namespace'\n";
  writeFileSync(join(newer, "bwrap.real"), newBody, { mode: 0o755 });
  symlinkSync(join(newer, "bwrap.real"), join(newer, "bwrap"));
  writeFileSync(join(older, "bwrap"), oldBody, { mode: 0o755 });
  assert.equal(keptBwrapDisableUserns(newer), sha(newBody), "the bytes behind the link");
  assert.equal(keptBwrapDisableUserns(older), undefined, "an old bubblewrap: nothing kept");
  rmSync(d, { recursive: true, force: true });
});

test("keptBwrapDisableUserns: in a launch the --help pass is kept for the boot, and a changed bubblewrap is asked again", () => {
  const d = mkdtempSync(join(tmpdir(), "box-kept-launch-"));
  const file = join(d, "rt", "probe-cache", "kernel-probes.json");
  const bin = join(d, "bin");
  mkdirSync(bin);
  const body = "#!/bin/sh\necho '    --disable-userns  Disable further use of user namespaces'\n";
  writeFileSync(join(bin, "bwrap"), body, { mode: 0o755 });
  let asked = 0;
  const help = (b: string): string | null => { asked++; return spawnSync(b, ["--help"], { encoding: "utf8" }).stdout; };
  const launch = (): string | undefined => {
    enableProbeCache({}, { file });
    try { return keptBwrapDisableUserns(bin, { help }); } finally { disableProbeCache(); }
  };
  try {
    assert.equal(launch(), sha(body));
    assert.equal(asked, 1);
    assert.equal(launch(), sha(body), "the next launch: the kept pass, the hash taken afresh");
    assert.equal(asked, 1, "no second --help");
    // The bubblewrap replaced (an older one at the same path): its identity
    // moved, so it is asked again, and its answer is not kept.
    const old = "#!/bin/sh\necho '    --unshare-user  Create new user namespace'\n";
    rmSync(join(bin, "bwrap"));
    writeFileSync(join(bin, "bwrap"), old, { mode: 0o755 });
    assert.equal(launch(), undefined);
    assert.equal(asked, 2);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("writeExecBoxShims: the kept bwrap answer is a hard export when given, a hard unset otherwise", () => {
  const h = sha("bwrap");
  const on = mkdtempSync(join(tmpdir(), "box-shim-"));
  const dOn = writeExecBoxShims(["cat"], "/box", "/s", on, undefined, undefined, undefined, undefined, undefined, undefined, h);
  const body = readFileSync(join(dOn, "cat"), "utf8");
  assert.match(body, new RegExp(`\\nexport MANDU_BWRAP_DISABLE_USERNS_SHA256="${h}"\\n`));
  assert.ok(body.indexOf("MANDU_BWRAP_DISABLE_USERNS_SHA256") < body.indexOf(`exec "/box"`), "set before the box runs");
  rmSync(on, { recursive: true, force: true });
  // Anything but the canonical hex is not baked: an ambient value is unset
  // (the box probes for itself), and nothing reaches the shell unquoted.
  for (const v of [undefined, "", "not-hex", h.toUpperCase(), `${h}"; touch /tmp/x; "`]) {
    const off = mkdtempSync(join(tmpdir(), "box-shim-"));
    const dOff = writeExecBoxShims(["cat"], "/box", "/s", off, undefined, undefined, undefined, undefined, undefined, undefined, v);
    const b = readFileSync(join(dOff, "cat"), "utf8");
    assert.match(b, /\nunset MANDU_BWRAP_DISABLE_USERNS_SHA256\n/, String(v));
    assert.doesNotMatch(b, /export MANDU_BWRAP_DISABLE_USERNS_SHA256/, String(v));
    rmSync(off, { recursive: true, force: true });
  }
});

test("applyExecBox: the box's bubblewrap (plan.bwrapDir) is probed once and its kept answer reaches the shims", () => {
  const seen: Array<string | undefined> = [];
  const dirs: Array<string | undefined> = [];
  const h = sha("bwrap");
  const deps = {
    ...okDeps([]),
    bwrapKept: (d: string | undefined): string | undefined => { dirs.push(d); return h; },
    writeShims: (...a: unknown[]) => { seen.push(a[10] as string | undefined); return "/run/sid/exec-box-shims"; },
  };
  applyExecBox(plan({ bwrapDir: "/usr/lib/mandu/bin" }), "/run/sid", deps);
  assert.deepEqual([...dirs], ["/usr/lib/mandu/bin"]);
  assert.deepEqual([...seen], [h]);
  // No kept answer: nothing reaches the shims (they bake the unset).
  applyExecBox(plan(), "/run/sid", { ...deps, bwrapKept: (d: string | undefined) => { dirs.push(d); return undefined; } });
  assert.deepEqual(dirs, ["/usr/lib/mandu/bin", undefined]);
  assert.deepEqual(seen, [h, undefined]);
});
