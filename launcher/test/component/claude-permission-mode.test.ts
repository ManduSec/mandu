/**
 * claude-permission-mode.test — E2E: `mandu claude` starts Claude Code in
 * its default permission mode unless the user chose one
 * (src/claude-permission-mode.ts; supported-agents.md §2, decided
 * 2026-10-09). The launch turns Claude Code's feature flags off
 * (CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC), which alone would start it in
 * `auto`.
 *
 * Through main(), with a stand-in binary NAMED `claude` that records the
 * argv it received, in an empty HOME and launch folder (no host settings
 * decide): no choice gets `--permission-mode default`; a choice on the
 * command line, in the user's settings or in the project's local settings
 * is kept untouched; a subcommand that runs no session gets nothing. And the
 * SDK route: a `claude` a Node host starts gets the same, from the preload.
 *
 * The real Claude Code's transcript under these flags (2.1.290–2.1.295):
 * supported-agents.md §2.
 */
import { test } from "node:test";
import "../lib/private-home.js"; // daemons' npm cache, the Mandu home and agent trust files go to temp (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:net";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { answerUnavailable } from "../lib/unanswered-arbiter.js";
import { claudeManagedSettings } from "../../src/claude-sandbox.js";

// Axes: stated per launch (MANDU_MODE: "off"); the permission mode is
// axis-independent (the launch passes it in every mode).

// An administrator's managed Claude Code settings on this host would decide
// the mode themselves: the expectations below assume none.
const MANAGED = existsSync(claudeManagedSettings()) || existsSync(join(claudeManagedSettings(), "..", "managed-settings.d"));
const SKIP = MANAGED ? "this host has managed Claude Code settings" : false;

interface Rig { dir: string; work: string; home: string; claude: string; record: string; env: (extra?: Record<string, string>) => Record<string, string | undefined> }

async function withRig(fn: (r: Rig) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-permmode-"));
  const sock = join(dir, "arbiter.sock");
  const srv: Server = createServer(answerUnavailable());
  srv.listen(sock);
  await once(srv, "listening");
  const record = join(dir, "claude-runs.json");
  const claude = join(dir, "claude");
  // Records every start (argv after argv[0]); `--version` answers like Claude Code.
  writeFileSync(claude, `#!/usr/bin/env node
const fs = require("fs");
const a = process.argv.slice(2);
if (a[0] === "--version") { console.log("2.1.295 (Claude Code)"); process.exit(0); }
const p = ${JSON.stringify(record)};
const all = fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, "utf8")) : [];
all.push(a);
fs.writeFileSync(p, JSON.stringify(all));
`, { mode: 0o755 });
  const home = join(dir, "home");
  const work = join(dir, "work");
  mkdirSync(home);
  mkdirSync(work);
  const env = (extra: Record<string, string> = {}) => ({
    HOME: home, PWD: work, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
    MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", XDG_RUNTIME_DIR: dir, ...extra,
  });
  try { await fn({ dir, work, home, claude, record, env }); } finally {
    srv.close(); rmSync(dir, { recursive: true, force: true });
  }
}

/** The argv of the stand-in's last start. */
function lastRun(r: Rig): string[] {
  const all = JSON.parse(readFileSync(r.record, "utf8")) as string[][];
  return all[all.length - 1]!;
}

/** The values the argv gives --permission-mode. */
function modes(argv: string[]): string[] {
  return argv.flatMap((a, i) => (a === "--permission-mode" ? [argv[i + 1]!] : a.startsWith("--permission-mode=") ? [a.slice(18)] : []));
}

async function launch(r: Rig, args: string[], extra: Record<string, string> = {}): Promise<string[]> {
  const code = await main(["--target", "claude", "--no-scope", "--no-reply-filter", "--no-mcp", "--", r.claude, ...args], r.env(extra));
  assert.equal(code, 0);
  return lastRun(r);
}

function writeSettings(path: string, doc: unknown): void {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, JSON.stringify(doc));
}

test("no choice: the TUI, -p and --resume start with --permission-mode default, once, ahead of the user's own arguments", { skip: SKIP }, async () => {
  await withRig(async (r) => {
    for (const args of [[], ["-p", "hi"], ["--resume", "abc"], ["--allow-dangerously-skip-permissions", "-p", "hi"]]) {
      const got = await launch(r, args);
      assert.deepEqual(modes(got), ["default"], JSON.stringify(got));
      assert.ok(got.indexOf("--permission-mode") < (args.length > 0 ? got.indexOf(args[0]!) : got.length), JSON.stringify(got));
      assert.deepEqual(got.slice(got.length - args.length), args, "the user's arguments follow, unchanged");
    }
  });
});

test("a mode chosen on the command line is kept: --permission-mode (each value, either spelling) and --dangerously-skip-permissions", { skip: SKIP }, async () => {
  await withRig(async (r) => {
    for (const m of ["acceptEdits", "auto", "plan", "bypassPermissions"]) {
      assert.deepEqual(modes(await launch(r, ["--permission-mode", m, "-p", "hi"])), [m]);
    }
    assert.deepEqual(modes(await launch(r, ["--permission-mode=plan", "-p", "hi"])), ["plan"]);
    assert.deepEqual(modes(await launch(r, ["--dangerously-skip-permissions", "-p", "hi"])), []);
  });
});

test("a mode chosen in Claude Code's settings is kept: the user's settings.json, the project's settings.local.json, the run's inline --settings", { skip: SKIP }, async () => {
  await withRig(async (r) => {
    const user = join(r.home, ".claude", "settings.json");
    writeSettings(user, { permissions: { defaultMode: "acceptEdits" } });
    assert.deepEqual(modes(await launch(r, ["-p", "hi"])), [], "user settings decide");
    // --setting-sources leaving the user file out: Claude Code would not read it.
    assert.deepEqual(modes(await launch(r, ["--setting-sources", "project,local", "-p", "hi"])), ["default"]);
    rmSync(user);
    writeSettings(join(r.work, ".claude", "settings.local.json"), { permissions: { defaultMode: "plan" } });
    assert.deepEqual(modes(await launch(r, ["-p", "hi"])), [], "local settings decide");
    rmSync(join(r.work, ".claude"), { recursive: true });
    assert.deepEqual(modes(await launch(r, ["--settings", JSON.stringify({ permissions: { defaultMode: "plan" } }), "-p", "hi"])), []);
    // A settings file that sets something else is not a choice.
    writeSettings(user, { permissions: { allow: ["Bash(ls)"] } });
    assert.deepEqual(modes(await launch(r, ["-p", "hi"])), ["default"]);
  });
});

test("no session: claude mcp list and claude --help get no --permission-mode", { skip: SKIP }, async () => {
  await withRig(async (r) => {
    assert.deepEqual(modes(await launch(r, ["mcp", "list"])), []);
    assert.deepEqual(modes(await launch(r, ["--help"])), []);
  });
});

test("the SDK route: a claude a Node host starts gets --permission-mode default unless it chose one", { skip: SKIP }, async () => {
  await withRig(async (r) => {
    const host = (args: string[]): string => {
      const f = join(r.dir, "host.mjs");
      // The SDKs' shape: an env that REPLACES the child's own.
      writeFileSync(f, [
        'import { spawn } from "node:child_process";',
        `const c = spawn(${JSON.stringify(r.claude)}, ${JSON.stringify(args)}, { env: { PATH: process.env.PATH, HOME: ${JSON.stringify(r.home)} }, stdio: "inherit" });`,
        'c.on("exit", (code) => process.exit(code ?? 1));',
      ].join("\n"));
      return f;
    };
    const run = async (args: string[]): Promise<string[]> => {
      const code = await main(["--target", "claude", "--no-scope", "--no-reply-filter", "--no-mcp", "--", "node", host(args)], r.env());
      assert.equal(code, 0);
      return lastRun(r);
    };
    assert.deepEqual(modes(await run(["--output-format", "stream-json", "--setting-sources="])), ["default"]);
    assert.deepEqual(modes(await run(["--permission-mode", "bypassPermissions", "--allow-dangerously-skip-permissions"])), ["bypassPermissions"]);
    writeSettings(join(r.home, ".claude", "settings.json"), { permissions: { defaultMode: "acceptEdits" } });
    assert.deepEqual(modes(await run(["-p", "hi"])), [], "the user's settings decide");
    assert.deepEqual(modes(await run(["--setting-sources=", "-p", "hi"])), ["default"], "settingSources: [] reads no user file");
  });
});

// ── a `claude` the session starts by name: the PATH shim (2026-10-18) ──────

/** A stand-in named `claude` that, given `--nest <cmd>`, runs `<cmd>` in a
 *  shell (the agent's own Bash tool starting a nested claude). */
function nestingClaude(r: Rig): void {
  writeFileSync(r.claude, `#!/usr/bin/env node
const fs = require("fs");
const a = process.argv.slice(2);
if (a.includes("--version")) /* after the shim's --settings, as the real one answers */ { console.log("2.1.302 (Claude Code)"); process.exit(0); }
const p = ${JSON.stringify(r.record)};
const all = fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, "utf8")) : [];
all.push(a);
fs.writeFileSync(p, JSON.stringify(all));
const n = a.indexOf("--nest");
if (n >= 0) {
  const c = require("child_process").spawnSync("/bin/sh", ["-c", a[n + 1]], { stdio: "inherit" });
  process.exit(c.status ?? 1);
}
`, { mode: 0o755 });
}

/** Every start's argv, in order. */
function allRuns(r: Rig): string[][] {
  return existsSync(r.record) ? JSON.parse(readFileSync(r.record, "utf8")) as string[][] : [];
}

/** A start's argv without the routing `--settings` the `claude` shim puts
 *  first (agent-sdks.md §3.5; nested-claude-route.test.ts proves it), which
 *  must be there: this suite is about the permission mode around it. */
function unrouted(argv: string[]): string[] {
  const i = argv.indexOf("--settings");
  assert.ok(i >= 0, `the shim's routing --settings: ${JSON.stringify(argv)}`);
  const doc = JSON.parse(argv[i + 1]!) as { env?: Record<string, string> };
  assert.match(doc.env?.["ANTHROPIC_BASE_URL"] ?? "", /^http:\/\/127\.0\.0\.1:\d+$/);
  return [...argv.slice(0, i), ...argv.slice(i + 2)];
}

/** `mandu -- sh -c <script>` with the stand-in first on PATH, by name only. */
async function shellLaunch(r: Rig, script: string): Promise<string[][]> {
  rmSync(r.record, { force: true });
  const code = await main(["--target", "shell", "--no-scope", "--no-reply-filter", "--no-mcp", "--", "/bin/sh", "-c", script],
    r.env({ PATH: `${r.dir}:${process.env["PATH"]}` }));
  assert.equal(code, 0);
  return allRuns(r).map(unrouted);
}

test("mandu -- sh: a claude the shell starts by name gets --permission-mode default unless it chose one; a subcommand gets nothing", { skip: SKIP }, async () => {
  await withRig(async (r) => {
    nestingClaude(r);
    assert.deepEqual(await shellLaunch(r, "claude -p hi"), [["--permission-mode", "default", "-p", "hi"]]);
    assert.deepEqual(await shellLaunch(r, "claude"), [["--permission-mode", "default"]], "the TUI");
    // The SDKs' stream-json command line, started from a script.
    const sdk = ["--output-format", "stream-json", "--verbose", "--input-format", "stream-json"];
    assert.deepEqual(await shellLaunch(r, `claude ${sdk.join(" ")}`), [["--permission-mode", "default", ...sdk]]);
    for (const chosen of [
      ["--permission-mode", "plan", "-p", "hi"], ["--permission-mode=auto"], ["--dangerously-skip-permissions", "-p", "hi"],
      ["--inherit-permission-mode", "acceptEdits", "-p", "hi"],
    ]) {
      assert.deepEqual(await shellLaunch(r, `claude ${chosen.join(" ")}`), [chosen], JSON.stringify(chosen));
    }
    // Not a choice: it only makes bypass selectable.
    assert.deepEqual(await shellLaunch(r, "claude --allow-dangerously-skip-permissions -p hi"),
      [["--permission-mode", "default", "--allow-dangerously-skip-permissions", "-p", "hi"]]);
    for (const sub of [["mcp", "list"], ["daemon"], ["agents"]]) {
      assert.deepEqual(await shellLaunch(r, `claude ${sub.join(" ")}`), [sub], JSON.stringify(sub));
    }
    // `claude --version` answers as the real one does, through the shim.
    const out = join(r.dir, "version.txt");
    await shellLaunch(r, `claude --version > ${out}`);
    assert.equal(readFileSync(out, "utf8").trim(), "2.1.302 (Claude Code)");
  });
});

test("mandu -- sh: a mode in the user's or the launch folder's settings is kept; a claude started in another folder is left alone", { skip: SKIP }, async () => {
  await withRig(async (r) => {
    nestingClaude(r);
    const user = join(r.home, ".claude", "settings.json");
    writeSettings(user, { permissions: { defaultMode: "acceptEdits" } });
    assert.deepEqual(await shellLaunch(r, "claude -p hi"), [["-p", "hi"]], "user settings decide");
    assert.deepEqual(await shellLaunch(r, "claude --setting-sources project -p hi"), [["--permission-mode", "default", "--setting-sources", "project", "-p", "hi"]]);
    rmSync(user);
    writeSettings(join(r.work, ".claude", "settings.local.json"), { permissions: { defaultMode: "plan" } });
    assert.deepEqual(await shellLaunch(r, "claude -p hi"), [["-p", "hi"]], "the launch folder's local settings decide");
    rmSync(join(r.work, ".claude"), { recursive: true });
    const elsewhere = join(r.dir, "elsewhere");
    mkdirSync(elsewhere);
    assert.deepEqual(await shellLaunch(r, `cd ${elsewhere} && claude -p hi`), [["-p", "hi"]], "another folder's settings were not read: left alone");
    assert.deepEqual(await shellLaunch(r, `cd ${elsewhere} && claude --setting-sources user -p hi`),
      [["--permission-mode", "default", "--setting-sources", "user", "-p", "hi"]], "only the user file read: decided");
  });
});

test("mandu claude by name: the launch adds the flag once (the shim does not add it again), and the agent's own nested claude gets it too", { skip: SKIP }, async () => {
  await withRig(async (r) => {
    nestingClaude(r);
    const code = await main(["--target", "claude", "--no-scope", "--no-reply-filter", "--no-mcp", "--", "claude", "-p", "hi", "--nest", "claude -p inner"],
      r.env({ PATH: `${r.dir}:${process.env["PATH"]}` }));
    assert.equal(code, 0);
    const [outer, inner, ...rest] = allRuns(r);
    assert.equal(rest.length, 0);
    assert.deepEqual(modes(outer!), ["default"], JSON.stringify(outer));
    assert.ok(outer!.indexOf("--permission-mode") < outer!.indexOf("-p"), "the launch's flag ahead of the user's arguments");
    assert.deepEqual(unrouted(inner!), ["--permission-mode", "default", "-p", "inner"]);
  });
});

const SYSTEM_CLAUDE = existsSync("/usr/bin/claude") || existsSync("/bin/claude") ? "this host has a claude in /usr/bin or /bin" : false;

test("no claude on PATH: the session gets no claude shim (`command -v claude` stays honest)", { skip: SKIP || SYSTEM_CLAUDE }, async () => {
  await withRig(async (r) => {
    const probe = join(r.dir, "probe.txt");
    // A PATH with the shell tools but no claude.
    const code = await main(["--target", "shell", "--no-scope", "--no-reply-filter", "--no-mcp", "--", "/bin/sh", "-c", `command -v claude > ${probe}; true`],
      r.env({ PATH: "/usr/bin:/bin" }));
    assert.equal(code, 0);
    assert.equal(readFileSync(probe, "utf8").trim(), "", "no shim named claude");
  });
});

test("fail closed: a `claude` on PATH but the shim's preload missing (a broken install) refuses the launch, naming the file", { skip: SKIP }, async () => {
  await withRig(async (r) => {
    nestingClaude(r);
    // A source tree without the preload and its rule (MANDU_DEV_REPO points
    // the dev layout at it): the session's own `claude` would run unrouted.
    const broken = join(r.dir, "repo-without-preload");
    mkdirSync(broken);
    const errs: string[] = [];
    const orig = console.error;
    console.error = (...a: unknown[]) => { errs.push(a.map(String).join(" ")); };
    let err: unknown = null;
    try {
      await main(["--target", "shell", "--no-scope", "--no-reply-filter", "--no-mcp", "--no-net-proxy", "--no-exec-wrap", "--", "/bin/sh", "-c", "claude -p hi"],
        r.env({ PATH: `${r.dir}:${process.env["PATH"]}`, MANDU_DEV_REPO: broken }));
    } catch (e) { err = e; } finally { console.error = orig; }
    assert.match(`${String(err)}\n${errs.join("\n")}`, /the claude shim's preload is missing \(.*sdk-route-preload\.cjs\); reinstall Mandu/);
    assert.deepEqual(allRuns(r), [], "nothing started");
  });
});
