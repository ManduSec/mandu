/**
 * agent-own-sandbox.test — E2E: on macOS, when Mandu's Seatbelt profile wraps
 * a launch, Mandu turns the agent's OWN per-command sandbox off for the
 * session (macOS cannot start it inside Mandu's profile), unless the run asks
 * for it (src/codex-sandbox.ts, src/claude-sandbox.ts; decided 2026-10-02).
 * Through main(), with stand-in binaries NAMED `codex` and `claude` that
 * record the argv they received; the stand-in `claude` also answers Claude
 * Code's read-only `sandbox status` probe the way 2.1.286 does (on from the
 * settings files unless the last `--settings` says otherwise), logging the
 * environment each probe gets, and prints the version in the rig's
 * `version` file (default 2.1.286) for `--version`.
 *
 * The darwin cases run inside Mandu's real profile (mode off still applies
 * one: the TCP rules of landlock-net); `--no-landlock-net` in mode off
 * applies none, and then the agent's own sandbox stays. Linux: nothing
 * changes (there the agent's sandbox nests in Mandu's).
 */
import { test } from "node:test";
import "../lib/private-home.js"; // daemons' npm cache, the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:net";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { answerUnavailable } from "../lib/unanswered-arbiter.js";
// The launches below run in mode off, whose profile blocks no credential
// file: the OFF lines say so (the *_NO_CREDS wording), never claim it.
import { CODEX_SANDBOX_OFF_NOTE, CODEX_SANDBOX_OFF_NOTE_NO_CREDS as CODEX_OFF } from "../../src/codex-sandbox.js";
import { CLAUDE_SANDBOX_OFF_NOTE, CLAUDE_SANDBOX_OFF_NOTE_NO_CREDS as CLAUDE_OFF } from "../../src/claude-sandbox.js";

// Axes: stated per launch (MANDU_MODE: "off"); the decision is axis-independent.

const DARWIN = process.platform === "darwin";
// An administrator's Codex requirements on the host keep its sandbox on by
// design: the expectations below assume none.
const CODEX_ADMIN = existsSync("/etc/codex/requirements.toml") || existsSync("/etc/codex/managed_config.toml");
const SKIP_DARWIN = !DARWIN ? "macOS only (Mandu's Seatbelt profile)" : CODEX_ADMIN ? "this Mac has administrator Codex settings" : false;
const OFF = 'sandbox_mode="danger-full-access"';

interface Rig { dir: string; sock: string; codex: string; claude: string; argvFile: string; home: string; probeLog: string; versionFile: string }

async function withRig(fn: (r: Rig) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-own-sandbox-"));
  const sock = join(dir, "arbiter.sock");
  const srv: Server = createServer(answerUnavailable());
  srv.listen(sock);
  await once(srv, "listening");
  const argvFile = join(dir, "argv.json");
  const record = `require("fs").writeFileSync(${JSON.stringify(argvFile)}, JSON.stringify(process.argv.slice(2)));`;
  const codex = join(dir, "codex");
  writeFileSync(codex, `#!/usr/bin/env node\n${record}\n`, { mode: 0o755 });
  // The stand-in claude: `[--settings X] sandbox status` answers like 2.1.286
  // and logs the probe's environment; anything else records its argv.
  const claude = join(dir, "claude");
  const probeLog = join(dir, "probes.jsonl");
  const versionFile = join(dir, "version");
  writeFileSync(claude, `#!/usr/bin/env node
const fs = require("fs");
const a = process.argv.slice(2);
if (a[0] === "--version") {
  let v = "2.1.286";
  try { v = fs.readFileSync(${JSON.stringify(versionFile)}, "utf8").trim(); } catch {}
  console.log(v + " (Claude Code)");
  process.exit(0);
}
const si = a.indexOf("sandbox");
if (si >= 0 && a[si + 1] === "status") {
  const e = process.env;
  fs.appendFileSync(${JSON.stringify(probeLog)}, JSON.stringify({ base: e.ANTHROPIC_BASE_URL ?? null, quiet: e.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC ?? null,
    secrets: ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"].filter((k) => e[k] !== undefined) }) + "\\n");
  let s = null;
  for (let i = 0; i < si; i++) {
    if (a[i] === "--settings") s = a[i + 1];
    else if (a[i].startsWith("--settings=")) s = a[i].slice(11);
  }
  let on = process.env.STANDIN_SANDBOX_ON === "1", src = on ? "settings" : "off";
  if (s !== null && s.trim().startsWith("{")) {
    const v = JSON.parse(s);
    if (v.sandbox && typeof v.sandbox.enabled === "boolean") { on = v.sandbox.enabled; src = "policy"; }
  }
  console.log(JSON.stringify({ statusVersion: 3, enabled: on, enabledSource: src }));
  process.exit(0);
}
${record}
`, { mode: 0o755 });
  const home = join(dir, "home");
  mkdirSync(home);
  try { await fn({ dir, sock, codex, claude, argvFile, home, probeLog, versionFile }); } finally {
    srv.close(); rmSync(dir, { recursive: true, force: true });
  }
}

/** Claude Code's user settings in the rig's HOME: the sandbox on or off. */
function claudeSettings(r: Rig, on: boolean | null): void {
  mkdirSync(join(r.home, ".claude"), { recursive: true });
  const f = join(r.home, ".claude", "settings.json");
  if (on === null) rmSync(f, { force: true });
  else writeFileSync(f, JSON.stringify({ sandbox: { enabled: on } }));
}

// XDG_RUNTIME_DIR: the scope run dir in the test's own dir. CODEX_HOME: the
// test's own (empty), never the host's. HOME (claude): an empty one, so no
// host Claude Code settings or credential rules decide.
const env = (r: Rig, extra: Record<string, string> = {}) => ({
  HOME: process.env["HOME"], PWD: r.dir, MANDU_ARBITER_SOCK: r.sock, PATH: process.env["PATH"], CODEX_HOME: join(r.dir, "codex-home"),
  MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", XDG_RUNTIME_DIR: r.dir, OPENAI_API_KEY: "sk-test-only", ...extra,
});

/** Run main() with console.error captured (the launch notes' channel). */
async function launch(args: string[], e: Record<string, string | undefined>): Promise<{ code: number; notes: string }> {
  const orig = console.error;
  let notes = "";
  console.error = (...a: unknown[]) => { notes += a.map(String).join(" ") + "\n"; };
  try { return { code: await main(args, e), notes }; } finally { console.error = orig; }
}

/** The -c list Codex applies at the innermost level that has one (0.159.3:
 *  a level with any -c replaces the outer lists). */
function innermostConfig(argv: string[]): string[] {
  const levels: string[][] = [[]];
  const subs = new Set(["exec", "e", "resume", "fork", "review"]);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "-c") { levels[levels.length - 1]!.push(argv[++i]!); continue; }
    if (subs.has(a)) levels.push([]);
  }
  return [...levels].reverse().find((l) => l.length > 0) ?? [];
}

const got = (r: Rig): string[] => JSON.parse(readFileSync(r.argvFile, "utf8")) as string[];
const probeLog = (r: Rig): Array<{ base: string | null; quiet: string | null; secrets: string[] }> =>
  existsSync(r.probeLog) ? readFileSync(r.probeLog, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as { base: string | null; quiet: string | null; secrets: string[] }) : [];

test("macOS, codex exec with its own -c: Mandu's sandbox override sits at the root and the exec level, after the routing, in force at the innermost level; ONE line says so", { skip: SKIP_DARWIN }, async () => {
  await withRig(async (r) => {
    const { code, notes } = await launch(["--target", "codex", "--no-scope", "--no-reply-filter", "--", r.codex, "exec", "-c", "model=q", "--skip-git-repo-check", "hi"], env(r));
    assert.equal(code, 0);
    const a = got(r);
    assert.deepEqual(a.slice(0, 2), ["-c", "model_provider=mandu"], "the routing stays first");
    const execAt = a.indexOf("exec");
    assert.ok(a.slice(0, execAt).includes(OFF) && a.slice(execAt).includes(OFF), JSON.stringify(a));
    const inner = innermostConfig(a);
    assert.ok(inner.includes(OFF) && inner.includes("model_provider=mandu") && inner.includes("model=q"), JSON.stringify(inner));
    assert.ok(inner.indexOf(OFF) < inner.indexOf("model=q"), "the user's own -c at that level comes after Mandu's (a later -c sandbox_mode would win)");
    assert.equal(a[a.length - 1], "hi");
    assert.ok(notes.includes(CODEX_OFF), notes);
    assert.equal(notes.split(CODEX_OFF).length - 1, 1, "once");
    assert.ok(!notes.includes(CODEX_SANDBOX_OFF_NOTE), "mode off: no claim that credential files are blocked");
    assert.doesNotMatch(notes, /Codex's command sandbox network/, "the Linux network option makes no claim for a disabled macOS sandbox");
  });
});

test("macOS, codex --sandbox workspace-write: no override (the run asked for it); the WARNING says its commands will fail and how to let Mandu turn it off", { skip: SKIP_DARWIN }, async () => {
  await withRig(async (r) => {
    const { code, notes } = await launch(["--target", "codex", "--no-scope", "--no-reply-filter", "--", r.codex, "--sandbox", "workspace-write", "exec", "hi"], env(r));
    assert.equal(code, 0);
    assert.ok(!got(r).includes(OFF), JSON.stringify(got(r)));
    assert.match(notes, /WARNING — Codex cannot run commands inside Mandu on macOS \(this run asks for Codex's own sandbox \(--sandbox workspace-write\)/);
    assert.ok(!notes.includes(CODEX_OFF));
  });
});

test("macOS, codex login / --version: no model session, no override, no line", { skip: SKIP_DARWIN }, async () => {
  await withRig(async (r) => {
    for (const argv of [["login", "status"], ["--version"]]) {
      const { code, notes } = await launch(["--target", "codex", "--no-scope", "--no-reply-filter", "--", r.codex, ...argv], env(r));
      assert.equal(code, 0);
      assert.ok(!got(r).includes(OFF), JSON.stringify(got(r)));
      assert.doesNotMatch(notes, /own sandbox|Codex cannot run commands/);
    }
  });
});

test("macOS, no Mandu profile applied (mode off, --no-landlock-net): Codex's own sandbox works, so it stays: no override, no line", { skip: SKIP_DARWIN }, async () => {
  await withRig(async (r) => {
    const { code, notes } = await launch(["--target", "codex", "--no-scope", "--no-reply-filter", "--no-landlock-net", "--", r.codex, "exec", "hi"], env(r));
    assert.equal(code, 0);
    assert.ok(!got(r).includes(OFF), JSON.stringify(got(r)));
    assert.doesNotMatch(notes, /own sandbox is OFF|Codex cannot run commands/);
  });
});

test("macOS, claude with its sandbox on in its settings: Mandu's --settings carries sandbox.enabled false (probed off), ONE line says so; off in its settings: untouched", { skip: DARWIN ? false : "macOS only (Mandu's Seatbelt profile)" }, async () => {
  await withRig(async (r) => {
    claudeSettings(r, true);
    const on = await launch(["--target", "claude", "--no-scope", "--no-reply-filter", "--", r.claude, "-p", "hi"],
      env(r, { HOME: r.home, STANDIN_SANDBOX_ON: "1", ANTHROPIC_API_KEY: "sk-ant-fake-canary-0000", CLAUDE_CODE_OAUTH_TOKEN: "fake-oauth-canary" }));
    assert.equal(on.code, 0);
    const a = got(r);
    const last = a.lastIndexOf("--settings");
    assert.ok(last >= 0, JSON.stringify(a));
    assert.deepEqual((JSON.parse(a[last + 1]!) as { sandbox?: unknown }).sandbox, { enabled: false });
    assert.deepEqual(a.slice(-2), ["-p", "hi"], "the user's arguments follow, untouched");
    assert.ok(on.notes.includes(CLAUDE_OFF), on.notes);
    assert.ok(!on.notes.includes(CLAUDE_SANDBOX_OFF_NOTE), "mode off: no claim that credential files are blocked");
    // the probes ran with no credential and a dead model endpoint (no model
    // turn can happen outside Mandu), though the launch had a key
    const probes = probeLog(r);
    assert.equal(probes.length, 2, "before and after Mandu's setting");
    for (const p of probes) assert.deepEqual(p, { base: "http://127.0.0.1:9", quiet: "1", secrets: [] });
    claudeSettings(r, null);
    const off = await launch(["--target", "claude", "--no-scope", "--no-reply-filter", "--", r.claude, "-p", "hi"], env(r, { HOME: r.home }));
    assert.equal(off.code, 0);
    assert.ok(!got(r).some((x) => x.includes('"sandbox"')), JSON.stringify(got(r)));
    assert.ok(!off.notes.includes(CLAUDE_OFF));
  });
});

test("macOS, claude with the user's own --settings: Mandu merges sandbox.enabled false into it (Claude Code reads only the last); one that turns the sandbox on keeps it, with the WARNING", { skip: DARWIN ? false : "macOS only (Mandu's Seatbelt profile)" }, async () => {
  await withRig(async (r) => {
    claudeSettings(r, true);
    const merged = await launch(["--target", "claude", "--no-scope", "--no-reply-filter", "--", r.claude, "--settings", '{"model":"opus"}', "-p", "hi"], env(r, { HOME: r.home, STANDIN_SANDBOX_ON: "1" }));
    assert.equal(merged.code, 0);
    const a = got(r);
    const last = a.lastIndexOf("--settings");
    // The last --settings also carries the launch's routing env (claude-route.ts:
    // a settings file must not re-point the model traffic); the rest is the run's.
    const { env: routed, ...mergedRest } = JSON.parse(a[last + 1]!) as { env?: Record<string, string> };
    assert.deepEqual(mergedRest, { model: "opus", sandbox: { enabled: false } }, JSON.stringify(a));
    assert.match(routed?.ANTHROPIC_BASE_URL ?? "", /^http:\/\/127\.0\.0\.1:\d+$/, "the routing rides in the same --settings");
    assert.ok(merged.notes.includes(CLAUDE_OFF));
    const kept = await launch(["--target", "claude", "--no-scope", "--no-reply-filter", "--", r.claude, "--settings", '{"sandbox":{"enabled":true}}', "-p", "hi"], env(r, { HOME: r.home }));
    assert.equal(kept.code, 0);
    const b = got(r);
    const { env: routedB, ...keptRest } = JSON.parse(b[b.lastIndexOf("--settings") + 1]!) as { env?: Record<string, string> };
    assert.deepEqual(keptRest, { sandbox: { enabled: true } }, "the run's own choice, untouched");
    assert.match(routedB?.ANTHROPIC_BASE_URL ?? "", /^http:\/\/127\.0\.0\.1:\d+$/);
    assert.match(kept.notes, /WARNING: mandu: Claude Code's own sandbox is ON for this run \(your --settings\)/);
  });
});

test("macOS, claude on by settings Mandu cannot read (the status probe says on; no file Mandu reads does): left on, with the WARNING", { skip: DARWIN ? false : "macOS only (Mandu's Seatbelt profile)" }, async () => {
  await withRig(async (r) => {
    claudeSettings(r, null);
    const { code, notes } = await launch(["--target", "claude", "--no-scope", "--no-reply-filter", "--", r.claude, "-p", "hi"], env(r, { HOME: r.home, STANDIN_SANDBOX_ON: "1" }));
    assert.equal(code, 0);
    assert.ok(!got(r).some((x) => x.includes('"sandbox"')), JSON.stringify(got(r)));
    assert.match(notes, /WARNING: mandu: Claude Code's own sandbox is ON from settings Mandu cannot read/);
  });
});

test("macOS, a Claude Code below 2.1.284: the status probe never runs (an older one takes the words for a prompt); the settings files decide", { skip: DARWIN ? false : "macOS only (Mandu's Seatbelt profile)" }, async () => {
  await withRig(async (r) => {
    writeFileSync(r.versionFile, "2.1.273");
    claudeSettings(r, true);
    const { code, notes } = await launch(["--target", "claude", "--no-scope", "--no-reply-filter", "--", r.claude, "-p", "hi"], env(r, { HOME: r.home, STANDIN_SANDBOX_ON: "1" }));
    assert.equal(code, 0);
    assert.deepEqual(probeLog(r), [], "no `sandbox status` on a version without it");
    const a = got(r);
    assert.deepEqual((JSON.parse(a[a.lastIndexOf("--settings") + 1]!) as { sandbox?: unknown }).sandbox, { enabled: false }, "the user file turns it on: Mandu turns it off");
    assert.ok(notes.includes(CLAUDE_OFF), notes);
    // 2.1.284 itself has it
    writeFileSync(r.versionFile, "2.1.284");
    await launch(["--target", "claude", "--no-scope", "--no-reply-filter", "--", r.claude, "-p", "hi"], env(r, { HOME: r.home, STANDIN_SANDBOX_ON: "1" }));
    assert.equal(probeLog(r).length, 2);
  });
});

test("macOS, reviews 3 and 4: a permission profile in the project's .codex/config.toml (here or under -C) keeps Codex's sandbox (WARNING, no override); a Claude Code Read(...) deny rule on a file Mandu does not protect keeps Claude Code's", { skip: SKIP_DARWIN }, async () => {
  await withRig(async (r) => {
    const proj = join(r.dir, "proj");
    mkdirSync(join(proj, ".git"), { recursive: true });
    mkdirSync(join(proj, ".codex"));
    writeFileSync(join(proj, ".codex", "config.toml"), `default_permissions = "team"\n[permissions.team.filesystem]\n":minimal" = "read"\n"${join(r.dir, "prod-keys")}" = "deny"\n`);
    const back = process.cwd();
    process.chdir(proj);
    try {
      const cx = await launch(["--target", "codex", "--no-scope", "--no-reply-filter", "--", r.codex, "exec", "hi"], env(r, { PWD: proj }));
      assert.equal(cx.code, 0);
      assert.ok(!got(r).includes(OFF), JSON.stringify(got(r)));
      assert.ok(cx.notes.includes(`your Codex config relies on its own sandbox (a permission profile of your own (${join(proj, ".codex", "config.toml")}))`), cx.notes);
      assert.ok(!cx.notes.includes(CODEX_OFF));
    } finally {
      process.chdir(back);
    }
    // the same project named by the run's -C from elsewhere (review 4)
    const viaC = await launch(["--target", "codex", "--no-scope", "--no-reply-filter", "--", r.codex, "-C", proj, "exec", "hi"], env(r));
    assert.equal(viaC.code, 0);
    assert.ok(!got(r).includes(OFF), JSON.stringify(got(r)));
    assert.match(viaC.notes, /your Codex config relies on its own sandbox \(a permission profile of your own/);
    mkdirSync(join(r.home, ".claude"), { recursive: true });
    writeFileSync(join(r.home, ".claude", "settings.json"), JSON.stringify({ sandbox: { enabled: true }, permissions: { deny: ["Read(//etc/mdu-fake-acme.pem)"] } }));
    const cl = await launch(["--target", "claude", "--no-scope", "--no-reply-filter", "--", r.claude, "-p", "hi"], env(r, { HOME: r.home, STANDIN_SANDBOX_ON: "1" }));
    assert.equal(cl.code, 0);
    assert.ok(!got(r).some((x) => x.includes('"enabled":false')), JSON.stringify(got(r)));
    assert.match(cl.notes, /WARNING: mandu: Claude Code's own sandbox is ON .*Read\(\/\/etc\/mdu-fake-acme\.pem\)/);
    assert.ok(!cl.notes.includes(CLAUDE_OFF));
  });
});

test("Linux: nothing changes; Codex gets no sandbox override and Claude Code no sandbox setting (their sandboxes nest in Mandu's there)", { skip: DARWIN ? "Linux only" : false }, async () => {
  await withRig(async (r) => {
    const cx = await launch(["--target", "codex", "--no-scope", "--no-reply-filter", "--", r.codex, "exec", "hi"], env(r));
    assert.equal(cx.code, 0);
    assert.ok(!got(r).includes(OFF), JSON.stringify(got(r)));
    assert.ok(!cx.notes.includes(CODEX_OFF));
    const cl = await launch(["--target", "claude", "--no-scope", "--no-reply-filter", "--", r.claude, "-p", "hi"], env(r, { HOME: r.home, STANDIN_SANDBOX_ON: "1" }));
    assert.equal(cl.code, 0);
    assert.ok(!got(r).some((x) => x.includes('"enabled":false')), JSON.stringify(got(r)));
    assert.ok(!cl.notes.includes(CLAUDE_OFF));
  });
});


test("macOS: Linux's network opt-out does not restore Codex's sandbox under Seatbelt or claim that commands have no network", { skip: SKIP_DARWIN }, async () => {
  await withRig(async (r) => {
    const { code, notes } = await launch(["--target", "codex", "--no-scope", "--no-reply-filter", "--no-codex-shell-network", "--", r.codex, "exec", "hi"], env(r));
    assert.equal(code, 0);
    assert.ok(got(r).includes(OFF), "the non-nesting macOS sandbox decision remains in force");
    assert.ok(notes.includes(CODEX_OFF), "the actual sandbox-off choice is announced");
    assert.doesNotMatch(notes, /Codex's command sandbox network (?:stays off|left as|is ON)/);
  });
});
