/**
 * twin-write-notice.test.ts — a write the agent's programs make to a
 * registered secret file lands in the session's placeholder copy and is
 * discarded; the REAL launcher now says which files, by path only, when the
 * session ends (confidentiality-plan-10-flow-taint.md §4.1; guarantees.md
 * §2 and §3).
 *
 * Measured before (2026-10-09, the mount layer alone): in a shell launch
 * `echo FEATURE_X=1 >> .env` exited 0 and a later read in the session showed
 * the line, `printf 'NEW_TOKEN=…' > .env` exited 0 and was read back as
 * written, yet after the launch the real .env was byte-identical to the
 * original and Mandu printed nothing: the change went with the session's
 * secret-twins directory. The write path is deliberate (writing through
 * would put placeholders over the user's credential, write-protection.md
 * §2); the silence was the bug.
 *
 * withStack's private arbiter runs `secrets`; its throwaway HOME holds
 * `~/.aws/credentials` and the workspace a `.env` and `conf/.env` (catalog
 * files, confined by discovery). The real launcher runs a shell agent:
 *   W  (the default posture: the mount layer, plus the guard where it is
 *      built; the compact display, MANDU_VERBOSE=0; the scope dir removed
 *      at the end, MANDU_KEEP_SCOPE_DIR=0) appends to `.env` and
 *      overwrites `conf/.env` with a fresh token, and only reads
 *      `~/.aws/credentials`. Asserted: each write succeeded in the session;
 *      the launch prints exactly one notice line for each of the two
 *      changed files ("discarded it, and the real file is unchanged",
 *      checked) and none for the third; no notice carries a canary, the
 *      fresh token or the appended text; the real files are
 *      byte-identical; the `session_exit` event names the two paths.
 *   R  the same launch reading all three and writing a plain file prints
 *      no notice, and its `session_exit` names nothing.
 *   C  the real `.env` changes outside the session while the agent's
 *      change sits in its copy (the scope dir kept): its line says the real
 *      file also changed and that the copy stays until `mandu reap`; the
 *      line for `conf/.env` still says its real file is unchanged; and the
 *      launch removed its snapshot file, so reap does not say it twice.
 *   K  the launcher is killed (SIGKILL) mid-session after the writes: it
 *      says nothing, its scope dir and the twins' snapshots stay, and
 *      `mandu reap` names the two changed files, by path only, before it
 *      removes the dir.
 *   G  guard only (`--no-secret-bind`; skipped where the guard is not
 *      built): the guard hands the write the same twin file, and the
 *      notice names it the same way.
 *
 * `--no-reply-filter` keeps stdout as the AGENT sees it. GATED on Linux +
 * bwrap + an unprivileged userns (the guard-only case also on the built
 * guard); zero API budget.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { withStack, runLauncher, probeKernelTier } from "../../lib/launcher-live.js";
import { installExitGuard } from "../../lib/exit-guard.js";
import { pickGuard } from "../../lib/native-guard.js";
import { stateAxes } from "../../lib/axes.js";

installExitGuard("twin-write-notice");

// This suite STATES its axes (protection-modes.md §4): `secrets`. withStack
// brings its private arbiter up in the same mode.
stateAxes("secrets");

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const probe = process.platform === "linux" ? probeKernelTier() : null;
const GATE = process.platform !== "linux"
  ? "Linux only (bwrap secret twins)"
  : !probe!.bwrap
    ? "`bwrap` not installed"
    : !probe!.userns
      ? "unprivileged user namespaces unavailable"
      : false;
const GUARD_GATE = GATE !== false ? GATE : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)" : false;

const ENV_KEY = "sk_live_CANARYtwinwrite7f3a91c0d2e4";
const CONF_KEY = "sk_live_CANARYtwinconf0c9d8e7f6a5b";
const AWS_KEY = "awsCANARYtwinwrite0b1c2d3e4f5a6b7c8";
const CANARIES = [ENV_KEY, CONF_KEY, AWS_KEY];
/** What a program writes into the copy: a refreshed token, and a new line. */
const FRESH = "ghp_FRESHtokenWRITTENinSESSION0123456789";
const APPENDED = "FEATURE_X_TWIN_WRITE=1";
const NOTICE = /^mandu: during this session the agent changed (.+); Mandu kept the change in its placeholder copy and discarded it, and the real file is unchanged\. Apply the change yourself if you want it\.$/;
/** The same, with the scope dir kept: "did not apply it (… until `mandu reap` …)", then what became of the real file. */
const KEPT = /^mandu: during this session the agent changed (.+); Mandu kept the change in its placeholder copy and did not apply it \(the copy stays in the session's scope dir until `mandu reap` removes it\)(, and the real file is unchanged\. Apply the change yourself if you want it\.|\. The real file also changed during the session, so check it before you apply the change yourself\.)$/;
/** `mandu reap`'s line for a session whose launcher died first. */
const REAPED = /^ {2}the session (\d+-\d+) ended before Mandu could say so: its agent changed (.+); the change went to the file's placeholder copy, which goes with the scope dir, never to the real file\. Apply it yourself if you want it\.$/;

/** The writing agent, in bash. Tools by absolute path (withStack's HOME is
 *  under /tmp, which the exec box replaces); the redirections are bash's. */
const WRITE_SCRIPT = String.raw`
set -u
cd "$WS"
echo '${APPENDED}' >> .env; echo "APPEND_RC $?"
/bin/grep -q '^${APPENDED}$' .env && echo "APPEND_SEEN yes" || echo "APPEND_SEEN no"
printf 'NEW_TOKEN=%s\n' "$FRESH" > conf/.env; echo "OVERWRITE_RC $?"
/bin/grep -q "^NEW_TOKEN=$FRESH$" conf/.env && echo "OVERWRITE_SEEN yes" || echo "OVERWRITE_SEEN no"
echo "AWS_BYTES $(/bin/cat "$HOME/.aws/credentials" | /usr/bin/wc -c)"
echo "AGENT_DONE"
`;

/** The writing agent that then waits: both writes, a flag the test sees
 *  (the workspace is the host's), and a wait (bounded) for the test's go. */
const WRITE_THEN_WAIT_SCRIPT = String.raw`
set -u
cd "$WS"
echo '${APPENDED}' >> .env; echo "APPEND_RC $?"
printf 'NEW_TOKEN=%s\n' "$FRESH" > conf/.env; echo "OVERWRITE_RC $?"
: > ready.flag
i=0; while [ ! -e go.flag ] && [ $i -lt 1200 ]; do /bin/sleep 0.1; i=$((i+1)); done
echo "AGENT_DONE"
`;

/** The reading agent: every secret read, a plain file written, no secret written. */
const READ_SCRIPT = String.raw`
set -u
cd "$WS"
for f in .env conf/.env "$HOME/.aws/credentials"; do echo "READ $f $(/bin/cat "$f" | /usr/bin/wc -c)"; done
echo 'a plain note' >> notes.md; echo "PLAIN_RC $?"
echo "AGENT_DONE"
`;

interface Seeded { env: string; conf: string; aws: string; before: Map<string, Buffer> }

function seed(workspace: string, home: string): Seeded {
  const env = join(workspace, ".env");
  writeFileSync(env, `API_KEY=${ENV_KEY}\nDEBUG=1\n`, { mode: 0o600 });
  mkdirSync(join(workspace, "conf"), { recursive: true });
  const conf = join(workspace, "conf", ".env");
  writeFileSync(conf, `API_KEY=${CONF_KEY}\n`, { mode: 0o600 });
  mkdirSync(join(home, ".aws"), { recursive: true, mode: 0o700 });
  const aws = join(home, ".aws", "credentials");
  writeFileSync(aws, `[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = ${AWS_KEY}\n`, { mode: 0o600 });
  return { env, conf, aws, before: new Map([env, conf, aws].map((p) => [p, readFileSync(p)])) };
}

/** The launcher's `session_exit` events the private arbiter stored. */
function sessionExits(tmp: string): Array<Record<string, unknown>> {
  const dir = join(tmp, "events");
  if (!existsSync(dir)) return [];
  const out: Array<Record<string, unknown>> = [];
  for (const f of readdirSync(dir, { recursive: true }) as string[]) {
    if (!f.endsWith(".ndjson")) continue;
    for (const l of readFileSync(join(dir, f), "utf8").split("\n")) {
      if (l.includes('"session_exit"')) out.push(JSON.parse(l) as Record<string, unknown>);
    }
  }
  return out;
}

type Ctx = { tmp: string; workspace: string; home: string; launcherEnv: (u: string, p: number) => Record<string, string | undefined> };

async function launch(
  ctx: Ctx, script: string, extraArgs: string[], extraEnv: Record<string, string> = {},
): Promise<{ code: number; out: string; diag: string }> {
  const agent = join(ctx.tmp, "agent.sh");
  writeFileSync(join(ctx.tmp, "work.sh"), script);
  writeFileSync(agent, `WS='${ctx.workspace}' FRESH='${FRESH}' exec bash ${join(ctx.tmp, "work.sh")}\n`);
  const env = { ...ctx.launcherEnv("https://127.0.0.1:1", 0), HOME: ctx.home, ...extraEnv };
  const r = await runLauncher(["--no-scope", "--no-mcp", "--no-reply-filter", "--target", "claude", ...extraArgs, "--", "/bin/sh", agent], env, ctx.workspace, 240_000);
  return { ...r, diag: `\n--- launch output (tail) ---\n${r.out.slice(-6000)}` };
}

/** Wait for `path` while the launch runs: true once it exists, false when
 *  the launch ended first or the time ran out. */
async function untilFile(path: string, running: Promise<unknown>, timeoutMs: number): Promise<boolean> {
  let ended = false;
  running.then(() => { ended = true; }, () => { ended = true; });
  for (const end = Date.now() + timeoutMs; Date.now() < end;) {
    if (existsSync(path)) return true;
    if (ended) return existsSync(path);
    await new Promise((r) => setTimeout(r, 100));
  }
  return false;
}

/** The launch's scope dir (`<XDG_RUNTIME_DIR>/mandu/<epochSec>-<pid>`, the
 *  launcher's pid) and that pid; null when there is not exactly one. */
function scopeDirOf(tmp: string): { dir: string; pid: number } | null {
  const base = join(tmp, "mandu");
  let names: string[];
  try { names = readdirSync(base); } catch { return null; }
  const scopes = names.map((n) => /^\d+-(\d+)$/.exec(n)).filter((m): m is RegExpExecArray => m !== null);
  return scopes.length === 1 ? { dir: join(base, scopes[0]![0]), pid: Number(scopes[0]![1]) } : null;
}

function pidAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (e) { return (e as NodeJS.ErrnoException).code === "EPERM"; }
}

/** The checks every writing launch shares. */
function assertWriteNoticed(r: { code: number; out: string; diag: string }, s: Seeded, tmp: string): void {
  const { out, diag } = r;
  assert.equal(r.code, 0, `the launch failed${diag}`);
  assert.ok(out.includes("AGENT_DONE"), `the agent's script did not finish${diag}`);
  // THE LEAK ORACLE first: no canary reached the agent's world.
  for (const c of CANARIES) assert.ok(!out.includes(c), `CONFIDENTIALITY VIOLATION: ${c} reached the agent's world${diag}`);
  // The writes succeeded in the session (into the placeholder copy).
  for (const l of ["APPEND_RC 0", "APPEND_SEEN yes", "OVERWRITE_RC 0", "OVERWRITE_SEEN yes"]) {
    assert.ok(out.split("\n").includes(l), `${l}${diag}`);
  }
  assert.match(out, /^AWS_BYTES [1-9]\d*$/m, `the agent read the credentials file${diag}`);

  // One notice line per changed file, by path only; none for the file only read.
  const notices = out.split("\n").filter((l) => l.startsWith("mandu: during this session"));
  const named = notices.map((l) => NOTICE.exec(l)?.[1]);
  assert.deepEqual([...named].sort(), [s.conf, s.env].sort(), `the notice names .env and conf/.env, once each:\n${notices.join("\n")}${diag}`);
  for (const l of notices) {
    for (const v of [...CANARIES, FRESH, APPENDED, "$MDU:"]) assert.ok(!l.includes(v), `a notice carries ${v}: ${l}`);
  }

  // The real files never changed.
  for (const [p, b] of s.before) assert.ok(readFileSync(p).equals(b), `${p} changed on disk${diag}`);

  // The dashboard's record: the session_exit event names the same two paths.
  const exits = sessionExits(tmp);
  assert.equal(exits.length, 1, `one session_exit event${diag}`);
  assert.deepEqual([...((exits[0]!["discardedWrites"] as string[] | undefined) ?? [])].sort(), [s.conf, s.env].sort(), JSON.stringify(exits[0]));
  assert.ok(!JSON.stringify(exits[0]).includes(FRESH), "the event never carries the content");
}

test("LIVE (default posture, compact display): a write to a registered file is named at the end, the real file unchanged", { skip: GATE, timeout: 300_000 }, async () => {
  await withStack(async (ctx) => {
    const s = seed(ctx.workspace, ctx.home);
    // The compact display (no --verbose): the notice prints whatever the
    // setting. The scope dir goes at the end (the harness keeps it by
    // default), so the copy is discarded and the line says so.
    const r = await launch(ctx, WRITE_SCRIPT, [], { MANDU_VERBOSE: "0", MANDU_KEEP_SCOPE_DIR: "0" });
    // The default banner (packaging.md §5) opens with the mode and what it masks.
    assert.match(r.out, /mandu: secrets mode · (?:\d+ credential files?(?:, \d+ env vars?)? masked|credential files GATED \(\d+ behind a placeholder)/, `the placeholder copies engaged${r.diag}`);
    assertWriteNoticed(r, s, ctx.tmp);
    console.error(`twin-write-notice (default${GUARD.path ? ", guard built" : ", mount layer only"}): 2 files named, the real files unchanged`);
  }, { mode: "secrets" });
});

test("LIVE: a launch that only reads its secrets (and writes a plain file) prints no notice", { skip: GATE, timeout: 300_000 }, async () => {
  await withStack(async (ctx) => {
    const s = seed(ctx.workspace, ctx.home);
    const r = await launch(ctx, READ_SCRIPT, []);
    assert.equal(r.code, 0, `the launch failed${r.diag}`);
    assert.ok(r.out.includes("AGENT_DONE"), `the agent's script did not finish${r.diag}`);
    assert.ok(/confidentiality — \d+ secret\(s\) (?:confined|behind placeholder copies by the mount layer only)/.test(r.out), `the twins engaged${r.diag}`);
    for (const c of CANARIES) assert.ok(!r.out.includes(c), `CONFIDENTIALITY VIOLATION: ${c} reached the agent's world${r.diag}`);
    assert.equal(r.out.split("\n").filter((l) => /^READ .+ [1-9]\d*$/.test(l)).length, 3, `every secret was read${r.diag}`);
    assert.ok(r.out.split("\n").includes("PLAIN_RC 0"), r.diag);
    assert.ok(!/during this session the agent changed/.test(r.out), `no notice for a session that changed no secret file${r.diag}`);
    for (const [p, b] of s.before) assert.ok(readFileSync(p).equals(b), `${p} changed on disk`);
    const exits = sessionExits(ctx.tmp);
    assert.equal(exits.length, 1, r.diag);
    assert.equal("discardedWrites" in exits[0]!, false, JSON.stringify(exits[0]));
  }, { mode: "secrets" });
});

test("LIVE: the real file changed meanwhile (scope dir kept): its line says so, never that it is unchanged", { skip: GATE, timeout: 300_000 }, async () => {
  await withStack(async (ctx) => {
    const s = seed(ctx.workspace, ctx.home);
    const ready = join(ctx.workspace, "ready.flag");
    // The harness keeps the scope dir (MANDU_KEEP_SCOPE_DIR=1).
    const running = launch(ctx, WRITE_THEN_WAIT_SCRIPT, []);
    const sawReady = await untilFile(ready, running, 200_000);
    // The user edits the real .env in another terminal while the agent's
    // change sits in its placeholder copy.
    const OUTSIDE = "EDITED_OUTSIDE_THE_SESSION=1";
    if (sawReady) appendFileSync(s.env, `${OUTSIDE}\n`);
    writeFileSync(join(ctx.workspace, "go.flag"), "");
    const r = await running;
    assert.ok(sawReady, `the agent never signalled its writes${r.diag}`);
    assert.equal(r.code, 0, `the launch failed${r.diag}`);
    assert.ok(r.out.includes("AGENT_DONE"), r.diag);
    for (const c of CANARIES) assert.ok(!r.out.includes(c), `CONFIDENTIALITY VIOLATION: ${c} reached the agent's world${r.diag}`);
    for (const l of ["APPEND_RC 0", "OVERWRITE_RC 0"]) assert.ok(r.out.split("\n").includes(l), `${l}${r.diag}`);

    const notices = r.out.split("\n").filter((l) => l.startsWith("mandu: during this session"));
    const byPath = new Map(notices.map((l) => { const m = KEPT.exec(l); return [m?.[1] ?? `unmatched: ${l}`, m?.[2] ?? ""]; }));
    assert.deepEqual([...byPath.keys()].sort(), [s.conf, s.env].sort(), `one kept-copy line each for .env and conf/.env:\n${notices.join("\n")}${r.diag}`);
    assert.match(byPath.get(s.env)!, /The real file also changed during the session/, "the edited real file is never called unchanged");
    assert.match(byPath.get(s.conf)!, /the real file is unchanged/, "the untouched one is, checked");
    for (const l of notices) for (const v of [...CANARIES, FRESH, APPENDED, OUTSIDE]) assert.ok(!l.includes(v), `a notice carries ${v}: ${l}`);

    // The real files: .env holds the outside edit and never the agent's line.
    assert.equal(readFileSync(s.env, "utf8"), `${s.before.get(s.env)!.toString("utf8")}${OUTSIDE}\n`);
    assert.ok(readFileSync(s.conf).equals(s.before.get(s.conf)!), "conf/.env unchanged");
    // Said once: the kept scope dir no longer holds the twins' snapshots, so
    // `mandu reap` will not say it again.
    const scope = scopeDirOf(ctx.tmp);
    assert.ok(scope !== null && existsSync(join(scope.dir, "secret-twins")), `the scope dir was kept${r.diag}`);
    assert.equal(existsSync(join(scope.dir, "secret-twins", "twin-snapshots.json")), false, "the snapshot file went once the launch said it");
    console.error("twin-write-notice (real file changed meanwhile, scope kept): worded by the check");
  }, { mode: "secrets" });
});

test("LIVE: a launcher killed mid-session says nothing; `mandu reap` names the changed files before it removes the scope dir", { skip: GATE, timeout: 300_000 }, async () => {
  await withStack(async (ctx) => {
    const s = seed(ctx.workspace, ctx.home);
    const ready = join(ctx.workspace, "ready.flag");
    const running = launch(ctx, WRITE_THEN_WAIT_SCRIPT, []);
    const sawReady = await untilFile(ready, running, 200_000);
    const scope = scopeDirOf(ctx.tmp);
    // A crash, an OOM kill: the launcher's own end never runs.
    if (sawReady && scope !== null) process.kill(scope.pid, "SIGKILL");
    writeFileSync(join(ctx.workspace, "go.flag"), "");
    const r = await running;
    assert.ok(sawReady, `the agent never signalled its writes${r.diag}`);
    assert.ok(scope !== null, `one scope dir under ${ctx.tmp}/mandu${r.diag}`);
    for (const c of CANARIES) assert.ok(!r.out.includes(c), `CONFIDENTIALITY VIOLATION: ${c} reached the agent's world${r.diag}`);
    assert.ok(!/during this session the agent changed/.test(r.out), `a killed launcher prints nothing${r.diag}`);
    for (let i = 0; i < 100 && pidAlive(scope.pid); i++) await new Promise((res) => setTimeout(res, 100));
    assert.equal(pidAlive(scope.pid), false, `launcher pid ${scope.pid} is gone`);
    assert.ok(existsSync(join(scope.dir, "secret-twins", "twin-snapshots.json")), "the twins' snapshots stay for reap");

    const env = { ...ctx.launcherEnv("https://127.0.0.1:1", 0), HOME: ctx.home };
    const reap = await runLauncher(["reap"], env, ctx.workspace, 60_000);
    const diag = `\n--- mandu reap ---\n${reap.out}`;
    assert.equal(reap.code, 0, diag);
    const lines = reap.out.split("\n").filter((l) => l.includes("ended before Mandu could say so"));
    const named = lines.map((l) => REAPED.exec(l));
    assert.ok(named.every((m) => m !== null && m[1] === scope.dir.split("/").pop()), `each line names the dead session:\n${lines.join("\n")}${diag}`);
    assert.deepEqual(named.map((m) => m![2]).sort(), [s.conf, s.env].sort(), `reap names .env and conf/.env, once each, never ~/.aws/credentials${diag}`);
    for (const l of lines) for (const v of [...CANARIES, FRESH, APPENDED, "$MDU:"]) assert.ok(!l.includes(v), `a reap line carries ${v}: ${l}`);
    assert.match(reap.out, /rm-stale-scope-dir: scope \d+-\d+: launcher pid \d+ is dead/, diag);
    assert.equal(existsSync(scope.dir), false, `reap removed the scope dir${diag}`);
    for (const [p, b] of s.before) assert.ok(readFileSync(p).equals(b), `${p} changed on disk`);
    console.error("twin-write-notice (launcher killed): mandu reap named 2 files");
  }, { mode: "secrets" });
});

test("LIVE (guard only): the guard hands the write the same placeholder copy, and the notice names it", { skip: GUARD_GATE, timeout: 300_000 }, async () => {
  await withStack(async (ctx) => {
    const s = seed(ctx.workspace, ctx.home);
    const r = await launch(ctx, WRITE_SCRIPT, ["--no-secret-bind"], { MANDU_KEEP_SCOPE_DIR: "0" });
    assert.ok(/bind mount SKIPPED \(--no-secret-bind\)/.test(r.out), `the guard-only posture${r.diag}`);
    assert.ok(/net-guard LIVE/.test(r.out), `the guard engaged${r.diag}`);
    assertWriteNoticed(r, s, ctx.tmp);
    console.error("twin-write-notice (guard only): 2 files named, the real files unchanged");
  }, { mode: "secrets" });
});
