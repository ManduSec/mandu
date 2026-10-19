/**
 * hard-link-twin-meta.test.ts — a protected file with a second hard link,
 * made before the launch, shows the placeholder file's size under BOTH names
 * in the bind posture, under the REAL launcher (P0 4c, 2026-10-09;
 * confidentiality.md §7.2a "Another name for a twinned file").
 *
 * Measured before: the bind puts the placeholder file over the protected
 * file's own name only. With `.env` hard-linked as `notes.bak` before the
 * launch, `stat notes.bak` in the agent's shell printed the REAL file's
 * size (the token's length, give or take), inode, link count and mtime: the
 * guard's stat trap is off under the bind. The launcher now turns it on for
 * a session whose protected file has `st_nlink > 1`, and says so in one
 * line; the guard (outside the bind) matches every name of the file by
 * inode and answers the placeholder file's metadata.
 *
 * withStack's private arbiter runs `secrets`; the real launcher (the guard
 * on, the default bind posture) runs a shell agent that stats both names
 * by `stat` (an lstat), `stat -L` (a following stat) and, where python3 is
 * installed, `os.stat`/`os.lstat`, and measures what `cat` reads. Asserted:
 *   - THE LEAK ORACLE: the canary never reaches the agent's output;
 *   - under both names, by every form, the size is the bytes `cat` reads
 *     (the placeholder file's) and never the real file's, the mtime is not
 *     the real file's (set to 2001 before the launch), and the inode is the
 *     one the registered name shows;
 *   - the launch says the protected file has another name on disk.
 *
 * `--no-reply-filter` keeps stdout as the AGENT sees it. GATED on Linux +
 * bwrap + an unprivileged userns + the built guard; zero API budget.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { linkSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { withStack, runLauncher, probeKernelTier } from "../../lib/launcher-live.js";
import { installExitGuard } from "../../lib/exit-guard.js";
import { pickGuard } from "../../lib/native-guard.js";
import { stateAxes } from "../../lib/axes.js";

installExitGuard("hard-link-twin-meta");

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
      : !GUARD.path
        ? "mandu-net-guard is not built (scripts/build-native.sh)"
        : false;
const HAS_PY = spawnSync("sh", ["-c", "command -v python3"]).status === 0;

const KEY = "sk_live_CANARYhardlink4c7e2a91d0b3f5";
const OLD = 1_000_000_000; // the real file's mtime: 2001-09-09

/** The agent's work. Tools by absolute path (withStack's HOME is under
 *  /tmp, which the exec box replaces). Each line: `META <name> <form> <size>
 *  <inode> <links> <mtime>`, and `READ <name> <bytes cat reads>`. */
const AGENT_SCRIPT = String.raw`
set -u
cd "$WS"
for f in .env notes.bak; do
  echo "META $f lstat $(/usr/bin/stat -c '%s %i %h %Y' "$f")"
  echo "META $f stat $(/usr/bin/stat -L -c '%s %i %h %Y' "$f")"
  if [ -n "$PY" ]; then
    "$PY" -c 'import os, sys
f = sys.argv[1]
for form, st in (("py_stat", os.stat(f)), ("py_lstat", os.lstat(f))):
    print("META %s %s %d %d %d %d" % (f, form, st.st_size, st.st_ino, st.st_nlink, int(st.st_mtime)))' "$f"
  fi
  echo "READ $f $(/bin/cat "$f" | /usr/bin/wc -c)"
done
echo "AGENT_DONE"
`;

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("LIVE (bind): a protected file's hard link of another name, made before the launch, shows the placeholder file's size, inode and times by every stat form", { skip: GATE, timeout: 300_000 }, async () => {
  await withStack(async ({ tmp, workspace, home, launcherEnv }) => {
    const env = join(workspace, ".env");
    writeFileSync(env, `API_KEY=${KEY}\nDEBUG=1\n`, { mode: 0o600 });
    utimesSync(env, OLD, OLD);
    linkSync(env, join(workspace, "notes.bak"));
    const real = statSync(env);
    assert.equal(real.nlink, 2);

    const script = join(tmp, "agent.sh");
    writeFileSync(join(tmp, "work.sh"), AGENT_SCRIPT);
    const py = HAS_PY ? spawnSync("sh", ["-c", "command -v python3"]).stdout.toString().trim() : "";
    writeFileSync(script, `WS='${workspace}' PY='${py}' exec bash ${join(tmp, "work.sh")}\n`);
    const r = await runLauncher(
      ["--no-scope", "--no-mcp", "--no-reply-filter", "--target", "claude", "--", "/bin/sh", script],
      { ...launcherEnv("https://127.0.0.1:1", 0), HOME: home },
      workspace,
      240_000,
    );
    const out = r.out;
    const diag = `\n--- launch output (tail) ---\n${out.slice(-6000)}`;
    assert.equal(r.code, 0, `the launch failed${diag}`);
    assert.ok(out.includes("AGENT_DONE"), `the agent's script did not finish${diag}`);
    assert.ok(/confidentiality — \d+ secret\(s\) confined/.test(out), `the twins engaged${diag}`);
    assert.ok(/net-guard LIVE/.test(out), `the guard engaged${diag}`);
    assert.ok(!/bind mount SKIPPED|mount layer is off/.test(out), `the bind posture${diag}`);

    // THE LEAK ORACLE first.
    assert.ok(!out.includes(KEY), `CONFIDENTIALITY VIOLATION: the canary reached the agent's world${diag}`);

    const lines = out.split("\n");
    const read = new Map(lines.filter((l) => l.startsWith("READ ")).map((l) => { const [, n, b] = l.split(" "); return [n!, Number(b)] as const; }));
    const twinSize = read.get(".env");
    assert.ok(twinSize !== undefined && twinSize > 0, `cat .env: ${twinSize}${diag}`);
    assert.equal(read.get("notes.bak"), twinSize, `cat of the hard link reads the placeholder file too${diag}`);
    assert.notEqual(twinSize, real.size, "the placeholder file differs in size from the real one (the test's premise)");

    const metas = lines.filter((l) => l.startsWith("META ")).map((l) => {
      const [, name, form, size, ino, links, mtime] = l.trim().split(/\s+/);
      return { name: name!, form: form!, size: Number(size), ino: Number(ino), links: Number(links), mtime: Number(mtime), line: l };
    });
    const forms = HAS_PY ? ["lstat", "stat", "py_stat", "py_lstat"] : ["lstat", "stat"];
    assert.equal(metas.length, 2 * forms.length, `every name by every form${diag}`);
    const regIno = metas.find((m) => m.name === ".env" && m.form === "stat")!.ino;
    assert.notEqual(regIno, real.ino, "the registered name shows the placeholder file (the bind)");
    for (const m of metas) {
      assert.equal(m.size, twinSize, `${m.name} ${m.form}: the size is the placeholder file's, not the real ${real.size}: ${m.line}${diag}`);
      assert.notEqual(m.ino, real.ino, `${m.name} ${m.form}: the real inode: ${m.line}`);
      assert.equal(m.ino, regIno, `${m.name} ${m.form}: every name shows the same file as the registered name: ${m.line}`);
      assert.notEqual(m.mtime, OLD, `${m.name} ${m.form}: the real mtime: ${m.line}`);
      assert.equal(m.links, 1, `${m.name} ${m.form}: the placeholder file's link count: ${m.line}`);
    }
    assert.ok(/another name on disk \(a hard link\)/.test(out), `the launch says why stats are slower${diag}`);
    console.error(`hard-link-twin-meta (bind): ${metas.length} looks, every one the placeholder file's (${twinSize} bytes, real ${real.size})`);
  }, { mode: "secrets" });
});
