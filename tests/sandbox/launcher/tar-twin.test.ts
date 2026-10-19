/**
 * tar-twin.test.ts — GNU tar archives the secrets of a confined launch as
 * any non-reader sees them, under the REAL launcher (2026-10-03;
 * confidentiality.md §7.2a "An open the guard performs").
 *
 * Measured before: under a confined launch `tar cf x.tar conf/.env` (any
 * argument with a directory part, a secret or not) failed "Cannot stat:
 * Invalid argument": GNU tar 1.35 opens the argument's parent with
 * `openat2(…, O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)`, the guard performs
 * every openat2, and its performer added `O_NOCTTY`, which openat2 refuses
 * beside `O_PATH`. The guard-level suite (tests/sandbox/guard/tar-secret)
 * covers the reader lists; this one the product's two postures.
 *
 * withStack's throwaway HOME holds `~/.aws/credentials` and the workspace a
 * `.env` and `conf/.env` (catalog files, confined by discovery). The private
 * arbiter runs `secrets`; the real launcher (the guard on) runs a shell
 * agent, once with the twin binds (the default) and once guard-only
 * (`--no-secret-bind`, where the guard serves the twin by descriptor and an
 * lstat still sees the real size). In each, the agent's tar archives a
 * relative `dir/file`, an absolute path, a directory and a HOME file into
 * the workspace's `out/`. Asserted, the archives read outside the launch:
 *   - THE LEAK ORACLE: no archive holds a byte of a canary, and no canary
 *     reaches the agent's output;
 *   - tar exits 0 every time, with no "Invalid argument" and no "file changed
 *     as we read it";
 *   - each secret's member is exactly what `cat` of it shows the agent (the
 *     twin), and a plain file beside it is archived as written.
 *
 * `--no-reply-filter` keeps stdout as the AGENT sees it. GATED on Linux +
 * bwrap + an unprivileged userns + the built guard; zero API budget.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { withStack, runLauncher, probeKernelTier } from "../../lib/launcher-live.js";
import { installExitGuard } from "../../lib/exit-guard.js";
import { pickGuard } from "../../lib/native-guard.js";
import { stateAxes } from "../../lib/axes.js";

installExitGuard("tar-twin");

// This suite STATES its axes (protection-modes.md §4): `secrets`. withStack
// brings its private arbiter up in the same mode.
stateAxes("secrets");

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const probe = process.platform === "linux" ? probeKernelTier() : null;
const has = (p: string): boolean => spawnSync("sh", ["-c", `command -v ${p}`]).status === 0;
const GATE = process.platform !== "linux"
  ? "Linux only (bwrap secret twins)"
  : !probe!.bwrap
    ? "`bwrap` not installed"
    : !probe!.userns
      ? "unprivileged user namespaces unavailable"
      : !GUARD.path
        ? "mandu-net-guard is not built (scripts/build-native.sh)"
        : !has("tar")
          ? "tar is not installed"
          : false;

const ENV_KEY = "sk_live_CANARYtar7f3a91c0d2e4b6";
const CONF_KEY = "sk_live_CANARYconf0c9d8e7f6a5b4";
const AWS_KEY = "awsCANARYtar0b1c2d3e4f5a6b7c8d9e";
const CANARIES = [ENV_KEY, CONF_KEY, AWS_KEY];
const sha256 = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");

/** The agent's work, in bash (a child of the agent `/bin/sh`). Tools by
 *  absolute path where the exec-box shims them (withStack's HOME is under
 *  /tmp, which the box replaces). Each `cat` prints the hash of what the
 *  agent sees, so the test compares the archives with it. */
const AGENT_SCRIPT = String.raw`
set -u
cd "$WS"
/usr/bin/mkdir -p out
run() { local tag="$1"; shift; tar "$@" 2>"out/$tag.err"; echo "$tag EXIT $?"; /usr/bin/sed "s/^/$tag ERR /" "out/$tag.err"; }
run REL cf out/rel.tar conf/.env conf/plain.txt
run ABS cf out/abs.tar "$WS/.env"
run DIR cf out/dir.tar conf
run HOME cf out/home.tar "$HOME/.aws/credentials"
run BARE cf out/bare.tar .env
for f in .env conf/.env "$HOME/.aws/credentials"; do
  echo "SEEN $f $(/bin/cat "$f" | /usr/bin/sha256sum | /usr/bin/cut -c1-64)"
done
echo "AGENT_DONE"
`;

/** A member's bytes, read outside the launch. */
function member(archive: string, name: string): Buffer {
  const r = spawnSync("tar", ["-xOf", archive, name]);
  assert.equal(r.status, 0, `tar -xOf ${archive} ${name}: ${String(r.stderr)}`);
  return r.stdout;
}

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

for (const posture of ["bind", "guard-only"] as const) {
  test(`LIVE (${posture}): tar archives the twins of a confined launch's secrets, exit 0, never a raw byte`, { skip: GATE, timeout: 300_000 }, async () => {
    await withStack(async ({ tmp, workspace, home, launcherEnv }) => {
      writeFileSync(join(workspace, ".env"), `API_KEY=${ENV_KEY}\nDEBUG=1\n`, { mode: 0o600 });
      mkdirSync(join(workspace, "conf"), { recursive: true });
      writeFileSync(join(workspace, "conf", ".env"), `API_KEY=${CONF_KEY}\n`, { mode: 0o600 });
      writeFileSync(join(workspace, "conf", "plain.txt"), "hello\n");
      mkdirSync(join(home, ".aws"), { recursive: true, mode: 0o700 });
      const aws = join(home, ".aws", "credentials");
      writeFileSync(aws, `[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = ${AWS_KEY}\n`, { mode: 0o600 });
      const script = join(tmp, "agent.sh");
      writeFileSync(join(tmp, "work.sh"), AGENT_SCRIPT);
      writeFileSync(script, `WS='${workspace}' exec bash ${join(tmp, "work.sh")}\n`);
      const env = { ...launcherEnv("https://127.0.0.1:1", 0), HOME: home };
      const args = ["--no-scope", "--no-mcp", "--no-reply-filter", "--target", "claude"];
      if (posture === "guard-only") args.push("--no-secret-bind");
      const r = await runLauncher([...args, "--", "/bin/sh", script], env, workspace, 240_000);
      const out = r.out;
      const diag = `\n--- launch output (tail) ---\n${out.slice(-6000)}`;
      const tagged = (t: string): string[] => out.split("\n").filter((l) => l.startsWith(`${t} `)).map((l) => l.slice(t.length + 1));

      assert.equal(r.code, 0, `the launch failed${diag}`);
      assert.ok(out.includes("AGENT_DONE"), `the agent's script did not finish${diag}`);
      assert.ok(/confidentiality — \d+ secret\(s\) confined/.test(out), `the twins engaged${diag}`);
      assert.ok(/net-guard LIVE/.test(out), `the guard engaged${diag}`);
      if (posture === "guard-only") assert.ok(/bind mount SKIPPED \(--no-secret-bind\)/.test(out), `the guard-only posture${diag}`);

      // THE LEAK ORACLE first: no canary in the agent's output or any archive.
      for (const c of CANARIES) assert.ok(!out.includes(c), `${c} reached the agent's world${diag}`);
      const dir = join(workspace, "out");
      for (const f of ["rel.tar", "abs.tar", "dir.tar", "home.tar", "bare.tar"]) {
        const bytes = readFileSync(join(dir, f));
        for (const c of CANARIES) assert.ok(!bytes.includes(c), `CONFIDENTIALITY VIOLATION: ${f} holds ${c}${diag}`);
      }

      // tar runs to the end on every form, with no EINVAL and no size mismatch.
      for (const t of ["REL", "ABS", "DIR", "HOME", "BARE"]) {
        // Only tar's notes on the names it stores (absolute paths) besides.
        const said = tagged(t).filter((l) => !/^ERR tar: Removing leading `\/' from /.test(l));
        assert.deepEqual(said, ["EXIT 0"], `tar ${t}: ${tagged(t).join(" | ")}${diag}`);
      }
      assert.ok(!/Invalid argument|file changed as we read it/.test(out), `tar complained${diag}`);

      // Each member is what the agent's cat sees (the twin); plain stays plain.
      const seen = new Map(tagged("SEEN").map((l) => { const i = l.lastIndexOf(" "); return [l.slice(0, i), l.slice(i + 1)] as const; }));
      const want = (f: string): string => {
        const h = seen.get(f);
        assert.ok(h && /^[0-9a-f]{64}$/.test(h), `cat ${f}: ${h}${diag}`);
        return h!;
      };
      assert.equal(sha256(member(join(dir, "rel.tar"), "conf/.env")), want("conf/.env"), "rel: conf/.env is the twin");
      assert.equal(member(join(dir, "rel.tar"), "conf/plain.txt").toString(), "hello\n", "rel: the plain file as written");
      assert.equal(sha256(member(join(dir, "abs.tar"), join(workspace, ".env").slice(1))), want(".env"), "abs: .env is the twin");
      assert.equal(sha256(member(join(dir, "dir.tar"), "conf/.env")), want("conf/.env"), "dir: conf/.env is the twin");
      assert.equal(sha256(member(join(dir, "home.tar"), aws.slice(1))), want(aws), "home: the credentials are the twin");
      assert.equal(sha256(member(join(dir, "bare.tar"), ".env")), want(".env"), "bare: .env is the twin");
      console.error(`tar-twin (${posture}): 5 archives, every member the twin, no canary`);
    }, { mode: "secrets" });
  });
}
