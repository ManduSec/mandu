/**
 * exec-shims.test — the shim dir + per-command shim script content.
 */
import { test } from "node:test";
import { Layout } from "../../src/services/layout.js";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, readFileSync, statSync, existsSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { EXEC_WRAP_PROBE_OK, execShimProbeInputs, mountOf, probeExecShim, probeExecShimCached, writeExecShims } from "../../src/services/exec-shims.js";
import { PROBE_CACHE_ENV, disableProbeCache, enableProbeCache, parseCacheFile, probeContext, probeKey, type ProbeCacheIo } from "../../src/probe-cache.js";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

test("writes one executable shim per command, wiring the arbiter + wrap.ts", () => {
  const scope = mkdtempSync(join(tmpdir(), "shim-"));
  const shimDir = writeExecShims(["curl", "git"], Layout.dev("/repo"), "/run/b.sock", scope);
  assert.equal(shimDir, join(scope, "exec-shims"));
  for (const cmd of ["curl", "git"]) {
    const p = join(shimDir, cmd);
    assert.ok(existsSync(p), `${cmd} shim exists`);
    assert.ok((statSync(p).mode & 0o111) !== 0, `${cmd} shim is executable`);
    const body = readFileSync(p, "utf8");
    assert.match(body, /MANDU_EXECWRAP_CMD="curl"|MANDU_EXECWRAP_CMD="git"/);
    assert.match(body, /MANDU_ARBITER_SOCK/);
    assert.match(body, /exec -a "\$MANDU_EXECWRAP_CMD"/);
    assert.match(body, /interceptors\/exec-wrap.*wrap\.ts/);
  }
  rmSync(scope, { recursive: true, force: true });
});

test("skips empty entries and throws when the list is empty", () => {
  const scope = mkdtempSync(join(tmpdir(), "shim-"));
  const dir = writeExecShims(["curl", "", "  "], Layout.dev("/repo"), "/s", scope);
  assert.ok(existsSync(join(dir, "curl")));
  assert.throws(() => writeExecShims(["", "  "], Layout.dev("/repo"), "/s", scope), /no commands/i);
  rmSync(scope, { recursive: true, force: true });
});

// -- the load probe (portable-wrapper.md section 5): LIVE only for a shim that loads --

test("probe: the repo's real exec-wrap loads in probe mode, runs nothing and connects to nothing", async () => {
  const scope = mkdtempSync(join(tmpdir(), "shim-probe-"));
  try {
    // A socket path nothing listens on: the probe must not need the arbiter.
    const dir = writeExecShims(["curl"], Layout.dev(REPO), join(scope, "no-arbiter.sock"), scope);
    await probeExecShim(dir, "curl");
  } finally {
    rmSync(scope, { recursive: true, force: true });
  }
});

test("probe: a checkout whose exec-wrap dependencies are missing is reported as a failed start", async () => {
  const scope = mkdtempSync(join(tmpdir(), "shim-probe-"));
  try {
    // The shim's runtime is the package-local tsx, absent in a checkout that
    // never ran npm install in interceptors/exec-wrap.
    const fakeRepo = join(scope, "repo");
    mkdirSync(join(fakeRepo, "interceptors", "exec-wrap", "src"), { recursive: true });
    const dir = writeExecShims(["curl"], Layout.dev(fakeRepo), "/s", scope);
    await assert.rejects(probeExecShim(dir, "curl"), (e: Error) => {
      assert.match(e.message, /the exec-wrap shim cannot load \(Error \[ERR_MODULE_NOT_FOUND\]: Cannot find/);
      assert.match(e.message, /would block every 'curl' call/);
      return true;
    });
  } finally {
    rmSync(scope, { recursive: true, force: true });
  }
});

test("probe: exit 0 without the ok line, a non-zero exit, a missing shim and a hang all fail", async () => {
  const scope = mkdtempSync(join(tmpdir(), "shim-probe-"));
  try {
    const shim = (name: string, body: string): void => {
      writeFileSync(join(scope, name), `#!/usr/bin/env bash\n${body}\n`);
      chmodSync(join(scope, name), 0o755);
    };
    shim("silent", "exit 0");
    shim("crash", "echo 'Error [ERR_MODULE_NOT_FOUND]: Cannot find package tsx' >&2; exit 1");
    shim("hang", "exec sleep 30");
    shim("ok", `echo '${EXEC_WRAP_PROBE_OK}'`);
    await assert.rejects(probeExecShim(scope, "silent"), /printed no ok line/);
    await assert.rejects(probeExecShim(scope, "crash"), /ERR_MODULE_NOT_FOUND/);
    await assert.rejects(probeExecShim(scope, "hang", 300), /timed out/);
    await assert.rejects(probeExecShim(scope, "absent"), /cannot load/);
    await probeExecShim(scope, "ok");
  } finally {
    rmSync(scope, { recursive: true, force: true });
  }
});

// -- the probe kept for the boot (portable-wrapper.md section 5; packaging.md section 5.4) --

const PKG = "/opt/mandu";
const BUNDLE = `${PKG}/dist/exec-shim.mjs`;
const CLIENT = `${PKG}/dist/arbiter-client.mjs`;
const MOUNTINFO =
  "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n" +
  "40 22 0:30 / /run/user/1000 rw,nosuid,nodev,relatime shared:9 - tmpfs tmpfs rw,size=100k,mode=700\n";

/** A host made of maps (the probe-cache io): identities, PATH, files. */
function shimHost(over: { ids?: Record<string, string | null>; onPath?: Record<string, string>; mountinfo?: string } = {}): ProbeCacheIo {
  const ids: Record<string, string | null> = {
    "/usr/bin/env": "env|1", "/usr/bin/bash": "bash|1", "/usr/bin/node": "node|1",
    [BUNDLE]: "bundle|1", [CLIENT]: "client|1", "/etc/ld.so.cache": "ldcache|1", ...over.ids,
  };
  const onPath: Record<string, string> = { bash: "/usr/bin/bash", node: "/usr/bin/node", ...over.onPath };
  const files: Record<string, string> = { "/proc/sys/kernel/random/boot_id": "boot-1", "/proc/self/mountinfo": over.mountinfo ?? MOUNTINFO };
  return {
    readText: (p) => files[p] ?? null,
    readLink: () => null,
    identity: (p) => ids[p] ?? null,
    which: (n) => onPath[n] ?? null,
  };
}

const SESSION = { shimDir: "/run/user/1000/mandu/s1/exec-shims", sock: "/run/user/1000/mandu/arbiter.sock" };
const BASE_ENV = { PATH: "/usr/bin:/bin" };

function shimKey(o: { layout?: Layout; cmd?: string; shimDir?: string; sock?: string; io?: ProbeCacheIo; env?: NodeJS.ProcessEnv } = {}): string {
  const io = o.io ?? shimHost();
  const env = o.env ?? BASE_ENV;
  const inputs = execShimProbeInputs(o.cmd ?? "curl", o.shimDir ?? SESSION.shimDir, { layout: o.layout ?? Layout.installed(PKG), arbiterSock: o.sock ?? SESSION.sock }, { io, env, platform: "linux" });
  assert.ok(inputs, "cacheable");
  return probeKey("exec-shim", inputs(), probeContext(env, io), env, io);
}

test("probe key: the same for every session of one install, and moves with everything the probe loads", () => {
  const base = shimKey();
  assert.match(base, /^[0-9a-f]{64}$/);
  assert.equal(shimKey({ shimDir: "/run/user/1000/mandu/s2/exec-shims", sock: "/run/user/1000/mandu/other.sock" }), base,
    "a new session's shim dir and arbiter socket (not read in probe mode) are the same question");
  const moved: Array<[string, string]> = [
    ["the exec-shim bundle rebuilt", shimKey({ io: shimHost({ ids: { [BUNDLE]: "bundle|2" } }) })],
    ["the exec-shim bundle gone", shimKey({ io: shimHost({ ids: { [BUNDLE]: null } }) })],
    ["the arbiter client module rebuilt", shimKey({ io: shimHost({ ids: { [CLIENT]: "client|2" } }) })],
    ["node replaced", shimKey({ io: shimHost({ ids: { "/usr/bin/node": "node|2" } }) })],
    ["another node first on PATH", shimKey({ io: shimHost({ onPath: { node: "/home/u/.local/bin/node" }, ids: { "/home/u/.local/bin/node": "node|9" } }) })],
    ["no node on PATH", shimKey({ io: shimHost({ onPath: { node: "" } }) })],
    ["bash replaced", shimKey({ io: shimHost({ ids: { "/usr/bin/bash": "bash|2" } }) })],
    ["/usr/bin/env replaced", shimKey({ io: shimHost({ ids: { "/usr/bin/env": "env|2" } }) })],
    ["a shared library changed (ld.so.cache)", shimKey({ io: shimHost({ ids: { "/etc/ld.so.cache": "ldcache|2" } }) })],
    ["the shim dir's mount went noexec", shimKey({ io: shimHost({ mountinfo: MOUNTINFO.replace("rw,nosuid,nodev", "rw,nosuid,nodev,noexec") }) })],
    ["another package root (the script's tokens)", shimKey({ layout: Layout.installed("/opt/mandu2"), io: shimHost({ ids: { "/opt/mandu2/dist/exec-shim.mjs": "bundle|1", "/opt/mandu2/dist/arbiter-client.mjs": "client|1" } }) })],
    ["another command", shimKey({ cmd: "wget" })],
    ["NODE_OPTIONS", shimKey({ env: { ...BASE_ENV, NODE_OPTIONS: "--require /tmp/x.cjs" } })],
    ["LD_PRELOAD", shimKey({ env: { ...BASE_ENV, LD_PRELOAD: "/tmp/x.so" } })],
    ["BASH_ENV", shimKey({ env: { ...BASE_ENV, BASH_ENV: "/tmp/rc" } })],
    ["PATH", shimKey({ env: { PATH: "/opt/bin:/usr/bin:/bin" } })],
    ["a new boot", shimKey({ io: { ...shimHost(), readText: (p) => (p === "/proc/sys/kernel/random/boot_id" ? "boot-2" : shimHost().readText(p)) } })],
  ];
  for (const [what, k] of moved) assert.notEqual(k, base, `${what} must change the key`);
  assert.equal(new Set(moved.map(([, k]) => k)).size, moved.length, "each change is its own key");
  assert.equal(shimKey({ env: { ...BASE_ENV, TERM: "xterm", MANDU_SESSION: "x" } }), base, "an unrelated variable is not an input");
});

test("probe key: the source form, a host other than Linux and a path bash would expand are never kept (always probed)", () => {
  const ctx = { layout: Layout.installed(PKG), arbiterSock: SESSION.sock };
  const opts = { io: shimHost(), env: BASE_ENV, platform: "linux" };
  assert.ok(execShimProbeInputs("curl", SESSION.shimDir, ctx, opts));
  assert.equal(execShimProbeInputs("curl", SESSION.shimDir, { ...ctx, layout: Layout.dev("/repo") }, opts), null, "tsx loads the checkout's sources: no fixed key");
  assert.ok(execShimProbeInputs("curl", SESSION.shimDir, { ...ctx, layout: Layout.dev("/repo", "/repo/launcher", { bundled: true }) }, opts), "a checkout's fresh build is bundled");
  assert.equal(execShimProbeInputs("curl", SESSION.shimDir, ctx, { ...opts, platform: "darwin" }), null);
  for (const bad of ['/run/a"b', "/run/$HOME", "/run/a`id`", "/run/a\\b", "/run/a\nb"]) {
    assert.equal(execShimProbeInputs("curl", bad, ctx, opts), null, `shim dir ${JSON.stringify(bad)}`);
    assert.equal(execShimProbeInputs("curl", SESSION.shimDir, { ...ctx, arbiterSock: bad }, opts), null, `socket ${JSON.stringify(bad)}`);
  }
  assert.equal(execShimProbeInputs("curl", SESSION.shimDir, { ...ctx, layout: Layout.installed("/opt/$x") }, opts), null);
  assert.equal(execShimProbeInputs("", SESSION.shimDir, ctx, opts), null);
});

test("mountOf: the longest mount point holding the path, the top one of a stack, octal escapes decoded", () => {
  const mi =
    "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n" +
    "40 22 0:30 / /run/user/1000 rw,nosuid shared:9 - tmpfs tmpfs rw\n" +
    "41 40 0:31 / /run/user/1000 rw,noexec shared:10 - tmpfs tmpfs rw,size=1k\n" +
    "50 22 0:40 / /mnt/a\\040b rw master:3 - ext4 /dev/sdb1 rw\n" +
    "garbage line\n";
  assert.equal(mountOf("/run/user/1000/mandu/s/exec-shims", mi), "/run/user/1000 rw,noexec tmpfs rw,size=1k");
  assert.equal(mountOf("/run/user/10000/x", mi), "/ rw,relatime ext4 rw", "a prefix of the name is not a parent");
  assert.equal(mountOf("/mnt/a b/c", mi), "/mnt/a b rw ext4 rw");
  assert.equal(mountOf("/x", ""), null);
});

test("cached probe: a pass kept this boot skips the node start; a changed key, the bypass and a failure probe again; a failure is never kept", async () => {
  const d = mkdtempSync(join(tmpdir(), "shim-cache-"));
  try {
    const file = join(d, "probe-cache", "kernel-probes.json");
    mkdirSync(dirname(file), { mode: 0o700 });
    let host = shimHost();
    let probed = 0;
    let fail: Error | null = null;
    const probe = async (): Promise<void> => { probed++; if (fail) throw fail; };
    const ctx = { layout: Layout.installed(PKG), arbiterSock: SESSION.sock };
    const launchOnce = async (o: { shimDir?: string; env?: Record<string, string> } = {}): Promise<Error | null> => {
      const env = { ...BASE_ENV, ...o.env };
      enableProbeCache(env, { file, io: host, procEnv: env });
      try {
        await probeExecShimCached(o.shimDir ?? SESSION.shimDir, "curl", ctx, { probe, io: host, env, platform: "linux" });
        return null;
      } catch (e) {
        return e as Error;
      } finally {
        disableProbeCache();
      }
    };
    assert.equal(await launchOnce(), null);
    assert.equal(probed, 1, "the first launch of the boot probes");
    assert.equal(await launchOnce({ shimDir: "/run/user/1000/mandu/s2/exec-shims" }), null);
    assert.equal(probed, 1, "the next session's launch is answered by the kept pass");
    host = shimHost({ ids: { [BUNDLE]: "bundle|2" } });
    assert.equal(await launchOnce(), null);
    assert.equal(probed, 2, "a rebuilt bundle probes again");
    assert.equal(await launchOnce({ env: { [PROBE_CACHE_ENV]: "0" } }), null);
    assert.equal(probed, 3, "MANDU_PROBE_CACHE=0 probes afresh");
    // The shim cannot load: the probe's own error, every launch, nothing kept
    // (and the kept pass for these inputs dropped).
    host = shimHost({ ids: { [CLIENT]: null } });
    fail = new Error("the exec-wrap shim cannot load (Error [ERR_MODULE_NOT_FOUND]: Cannot find module); a shim that cannot load would block every 'curl' call");
    assert.equal(await launchOnce(), fail);
    assert.equal(await launchOnce(), fail);
    assert.equal(probed, 5, "a failure is asked again on every launch");
    assert.equal(parseCacheFile(readFileSync(file, "utf8"))!.entries["exec-shim"], undefined, "no pass is kept for a shim that cannot load");
    // Outside a launch (no enabled cache) it is a plain probe.
    fail = null;
    await probeExecShimCached(SESSION.shimDir, "curl", ctx, { probe, io: host, env: BASE_ENV, platform: "linux" });
    await probeExecShimCached(SESSION.shimDir, "curl", ctx, { probe, io: host, env: BASE_ENV, platform: "linux" });
    assert.equal(probed, 7);
    // The source form: probed on every launch, nothing kept.
    const before = probed;
    for (let i = 0; i < 2; i++) {
      enableProbeCache(BASE_ENV, { file, io: host, procEnv: BASE_ENV });
      try { await probeExecShimCached(SESSION.shimDir, "curl", { ...ctx, layout: Layout.dev("/repo") }, { probe, io: host, env: BASE_ENV, platform: "linux" }); }
      finally { disableProbeCache(); }
    }
    assert.equal(probed, before + 2);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});
