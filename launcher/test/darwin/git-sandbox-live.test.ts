/**
 * git-sandbox-live.test — the macOS git sandbox (hardened-git.ts, the
 * Seatbelt kind; docs/design/architecture/write-protection.md §5.2), run for REAL under
 * /usr/bin/sandbox-exec.
 *
 *   T1  a hostile repository's programs (fsmonitor, hooks, the signature
 *       verifier, filter, textconv and diff drivers, the pager, the ssh
 *       transport, auto gc) never START under the sandbox, even with STOCK
 *       git arguments (none of the hardening) and a writable markers
 *       directory: no fork, no exec but git. A stock lazy fetch in a partial
 *       clone (the lazy fetch on) starts no transport. A stock git without
 *       the sandbox springs them (the control).
 *   T2  what a program could do if one did start: the production profile
 *       with fork and the program's exec allowed back on purpose. It writes
 *       only where the call binds; it reaches no TCP or Unix socket, no
 *       process outside, no terminal, and cannot exec `open`.
 *   T3  Mandu's own git still works sandboxed: the launcher's object twins
 *       rebuild a pack into a cache spelled through a link (/tmp) and by its
 *       real path, trackedSecretRepos, and the arbiter's history runner,
 *       blob reader and R3 build (prepGit, a full PreparedCopies cycle).
 *   T4  every command form the four packages issue (the parity test's)
 *       exits sandboxed as it does unsandboxed: a git build that forks where
 *       Mandu's forms need it would show here.
 *   T5  sandbox-exec does not nest: inside another profile the probe says
 *       none (exit 71 underneath), and the hardened git runs as is.
 *   T6  a `git` planted first on PATH never runs outside a sandbox in the
 *       probe: its `--exec-path` runs under the git profile (a script cannot
 *       even start its interpreter), so the probe finds no sandbox and the
 *       planted file wrote nothing and reached no socket.
 *
 * darwin only; SKIPs elsewhere and where the probe finds no sandbox (no
 * /usr/bin/sandbox-exec, or this run is itself inside a Seatbelt profile).
 * The arbiter's modules are loaded at run time by path (the launcher does
 * not import the arbiter package), so its node_modules must be installed.
 *
 * docs-lane-exempt: the git calls (ls-files among them) run in temporary
 * repositories under /tmp, never over the docs.
 */
delete process.env["MANDU_GIT_SANDBOX"];

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFile, execFileSync, spawnSync } from "node:child_process";
import { chmodSync, closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, realpathSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  gitCommand, gitSandbox, gitSeatbeltProfile, hardenedGitArgs, hardenedGitEnv, isSeatbeltGitSandbox, probeGitSandbox, resolveGitBinary,
  type SeatbeltGitSandbox,
} from "../../src/hardened-git.js";
import { defaultGitRunner, prepareGitObjectTwins } from "../../src/git-object-twins.js";
import { trackedSecretRepos } from "../../src/secret-setup.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the sandbox wraps the git the confidentiality axis's launch prep and scans run

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG = resolve(HERE, "..", "..");
const REPO = resolve(PKG, "..");
const probed = process.platform === "darwin" ? probeGitSandbox({ env: { PATH: process.env["PATH"] } }) : null;
const SB: SeatbeltGitSandbox | null = probed !== null && isSeatbeltGitSandbox(probed) ? probed : null;
const SKIP = process.platform !== "darwin" ? "darwin only" : SB === null ? "sandbox-exec cannot make the git sandbox here (none, or inside another profile)" : false;

const NODE = realpathSync(process.execPath);
const TOKEN = "gh" + "p_" + "Z8y1Km6Ut3Qa7Jc0Vm5Xr2Gb4Ht9Od1Eb6Fy";
const PEM = "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n-----END OPENSSH PRIVATE KEY-----\n";

/** A short scratch root under /tmp, by its real path (/private/tmp/…): a
 *  Unix socket path must fit 104 bytes. */
let S = "";
const servers: Server[] = [];

before(() => {
  if (SKIP) return;
  S = realpathSync(mkdtempSync("/tmp/mdu-gsb."));
});
after(() => {
  for (const s of servers) s.close();
  if (S !== "") rmSync(S, { recursive: true, force: true });
});

const EPERM = /Operation not permitted|EPERM|cannot fork|cannot exec|cannot run|Resource temporarily/;

/** A clean git for building fixtures: no user or system config. */
function stockEnv(home: string): Record<string, string> {
  return {
    PATH: process.env["PATH"] ?? "/usr/bin:/bin", HOME: home, LC_ALL: "C",
    GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
    GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  };
}

interface Hostile {
  dir: string;
  root: string;
  markers: string;
  blob: string;
  /** The promisor fixture's object deleted from the store (its lazy fetch
   *  would run the promisor remote's transport); "" elsewhere. */
  missing: string;
  env: Record<string, string>;
  fired(): string[];
  clear(): void;
}

/** A booby-trapped repository (the pattern of tests/integration/test/lib/
 *  hostile-git-repo.ts, self-contained here): a real history with a signed
 *  commit and a deleted key, then every config key and attribute that
 *  starts a program naming a marker program that appends to `markers/`. */
function hostile(name: string, opts: { promisor?: boolean; settled?: boolean } = {}): Hostile {
  const dir = join(S, name);
  const root = join(dir, "repo");
  const markers = join(dir, "markers");
  const bin = join(dir, "bin");
  for (const d of [root, markers, bin]) mkdirSync(d, { recursive: true });
  const env = stockEnv(dir);
  const git = (...a: string[]): string => execFileSync("git", a, { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const prog = (n: string): string => {
    const p = join(bin, n);
    writeFileSync(p, `#!/bin/sh\necho "$0 $*" >> '${join(markers, n)}'\nexit 0\n`);
    chmodSync(p, 0o755);
    return p;
  };
  const past = new Date(Date.now() - 3_600_000);
  const settle = (): void => {
    for (const f of ["config.env", "crlf.txt", "README.md", "old.txt", "deploy/id_rsa"]) {
      try { utimesSync(join(root, f), past, past); } catch { /* not there */ }
    }
  };
  git("init", "-q", "-b", "main");
  mkdirSync(join(root, "deploy"));
  writeFileSync(join(root, "deploy", "id_rsa"), PEM);
  writeFileSync(join(root, "config.env"), `GITHUB_TOKEN=${TOKEN}\n`);
  writeFileSync(join(root, "crlf.txt"), "one\r\ntwo\r\n");
  writeFileSync(join(root, "README.md"), "# hostile\n");
  settle();
  git("add", "-A");
  git("commit", "-qm", "init");
  const signer = join(bin, "signer");
  writeFileSync(signer, "#!/bin/sh\ncat >/dev/null\necho '[GNUPG:] SIG_CREATED ' >&2\nprintf -- '-----BEGIN PGP SIGNATURE-----\\n\\nx\\n-----END PGP SIGNATURE-----\\n'\n");
  chmodSync(signer, 0o755);
  git("-c", `gpg.program=${signer}`, "commit", "-q", "--allow-empty", "-S", "-m", "signed");
  const blob = git("rev-parse", "HEAD:deploy/id_rsa").trim();
  git("rm", "-q", "deploy/id_rsa");
  settle();
  git("commit", "-qam", "rotate");
  let missing = "";
  if (opts.promisor) {
    writeFileSync(join(root, "old.txt"), "an old version only the history holds\n");
    settle();
    git("add", "old.txt");
    git("commit", "-qm", "old");
    missing = git("rev-parse", "HEAD:old.txt").trim();
    git("rm", "-q", "old.txt");
    git("commit", "-qm", "drop old");
    rmSync(join(root, ".git", "objects", missing.slice(0, 2), missing.slice(2)));
  }
  // The traps, last (the fixture's own git above must not spring them).
  const hooks = join(dir, "hooks");
  mkdirSync(hooks);
  for (const h of ["pre-commit", "commit-msg", "post-commit", "post-checkout", "post-index-change", "reference-transaction", "pre-auto-gc"]) {
    for (const d of [hooks, join(root, ".git", "hooks")]) {
      writeFileSync(join(d, h), `#!/bin/sh\necho "$0" >> '${join(markers, `hook-${h}`)}'\nexit 0\n`);
      chmodSync(join(d, h), 0o755);
    }
  }
  const cfg: Array<[string, string]> = [
    ["core.fsmonitor", prog("fsmonitor")],
    ["core." + "hooksPath", hooks],
    ["log.showSignature", "true"],
    ["gpg.program", prog("gpg")],
    ["commit.gpgSign", "true"],
    ["filter.evil.clean", prog("filter-clean")],
    ["filter.evil.smudge", prog("filter-smudge")],
    ["filter.evil.required", "true"],
    ["filter.proc.process", prog("filter-process")],
    ["diff.evil.textconv", prog("textconv")],
    ["diff.external", prog("extdiff")],
    ["core.pager", prog("pager")],
    ["core.editor", prog("editor")],
    ["core.sshCommand", prog("ssh")],
    ["credential.helper", `!${prog("credential")}`],
    ["gc.auto", "1"],
    ["gc.autoPackLimit", "1"],
    ["maintenance.auto", "true"],
    ["remote.origin.url", "ssh://mandu-test.invalid/hostile.git"],
  ];
  if (opts.promisor) cfg.push(["core.repositoryformatversion", "1"], ["extensions.partialClone", "origin"], ["remote.origin.promisor", "true"]);
  for (const [k, v] of cfg) git("config", k, v);
  writeFileSync(join(root, ".gitattributes"), "* filter=evil diff=evil\n");
  writeFileSync(join(root, ".git", "info", "attributes"), "config.env filter=proc\n");
  if (!opts.settled) {
    const later = new Date(Date.now() + 120_000);
    for (const f of ["config.env", "crlf.txt", "README.md"]) utimesSync(join(root, f), later, later);
  }
  const fired = (): string[] => readdirSync(markers).sort();
  const clear = (): void => { for (const f of readdirSync(markers)) rmSync(join(markers, f), { force: true }); };
  return { dir, root, markers, blob, missing, env, fired, clear };
}

/** Run `git <args>` (the arguments as given: STOCK unless the caller
 *  hardened them) in `sandbox`, `writable` its only writable paths. */
function run(args: readonly string[], cwd: string, env: Record<string, string>, sandbox: SeatbeltGitSandbox | null, writable: readonly string[] = [], input = ""): { code: number; err: string } {
  const cmd = gitCommand(args, sandbox, writable);
  const r = spawnSync(cmd.file, cmd.args, { cwd, env, input, encoding: "utf8", timeout: 30_000, stdio: ["pipe", "ignore", "pipe"] });
  return { code: r.status ?? -1, err: r.stderr ?? "" };
}

// ── T1 ──────────────────────────────────────────────────────────────────────

test("T1: a hostile repository's programs never start under the sandbox, stock git arguments and all (a stock lazy fetch included); a stock git without it springs them", { skip: SKIP }, () => {
  const h = hostile("t1");
  // A commit in a repository whose work tree matches its index (no filter
  // run first): what a commit itself starts, hooks and the signer.
  const settled = hostile("t1-settled", { settled: true });
  const cases: Array<{ what: string; args: string[]; repo?: Hostile; writeRepo?: boolean }> = [
    { what: "status (fsmonitor; the clean filter on stat-dirty files)", args: ["status", "--porcelain"] },
    { what: "log (the signature verifier)", args: ["log", "-3", "--format=%H %G?"] },
    { what: "log -p (textconv, the external diff, the pager)", args: ["log", "-p", "-2"] },
    { what: "diff (a work-tree compare through the filter)", args: ["diff"] },
    { what: "hash-object (a REQUIRED clean filter)", args: ["hash-object", "--", "README.md"] },
    { what: "fetch (the ssh transport, the credential helper)", args: ["fetch", "origin"] },
    { what: "commit (hooks, the signer, auto gc and maintenance), the repository writable", args: ["commit", "-q", "--allow-empty", "-m", "x"], repo: settled, writeRepo: true },
    { what: "checkout (the smudge filter, post-checkout), the repository writable", args: ["checkout", "-q", "--", "README.md"], writeRepo: true },
  ];
  for (const c of cases) {
    const r0 = c.repo ?? h;
    r0.clear();
    const r = run(c.args, r0.root, r0.env, SB, c.writeRepo ? [r0.markers, r0.root] : [r0.markers]);
    assert.deepEqual(r0.fired(), [], `${c.what}: nothing a repository named started (${r.err.trim().split("\n").slice(-1)[0]})`);
    if (c.args[0] === "hash-object") {
      assert.notEqual(r.code, 0, "the required filter could not run, so the call fails (fail closed)");
      assert.match(r.err, EPERM, r.err);
    }
  }
  // A STOCK lazy fetch: a missing object read in a partial clone, with the
  // lazy fetch ON (no GIT_NO_LAZY_FETCH, no protocol.allow=never) — the case
  // where only the sandbox stands between the promisor remote's transport
  // (core.sshCommand) and a start.
  const p = hostile("t1-promisor", { promisor: true, settled: true });
  assert.equal(p.env["GIT_NO_LAZY_FETCH"], undefined, "stock: the lazy fetch is on");
  p.clear();
  const lazy = run(["cat-file", "--batch"], p.root, p.env, SB, [p.markers], `${p.missing}\n`);
  assert.deepEqual(p.fired(), [], `a stock lazy fetch under the sandbox starts no transport (${lazy.err.trim().split("\n").slice(-1)[0]})`);
  p.clear();
  run(["cat-file", "--batch"], p.root, p.env, null, [], `${p.missing}\n`);
  assert.ok(p.fired().includes("ssh"), `the control: the same stock lazy fetch outside the sandbox runs the transport: ${p.fired().join(", ")}`);
  // The control: the same repositories spring their traps under a stock git
  // (outside the sandbox), so the quiet above is the sandbox's doing.
  h.clear();
  run(["status", "--porcelain"], h.root, h.env, null);
  const statusFired = h.fired();
  assert.ok(statusFired.includes("fsmonitor") && statusFired.some((m) => m.startsWith("filter-")), `a stock status springs fsmonitor and the filter: ${statusFired.join(", ")}`);
  settled.clear();
  run(["commit", "-q", "--allow-empty", "-m", "y"], settled.root, settled.env, null);
  const commitFired = settled.fired();
  assert.ok(commitFired.includes("hook-pre-commit") && commitFired.includes("gpg"), `a stock commit runs its hooks and its signer: ${commitFired.join(", ")}`);
});

// ── T2 ──────────────────────────────────────────────────────────────────────

test("T2: a program that did start (fork and its exec allowed back on purpose) writes only where the call binds, and reaches no socket, process, terminal or launcher", { skip: SKIP }, async () => {
  const dir = join(S, "t2");
  const repo = join(dir, "repo");
  const inside = join(dir, "in");
  const outside = join(dir, "outside");
  for (const d of [repo, inside]) mkdirSync(d, { recursive: true });
  const env = stockEnv(dir);
  execFileSync("git", ["init", "-q"], { cwd: repo, env });
  writeFileSync(join(repo, "f.txt"), "content\n");
  writeFileSync(join(repo, ".gitattributes"), "f.txt filter=x\n");

  let tcpConnections = 0;
  const tcp = createServer((c) => { tcpConnections++; c.destroy(); });
  servers.push(tcp);
  await new Promise<void>((res) => tcp.listen(0, "127.0.0.1", () => res()));
  const port = (tcp.address() as { port: number }).port;
  const sock = join(dir, "u.sock");
  let unixConnections = 0;
  const unix = createServer((c) => { unixConnections++; c.destroy(); });
  servers.push(unix);
  await new Promise<void>((res) => unix.listen(sock, () => res()));

  const report = join(inside, "report");
  const prog = join(dir, "filter.cjs");
  writeFileSync(prog, `#!${NODE}
const fs = require("fs"), net = require("net"), cp = require("child_process");
const r = (k, v) => fs.appendFileSync(${JSON.stringify(report)}, k + "=" + v + "\\n");
const tryWrite = (k, p) => { try { fs.writeFileSync(p, "x"); r(k, "written"); } catch (e) { r(k, e.code); } };
tryWrite("outside", ${JSON.stringify(outside)});
tryWrite("repo", ${JSON.stringify(join(repo, "planted"))});
tryWrite("inside", ${JSON.stringify(join(inside, "ok"))});
try { process.kill(${process.pid}, 0); r("signal", "delivered"); } catch (e) { r("signal", e.code); }
try { fs.closeSync(fs.openSync("/dev/tty", "r+")); r("tty", "opened"); } catch (e) { r("tty", e.code); }
const open = cp.spawnSync("/usr/bin/open", ["-h"], { stdio: "ignore" });
r("exec", open.error ? open.error.code : "ran " + open.status);
const connect = (k, target) => new Promise((done) => {
  const s = net.connect(target);
  s.setTimeout(3000, () => { s.destroy(); r(k, "timeout"); done(); });
  s.on("connect", () => { s.destroy(); r(k, "connected"); done(); });
  s.on("error", (e) => { r(k, e.code); done(); });
});
const chunks = [];
process.stdin.on("data", (c) => chunks.push(c));
process.stdin.on("end", async () => {
  await connect("tcp", { port: ${port}, host: "127.0.0.1" });
  await connect("unix", { path: ${JSON.stringify(sock)} });
  process.stdout.write(Buffer.concat(chunks));
});
`);
  chmodSync(prog, 0o755);

  // The PRODUCTION profile for a call binding `inside`, then fork and the
  // program's exec (the script and its interpreter) allowed back: the only
  // difference from what Mandu runs. Everything else still applies.
  const sb = SB!;
  const profile = gitSeatbeltProfile(sb.git, [inside]) +
    `(allow process-fork)\n(allow process-exec (literal ${JSON.stringify(prog)}) (literal ${JSON.stringify(NODE)}) (literal "/bin/sh"))\n`;
  const args = ["-p", profile, sb.git, "-c", `filter.x.clean=${prog}`, "-c", "filter.x.required=true", "hash-object", "--", "f.txt"];
  const out = await new Promise<{ code: number; stdout: string; stderr: string }>((res) => {
    execFile(sb.sandboxExec, args, { cwd: repo, env: hardenedGitEnv(env), timeout: 30_000 }, (e, stdout, stderr) =>
      res({ code: e ? (typeof (e as { code?: unknown }).code === "number" ? (e as { code: number }).code : 1) : 0, stdout: String(stdout), stderr: String(stderr) }));
  });
  assert.equal(out.code, 0, `git ran the program inside the sandbox: ${out.stderr}`);
  assert.match(out.stdout.trim(), /^[0-9a-f]{40}$/);
  const got = Object.fromEntries(readFileSync(report, "utf8").trim().split("\n").map((l) => l.split("=") as [string, string]));
  assert.deepEqual(got, {
    outside: "EPERM", repo: "EPERM", inside: "written",
    signal: "EPERM", tty: "EPERM", exec: "EPERM", tcp: "EPERM", unix: "EPERM",
  }, JSON.stringify(got));
  assert.equal(existsSync(outside), false);
  assert.equal(existsSync(join(repo, "planted")), false);
  assert.equal(tcpConnections, 0, "the loopback server saw no connection");
  assert.equal(unixConnections, 0, "the Unix socket saw no connection");
});

// ── T3 ──────────────────────────────────────────────────────────────────────

/** A workspace repository with a protected file committed twice (two
 *  versions to hide) and repacked. */
function workspace(name: string): { ws: string; secret: string; blob: string } {
  const ws = join(S, name);
  mkdirSync(ws, { recursive: true });
  const env = stockEnv(S);
  const git = (...a: string[]): string => execFileSync("git", a, { cwd: ws, env, encoding: "utf8" });
  git("init", "-q", "-b", "main");
  mkdirSync(join(ws, "deploy"));
  writeFileSync(join(ws, "secret.env"), "TOKEN=one\n");
  writeFileSync(join(ws, "README"), "readme\n");
  writeFileSync(join(ws, "deploy", "id_rsa"), "KEY\n");
  git("add", "."); git("commit", "-qm", "one");
  const blob = git("rev-parse", "HEAD:deploy/id_rsa").trim();
  writeFileSync(join(ws, "secret.env"), "TOKEN=two\n");
  git("rm", "-q", "deploy/id_rsa");
  git("commit", "-qam", "two");
  git("repack", "-adq");
  return { ws, secret: join(ws, "secret.env"), blob };
}

test("T3: Mandu's own git works sandboxed: the launcher's object twins (a cache spelled through /tmp and by its real path), trackedSecretRepos", { skip: SKIP }, async () => {
  const sandbox = gitSandbox();
  assert.ok(sandbox !== null && isSeatbeltGitSandbox(sandbox), "the production runner runs git under Seatbelt here");
  const { ws, secret } = workspace("t3-ws");
  // /tmp is a link on macOS; a Seatbelt rule matches the resolved path only,
  // so a bind spelled /tmp/… works only because gitCommand adds its
  // canonical spelling.
  const linked = S.replace(/^\/private\/tmp\//, "/tmp/");
  assert.notEqual(linked, S, "the scratch root has a /tmp spelling");
  for (const [label, base] of [["through /tmp", linked], ["by its real path", S]] as const) {
    const cacheDir = join(base, `t3-cache-${label === "by its real path" ? "real" : "link"}`);
    mkdirSync(cacheDir);
    const denyFile = join(S, `t3-deny-${label.length}`);
    closeSync(openSync(denyFile, "w", 0o000));
    const got = await prepareGitObjectTwins([secret], { cacheDir, denyFile });
    assert.equal(got.repos, 1, label);
    assert.equal(got.packsRebuilt, 1, `${label}: pack-objects and index-pack wrote the sanitized pack into the cache from inside the sandbox`);
    assert.ok(readdirSync(realpathSync(cacheDir), { recursive: true }).some((f) => String(f).endsWith(".idx")), `${label}: the rebuilt index is there`);
  }
  // The macOS launch's committed-file check (read-only calls).
  assert.deepEqual(await trackedSecretRepos([realpathSync(secret)]), [{ root: realpathSync(ws), checked: true }]);
  // The same runner over a hostile repository: nothing it names starts.
  const h = hostile("t3-hostile");
  const r = await defaultGitRunner(["ls-files", "-s", "-z"], { cwd: h.root });
  assert.equal(r.code, 0, r.stderr);
  assert.deepEqual(h.fired(), []);
});

interface HistoryModule {
  defaultHistoryGitRunner: (args: string[], opts: { cwd: string; timeoutMs: number }) => Promise<{ code: number; stdout: string; stderr: string }>;
  defaultBlobReader: (root: string, oids: readonly string[], opts: { timeoutMs: number }) => Promise<Buffer>;
}
interface PreparedModule {
  PreparedCopies: new (o: Record<string, unknown>) => { runCycle(): Promise<void>; idle(): Promise<void>; summary(): { ready: Array<{ root: string }>; failed: unknown[] }; stop?(): Promise<void> };
  prepGitCommand: (args: readonly string[], o: { writable?: readonly string[]; lowPriority?: boolean }, sandbox: unknown) => { file: string; args: string[] };
}
interface SealsModule {
  CacheSealStore: new (o: { dbPath: string; confidentiality: boolean }) => { markShutdown(): void };
}
/** An arbiter module by path, at run time (the launcher never imports the
 *  arbiter package statically). */
const arbiterModule = async <T>(rel: string): Promise<T> => (await import(pathToFileURL(join(REPO, "arbiter", rel)).href)) as T;

test("T3: the arbiter's git works sandboxed: the history runner, the blob reader, and an R3 build (prepGit, nice 19) into a cache spelled through /tmp", { skip: SKIP }, async () => {
  const hist = await arbiterModule<HistoryModule>("policy/secret-history-scan.ts");
  const prep = await arbiterModule<PreparedModule>("policy/prepared-copies.ts");
  const seals = await arbiterModule<SealsModule>("policy/cache-seals.ts");
  const { ws, blob } = workspace("t3-arb");
  const root = realpathSync(ws);
  const log = await hist.defaultHistoryGitRunner(["rev-list", "--all"], { cwd: root, timeoutMs: 30_000 });
  assert.equal(log.code, 0, log.stderr);
  assert.equal(log.stdout.trim().split("\n").length, 2);
  const bytes = await hist.defaultBlobReader(root, [blob], { timeoutMs: 30_000 });
  assert.match(bytes.toString("utf8"), /KEY\n/);
  // The build's command line is the one the probe's sandbox gives.
  const cmd = prep.prepGitCommand(["index-pack"], { writable: ["/tmp/x"], lowPriority: true }, gitSandbox());
  assert.deepEqual(cmd.args.slice(0, 4), ["-n", "19", "/usr/bin/sandbox-exec", "-p"]);
  assert.equal(cmd.file, "/usr/bin/nice");
  assert.match(cmd.args[4]!, /\(subpath "\/private\/tmp\/x"\) \(subpath "\/tmp\/x"\)/);
  // A full preparation cycle: init --bare, pack-objects and index-pack
  // write only the build's own work directory, spelled through /tmp.
  const cacheDir = join(S.replace(/^\/private\/tmp\//, "/tmp/"), "t3-prep", "object-twins");
  const store = new seals.CacheSealStore({ dbPath: join(S, "t3-mandu.db"), confidentiality: true });
  try {
    const p = new prep.PreparedCopies({ cacheDir, seals: store, repos: () => [root], lockedSet: () => ({ sha1: [blob], sha256: [] }) });
    await p.runCycle();
    await p.idle();
    const s = p.summary();
    assert.deepEqual(s.failed, [], "no build failed inside the sandbox");
    assert.deepEqual(s.ready.map((x) => x.root), [root]);
    const keys = readdirSync(cacheDir).filter((n) => /^[0-9a-f]{32}$/.test(n));
    assert.equal(keys.length, 1);
    assert.deepEqual(readdirSync(cacheDir).filter((n) => n.startsWith(".tmp-")), [], "the work directory is gone");
  } finally {
    store.markShutdown();
  }
});

// ── T4 ──────────────────────────────────────────────────────────────────────

/** The command forms launcher, arbiter, dashboard and fs-sync issue
 *  (tests/integration/test/e2e/hardened-git-parity.test.ts FORMS). */
const FORMS: Array<{ what: string; args: string[]; input?: string; literal?: boolean; promisor?: boolean; settled?: boolean; fails?: boolean }> = [
  { what: "the history walk", args: ["log", "--all", "--reflog", "-m", "--root", "--format=", "--raw", "-z", "--no-abbrev", "--no-renames", "--", "config.env"], literal: true },
  { what: "the scan's trace walk", args: ["log", "--all", "--reflog", "-m", "--root", "--no-renames", "--raw", "--no-abbrev", "--format=commit %H"], literal: true },
  { what: "the dashboard's commit list", args: ["log", "--format=COMMIT:%H%n%s%n%an%n%aI%n%D", "--name-only"] },
  { what: "the dashboard's commit detail", args: ["log", "-1", "--format=%H%n%s%n%an%n%aI%n%D%n%b", "HEAD~1"] },
  { what: "the dashboard's diff", args: ["diff-tree", "-p", "--root", "--no-ext-diff", "--no-textconv", "HEAD"] },
  { what: "the index read", args: ["ls-files", "-s", "-z"], literal: true },
  { what: "gitRevOf's reads", args: ["ls-files", "--debug"] },
  { what: "gitRevOf's staged check", args: ["diff-index", "--cached", "--quiet", "HEAD", "--"] },
  { what: "gitRevOf's untracked list", args: ["ls-files", "-o", "--exclude-standard", "-z"] },
  { what: "the working-copy hash", args: ["hash-object", "--no-filters", "--", "config.env", "crlf.txt"], literal: true },
  { what: "the history state", args: ["rev-list", "--all", "--reflog", "--no-walk"] },
  { what: "the scan's object list", args: ["rev-list", "--all", "--reflog", "--objects"] },
  { what: "the repository facts", args: ["rev-parse", "--show-toplevel", "--show-object-format", "--git-path", "shallow", "--git-common-dir"] },
  { what: "replace refs", args: ["for-each-ref", "--format=%(objectname) %(refname)", "refs/replace/"] },
  { what: "the blob reader", args: ["cat-file", "--batch"], input: "HEAD:config.env\n" },
  { what: "the net guard's remotes", args: ["config", "--get-regexp", "^remote\\..*\\.url$"] },
  { what: "the dashboard's file browser", args: ["ls-tree", "-r", "-l", "-z", "HEAD"] },
  { what: "the self-status range", args: ["diff", "--no-ext-diff", "--no-textconv", "--name-only", "HEAD~1", "HEAD", "--", "."] },
  { what: "fs-sync's ignore check", args: ["check-ignore", "-z", "--stdin"], input: "node_modules/x\0" },
  { what: "fs-sync's commit (the repository writable)", args: ["commit", "-q", "--allow-empty", "-m", "sync"], settled: true },
  { what: "a lazy fetch", args: ["cat-file", "--batch"], input: "0000000000000000000000000000000000000001\n", promisor: true },
  // No sandboxed runner fetches (the parity test has it to prove no
  // transport starts): it fails both ways, sandboxed already at its write of
  // FETCH_HEAD (exit 255) before `protocol.allow=never` refuses it (128).
  { what: "a fetch", args: ["fetch", "origin"], fails: true },
];

test("T4: every command form Mandu issues exits under the sandbox as it does without it (nothing it needs forks or writes outside a bind); none starts a program", { skip: SKIP }, () => {
  const plain = hostile("t4-plain");
  const promisor = hostile("t4-promisor", { promisor: true });
  const settled = hostile("t4-settled", { settled: true });
  for (const f of FORMS) {
    const h = f.promisor ? promisor : f.settled ? settled : plain;
    const env = hardenedGitEnv(h.env, { GIT_OPTIONAL_LOCKS: "0", LC_ALL: "C" });
    const args = hardenedGitArgs(f.args, { literalPathspecs: f.literal === true });
    const writable = f.settled ? [h.root] : [];
    const boxed = run(args, h.root, env, SB, writable, f.input ?? "");
    const plainRun = run(args, h.root, env, null, [], f.input ?? "");
    if (f.fails) {
      assert.ok(boxed.code !== 0 && plainRun.code !== 0, `${f.what}: fails both ways (${boxed.code}, ${plainRun.code})`);
    } else {
      assert.equal(boxed.code, plainRun.code, `${f.what}: exit ${boxed.code} sandboxed, ${plainRun.code} without (${boxed.err.trim().split("\n").slice(-1)[0]})`);
    }
    assert.doesNotMatch(boxed.err, /cannot fork|cannot exec/, f.what);
    assert.deepEqual(h.fired(), [], `${f.what} started a program`);
  }
});

// ── T5 ──────────────────────────────────────────────────────────────────────

test("T5: inside another Seatbelt profile the probe finds no sandbox (sandbox-exec does not nest: exit 71) and the hardened git runs as is", { skip: SKIP }, () => {
  const outer = '(version 1)(allow default)(deny file-read* (literal "/nonexistent-mandu-outer"))';
  // The raw fact: a nested sandbox-exec cannot apply its profile.
  const nested = spawnSync("/usr/bin/sandbox-exec", ["-p", outer, "/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)", "/usr/bin/true"], { encoding: "utf8" });
  assert.equal(nested.status, 71, nested.stderr);
  assert.match(nested.stderr, /sandbox_apply: Operation not permitted/);
  // Mandu's own module, run inside the outer profile.
  const dir = join(S, "t5");
  mkdirSync(dir);
  const env = stockEnv(dir);
  execFileSync("git", ["init", "-q", "-b", "main"], { cwd: dir, env });
  execFileSync("git", ["commit", "-q", "--allow-empty", "-m", "one"], { cwd: dir, env });
  const script = join(dir, "probe.ts");
  writeFileSync(script, `
import { execFileSync } from "node:child_process";
import { gitCommand, gitSandbox, hardenedGitArgs, hardenedGitEnv, probeGitSandbox } from ${JSON.stringify(join(PKG, "src", "hardened-git.ts"))};
const probe = probeGitSandbox({ env: { PATH: process.env.PATH } });
const cmd = gitCommand(hardenedGitArgs(["rev-parse", "HEAD"]), gitSandbox());
const rev = execFileSync(cmd.file, cmd.args, { cwd: ${JSON.stringify(dir)}, env: hardenedGitEnv(), encoding: "utf8" }).trim();
process.stdout.write(JSON.stringify({ probe, file: cmd.file, rev }));
`);
  const tsx = join(PKG, "node_modules", "tsx", "dist", "cli.mjs");
  const r = spawnSync("/usr/bin/sandbox-exec", ["-p", outer, NODE, tsx, script], { cwd: dir, encoding: "utf8", timeout: 60_000, env: { ...process.env, MANDU_GIT_SANDBOX: "" } });
  assert.equal(r.status, 0, r.stderr);
  const got = JSON.parse(r.stdout) as { probe: unknown; file: string; rev: string };
  assert.equal(got.probe, null, "inside another profile: no git sandbox");
  assert.equal(got.file, "git", "the hardened git runs as is (the outer profile confines it)");
  assert.equal(got.rev, execFileSync("git", ["rev-parse", "HEAD"], { cwd: dir, env, encoding: "utf8" }).trim());
});

// ── T6 ──────────────────────────────────────────────────────────────────────

test("T6: a git planted first on PATH never runs outside a sandbox in the probe: its --exec-path runs under the git profile, where a script cannot even start its interpreter", { skip: SKIP }, async () => {
  const dir = join(S, "t6");
  const bin = join(dir, "bin");
  mkdirSync(bin, { recursive: true });
  let connections = 0;
  const srv = createServer((c) => { connections++; c.destroy(); });
  servers.push(srv);
  await new Promise<void>((res) => srv.listen(0, "127.0.0.1", () => res()));
  const port = (srv.address() as { port: number }).port;
  const marker = join(dir, "ran");
  const planted = join(bin, "git");
  // What an agent would put in ~/.local/bin: log, phone home, then pass
  // through to the real git so nothing looks amiss.
  writeFileSync(planted, `#!/bin/sh\necho "$*" >> '${marker}'\n/usr/bin/nc -z -G 2 127.0.0.1 ${port}\nexec /usr/bin/git "$@"\n`);
  chmodSync(planted, 0o755);
  const path = `${bin}:${process.env["PATH"] ?? "/usr/bin:/bin"}`;
  assert.equal(resolveGitBinary({ path }), planted, "PATH's first git, as found: its sandboxed --exec-path answered nothing");
  assert.equal(probeGitSandbox({ env: { PATH: path } }), null, "a git the profile cannot run: no sandbox (the documented PATH residual: Mandu's calls then run it as `git`)");
  await new Promise((res) => setTimeout(res, 200));
  assert.equal(existsSync(marker), false, "the planted git never ran outside a sandbox during the probe");
  assert.equal(connections, 0, "and reached no socket");
  // The control: the same file, run plainly, does both.
  execFileSync(planted, ["--version"], { stdio: "ignore" });
  await new Promise((res) => setTimeout(res, 200));
  assert.equal(existsSync(marker), true);
  assert.ok(connections >= 1, "the control reached the server");
});

// Review 2026-09-30: Apple's /usr/bin/git is an xcrun shim that runs the git
// its per-user cache names, and that cache is the user's (the agent can
// rewrite it). The hardened env sets xcrun_nocache=1, so a poisoned cache is
// never read by any Mandu git call through the shim. Run on a copy of the
// cache (xcrun_db names it), never the real one.
const XCRUN_DB = (() => {
  try { return execFileSync("getconf", ["DARWIN_USER_TEMP_DIR"], { encoding: "utf8" }).trim() + "xcrun_db"; } catch { return ""; }
})();
test("T7: a poisoned xcrun cache never picks the git Mandu runs through /usr/bin/git (the hardened env ignores the cache); plain git follows it", {
  skip: process.platform !== "darwin" ? "darwin only" : !existsSync("/usr/bin/xcrun") || !existsSync(XCRUN_DB) ? "no xcrun shim cache on this host" : false,
}, () => {
  // The cache is binary (offsets into a string table), so the git entry's
  // path is replaced in place by a planted path of the SAME byte length.
  const db = readFileSync(XCRUN_DB);
  const text = db.toString("latin1");
  const target = /git\|[^\0]*?\0(\/[^\0|]*\/git)\0/.exec(text)?.[1] ?? /(\/[^\0|]*\/usr\/bin\/git)\0/.exec(text)?.[1];
  assert.ok(target, "the cache names a git (run `git --version` once through the shim to make it)");
  const dir = mkdtempSync("/tmp/xc");
  const name = "g".repeat(target!.length - dir.length - 1);
  assert.ok(name.length > 0, `${dir} is too long to plant a ${target!.length}-byte path`);
  const evil = `${dir}/${name}`;
  const marker = join(dir, "ran");
  try {
    writeFileSync(evil, `#!/bin/sh\necho planted > '${marker}'\necho 'git version 0.0.0-planted'\n`, { mode: 0o755 });
    const copy = join(dir, "xcrun_db");
    writeFileSync(copy, Buffer.from(text.split(target!).join(evil), "latin1"), { mode: 0o600 });
    // The control: plain git through the shim follows the poisoned copy.
    const plain = spawnSync("/usr/bin/git", ["--version"], { env: { ...process.env, xcrun_db: copy }, encoding: "utf8" });
    assert.match(plain.stdout, /planted/, `the control: plain git follows the poisoned cache (${plain.stderr})`);
    assert.equal(existsSync(marker), true);
    rmSync(marker, { force: true });
    // Mandu's hardened env: the cache is never read.
    const hardened = spawnSync("/usr/bin/git", hardenedGitArgs(["--version"]), { env: hardenedGitEnv({ ...process.env, xcrun_db: copy }), encoding: "utf8" });
    assert.equal(hardened.status, 0, hardened.stderr);
    assert.doesNotMatch(hardened.stdout, /planted/);
    assert.equal(existsSync(marker), false, "the planted git never ran");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
