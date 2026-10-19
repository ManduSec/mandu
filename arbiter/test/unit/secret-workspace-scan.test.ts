/**
 * secret-workspace-scan.test — S2 of confidentiality plan 14 (§13.1, §13.3):
 * the walk over a REAL fixture tree, with the arbiter's own coverage rule
 * (`pathConfidentiality` with a label lookup, the call discovery makes).
 *
 * Pins:
 *   - special files: a real FIFO (the scan does not stall), a symlinked
 *     file (counted, never followed), a symlinked directory (never
 *     descended), an over-size file, a binary file;
 *   - the safe open itself: a symlink or a FIFO swapped in after the lstat
 *     is refused by the open / the fstat, never read; `/dev/null` is not a
 *     regular file;
 *   - pruned or skipped: depth, SKIP_DIRS (`.git`, `node_modules`), the
 *     agent's auth, the Mandu home, a file the catalog covers and a file a
 *     label covers (both NEVER OPENED, proven by an fs seam that records
 *     every open);
 *   - the home tier's name hints and a root's tier (HOME and above: home);
 *     a relative root, a pseudo-filesystem root, a nested root;
 *   - macOS (the platform injected, both platforms on every host): HOME's
 *     app-data and media folders and the mount points under `/`
 *     (`systemPrunes`) never entered, Linux unchanged; a root inside
 *     `/System/Volumes` or `/.vol` refused, one on another volume walked;
 *   - each budget and its `capped` line: the per-file cap, the total, the
 *     file count, the deadline;
 *   - the cache: a hit on an unchanged file, a miss on a changed mtime, the
 *     entry cap;
 *   - `repoRoot`: the nearest `.git` at or below the scan root;
 *   - no value: no key byte and no 8-character run of a key body anywhere
 *     in the scan's answer.
 *
 * Fixture keys are assembled at run time from random bytes. No privilege.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { promises as fsp } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { pathConfidentiality } from "../../policy/secret-catalog.js";
import { DARWIN_HOME_SKIP } from "../../policy/secret-discovery.js";
import type { LabelDecision } from "../../policy/path-labels.js";
import { isSecret } from "../../symbol-table/confidentiality.js";
import {
  DEFAULT_WORKSPACE_LIMITS,
  HOME_MAX_DEPTH,
  WORKSPACE_MAX_DEPTH,
  WorkspaceScanCache,
  defaultWorkspaceFs,
  nameHints,
  readRegularFile,
  rootTier,
  scanSecretWorkspace,
  systemPrunes,
  workspaceLimitsFromEnv,
  type WorkspaceScanFs,
  type WorkspaceScanOptions,
} from "../../policy/secret-workspace-scan.js";
import { stateAxes } from "../axes.js";
import { randomSecretBody } from "../helpers/random-secret.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); none is read

// A letter and a digit, no placeholder run: a value the detectors take
// (a plain random draw has no digit 0.19% of the time; random-secret.ts).
const alnum = randomSecretBody;
const TOKEN_BODY = alnum(36);
const TOKEN = "gh" + "p_" + TOKEN_BODY;
const AWS_BODY = alnum(16).toUpperCase().replace(/[^A-Z0-9]/g, "Q");
const AWS = "AK" + "IA" + AWS_BODY;
const PASS = "Zr8" + alnum(14) + "9q";
const BODIES = [TOKEN_BODY, AWS_BODY, PASS];
const RUNS = BODIES.flatMap((b) => Array.from({ length: b.length - 7 }, (_, i) => b.slice(i, i + 8)));

function noValue(what: string, s: string): void {
  assert.ok(!s.includes(TOKEN) && !s.includes(AWS) && !s.includes(PASS), `${what} carries a secret`);
  assert.equal(RUNS.find((r) => s.includes(r)), undefined, `${what} carries an 8-character run of a secret's body`);
}

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

interface Tree { dir: string; home: string; proj: string; outside: string; labelled: string; catalogCovered: string }

function tree(): Tree {
  const dir = mkdtempSync(join(tmpdir(), "mdu-ws-scan-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const proj = join(home, "proj");
  const outside = join(dir, "outside");
  const put = (p: string, body: string | Buffer): void => { mkdirSync(join(p, ".."), { recursive: true }); writeFileSync(p, body); };
  // The workspace: a work tree (a `.git` folder) with secrets the catalog misses.
  put(join(proj, ".git", "config"), `[remote]\n\turl = https://u:${PASS}@example.org/x\n`);
  put(join(proj, "deploy", "staging.conf"), `API_TOKEN=${TOKEN}\n`);
  put(join(proj, "notes", "deploy.md"), `the key: ${AWS}\n`);
  put(join(proj, "README.md"), "API_KEY=your-api-key-here\npassword = changeme-changeme-123\n");
  put(join(proj, ".env.staging"), `TOKEN=${TOKEN}\n`);             // the catalog covers it
  put(join(proj, "labelled.txt"), `token ${TOKEN}\n`);              // a label covers it
  put(join(proj, "node_modules", "pkg", "index.js"), `const t = "${TOKEN}";\n`);
  put(join(proj, "bin.dat"), Buffer.concat([Buffer.from([0, 1, 2]), Buffer.from(`${TOKEN}\n`)]));
  put(join(proj, "big.txt"), `${"x".repeat(9000)}\n${TOKEN}\n`);
  put(join(proj, "a", "b", "c", "d", "e", "f", "g", "h", "i", "deep.txt"), `${TOKEN}\n`);
  put(join(proj, "sub", "inner", "creds.yaml"), `db_password: ${PASS}\n`);
  put(join(proj, "sub", "inner", ".git", "HEAD"), "ref: refs/heads/main\n");
  put(join(outside, "leak.txt"), `${TOKEN}\n`);
  symlinkSync(join(proj, "deploy", "staging.conf"), join(proj, "link.conf"));
  symlinkSync(outside, join(proj, "linkdir"));
  execFileSync("mkfifo", [join(proj, "pipe.conf")]);
  // The home: name hints only, the agent's auth and the Mandu home pruned.
  put(join(home, "app.toml"), `db_password = "${PASS}"\n`);
  put(join(home, "notes.txt"), `${TOKEN}\n`);                        // no name hint: not read
  put(join(home, ".claude", "settings.json"), `{"token": "${TOKEN}"}\n`);
  put(join(home, ".mandu", "state", "workspaces", "w1", "agentview", "config.json"), `{"token": "${TOKEN}"}\n`);
  return { dir, home, proj, outside, labelled: join(proj, "labelled.txt"), catalogCovered: join(proj, ".env.staging") };
}

/** The arbiter's rule: the catalog, then a label (here: one exact path). */
function covered(t: Tree): (p: string) => boolean {
  const lookup = (p: string): LabelDecision | null => (p === t.labelled ? { level: "no-model", bindings: [], via: t.labelled } : null);
  return (p) => {
    const m = pathConfidentiality(p, t.home, lookup);
    return m.rule !== null && isSecret(m.level);
  };
}

/** An fs seam that records every path it opened. */
function recording(): { fs: WorkspaceScanFs; opened: string[] } {
  const opened: string[] = [];
  return {
    opened,
    fs: { ...defaultWorkspaceFs, readRegular: async (p, caps) => { opened.push(p); return readRegularFile(p, caps); } },
  };
}

const base = (t: Tree, over: Partial<WorkspaceScanOptions> = {}): WorkspaceScanOptions => ({
  home: t.home, env: {}, isCovered: covered(t), yieldNow: async () => {},
  limits: { fileMaxBytes: 8 * 1024 }, discovery: { installEnv: {}, selfDir: null },
  ...over,
});

test("the walk: findings, specials, prunes and coverage over a real tree; covered files are never opened", async () => {
  const t = tree();
  const { fs, opened } = recording();
  const scan = await scanSecretWorkspace([t.proj], base(t, { fs }));
  assert.deepEqual(scan.roots, [{ root: t.proj, tier: "workspace" }]);
  const found = Object.fromEntries(scan.findings.map((f) => [f.path, f]));
  assert.deepEqual(Object.keys(found).sort(), [
    join(t.proj, "deploy", "staging.conf"), join(t.proj, "notes", "deploy.md"), join(t.proj, "sub", "inner", "creds.yaml"),
  ].sort());
  const conf = found[join(t.proj, "deploy", "staging.conf")]!;
  assert.equal(conf.tier, "workspace");
  assert.equal(conf.root, t.proj);
  assert.equal(conf.repoRoot, t.proj, "the nearest .git at or below the root");
  assert.deepEqual(conf.detectors.map((d) => [d.kind, d.rule, d.preview]), [["content-shape", "github-token", "ghp_…"]]);
  assert.equal(found[join(t.proj, "notes", "deploy.md")]!.detectors[0]!.preview, "AKIA…");
  assert.equal(found[join(t.proj, "sub", "inner", "creds.yaml")]!.repoRoot, join(t.proj, "sub", "inner"), "a nested work tree is its own");
  // Covered: the catalog's .env.staging and the labelled file, never opened.
  assert.equal(scan.counts.covered, 2);
  assert.ok(!opened.includes(t.catalogCovered), "the catalog-covered file was opened");
  assert.ok(!opened.includes(t.labelled), "the labelled file was opened");
  // Pruned: .git, node_modules, the symlinked directory: none opened.
  assert.ok(!opened.some((p) => p.includes("/.git/") || p.includes("/node_modules/") || p.startsWith(t.outside) || p.includes("/linkdir")));
  // Specials: the FIFO is not read (and did not stall the walk), the link not followed.
  assert.equal(scan.capped.special, 1);
  assert.ok(!opened.includes(join(t.proj, "pipe.conf")), "a FIFO decided on lstat is never opened");
  assert.equal(scan.capped.symlinks, 2, "link.conf and linkdir");
  assert.equal(scan.capped.tooBig, 1);
  assert.equal(scan.capped.binary, 1);
  assert.equal(scan.capped.depth, 1, "a/b/…/i is below depth 8");
  assert.ok(scan.capped.lines.some((l) => /over 8 KiB not read \(MANDU_WORKSPACE_SCAN_FILE_MAX_KB\)/.test(l)), scan.capped.lines.join("\n"));
  assert.ok(scan.capped.lines.some((l) => /1 special file/.test(l)));
  assert.ok(scan.capped.lines.some((l) => /2 symbolic link/.test(l)));
  assert.ok(scan.capped.lines.some((l) => /below the depth limit/.test(l)));
  assert.ok(scan.capped.lines.some((l) => /1 binary file/.test(l)));
  assert.ok(!opened.includes(join(t.proj, "big.txt")), "an over-size file decided on lstat is never opened");
  assert.ok(opened.includes(join(t.proj, "bin.dat")), "a binary file is opened: its first bytes decide");
  assert.equal(scan.counts.read, opened.length);
  assert.ok(scan.counts.bytes > 0);
  noValue("the scan", JSON.stringify(scan));
});

test("the home tier: name hints only, depth 4, the agent's auth and the Mandu home pruned; HOME and above are home roots", async () => {
  const t = tree();
  const { fs, opened } = recording();
  const scan = await scanSecretWorkspace([t.home], base(t, { fs }));
  assert.deepEqual(scan.roots, [{ root: t.home, tier: "home" }]);
  const paths = scan.findings.map((f) => f.path);
  assert.ok(paths.includes(join(t.home, "app.toml")), JSON.stringify(paths));
  assert.equal(scan.findings.find((f) => f.path === join(t.home, "app.toml"))!.tier, "home");
  assert.ok(!opened.includes(join(t.home, "notes.txt")), "no name hint: not read");
  assert.ok(!opened.some((p) => p.includes("/.claude/")), "the agent's own auth is pruned");
  assert.ok(!opened.some((p) => p.includes("/.mandu/")), "the Mandu home is pruned");
  assert.ok(paths.includes(join(t.proj, "deploy", "staging.conf")), "a hinted name below HOME is read");
  assert.ok(!paths.includes(join(t.proj, "notes", "deploy.md")), "an unhinted one is not");
  // includeHome adds HOME beside a workspace root; the home walk leaves the
  // workspace root to its own (full) walk.
  const both = await scanSecretWorkspace([t.proj], base(t, { includeHome: true }));
  assert.deepEqual(both.roots.map((r) => [r.root, r.tier]), [[t.proj, "workspace"], [t.home, "home"]]);
  assert.equal(both.findings.filter((f) => f.path === join(t.proj, "deploy", "staging.conf")).length, 1);
  assert.equal(both.findings.find((f) => f.path === join(t.proj, "deploy", "staging.conf"))!.tier, "workspace");
  assert.ok(both.findings.some((f) => f.path === join(t.home, "app.toml")));
  assert.equal(HOME_MAX_DEPTH, 4);
  assert.equal(WORKSPACE_MAX_DEPTH, 8);
});

test("roots: tiers, a relative root, a pseudo-filesystem, Mandu's own state, a nested root, a missing one, over the cap", async () => {
  assert.equal(rootTier("/home/u", "/home/u"), "home");
  assert.equal(rootTier("/home", "/home/u"), "home");
  assert.equal(rootTier("/", "/home/u"), "home");
  assert.equal(rootTier("/home/u/proj", "/home/u"), "workspace");
  assert.equal(rootTier("/srv/app", "/home/u"), "workspace");
  assert.equal(rootTier("/home/uu", "/home/u"), "workspace", "a sibling with a common prefix is not above HOME");
  const t = tree();
  const scan = await scanSecretWorkspace(
    ["rel/dir", "/proc/self", join(t.home, ".mandu", "state"), t.proj, join(t.proj, "deploy"), join(t.dir, "nope")],
    base(t),
  );
  const why = Object.fromEntries(scan.roots.map((r) => [r.root, r.reason ?? "walked"]));
  assert.equal(why["rel/dir"], "not an absolute path");
  assert.equal(why["/proc/self"], "a kernel pseudo-filesystem, not scanned");
  assert.equal(why[join(t.home, ".mandu", "state")], "Mandu's own state, not scanned");
  assert.equal(why[t.proj], "walked");
  assert.equal(why[join(t.proj, "deploy")], "inside another root");
  assert.equal(why[join(t.dir, "nope")], "does not exist or cannot be read");
  const many = await scanSecretWorkspace(Array.from({ length: 10 }, () => t.proj), base(t));
  assert.ok(many.capped.lines.some((l) => /2 root\(s\) over 8 not scanned/.test(l)));
  assert.equal(many.roots.filter((r) => r.reason === undefined).length, 1);
});

test("a root of / is a home root: name hints, /proc /sys /dev pruned, the deadline bounds it", async () => {
  const t = tree();
  const { fs, opened } = recording();
  let clock = 0;
  const scan = await scanSecretWorkspace(["/"], base(t, { fs, limits: { timeoutMs: 400, maxFiles: 300 }, now: () => (clock += 1) }));
  assert.deepEqual(scan.roots, [{ root: "/", tier: "home" }]);
  assert.ok(!opened.some((p) => p.startsWith("/proc/") || p.startsWith("/sys/") || p.startsWith("/dev/")), opened.filter((p) => /^\/(proc|sys|dev)\//.test(p)).join(","));
  assert.ok(opened.every((p) => nameHints(p.slice(p.lastIndexOf("/") + 1))));
  assert.ok(scan.counts.examined <= 300);
});

// ── macOS (2026-09-30): HOME's app-data and media folders, and the mount
// points under `/`, are never walked; Linux unchanged ─────────────────────

test("systemPrunes: Linux (and any host but macOS) prunes the kernel's pseudo-filesystems only; macOS adds the mount points under /", () => {
  const linux = systemPrunes("linux");
  assert.deepEqual([...linux.walk].sort(), ["/dev", "/proc", "/sys"]);
  assert.deepEqual(linux.roots, [
    { dir: "/proc", why: "a kernel pseudo-filesystem, not scanned" },
    { dir: "/sys", why: "a kernel pseudo-filesystem, not scanned" },
    { dir: "/dev", why: "a kernel pseudo-filesystem, not scanned" },
  ]);
  assert.deepEqual(systemPrunes("win32"), linux);
  const mac = systemPrunes("darwin");
  assert.deepEqual([...mac.walk].sort(), ["/.vol", "/System/Volumes", "/Volumes", "/dev", "/home", "/net", "/proc", "/sys"]);
  assert.deepEqual(mac.roots.map((r) => r.dir), ["/proc", "/sys", "/dev", "/System/Volumes", "/.vol"],
    "a root on another volume or an automounted one is walked when named; only the second paths to this disk are refused");
});

/** A filesystem seam serving the directory `top` as `/`: the scan sees the
 *  absolute paths it would see on a host (`/System/Volumes/…`) and reads
 *  the fixture. Records every folder listed and every file opened. */
function rootedFs(top: string): { fs: WorkspaceScanFs; listed: string[]; opened: string[] } {
  const listed: string[] = [];
  const opened: string[] = [];
  const at = (p: string): string => (p === "/" ? top : join(top, p));
  return {
    listed,
    opened,
    fs: {
      lstat: (p) => defaultWorkspaceFs.lstat(at(p)),
      stat: (p) => defaultWorkspaceFs.stat(at(p)),
      readdir: async (p) => { listed.push(p); return defaultWorkspaceFs.readdir(at(p)); },
      readRegular: async (p, caps) => { opened.push(p); return readRegularFile(at(p), caps); },
    },
  };
}

test("macOS: a walk from / never enters /System/Volumes, /.vol, /Volumes, /net, /home or HOME's Library; Linux walks them as before", async () => {
  const top = mkdtempSync(join(tmpdir(), "mdu-ws-root-"));
  dirs.push(top);
  const put = (p: string): void => { mkdirSync(join(top, p, ".."), { recursive: true }); writeFileSync(join(top, p), `db_password = "${PASS}"\n`); };
  const mounts = ["/System/Volumes/Data/app.toml", "/.vol/16777220/app.toml", "/Volumes/Ext/app.toml", "/net/host/app.toml", "/home/u2/app.toml"];
  const library = "/Users/u/Library/Application Support/app.toml";
  const kept = ["/Users/u/app.toml", "/srv/app.toml", "/System/Library/app.toml"];
  for (const p of [...mounts, library, ...kept, "/proc/1/app.toml"]) put(p);
  const opts = (platform: NodeJS.Platform, fs: WorkspaceScanFs): WorkspaceScanOptions => ({
    home: "/Users/u", env: {}, isCovered: () => false, yieldNow: async () => {},
    discovery: { installEnv: {}, selfDir: null }, platform, fs,
  });

  const mac = rootedFs(top);
  const m = await scanSecretWorkspace(["/"], opts("darwin", mac.fs));
  assert.deepEqual(m.roots, [{ root: "/", tier: "home" }]);
  assert.deepEqual(m.findings.map((f) => f.path).sort(), [...kept].sort(), "only what lies outside every prune");
  for (const d of ["/System/Volumes", "/.vol", "/Volumes", "/net", "/home", "/Users/u/Library", "/proc"]) {
    assert.ok(!mac.listed.some((p) => p === d || p.startsWith(`${d}/`)), `${d} was entered: ${mac.listed.join(", ")}`);
  }
  assert.ok(mac.listed.includes("/System"), "/System itself is walked, only its Volumes are not");
  assert.ok(!mac.opened.some((p) => mounts.includes(p) || p === library));

  const lin = rootedFs(top);
  const l = await scanSecretWorkspace(["/"], opts("linux", lin.fs));
  assert.deepEqual(l.findings.map((f) => f.path).sort(), [...mounts, library, ...kept].sort(), "Linux: every folder but /proc, /sys and /dev");
  assert.ok(!lin.listed.some((p) => p.startsWith("/proc")));
  noValue("the scans", JSON.stringify([m, l]));
});

test("macOS roots: inside /System/Volumes or /.vol refused (a second path to this disk); on another volume or an automounted one walked", async () => {
  const top = mkdtempSync(join(tmpdir(), "mdu-ws-roots-"));
  dirs.push(top);
  const roots = ["/System/Volumes/Data/Users/u", "/.vol/16777220", "/Volumes/Ext/proj", "/net/host/proj", "/home/u2/proj"];
  for (const r of roots) {
    mkdirSync(join(top, r), { recursive: true });
    writeFileSync(join(top, r, "deploy.conf"), `API_TOKEN=${TOKEN}\n`);
  }
  const opts = (platform: NodeJS.Platform): WorkspaceScanOptions => ({
    home: "/Users/u", env: {}, isCovered: () => false, yieldNow: async () => {},
    discovery: { installEnv: {}, selfDir: null }, platform, fs: rootedFs(top).fs,
  });
  const mac = await scanSecretWorkspace(roots, opts("darwin"));
  const why = Object.fromEntries(mac.roots.map((r) => [r.root, r.reason ?? "walked"]));
  assert.equal(why["/System/Volumes/Data/Users/u"], "the system's volumes, a second path to this Mac's folders, not scanned");
  assert.equal(why["/.vol/16777220"], "a kernel pseudo-filesystem, not scanned");
  for (const r of roots.slice(2)) assert.equal(why[r], "walked", r);
  assert.deepEqual(mac.findings.map((f) => f.path).sort(), roots.slice(2).map((r) => `${r}/deploy.conf`).sort());
  const lin = await scanSecretWorkspace(roots, opts("linux"));
  assert.ok(lin.roots.every((r) => r.reason === undefined), JSON.stringify(lin.roots));
  assert.equal(lin.findings.length, roots.length);
  noValue("the scans", JSON.stringify([mac, lin]));
});

test("macOS home tier: HOME's Library, .Trash, Pictures, Music and Movies never entered; no label re-entry is needed (a covered file is never opened, walked or not); Linux walks them", async () => {
  const t = tree();
  const put = (p: string, body: string): void => { mkdirSync(join(p, ".."), { recursive: true }); writeFileSync(p, body); };
  const media = DARWIN_HOME_SKIP.map((d) => join(t.home, d, "app", "app.toml"));
  for (const p of media) put(p, `db_password = "${PASS}"\n`);
  // Already protected inside ~/Library: a labelled file and a catalog match.
  const labelled = join(t.home, "Library", "Application Support", "acme", "token.conf");
  put(labelled, `API_TOKEN=${TOKEN}\n`);
  const catalog = join(t.home, "Library", "acme", ".env");
  put(catalog, `TOKEN=${TOKEN}\n`);
  // A project's own Library/ is not HOME's; an iCloud Drive project named as
  // a root is walked as a workspace.
  const projLib = join(t.proj, "Library", "app.toml");
  put(projLib, `db_password = "${PASS}"\n`);
  const icloud = join(t.home, "Library", "Mobile Documents", "com~apple~CloudDocs", "proj");
  put(join(icloud, "deploy", "prod.conf"), `API_TOKEN=${TOKEN}\n`);
  const lookup = (p: string): LabelDecision | null => (p === t.labelled || p === labelled ? { level: "no-model", bindings: [], via: p } : null);
  const isCovered = (p: string): boolean => {
    const m = pathConfidentiality(p, t.home, lookup);
    return m.rule !== null && isSecret(m.level);
  };
  const run = async (roots: string[], platform: NodeJS.Platform) => {
    const { fs, opened } = recording();
    return { scan: await scanSecretWorkspace(roots, base(t, { fs, isCovered, platform })), opened };
  };
  const inPruned = (p: string): boolean => DARWIN_HOME_SKIP.some((d) => p.startsWith(join(t.home, d) + "/"));

  for (const roots of [[t.home], [t.dir]]) {
    const mac = await run(roots, "darwin");
    assert.equal(mac.scan.roots[0]!.tier, "home");
    assert.ok(!mac.opened.some(inPruned), `opened under a pruned folder: ${mac.opened.filter(inPruned).join(", ")}`);
    assert.ok(!mac.scan.findings.some((f) => inPruned(f.path)));
    assert.ok(mac.scan.findings.some((f) => f.path === projLib), "a project's Library/ is walked");
    assert.ok(mac.scan.findings.some((f) => f.path === join(t.home, "app.toml")), "the rest of HOME is walked");

    const lin = await run(roots, "linux");
    for (const p of media) assert.ok(lin.scan.findings.some((f) => f.path === p), `Linux walks ${p}`);
    // Walked, the protected files are counted covered and never opened: the
    // prune loses no key finding, so it needs no label re-entry (it does lose
    // sensitivity labels under ~/Library, plan 14 §11.3).
    assert.ok(!lin.opened.includes(labelled) && !lin.opened.includes(catalog));
    assert.ok(!lin.scan.findings.some((f) => f.path === labelled || f.path === catalog));
    assert.equal(lin.scan.counts.covered - mac.scan.counts.covered, 2, "the two protected files, counted only where walked");
    noValue("the scans", JSON.stringify([mac.scan, lin.scan]));
  }
  const own = await run([icloud], "darwin");
  assert.deepEqual(own.scan.roots, [{ root: icloud, tier: "workspace" }]);
  assert.deepEqual(own.scan.findings.map((f) => f.path), [join(icloud, "deploy", "prod.conf")], "a root inside ~/Library is walked when named");
});

test("name hints: configuration and key names, not source or prose", () => {
  for (const n of [".env", ".env-staging", "prod.env", "server.pem", "tls.key", ".npmrc", ".bashrc", "app.json", "a.yaml", "b.yml",
    "c.toml", "d.ini", "e.cfg", "nginx.conf", "app.properties", "prod.tfvars", "my_secret", "TOKEN.txt", "credentials", "passwd.old",
    "oauth.txt", "Config.cs", "settings.py"]) {
    assert.ok(nameHints(n), n);
  }
  for (const n of ["main.rs", "README.md", "notes.txt", "index.js", "photo.png"]) assert.ok(!nameHints(n), n);
});

test("the safe open: a symlink or a FIFO swapped in after the lstat is never read; /dev/null is not regular; caps on the descriptor", async () => {
  const t = tree();
  const caps = { fileMax: 8 * 1024, totalLeft: 1 << 20 };
  assert.deepEqual(await readRegularFile(join(t.proj, "link.conf"), caps), { kind: "symlink" }, "O_NOFOLLOW");
  const t0 = Date.now();
  assert.deepEqual(await readRegularFile(join(t.proj, "pipe.conf"), caps), { kind: "not-regular" }, "O_NONBLOCK + fstat: no writer, no stall");
  assert.ok(Date.now() - t0 < 2000);
  assert.deepEqual(await readRegularFile("/dev/null", caps), { kind: "not-regular" });
  assert.deepEqual(await readRegularFile(join(t.proj, "big.txt"), caps), { kind: "too-big" });
  assert.deepEqual(await readRegularFile(join(t.proj, "deploy", "staging.conf"), { fileMax: caps.fileMax, totalLeft: 4 }), { kind: "over-total" });
  assert.deepEqual(await readRegularFile(join(t.dir, "absent"), caps), { kind: "unreadable" });
  const ok = await readRegularFile(join(t.proj, "deploy", "staging.conf"), caps);
  assert.equal(ok.kind, "read");

  // The race: the walk's lstat saw a regular file, then the name became a
  // link to /dev/zero, or a FIFO. The open and the fstat catch both.
  const swapLink = join(t.proj, "swap-link.conf");
  const swapFifo = join(t.proj, "swap-fifo.conf");
  symlinkSync("/dev/zero", swapLink);
  execFileSync("mkfifo", [swapFifo]);
  const regular = await fsp.lstat(join(t.proj, "README.md"), { bigint: true });
  const lying: WorkspaceScanFs = {
    ...defaultWorkspaceFs,
    lstat: async (p) => (p === swapLink || p === swapFifo ? regular : defaultWorkspaceFs.lstat(p)),
  };
  const scan = await scanSecretWorkspace([t.proj], base(t, { fs: lying }));
  assert.equal(scan.capped.symlinks, 3, "link.conf, linkdir, and the swapped-in link");
  assert.equal(scan.capped.special, 2, "pipe.conf, and the swapped-in FIFO");
});

test("names with control characters travel as data", async () => {
  const t = tree();
  const odd = join(t.proj, "odd\nname\x1b[31m.conf");
  writeFileSync(odd, `API_TOKEN=${TOKEN}\n`);
  const scan = await scanSecretWorkspace([t.proj], base(t));
  const f = scan.findings.find((x) => x.path === odd);
  assert.ok(f, "found under its exact name");
  const wire = JSON.stringify(scan);
  assert.ok(!wire.includes("\n") && !wire.includes("\x1b"), "JSON escapes them");
  noValue("the scan", wire);
});

test("budgets: the total, the file count and the deadline each stop the walk and say so", async () => {
  const t = tree();
  const total = await scanSecretWorkspace([t.proj], base(t, { limits: { fileMaxBytes: 8 * 1024, totalMaxBytes: 40 } }));
  assert.ok(total.capped.overTotal > 0);
  assert.ok(total.counts.bytes <= 40);
  assert.ok(total.capped.lines.some((l) => /not read: over the 0 MiB total \(MANDU_WORKSPACE_SCAN_MAX_MB\)/.test(l)), total.capped.lines.join("\n"));

  const files = await scanSecretWorkspace([t.proj], base(t, { limits: { fileMaxBytes: 8 * 1024, maxFiles: 3 } }));
  assert.equal(files.counts.examined, 3);
  assert.ok(files.capped.overFiles > 0 || files.capped.lines.some((l) => /folder\(s\) not examined/.test(l)));
  assert.ok(files.capped.lines.some((l) => /over the 3 file cap \(MANDU_WORKSPACE_SCAN_FILES\)/.test(l)), files.capped.lines.join("\n"));

  let clock = 0;
  const timed = await scanSecretWorkspace([t.proj], base(t, { limits: { fileMaxBytes: 8 * 1024, timeoutMs: 5 }, now: () => (clock += 1) }));
  assert.ok(timed.capped.lines.some((l) => /time budget ran out \(MANDU_WORKSPACE_SCAN_TIMEOUT_S\)/.test(l)), timed.capped.lines.join("\n"));
  assert.ok(timed.counts.examined < 10);

  assert.deepEqual(workspaceLimitsFromEnv({}), DEFAULT_WORKSPACE_LIMITS);
  assert.deepEqual(DEFAULT_WORKSPACE_LIMITS, { fileMaxBytes: 256 * 1024, totalMaxBytes: 64 * 1024 * 1024, maxFiles: 20_000, timeoutMs: 30_000 });
  const l = workspaceLimitsFromEnv({
    MANDU_WORKSPACE_SCAN_FILE_MAX_KB: "16", MANDU_WORKSPACE_SCAN_MAX_MB: "2", MANDU_WORKSPACE_SCAN_FILES: "100", MANDU_WORKSPACE_SCAN_TIMEOUT_S: "3",
  });
  assert.deepEqual(l, { fileMaxBytes: 16 * 1024, totalMaxBytes: 2 * 1024 * 1024, maxFiles: 100, timeoutMs: 3000 });
  assert.equal(workspaceLimitsFromEnv({ MANDU_WORKSPACE_SCAN_FILES: "nope" }).maxFiles, 20_000);
});

test("the cache: an unchanged file is not read again; a changed mtime is; masks only; capped", async () => {
  const t = tree();
  const cache = new WorkspaceScanCache();
  const first = recording();
  const a = await scanSecretWorkspace([t.proj], base(t, { fs: first.fs, cache }));
  assert.ok(a.counts.read > 0);
  assert.equal(a.counts.cached, 0);
  const second = recording();
  const b = await scanSecretWorkspace([t.proj], base(t, { fs: second.fs, cache }));
  assert.equal(b.counts.read, 0, "nothing changed: nothing read");
  assert.deepEqual(second.opened.filter((p) => !p.endsWith("big.txt")), [], "only the over-size file is re-decided (never cached)");
  assert.equal(b.counts.cached, a.counts.read);
  assert.deepEqual(b.findings, a.findings);
  const conf = join(t.proj, "deploy", "staging.conf");
  utimesSync(conf, new Date(), new Date(Date.now() + 5000));
  const third = recording();
  const c = await scanSecretWorkspace([t.proj], base(t, { fs: third.fs, cache }));
  assert.deepEqual(third.opened.filter((p) => !p.endsWith("big.txt")), [conf], "the changed file, and only it, is read again");
  assert.equal(c.findings.length, a.findings.length);
  noValue("the cache's key and content", JSON.stringify([...(cache as unknown as { map: Map<string, unknown> }).map]));
  // The entry cap: least recently used first.
  const small = new WorkspaceScanCache(2);
  small.set("a", { binary: false, hits: [] });
  small.set("b", { binary: false, hits: [] });
  small.get("a");
  small.set("c", { binary: true, hits: [] });
  assert.equal(small.size, 2);
  assert.equal(small.get("b"), undefined);
  assert.notEqual(small.get("a"), undefined);
  // A new detector fingerprint is a new key.
  const id = { dev: 1n, ino: 2n, size: 3n, mtimeNs: 4n, ctimeNs: 5n };
  assert.notEqual(WorkspaceScanCache.key(id, "f1"), WorkspaceScanCache.key(id, "f2"));
  assert.notEqual(WorkspaceScanCache.key(id, "f1"), WorkspaceScanCache.key({ ...id, ctimeNs: 6n }, "f1"));
});

test("a linked work tree below a root is not walked; a submodule and a root that is itself one are (§13.9)", async () => {
  const t = tree();
  const put = (p: string, body: string): void => { mkdirSync(join(p, ".."), { recursive: true }); writeFileSync(p, body); };
  // An agent's worktree of the same repository, and a `git worktree add` one.
  const wt = join(t.proj, ".claude", "worktrees", "w1");
  put(join(wt, ".git"), `gitdir: ${join(t.proj, ".git", "worktrees", "w1")}\n`);
  put(join(wt, "deploy", "staging.conf"), `API_TOKEN=${TOKEN}\n`);
  const wt2 = join(t.proj, "wt2");
  put(join(wt2, ".git"), "gitdir: ../.git/worktrees/wt2");
  put(join(wt2, "notes.md"), `${AWS}\n`);
  // A submodule's gitfile names `modules/`: its own content, walked.
  const sm = join(t.proj, "vendor", "sm");
  put(join(sm, ".git"), "gitdir: ../../.git/modules/sm\n");
  put(join(sm, "sm.conf"), `API_TOKEN=${TOKEN}\n`);
  const { fs, opened } = recording();
  const scan = await scanSecretWorkspace([t.proj], base(t, { fs }));
  assert.equal(scan.capped.worktrees, 2);
  assert.ok(scan.capped.lines.some((l) => /2 linked git work tree\(s\) inside a root not walked/.test(l)), scan.capped.lines.join("\n"));
  assert.ok(!opened.some((p) => p.startsWith(wt + "/") && !p.endsWith("/.git")), "a file of the nested work tree was read");
  assert.ok(!scan.findings.some((f) => f.path.startsWith(wt) || f.path.startsWith(wt2)));
  const smHit = scan.findings.find((f) => f.path === join(sm, "sm.conf"));
  assert.ok(smHit, "a submodule is walked");
  assert.equal(smHit.repoRoot, sm);
  // The root may itself be a linked work tree: walked.
  const own = await scanSecretWorkspace([wt], base(t));
  assert.equal(own.capped.worktrees, 0);
  assert.deepEqual(own.findings.map((f) => [f.path, f.repoRoot]), [[join(wt, "deploy", "staging.conf"), wt]]);
  noValue("the scan", JSON.stringify([scan, own]));
});
