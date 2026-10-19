/**
 * Unit: known-repos — the known-repository registry and the HOME walk
 * (confidentiality-plan-14 §11.1 R1): the data-plane cap refuses and never
 * evicts, the recomputed sources are replaced wholesale and capped, a gone
 * work tree and a lapsed data-plane source are pruned, the order, the
 * mandu.db round trip; the walk's depth / repository / directory caps and
 * discovery's prunes (the agent's own auth, Mandu's home, the skip list, a
 * directory link never followed), a nested clone and a linked worktree; on
 * macOS (the platform injected, both on every host) HOME's app-data and
 * media folders are never entered unless a label concerns them (the
 * re-entry per label kind, discovery's `darwinPrune`), Linux unchanged.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DEFAULT_REPO_WALK_LIMITS, findRepositories, isWorkTreeRoot, KnownRepoStore, orderRepos, workTreeRootAt, type KnownRepo,
} from "../../policy/known-repos.js";
import { DARWIN_HOME_SKIP } from "../../policy/secret-discovery.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the registry serves the confidentiality axis's locks

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = realpathSync(mkdtempSync(join(tmpdir(), "mdu-known-repos-"))); dirs.push(d); return d; };
const ENV = { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" };
const gitInit = (d: string): void => { mkdirSync(d, { recursive: true }); execFileSync("git", ["init", "-q", d], { env: ENV }); };

test("registry: data-plane roots are added and renewed; at the cap a new one is REFUSED, never another evicted", () => {
  let t = 1000;
  const s = new KnownRepoStore({ now: () => t, limits: { dataPlane: 2 } });
  assert.equal(s.add("/r/a", "launch"), "added");
  t++;
  assert.equal(s.add("/r/b", "register"), "added");
  t++;
  assert.equal(s.add("/r/c", "scan"), "full");
  assert.equal(s.has("/r/c"), false);
  assert.equal(s.add("/r/a", "scan"), "renewed", "a root already holding a data-plane source is renewed even at the cap");
  assert.deepEqual(s.get("/r/a")!.sources, { launch: 1000, scan: 1002 });
  assert.throws(() => s.add("/r/x", "walk"), /recomputed/);
  // A walk-only root takes a data-plane source only under the cap.
  s.replaceSource("walk", ["/r/w"]);
  assert.equal(s.add("/r/w", "register"), "full");
  assert.deepEqual(Object.keys(s.get("/r/w")!.sources), ["walk"]);
});

test("registry: label and walk are replaced wholesale and capped in the caller's order; a root leaves with its last source", () => {
  const s = new KnownRepoStore({ limits: { walk: 2 } });
  assert.deepEqual(s.replaceSource("walk", ["/r/1", "/r/2", "/r/3"]), ["/r/1", "/r/2"], "the first found are kept (breadth-first: the shallowest)");
  s.add("/r/2", "launch");
  s.replaceSource("walk", ["/r/9"]);
  assert.equal(s.has("/r/1"), false, "walk-only, no longer found: gone");
  assert.deepEqual(Object.keys(s.get("/r/2")!.sources), ["launch"], "still named by a launch: stays");
  assert.equal(s.has("/r/9"), true);
  s.replaceSource("label", ["/r/9"]);
  s.replaceSource("walk", []);
  assert.deepEqual(Object.keys(s.get("/r/9")!.sources), ["label"]);
});

test("registry: prune drops a gone work tree whatever named it, and a data-plane source not renewed in 30 days", () => {
  let t = 0;
  const s = new KnownRepoStore({ now: () => t });
  s.add("/r/old", "register");
  s.add("/r/gone", "launch");
  s.replaceSource("walk", ["/r/both"]);
  s.add("/r/both", "scan");
  t = 31 * 24 * 3600_000;
  s.add("/r/fresh", "launch");
  const dropped = s.prune((r) => r !== "/r/gone");
  assert.deepEqual(dropped, ["/r/gone", "/r/old"]);
  assert.deepEqual(Object.keys(s.get("/r/both")!.sources), ["walk"], "the lapsed scan source goes; the walk keeps it");
  assert.equal(s.has("/r/fresh"), true);
});

test("registry: the order is best source, then most recent, then path; mandu.db round trip", () => {
  const list: KnownRepo[] = [
    { root: "/w", sources: { walk: 5 }, firstSeen: 0 },
    { root: "/l", sources: { label: 1 }, firstSeen: 0 },
    { root: "/a2", sources: { launch: 1, walk: 9 }, firstSeen: 0 },
    { root: "/a1", sources: { launch: 3 }, firstSeen: 0 },
    { root: "/s", sources: { scan: 2 }, firstSeen: 0 },
    { root: "/g", sources: { register: 2 }, firstSeen: 0 },
  ];
  assert.deepEqual(orderRepos(list).map((r) => r.root), ["/a2", "/a1", "/l", "/s", "/g", "/w"]);
  const d = tmp();
  const db = join(d, "mandu.db");
  const a = new KnownRepoStore({ dbPath: db, now: () => 7 });
  a.add("/r/a", "launch");
  a.replaceSource("walk", ["/r/b"]);
  a.close();
  const b = new KnownRepoStore({ dbPath: db });
  assert.deepEqual(b.list().map((r) => [r.root, r.sources]), [["/r/a", { launch: 7 }], ["/r/b", { walk: 7 }]]);
  b.remove("/r/a");
  b.close();
  const c = new KnownRepoStore({ dbPath: db });
  assert.deepEqual(c.list().map((r) => r.root), ["/r/b"]);
  c.close();
});

test("what a root is: a .git directory with HEAD, or a gitdir file; the nearest ancestor; never inside .git", () => {
  const d = tmp();
  gitInit(join(d, "repo"));
  mkdirSync(join(d, "repo", "sub", "deep"), { recursive: true });
  mkdirSync(join(d, "fake", ".git"), { recursive: true }); // no HEAD
  mkdirSync(join(d, "wt"), { recursive: true });
  writeFileSync(join(d, "wt", ".git"), "gitdir: /elsewhere/.git/worktrees/wt\n");
  mkdirSync(join(d, "junk"), { recursive: true });
  writeFileSync(join(d, "junk", ".git"), "not a pointer\n");
  assert.equal(isWorkTreeRoot(join(d, "repo")), true);
  assert.equal(isWorkTreeRoot(join(d, "fake")), false);
  assert.equal(isWorkTreeRoot(join(d, "wt")), true);
  assert.equal(isWorkTreeRoot(join(d, "junk")), false);
  assert.equal(workTreeRootAt(join(d, "repo", "sub", "deep", "gone.txt")), join(d, "repo"), "a path need not exist");
  assert.equal(workTreeRootAt(join(d, "repo", ".git", "config")), null);
  assert.equal(workTreeRootAt("relative/path"), null);
});

test("HOME walk: nested clones and worktrees found; discovery's prunes, Mandu's home and a directory link are never entered; the depth cap", async () => {
  const home = tmp();
  gitInit(join(home, "proj"));
  gitInit(join(home, "proj", "vendor", "lib")); // a nested clone
  gitInit(join(home, "a", "b", "c", "d", "five")); // depth 5: found
  gitInit(join(home, "a", "b", "c", "d", "e", "six")); // depth 6: below the cap
  gitInit(join(home, "node_modules", "pkg")); // discovery's skip list
  gitInit(join(home, ".cache", "x"));
  gitInit(join(home, ".claude", "plugins", "m")); // an agent's own data (AGENT_STORES)
  gitInit(join(home, ".mandu", "state", "workspaces", "w", "shadow")); // Mandu's own
  gitInit(join(tmp(), "outside"));
  symlinkSync(join(dirs[dirs.length - 1]!, "outside"), join(home, "link")); // a directory link
  mkdirSync(join(home, "wt"), { recursive: true });
  writeFileSync(join(home, "wt", ".git"), "gitdir: /x/.git/worktrees/wt\n");
  const r = await findRepositories(home, { yieldNow: async () => {}, env: {}, selfDir: null });
  assert.deepEqual(r.roots, [join(home, "proj"), join(home, "wt"), join(home, "proj", "vendor", "lib"), join(home, "a", "b", "c", "d", "five")],
    "breadth-first; nothing pruned, linked or too deep");
  assert.equal(r.truncated, null);
  assert.equal(DEFAULT_REPO_WALK_LIMITS.maxDepth, 5);
});

test("HOME walk: the repository, directory and time caps stop it and say which", async () => {
  const home = tmp();
  for (let i = 0; i < 5; i++) gitInit(join(home, `r${i}`));
  const byRepos = await findRepositories(home, { limits: { maxRepos: 2 }, yieldNow: async () => {}, env: {}, selfDir: null });
  assert.deepEqual(byRepos.roots, [join(home, "r0"), join(home, "r1")]);
  assert.equal(byRepos.truncated, "repos");
  const byDirs = await findRepositories(home, { limits: { maxDirs: 1 }, yieldNow: async () => {}, env: {}, selfDir: null });
  assert.equal(byDirs.truncated, "dirs");
  assert.deepEqual(byDirs.roots, []);
  let t = 0;
  const byTime = await findRepositories(home, { limits: { timeMs: 10 }, now: () => (t += 20), yieldNow: async () => {}, env: {}, selfDir: null });
  assert.equal(byTime.truncated, "time");
});

test("HOME walk, macOS: HOME's Library, .Trash, Pictures, Music and Movies are never entered (direct children, by the walk's real spelling of HOME); Linux walks them", async () => {
  const home = tmp();
  for (const d of DARWIN_HOME_SKIP) gitInit(join(home, d, "app", "repo"));
  gitInit(join(home, "proj"));
  gitInit(join(home, "proj", "Library", "vendored")); // a project's own Library/ is not HOME's
  const opts = { yieldNow: async () => {}, env: {}, selfDir: null };
  const mac = await findRepositories(home, { ...opts, platform: "darwin" });
  assert.deepEqual(mac.roots, [join(home, "proj"), join(home, "proj", "Library", "vendored")]);
  const linux = await findRepositories(home, { ...opts, platform: "linux" });
  assert.deepEqual(linux.roots.slice().sort(), [
    ...DARWIN_HOME_SKIP.map((d) => join(home, d, "app", "repo")), join(home, "proj"), join(home, "proj", "Library", "vendored"),
  ].sort());
  assert.ok(mac.dirs < linux.dirs, `the pruned folders are not read: ${mac.dirs} vs ${linux.dirs}`);
  // HOME named through a link (a HOME under /tmp or /var on a Mac): the walk
  // runs on the real spelling, and so does the prune.
  const link = join(tmp(), "home-link");
  symlinkSync(home, link);
  const viaLink = await findRepositories(link, { ...opts, platform: "darwin" });
  assert.deepEqual(viaLink.roots, mac.roots);
});

test("HOME walk, macOS: a label keeps a pruned folder walked where it concerns a repository (discovery's rule, darwinPrune): a folder label inside it walks that folder, a pattern rooted above or inside it or unrooted walks it all; a labelled file or an unrelated label lifts nothing; Linux the same with or without labels", async () => {
  const home = tmp();
  const cloud = join(home, "Library", "Mobile Documents", "com~apple~CloudDocs");
  const icloud = join(cloud, "proj"); // an iCloud Drive project
  gitInit(icloud);
  mkdirSync(join(icloud, "deploy"), { recursive: true });
  writeFileSync(join(icloud, "deploy", "id_rsa"), "k\n");
  const container = join(home, "Library", "Containers", "x", "repo");
  gitInit(container);
  const music = join(home, "Music", "lib", "repo");
  gitInit(music);
  const work = join(home, "work", "a");
  gitInit(work);
  symlinkSync(cloud, join(home, "Library", "cloud-link")); // a directory link inside ~/Library
  const opts = { yieldNow: async () => {}, env: {}, selfDir: null };
  const walk = async (labelPaths: string[], platform: NodeJS.Platform = "darwin", limits = {}): Promise<string[]> =>
    (await findRepositories(home, { ...opts, platform, labelPaths, limits })).roots;
  const all = [container, icloud, music, work].sort();
  const library = [container, icloud, work].sort();

  // Why the walk must re-enter: the `label` source only walks UP from a
  // label (LockResolver.rootOf → workTreeRootAt), so a folder label above a
  // repository, or a pattern's prefix above it, names no work tree at all.
  assert.equal(workTreeRootAt(cloud), null);
  assert.equal(workTreeRootAt(join(home, "Library")), null);
  assert.equal(workTreeRootAt(join(icloud, "deploy", "id_rsa")), icloud, "a labelled file's repository is the label source's");

  assert.deepEqual(await walk([]), [work], "no label: the pruned folders are not entered");
  // A folder label inside ~/Library: that folder is walked, in ~/Library's
  // turn (so its repositories come before shallower ones found later), the
  // rest of ~/Library (and ~/Music) is not; a trailing slash is the same
  // folder.
  assert.deepEqual(await walk([cloud]), [icloud, work]);
  assert.deepEqual(await walk([`${cloud}/`]), [icloud, work]);
  assert.deepEqual(await walk([cloud, icloud]), [icloud, work], "nested labels: the outer one walks, the repository found once");
  // A pattern whose literal prefix is the folder, inside it, above it, or
  // none: the whole folder is walked (~/Music only when the pattern can
  // match there).
  assert.deepEqual((await walk([`${home}/Library/**/id_rsa`])).sort(), library);
  assert.deepEqual((await walk([`${cloud}/**/*.pem`])).sort(), library);
  assert.deepEqual((await walk([`${home}/**/id_rsa`])).sort(), all);
  assert.deepEqual((await walk(["**/*.pem"])).sort(), all);
  // A label on the pruned folder itself, or on HOME: walked as on Linux.
  assert.deepEqual((await walk([join(home, "Library")])).sort(), library);
  assert.deepEqual((await walk([home])).sort(), all);
  // Lifts nothing: a labelled FILE (its repository is the label source's),
  // a label or a pattern elsewhere, a folder reached only through a
  // directory link, a labelled folder below the depth cap.
  assert.deepEqual(await walk([join(icloud, "deploy", "id_rsa")]), [work]);
  assert.deepEqual(await walk([join(home, "work"), `${home}/work/**/*.pem`, "/srv/**/*.pem"]), [work]);
  assert.deepEqual(await walk([join(home, "Library", "cloud-link")]), [work], "a directory link is never followed");
  assert.deepEqual(await walk([cloud], "darwin", { maxDepth: 2 }), [work], "below the depth cap (the folder is 3 below HOME)");
  // Linux: no prune, so labels change nothing.
  assert.deepEqual((await walk([], "linux")).sort(), all);
  assert.deepEqual((await walk([cloud], "linux")).sort(), all);
});
