/**
 * paths-command.test — `mandu paths` (docs/design/architecture/on-disk-layout.md §5):
 * every location of Mandu's folder in §3 order, what it holds, whether it
 * exists, its mode against the expected one, and the places outside the
 * folder. Most tests build a temporary HOME; one drives the report with fake
 * reads only.
 * No arbiter here; the axis is stated per the suite rule.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { MANDU_PATHS, type ManduPathName } from "../../src/generated/mandu-paths.js";
import {
  gatherPaths,
  PATH_DESCRIPTIONS,
  pathsJson,
  realPathsDeps,
  renderPaths,
  runPaths,
  shPath,
  shq,
  tilde,
  type PathsDeps,
} from "../../src/paths-command.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // no arbiter here; stated per the suite rule

/** Write `rel` under `root` with `mode` (a trailing / makes a directory). */
function put(root: string, rel: string, mode: number): string {
  const p = join(root, rel.replace(/\/$/, ""));
  mkdirSync(rel.endsWith("/") ? p : dirname(p), { recursive: true });
  if (!rel.endsWith("/")) writeFileSync(p, "x");
  chmodSync(p, mode);
  return p;
}

function tempHome(): { home: string; env: Record<string, string>; rm(): void } {
  const home = mkdtempSync(join(tmpdir(), "mandu-paths-"));
  // Only HOME and a runtime dir: no XDG root or override leaks in from the host.
  return { home, env: { HOME: home, XDG_RUNTIME_DIR: join(home, "run") }, rm: () => rmSync(home, { recursive: true, force: true }) };
}

/** An owner-only home. */
function newLayout(home: string): void {
  put(home, ".mandu/", 0o700);
  put(home, ".mandu/config.toml", 0o600);
  put(home, ".mandu/policy.yaml", 0o600);
  put(home, ".mandu/state/", 0o700);
  put(home, ".mandu/state/mandu.db", 0o600);
  put(home, ".mandu/events/", 0o700);
}

test("every table entry has a plain description", () => {
  assert.deepEqual(Object.keys(PATH_DESCRIPTIONS).sort(), Object.keys(MANDU_PATHS).sort());
  for (const [name, text] of Object.entries(PATH_DESCRIPTIONS)) {
    assert.ok(text.length > 5, name);
    assert.doesNotMatch(text, /symbol|arbiter|AgentView|T-LLM|shadow/i, `${name}: plain words only`);
  }
});

test("the rows follow the table's (§3) order, each path once, the home first and the outside places last", () => {
  const h = tempHome();
  try {
    const r = gatherPaths(h.env, h.home, realPathsDeps);
    const names = r.rows.map((x) => x.name);
    const tableOrder = (Object.keys(MANDU_PATHS) as ManduPathName[]).filter((n) => names.includes(n));
    assert.deepEqual(names, tableOrder);
    // config-root and view-state are the home and state/ under another name.
    assert.ok(!names.includes("config-root") && !names.includes("view-state"));
    assert.equal(new Set(r.rows.map((x) => x.path)).size, r.rows.length);
    assert.equal(r.rows[0]!.path, join(h.home, ".mandu"));
    assert.deepEqual(r.rows.filter((x) => x.where === "outside").map((x) => x.name), ["runtime-dir", "install-prefix", "exec-box-cache", "bin-dir"]);
    assert.ok(r.rows.filter((x) => x.where === "home").every((x) => x.path.startsWith(join(h.home, ".mandu"))));
    assert.equal(r.home, join(h.home, ".mandu"));
  } finally {
    h.rm();
  }
});

test("a loose home: flagged with the chmod fix, the report in plain words", () => {
  const h = tempHome();
  try {
    newLayout(h.home);
    chmodSync(join(h.home, ".mandu"), 0o755);
    const r = gatherPaths(h.env, h.home, realPathsDeps);
    const home = r.rows.find((x) => x.name === "mandu-home")!;
    assert.deepEqual([home.exists, home.mode, home.expectedMode, home.loose], [true, 0o755, 0o700, true]);
    const walks = r.rows.find((x) => x.name === "object-walks")!;
    assert.deepEqual([walks.exists, walks.mode], [false, null]);

    const text = renderPaths(r);
    assert.match(text, /^Where Mandu keeps its files/);
    assert.match(text, /~\/\.mandu +0755 \(Mandu sets 0700\) \(!\)/);
    assert.match(text, /Other users on this machine can open these/);
    assert.match(text, /chmod 700 ~\/\.mandu\n/);
    assert.ok(!text.includes(h.home), "paths under HOME are shown with ~");
    assert.match(text, /Outside Mandu's folder/);
    assert.match(text, /not there yet/);
  } finally {
    h.rm();
  }
});

test("an owner-only home: nothing flagged, and the places older versions used are not in the report", () => {
  const h = tempHome();
  try {
    newLayout(h.home);
    put(h.home, ".config/mandu/policy.yaml", 0o644);
    put(h.home, ".local/state/mandu/events/", 0o755);
    const r = gatherPaths(h.env, h.home, realPathsDeps);
    assert.ok(r.rows.every((x) => !x.loose));
    assert.ok(r.rows.every((x) => !/\/(\.config|\.local\/state|\.cache)\/mandu(\/|$)/.test(x.path)), "only the new layout");
    const text = renderPaths(r);
    assert.doesNotMatch(text, /\(!\)|Other users|older versions/);
    assert.match(text, /~\/\.mandu\/state\/mandu\.db +0600 +the placeholders/);
  } finally {
    h.rm();
  }
});

test("MANDU_HOME moves the whole folder", () => {
  const h = tempHome();
  try {
    const other = join(h.home, "elsewhere");
    const r = gatherPaths({ ...h.env, MANDU_HOME: other }, h.home, realPathsDeps);
    assert.equal(r.home, other);
    assert.equal(r.rows.find((x) => x.name === "symbol-db")!.path, join(other, "state", "mandu.db"));
  } finally {
    h.rm();
  }
});

test("pure with fake reads: stat and exists decide everything", () => {
  const modes: Record<string, number> = { "/h/.mandu": 0o700, "/h/.mandu/events": 0o750, "/h/.mandu/state": 0o700, "/h/.mandu/state/mandu.db": 0o600 };
  const deps: PathsDeps = {
    stat: (p) => (p in modes ? { mode: modes[p]! } : null),
    exists: (p) => p in modes,
  };
  const r = gatherPaths({ HOME: "/h", XDG_RUNTIME_DIR: "/run/user/1" }, "/h", deps);
  assert.deepEqual(r.rows.filter((x) => x.loose).map((x) => x.name), ["events"]);
  assert.equal(r.rows.find((x) => x.name === "runtime-dir")!.path, "/run/user/1/mandu");
  // The runtime dir may be readable by the agent; it is never flagged.
  modes["/run/user/1/mandu"] = 0o755;
  assert.equal(gatherPaths({ HOME: "/h", XDG_RUNTIME_DIR: "/run/user/1" }, "/h", deps).rows.find((x) => x.name === "runtime-dir")!.loose, false);
});

// on-disk-layout.md §5 "A broken link": a dangling symlink is there but
// broken, the same rule as the dashboard's "Where your data lives"
// (dashboard/test/unit/data-locations.test.ts pins its side).
test("a dangling symlink is there but broken: exists, no mode, said as a broken link", () => {
  const h = tempHome();
  try {
    newLayout(h.home);
    symlinkSync(join(h.home, "gone"), join(h.home, ".mandu", "packs"));
    const r = gatherPaths(h.env, h.home, realPathsDeps);
    const at = (n: ManduPathName) => { const x = r.rows.find((y) => y.name === n)!; return { exists: x.exists, brokenLink: x.brokenLink, mode: x.mode, loose: x.loose }; };
    assert.deepEqual(at("packs"), { exists: true, brokenLink: true, mode: null, loose: false });
    assert.deepEqual(at("pack-keys"), { exists: false, brokenLink: false, mode: null, loose: false }, "nothing at all: not there");
    assert.deepEqual(at("events"), { exists: true, brokenLink: false, mode: 0o700, loose: false });
    const text = renderPaths(r);
    assert.match(text, /~\/\.mandu\/packs +broken link +rule packs/);
    assert.match(text, /A broken link points at something that is not there/);
    const j = JSON.parse(pathsJson(r)) as { paths: { name: string; exists: boolean; brokenLink: boolean; mode: string | null }[] };
    const packs = j.paths.find((x) => x.name === "packs")!;
    assert.deepEqual([packs.exists, packs.brokenLink, packs.mode], [true, true, null]);
    // No broken link, no note.
    assert.doesNotMatch(renderPaths(gatherPaths({ ...h.env, HOME: join(h.home, "none") }, join(h.home, "none"), realPathsDeps)), /broken link/);
  } finally {
    h.rm();
  }
});

test("--json: the same report, modes as octal strings", () => {
  const h = tempHome();
  try {
    newLayout(h.home);
    chmodSync(join(h.home, ".mandu"), 0o755);
    let out = "";
    assert.equal(runPaths(["--json"], h.env, realPathsDeps, (s) => { out += s; }), 0);
    const j = JSON.parse(out) as {
      home: string;
      paths: { name: string; path: string; exists: boolean; brokenLink: boolean; mode: string | null; expectedMode: string | null; loose: boolean; holds: string; where: string }[];
    };
    assert.equal(j.home, join(h.home, ".mandu"));
    assert.deepEqual(j.paths[0], {
      name: "mandu-home", path: join(h.home, ".mandu"), where: "home", holds: PATH_DESCRIPTIONS["mandu-home"],
      exists: true, mode: "0755", brokenLink: false, expectedMode: "0700", loose: true,
    });
    assert.deepEqual(Object.keys(j), ["home", "paths"]);
    assert.equal(out, pathsJson(gatherPaths(h.env, h.home, realPathsDeps)));
  } finally {
    h.rm();
  }
});

test("an unknown option is refused; shq quotes only what needs it", () => {
  assert.equal(runPaths(["--bogus"], { HOME: "/nonexistent" }, realPathsDeps, () => {}), 2);
  assert.equal(shq("/home/u/.mandu"), "/home/u/.mandu");
  assert.equal(shq("/home/my user/.mandu"), "'/home/my user/.mandu'");
  assert.equal(shq("/a'b"), `'/a'\\''b'`);
  assert.equal(tilde("/home/u/.mandu", "/home/u"), "~/.mandu");
  assert.equal(tilde("/home/u", "/home/u"), "~");
  assert.equal(tilde("/home/uv/.mandu", "/home/u"), "/home/uv/.mandu");
  assert.equal(shPath("/home/u/my dir/x", "/home/u"), "~/'my dir/x'");
  assert.equal(shPath("/srv/my dir", "/home/u"), "'/srv/my dir'");
});

test("the runtime dir row is the runtime-base rule's: a TMPDIR too long for a socket (macOS) lists the private /tmp/mandu-<uid>", () => {
  const uid = process.getuid?.();
  if (uid === undefined) return;
  const env = { HOME: "/h", TMPDIR: "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/", MANDU_RUNTIME_FALLBACK_ROOT: "/fb" };
  const r = gatherPaths(env, "/h", { stat: () => null, exists: () => false });
  assert.equal(r.rows.find((x) => x.name === "runtime-dir")?.path, `/fb/mandu-${uid}`);
  const short = gatherPaths({ HOME: "/h", TMPDIR: "/t" }, "/h", { stat: () => null, exists: () => false });
  assert.equal(short.rows.find((x) => x.name === "runtime-dir")?.path, `/t/mandu-${uid}`, "a short TMPDIR: the per-user rule 3");
});
