/**
 * bwrap-path.test — which bubblewrap Mandu runs when it runs the
 * distribution's (src/bwrap-path.ts; rootless-confinement-ubuntu-2404.md §0.7,
 * decision A): the first `bwrap` on PATH outside the current directory, by
 * real path, never one planted in the workspace; an administrator's
 * `bwrap_path` in its place, honoured only when root's alone.
 *
 * Pure over injected facts, plus the real filesystem with planted fakes
 * (none of them ever runs: the resolver only stats).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  adminBwrap,
  adminBwrapLine,
  findBwrapOnPath,
  insideDir,
  systemBwrap,
  type BwrapStat,
} from "../../src/bwrap-path.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // no axis is read; the bubblewrap the confidentiality layers run

const exe = (paths: string[]) => (p: string): boolean => paths.includes(p);
const ident = (links: Record<string, string> = {}) => (p: string): string | null => links[p] ?? p;

test("insideDir: component-wise, and `/` contains nothing", () => {
  assert.ok(insideDir("/ws", "/ws"));
  assert.ok(insideDir("/ws/bin", "/ws"));
  assert.ok(insideDir("/ws/bin", "/ws/"));
  assert.ok(!insideDir("/wsx/bin", "/ws"));
  assert.ok(!insideDir("/usr/bin", "/"), "a cwd of / would exclude every binary");
});

test("findBwrapOnPath: relative, empty and inside-the-cwd entries are skipped; the answer is the real path", () => {
  const files = ["/ws/bwrap", "/ws/bin/bwrap", "/ws/node_modules/.bin/bwrap", "/usr/bin/bwrap", "/usr/local/bin/bwrap"];
  const find = (path: string, links: Record<string, string> = {}): string | null =>
    findBwrapOnPath({ path, cwd: "/ws", executable: exe(files), realpath: ident(links) });
  assert.equal(find(".:/usr/bin"), "/usr/bin/bwrap", "`.` is the cwd");
  assert.equal(find(":/usr/bin"), "/usr/bin/bwrap", "an empty entry is the cwd");
  assert.equal(find("bin:node_modules/.bin:/usr/bin"), "/usr/bin/bwrap", "relative entries");
  assert.equal(find("/ws/bin:/ws/node_modules/.bin:/usr/bin"), "/usr/bin/bwrap", "absolute entries inside the cwd");
  assert.equal(find("/usr/local/bin:/usr/bin"), "/usr/local/bin/bwrap", "the first outside wins");
  // A directory outside that resolves inside (a symlinked dir), and a binary
  // outside that is a link into the workspace: both by real path.
  assert.equal(find("/opt/tools:/usr/bin", { "/opt/tools": "/ws/bin" }), "/usr/bin/bwrap");
  assert.equal(find("/usr/local/bin:/usr/bin", { "/usr/local/bin/bwrap": "/ws/bwrap" }), "/usr/bin/bwrap");
  // A cwd reached through a link: its real path is excluded too.
  assert.equal(findBwrapOnPath({ path: "/real/ws/bin:/usr/bin", cwd: "/link/ws", executable: exe(["/real/ws/bin/bwrap", "/usr/bin/bwrap"]), realpath: ident({ "/link/ws": "/real/ws" }) }), "/usr/bin/bwrap");
  assert.equal(find(".:/ws/bin"), null, "only planted ones: none, never a bare `bwrap`");
  assert.equal(find(""), null);
});

test("findBwrapOnPath on the real filesystem: a planted ./bwrap and a workspace bin/ are never chosen", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "mdu-bwrap-path-")));
  try {
    const ws = join(root, "ws");
    const sys = join(root, "sys");
    for (const d of [join(ws, "bin"), join(ws, "node_modules", ".bin"), sys, join(root, "tools")]) mkdirSync(d, { recursive: true });
    for (const f of [join(ws, "bwrap"), join(ws, "bin", "bwrap"), join(ws, "node_modules", ".bin", "bwrap"), join(sys, "bwrap")]) {
      writeFileSync(f, "#!/bin/sh\nexit 0\n");
      chmodSync(f, 0o755);
    }
    symlinkSync(join(ws, "bwrap"), join(root, "tools", "bwrap"));
    const path = [".", "", "bin", join(ws, "bin"), join(ws, "node_modules", ".bin"), join(root, "tools"), sys].join(":");
    assert.equal(findBwrapOnPath({ path, cwd: ws }), join(sys, "bwrap"));
    assert.equal(findBwrapOnPath({ path: [".", join(ws, "bin"), join(root, "tools")].join(":"), cwd: ws }), null);
    // A non-executable file is not a bubblewrap.
    chmodSync(join(sys, "bwrap"), 0o644);
    assert.equal(findBwrapOnPath({ path: `${sys}`, cwd: ws }), null);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ── the administrator's bwrap_path ───────────────────────────────────────────

test("adminBwrapLine: one plain absolute path on its line; anything else is unreadable", () => {
  assert.deepEqual(adminBwrapLine("models: []\n"), { kind: "absent" });
  assert.deepEqual(adminBwrapLine("bwrap_path: /opt/bw/bin/bwrap\n"), { kind: "path", path: "/opt/bw/bin/bwrap" });
  assert.deepEqual(adminBwrapLine('bwrap_path: "/opt/bw/bin/bwrap"  # pinned 0.12\n'), { kind: "path", path: "/opt/bw/bin/bwrap" });
  assert.deepEqual(adminBwrapLine("bwrap_path: '/opt/bw/bin/bwrap'\r\n"), { kind: "path", path: "/opt/bw/bin/bwrap" });
  for (const bad of ["bwrap_path: bwrap\n", "bwrap_path: >-\n  /opt/bw\n", "bwrap_path: /opt/../tmp/bwrap\n", "bwrap_path:\n", "bwrap_path: /opt/my bwrap\n"]) {
    assert.deepEqual(adminBwrapLine(bad), { kind: "unreadable" }, bad);
  }
  assert.deepEqual(adminBwrapLine("  bwrap_path: /x\n"), { kind: "absent" }, "only a top-level key");
});

function adminHost(o: { files: Record<string, string>; stats?: Record<string, BwrapStat | null>; links?: Record<string, string> }) {
  const root = (isFile: boolean): BwrapStat => ({ uid: 0, mode: isFile ? 0o100755 : 0o40755, isFile, isDir: !isFile });
  const stats: Record<string, BwrapStat | null> = {
    "/": root(false), "/etc": root(false), "/etc/mandu": root(false), "/etc/mandu/policy.d": root(false),
    "/opt": root(false), "/opt/bw": root(false), "/opt/bw/bwrap": root(true), "/usr": root(false), "/usr/bin": root(false), "/usr/bin/bwrap": root(true),
    ...Object.fromEntries(Object.keys(o.files).map((f) => [`/etc/mandu/policy.d/${f}`, { uid: 0, mode: 0o100644, isFile: true, isDir: false }])),
    ...o.stats,
  };
  return {
    adminDir: "/etc/mandu/policy.d",
    listDir: (d: string) => (d === "/etc/mandu/policy.d" ? Object.keys(o.files) : null),
    readText: (p: string) => o.files[p.slice("/etc/mandu/policy.d/".length)] ?? null,
    stat: (p: string) => (p in stats ? stats[p]! : null),
    realpath: (p: string) => o.links?.[p] ?? (p in stats ? p : null),
    path: "/usr/bin",
    cwd: "/ws",
    executable: (p: string) => p === "/usr/bin/bwrap",
  };
}

test("adminBwrap: a root-owned file naming a root-owned binary is used; none set falls to PATH", () => {
  const h = adminHost({ files: { "10-corp.yaml": "models: []\nbwrap_path: /opt/bw/bwrap\n" } });
  assert.deepEqual(adminBwrap(h), { kind: "path", path: "/opt/bw/bwrap", file: "/etc/mandu/policy.d/10-corp.yaml" });
  assert.deepEqual(systemBwrap(h), { bin: "/opt/bw/bwrap", source: "admin" });
  const none = adminHost({ files: { "10-corp.yaml": "models: []\n" } });
  assert.deepEqual(adminBwrap(none), { kind: "none" });
  assert.deepEqual(systemBwrap(none), { bin: "/usr/bin/bwrap", source: "path" });
  // No directory at all: no administrator.
  assert.deepEqual(adminBwrap({ ...none, listDir: () => null }), { kind: "none" });
  // The last file in name order wins.
  const two = adminHost({ files: { "10.yaml": "bwrap_path: /usr/bin/bwrap\n", "20.yaml": "bwrap_path: /opt/bw/bwrap\n" } });
  assert.equal(systemBwrap(two).bin, "/opt/bw/bwrap");
});

test("adminBwrap: set but unusable means NO bubblewrap with the reason, never the PATH one in its place", () => {
  const cases: Array<[string, ReturnType<typeof adminHost>, RegExp]> = [
    ["missing binary", adminHost({ files: { "a.yaml": "bwrap_path: /opt/bw/missing\n" } }), /does not exist/],
    ["binary not root's", adminHost({ files: { "a.yaml": "bwrap_path: /opt/bw/bwrap\n" }, stats: { "/opt/bw/bwrap": { uid: 1000, mode: 0o100755, isFile: true, isDir: false } } }), /is not root's alone/],
    ["directory writable by others", adminHost({ files: { "a.yaml": "bwrap_path: /opt/bw/bwrap\n" }, stats: { "/opt/bw": { uid: 0, mode: 0o40777, isFile: false, isDir: true } } }), /is not root's alone/],
    ["a link out to a user's binary", adminHost({ files: { "a.yaml": "bwrap_path: /opt/bw/bwrap\n" }, links: { "/opt/bw/bwrap": "/home/u/bwrap" }, stats: { "/home": { uid: 0, mode: 0o40755, isFile: false, isDir: true }, "/home/u": { uid: 1000, mode: 0o40755, isFile: false, isDir: true }, "/home/u/bwrap": { uid: 1000, mode: 0o100755, isFile: true, isDir: false } } }), /is not root's alone/],
    ["unreadable value", adminHost({ files: { "a.yaml": "bwrap_path: >-\n  /opt/bw/bwrap\n" } }), /not one absolute path on its line/],
  ];
  for (const [what, h, why] of cases) {
    const a = adminBwrap(h);
    assert.equal(a.kind, "refused", what);
    assert.match((a as { why: string }).why, why, what);
    const s = systemBwrap(h);
    assert.equal(s.bin, null, `${what}: no other bubblewrap in its place`);
    assert.match(s.refused ?? "", why, what);
  }
});

test("adminBwrap: a file someone other than root could write is ignored (the PATH answer stands)", () => {
  const userFile = adminHost({ files: { "a.yaml": "bwrap_path: /opt/bw/bwrap\n" }, stats: { "/etc/mandu/policy.d/a.yaml": { uid: 1000, mode: 0o100644, isFile: true, isDir: false } } });
  assert.deepEqual(adminBwrap(userFile), { kind: "none" });
  assert.deepEqual(systemBwrap(userFile), { bin: "/usr/bin/bwrap", source: "path" });
  const openDir = adminHost({ files: { "a.yaml": "bwrap_path: /opt/bw/bwrap\n" }, stats: { "/etc/mandu/policy.d": { uid: 0, mode: 0o40777, isFile: false, isDir: true } } });
  assert.deepEqual(adminBwrap(openDir), { kind: "none" });
});

test("the real resolver (the administrator's directory, this process's PATH) answers an absolute path or nothing", () => {
  // Smoke: the real resolver answers without throwing, absolute or nothing.
  const s = systemBwrap();
  assert.ok(s.bin === null || s.bin.startsWith("/"), JSON.stringify(s));
});
