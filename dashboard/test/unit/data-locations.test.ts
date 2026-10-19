/**
 * data-locations.test — the product page's "Where your data lives" projection
 * (src/data-locations.ts, GET /api/data-locations; on-disk-layout.md §9.2).
 *
 * Over a temporary HOME + MANDU_HOME: owner-only stores read `ownerOnly: true`,
 * a store opened to others reads false, missing locations are listed as not
 * there, the home is spelled `~`, a symlink reads its target's mode (a
 * dangling one is there but broken, as in `mandu paths`), and the rows
 * and their plain words match `mandu paths` (launcher/src/paths-command.ts,
 * read as text: the packages are standalone). Each row says whether only
 * Mandu's own developers use it (`developer`, dashboard.md §4.25q), and the
 * set of those places cannot drift from the table's descriptions.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { buildDataLocations, DEVELOPER_LOCATIONS, LOCATION_DESCRIPTIONS, tilde, type DataLocation } from "../../src/data-locations.js";
import { MANDU_PATHS } from "../../src/generated/mandu-paths.js";
import { tmpDir } from "./tmp-dir.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

function withHome(fn: (home: string, mandu: string) => void): void {
  const home = tmpDir("mdu-dataloc-");
  try {
    fn(home, join(home, ".mandu"));
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

const byName = (rows: DataLocation[], name: string): DataLocation => {
  const r = rows.find((x) => x.name === name);
  assert.ok(r, `row ${name}`);
  return r;
};

test("owner-only stores read ownerOnly true; a store at 0755 reads false; missing ones are listed as not there", () => {
  withHome((home, mandu) => {
    mkdirSync(join(mandu, "state"), { recursive: true, mode: 0o700 });
    chmodSync(mandu, 0o700);
    chmodSync(join(mandu, "state"), 0o700);
    mkdirSync(join(mandu, "events"), { mode: 0o755 });
    chmodSync(join(mandu, "events"), 0o755); // the umask must not decide the test
    writeFileSync(join(mandu, "policy.yaml"), "secret: value-that-must-not-leak\n", { mode: 0o600 });
    const env = { HOME: home };
    const d = buildDataLocations(env, home);

    assert.equal(d.home, "~/.mandu", "Mandu's folder, the home spelled ~");
    const homeRow = byName(d.locations, "mandu-home");
    assert.deepEqual(
      { path: homeRow.path, where: homeRow.where, exists: homeRow.exists, mode: homeRow.mode, ownerOnly: homeRow.ownerOnly },
      { path: "~/.mandu", where: "home", exists: true, mode: "0700", ownerOnly: true },
    );
    assert.equal(byName(d.locations, "state-root").ownerOnly, true);
    assert.equal(byName(d.locations, "policy").mode, "0600");
    assert.equal(byName(d.locations, "policy").ownerOnly, true);

    const events = byName(d.locations, "events");
    assert.equal(events.mode, "0755");
    assert.equal(events.ownerOnly, false, "group/other bits on a store the agent may not read: not owner-only");

    const packs = byName(d.locations, "packs");
    assert.deepEqual({ exists: packs.exists, mode: packs.mode, ownerOnly: packs.ownerOnly }, { exists: false, mode: null, ownerOnly: null });

    for (const r of d.locations) {
      if (r.where === "home") assert.ok(r.path.startsWith("~/.mandu"), r.path);
      assert.equal(r.holds, LOCATION_DESCRIPTIONS[r.name]);
    }
    // Only locations: no file content is ever in the response.
    assert.doesNotMatch(JSON.stringify(d), /value-that-must-not-leak/);
  });
});

test("MANDU_HOME moves Mandu's folder; the runtime dir and the install stay outside and carry no owner-only verdict", () => {
  withHome((home) => {
    const mandu = join(home, "elsewhere", "mh");
    mkdirSync(mandu, { recursive: true, mode: 0o700 });
    chmodSync(mandu, 0o700);
    const rt = join(home, "run");
    mkdirSync(join(rt, "mandu"), { recursive: true, mode: 0o700 });
    const d = buildDataLocations({ HOME: home, MANDU_HOME: mandu, MANDU_RUNTIME_DIR: join(rt, "mandu") }, home);
    assert.equal(d.home, "~/elsewhere/mh");
    assert.equal(byName(d.locations, "symbol-db").path, "~/elsewhere/mh/state/mandu.db");
    const runtime = byName(d.locations, "runtime-dir");
    assert.equal(runtime.where, "outside");
    assert.equal(runtime.exists, true);
    assert.equal(runtime.ownerOnly, null, "the table lets the agent read it: no owner-only verdict");
    assert.equal(byName(d.locations, "bin-dir").path, "~/.local/bin");
    assert.equal(byName(d.locations, "bin-dir").ownerOnly, null);
  });
});

test("a path outside the home is shown as it is; the home alone is ~", () => {
  assert.equal(tilde("/srv/mandu", "/home/u"), "/srv/mandu");
  assert.equal(tilde("/home/u", "/home/u"), "~");
  assert.equal(tilde("/home/user2/x", "/home/u"), "/home/user2/x", "a sibling home with the same prefix is not ~");
  assert.equal(tilde("/x", "/"), "/x");
});

test("a symlinked store reads its target's mode (as `mandu paths` does); a dangling link is there but broken", () => {
  withHome((home) => {
    // A symlinked ~/.mandu → a 0700 dir: the target's badge.
    const real = join(home, "real-mandu");
    mkdirSync(real, { mode: 0o700 });
    chmodSync(real, 0o700);
    symlinkSync(real, join(home, ".mandu"));
    // A link to a 0755 dir: open to others, like the target.
    const open = join(home, "open");
    mkdirSync(open, { mode: 0o755 });
    chmodSync(open, 0o755);
    symlinkSync(open, join(real, "events"));
    // A dangling link.
    symlinkSync(join(home, "gone"), join(real, "packs"));
    const rows = buildDataLocations({ HOME: home }, home).locations;
    const at = (n: string) => { const r = byName(rows, n); return { exists: r.exists, brokenLink: r.brokenLink, mode: r.mode, ownerOnly: r.ownerOnly }; };
    assert.deepEqual(at("mandu-home"), { exists: true, brokenLink: false, mode: "0700", ownerOnly: true });
    assert.equal(byName(rows, "mandu-home").path, "~/.mandu", "the link's own path is shown, not the target's");
    assert.deepEqual(at("events"), { exists: true, brokenLink: false, mode: "0755", ownerOnly: false });
    // on-disk-layout.md §5 "A broken link": the same rule as `mandu paths`
    // (launcher/test/unit/paths-command.test.ts pins its side).
    assert.deepEqual(at("packs"), { exists: true, brokenLink: true, mode: null, ownerOnly: null });
    assert.deepEqual(at("pack-keys"), { exists: false, brokenLink: false, mode: null, ownerOnly: null }, "nothing at all: not there");
  });
});

test("rows: the table's order, each path once (config-root and view-state repeat the home and state/)", () => {
  withHome((home) => {
    const names = buildDataLocations({ HOME: home }, home).locations.map((r) => r.name);
    const expected = (Object.keys(MANDU_PATHS) as (keyof typeof MANDU_PATHS)[]).filter((n) => n !== "config-root" && n !== "view-state");
    assert.deepEqual(names, expected);
  });
});

test("parity with `mandu paths`: the same names and the same plain words as launcher/src/paths-command.ts", () => {
  const src = readFileSync(join(REPO, "launcher", "src", "paths-command.ts"), "utf8");
  const block = src.match(/PATH_DESCRIPTIONS[^=]*=\s*\{([\s\S]*?)\n\};/);
  assert.ok(block, "PATH_DESCRIPTIONS found in paths-command.ts");
  const launcher = [...block[1]!.matchAll(/^\s*"([a-z0-9-]+)":\s*"((?:[^"\\]|\\.)*)",?\s*$/gm)].map((m) => [m[1]!, m[2]!] as const);
  assert.ok(launcher.length > 10, "parsed the launcher's rows");
  assert.deepEqual(
    Object.entries(LOCATION_DESCRIPTIONS),
    launcher.map(([k, v]) => [k, v]),
    "the dashboard's copy of the descriptions drifted from `mandu paths`; mirror paths-command.ts",
  );
});

test("developer: true exactly for DEVELOPER_LOCATIONS, there or not", () => {
  withHome((home, mandu) => {
    mkdirSync(join(mandu, "dev"), { recursive: true });
    const rows = buildDataLocations({ HOME: home }, home).locations;
    for (const r of rows) assert.equal(r.developer, DEVELOPER_LOCATIONS.has(r.name), r.name);
    assert.deepEqual({ developer: byName(rows, "dev-root").developer, exists: byName(rows, "dev-root").exists }, { developer: true, exists: true });
    assert.deepEqual({ developer: byName(rows, "runs-root").developer, exists: byName(rows, "runs-root").exists }, { developer: true, exists: false });
    assert.equal(byName(rows, "symbol-db").developer, false);
    assert.equal(byName(rows, "runtime-dir").developer, false);
    assert.equal(rows.filter((r) => r.developer).length, DEVELOPER_LOCATIONS.size, "every developer place is a row");
  });
});

test("DEVELOPER_LOCATIONS cannot drift: exactly the places whose words say (developers) or Mandu's own tests, and dev-root", () => {
  const byWords = Object.entries(LOCATION_DESCRIPTIONS)
    .filter(([name, words]) => name === "dev-root" || /\(developers\)|Mandu's own tests/.test(words))
    .map(([name]) => name)
    .sort();
  assert.deepEqual([...DEVELOPER_LOCATIONS].sort(), byWords, "a developer-only path must be in DEVELOPER_LOCATIONS (and only those), or it shows on the product page");
});

test("the plain words use the product vocabulary only", () => {
  const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter|symbol)\b|\$MDU:/i;
  for (const [name, words] of Object.entries(LOCATION_DESCRIPTIONS)) assert.doesNotMatch(words, FORBIDDEN, name);
});

test("the runtime dir row is the runtime-base rule's (the same as `mandu paths`): a TMPDIR too long for a socket lists /tmp/mandu-<uid>", () => {
  const uid = process.getuid?.();
  if (uid === undefined) return;
  const rows = buildDataLocations({ HOME: "/h", TMPDIR: "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/", MANDU_RUNTIME_FALLBACK_ROOT: "/fb" }, "/h", () => null, () => false).locations;
  assert.equal(byName(rows, "runtime-dir").path, `/fb/mandu-${uid}`);
});
