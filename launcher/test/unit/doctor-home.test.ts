/**
 * doctor-home.test — the `mandu doctor` rows about Mandu's folder
 * (docs/design/architecture/on-disk-layout.md §3): loose modes with the chmod fix.
 * Temporary HOMEs only.
 * No arbiter here; the axis is stated per the suite rule.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { gatherHomeFacts, homeRows } from "../../src/doctor-home.js";
import { realPathsDeps } from "../../src/paths-command.js";
import { gatherFacts, renderDoctor, type DoctorDeps, type DoctorFacts } from "../../src/doctor.js";
import { Layout } from "../../src/services/layout.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // no arbiter here; stated per the suite rule

function put(root: string, rel: string, mode: number): string {
  const p = join(root, rel.replace(/\/$/, ""));
  mkdirSync(rel.endsWith("/") ? p : dirname(p), { recursive: true });
  if (!rel.endsWith("/")) writeFileSync(p, "x");
  chmodSync(p, mode);
  return p;
}

function tempHome(): { home: string; env: Record<string, string>; rm(): void } {
  const home = mkdtempSync(join(tmpdir(), "mandu-doc-home-"));
  return { home, env: { HOME: home, XDG_RUNTIME_DIR: join(home, "run") }, rm: () => rmSync(home, { recursive: true, force: true }) };
}

function newHome(home: string): void {
  put(home, ".mandu/", 0o700);
  put(home, ".mandu/config.toml", 0o600);
  put(home, ".mandu/state/", 0o700);
  put(home, ".mandu/state/mandu.db", 0o600);
  put(home, ".mandu/events/", 0o700);
}

const rowsFor = (env: Record<string, string>, home: string): string => homeRows(gatherHomeFacts(env, home, realPathsDeps)).join("\n");

test("an owner-only folder: one OK row", () => {
  const h = tempHome();
  try {
    newHome(h.home);
    assert.equal(rowsFor(h.env, h.home), "  ✓ ~/.mandu: only you can open it");
  } finally {
    h.rm();
  }
});

// on-disk-layout.md §5 "A broken link": there, but Mandu cannot use it.
test("a broken link: named with its fix; a broken home is no \"only you\"", () => {
  const h = tempHome();
  try {
    newHome(h.home);
    symlinkSync(join(h.home, "gone"), join(h.home, ".mandu", "packs"));
    const rows = rowsFor(h.env, h.home);
    assert.match(rows, /✓ ~\/\.mandu: only you can open it/);
    assert.match(rows, /✗ this is a link to something that is not there; Mandu cannot use it:\n +~\/\.mandu\/packs\n +fix: /);
    rmSync(join(h.home, ".mandu"), { recursive: true, force: true });
    symlinkSync(join(h.home, "unmounted"), join(h.home, ".mandu"));
    const home = rowsFor(h.env, h.home);
    assert.doesNotMatch(home, /only you can open it|does not exist yet/);
    assert.match(home, /✗ this is a link to something that is not there[^\n]*\n +~\/\.mandu\n/);
  } finally {
    h.rm();
  }
});

test("no folder yet: the first launch creates it", () => {
  const h = tempHome();
  try {
    assert.match(rowsFor(h.env, h.home), /does not exist yet: the first launch creates it/);
  } finally {
    h.rm();
  }
});

test("(a) the folder, state/, events/ and the database files open to others: named, with the chmod fix", () => {
  const h = tempHome();
  try {
    newHome(h.home);
    chmodSync(join(h.home, ".mandu"), 0o755);
    chmodSync(join(h.home, ".mandu/state"), 0o750);
    chmodSync(join(h.home, ".mandu/events"), 0o777);
    chmodSync(join(h.home, ".mandu/state/mandu.db"), 0o644);
    put(h.home, ".mandu/state/mandu.db-wal", 0o640);
    put(h.home, ".mandu/state/mandu.db.owner", 0o664);
    const f = gatherHomeFacts(h.env, h.home, realPathsDeps);
    const m = join(h.home, ".mandu");
    assert.deepEqual(f.loose.map((l) => [l.path, l.mode]), [
      [m, 0o755], [`${m}/state`, 0o750], [`${m}/state/mandu.db`, 0o644], [`${m}/events`, 0o777], [`${m}/state/mandu.db-wal`, 0o640],
      [`${m}/state/mandu.db.owner`, 0o664],
    ]);
    const text = homeRows(f).join("\n");
    assert.match(text, /✗ other users on this machine can open these; only you should:/);
    assert.match(text, /~\/\.mandu\/events \(0777\)/);
    assert.ok(text.includes("chmod 700 ~/.mandu ~/.mandu/state ~/.mandu/events\n"), text);
    assert.ok(text.includes("chmod 600 ~/.mandu/state/mandu.db ~/.mandu/state/mandu.db-wal ~/.mandu/state/mandu.db.owner"), text);
    assert.doesNotMatch(text, /✓/);
  } finally {
    h.rm();
  }
});

test("files in the places older versions used are not Mandu's: no row names them", () => {
  const h = tempHome();
  try {
    newHome(h.home);
    put(h.home, ".config/mandu/config.toml", 0o644);
    put(h.home, ".local/state/mandu/events/", 0o755);
    put(h.home, ".cache/mandu/notes.txt", 0o644);
    assert.equal(rowsFor(h.env, h.home), "  ✓ ~/.mandu: only you can open it");
  } finally {
    h.rm();
  }
});

test("doctor: the folder section is rendered from gathered facts; a fixture without the probe reports none", async () => {
  const h = tempHome();
  try {
    newHome(h.home);
    chmodSync(join(h.home, ".mandu/events"), 0o755);
    const base: DoctorDeps = {
      nodeVersion: () => "22.22.1",
      gitVersion: () => "2.50.1",
      commandExists: () => false,
      socketReachable: async () => false,
      fileExists: () => false,
      platform: () => "linux",
      usernsOk: () => true,
      readKnob: () => null,
      nativeBin: () => null,
    };
    const layout = Layout.detect(new URL("../../src/run.ts", import.meta.url).href, {});
    const without = await gatherFacts(h.env, layout, base);
    assert.equal(without.home, undefined);
    assert.doesNotMatch(renderDoctor(without), /Mandu's folder/);

    const facts: DoctorFacts = await gatherFacts(h.env, layout, { ...base, homeFacts: (env) => gatherHomeFacts(env, h.home, realPathsDeps) });
    const out = renderDoctor(facts);
    assert.match(out, /Mandu's folder \(`mandu paths` lists everything in it\)/);
    assert.ok(out.includes("chmod 700 ~/.mandu/events"), out);
  } finally {
    h.rm();
  }
});
