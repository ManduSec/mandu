/**
 * paths-command e2e — `mandu paths` and the folder rows of `mandu doctor`
 * through the real CLI entry (docs/design/architecture/on-disk-layout.md §3, §5), on a
 * temporary HOME:
 *   - a home with loose modes: both name them with the chmod fix, `--json`
 *     parses and agrees with the text;
 *   - a home with nothing yet: both say so;
 *   - neither creates or re-modes a file, and neither prints a file's
 *     contents: the report names places, never what is in them.
 * No arbiter is started (the socket points nowhere); the axis is stated per
 * the suite rule.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { runCli } from "../lib/run-cli.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // no arbiter here; stated per the suite rule

const SECRET = "PATHS-E2E-SECRET-VALUE";

function put(root: string, rel: string, mode: number, body = SECRET): void {
  const p = join(root, rel.replace(/\/$/, ""));
  mkdirSync(rel.endsWith("/") ? p : dirname(p), { recursive: true });
  if (!rel.endsWith("/")) writeFileSync(p, body);
  chmodSync(p, mode);
}

/** Every path under `root` with its mode, to prove nothing changed. */
function snapshot(root: string): string[] {
  const out: string[] = [];
  const walk = (d: string): void => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      out.push(`${p.slice(root.length)} ${(statSync(p).mode & 0o7777).toString(8)}`);
      if (e.isDirectory()) walk(p);
    }
  };
  walk(root);
  return out.sort();
}

test("mandu paths / doctor on a home with loose modes: named with the fix, --json agrees, nothing touched or printed", { timeout: 180_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-paths-e2e-"));
  const home = join(dir, "home");
  put(home, ".mandu/", 0o755);
  put(home, ".mandu/config.toml", 0o600);
  put(home, ".mandu/state/", 0o700);
  put(home, ".mandu/state/mandu.db", 0o644);
  put(home, ".mandu/events/", 0o700);
  put(home, ".mandu/events/s1.ndjson", 0o600);
  const env = { HOME: home, XDG_RUNTIME_DIR: join(dir, "run"), MANDU_ARBITER_SOCK: join(dir, "absent.sock") };
  const before = snapshot(dir);
  try {
    const text = await runCli(["paths"], env);
    assert.equal(text.code, 0, text.stderr);
    assert.match(text.stdout, /^Where Mandu keeps its files/);
    assert.ok(text.stdout.includes("Mandu's folder: ~/.mandu"), text.stdout);
    assert.match(text.stdout, /\(!\) Other users on this machine can open these/);
    assert.match(text.stdout, /~\/\.mandu\/state\/mandu\.db +0644 \(Mandu sets 0600\) \(!\)/);
    assert.match(text.stdout, /~\/\.mandu\/events +0700 /);

    const json = await runCli(["paths", "--json"], env);
    assert.equal(json.code, 0, json.stderr);
    const j = JSON.parse(json.stdout) as { home: string; paths: { name: string; mode: string | null; loose: boolean }[] };
    assert.equal(j.home, `${home}/.mandu`);
    assert.deepEqual(j.paths.filter((p) => p.loose).map((p) => [p.name, p.mode]), [["mandu-home", "0755"], ["symbol-db", "0644"]]);

    const doctor = await runCli(["doctor"], env);
    assert.equal(doctor.code, 0, doctor.stderr);
    assert.ok(doctor.stdout.includes("chmod 700 ~/.mandu\n"), doctor.stdout);
    assert.ok(doctor.stdout.includes("chmod 600 ~/.mandu/state/mandu.db"), doctor.stdout);

    for (const r of [text, json, doctor]) assert.ok(!r.stdout.includes(SECRET) && !r.stderr.includes(SECRET), "a place is named, never its contents");
    assert.deepEqual(snapshot(dir), before, "paths and doctor only look: nothing created or re-moded");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("mandu paths / doctor on a home with nothing yet: they say so and create nothing", { timeout: 180_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-paths-e2e-"));
  const home = join(dir, "home");
  mkdirSync(home);
  const env = { HOME: home, XDG_RUNTIME_DIR: join(dir, "run"), MANDU_ARBITER_SOCK: join(dir, "absent.sock") };
  try {
    const r = await runCli(["paths"], env);
    assert.equal(r.code, 0, r.stderr);
    assert.doesNotMatch(r.stdout, /\(!\)/);
    assert.match(r.stdout, /~\/\.mandu +not there yet /);

    const doctor = await runCli(["doctor"], env);
    assert.equal(doctor.code, 0, doctor.stderr);
    assert.match(doctor.stdout, /~\/\.mandu does not exist yet: the first launch creates it/);
    assert.ok(!existsSync(join(home, ".mandu")), "neither creates the folder");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
