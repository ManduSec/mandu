/**
 * supervisor-checkout-bundle.test — in a checkout the supervisor starts each
 * service from the checkout's prebuilt bundle only while that bundle is
 * fresh, else from source as one node process (packaging.md §5.1;
 * dashboard.md §4.8 "How a service is started").
 *
 *   - the choice is made at EVERY spawn: a bundle fresh at the first start
 *     and stale at a restart is not started again (the dashboard is
 *     resident; it outlives builds);
 *   - fresh → the bundled form's command, cwd and env (over the definition's
 *     own); stale → the source form, and the log names why;
 *   - a definition without a bundled form (installed, a test) is never asked
 *     about;
 *   - checkoutBundleFresh is the launcher's own build-record rule
 *     (launcher/scripts/bundle-stamp.mjs, loaded from the checkout): a clean
 *     record over unchanged inputs is fresh; an input changed since, no
 *     record, or no checkout script at all is stale.
 *
 * Fake services (node one-liners) stand in for the real ones; the real
 * proxies through the real bundle: tests/stack/supervisor-checkout-bundle.test.ts.
 * Axes: none (process control only; no arbiter decision is taken).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, utimesSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type { ServiceDefinition } from "../../../src/supervisor/supervisor.js";
import { checkoutBundleFresh, type BundleFreshness } from "../../../src/supervisor/supervisor-defs.js";
import { mkSup, nodeArgs, registerTmpHooks, tmpdir, waitForLog } from "./supervisor-harness.js";

registerTmpHooks();

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");

/** Listens on FAKE_SOCK and says which form it is (FAKE_FORM) and its cwd. */
const FORM_SCRIPT = `
const net = require('net');
const fs = require('fs');
try { fs.unlinkSync(process.env.FAKE_SOCK); } catch {}
net.createServer(() => {}).listen(process.env.FAKE_SOCK, () => {
  process.stdout.write('form=' + process.env.FAKE_FORM + ' cwd=' + process.cwd() + ' base=' + process.env.FAKE_BASE + '\\n');
});
setInterval(() => {}, 1e9);
`;

function twoForms(): { def: ServiceDefinition; sock: string; srcDir: string; binDir: string } {
  const dir = tmpdir();
  const srcDir = join(dir, "src");
  const binDir = join(dir, "dist");
  mkdirSync(srcDir);
  mkdirSync(binDir);
  const sock = join(dir, "svc.sock");
  const def: ServiceDefinition = {
    label: "Fake (two forms)",
    command: process.execPath,
    args: nodeArgs(FORM_SCRIPT),
    cwd: srcDir,
    env: { FAKE_SOCK: sock, FAKE_FORM: "source", FAKE_BASE: "kept" },
    ready: { kind: "socket", path: sock },
    endpoint: sock,
    checkoutBundle: {
      command: process.execPath, args: nodeArgs(FORM_SCRIPT), cwd: binDir,
      env: { FAKE_FORM: "bundle" }, distDir: join(dir, "launcher-dist"), repoRoot: dir,
    },
  };
  return { def, sock, srcDir, binDir };
}

test("fresh: the bundled form runs (its command, cwd and env over the definition's); a restart asks again and a stale bundle is not started", async () => {
  const f = twoForms();
  const verdicts: BundleFreshness[] = [{ fresh: true }, { fresh: false, reason: "launcher/src/run.ts changed since the build" }];
  const asked: Array<[string, string]> = [];
  const logs: string[] = [];
  const sup = mkSup({ arbiter: f.def }, {
    log: (m) => logs.push(m),
    bundleFresh: async (dist, repo) => { asked.push([dist, repo]); return verdicts.shift() ?? { fresh: true }; },
  });
  try {
    await sup.start("arbiter");
    await waitForLog(sup, "arbiter", (l) => l.startsWith("form="));
    const first = sup.logs("arbiter").find((l) => l.line.startsWith("form="))!.line;
    assert.equal(first, `form=bundle cwd=${f.binDir} base=kept`, "the bundle, in its cwd, with the definition's env underneath");
    assert.deepEqual(asked, [[f.def.checkoutBundle!.distDir, f.def.checkoutBundle!.repoRoot]]);
    assert.ok(logs.some((m) => m.includes("starting from the checkout's bundle")), logs.join("\n"));

    await sup.restart("arbiter");
    await waitForLog(sup, "arbiter", (l) => l.startsWith("form=source"));
    assert.equal(asked.length, 2, "asked again at the restart");
    assert.ok(sup.logs("arbiter").some((l) => l.line === `form=source cwd=${f.srcDir} base=kept`));
    assert.ok(logs.some((m) => /starting from source \(the bundle in .* is not used: launcher\/src\/run\.ts changed since the build\)/.test(m)), logs.join("\n"));
  } finally {
    await sup.shutdownAll();
  }
});

test("a definition without a bundled form (installed, a test's) is spawned as is and the record is never read", async () => {
  const f = twoForms();
  delete f.def.checkoutBundle;
  let asked = 0;
  const sup = mkSup({ arbiter: f.def }, { bundleFresh: async () => { asked++; return { fresh: true }; } });
  try {
    await sup.start("arbiter");
    await waitForLog(sup, "arbiter", (l) => l.startsWith("form="));
    assert.ok(sup.logs("arbiter").some((l) => l.line.startsWith("form=source")));
    assert.equal(asked, 0);
  } finally {
    await sup.shutdownAll();
  }
});

test("checkoutBundleFresh is the launcher's build-record check: fresh over unchanged inputs; a changed input, no record or no checkout script is stale", async () => {
  const repo = tmpdir();
  const dist = join(repo, "launcher", "dist");
  mkdirSync(join(repo, "launcher", "scripts"), { recursive: true });
  mkdirSync(join(repo, "launcher", "src"), { recursive: true });
  mkdirSync(dist);
  copyFileSync(join(REPO, "launcher", "scripts", "bundle-stamp.mjs"), join(repo, "launcher", "scripts", "bundle-stamp.mjs"));
  const input = join(repo, "launcher", "src", "run.ts");
  writeFileSync(input, "export {};\n");
  const past = new Date(Date.now() - 60_000);
  utimesSync(input, past, past);
  writeFileSync(join(dist, "net-proxy.mjs"), "// built\n");

  const none = await checkoutBundleFresh(dist, repo);
  assert.equal(none.fresh, false, "no record: stale");

  const stamp = (await import(join(repo, "launcher", "scripts", "bundle-stamp.mjs"))) as {
    writeStamp: (d: string, o: { repoRoot: string; inputs: string[]; outputs: string[]; startMs: number }) => string | null;
  };
  assert.equal(stamp.writeStamp(dist, { repoRoot: repo, inputs: ["launcher/src/run.ts"], outputs: ["net-proxy.mjs"], startMs: Date.now() }), null);
  assert.deepEqual(await checkoutBundleFresh(dist, repo), { fresh: true });

  const other = await checkoutBundleFresh(dist, join(repo, "launcher"));
  assert.equal(other.fresh, false, "a record must name the repository asked about");

  writeFileSync(input, "export const edited = 1;\n");
  const edited = await checkoutBundleFresh(dist, repo);
  assert.equal(edited.fresh, false);
  assert.match((edited as { reason: string }).reason, /launcher\/src\/run\.ts changed since the build/);

  const noScript = await checkoutBundleFresh(dist, tmpdir());
  assert.equal(noScript.fresh, false, "no checkout script: stale, never a throw");
  assert.match((noScript as { reason: string }).reason, /could not be checked/);
});
