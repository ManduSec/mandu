/**
 * D (2026-10-17, confidentiality.md §6 "Read by a program the launch did not
 * see") over the REAL ArbiterServer:
 *
 *   (a) `discoverSecrets` walks the human labels' places as roots of their
 *       own: a labelled folder outside the launch's roots is in the report;
 *   (b) a label set mid-session (a dashboard act) registers the files
 *       already under it, so their values are known secrets (the value
 *       backstop masks a program's print of them) with no launch walk;
 *   (c) the same for a pattern label a policy.yaml edit adds mid-session;
 *   (d) a `public` label, a lowered one and the axis OFF register nothing.
 *
 * Before the change (b) and (c) left the files unregistered until the next
 * launch, and (a) did not list the folder.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // explicit below: confidentiality ON, integrity OFF; (d) turns the axis OFF by name

const PLAN = ["PLAN", "LABEL", "SET", "MID", "SESSION", "5e1f"].join("-");

function rig(opts: { confidentiality?: boolean; policy?: string } = {}): { dir: string; home: string; out: string; server: ArbiterServer; policy: string } {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-label-set-")));
  const home = join(dir, "home");
  const out = join(dir, "outside");
  mkdirSync(home, { recursive: true });
  for (const d of ["vault/sub", "notes", "open"]) mkdirSync(join(out, d), { recursive: true });
  writeFileSync(join(out, "vault", "plan.md"), `password: ${PLAN}\n`);
  writeFileSync(join(out, "vault", "sub", "deeper.md"), `password: ${PLAN}-2\n`);
  writeFileSync(join(out, "notes", "plan.md"), `password: ${PLAN}-3\n`);
  writeFileSync(join(out, "notes", "readme.txt"), "hello\n");
  writeFileSync(join(out, "open", "plan.md"), `password: ${PLAN}-4\n`);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, opts.policy ?? "version: 1\n");
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: opts.confidentiality ?? true, integrity: false, policyPath: policy, policyPollMs: 50,
  });
  return { dir, home, out, server, policy };
}

const registered = (server: ArbiterServer): string[] => {
  const r = server.dispatch({ id: 9, op: "secretRegistry" } as never) as { ok: true; result: { entries: Array<{ path: string }> } };
  return [...new Set(r.result.entries.map((e) => e.path))];
};
const setLabel = (server: ArbiterServer, path: string, confidentiality: string): void => {
  const r = server.dispatch({ id: 1, op: "setPathLabel", path, confidentiality } as never) as { ok: boolean; error?: string };
  assert.ok(r.ok, r.error);
};

test("(a) discoverSecrets: a labelled folder outside the launch's roots is walked as a root of its own", async () => {
  const { dir, home, out, server } = rig();
  await server.listen();
  try {
    setLabel(server, join(out, "vault"), "no-model");
    const r = server.dispatch({ id: 2, op: "discoverSecrets", roots: [home], home } as never) as { ok: true; result: { files: Array<{ path: string }>; limits: { maxLabelFiles?: number } } };
    const paths = r.result.files.map((f) => f.path);
    assert.ok(paths.includes(join(out, "vault", "plan.md")), paths.join(" "));
    assert.ok(paths.includes(join(out, "vault", "sub", "deeper.md")));
    assert.ok(!paths.includes(join(out, "open", "plan.md")), "an unlabelled folder beside it is not");
    assert.equal(typeof r.result.limits.maxLabelFiles, "number");
  } finally {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("(b) a label set mid-session registers the files already under it (bounded walk), no launch needed", async () => {
  const { dir, out, server } = rig();
  await server.listen();
  try {
    await server.labelRegistrationsSettled();
    assert.deepEqual(registered(server), [], "nothing registered at start");
    setLabel(server, join(out, "vault"), "no-model");
    await server.labelRegistrationsSettled();
    const reg = registered(server);
    assert.ok(reg.includes(join(out, "vault", "plan.md")), reg.join(" "));
    assert.ok(reg.includes(join(out, "vault", "sub", "deeper.md")));
    assert.ok(!reg.includes(join(out, "open", "plan.md")), "only the labelled folder's files");
    // (That a print of the value is then masked at the model is the stack
    // test's to show: tests/stack/labelled-recursive-read.test.ts.)
  } finally {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("(c) a pattern label added by a policy.yaml edit mid-session registers only the files it matches", async () => {
  const { dir, out, server, policy } = rig();
  await server.listen();
  try {
    await server.labelRegistrationsSettled();
    writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(out, "notes")}/*.md\n    level: no-model\n`);
    const deadline = Date.now() + 10_000;
    let reg: string[] = [];
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 100));
      await server.labelRegistrationsSettled();
      reg = registered(server);
      if (reg.length > 0) break;
    }
    assert.ok(reg.includes(join(out, "notes", "plan.md")), reg.join(" "));
    assert.ok(!reg.includes(join(out, "notes", "readme.txt")), "a file the pattern does not match is not registered");
  } finally {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("(d) a public label registers nothing, nor does any label with the confidentiality axis OFF", async () => {
  {
    const { dir, out, server } = rig();
    await server.listen();
    try {
      setLabel(server, join(out, "open"), "public");
      await server.labelRegistrationsSettled();
      assert.deepEqual(registered(server), []);
    } finally {
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  }
  {
    const { dir, out, server } = rig({ confidentiality: false });
    await server.listen();
    try {
      setLabel(server, join(out, "vault"), "no-model");
      await server.labelRegistrationsSettled();
      assert.deepEqual(registered(server), []);
    } finally {
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  }
});
