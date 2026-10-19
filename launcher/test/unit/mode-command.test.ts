/**
 * mode-command — `mandu mode [name]` (protection-modes.md §3.2).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { runMode as runModeIn, downgradeLines, type ModeCommandDeps } from "../../src/mode-command.js";
import { hermetic } from "../lib/test-runtime.js";
import { applyModeEdit } from "../../src/config-edit.js";
import { DEFAULT_MODE } from "../../src/mode.js";

/** runMode with this file's own runtime dir when the user env names none (test-runtime.ts). */
const runMode = hermetic(hermetic(runModeIn, 1), 2);

function rig(opts: { file?: string | null; running?: { integrity?: boolean; confidentiality?: boolean } | null }) {
  const state = { file: opts.file ?? null, out: [] as string[], err: [] as string[] };
  const deps: ModeCommandDeps = {
    readAxes: async () => opts.running ?? {},
    sockExists: () => opts.running !== null && opts.running !== undefined,
    readFile: () => state.file,
    writeMode: (_p, m) => { state.file = applyModeEdit(state.file ?? "", m); },
    out: (l) => state.out.push(l),
    err: (l) => state.err.push(l),
  };
  return { state, deps };
}
const env = { MANDU_HOME: "/x", MANDU_ARBITER_SOCK: "/x/arbiter.sock" };

test("no argument: prints running and saved, then the product modes and the frozen line", async () => {
  const { state, deps } = rig({ file: `mode = "full"\n`, running: { integrity: false, confidentiality: true } });
  assert.equal(await runMode([], env, env, deps), 0);
  const text = state.out.join("\n");
  assert.match(text, /^running: secrets/m);
  assert.match(text, /^saved: {3}full/m);
  assert.match(text, /mandu stop/, "running differs from saved ⇒ says how to apply");
  for (const m of ["secrets", "off"]) assert.match(text, new RegExp(`^  ${m} `, "m"));
  for (const m of ["injection", "full"]) assert.doesNotMatch(text, new RegExp(`^  ${m} `, "m"));
  assert.match(text, /^  \(frozen: injection, full; need MANDU_EXPERIMENTAL_INTEGRITY=1\)$/m);
  // The saved mode is a frozen one: a launch would refuse it, so the listing says so.
  assert.match(text, /^warning: the saved mode full is frozen; a launch refuses it \(docs\/design\/architecture\/protection-modes\.md\)/m);
});

test("no argument: a frozen saved mode gets no warning with the opt-in, a product one never does", async () => {
  const frozen = rig({ file: `mode = "injection"\n`, running: null });
  const optIn = { ...env, MANDU_EXPERIMENTAL_INTEGRITY: "1" };
  assert.equal(await runMode([], optIn, optIn, frozen.deps), 0);
  assert.doesNotMatch(frozen.state.out.join("\n"), /is frozen/);
  const product = rig({ file: `mode = "secrets"\n`, running: null });
  assert.equal(await runMode([], env, env, product.deps), 0);
  assert.doesNotMatch(product.state.out.join("\n"), /is frozen/);
});

test("frozen integrity: `mandu mode full|injection` without the opt-in exits 2 and leaves the config untouched", async () => {
  for (const m of ["full", "injection", "FULL"]) {
    const before = "proxy-port = 0\nmode = \"secrets\"\n";
    const { state, deps } = rig({ file: before, running: null });
    for (const e of [env, { ...env, MANDU_EXPERIMENTAL_INTEGRITY: "0" }, { ...env, MANDU_EXPERIMENTAL_INTEGRITY: "" }]) {
      assert.equal(await runMode([m], e, e, deps), 2, m);
      assert.equal(state.file, before, `config untouched: ${m}`);
      assert.deepEqual(state.out, [], `nothing claims a save: ${m}`);
      const err = state.err.join("\n");
      assert.match(err, /is frozen \(docs\/design\/architecture\/protection-modes\.md\)/);
      assert.match(err, /MANDU_EXPERIMENTAL_INTEGRITY=1/);
      assert.match(err, new RegExp(`\`mandu mode ${m.toLowerCase()}\``));
    }
  }
});

test("frozen integrity: `mandu mode full` with the opt-in saves it", async () => {
  const { state, deps } = rig({ file: "proxy-port = 0\n", running: null });
  const optIn = { ...env, MANDU_EXPERIMENTAL_INTEGRITY: "1" };
  assert.equal(await runMode(["full"], optIn, optIn, deps), 0);
  assert.match(state.file!, /^mode = "full"$/m);
  assert.match(state.out.join("\n"), /saved mode full/);
  assert.deepEqual(state.err, []);
});

test("the product modes save without any opt-in", async () => {
  for (const m of ["secrets", "off"]) {
    const { state, deps } = rig({ file: "", running: null });
    assert.equal(await runMode([m], env, env, deps), 0, m);
    assert.match(state.file!, new RegExp(`^mode = "${m}"$`, "m"));
  }
});

test("no argument, nothing saved and nothing running: the built-in default, said as such", async () => {
  const { state, deps } = rig({ file: null, running: null });
  assert.equal(await runMode([], env, env, deps), 0);
  assert.match(state.out.join("\n"), /^running: nothing running$/m);
  assert.match(state.out.join("\n"), new RegExp(`^saved: {3}${DEFAULT_MODE}  \\(nothing saved: the built-in default\\)`, "m"));
});

test("legacy axis keys without a mode key still read as a named mode", async () => {
  const { state, deps } = rig({ file: "confidentiality = true\nintegrity = false\n", running: null });
  await runMode([], env, env, deps);
  assert.match(state.out.join("\n"), /^saved: {3}secrets/m);
});

test("an exported variable is called out, because it beats the saved mode", async () => {
  const { state, deps } = rig({ file: null, running: null });
  await runMode([], env, { ...env, MANDU_MODE: "off" }, deps);
  assert.match(state.out.join("\n"), /MANDU_MODE is exported/);
});

test("with a name: writes through the surgical editor and says a restart is needed", async () => {
  const { state, deps } = rig({ file: "proxy-port = 0\nintegrity = true\n", running: { integrity: true, confidentiality: false } });
  assert.equal(await runMode(["secrets"], env, env, deps), 0);
  assert.match(state.file!, /^mode = "secrets"$/m);
  assert.match(state.file!, /^integrity = false$/m, "the stale axis line is re-aligned");
  assert.match(state.file!, /^proxy-port = 0$/m);
  const text = state.out.join("\n");
  assert.match(text, /saved mode secrets/);
  assert.match(text, /no longer covered: untrusted text/);
  assert.match(text, /still in mode injection/);
});

test("an unknown name is a usage error and writes nothing", async () => {
  const { state, deps } = rig({ file: "x = 1\n", running: null });
  assert.equal(await runMode(["standard"], env, env, deps), 2);
  assert.equal(state.file, "x = 1\n");
  assert.match(state.err.join("\n"), /unknown mode 'standard'/);
});

test("a bad mode value in the file is reported, not mapped", async () => {
  const { state, deps } = rig({ file: `mode = "standard"\n`, running: null });
  await runMode([], env, env, deps);
  assert.match(state.out.join("\n"), /mode = "standard", which is not a mode/);
});

test("downgradeLines names each axis that goes off, and nothing on an upgrade", () => {
  assert.equal(downgradeLines("full", "off").length, 2);
  assert.equal(downgradeLines("full", "secrets").length, 1);
  assert.equal(downgradeLines("secrets", "full").length, 0);
  assert.equal(downgradeLines("secrets", "injection").length, 1);
});
