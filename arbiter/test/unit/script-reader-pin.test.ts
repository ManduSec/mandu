/**
 * script-reader-pin — confidentiality plan 13 §9 R5, the `(interpreter,
 * script)` reader pin, as pure decisions (flow-taint.ts, the validator,
 * policyDelta).
 *
 * Before R5 a reader entry named a program by its executable (and hash,
 * D8); an interpreter (python, node, a shell, perl) named that way admits any
 * code the agent hands it, so its output could never be cleared
 * (`readerOutputRefusal`). R5 lets an entry name the script too:
 * `{ app: python3, script: /opt/tools/report.py }`. It matches only an opener
 * the guard reports running exactly that file, out of the agent's reach,
 * isolated from per-user code and not traced; it may carry `output:`; and
 * its first use pins the interpreter and the script's hash. A bare
 * interpreter entry admits nothing (plan 13 §8 decision (b), 2026-10-02; the
 * test marked DECISION failed on the code before it). Each assertion marked
 * NEW failed on the code before R5 (the entry had no `script:` and the
 * validator refused the key).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  decideOpen, entryAdmitsNothing, inlineCodeProblem, matchReader, parseScriptFacts, readerOutputRefusal, readerOutputRule, scriptFactsProblem,
  scriptInterpreterFamily, withPinnedReader, type OpenerFacts, type ReaderEntry, type ScriptFacts,
} from "../../policy/flow-taint.js";
import { compilePolicy, relaxationsOf } from "../../policy/compiled-policy.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { isTightening, policyDelta } from "../../policy/policy-delta.js";
import { policyWarnings, validatePolicyDocument } from "../../policy/policy-file-validate.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const PY = "/usr/bin/python3.12";
const PY_SHA = "a".repeat(64);
const SCRIPT = "/opt/tools/report.py";
const S_SHA = "b".repeat(64);
const FILE = "/home/u/.pgpass";

const facts = (over: Partial<ScriptFacts> = {}): ScriptFacts => ({ path: SCRIPT, sha256: S_SHA, system: true, isolated: true, traced: false, ...over });
const opener = (over: Partial<OpenerFacts> = {}): OpenerFacts => ({ exe: PY, sha256: PY_SHA, exeSystem: true, loaderEnv: [], script: facts(), ...over });
// The human wrote the pair by hand and vouches for it (plan 13 D8 (12)).
const entry = { app: "python3", script: SCRIPT, output: "clear" as const, prints: "nothing" as const };

test("the families a script pin applies to; ruby is not one", () => {
  assert.equal(scriptInterpreterFamily("python3"), "python");
  assert.equal(scriptInterpreterFamily("python3.12"), "python");
  assert.equal(scriptInterpreterFamily("node"), "node");
  assert.equal(scriptInterpreterFamily("bash"), "shell");
  assert.equal(scriptInterpreterFamily("perl"), "perl");
  assert.equal(scriptInterpreterFamily("ruby"), null);
  assert.equal(scriptInterpreterFamily("env"), null);
  assert.equal(scriptInterpreterFamily("psql"), null);
});

test("NEW: a script entry matches the pair the guard reports, and pins the script's hash on first use", () => {
  const m = matchReader([entry], opener());
  assert.ok(m, "python3 running the pinned script is the reader");
  assert.equal(m!.pin.script, SCRIPT);
  assert.equal(m!.pinNeeded, true, "the interpreter by name: its path and hash are pinned on first use (a system binary)");
  assert.equal(m!.scriptPinNeeded, true, "and the script's hash");
  const d = decideOpen(FILE, { readers: [entry] }, opener());
  assert.equal(d.verdict, "raw");
  assert.equal(d.pinNeeded, true);
  assert.match(d.why, /python3 running \/opt\/tools\/report\.py/);
  // fully pinned: nothing more to write
  const pinned = { ...entry, path: PY, sha256: PY_SHA, scriptSha256: S_SHA };
  const m2 = matchReader([pinned], opener());
  assert.deepEqual([m2?.pinNeeded, m2?.scriptPinNeeded], [false, undefined]);
});

test("NEW: fail-closed: every fact the pin rests on, absent or wrong, is no reader", () => {
  const cases: Array<[string, OpenerFacts]> = [
    ["no script facts (an older guard, the data socket)", opener({ script: undefined })],
    ["inline code (python -c)", opener({ script: undefined, scriptProblem: "inline code (python -c)" })],
    ["another script", opener({ script: facts({ path: "/opt/tools/other.py" }) })],
    ["a workspace copy (agent-writable)", opener({ script: facts({ path: SCRIPT, system: false }) })],
    ["not isolated from the user site-packages", opener({ script: facts({ isolated: false }) })],
    ["traced by another process", opener({ script: facts({ traced: true }) })],
    ["unreadable hash", opener({ script: facts({ sha256: undefined }) })],
  ];
  for (const [why, o] of cases) {
    assert.equal(matchReader([entry], o), null, why);
    assert.equal(decideOpen(FILE, { readers: [entry] }, o).verdict, "deny", `${why}: a listed file refuses a non-reader`);
    assert.notEqual(scriptFactsProblem(entry, o), null, why);
  }
  // a changed script: the hash pinned before no longer matches
  assert.equal(matchReader([{ ...entry, scriptSha256: "c".repeat(64) }], opener()), null, "a rebuilt script must be re-pinned");
  // a loader / interpreter variable the launch did not give (D8)
  assert.equal(decideOpen(FILE, { readers: [entry] }, opener({ loaderEnv: ["PYTHONPATH"] })).verdict, "deny");
  // the interpreter by name only from a binary out of the agent's reach (D8)
  assert.notEqual(decideOpen(FILE, { readers: [entry] }, opener({ exe: "/home/u/venv/bin/python3", exeSystem: false })).verdict, "raw");
  // a `from:` condition still needs a trusted parent
  assert.equal(matchReader([{ ...entry, from: "make" }], opener({ ancestors: [{ exe: "/home/u/ws/make", trusted: false }] })), null);
  assert.ok(matchReader([{ ...entry, from: "make" }], opener({ ancestors: [{ exe: "/usr/bin/make", trusted: true }] })));
  // a script entry on an interpreter that cannot carry one matches nothing
  assert.equal(matchReader([{ app: "ruby", script: "/opt/tools/r.rb" }], opener({ exe: "/usr/bin/ruby", script: facts({ path: "/opt/tools/r.rb" }) })), null);
  // the agent's own process is never a reader
  assert.equal(decideOpen(FILE, { readers: [entry] }, opener({ isAgent: true })).verdict, "twin");
});

test("DECISION (b): a bare interpreter entry admits nothing, inline code included; only the script pin clears an interpreter (plan 13 §8, 2026-10-02)", () => {
  const inline = opener({ script: undefined, scriptProblem: "inline code (python -c)" });
  // Each of these matched before the decision (a bare name, or the
  // interpreter pinned by path and hash, named the binary).
  const bare: ReaderEntry[] = ["python3", { app: "python3", path: PY, sha256: PY_SHA }, { app: "python3.12" }, { app: "mytool", path: PY, sha256: PY_SHA }];
  for (const e of bare) {
    assert.equal(matchReader([e], inline), null, `${JSON.stringify(e)}: inline code`);
    assert.equal(matchReader([e], opener()), null, `${JSON.stringify(e)}: not even a script every R5 check passes (it is not the one pinned)`);
    assert.equal(entryAdmitsNothing(e), true, JSON.stringify(e));
  }
  for (const [what, o] of [
    ["python -c", inline],
    ["stdin", opener({ script: undefined, scriptProblem: "standard input" })],
    ["a module (-m)", opener({ script: undefined, scriptProblem: "a module (python -m)" })],
    ["an agent-writable script", opener({ script: facts({ path: "/home/u/ws/x.py", system: false }) })],
    ["no facts at all", opener({ script: undefined })],
    ["bash -c '. .env'", { exe: "/usr/bin/bash", sha256: PY_SHA, exeSystem: true, loaderEnv: [], scriptProblem: "inline code (sh -c)" } as OpenerFacts],
    ["ruby (no script pin exists)", { exe: "/usr/bin/ruby", sha256: PY_SHA, exeSystem: true, loaderEnv: [] } as OpenerFacts],
  ] as ReadonlyArray<readonly [string, OpenerFacts]>) {
    assert.notEqual(inlineCodeProblem(o), null, what);
    for (const ask of ["known", "always", "never"] as const) {
      const d = decideOpen(FILE, { readers: ["python3", "bash", "ruby", { app: "python3", path: PY, sha256: PY_SHA }] }, o, { ask });
      assert.equal(d.verdict, "deny", `${what} (${ask}): ${d.why}`);
      assert.match(d.why, /pinned script/, what);
      assert.equal(decideOpen(FILE, { readers: ["python3", "bash", "ruby"], others: "twin" }, o, { ask }).verdict, "twin", `${what}: others: twin`);
      assert.equal(decideOpen(FILE, {}, o, { ask }).verdict, "twin", `${what}: no list`);
    }
  }
  // the script pin still clears the pair; a bare entry beside it changes nothing
  assert.equal(matchReader(["python3", entry], opener())!.pin.script, SCRIPT);
  assert.equal(decideOpen(FILE, { readers: ["python3", entry] }, opener()).verdict, "raw");
  assert.equal(inlineCodeProblem(opener()), null, "a script every R5 check passes");
  assert.equal(inlineCodeProblem({ exe: "/usr/bin/ssh-add", loaderEnv: [] }), null, "a leaf program is not concerned");
  assert.equal(entryAdmitsNothing("ssh-add"), false);
  assert.equal(entryAdmitsNothing(entry), false);
});

test("NEW: output: a script entry may be cleared; a bare interpreter still may not", () => {
  assert.equal(readerOutputRefusal("python3", "clear", SCRIPT), null);
  assert.notEqual(readerOutputRefusal("python3", "clear"), null);
  assert.notEqual(readerOutputRefusal("ruby", "clear", "/opt/x.rb"), null, "no family, no exemption");
  assert.notEqual(readerOutputRefusal("env", "clear", "/opt/x"), null);
});

test("NEW: the fold: a script row is cleared only by the entry naming its script, and only when it started no other program", () => {
  const row = { path: FILE, app: "python3.12", exe: PY, sha256: PY_SHA, via: "reader" as const, script: SCRIPT, scriptSha256: S_SHA };
  assert.equal(readerOutputRule({ ...row, spawned: false }, [entry]).output, "clear");
  assert.equal(readerOutputRule({ ...row, spawned: true }, [entry]).output, "secret", "it ran another program (a PATH the agent can write)");
  assert.equal(readerOutputRule(row, [entry]).output, "secret", "unknown counts as started");
  assert.equal(readerOutputRule({ ...row, spawned: false, script: "/opt/tools/other.py" }, [entry]).output, "secret", "another script");
  assert.equal(readerOutputRule({ ...row, spawned: false, script: undefined }, [entry]).output, "secret", "a row with no script facts (-c, an older guard)");
  assert.equal(readerOutputRule({ ...row, spawned: false, scriptSha256: "c".repeat(64) }, [{ ...entry, scriptSha256: S_SHA }]).output, "secret", "a changed script");
  assert.equal(readerOutputRule({ ...row, spawned: false, via: "verdict" }, [entry]).output, "secret", "an Inbox approval promised a masked output");
  // a bare python3 entry beside it does not mask the pinned pair's row, and
  // clears nothing on its own
  assert.equal(readerOutputRule({ ...row, spawned: false }, ["python3", entry]).output, "clear");
  assert.equal(readerOutputRule({ ...row, spawned: false, script: undefined }, [{ app: "python3", output: "clear" }]).output, "secret");
  // mask keeps its spans
  assert.deepEqual(readerOutputRule({ ...row, spawned: false }, [{ app: "python3", script: SCRIPT, output: "mask", mask: ["pw=\\S+"] }]), { app: "python3.12", output: "mask", mask: ["pw=\\S+"] });
});

test("NEW: withPinnedReader: the script entry takes the interpreter's pin and the script's hash, keeping its output", () => {
  const readers: ReaderEntry[] = ["psql", entry];
  const pin = { app: "python3", path: PY, sha256: PY_SHA, script: SCRIPT, scriptSha256: S_SHA };
  const out = withPinnedReader(readers, pin, { system: true })!;
  assert.deepEqual(out, ["psql", { ...pin, output: "clear", prints: "nothing" }], "the human's word stays on the pin (D8 (12))");
  assert.equal(withPinnedReader(out, pin, { system: true }), null, "already pinned: nothing to write");
  // an interpreter the agent could have written (approved elsewhere): the
  // pin is appended without the output, the entry stays
  const appended = withPinnedReader(readers, pin, { system: false })!;
  assert.deepEqual(appended, ["psql", entry, pin]);
  // the human pinned that interpreter by path and hash: output kept
  const human = withPinnedReader([{ ...entry, path: PY, sha256: PY_SHA }], pin, { system: false })!;
  assert.deepEqual(human, [{ ...pin, output: "clear", prints: "nothing" }]);
  // a bare interpreter entry is never replaced by a script pin
  assert.deepEqual(withPinnedReader(["python3"], pin, { system: true }), ["python3", pin]);
});

test("parseScriptFacts: malformed facts are absent", () => {
  assert.deepEqual(parseScriptFacts({ path: SCRIPT, sha256: S_SHA.toUpperCase(), system: true, isolated: true, traced: false }), facts());
  for (const bad of [null, "x", { path: "rel.py", system: true, isolated: true, traced: false }, { path: SCRIPT, system: "yes", isolated: true, traced: false }, { path: SCRIPT, system: true, isolated: true }]) {
    assert.equal(parseScriptFacts(bad), undefined, JSON.stringify(bad));
  }
});

const doc = (readers: unknown[]): PolicyFileConfig => ({ version: 1, paths: [{ path: FILE, level: "no-model", readers }] } as unknown as PolicyFileConfig);

test("NEW: the validator: script entries, their form, their family, and their output", () => {
  assert.deepEqual(validatePolicyDocument(doc([entry])), []);
  assert.deepEqual(validatePolicyDocument(doc([{ ...entry, scriptSha256: S_SHA, path: PY, sha256: PY_SHA }])), []);
  const errs = (r: unknown) => validatePolicyDocument(doc([r])).join("\n");
  assert.match(errs({ app: "python3", script: "report.py" }), /script: must be the script's absolute path/);
  assert.match(errs({ app: "python3", script: "/opt/../opt/r.py" }), /absolute path/);
  assert.match(errs({ app: "python3", script: "/opt//r.py" }), /absolute path/);
  assert.match(errs({ app: "ruby", script: "/opt/r.rb" }), /ruby loads code from the user's gem directory/);
  assert.match(errs({ app: "env", script: "/opt/r" }), /env is not one/);
  assert.match(errs({ app: "python3", scriptSha256: S_SHA }), /only meaningful with script/);
  assert.match(errs({ app: "python3", script: SCRIPT, scriptSha256: "xyz" }), /64 hex/);
  assert.match(errs({ app: "python3", output: "clear" }), /runs any code it is given/, "a bare interpreter is still refused output");
  // ssh_agent readers take no script
  assert.match(validatePolicyDocument({ version: 1, ssh_agent: { readers: [{ app: "bash", script: SCRIPT }] } } as unknown as PolicyFileConfig).join("\n"), /script/);
  // warnings: none for the pair, still one for a bare interpreter, which now names the pin
  assert.deepEqual(policyWarnings(doc([entry])), []);
  assert.match(policyWarnings(doc(["python3"])).join("\n"), /pin it with the interpreter \(\{ app: python3, script:/);
  assert.doesNotMatch(policyWarnings(doc(["env"])).join("\n"), /pin it with the interpreter/);
});

const SILENT = { info: () => {}, warn: () => {} };
const compiled = (d: PolicyFileConfig) => compilePolicy({ specId: "claude-code", document: d, log: SILENT });

test("NEW: policyDelta and relaxationsOf: a script entry is a relaxation; lowering its output alone tightens", () => {
  const none = doc(["psql"]);
  const pair = doc(["psql", { app: "python3", script: SCRIPT }]);
  const cleared = doc(["psql", { app: "python3", script: SCRIPT, output: "clear" }]);
  assert.equal(isTightening(policyDelta(compiled(none), compiled(pair))), false, "a new reader (the pair) is a relaxation");
  assert.equal(isTightening(policyDelta(compiled(pair), compiled(cleared))), false, "raising its output relaxes");
  assert.equal(isTightening(policyDelta(compiled(cleared), compiled(pair))), true, "lowering it back, nothing else changed, tightens");
  assert.equal(isTightening(policyDelta(compiled(pair), compiled(doc(["psql", { app: "python3", script: "/opt/tools/other.py" }])))), false, "another script is another reader");
  const r = relaxationsOf(compiled(cleared)).filter((x) => x.kind === "app-output");
  assert.equal(r.length, 1);
  assert.match(r[0]!.detail, /python3 running \/opt\/tools\/report\.py's output is shown to the model in the clear/);
});
