/**
 * program-identity — P0 item 14 (2026-10-07; confidentiality plan 13 D8
 * (13)): programs known by name only. Each red on the code before:
 *
 *   (1) names: nushell's binary is `nu` (the list had only `nushell`), the
 *       public-domain ksh line ships as `oksh`, `loksh` and `pdksh`, and
 *       Racket's two builds install `racketbc` and `racketcs` beside
 *       `racket`: none ran code by name.
 *   (2) a printer or a launcher that is no byte-identical copy of an
 *       installed one (a non-identical GNU `env`, `cat` or `xargs` renamed
 *       `mytool`, pinned with the human's `prints: nothing`) was that pin's
 *       program: it read the secret raw. The guard now reads the
 *       executable's content for the package such programs share
 *       (reader_identity.rs `content_of`, `pkg:<package>`); the arbiter
 *       treats it as a printer: no reader in any form, never asked about,
 *       what a non-reader gets.
 *   (3) the interpreters the guard now knows by content (elvish, nushell,
 *       the dotnet muxer, Racket BC, julia before 1.6, the pdksh line) are
 *       refused as every `runs:` family is.
 *   (4) the policy rule list (the dashboard's "Your rules") had no readers
 *       in its snapshot, so the page judged a reader list by the names it
 *       mirrors; the snapshot now carries each path's readers and the
 *       arbiter's per-entry judgment (admits nothing, reads the twin, a
 *       copy of).
 *
 * Axes: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  addCodeRunnerHashes, argsCodeProblem, clearHostProgramHashesForTest, contentPackageOf, decideOpen, entryAdmitsNothing, inlineCodeProblem, loaderEnvProblem,
  matchReader, openerPrints, readerRunsCode, runtimeOf, verdictProgramOf,
} from "../../policy/flow-taint.js";
import { refreshProgramHashes } from "../../policy/program-hashes.js";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const sha = (b: string): string => createHash("sha256").update(b).digest("hex");
/** A GNU env of another version than the host's, renamed (no host hash). */
const ENVCOPY = sha("a GNU env 9.1 static build, renamed mytool");
const ENV = "/w/.env";
const PIN = { app: "mytool", path: "/home/u/bin/mytool", sha256: ENVCOPY, prints: "nothing" as const };

// ── (1) names ───────────────────────────────────────────────────────────────

test("(1) nushell's nu, the pdksh line and Racket's two builds run code by name; elvish, nushell and dotnet still do", () => {
  for (const name of ["nu", "oksh", "loksh", "pdksh", "racketbc", "racketcs", "elvish", "nushell", "dotnet", "/usr/bin/nu", "/usr/local/bin/oksh"]) {
    assert.ok(readerRunsCode(name), name);
    assert.equal(entryAdmitsNothing(name), true, name);
    const d = decideOpen(ENV, { readers: [name] }, { exe: name.startsWith("/") ? name : `/usr/bin/${name}`, sha256: sha(name), exeSystem: true, loaderEnv: [] }, { ask: "always" });
    assert.equal(d.verdict, "deny", `${name}: ${d.why}`);
  }
  // not caught by the new names: a word that only starts like one
  for (const n of ["nuke", "numfmt", "ksh-like", "racket-docs"]) assert.equal(readerRunsCode(n), false, n);
});

// ── (2) a printer's or a launcher's package by content ──────────────────────

test("(2) on the code before (no finding), a pinned non-identical GNU env, vouched for, read raw", () => {
  assert.equal(decideOpen(ENV, { readers: [PIN] }, { exe: PIN.path, sha256: ENVCOPY, exeSystem: false, loaderEnv: [] }).verdict, "raw");
});

test("(2) the guard's pkg: finding makes the opener a printer: no reader in any form, never a question, what a non-reader gets", () => {
  const opener = { exe: PIN.path, sha256: ENVCOPY, exeSystem: true, loaderEnv: ["pkg:coreutils"] };
  assert.equal(contentPackageOf(opener), "coreutils");
  assert.equal(openerPrints(opener), true);
  assert.equal(loaderEnvProblem(opener), null, "not a loader variable");
  assert.equal(argsCodeProblem(opener), null, "not code by argument: a printer");
  assert.equal(runtimeOf(opener), null);
  assert.equal(inlineCodeProblem(opener), null);
  assert.equal(verdictProgramOf(opener), undefined, "a write by it is keyed as any program's");
  assert.equal(matchReader([PIN], opener), null, "no entry names it");
  for (const ask of ["never", "known", "always"] as const) {
    const pinned = decideOpen(ENV, { readers: [PIN] }, opener, { ask });
    assert.equal(pinned.verdict, "deny", `${ask}: ${pinned.why}`);
    assert.match(pinned.why, /^mytool is, by its content, a program of GNU coreutils/);
    assert.equal(decideOpen(ENV, { readers: ["mytool"] }, opener, { ask }).verdict, "deny", ask);
    assert.equal(decideOpen(ENV, { readers: [PIN], others: "twin" }, opener, { ask }).verdict, "twin", ask);
    assert.equal(decideOpen(ENV, {}, opener, { ask }).verdict, "twin", `${ask}: no reader list`);
    // a known consumer's name buys nothing either
    assert.equal(decideOpen("/h/.ssh/id_ed25519", {}, { ...opener, exe: "/home/u/bin/ssh" }, { ask }).verdict, "twin", ask);
  }
  for (const [pkg, says] of [["findutils", "GNU findutils"], ["util-linux", "util-linux"], ["diffutils", "GNU diffutils"], ["sed", "GNU sed"], ["grep", "GNU grep"], ["tar", "GNU tar"], ["something-new", "something-new"]] as const) {
    const d = decideOpen(ENV, { readers: [PIN] }, { ...opener, loaderEnv: [`pkg:${pkg}`] });
    assert.equal(d.verdict, "deny", pkg);
    assert.match(d.why, new RegExp(`by its content, a program of ${says}`), pkg);
  }
});

test("(2) a clean leaf program is untouched", () => {
  const sum = { exe: "/usr/bin/gnusha256sum", sha256: sha("gnusha256sum"), exeSystem: true, loaderEnv: [] as string[] };
  assert.equal(contentPackageOf(sum), null);
  assert.equal(openerPrints(sum), false);
  assert.equal(decideOpen(ENV, { readers: [{ app: "gnusha256sum", prints: "nothing" }] }, sum).verdict, "raw");
});

// ── (3) the interpreters known by content since P0 item 14 ──────────────────

test("(3) elvish, nushell, the dotnet muxer, Racket BC, julia before 1.6 and the pdksh line are refused as every runs: family", () => {
  for (const family of ["elvish", "nushell", "dotnet", "racket", "julia", "pdksh"]) {
    const opener = { exe: PIN.path, sha256: ENVCOPY, exeSystem: true, loaderEnv: [`runs:${family}`] };
    assert.equal(verdictProgramOf(opener), null, family);
    for (const ask of ["never", "known", "always"] as const) {
      const d = decideOpen(ENV, { readers: [PIN] }, opener, { ask });
      assert.equal(d.verdict, "deny", `${family} ${ask}: ${d.why}`);
      assert.match(d.why, new RegExp(`by its content, a ${family} interpreter`));
    }
  }
});

// ── over a real server: (2) the open, (4) the rule list ─────────────────────

async function rig(policyOf: (dir: string, secret: string) => string, fn: (r: { guard: ArbiterClient; admin: ArbiterClient; dir: string; secret: string }) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-program-identity-"));
  const secret = join(dir, ".env");
  writeFileSync(secret, "API_KEY=program_identity_canary_01\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, policyOf(dir, secret));
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), policyPath: policy, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await s.listen();
  const guard = new ArbiterClient(join(dir, "human", "h.sock")); await guard.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect();
  try { await fn({ guard, admin, dir, secret }); } finally { guard.close(); admin.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); }
}

test("(2) over a real server: the pkg: opener, pinned and vouched for, is refused unprompted and holds nothing", async () => {
  await rig((_d, secret) => `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [{ app: mytool, path: ${PIN.path}, sha256: ${ENVCOPY}, prints: nothing }]\n`, async ({ guard, secret }) => {
    const d = await guard.decideSecretOpen({ path: secret, exe: PIN.path, sha256: ENVCOPY, isAgent: false, exeSystem: true, openerEnv: ["pkg:coreutils"], procKey: "pi-1", session: "pi", ask: "always" });
    assert.equal(d.verdict, "deny", d.reason);
    assert.match(d.reason, /by its content, a program of GNU coreutils/);
    assert.equal(d.approvalId, undefined, "never asked about");
    assert.equal((await guard.processSecretTaint("pi-1")).level, null, "no taint row");
    // the same binary with no finding (the code before) was the listed reader
    assert.equal((await guard.decideSecretOpen({ path: secret, exe: PIN.path, sha256: ENVCOPY, isAgent: false, exeSystem: true, openerEnv: [], procKey: "pi-2", session: "pi" })).verdict, "raw");
  });
});

test("(4) the policy snapshot's rule list carries each path's readers and the arbiter's judgment of each entry", async () => {
  const COPY = sha("byte for byte the host's python3.12");
  await rig((_d, secret) => `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [{ app: mytool, path: /home/u/bin/mytool, sha256: ${COPY} }, ssh-add, { app: deploy, prints: nothing }, aws, cat, nu]\n`, async ({ admin, secret }) => {
    addCodeRunnerHashes([[COPY, "python3.12"]]);
    try {
      const snap = await admin.policySnapshot();
      const row = snap.document?.paths.find((p) => p.path === secret);
      assert.ok(row, JSON.stringify(snap.document?.paths));
      assert.deepEqual((row.readers ?? []).map((r) => (typeof r === "string" ? r : r.app)), ["mytool", "ssh-add", "deploy", "aws", "cat", "nu"]);
      // mytool by its hash (a copy of python3.12), cat and nu by name
      assert.deepEqual(row.readersAdmitNothing, [true, false, false, false, true, true]);
      // aws is neither vetted nor vouched for: the placeholder copy
      assert.deepEqual(row.readersReadTwin, [false, false, false, true, false, false]);
      assert.deepEqual(row.readersCopyOf, ["python3.12", null, null, null, null, null]);
    } finally {
      clearHostProgramHashesForTest();
      refreshProgramHashes({ minIntervalMs: 0 });
    }
  });
});
