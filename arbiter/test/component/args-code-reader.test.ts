/**
 * args-code-reader (component) — confidentiality plan 13 §3 D8, "code by
 * argument" (2026-10-02), over a real ArbiterServer: the guard (a production
 * client on the HUMAN socket, plan 13 D9) reports an opener or a writer whose
 * command line hands it code as an `args:` finding beside its loader
 * findings (args_code.rs).
 *
 *   policy.yaml: <ws>/.env  readers: [ssh, { app: psql, output: clear }, git]
 *   (psql and git are printers: listed, they admit nothing)
 *
 * Asserted:
 *   - a listed reader handed code (`ssh -o proxycommand`, `psql -f`) gets no
 *     raw byte, no pin, no taint row and no Inbox row, under `ask: always`;
 *   - the same binary with a clean command line reads raw (control);
 *   - git, listed, reads nothing raw with or without a finding: a printer
 *     since 2026-10-04 (plan 13 §4.9);
 *   - a protected write by such a program is asked about, keyed by its run
 *     (decision (c)), not refused as a loader problem, and its row says why.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const GIT = "/usr/bin/git";
const SSH = "/usr/bin/ssh";
const PSQL = "/usr/bin/psql";
const SHA = "a".repeat(64);

test("code by argument: a listed reader handed code reads nothing and files no row; a clean run of the same binary reads raw; a protected write by it is asked per run (secrets axes)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-args-code-"));
  const secret = join(dir, ".env");
  writeFileSync(secret, "DB_PASSWORD=argscanary0000000001\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers:\n      - ssh\n      - { app: psql, output: clear }\n      - git\n`);
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"), humanSocketPath: join(dir, "human", "h.sock"),
    dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), policyPath: policy, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await s.listen();
  const guard = new ArbiterClient(join(dir, "human", "h.sock")); await guard.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect();
  const open = (procKey: string, exe: string, openerEnv: string[]) =>
    guard.decideSecretOpen({ path: secret, exe, sha256: SHA, isAgent: false, exeSystem: true, openerEnv, procKey, session: "ac", ask: "always" } as Parameters<ArbiterClient["decideSecretOpen"]>[0]);
  const pending = async (dest: string) => (await admin.egressApprovals("pending")).filter((e) => e.destination === dest);
  try {
    const before = readFileSync(policy, "utf8");
    // (psql, which carried two of these cases, is a printer since plan 13 D8
    // (12)'s correction: refused below with git)
    for (const [key, exe, finding] of [["s1", SSH, "args:ssh -o proxycommand"], ["s2", SSH, "args:ssh -o localcommand"], ["s4", SSH, "args:ssh -F"]] as const) {
      const d = await open(key, exe, [finding]);
      assert.equal(d.verdict, "deny", `${finding}: ${JSON.stringify(d)}`);
      assert.match(String(d.reason), /hands it code to run/);
      assert.equal((await guard.processSecretTaint(key)).rows.length, 0, `${finding}: no taint row`);
    }
    assert.equal(readFileSync(policy, "utf8"), before, "nothing was pinned");
    assert.deepEqual(await pending(secret), [], "never prompted, even under ask: always");

    // git and psql, listed, handed code or not: printers, refused unprompted
    for (const [key, exe, env] of [["g1", GIT, ["args:git -c alias.x"]], ["g2", GIT, []], ["p1", PSQL, ["args:psql -f"]], ["p3", PSQL, []]] as const) {
      const g = await open(key, exe, [...env]);
      assert.equal(g.verdict, "deny", JSON.stringify(g));
      assert.match(String(g.reason), /prints or copies/);
      assert.equal((await guard.processSecretTaint(key)).rows.length, 0);
    }
    assert.equal(readFileSync(policy, "utf8"), before, "git is not pinned");
    assert.deepEqual(await pending(secret), [], "nor asked about");

    // control: the same binaries, clean, read raw (and are pinned on first use)
    assert.equal((await open("s3", SSH, [])).verdict, "raw");
    assert.match(readFileSync(policy, "utf8"), new RegExp(`path: ${SSH}`));

    // a protected write by git handed code: asked, keyed by the run
    const target = join(dir, "bashrc");
    const w = await guard.decideProtectedWrite({ path: target, exe: GIT, sha256: SHA, exeSystem: true, openerEnv: ["args:git -c core.editor"], procKey: "gw-1", label: "a shell startup file", session: "ac" });
    assert.equal(w.verdict, "ask", JSON.stringify(w));
    const rows = await pending(target);
    assert.equal(rows.length, 1);
    assert.equal(rows[0]!.symbol, `write:${GIT}#${SHA}#run:gw-1`, "keyed by its run: an answer covers this change only");
    assert.match(rows[0]!.reason, /running code its command line or environment hands it/);
    // and a clean run of git keys by the binary, as before
    await guard.decideProtectedWrite({ path: target, exe: GIT, sha256: SHA, exeSystem: true, openerEnv: [], procKey: "gw-2", label: "a shell startup file", session: "ac" });
    assert.ok((await pending(target)).some((r) => r.symbol === `write:${GIT}#${SHA}`));
  } finally {
    guard.close(); admin.close(); await s.close(); rmSync(dir, { recursive: true, force: true });
  }
});
