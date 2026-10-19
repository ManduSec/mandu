/**
 * writer-identity e2e — the Plan 13 D8 follow-up for write protection
 * (write-protection.md §2.1): the human's answer to a held change of a file
 * that runs later (~/.ssh/authorized_keys, a shell startup file, a git hook)
 * names the writer's BINARY, over the production wiring.
 *
 * A REAL ArbiterServer, the guard's question (`decideProtectedWrite`) over the
 * production ArbiterClient on the data socket, the human's answer over the
 * admin socket, `mandu why`'s op read back on the admin socket:
 *   - after the human allows /usr/bin/nano (Always), an agent-written
 *     /tmp/x/nano (the same bytes) is held under its own row, and a rebuilt
 *     /usr/bin/nano is asked again;
 *   - the allowed binary run with LD_PRELOAD, with agent-writable code mapped
 *     in, or whose environment the guard did not report, is refused with no
 *     row and does not spend a `once`;
 *   - the Inbox row and `whyPath` name the path, the hash stays in the key.
 *   - plan 13 §8 decision (c): a writer that runs code is named with its
 *     script (the guard's R5 facts on `decideProtectedWrite`): after the
 *     human allows python3 running a.py (Always), python3 running b.py and
 *     `python3 -c` are each asked; a shell running inline code is asked
 *     about each change, an Always kept as once; `mandu why` names the script.
 * Run with the secrets axis ON and OFF (write protection holds in every mode
 * but `off`, whatever the axis). The same properties under the real guard:
 * tests/sandbox/write-protect.test.ts.
 *
 * Axes stated: secrets (each server also states its own).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

const SHA = "d".repeat(64);

for (const confidentiality of [true, false]) {
  test(`D8 follow-up e2e (confidentiality ${confidentiality ? "on" : "off"}): an approved /usr/bin/nano admits no other binary named nano, nor itself run with agent code`, async () => {
    const tmp = mkdtempSync(join(tmpdir(), "mandu-writer-identity-"));
    const socketPath = join(tmp, "a.sock");
    const adminPath = join(tmp, "admin.sock");
    const server = new ArbiterServer({ socketPath, adminSocketPath: adminPath, humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "db.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality, integrity: false });
    await server.listen();
    // The production wiring: the guard's own client type on the human socket
    // (plan 13 D9: a data-socket report is refused).
    const guard = new ArbiterClient(join(tmp, "human", "h.sock")); await guard.connect();
    const admin = new ArbiterClient(adminPath); await admin.connect();
    const keys = "/home/u/.ssh/authorized_keys";
    const write = (exe: string, procKey: string, more: { sha256?: string; exeSystem?: boolean; openerEnv?: string[] } = {}) =>
      guard.decideProtectedWrite({ path: keys, exe, procKey, label: "an ssh setting", session: "s-wid", sha256: SHA, exeSystem: exe.startsWith("/usr/"), openerEnv: [], ...more });
    try {
      // 1. The human allows the system's nano, standing.
      const held = await write("/usr/bin/nano", "nano-1");
      assert.equal(held.verdict, "ask");
      const [row] = (await admin.egressApprovals("pending")).filter((e) => e.destination === keys);
      assert.equal(row?.symbol, `write:/usr/bin/nano#${SHA}`);
      await admin.resolveEgressApproval(held.approvalId!, true, "always");
      assert.equal((await write("/usr/bin/nano", "nano-2")).verdict, "allow");

      // 2. The agent's copy, same bytes, another path: held under its own row.
      const copy = await write("/tmp/x/nano", "copy-1");
      assert.equal(copy.verdict, "ask", `the agent's /tmp/x/nano rode the approval of /usr/bin/nano (${copy.verdict}: ${copy.reason})`);
      const copyRow = (await admin.egressApprovals("pending")).find((e) => e.id === copy.approvalId);
      assert.match(copyRow?.reason ?? "", /^nano \(\/tmp\/x\/nano\) wants to change .*The agent could have written this program\./);
      // A rebuilt /usr/bin/nano is another binary.
      assert.equal((await write("/usr/bin/nano", "nano-3", { sha256: "e".repeat(64) })).verdict, "ask");

      // 3. The allowed binary with the agent's code in it: refused, no row.
      const rc = "/home/u/.bashrc";
      const first = await guard.decideProtectedWrite({ path: rc, exe: "/usr/bin/nano", procKey: "nano-rc-1", label: "a shell startup file", sha256: SHA, exeSystem: true, openerEnv: [] });
      await admin.resolveEgressApproval(first.approvalId!, true, "once");
      for (const env of [["LD_PRELOAD"], ["code:/tmp/x/hook.so"], undefined]) {
        const r = await guard.decideProtectedWrite({ path: rc, exe: "/usr/bin/nano", procKey: "pre-1", label: "a shell startup file", sha256: SHA, exeSystem: true, ...(env ? { openerEnv: env } : {}) });
        assert.equal(r.verdict, "deny", `nano with ${JSON.stringify(env)} was not refused (${r.verdict}: ${r.reason})`);
        assert.equal(r.approvalId, undefined);
      }
      assert.equal((await admin.egressApprovals("pending")).filter((e) => e.destination === rc).length, 0, "no row for an unclean writer");
      assert.equal((await guard.decideProtectedWrite({ path: rc, exe: "/usr/bin/nano", procKey: "nano-rc-2", label: "a shell startup file", sha256: SHA, exeSystem: true, openerEnv: [] })).verdict, "allow", "the once is still the clean nano's");

      // 4. `mandu why` reads the verdict back by path, never the hash.
      const why = await admin.whyPath(keys);
      const v = why.verdicts.filter((x) => x.kind === "write");
      assert.deepEqual(v.map((x) => [x.exe, x.status]).sort(), [["/tmp/x/nano", "pending"], ["/usr/bin/nano", "approved"], ["/usr/bin/nano", "pending"]]);
      assert.ok(!JSON.stringify(why).includes(SHA), "no hash in mandu why");
    } finally {
      guard.close(); admin.close(); await server.close(); rmSync(tmp, { recursive: true, force: true });
    }
  });
}

for (const confidentiality of [true, false]) {
  test(`decision (c) e2e (confidentiality ${confidentiality ? "on" : "off"}): an Always for python3 running a.py admits neither b.py nor python3 -c; inline bash is asked per change; mandu why names the script`, async () => {
    const tmp = mkdtempSync(join(tmpdir(), "mandu-writer-script-"));
    const adminPath = join(tmp, "admin.sock");
    const server = new ArbiterServer({ socketPath: join(tmp, "a.sock"), adminSocketPath: adminPath, humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "db.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality, integrity: false });
    await server.listen();
    const guard = new ArbiterClient(join(tmp, "human", "h.sock")); await guard.connect();
    const admin = new ArbiterClient(adminPath); await admin.connect();
    const rc = "/home/u/.bashrc";
    const PY = "/usr/bin/python3.12";
    const script = (path: string) => ({ path, sha256: "c".repeat(64), system: true, isolated: true, traced: false });
    const write = (exe: string, procKey: string, more: { script?: ReturnType<typeof script>; scriptProblem?: string }) =>
      guard.decideProtectedWrite({ path: rc, exe, procKey, label: "a shell startup file", session: "s-wsc", sha256: SHA, exeSystem: true, openerEnv: [], ...more });
    try {
      const held = await write(PY, "py-1", { script: script("/opt/tools/a.py") });
      assert.equal(held.verdict, "ask");
      await admin.resolveEgressApproval(held.approvalId!, true, "always");
      assert.equal((await write(PY, "py-2", { script: script("/opt/tools/a.py") })).verdict, "allow");
      assert.equal((await write(PY, "py-3", { script: script("/opt/tools/b.py") })).verdict, "ask", "python3 running b.py");
      assert.equal((await write(PY, "py-4", { scriptProblem: "inline code (python -c)" })).verdict, "ask", "python3 -c");
      // the agent's shell appending to ~/.bashrc: one answer, one change
      const sh = await write("/usr/bin/bash", "sh-1", { scriptProblem: "inline code (sh -c)" });
      assert.equal(sh.verdict, "ask");
      assert.equal((await admin.resolveEgressApproval(sh.approvalId!, true, "always")).scope, "once");
      assert.equal((await write("/usr/bin/bash", "sh-1", { scriptProblem: "inline code (sh -c)" })).verdict, "allow");
      assert.equal((await write("/usr/bin/bash", "sh-1", { scriptProblem: "inline code (sh -c)" })).verdict, "ask", "its next change is asked again");
      assert.equal((await write("/usr/bin/bash", "sh-2", { scriptProblem: "inline code (sh -c)" })).verdict, "ask", "another run is asked");
      const why = await admin.whyPath(rc);
      const v = why.verdicts.filter((x) => x.kind === "write");
      assert.ok(v.some((x) => x.exe === PY && x.script === "/opt/tools/a.py" && x.status === "approved"), JSON.stringify(v));
      assert.ok(v.some((x) => x.exe === "/usr/bin/bash" && x.run === true), JSON.stringify(v));
      assert.ok(!JSON.stringify(v).includes(SHA), "no hash in mandu why");
    } finally {
      guard.close(); admin.close(); await server.close(); rmSync(tmp, { recursive: true, force: true });
    }
  });
}
