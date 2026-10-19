/**
 * dir-change-label-raise (component) — a directory change in a shell command
 * never LOWERS the level its relative tokens read at (2026-10-17,
 * confidentiality.md §6, "A directory change only raises").
 *
 * A real ArbiterServer with both sockets, its policy labelling the
 * workspace's `secrets/` and `vault/` no-model and `notes/*.md` too (human
 * labels; no file is a registered secret, so no twin and no value backstop stand behind this
 * verdict). `guard` and `proxy` are production clients on the human socket,
 * `agent` one on the data socket. Each Bash call is recorded as it runs
 * under Mandu (the proxy's command record, the guard's call root with the
 * kernel's start directory, the proxy's callTaint binding), then its result
 * is classified.
 *
 * Before the fix, `changesDirectory` made the scan drop the start directory
 * entirely, so `cd . && cat secrets/plan.md` read `secrets/plan.md` as
 * written: a relative token matches no label (the store is keyed by
 * absolute path), and the plan classified PUBLIC, in clear to the model.
 * Now the start-directory reading stays as a raise, a token that names the
 * tail of a labelled path is read there whatever the shell's directory, and
 * a directory change whose target the scan cannot read masks a command
 * that reads any relative path while a label stands.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const PLAN = "PLAN-UNREGISTERED-LABELLED-91c4\n";

test("a directory change in a Bash command never lowers a labelled relative path's level: every cd spelling, the flag forms, an unknown target (secrets axes, explicit)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-dirchange-"));
  const ws = join(dir, "ws");
  mkdirSync(join(ws, "secrets"), { recursive: true });
  mkdirSync(join(ws, "vault"), { recursive: true });
  mkdirSync(join(ws, "sub", "deeper"), { recursive: true });
  writeFileSync(join(ws, "secrets", "plan.md"), PLAN);
  writeFileSync(join(ws, "vault", "plan.md"), PLAN);
  mkdirSync(join(ws, "notes"), { recursive: true });
  writeFileSync(join(ws, "notes", "plan.md"), PLAN);
  writeFileSync(join(ws, "README.md"), "hello\n");
  const policy = join(dir, "policy.yaml");
  // `vault`: a name no catalog shape matches, so a bare `cd vault` meets the label alone
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(ws, "secrets")}\n    level: no-model\n  - path: ${join(ws, "vault")}\n    level: no-model\n  - path: ${join(ws, "notes")}/*.md\n    level: no-model\n`);
  const human = join(dir, "human", "h.sock");
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: human, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    policyPath: policy, log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const guard = new ArbiterClient(human); await guard.connect();
  const proxy = new ArbiterClient(human); await proxy.connect();
  const agent = new ArbiterClient(join(dir, "a.sock")); await agent.connect();
  const session = "s-dirchange";
  let n = 0;
  const call = async (command: string, cwd: string | null, tool = "Bash"): Promise<string | undefined> => {
    const callId = `toolu_dc_${n++}`;
    await proxy.recordCallCommand({ callId, command, sessionKey: session });
    await guard.recordExecRoot({
      procKey: `sh-${callId}`, ancestors: ["agent-0"], argv: ["/bin/bash", "-c", command], session, callRoot: true,
      ...(cwd !== null ? { cwd } : {}),
    });
    await proxy.callTaint(callId, { command, session });
    const r = await agent.classify({
      tool, value: PLAN, boundary: "model_context", origin: command,
      params: tool === "Bash" ? { command } : { cmd: command, workdir: cwd ?? undefined }, sessionKey: session, callId,
    } as Parameters<ArbiterClient["classify"]>[0]);
    return (r as { confidentiality?: string }).confidentiality;
  };
  try {
    // the baseline the fix must not lose
    assert.equal(await call("cat secrets/plan.md", ws), "no-model", "the plain relative read is masked");
    assert.equal(await call("cat README.md", ws), "public", "a benign relative read stays in clear");

    const masked: Array<[string, string | null]> = [
      ["cd . && cat secrets/plan.md", ws],
      ["cd .; cat secrets/plan.md", ws],
      ["cd ./ && cat secrets/plan.md", ws],
      ["cd -- . && cat secrets/plan.md", ws],
      ["pushd . >/dev/null && cat secrets/plan.md", ws],
      ['cd "$PWD" && cat secrets/plan.md', ws],
      ["(cd . && cat secrets/plan.md)", ws],
      ["\\cd . && cat secrets/plan.md", ws],
      ["builtin cd . && cat secrets/plan.md", ws],
      // a resolvable change of directory
      ["cd vault && cat plan.md", ws],
      ["cd sub && cat ../vault/plan.md", ws],
      ["cd sub/deeper && cat ../../vault/plan.md", ws],
      ["cd sub; cd deeper; cat ../../vault/plan.md", ws],
      [`cd ${ws}/vault && cat plan.md`, join(dir)],
      ["cd .. && cat ws/vault/plan.md", ws],
      ["cd ../.. && cat secrets/plan.md", join(ws, "sub", "deeper")],
      // flag forms
      ["git -C sub show HEAD:../vault/plan.md", ws],
      ["make -C vault -f plan.md", ws],
      ["tar -C vault -cf - plan.md", ws],
      ["tar -Cvault -cf - plan.md", ws],
      ["env -C sub cat ../vault/plan.md", ws],
      ["env --chdir=vault cat plan.md", ws],
      ["ls --directory=vault plan.md", ws],
      // an interpreter one-liner's chdir
      [`python3 -c "import os; os.chdir('sub'); print(open('../vault/plan.md').read())"`, ws],
      [`node -e "process.chdir('vault'); console.log(require('fs').readFileSync('plan.md','utf8'))"`, ws],
      // a target the scan cannot read: the precaution
      ['cd "$TARGET" && cat plan.md', ws],
      ["cd - && cat plan.md", ws],
      ["cd $(dirname vault/x) && cat plan.md", ws],
      ["cd vau* && cat plan.md", ws],
      ["cd ~other && cat plan.md", ws],
      ["popd && cat plan.md", ws],
      // the start directory unknown (no guard): the token names the labelled path's tail
      ["cd . && cat secrets/plan.md", null],
      ["cd sub && cat ../vault/plan.md", null],
      ["cat secrets/plan.md", null],
      // the adversarial review's shapes: a pattern's prefix entered by cd,
      // quoting inside a token, a clustered -C, a substitution and an input
      // redirection after an unreadable cd
      ["cd notes && cat plan.md", ws],
      ['cat va""ult/plan.md', ws],
      ["env -iC .. cat vault/plan.md", join(ws, "sub")],
      ['cd "$D" && echo "$(cat plan.md)"', ws],
      ["cd vau*;head<plan.md", ws],
    ];
    for (const [command, cwd] of masked) {
      assert.equal(await call(command, cwd), "no-model", `CONFIDENTIALITY VIOLATION: ${command} (start ${cwd}) must classify no-model, not public`);
    }
    // Codex's exec_command: the same reading
    for (const command of ["cd . && cat secrets/plan.md", "cd sub && cat ../vault/plan.md", 'cd "$T" && cat plan.md']) {
      assert.equal(await call(command, ws, "exec_command"), "no-model", `CONFIDENTIALITY VIOLATION: exec_command ${command}`);
    }

    // what the fix must not over-mask: a benign directory change
    const clear: Array<[string, string | null]> = [
      ["cd . && cat README.md", ws],
      ["cd sub && ls", ws],
      ["cd sub && cat ../README.md", ws],
      ["git -C sub log --oneline", ws],
      ["make -C sub test", ws],
    ];
    for (const [command, cwd] of clear) {
      assert.equal(await call(command, cwd), "public", `utility: ${command} names no labelled path`);
    }
  } finally {
    guard.close(); proxy.close(); agent.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
