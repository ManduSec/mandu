/**
 * tar-secret (sandbox) — GNU tar archives a guarded secret as any non-reader
 * sees it, under the REAL guard (2026-10-03; confidentiality.md §7.2a "An
 * open the guard performs").
 *
 * Measured before: `tar cf x.tar dir/file` failed "Cannot stat: Invalid
 * argument" under the guard for ANY argument with a directory part (a
 * secret or not; `tar cf x.tar .env` worked). GNU tar 1.35 opens such an
 * argument's parent with `openat2(…, O_PATH|O_DIRECTORY|O_NOFOLLOW|
 * O_CLOEXEC)`; the guard performs every openat2, and its performer added
 * `O_NOCTTY`, which openat2 refuses beside `O_PATH` (EINVAL).
 *
 *   the real mandu-net-guard (seccomp user notification, no root) around an
 *   "agent" running tar, in `secrets`, against a real ArbiterServer loaded
 *   from a policy.yaml on disk:
 *     ~/.netrc       no reader list        → every program gets the twin
 *     ~/proj/.env    readers [ssh-add], others: twin
 *     ~/.pgpass      readers [tar]         → refused: tar is a printer, and a
 *                                            printer admits nothing (plan 13 D8,
 *                                            2026-10-03; until then the control
 *                                            that a listed tar archived the file)
 *     ~/deny/.env    readers [ssh-add]        → others: deny (the default), tar refused
 *
 * Each archive run twice: with the guard's stat twins off and on
 * (MANDU_NET_GUARD_STAT_TWINS, the guard-only posture's metadata). The
 * oracle, read from the archives outside the guard:
 *   - THE LEAK ORACLE: no archive tar writes as a non-reader holds a byte of
 *     the canary; each such member is exactly the twin the guard serves;
 *   - tar exits 0 (relative `dir/file`, an absolute path, a directory tree
 *     through gzip, `-h`), with no "Invalid argument" and no "file changed
 *     as we read it" (the size tar reads is the size it stats: it stats the
 *     descriptor it opened);
 *   - tar listed as the reader is refused like any non-reader (printers
 *     admit nothing), and its archive holds no byte of the canary;
 *   - `others: deny` refuses tar's open (Permission denied), never EINVAL.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../../arbiter/ipc/client.js";
import { agentNodeCopy, pickGuard } from "../../lib/native-guard.js";
import { stateAxes } from "../../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const has = (p: string): boolean => spawnSync("sh", ["-c", `command -v ${p}`]).status === 0;
const skip = process.platform !== "linux" ? "Linux only"
  : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : !["tar", "gzip"].every(has) ? "tar and gzip are needed"
  : false;

const CANARY = `TAR_CANARY_${process.pid}_q9Zr4`;

/** The "agent": runs its Bash calls, prints what each returned. */
const AGENT_SOURCE = `import { spawnSync } from "node:child_process";
const cmds = JSON.parse(process.argv[2]);
const out = {};
for (const [k, cmd] of Object.entries(cmds)) {
  const r = spawnSync("bash", ["-c", cmd], { encoding: "utf8" });
  out[k] = (r.stdout ?? "") + (r.stderr ?? "");
}
process.stdout.write("AGENT_OUT " + JSON.stringify(out) + "\\n");
`;

function runGuarded(argv: string[], env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string; status: number | null }> {
  return new Promise((ok) => {
    const child = spawn(GUARD.path!, ["--allow", "127.0.0.0/8:*", "--", ...argv], { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (c) => (stdout += String(c)));
    child.stderr.on("data", (c) => (stderr += String(c)));
    const timer = setTimeout(() => child.kill("SIGKILL"), 120_000);
    child.on("close", (status) => { clearTimeout(timer); ok({ stdout, stderr, status }); });
  });
}

/** A member's bytes, read outside the guard. */
function member(archive: string, name: string): Buffer {
  const r = spawnSync("tar", ["-xOf", archive, name]);
  assert.equal(r.status, 0, `tar -xOf ${archive} ${name}: ${String(r.stderr)}`);
  return r.stdout;
}

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

for (const statTwins of ["0", "1"]) {
  test(`tar under the REAL guard archives what a non-reader sees, never the secret (stat twins ${statTwins}; secrets axes)`, { skip, timeout: 300_000 }, async (t) => {
    const tmp = mkdtempSync(join(tmpdir(), "mandu-tar-guard-"));
    const home = join(tmp, "home");
    for (const d of ["proj", "deny"]) mkdirSync(join(home, d), { recursive: true });
    const netrc = join(home, ".netrc");
    const env = join(home, "proj", ".env");
    const pgpass = join(home, ".pgpass");
    const denied = join(home, "deny", ".env");
    const plain = join(home, "proj", "plain.txt");
    writeFileSync(netrc, `machine x.example login u password ${CANARY}\n`);
    writeFileSync(env, `API_KEY=${CANARY}\nDEBUG=1\n`);
    writeFileSync(pgpass, `db:5432:*:u:${CANARY}\n`);
    writeFileSync(denied, `TOKEN=${CANARY}\n`);
    writeFileSync(plain, "hello\n");
    const policy = join(tmp, "policy.yaml");
    writeFileSync(policy, [
      "version: 1",
      "paths:",
      `  - path: ${netrc}`,
      "    level: no-model",
      `  - path: ${env}`,
      "    level: no-model",
      "    readers: [ssh-add]",
      "    others: twin",
      `  - path: ${pgpass}`,
      "    level: no-model",
      "    readers: [tar]",
      `  - path: ${denied}`,
      "    level: no-model",
      "    readers: [ssh-add]",
      "",
    ].join("\n"));
    const logs: string[] = [];
    const sock = join(tmp, "arbiter.sock");
    const server = new ArbiterServer({ socketPath: sock, humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: (l: string) => logs.push(l), confidentiality: true, integrity: false });
    await server.listen();
    const client = new ArbiterClient(sock);
    await client.connect();
    try {
      const twins: Record<string, Buffer> = {};
      const secrets: Array<{ path: string; twin: string; level: string }> = [];
      for (const [p, name] of [[netrc, "twin-netrc"], [env, "twin-env"], [pgpass, "twin-pgpass"], [denied, "twin-denied"]] as const) {
        const reg = await client.registerSecret({ path: p, home });
        assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
        const twin = join(tmp, name);
        writeFileSync(twin, typeof (reg as { twin?: unknown }).twin === "string" ? String((reg as { twin?: string }).twin) : `${reg.symbol}\n`);
        twins[p] = readFileSync(twin);
        assert.ok(!twins[p]!.includes(CANARY), `the twin of ${p} holds no canary`);
        secrets.push({ path: p, twin, level: "no-model" });
      }
      const secretPolicy = join(tmp, "secret-policy.json");
      const agentNode = agentNodeCopy(tmp);
      writeFileSync(secretPolicy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session: `tar-${process.pid}`, secrets }));
      const out = join(tmp, "out");
      mkdirSync(out);
      const cmds: Record<string, string> = {
        // A relative argument with a directory part: tar's openat2(O_PATH) of `proj/`.
        relDir: `cd "$HOME" && tar cf "$O/rel.tar" proj/.env proj/plain.txt; echo "EXIT $?"`,
        // An absolute one.
        abs: `tar cf "$O/abs.tar" "$HOME/.netrc"; echo "EXIT $?"`,
        // A tree, through gzip.
        tree: `cd "$HOME" && tar czf "$O/tree.tgz" proj; echo "EXIT $?"`,
        // Following symlinks (`-h`): its stat by path follows, the call the stat twins answer.
        deref: `tar chf "$O/deref.tar" "$HOME/.netrc"; echo "EXIT $?"`,
        // tar listed as the reader of .pgpass: a printer admits nothing (plan 13 D8).
        reader: `tar cf "$O/reader.tar" "$HOME/.pgpass"; echo "EXIT $?"`,
        // others: deny: tar is no reader, and gets nothing.
        denied: `tar cf "$O/denied.tar" "$HOME/deny/.env"; echo "EXIT $?"`,
      };
      const agentJs = join(tmp, "agent.mjs");
      writeFileSync(agentJs, AGENT_SOURCE);
      const runEnv: NodeJS.ProcessEnv = { ...process.env, HOME: home, O: out, MANDU_ARBITER_SOCK: sock, MANDU_NET_GUARD_SECRETS: secretPolicy, MANDU_NET_GUARD_STAT_TWINS: statTwins };
      for (const n of ["TAR_OPTIONS", "GZIP", "TAPE"]) delete runEnv[n];
      const run = await runGuarded([agentNode, agentJs, JSON.stringify(cmds)], runEnv);
      const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
      if (!line && /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(run.stderr ?? "")) {
        t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
        return;
      }
      assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr.slice(-3000)}`);
      const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as Record<string, string>;
      const decided = logs.filter((l) => /decideSecretOpen/.test(l)).join("\n");
      const diag = `\n${JSON.stringify(got, null, 1)}\n${decided}`;

      // tar runs to the end on every argument it may read.
      for (const k of ["relDir", "abs", "tree", "deref"]) {
        assert.match(got[k]!, /^EXIT 0$/m, `${k}: tar failed${diag}`);
        // Only tar's notes on the names it stores (absolute paths) besides.
        const said = got[k]!.split("\n").filter((l) => l.startsWith("tar: ") && !/^tar: Removing leading `\/' from /.test(l));
        assert.deepEqual(said, [], `${k}: tar complained${diag}`);
      }
      for (const [k, v] of Object.entries(got)) {
        assert.ok(!/Invalid argument/.test(v), `${k}: EINVAL from the guard${diag}`);
        assert.ok(!/file changed as we read it/.test(v), `${k}: tar saw a size it did not read${diag}`);
      }

      // THE LEAK ORACLE: every archive of a non-reader, as bytes, holds no
      // canary; each member is exactly the twin (or the plain file).
      for (const f of ["rel.tar", "abs.tar", "deref.tar"]) {
        assert.ok(!readFileSync(join(out, f)).includes(CANARY), `CONFIDENTIALITY VIOLATION: ${f} holds the raw secret${diag}`);
      }
      assert.deepEqual(member(join(out, "rel.tar"), "proj/.env"), twins[env], "the others: twin member is the twin");
      assert.equal(member(join(out, "rel.tar"), "proj/plain.txt").toString(), "hello\n", "a plain file beside it is archived as written");
      assert.deepEqual(member(join(out, "abs.tar"), netrc.slice(1)), twins[netrc], "a file with no reader list: the twin");
      assert.deepEqual(member(join(out, "deref.tar"), netrc.slice(1)), twins[netrc], "-h: the twin");
      const tree = member(join(out, "tree.tgz"), "proj/.env");
      assert.ok(!tree.includes(CANARY), `CONFIDENTIALITY VIOLATION: the gzip tree holds the raw secret${diag}`);
      assert.deepEqual(tree, twins[env], "the tree's member is the twin");

      // Plan 13 D8, printers admit nothing: tar named in readers: is refused
      // like any program not on the list (others: deny), and archives nothing
      // of the file. (Before 2026-10-03, the control: it archived the real file.)
      assert.match(got["reader"]!, /Cannot open: Permission denied/, `a listed tar is refused${diag}`);
      assert.ok(!readFileSync(join(out, "reader.tar")).includes(CANARY), `CONFIDENTIALITY VIOLATION: the listed tar archived the raw secret${diag}`);

      // others: deny refuses tar's open; nothing of the file is archived.
      assert.match(got["denied"]!, /Cannot open: Permission denied/, `others: deny${diag}`);
      assert.match(got["denied"]!, /^EXIT 2$/m);
      assert.ok(!readFileSync(join(out, "denied.tar")).includes(CANARY), `CONFIDENTIALITY VIOLATION: the denied file reached the archive${diag}`);
    } finally {
      client.close();
      await server.close();
      rmSync(tmp, { recursive: true, force: true });
    }
  });
}
