/**
 * A protected file moved with its folder (docs/design/confidentiality/guard-file-identity.md
 * §2, 2026-10-16), across the REAL
 * components in `secrets` mode, GUARD-ONLY posture (`--no-secret-bind`: no
 * bind, the REAL mandu-net-guard serves every twin by descriptor): the
 * launcher's main(), a REAL ArbiterServer, and the production model proxy
 * (`new ProxyAdapter(new ArbiterClient(sock))`) in front of a mock upstream.
 * The "agent" is /bin/sh.
 *
 * The guard refuses a rename of a protected file itself, but a rename of a
 * folder above it is not refused: `mv ~/.aws ~/.aws2`. It knew the file by
 * path and by an identity list re-`stat`ed every 2 s by path, so once the
 * list was rebuilt the moved file read RAW under its new name. Now it holds
 * each protected file by its inode (`inode_pins`) and the moved file is the
 * same secret for the whole session:
 *
 *   M1 `~/.aws` renamed, then, past the 2 s rebuild, `cat
 *      ~/.aws2/credentials` reads the placeholder twin; the same for a
 *      workspace `.env` whose project folder is renamed. No output holds a
 *      raw byte, and no request to the model does.
 *   M2 the fallback: with the pin budget at 0 (`MANDU_NET_GUARD_PIN_MAX=0`,
 *      a test knob that only lowers it) no file is held, so a rename of a
 *      folder above one is refused; the files read as placeholders.
 *
 * Self-SKIPs where the guard is not built (scripts/build-native.sh).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { request as httpRequest } from "node:http";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter as ProxyAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { stateAxes } from "../lib/axes.js";
import { pickGuard } from "../lib/native-guard.js";

stateAxes("secrets");

const PICK = pickGuard(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "interceptors", "target"));
const GUARD = PICK.path;
const skip = process.platform !== "linux" || !GUARD ? "mandu-net-guard is not built (scripts/build-native.sh)" : false;

/** Key-shaped canaries assembled at run time (no key literal in this file). */
const AWS_KEY = ["AKIA", "MOVED", "FOLDER", "CRED", "MUST", "NOT", "BE", "READ"].join("_");
const ENV_KEY = ["sk", "proj", "MOVED", "PROJECT", "7731", "Qz".repeat(12)].join("-");

interface Stack { dir: string; home: string; ws: string; sock: string; close: () => Promise<void> }

async function stack(prefix: string, policyFor: (ws: string) => string = () => "version: 1\n"): Promise<Stack> {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  const home = join(dir, "home");
  const ws = join(dir, "ws");
  mkdirSync(join(home, ".aws"), { recursive: true });
  mkdirSync(join(ws, "app"), { recursive: true });
  writeFileSync(join(home, ".aws", "credentials"), `[default]\naws_secret_access_key=${AWS_KEY}\n`);
  writeFileSync(join(ws, "app", ".env"), `OPENAI_API_KEY=${ENV_KEY}\n`);
  writeFileSync(join(ws, "app", "main.py"), "print('hi')\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, policyFor(ws));
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
  });
  await server.listen();
  return { dir, home, ws, sock, close: async () => { await server.close(); rmSync(dir, { recursive: true, force: true }); } };
}

/** One guard-only launch of /bin/sh running `reads` in order; each output and status. */
async function launch(s: Stack, reads: Record<string, string>, env: Record<string, string> = {}): Promise<{ log: string; out: Record<string, { text: string; status: number }> }> {
  const outDir = mkdtempSync(join(s.dir, "out-"));
  const script = [`cd '${s.ws}'`, ...Object.entries(reads).map(([name, cmd]) => `( ${cmd} ) > '${outDir}/${name}' 2>&1; echo $? > '${outDir}/${name}.status'`)].join("\n");
  const lines: string[] = [];
  const orig = console.error;
  const saved = { HOME: process.env["HOME"], MANDU_HOME: process.env["MANDU_HOME"], MANDU_NET_GUARD_BIN: process.env["MANDU_NET_GUARD_BIN"] };
  const cwd = process.cwd();
  let code: number | null = null;
  let err: Error | null = null;
  try {
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    process.env["HOME"] = s.home;
    process.env["MANDU_HOME"] = join(s.home, ".mandu");
    process.env["MANDU_NET_GUARD_BIN"] = GUARD!;
    process.chdir(s.ws);
    try {
      code = await main(
        ["--target", "claude", "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", "--no-secret-bind", "--", "/bin/sh", "-c", script],
        {
          HOME: s.home, PWD: s.ws, MANDU_ARBITER_SOCK: s.sock, PATH: process.env["PATH"],
          MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: join(s.home, ".mandu"), MANDU_MODE: "secrets", XDG_RUNTIME_DIR: s.dir, MANDU_VERBOSE: "1", ...env,
        },
      );
    } catch (e) {
      err = e as Error;
    }
  } finally {
    console.error = orig;
    process.chdir(cwd);
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
  const log = lines.join("\n");
  assert.equal(err, null, `${err?.message}\n${log}`);
  assert.equal(code, 0, log);
  const out: Record<string, { text: string; status: number }> = {};
  for (const name of Object.keys(reads)) {
    const f = join(outDir, name);
    assert.ok(existsSync(f), `the confined launch ran ${name}\n${log}`);
    out[name] = { text: readFileSync(f, "utf8"), status: Number(readFileSync(`${f}.status`, "utf8").trim()) };
  }
  return { log, out };
}

/** Every output as a Bash tool result through the production model proxy;
 *  the bodies the upstream (the model) received. */
async function toModel(s: Stack, outputs: Record<string, { text: string }>): Promise<string[]> {
  const real = new ArbiterClient(s.sock);
  await real.connect();
  const up = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ProxyAdapter(real), upstream: up.fetcher, sessionKey: `moved-${Date.now()}`, log: () => {} });
  const port = await proxy.listen(0);
  try {
    let n = 0;
    for (const [name, o] of Object.entries(outputs)) {
      const id = `tu_${n++}`;
      const body = JSON.stringify({
        model: "claude-opus-4", stream: true,
        messages: [
          { role: "user", content: "Tidy the folders." },
          { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command: name } }] },
          { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: o.text }] },
        ],
      });
      const status = await new Promise<number>((resolve, reject) => {
        const r = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json" } },
          (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); });
        r.on("error", reject);
        r.end(body);
      });
      assert.equal(status, 200);
    }
    return up.requests.map((r) => r.bodyText);
  } finally {
    await proxy.close();
    real.close();
  }
}

/** Every derived label path the arbiter holds (what the next session reads). */
async function derivedPaths(s: Stack): Promise<string[]> {
  const c = new ArbiterClient(s.sock);
  await c.connect();
  try {
    return (await c.derivedLabelsSince({})).labels.map((l) => l.path);
  } finally {
    c.close();
  }
}

const show = (out: Record<string, { text: string; status: number }>): string => Object.entries(out).map(([k, v]) => `--- ${k} (exit ${v.status})\n${v.text}`).join("\n");
const raw = (t: string): boolean => t.includes(AWS_KEY) || t.includes(ENV_KEY);

test("M1 (guard only, §7.2a): ~/.aws and a project folder renamed; past the 2 s identity rebuild the moved files read as placeholders, never raw, and no model request holds a key", { skip, timeout: 300_000 }, async () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
  const s = await stack("mandu-moved-");
  try {
    const run = await launch(s, {
      awsBefore: "cat ~/.aws/credentials",
      envBefore: "cat app/.env",
      mvAws: "mv ~/.aws ~/.aws2",
      mvApp: "mv app app2",
      // Past ID_REFRESH (2 s): the rebuild that used to forget the files.
      awsAfter: "sleep 2.5; cat ~/.aws2/credentials",
      envAfter: "cat app2/.env",
      copied: "cp ~/.aws2/credentials app2/copy.txt && cat app2/copy.txt",
    });
    const all = show(run.out);
    assert.match(run.log, /bind mount SKIPPED \(--no-secret-bind\)/, `the guard-only posture: ${run.log}`);
    assert.match(run.out.awsBefore!.text, /\$MDU:/, `the credential is confined before the move\n${all}`);
    assert.match(run.out.envBefore!.text, /\$MDU:/, `the workspace .env is confined before the move\n${all}`);
    for (const [name, o] of Object.entries(run.out)) assert.ok(!raw(o.text), `${name}: no raw byte of either key\n${all}`);
    // The move itself is the agent's to make (the files are held by inode);
    // were it refused, the files would still be where the twins are.
    for (const k of ["awsAfter", "envAfter"]) {
      const o = run.out[k]!;
      assert.ok(o.status !== 0 || /\$MDU:/.test(o.text), `${k}: the placeholder or a refusal, never the raw file\n${all}`);
    }
    assert.equal(run.out.mvAws!.status, 0, `held by inode, the folder may move\n${all}`);
    assert.equal(run.out.mvApp!.status, 0, all);
    // The labels followed, after the renames stood: the arbiter knows both
    // new paths (the next session's guard reads them).
    const labelled = await derivedPaths(s);
    for (const p of [join(s.home, ".aws2", "credentials"), join(s.ws, "app2", ".env")]) assert.ok(labelled.includes(p), `${p} labelled: ${labelled.join(" ")}`);
    assert.match(run.out.awsAfter!.text, /\$MDU:/, all);
    assert.match(run.out.envAfter!.text, /\$MDU:/, all);
    for (const b of await toModel(s, run.out)) assert.ok(!raw(b), "no request to the model holds a key's bytes");
  } finally {
    await s.close();
  }
});

test("M3 (guard only, §7.2a): the person saves ~/.aws/credentials through a temporary file and a rename mid-session; the agent then moves the folder; past the rebuild the NEW file reads as a placeholder, never raw", { skip, timeout: 300_000 }, async () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
  const s = await stack("mandu-moved-saved-");
  const NEW_KEY = ["AKIA", "SAVED", "BY", "EDITOR", "MUST", "NOT", "BE", "READ"].join("_");
  const asked = join(s.dir, "asked");
  const saved = join(s.dir, "saved");
  // The person's editor, outside the agent's tree: when the agent asks,
  // write a new file beside the credential and rename it over.
  const cred = join(s.home, ".aws", "credentials");
  const editor = setInterval(() => {
    if (existsSync(asked) && !existsSync(saved)) {
      const tmpf = join(s.home, ".aws", ".credentials.tmp");
      writeFileSync(tmpf, `[default]\naws_secret_access_key=${NEW_KEY}\n`);
      renameSync(tmpf, cred);
      writeFileSync(saved, "1");
    }
  }, 50);
  try {
    const run = await launch(s, {
      before: "cat ~/.aws/credentials",
      wait: `touch '${asked}'; i=0; while [ ! -f '${saved}' ] && [ $i -lt 400 ]; do sleep 0.05; i=$((i+1)); done; [ -f '${saved}' ] && echo saved`,
      mvAws: "mv ~/.aws ~/.aws2",
      after: "sleep 2.5; cat ~/.aws2/credentials",
    });
    const all = show(run.out);
    const rawNew = (t: string): boolean => raw(t) || t.includes(NEW_KEY);
    assert.equal(run.out.wait!.text.trim(), "saved", all);
    for (const [name, o] of Object.entries(run.out)) assert.ok(!rawNew(o.text), `${name}: no raw byte of the old or the saved key\n${all}`);
    // The outcome expected: the guard rebuilds before it moves a folder, so
    // the saved file is held, the move runs, and the saved file is the
    // placeholder under its new path (a refusal here would be a regression
    // of the rebuild, a raw read the bug).
    assert.equal(run.out.mvAws!.status, 0, `the move runs\n${all}`);
    assert.match(run.out.after!.text, /^\[default\]\naws_secret_access_key=\$MDU:\S+\n$/, `the saved file, moved, is its placeholder\n${all}`);
    assert.ok(readFileSync(join(s.home, ".aws2", "credentials"), "utf8").includes(NEW_KEY), "host truth: the moved file is the saved one");
    for (const b of await toModel(s, run.out)) assert.ok(!rawNew(b), "no request to the model holds a key's bytes");
  } finally {
    clearInterval(editor);
    await s.close();
  }
});

/** renameat2(AT_FDCWD, a, AT_FDCWD, b, RENAME_EXCHANGE) from a program the
 *  agent runs (python3, glibc's wrapper): prints `rc=0` or `rc=<errno name>`. */
const EXCHANGE = (a: string, b: string): string =>
  `python3 -c 'import ctypes,errno,sys; l=ctypes.CDLL(None,use_errno=True); r=l.renameat2(-100,sys.argv[1].encode(),-100,sys.argv[2].encode(),2); print("rc=0" if r==0 else "rc="+errno.errorcode[ctypes.get_errno()])' ${a} ${b}`;

test("M4 (guard only, §7.2a): after the folder moves the agent recreates the registered path (a new folder and file there); the moved credential stays the placeholder, the real file is unchanged, and nothing reads raw", { skip, timeout: 300_000 }, async () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
  const s = await stack("mandu-moved-recreate-");
  try {
    const run = await launch(s, {
      mvAws: "mv ~/.aws ~/.aws2",
      mk: "mkdir ~/.aws && printf '[default]\\naws_secret_access_key=PLANTED\\n' > ~/.aws/credentials; echo made=$?",
      moved: "sleep 2.5; cat ~/.aws2/credentials",
      planted: "cat ~/.aws/credentials",
      movedAgain: "cat ~/.aws2/credentials",
    });
    const all = show(run.out);
    assert.equal(run.out.mvAws!.status, 0, all);
    for (const [name, o] of Object.entries(run.out)) assert.ok(!raw(o.text), `${name}: no raw byte\n${all}`);
    // A write to the registered path lands in the session's placeholder copy
    // of that secret (a protected file's writes never reach the real file),
    // and the moved credential, still that secret by its held inode, is
    // served the same copy: the two reads are one text, and it holds no key.
    assert.equal(run.out.moved!.text, run.out.planted!.text, `the moved credential and the registered path are one placeholder copy\n${all}`);
    assert.equal(run.out.movedAgain!.text, run.out.moved!.text, all);
    assert.ok(readFileSync(join(s.home, ".aws2", "credentials"), "utf8").includes(AWS_KEY), "host truth: the real credential is unchanged");
    assert.ok(!existsSync(join(s.home, ".aws", "credentials")) || !readFileSync(join(s.home, ".aws", "credentials"), "utf8").includes(AWS_KEY), "host truth: no copy of the key at the registered path");
    for (const b of await toModel(s, run.out)) assert.ok(!raw(b), "no request to the model holds a key's bytes");
  } finally {
    await s.close();
  }
});

test("M5 (guard only, §7.2a): RENAME_EXCHANGE of ~/.aws with another folder, either way round: with the file held it runs and the credential under the other name is the placeholder; with no pin held (budget 0) it is refused", { skip, timeout: 300_000 }, async () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
  for (const budget of [null, "0"] as const) {
    const s = await stack(`mandu-moved-xchg-${budget ?? "held"}-`);
    try {
      mkdirSync(join(s.home, "other"));
      writeFileSync(join(s.home, "other", "note.txt"), "plain\n");
      const run = await launch(s, {
        xchg: EXCHANGE("~/.aws", "~/other"),
        xchgBack: EXCHANGE("~/other", "~/.aws"),
        after: "sleep 2.5; cat ~/.aws/credentials ~/other/credentials 2>/dev/null",
      }, budget === null ? {} : { MANDU_NET_GUARD_PIN_MAX: budget });
      const all = show(run.out);
      for (const [name, o] of Object.entries(run.out)) assert.ok(!raw(o.text), `budget ${budget}: ${name}: no raw byte\n${all}`);
      if (budget === null) {
        assert.equal(run.out.xchg!.text.trim(), "rc=0", all);
        assert.equal(run.out.xchgBack!.text.trim(), "rc=0", all);
      } else {
        assert.equal(run.out.xchg!.text.trim(), "rc=EACCES", `the folder above an unheld file stays, as the source\n${all}`);
        assert.equal(run.out.xchgBack!.text.trim(), "rc=EACCES", `and as the other side of the exchange\n${all}`);
        assert.ok(existsSync(join(s.home, ".aws", "credentials")), "the credential is where it was");
      }
      assert.match(run.out.after!.text, /aws_secret_access_key=\$MDU:/, all);
      for (const b of await toModel(s, run.out)) assert.ok(!raw(b), "no request to the model holds a key's bytes");
    } finally {
      await s.close();
    }
  }
});

test("M8 (guard only, §7.2a): a folder exchange that would put one registered file on another's registered path (app/.env ↔ lib/.env) is refused before it runs, either way round; both files stay, both read as placeholders", { skip, timeout: 300_000 }, async () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
  const LIB_KEY = ["sk", "proj", "LIBFOLDER", "7731", "Zx".repeat(12)].join("-");
  const s = await stack("mandu-moved-cross-", (ws) => {
    mkdirSync(join(ws, "lib"), { recursive: true });
    writeFileSync(join(ws, "lib", ".env"), `OPENAI_API_KEY=${LIB_KEY}\n`);
    return "version: 1\n";
  });
  try {
    const run = await launch(s, {
      before: "cat app/.env lib/.env",
      xchg: EXCHANGE("app", "lib"),
      xchgBack: EXCHANGE("lib", "app"),
      mvOnto: "mkdir -p elsewhere && mv lib elsewhere/ && mv elsewhere/lib app2 && echo moved",
      after: "sleep 2.5; cat app/.env; cat app2/.env 2>/dev/null",
    });
    const all = show(run.out);
    const rawAny = (t: string): boolean => raw(t) || t.includes(LIB_KEY);
    for (const [name, o] of Object.entries(run.out)) assert.ok(!rawAny(o.text), `${name}: no raw byte\n${all}`);
    assert.match(run.out.before!.text, /\$MDU:[\s\S]*\$MDU:/, `both confined before\n${all}`);
    assert.equal(run.out.xchg!.text.trim(), "rc=EACCES", `app/.env would land on lib/.env: refused\n${all}`);
    assert.equal(run.out.xchgBack!.text.trim(), "rc=EACCES", `and the other way round\n${all}`);
    assert.ok(readFileSync(join(s.ws, "app", ".env"), "utf8").includes(ENV_KEY), "host truth: app/.env is app's");
    // A move of lib to a path no registered file has runs (and its label follows).
    assert.match(run.out.mvOnto!.text, /moved/, all);
    assert.ok(readFileSync(join(s.ws, "app2", ".env"), "utf8").includes(LIB_KEY), "host truth: lib's file, moved to a free path, is lib's");
    assert.match(run.out.after!.text, /\$MDU:/, all);
    for (const b of await toModel(s, run.out)) assert.ok(!rawAny(b), "no request to the model holds a key's bytes");
  } finally {
    await s.close();
  }
});

test("M6 (guard only, §7.2a): a move of ~/.aws to another filesystem (EXDEV: mv copies, then removes): the copy holds the placeholder, the real file is not removed, and nothing reads raw", { skip, timeout: 300_000 }, async (t) => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
  const s = await stack("mandu-moved-xdev-");
  const other = mkdtempSync(join("/dev/shm", "mandu-xdev-"));
  try {
    const dev = (p: string): string => spawnSync("stat", ["-c", "%d", p], { encoding: "utf8" }).stdout.trim();
    if (dev(other) === dev(s.home)) {
      t.skip("/dev/shm is on the home's filesystem here: no cross-mount rename to test");
      return;
    }
    const dest = join(other, "aws");
    const run = await launch(s, {
      mv: `mv ~/.aws '${dest}'`,
      copy: `sleep 2.5; cat '${dest}/credentials'`,
      orig: "cat ~/.aws/credentials",
    });
    const all = show(run.out);
    for (const [name, o] of Object.entries(run.out)) assert.ok(!raw(o.text), `${name}: no raw byte\n${all}`);
    assert.notEqual(run.out.mv!.status, 0, `mv cannot remove the real file\n${all}`);
    assert.ok(readFileSync(join(s.home, ".aws", "credentials"), "utf8").includes(AWS_KEY), "host truth: the real credential is still there");
    if (existsSync(join(dest, "credentials"))) {
      assert.ok(!readFileSync(join(dest, "credentials"), "utf8").includes(AWS_KEY), "host truth: the copy on the other filesystem holds no key");
    }
    assert.match(run.out.orig!.text, /aws_secret_access_key=\$MDU:/, all);
    for (const b of await toModel(s, run.out)) assert.ok(!raw(b), "no request to the model holds a key's bytes");
  } finally {
    rmSync(other, { recursive: true, force: true });
    await s.close();
  }
});

test("M7 (guard only, §7.2a): a file you labelled (policy.yaml, its words look like no key) moved with its folder is the placeholder this session AND the next, where nothing but its label knows it", { skip, timeout: 300_000 }, async () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
  const NOTE = ["quarterly", "plan", "MOVEDNOTE", String(Date.now())].join(" ");
  const s = await stack("mandu-moved-label-", (ws) => {
    mkdirSync(join(ws, "docs"));
    writeFileSync(join(ws, "docs", "notes.txt"), `${NOTE}\n`);
    return `version: 1\npaths:\n  - path: ${join(ws, "docs", "notes.txt")}\n    level: no-model\n`;
  });
  try {
    const a = await launch(s, { before: "cat docs/notes.txt", mv: "mv docs docs2", same: "sleep 2.5; cat docs2/notes.txt" });
    const b = await launch(s, { next: "cat docs2/notes.txt" });
    const all = `${show(a.out)}\n${show(b.out)}`;
    for (const o of [...Object.values(a.out), ...Object.values(b.out)]) assert.ok(!o.text.includes(NOTE), `no raw byte of the labelled file\n${all}`);
    assert.match(a.out.before!.text, /\$MDU:/, `confined before the move\n${all}`);
    assert.equal(a.out.mv!.status, 0, all);
    assert.match(a.out.same!.text, /\$MDU:/, `this session, held by its inode\n${all}`);
    assert.match(b.out.next!.text, /\$MDU:/, `the next session: its label followed the folder\n${all}`);
    assert.ok(readFileSync(join(s.ws, "docs2", "notes.txt"), "utf8").includes(NOTE), "host truth: the file itself is unchanged");
    for (const body of await toModel(s, { ...a.out, ...Object.fromEntries(Object.entries(b.out).map(([k, v]) => [`next-${k}`, v])) })) assert.ok(!body.includes(NOTE), "no request to the model holds the file's words");
  } finally {
    await s.close();
  }
});

test("M2 (guard only, §7.2a): with no file held (pin budget 0), a rename of a folder above a protected file is refused, and the files read as placeholders", { skip, timeout: 300_000 }, async () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
  const s = await stack("mandu-moved-unpinned-");
  try {
    const run = await launch(s, {
      mvAws: "mv ~/.aws ~/.aws2",
      mvApp: "mv app app2",
      mvOther: "mkdir other && mv other other2",
      aws: "sleep 2.5; cat ~/.aws/credentials ~/.aws2/credentials 2>/dev/null",
      env: "cat app/.env app2/.env 2>/dev/null",
    }, { MANDU_NET_GUARD_PIN_MAX: "0" });
    const all = show(run.out);
    assert.notEqual(run.out.mvAws!.status, 0, `a folder above an unheld protected file stays\n${all}`);
    assert.match(run.out.mvAws!.text, /Permission denied/, all);
    assert.notEqual(run.out.mvApp!.status, 0, all);
    assert.equal(run.out.mvOther!.status, 0, `any other folder moves\n${all}`);
    // A refused rename leaves no label behind (they are asked only after a
    // rename stood).
    const labelled = await derivedPaths(s);
    assert.ok(!labelled.some((p) => p.includes("/.aws2/") || p.includes("/app2/")), `no label for a rename that did not stand: ${labelled.join(" ")}`);
    assert.ok(existsSync(join(s.home, ".aws", "credentials")) && existsSync(join(s.ws, "app", ".env")), "both files are where they were");
    for (const [name, o] of Object.entries(run.out)) assert.ok(!raw(o.text), `${name}: no raw byte\n${all}`);
    assert.match(run.out.aws!.text, /\$MDU:/, all);
    for (const b of await toModel(s, run.out)) assert.ok(!raw(b), "no request to the model holds a key's bytes");
  } finally {
    await s.close();
  }
});
