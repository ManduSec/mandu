/**
 * path-row-narrowing.test.ts — confidentiality-plan-15-prompt-filter.md
 * §13.12, "What a path row registers", over the real IPC.
 *
 * A shell result masked whole ONLY because its command names a secret path
 * (the path-derived precaution) used to give every long line of the output
 * as a piece, so a batched read (`.env`, a script and the meeting notes in
 * one command; the live c6 demo on Codex, 2026-10-17) made the notes' lines
 * fingerprints of a row bound nowhere, and the egress tripwire blocked the
 * notes' upload. Now such a row keeps only the lines a registered secret was
 * found in, every credential-shaped line and span, and its whole value, when
 * ALL of: the proxy says `secretBy: "path-rule"`; the arbiter's own classify
 * record says the path rule alone, every reading placed on a file; the row
 * is that symbolize's own exec row, no higher than the path level, with no
 * secret symbol in its origin; the call's tree was bound by the recorder and
 * read no secret raw; every named file is registered as it is on disk. Each
 * condition unmet keeps every line (fail-closed), checked here one by one,
 * through the egress tripwire's own op. A restart keeps the mark.
 *
 * The stack e2e (real openai-proxy and net-proxy, the c6 shape):
 * tests/stack/path-row-bound-upload.test.ts.
 *
 * Mandu-new test. A real ArbiterServer on a temp socket, the real client.
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { linkSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

// Made-up values (no real credential).
const TOKEN = "secret_PathRowUnit7Qm2Xv9Lk4Tz8Wp3Hn6";
const ENV = `NOTION_TOKEN='${TOKEN}'\n`;
const SCRIPT = "#!/bin/sh\n# Add a markdown file to Notion as a new page under the team's notes page.\nset -a; . \"$here/.env\"; set +a\n";
const DEPLOY_LINE = "DEPLOY_KEY=ghp_Zq8vT3nLk2Wp9Rx4Hb7Mc1Fd6Gs0Jy5Ua8Ee2";
const LEAK = `token was ${TOKEN} yesterday`;
const VAULT_LINE = "DB_PASSWORD=correct horse battery staple pony";
const ordinary = (n: number | string): string => `Shipped: the new signup page is live, item ${n}.`;
const notes = (n: number | string): string => `# Team sync, 16 October\n\n${ordinary(n)}\nNext: Mina drafts the October newsletter by Friday.\n`;

interface Stack {
  dir: string;
  ws: string;
  env: string;
  c: ArbiterClient;
  server: ArbiterServer;
  boot(): Promise<void>;
  done(): Promise<void>;
}

async function stack(): Promise<Stack> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-path-row-"));
  const ws = join(dir, "ws");
  for (const d of ["notes-app", "meetings", "memo", "secrets", "other"]) mkdirSync(join(ws, d), { recursive: true });
  const env = join(ws, "notes-app", ".env");
  writeFileSync(env, ENV);
  writeFileSync(join(ws, "notes-app", "add-page.sh"), SCRIPT);
  writeFileSync(join(ws, "memo", "brief.md"), "Deal brief, internal.\n");
  writeFileSync(join(ws, "secrets", "plan.md"), "The acquisition closes in March, keep it quiet.\n");
  writeFileSync(join(ws, "other", ".env"), "OTHER_TOKEN=tok_PathRowOther0123456789abcd\n");
  // The plain files the batches print: a line of one may stop being a piece.
  writeFileSync(join(ws, "meetings", "sync.md"), notes(1));
  for (let m = 2; m <= 40; m++) writeFileSync(join(ws, "meetings", `sync-${m}.md`), notes(m));
  writeFileSync(join(ws, "meetings", "leak.txt"), `${LEAK}\n${DEPLOY_LINE}\n`);
  // A labelled file the guard never confined (not registered), reached
  // by a read the path scan cannot place.
  mkdirSync(join(dir, "vault", "sub"), { recursive: true });
  writeFileSync(join(dir, "vault", ".env"), `${VAULT_LINE}\n`);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, [
    "version: 1", "paths:",
    `  - path: ${env}`, "    level: no-model", "    bindings: [api.notion.com]",
    `  - path: ${join(ws, "memo", "brief.md")}`, "    level: any-model",
    `  - path: ${join(ws, "secrets", "plan.md")}`, "    level: no-model",
    "",
  ].join("\n"));
  const opts = {
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
  };
  const st = { dir, ws, env } as Stack;
  st.boot = async () => {
    st.server = new ArbiterServer(opts);
    await st.server.listen();
    st.c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's and the proxies' channel
    await st.c.connect();
  };
  st.done = async () => { st.c.close(); await st.server.close(); rmSync(dir, { recursive: true, force: true }); };
  await st.boot();
  return st;
}

const SESSION = "pr";
let n = 0;

interface Run {
  /** How the guard bound the call's tree: by the recorder, a guess, none. */
  bind?: "recorder" | "guess" | "none";
  /** The kernel's directory for the call's shell (relative tokens). */
  cwd?: string | null;
  /** A process in the tree read this file raw. */
  rawRead?: string;
  classify?: boolean;
  secretBy?: string | null;
  tool?: string;
  confidentiality?: string;
  originPrefix?: string;
  /** Runs once the proxy has relayed the call (the command's own effects). */
  afterRelay?: () => void;
}

/** One Bash call as the anthropic-proxy relays it; returns its row. */
async function run(k: Stack, command: string, output: string, o: Run = {}): Promise<string> {
  const callId = `call_pr_${n++}`;
  const bind = o.bind ?? "recorder";
  const proc = `sh-${callId}`;
  if (bind === "recorder") {
    await k.c.recordCallCommand({ callId, command, sessionKey: SESSION });
    await k.c.recordExecRoot({ procKey: proc, ancestors: ["agent-pr-0"], argv: ["/bin/bash", "-c", command], session: SESSION, callRoot: true, ...(o.cwd !== null ? { cwd: o.cwd ?? k.ws } : {}) });
  } else if (bind === "guess") {
    await k.c.recordExecRoot({ procKey: proc, argv: ["/bin/bash", "-c", command], session: SESSION });
  }
  if (o.afterRelay) { await new Promise((r) => setTimeout(r, 20)); o.afterRelay(); }
  if (o.rawRead) {
    await k.c.processLineage({ childKey: `${proc}-child`, parentKey: proc });
    await k.c.taintProcessSecret({ procKey: `${proc}-child`, path: o.rawRead, level: "no-model", app: "cat", session: SESSION });
  }
  await k.c.callTaint(callId, { command, session: SESSION });
  if (o.classify !== false) {
    const v = await k.c.classify({ tool: "Bash", value: output, boundary: "model_context", origin: command, params: { command }, sessionKey: SESSION, callId });
    assert.ok(v.confidentiality !== undefined && v.confidentiality !== "public", `the command names a secret path: ${JSON.stringify(v)}`);
    assert.equal((v as { namedFiles?: unknown }).namedFiles, undefined, "the placed files never leave the arbiter");
  }
  const secretBy = o.secretBy === undefined ? "path-rule" : o.secretBy;
  return k.c.symbolize({
    tool: o.tool ?? "Bash", value: output, origin: `${o.originPrefix ?? ""}${command}`, sessionKey: SESSION, callId,
    confidentiality: o.confidentiality ?? "no-model", integrity: "trusted",
    ...(secretBy !== null ? { secretBy } : {}),
  });
}

/** The rows the egress tripwire holds `text` for at `destination`. */
async function trips(k: Stack, text: string, destination = "httpbin.org"): Promise<string[]> {
  const r = await k.c.egressFingerprintScan({ surfaces: [{ where: "body", text }], destination });
  return r.hits.map((h) => h.symbol);
}

async function twinOf(k: Stack): Promise<string> {
  const reg = await k.c.registerSecret({ path: k.env, sessionKey: SESSION });
  assert.ok(typeof reg.twin === "string" && !reg.twin.includes(TOKEN), JSON.stringify(reg));
  return reg.twin as string;
}

const batch = (k: Stack, m: number | string, extra = ""): { command: string; output: string } => ({
  command: `cat ${k.env} ${join(k.ws, "notes-app", "add-page.sh")} ${join(k.ws, "meetings", `sync-${m}.md`)}${extra}`,
  output: "",
});

test("the c6 batch: a path row keeps no ordinary line, so the notes reach their host; a registered value, a credential line and the whole value stay pieces; a restart keeps it", async () => {
  const k = await stack();
  try {
    const twin = await twinOf(k);
    // 1. the batch, relative paths read where the kernel says the shell ran
    const command = "cat notes-app/.env notes-app/add-page.sh meetings/sync.md";
    const output = `${twin}${SCRIPT}${notes(1)}`;
    const row = await run(k, command, output);
    assert.match(row, /^\$MDU:nomodel_Bash\[/);
    const check = async (when: string): Promise<void> => {
      assert.ok(!(await trips(k, `{"content":"${ordinary(1)}"}`, "api.notion.com")).includes(row), `${when}: an ordinary line is no fingerprint at the token's host`);
      assert.ok(!(await trips(k, ordinary(1))).includes(row), `${when}: nor anywhere (the notes are no secret)`);
      assert.ok(!(await trips(k, "# Add a markdown file to Notion as a new page under the team's notes page.")).includes(row), `${when}: a script line neither`);
      assert.ok((await trips(k, `x ${output} y`)).includes(row), `${when}: the whole value stays a piece`);
      assert.ok((await trips(k, `a ${TOKEN} b`)).length > 0, `${when}: the token itself still trips (its own row)`);
    };
    await check("before the restart");

    // 2. what stays: a line holding a registered value, a credential line
    const out2 = `${twin}${notes(2)}${LEAK}\n${DEPLOY_LINE}\n`;
    const row2 = await run(k, "cat notes-app/.env meetings/sync-2.md meetings/leak.txt", out2);
    assert.ok(!(await trips(k, ordinary(2))).includes(row2), "the ordinary line goes");
    assert.ok((await trips(k, `> ${LEAK}`)).includes(row2), "a line a registered secret was found in stays a piece of the row (though a named plain file holds it)");
    assert.ok((await trips(k, `> ${DEPLOY_LINE}`)).includes(row2), "a credential-shaped line stays a piece");
    assert.ok((await trips(k, "ghp_Zq8vT3nLk2Wp9Rx4Hb7Mc1Fd6Gs0Jy5Ua8Ee2")).includes(row2), "and its span");

    k.c.close();
    await k.server.close();
    await k.boot();
    await check("after the restart, with no re-send");
  } finally { await k.done(); }
});

test("a leading cd (the c1 demo, Claude Code): `cd <abs> && …; cat .env` is placed in that folder, so its row is narrowed", async () => {
  const k = await stack();
  try {
    const twin = await twinOf(k);
    // the shell starts in the workspace; the command moves to the app first
    const command = `cd ${join(k.ws, "notes-app")} && ls; echo ---; cat add-page.sh 2>/dev/null; echo ---; cat ../meetings/sync-30.md; cat ${join(k.ws, "meetings", "sync-31.md")}; echo ---ENV---; cat .env 2>/dev/null`;
    const output = `add-page.sh\n---\n${SCRIPT}---\n${notes(30)}${notes(31)}---ENV---\n${twin}`;
    const row = await run(k, command, output);
    assert.match(row, /^\$MDU:nomodel_Bash\[/);
    assert.ok(!(await trips(k, ordinary(31))).includes(row), "a line of a plain file named by its absolute path goes");
    assert.ok(!(await trips(k, "# Add a markdown file to Notion as a new page under the team's notes page.")).includes(row), "a line of a plain file named relative to the cd goes");
    // `../meetings/sync-30.md` has a `..` segment: placed nowhere, its line stays
    assert.ok((await trips(k, ordinary(30))).includes(row), "a line of a file the scan cannot place stays a piece");
    assert.ok((await trips(k, `x ${output} y`)).includes(row), "the whole value stays a piece");
    assert.ok((await trips(k, `a ${TOKEN} b`)).length > 0, "the token itself still trips (its own row)");
  } finally { await k.done(); }
});

test("a leading relative cd (2026-10-19): `cd notes-app && …; cat .env` is placed below the kernel's directory for the shell, so its row is narrowed", async () => {
  const k = await stack();
  try {
    const twin = await twinOf(k);
    // the shell starts in the workspace (the kernel's record); the command moves to the app first
    const command = `cd notes-app && ls; echo ---; cat add-page.sh 2>/dev/null; cat ${join(k.ws, "meetings", "sync-37.md")}; echo ---ENV---; cat .env 2>/dev/null`;
    const output = `add-page.sh\n---\n${SCRIPT}${notes(37)}---ENV---\n${twin}`;
    const row = await run(k, command, output);
    assert.match(row, /^\$MDU:nomodel_Bash\[/);
    assert.ok(!(await trips(k, ordinary(37))).includes(row), "a line of a plain file named by its absolute path goes");
    assert.ok(!(await trips(k, "# Add a markdown file to Notion as a new page under the team's notes page.")).includes(row), "a line of a plain file named relative to the cd goes");
    assert.ok((await trips(k, `x ${output} y`)).includes(row), "the whole value stays a piece");
    assert.ok((await trips(k, `a ${TOKEN} b`)).length > 0, "the token itself still trips (its own row)");
  } finally { await k.done(); }
});

test("a leading cd that fails (2026-10-19, battery m1r2): `cd notes-app; …` from a shell already in notes-app is placed where it started, so its row is narrowed; the folder there is read as entered", async () => {
  const k = await stack();
  try {
    const twin = await twinOf(k);
    const app = join(k.ws, "notes-app");
    // Claude Code's shell kept an earlier call's directory: the `cd` fails, `;` runs the rest from notes-app
    const command = `cd notes-app; ls -la; echo ---; cat add-page.sh 2>/dev/null; cat ${join(k.ws, "meetings", "sync-38.md")} | head -50; echo ---ENV---; cat .env 2>/dev/null`;
    const cdError = "/bin/bash: line 1: cd: notes-app: No such file or directory";
    const listing = "-rw-r--r--  1 ci ci  123 Oct 19 04:39 add-page.sh";
    const output = `${cdError}\ntotal 8\n${listing}\n---\n${SCRIPT}${notes(38)}---ENV---\n${twin}`;
    const row = await run(k, command, output, { cwd: app });
    assert.match(row, /^\$MDU:nomodel_Bash\[/);
    assert.ok(!(await trips(k, ordinary(38))).includes(row), "a line of a plain file named by its absolute path goes");
    assert.ok(!(await trips(k, "# Add a markdown file to Notion as a new page under the team's notes page.")).includes(row), "a line of a plain file named relative to where the command started goes");
    assert.ok((await trips(k, `> ${cdError}`)).includes(row), "the shell's own error line: no file holds it, it stays a piece");
    assert.ok((await trips(k, `> ${listing}`)).includes(row), "a listing line: no file holds it, it stays a piece");
    assert.ok((await trips(k, `x ${output} y`)).includes(row), "the whole value stays a piece");
    assert.ok((await trips(k, `a ${TOKEN} b`)).length > 0, "the token itself still trips (its own row)");

    // the oracle: the folder IS there (the cd entered it), so the rest is
    // placed in it, where no .env is registered: not narrowed
    mkdirSync(join(app, "notes-app"));
    const entered = `cd notes-app; cat ${join(k.ws, "meetings", "sync-39.md")}; cat .env 2>/dev/null`;
    const row2 = await run(k, entered, `${notes(39)}${twin}`, { cwd: app });
    assert.ok((await trips(k, `x ${ordinary(39)} y`)).includes(row2), "a folder that is there: the cd may have entered it; the ordinary line stays a piece");
  } finally { await k.done(); }
});

test("each condition unmet keeps every line a piece (fail-closed)", async () => {
  const k = await stack();
  try {
    const twin = await twinOf(k);
    const abs = (m: number): { command: string; output: string } => {
      const b = batch(k, m);
      return { command: b.command, output: `${twin}${SCRIPT}${notes(m)}` };
    };
    // control: the same shape with every condition met narrows
    const ok = abs(10);
    const okRow = await run(k, ok.command, ok.output);
    assert.ok(!(await trips(k, ordinary(10))).includes(okRow), "control: narrowed");

    const cases: Array<[number, string, (m: number) => Promise<string>]> = [
      [11, "no secretBy from the proxy", (m) => { const b = abs(m); return run(k, b.command, b.output, { secretBy: null }); }],
      [12, "another secretBy", (m) => { const b = abs(m); return run(k, b.command, b.output, { secretBy: "value-backstop" }); }],
      [13, "no classify record of the call", (m) => { const b = abs(m); return run(k, b.command, b.output, { classify: false }); }],
      [14, "a reading not placed on a file (a relative token, no directory known)", (m) => run(k, `cat notes-app/.env ${join(k.ws, "meetings", `sync-${m}.md`)}`, `${twin}${notes(m)}`, { cwd: null })],
      [15, "a leading relative cd with no directory known for the shell (its relative tokens are read nowhere)", (m) => run(k, `cd notes-app && cat .env ${join(k.ws, "meetings", `sync-${m}.md`)}`, `${twin}${notes(m)}`, { cwd: null })],
      [28, "a cd that is not the first command", (m) => run(k, `cat ${join(k.ws, "meetings", `sync-${m}.md`)}; cd notes-app && cat .env`, `${notes(m)}${twin}`)],
      [29, "a leading relative cd to a folder that is not there (the cd fails: the rest is placed where the shell started, where no .env is registered)",(m) => run(k, `cd no-such-app; cat notes-app/.env ${join(k.ws, "meetings", `sync-${m}.md`)}; cat .env`, `${twin}${notes(m)}`)],
      [30, "a leading relative cd read from a directory the shell did not start in (the .env placed where none is registered)", (m) => run(k, `cd notes-app && cat .env ${join(k.ws, "meetings", `sync-${m}.md`)}`, `${twin}${notes(m)}`, { cwd: join(k.ws, "meetings") })],
      [24, "an escaped cd", (m) => run(k, `\\cd notes-app && cat .env ${join(k.ws, "meetings", `sync-${m}.md`)}`, `${twin}${notes(m)}`)],
      [26, "a leading absolute cd the rest undoes (a second cd)", (m) => run(k, `cd ${join(k.ws, "notes-app")} && cd ${k.ws} && cat .env ${join(k.ws, "meetings", `sync-${m}.md`)}`, `${twin}${notes(m)}`)],
      [27, "a leading absolute cd to a folder that is not there (the cd fails: the rest is placed where the shell started, where no .env is registered)",(m) => run(k, `cd ${join(k.ws, "no-such-app")} && cat .env ${join(k.ws, "meetings", `sync-${m}.md`)}`, `${twin}${notes(m)}`)],
      [25, "a .. segment in the secret's token (the kernel reads it through symlinks)", (m) => run(k, `cat lnk/../notes-app/.env ${join(k.ws, "meetings", `sync-${m}.md`)}`, `${twin}${notes(m)}`)],
      [16, "the row above the path level", async (m) => {
        await k.c.registerSecret({ path: join(k.ws, "memo", "brief.md"), sessionKey: SESSION });
        return run(k, `cat ${join(k.ws, "memo", "brief.md")} ${join(k.ws, "meetings", `sync-${m}.md`)}`, `Deal brief, internal.\n${notes(m)}`, { confidentiality: "no-model" });
      }],
      [17, "not an exec tool's row", (m) => { const b = abs(m); return run(k, b.command, b.output, { tool: "Read" }); }],
      [18, "a placeholder in the command", async (m) => {
        const field = (await k.c.registerSecret({ path: k.env, sessionKey: SESSION })).twin!.match(/\$MDU:[a-z]+_Read\[[0-9a-f]+\]\.NOTION_TOKEN/)![0];
        const b = abs(m);
        return run(k, b.command, b.output, { originPrefix: `echo ${field}; ` });
      }],
      [19, "no tree recorded for the call", (m) => { const b = abs(m); return run(k, b.command, b.output, { bind: "none" }); }],
      [20, "a tree found by guess, not by the recorder", (m) => { const b = abs(m); return run(k, b.command, b.output, { bind: "guess" }); }],
      [21, "a raw read of a secret in the tree", (m) => { const b = abs(m); return run(k, b.command, b.output, { rawRead: k.env }); }],
      [22, "a labelled file nobody registered (unconfined)", (m) => run(k, `cat ${join(k.ws, "secrets", "plan.md")} ${join(k.ws, "meetings", `sync-${m}.md`)}`, `The acquisition closes in March, keep it quiet.\n${notes(m)}`)],
      [23, "a registered file changed since its registration", async (m) => {
        const other = join(k.ws, "other", ".env");
        await k.c.registerSecret({ path: other, sessionKey: SESSION });
        writeFileSync(other, "OTHER_TOKEN=tok_PathRowOtherCHANGED9876543210\n");
        return run(k, `cat ${other} ${join(k.ws, "meetings", `sync-${m}.md`)}`, `OTHER_TOKEN=$MDU:x\n${notes(m)}`);
      }],
    ];
    for (const [m, why, make] of cases) {
      const row = await make(m);
      assert.ok((await trips(k, `x ${ordinary(m)} y`)).includes(row), `${why}: the ordinary line stays a piece of ${row}`);
    }
  } finally { await k.done(); }
});

test("review of §13.12: a line no named plain file holds stays a piece, so a secret read by a route the path scan cannot place is still a tripwire", async () => {
  const k = await stack();
  try {
    const twin = await twinOf(k);
    const vault = join(k.dir, "vault", ".env");
    // `narrows`: since 2026-10-17 the scan also reads a token as the shell
    // reads it (confidentiality.md §6, "A directory change only raises"), so
    // `.e""nv` is the secret `.env` it spells: a reading no plain file
    // places, which keeps the record from narrowing at all (every line stays
    // a piece, fail-closed).
    const cases: Array<[number, string, string, boolean]> = [
      [31, "command substitution", `cat notes-app/.env $(printf ${join(k.dir, "vault")}/%s .e""nv) meetings/sync-31.md`, false],
      [32, "find -exec", `find ${join(k.dir, "vault")} -maxdepth 1 -name '.e*' -exec cat {} + ; cat notes-app/.env meetings/sync-32.md`, true],
      [33, "a quoted split name", `cat notes-app/.env ${join(k.dir, "vault")}/.e""nv meetings/sync-33.md`, false],
    ];
    for (const [m, why, command, narrows] of cases) {
      const row = await run(k, command, `${VAULT_LINE}\n${twin}${notes(m)}`);
      const hits = await trips(k, `x ${ordinary(m)} y`);
      assert.equal(!hits.includes(row), narrows, `${why}: the notes' line (a named plain file holds it) ${narrows ? "goes" : "stays: the quoted name reads as the secret, unplaced"}`);
      assert.ok((await trips(k, `> ${VAULT_LINE}`)).includes(row), `${why}: the vault's line (${vault}) stays a piece`);
    }
  } finally { await k.done(); }
});

test("second review of §13.12: a line is attributed only to a plain file of one link, unchanged since the call was relayed; a pseudo file is never read", async () => {
  const k = await stack();
  try {
    const twin = await twinOf(k);
    const vault = join(k.dir, "vault", ".env");
    // the call writes the vault's text into a plain file, then prints it
    const scratch = join(k.ws, "meetings", "scratch.md");
    const r1 = await run(k, `find ${join(k.dir, "vault")} -name '.e*' -exec cat {} + > meetings/scratch.md; cat notes-app/.env meetings/scratch.md meetings/sync-34.md`,
      `${twin}${VAULT_LINE}\n${notes(34)}`, { afterRelay: () => writeFileSync(scratch, `${VAULT_LINE}\n`) });
    assert.ok((await trips(k, `> ${VAULT_LINE}`)).includes(r1), "a file the call wrote holds no attributable line");
    assert.ok(!(await trips(k, `x ${ordinary(34)} y`)).includes(r1), "the notes' line still goes");
    // a hard link to the vault, named as a plain file
    const linked = join(k.ws, "meetings", "linked.md");
    linkSync(vault, linked);
    const r2 = await run(k, `cat notes-app/.env meetings/linked.md meetings/sync-35.md`, `${twin}${VAULT_LINE}\n${notes(35)}`);
    assert.ok((await trips(k, `> ${VAULT_LINE}`)).includes(r2), "a file of two links holds no attributable line");
    // a size-0 pseudo file that reads without end is never read
    const t0 = Date.now();
    const r3 = await run(k, `cat notes-app/.env meetings/sync-36.md # /proc/${process.pid}/pagemap`, `${twin}${notes(36)}`);
    assert.ok(Date.now() - t0 < 10_000, "the symbolize returned at once");
    assert.ok(!(await trips(k, `x ${ordinary(36)} y`)).includes(r3), "and the notes' line goes");
  } finally { await k.done(); }
});
