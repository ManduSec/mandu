/**
 * clean-tree-release.test.ts — the classify op's clean-tree release over a
 * real ArbiterServer (docs/design/confidentiality/clean-tree-release.md §2,
 * rules R1-R8). demo-c4's shape: a repository's `.env` (a registered
 * credential file) and its key, hard-coded once in the code; shell commands
 * that name `.env` without printing it, bound by the guard's records to a
 * tree that read no secret.
 *
 * Offered: git's own output naming `.env` (with the `.env` labelled, and
 * catalog-only), and a `git log -p` line holding the key with the key as its
 * own symbol. Not offered: the axis off; a tree that read a secret raw; a
 * refused connection in it; a call no record binds; a document named beside
 * the `.env`; a `.env` changed since its registration; a command holding a
 * placeholder; `Read`; an output holding a token, a credential shape, an
 * encoded copy of the key, a raw copy of the `.env`, a short value of it.
 *
 * Run: npm run test:component
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

// Made-up values (no real credential).
const KEY = "sk_test_51CleanTree7Qm2Xv9Lk4Tz8Wp3";
const SHORT = "pa55wd";
const DOC_LINE = "The acquisition of Northwind closes in March; keep it quiet.";
const ENV = `STRIPE_SECRET_KEY=${KEY}\nDB_PASSWORD=${SHORT}\nPORT=4242\n`;

type Offer = { text: string; spans: Array<{ start: number; end: number; symbol: string }> };
type Verdict = { confidentiality?: string; raisedBy?: string; pathRelease?: Offer; valueOnly?: Offer };

async function stack(opts: { confidentiality?: boolean; labelEnv?: boolean } = {}) {
  const confidentiality = opts.confidentiality ?? true;
  const dir = mkdtempSync(join(tmpdir(), "mandu-clean-tree-"));
  const ws = join(dir, "ws");
  mkdirSync(join(ws, "storefront", "src"), { recursive: true });
  mkdirSync(join(ws, "memo"), { recursive: true });
  const env = join(ws, "storefront", ".env");
  writeFileSync(env, ENV);
  writeFileSync(join(ws, "storefront", "src", "checkout.js"), "const stripe = Stripe(process.env.STRIPE_SECRET_KEY);\n");
  const doc = join(ws, "memo", "plan.md");
  writeFileSync(doc, `# Plan\n\n${DOC_LINE}\nNothing else.\n`);
  const paths = [{ path: doc, level: "no-model" }, ...(opts.labelEnv === false ? [] : [{ path: env, level: "no-model", bindings: ["api.stripe.com"] }])];
  const human = join(dir, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: human, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality, integrity: false,
    policyDocument: { version: 1, paths } as never,
  });
  await server.listen();
  const c = new ArbiterClient(human);
  await c.connect();
  const session = "ctr";
  if (confidentiality) {
    for (const p of [env, doc]) {
      const r = await c.registerSecret({ path: p, home: dir, sessionKey: session });
      assert.ok(r.symbol, `${p}: ${r.reason}`);
    }
  }
  let n = 0;
  /** One shell call: the proxy's record of its command, the guard's record
   *  of the agent's shell for it (unless `bound` is false), the proxy's
   *  callTaint ask (which binds it), then `before`, then the classify. */
  const call = async (command: string, output: string, o: { tool?: string; bound?: boolean; cwd?: string | null; before?: (root: string) => Promise<void>; params?: Record<string, unknown> } = {}): Promise<Verdict> => {
    const callId = `call_${++n}`;
    const root = `sh-${n}`;
    await c.recordCallCommand({ callId, command, sessionKey: session });
    if (o.bound !== false) await c.recordExecRoot({ procKey: root, ancestors: ["agent-0"], argv: ["/bin/bash", "-c", command], session, callRoot: true, ...(o.cwd === null ? {} : { cwd: o.cwd ?? ws }) });
    if (o.before) await o.before(root);
    await c.callTaint(callId, { command, session });
    return c.classify({ tool: o.tool ?? "Bash", value: output, boundary: "model_context", origin: command, params: o.params ?? { command }, sessionKey: session, callId }) as Promise<Verdict>;
  };
  return { c, ws, env, doc, session, call, done: async () => { c.close(); await server.close(); rmSync(dir, { recursive: true, force: true }); } };
}

const UNTRACK = "(cd storefront && git rm -q --cached .env && printf '.env\\n' >> .gitignore && git add .gitignore && git commit -q -m 'Stop tracking .env' && git status --short --ignored)";
const FILTER = "(cd storefront && git filter-branch --force --index-filter 'git rm -q --cached --ignore-unmatch .env' --prune-empty -- --all 2>&1)";
const LOG_P = "cd storefront && git log --all -p --format='commit %h %s' -- src .env 2>&1";

test("offered: git's own output naming .env, released as it is (the .env labelled)", async () => {
  const k = await stack();
  try {
    for (const [command, out] of [
      [UNTRACK, "!! .env\n"],
      [FILTER, "Cannot rewrite branches: You have unstaged changes.\n"],
      ["cd storefront && git log --all --oneline -- .env", "ea68b4a Move the Stripe key to .env\n"],
    ] as const) {
      const v = await k.call(command, out);
      assert.equal(v.confidentiality, "no-model", `still the path verdict: ${command}`);
      assert.equal(v.raisedBy, undefined);
      assert.deepEqual(v.pathRelease, { text: out, spans: [] }, `${command}: ${JSON.stringify(v)}`);
    }
  } finally { await k.done(); }
});

test("offered: Codex's argv shell, checked by its own elements against the recorded command (folder-listing-compound.md, implementation round 2)", async () => {
  const k = await stack();
  try {
    const argv = ["bash", "-lc", "git rm --cached storefront/.env"];
    const callId = "call_argv";
    await k.c.recordCallCommand({ callId, command: `bash -lc '${argv[2]}'`, sessionKey: k.session });
    await k.c.recordExecRoot({ procKey: "sh-argv", ancestors: ["agent-0"], argv, session: k.session, callRoot: true, cwd: k.ws });
    await k.c.callTaint(callId, { command: `bash -lc '${argv[2]}'`, session: k.session });
    const v = await k.c.classify({ tool: "shell", value: "!! .env\n", boundary: "model_context", origin: `bash -lc '${argv[2]}'`, params: { command: argv, workdir: k.ws }, sessionKey: k.session, treeCallId: callId } as never) as Verdict;
    assert.equal(v.confidentiality, "no-model");
    assert.deepEqual(v.pathRelease, { text: "!! .env\n", spans: [] }, JSON.stringify(v));
  } finally { await k.done(); }
});

test("offered: a catalog-only .env (no label) the launcher registered", async () => {
  const k = await stack({ labelEnv: false });
  try {
    const v = await k.call(UNTRACK, "!! .env\n");
    assert.equal(v.confidentiality, "no-model");
    assert.deepEqual(v.pathRelease, { text: "!! .env\n", spans: [] }, JSON.stringify(v));
  } finally { await k.done(); }
});

test("offered: a `git log -p` line holding the key, the key as its own symbol", async () => {
  const k = await stack();
  try {
    const out = `commit 196115d Initial checkout service\n+const stripe = Stripe("${KEY}");\nerror: unable to read 0d1f2e3c4b5a69788796a5b4c3d2e1f0a9b8c7d6\n`;
    const v = await k.call(LOG_P, out);
    assert.ok(v.pathRelease, JSON.stringify(v));
    const at = out.indexOf(KEY);
    assert.deepEqual(v.pathRelease!.spans.map((s) => [s.start, s.end]), [[at, at + KEY.length]]);
    assert.match(v.pathRelease!.spans[0]!.symbol, /^\$MDU:nomodel_/);
    assert.equal(v.pathRelease!.text, out.replace(KEY, v.pathRelease!.spans[0]!.symbol));
    assert.ok(!v.pathRelease!.text.includes(KEY));
  } finally { await k.done(); }
});

test("not offered: the axis off", async () => {
  const k = await stack({ confidentiality: false });
  try {
    const v = await k.call(UNTRACK, "!! .env\n");
    assert.equal(v.pathRelease, undefined);
  } finally { await k.done(); }
});

test("not offered (R3): a raw read in the tree, a refused connection, a call no record binds", async () => {
  const k = await stack();
  try {
    const raw = await k.call(UNTRACK, "!! .env\n", { before: async (root) => {
      await k.c.processLineage({ childKey: `${root}-reader`, parentKey: root, session: k.session });
      await k.c.taintProcessSecret({ procKey: `${root}-reader`, path: k.env, level: "no-model", app: "node", session: k.session });
    } });
    assert.equal(raw.pathRelease, undefined, "a raw read");
    const refused = await k.call(UNTRACK, "!! .env\n", { before: async (root) => {
      await k.c.recordEgressRefusal({ procKeys: [root], kind: "blocked-destination", sessionKey: k.session });
    } });
    assert.equal(refused.pathRelease, undefined, "a refused connection");
    const unbound = await k.call(UNTRACK, "!! .env\n", { bound: false });
    assert.equal(unbound.pathRelease, undefined, "no record binds the call");
  } finally { await k.done(); }
});

test("not offered (R4): a document named beside the .env, a .env changed since its registration", async () => {
  const k = await stack();
  try {
    // review round 1 (design), finding 1: the counterfactual once answered
    // the whole command string as one empty place, which short-circuited
    // the token scan and called every command public
    const unregistered = join(k.ws, "memo", ".env");
    writeFileSync(unregistered, "OTHER_TOKEN=tok_UnregisteredOther0123456789\n");
    for (const command of [
      "cat memo/plan.md", "/bin/cat memo/plan.md", "cat storefront/.env memo/plan.md", "git show HEAD:memo/plan.md",
      `cat ${unregistered}`, "cd memo && cat .env", "cd storefront && cat ../memo/.env",
      "bash -c 'cd ../memo && cat .env'", "git -C memo show HEAD:.env", "cd storefront; popd; cat .env",
      "cat ~/.ssh/id_rsa",
      // review round 3, finding 1: a secret file that exists only in git
      // history (the empty-place answer once called these public)
      "git log --all -p -- config/.env.production", "git show HEAD~5:config/.env.production", "git log --all -p -- old/.env",
      "git show HEAD:memo/.env", "cd memo && git show HEAD:.env", "git show HEAD:keys/id_ed25519", "git show HEAD:old/credentials.json",
      "cd storefront && git show other-branch:.env",
      // finding 4: a search that reaches another folder's .env
      "find memo -name .env -exec cat {} +", "grep -r X --include=.env .", "x=../memo; cat $x/.env",
      // with exclusion-flags.md: a grep exclusion blanked must not make the
      // whole command read as one empty place
      "grep --exclude-dir=x memo/plan.md", "grep -n KEY --exclude-dir=x storefront/.env memo/plan.md",
    ]) {
      const v = await k.call(command, "x\n");
      assert.equal(v.pathRelease, undefined, `${command}: ${JSON.stringify(v)}`);
    }
    const both = await k.call("git rm -q --cached storefront/.env memo/plan.md && git status --short", "D  memo/plan.md\n");
    assert.equal(both.confidentiality, "no-model");
    assert.equal(both.pathRelease, undefined, "a document named");
    writeFileSync(k.env, `${ENV}NEW_TOKEN=tok_NotYetRegistered0123456789\n`);
    const changed = await k.call(UNTRACK, "!! .env\n");
    assert.equal(changed.pathRelease, undefined, "changed since registration");
  } finally { await k.done(); }
});

test("not offered (R1, R2, R6): Read, a command holding a placeholder, a token in the output", async () => {
  const k = await stack();
  try {
    const read = await k.call(k.env, "!! .env\n", { tool: "Read", params: { file_path: k.env } });
    assert.equal(read.pathRelease, undefined, "Read");
    const ph = await k.call("cd storefront && echo $MDU:nomodel_Read[abcd].STRIPE_SECRET_KEY > /dev/null; git status --short -- .env", "");
    assert.equal(ph.pathRelease, undefined, "a placeholder in the command");
    // review round 3, finding 3: Claude Code's Bash ignores a `workdir`
    const wd = await k.call("cat .env", "x\n", { cwd: null, params: { command: "cat .env", workdir: join(k.ws, "storefront") } });
    assert.equal(wd.pathRelease, undefined, "a workdir the tool does not honour is no start directory");
    const url = await k.call(UNTRACK, "!! .env\n", { params: { command: UNTRACK, note: "file:///tmp/x%20y" } });
    assert.equal(url.pathRelease, undefined, "a file: URL in the input (review round 2)");
    for (const t of ["see $MDU:nomodel_Read[abcd]\n", "see $mdu:x\n"]) {
      const v = await k.call(UNTRACK, t);
      assert.equal(v.pathRelease, undefined, `a token: ${t}`);
    }
  } finally { await k.done(); }
});

test("not offered (R7): a credential shape, an encoded copy of the key, a raw copy of the .env, a short value of it", async () => {
  const k = await stack();
  try {
    const cases: Array<[string, string]> = [
      ["a credential shape no row holds", "!! .env\nold: ghp_0123456789abcdefABCDEF0123456789abcd\n"],
      ["base64 of the key", `!! .env\n${Buffer.from(KEY).toString("base64")}\n`],
      ["a 12-character piece of the key", `!! .env\nrotated from ${KEY.slice(10, 22)}\n`],
      ["the .env raw", ENV],
      ["the short password", `!! .env\nDB pass ${SHORT} ok\n`],
      ["a bare token that reads as a credential (review round 1, finding 2)", "!! .env\nold: Zx9Kp2mWq8Lr5Tv3Nc7Bd1\n"],
    ];
    for (const [why, out] of cases) {
      const v = await k.call(UNTRACK, out);
      assert.equal(v.pathRelease, undefined, `${why}: ${JSON.stringify(v.pathRelease)}`);
    }
  } finally { await k.done(); }
});
