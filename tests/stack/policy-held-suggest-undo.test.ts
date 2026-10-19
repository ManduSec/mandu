/**
 * policy-held-suggest-undo e2e — first-session tour item 17, the part left
 * after !963: while a relaxing hand edit of policy.yaml waits in Approvals,
 * `mandu policy suggest` and the dashboard's Undo were refused ("decide that
 * change first"), and a re-save of the held edit dropped its comments.
 *
 * Across the real components: a REAL ArbiterServer (file-backed law, the
 * hand-edit poll running), `mandu policy suggest` over its production path
 * (`realPolicySuggestDeps()`: the ops it sends on the data socket; only the
 * arbiter lookup and the terminal injected) over a REAL fixture repository
 * (a deploy key committed, then deleted), and the dashboard's HTTP routes
 * over the production wiring (`makeApprovalsArbiter`, a real
 * DashboardServer: History's Undo, the Approvals verdict):
 *
 *   1. a hand edit that binds the billing key to a host is held; the card
 *      is on Approvals;
 *   2. `mandu policy suggest` applies the deploy key's lock: in force at
 *      once; the file keeps the hand edit, with the lock and EVERY comment
 *      of the person's file; one card, filed again for the new bytes;
 *   3. History's Undo of an earlier agent lock: done (200), in force; the
 *      file keeps the hand edit and its comments; one card;
 *   4. Approving the card makes the hand edit the law, the file untouched;
 *   5. THE INVARIANT (fail-closed): the billing key is never released to the
 *      host the held edit binds it to until the human approves it, after the
 *      suggestion, after the Undo; then only there. No secret value in the
 *      command's output, the dashboard's answers or policy.yaml.
 *
 * And the refusal left after !1095 (a second test): a suggestion the held
 * edit cannot take as well is refused until the hold is answered, and
 * `mandu policy suggest` says so in words that say what to do (answer the
 * change in Approvals, then run it again), not "Run this again"; answered,
 * the same command applies it. The CLI tells that refusal from a moved
 * file by the arbiter's words, pinned here to `StalePolicyError`.
 *
 * Secrets axes (confidentiality ON, integrity OFF), stated below.
 * policy-surface.md §8.4.6; confidentiality-plan-14-policy-suggestions.md
 * §5.3; dashboard.md §4.25j.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import type { EventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { HELD_EDIT_LINE, HELD_EDIT_REFUSAL_RE, realPolicySuggestDeps, runPolicySuggest, type PolicySuggestDeps } from "../../launcher/src/policy-suggest.js";
import { StalePolicyError } from "../../arbiter/policy/policy-document-store.js";
import type { Layout } from "../../launcher/src/services/layout.js";
import { randomSecretBody } from "../../arbiter/test/helpers/random-secret.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the server pins them below

// Assembled at run time: no key-shaped literal in this file.
const KEY_BODY = randomSecretBody(96);
const PEM = `-----BEGIN OPENSSH ` + `PRIVATE KEY-----\n${KEY_BODY}\n-----END OPENSSH PRIVATE KEY-----\n`;
const BILLING_BODY = randomSecretBody(32);
const RUNS = [KEY_BODY, BILLING_BODY].flatMap((b) => Array.from({ length: b.length - 7 }, (_, i) => b.slice(i, i + 8)));

function noValue(what: string, s: string): void {
  const hit = RUNS.find((r) => s.includes(r));
  assert.equal(hit, undefined, `${what} carries an 8-character run of a secret's body`);
}

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

async function waitFor<T>(what: string, probe: () => Promise<T | undefined>): Promise<T> {
  for (let i = 0; i < 250; i++) {
    const v = await probe();
    if (v !== undefined) return v;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error(`timed out waiting for ${what}`);
}

/** No recorded sessions: the routes this test calls read none. */
const noSessions: EventSource = {
  async listSessions() { return []; },
  async readEvents() { return []; },
  subscribe() { return () => {}; },
  close() {},
};

/** The person's own file: every comment here must survive the arbiter's writes. */
const COMMENTS = [
  "# Team policy. Ask Dana before you loosen anything.",
  "  # the billing key",
  "# kept by hand",
];
function law(env: string): string {
  return [
    COMMENTS[0],
    "version: 1",
    "",
    "paths:",
    COMMENTS[1],
    `  - path: ${env}   # prod`,
    "    level: no-model",
    "",
  ].join("\n");
}

test("tour 17 [secrets]: suggest and Undo work while a hand edit waits; the held edit keeps its comments; nothing is released before the human says so", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-t17b-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const repo = join(home, "proj");
  mkdirSync(repo, { recursive: true });
  const env = join(home, "billing", ".env");
  mkdirSync(join(home, "billing"));
  writeFileSync(env, `STRIPE_KEY=sk_live_${BILLING_BODY}\n`);
  const gitEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
  const git = (...a: string[]): string => execFileSync("git", a, { cwd: repo, env: gitEnv, encoding: "utf8" });
  git("init", "-q", "-b", "main");
  writeFileSync(join(repo, "README.md"), "a project\n");
  git("add", "."); git("commit", "-qm", "init");
  mkdirSync(join(repo, "deploy"));
  writeFileSync(join(repo, "deploy", "id_ed25519"), PEM);
  git("add", "."); git("commit", "-qm", "add deploy key");
  git("rm", "-q", "deploy/id_ed25519"); git("commit", "-qm", "remove the key");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, law(env));

  const dataSock = join(dir, "a.sock");
  const adminSock = join(dir, "admin.sock");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath: policy, policyPollMs: 30, confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  const data = new ArbiterClient(dataSock);
  await data.connect();
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc?.undoPolicyChange && wired.policyDoc.resolvePolicyProposal, "the dashboard's wiring forwards Undo and the verdict");
  const dash = new DashboardServer({ source: noSessions, policyDocArbiter: wired.policyDoc, fileBrowserHome: home, log: () => {}, ...ADMIN_OPTS });
  const base = `http://127.0.0.1:${await dash.listen(0)}`;
  const bodies: string[] = [];
  const call = async (method: "GET" | "POST", path: string, body?: unknown) => {
    const r = await fetch(base + path, { method, headers: { ...CSRF_ADMIN, ...(body !== undefined ? { "Content-Type": "application/json" } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    const text = await r.text();
    bodies.push(text);
    return { status: r.status, body: JSON.parse(text) as any };
  };
  const cards = async () => (await call("GET", "/api/policy/proposals?status=pending")).body.proposals as Array<{ id: string; onDisk?: boolean }>;
  const released = async (host: string): Promise<boolean> =>
    (await data.testFlow({ source: { tool: "Read", origin: env }, destination: host })).egress?.decision.allow === true;
  const lockedInForce = async (): Promise<string[]> =>
    ((await data.policyDocument()).inForce as { paths?: Array<{ path: string }> }).paths?.map((p) => p.path).sort() ?? [];
  const outputs: string[] = [];
  const suggestDeps = (keys: string[]): { d: PolicySuggestDeps; out: string[] } => {
    const out: string[] = [];
    return {
      out,
      d: {
        ...realPolicySuggestDeps(),
        arbiter: async () => ({ sock: dataSock, kind: "resident" as const, axisOn: true, stop: async () => {} }),
        cwd: () => repo,
        isTTY: () => true,
        readKey: async () => keys.shift() ?? "",
        readLine: async () => "",
        out: (s) => { out.push(s); outputs.push(s); },
        err: (s) => { out.push(s); outputs.push(s); },
      },
    };
  };
  const shellEnv = { HOME: home, NO_COLOR: "1", PATH: process.env["PATH"] ?? "/usr/bin:/bin" };
  const notes = join(home, "notes", "id_rsa");

  try {
    // 0. Before any hand edit: the agent locks a file of its own (undone later).
    const agentLock = await data.policyPropose({ edits: [{ op: "lock-path", path: notes, level: "no-model" }], sessionKey: "agent-1" });
    assert.ok(agentLock.applied && "changeId" in agentLock && agentLock.changeId, JSON.stringify(agentLock));
    assert.ok(readFileSync(policy, "utf8").startsWith(`${COMMENTS[0]}\nversion: 1\n`), "the agent's lock kept the person's comments");

    // 1. The hand edit binds the billing key to Stripe: a relaxation, held.
    const hand = readFileSync(policy, "utf8").replace(
      `  - path: ${env}   # prod\n    level: no-model\n`,
      `  - path: ${env}   # prod\n    level: no-model\n    ${COMMENTS[2]}\n    bindings: [api.stripe.com]   # billing goes to Stripe\n`,
    );
    assert.notEqual(hand, readFileSync(policy, "utf8"));
    writeFileSync(policy, hand);
    const [card] = await waitFor("the held card", async () => {
      const c = await cards();
      return c.length ? c : undefined;
    });
    assert.equal(card!.onDisk, true);
    assert.equal(await released("api.stripe.com"), false, "held: the binding is not the law");

    // 2. `mandu policy suggest` applies the deploy key's lock.
    const s = suggestDeps(["a"]);
    assert.equal(await runPolicySuggest([], shellEnv, {} as Layout, s.d), 0, s.out.join(""));
    const screen = s.out.join("");
    assert.match(screen, /Make ~\/proj\/deploy\/id_ed25519 a secret no AI may read/, screen);
    assert.match(screen, /Applied \(change pc-\d+; undo it in the dashboard, under Rule changes in Approvals\)\./, screen);
    assert.doesNotMatch(screen, /Not applied/);
    assert.ok((await lockedInForce()).includes(join(repo, "deploy/id_ed25519")), "the suggestion is in force");
    assert.equal(await released("api.stripe.com"), false, "the suggestion released nothing");
    let text = readFileSync(policy, "utf8");
    for (const c of [...COMMENTS, "# prod", "# billing goes to Stripe"]) assert.ok(text.includes(c), `the file keeps "${c}":\n${text}`);
    assert.match(text, /deploy\/id_ed25519/, "the file has the lock");
    assert.match(text, /bindings: \[api\.stripe\.com\]/, "and the hand edit");
    let now = await cards();
    assert.equal(now.length, 1, "one card");
    assert.notEqual(now[0]!.id, card!.id, "filed again for the file's new bytes");

    // 3. History's Undo of the agent's earlier lock.
    const undo = await call("POST", `/api/policy/changes/${encodeURIComponent(agentLock.changeId!)}/undo`);
    assert.equal(undo.status, 200, JSON.stringify(undo.body));
    assert.equal(undo.body.undone, agentLock.changeId);
    assert.ok(!(await lockedInForce()).includes(notes), "the Undo is in force");
    assert.equal(await released("api.stripe.com"), false, "the Undo released nothing the hand edit asks for");
    text = readFileSync(policy, "utf8");
    assert.doesNotMatch(text, /notes\/id_rsa/, "the file has the Undo");
    for (const c of [...COMMENTS, "# prod", "# billing goes to Stripe"]) assert.ok(text.includes(c), `the file keeps "${c}":\n${text}`);
    assert.match(text, /bindings: \[api\.stripe\.com\]/, "and the hand edit");
    now = await cards();
    assert.equal(now.length, 1, "one card");

    // 4. The human approves the hand edit: the law, the file untouched.
    const before = readFileSync(policy, "utf8");
    const ok = await call("POST", `/api/policy/proposals/${encodeURIComponent(now[0]!.id)}`, { verdict: "approved" });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.equal(await released("api.stripe.com"), true, "approved: released to Stripe");
    assert.equal(await released("paste.example"), false, "and only there");
    assert.equal(readFileSync(policy, "utf8"), before, "the approval wrote nothing over the person's file");
    assert.deepEqual(await cards(), []);

    // 5. The oracle.
    noValue("mandu policy suggest's output", outputs.join("\n"));
    noValue("the dashboard's answers", bodies.join("\n"));
    noValue("policy.yaml", readFileSync(policy, "utf8"));
    // The suggest command's scan may still be finishing in the background.
    for (let i = 0; i < 600; i++) {
      try { await data.suggestPolicy([repo], { home }); break; } catch { await new Promise((r) => setTimeout(r, 100)); }
    }
  } finally {
    await dash.close();
    wired.close();
    data.close();
    await arbiter.close();
  }
});

// ── The refusal left after !1095, in words that say what to do ──────────────
//
// A change the held edit cannot take as well (it names something the held
// edit removes or changes) is still refused until the hold is answered
// (policy-document-store.ts `applyGuarded`: `layer` → null →
// `StalePolicyError(path, true)`). `mandu policy suggest` used to end that
// with "policy.yaml changed on disk meanwhile (…). Run this again." and
// "run this again", which is refused the same way. It now says what waits,
// where it is answered and what to run after.

test("the held-edit words the CLI reads are the arbiter's own (a moved file's are not)", () => {
  assert.match(new StalePolicyError("/p/policy.yaml", true).message, HELD_EDIT_REFUSAL_RE);
  assert.doesNotMatch(new StalePolicyError("/p/policy.yaml").message, HELD_EDIT_REFUSAL_RE);
});

test("tour 17 [secrets]: a suggestion the held edit cannot take is refused until the hold is answered, and `mandu policy suggest` says to answer it in Approvals, then applies after it is", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-t17c-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const repo = join(home, "proj");
  mkdirSync(repo, { recursive: true });
  const env = join(home, "billing", ".env");
  mkdirSync(join(home, "billing"));
  writeFileSync(env, `STRIPE_KEY=sk_live_${BILLING_BODY}\n`);
  const gitEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
  const git = (...a: string[]): string => execFileSync("git", a, { cwd: repo, env: gitEnv, encoding: "utf8" });
  git("init", "-q", "-b", "main");
  writeFileSync(join(repo, "README.md"), "a project\n");
  git("add", "."); git("commit", "-qm", "init");
  mkdirSync(join(repo, "deploy"));
  writeFileSync(join(repo, "deploy", "id_ed25519"), PEM);
  git("add", "."); git("commit", "-qm", "add deploy key");
  git("rm", "-q", "deploy/id_ed25519"); git("commit", "-qm", "remove the key");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, law(env));

  const dataSock = join(dir, "a.sock");
  const adminSock = join(dir, "admin.sock");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath: policy, policyPollMs: 30, confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  const data = new ArbiterClient(dataSock);
  await data.connect();
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  // The one fault injected: the held document cannot take the suggestion's
  // edits (as when they name something the held edit removed). The real
  // `applyGuarded` then refuses with its real error, through the real ops,
  // wire and CLI.
  const store = (arbiter as unknown as { policyDocs: { applyGuarded: (after: unknown, change: unknown, layer: unknown) => unknown } }).policyDocs;
  const realGuarded = store.applyGuarded.bind(store);
  let layerFails = true;
  store.applyGuarded = (after, change, layer) => realGuarded(after, change, layerFails ? () => null : layer);
  const outputs: string[] = [];
  const run = async (keys: string[]): Promise<{ code: number; screen: string }> => {
    const out: string[] = [];
    const d: PolicySuggestDeps = {
      ...realPolicySuggestDeps(),
      arbiter: async () => ({ sock: dataSock, kind: "resident" as const, axisOn: true, stop: async () => {} }),
      cwd: () => repo,
      isTTY: () => true,
      readKey: async () => keys.shift() ?? "",
      readLine: async () => "",
      out: (s) => { out.push(s); outputs.push(s); },
      err: (s) => { out.push(s); outputs.push(s); },
    };
    const code = await runPolicySuggest([], { HOME: home, NO_COLOR: "1", PATH: process.env["PATH"] ?? "/usr/bin:/bin" }, {} as Layout, d);
    return { code, screen: out.join("") };
  };
  const pendingCards = async () => (await admin.policyProposals("pending")).proposals.filter((p) => p.diskHash);
  const lockedInForce = async (): Promise<string[]> =>
    ((await data.policyDocument()).inForce as { paths?: Array<{ path: string }> }).paths?.map((p) => p.path) ?? [];
  const deployKey = join(repo, "deploy/id_ed25519");

  try {
    // A relaxing hand edit: held, its card on Approvals.
    writeFileSync(policy, readFileSync(policy, "utf8").replace(
      `    level: no-model\n`, `    level: no-model\n    bindings: [api.stripe.com]   # billing goes to Stripe\n`,
    ));
    const [card] = await waitFor("the held card", async () => {
      const c = await pendingCards();
      return c.length ? c : undefined;
    });

    // `mandu policy suggest`: [a] on the deploy key's lock is refused, in words that say what to do.
    const first = await run(["a"]);
    assert.equal(first.code, 1, first.screen);
    assert.match(first.screen, /Make ~\/proj\/deploy\/id_ed25519 a secret no AI may read/, first.screen);
    assert.ok(first.screen.includes(HELD_EDIT_LINE), first.screen);
    assert.match(first.screen, /Answer that change there first \(Allow or Not now; `mandu dashboard` opens it\), then run `mandu policy suggest` again\. This suggestion stays waiting\./);
    assert.match(first.screen, /1 not applied\. 1 suggestion stays waiting; one waits on the change to policy\.yaml on the dashboard's Approvals page: answer that change there \(`mandu dashboard`\), then run `mandu policy suggest` again\.\n$/, first.screen);
    assert.doesNotMatch(first.screen, /Run this again|run this again|changed on disk meanwhile/, first.screen);
    // The refusal itself is unchanged: nothing written, the hold and its card stay.
    assert.ok(!(await lockedInForce()).includes(deployKey), "refused: the lock is not in force");
    assert.deepEqual((await pendingCards()).map((c) => c.id), [card!.id], "the same card still waits");

    // Answered as the words say (Not now on the card), the same command applies it.
    const denied = await admin.resolvePolicyProposal(card!.id, "denied", "dashboard");
    assert.ok(denied, "the card is answered");
    await waitFor("the hold to clear", async () => ((await pendingCards()).length === 0 ? true : undefined));
    layerFails = false;
    const second = await run(["a"]);
    assert.equal(second.code, 0, second.screen);
    assert.match(second.screen, /Applied \(change pc-\d+; undo it in the dashboard, under Rule changes in Approvals\)\./, second.screen);
    assert.ok((await lockedInForce()).includes(deployKey), "applied once the hold was answered");

    noValue("mandu policy suggest's output", outputs.join("\n"));
    noValue("policy.yaml", readFileSync(policy, "utf8"));
    // The suggest command's scan may still be finishing in the background.
    for (let i = 0; i < 600; i++) {
      try { await data.suggestPolicy([repo], { home }); break; } catch { await new Promise((r) => setTimeout(r, 100)); }
    }
  } finally {
    store.applyGuarded = realGuarded;
    admin.close();
    data.close();
    await arbiter.close();
  }
});
