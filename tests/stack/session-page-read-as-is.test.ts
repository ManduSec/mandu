/**
 * session-page-read-as-is — a session page lists, under *Your secrets*, the
 * files the AI read as they were ("Files the AI read as they were"), each
 * with a *Protect it* link that opens Add a rule's file browser at the file
 * (dashboard.md §4.25b *Files the AI read as they were*), across the REAL
 * components: a real ArbiterServer in `secrets`, the real anthropic-proxy in
 * its production wiring (`new ArbiterClientAdapter(data, human)`) with a
 * scripted model behind it, and the real dashboard over the arbiter's store
 * (`ArbiterEventSource`), with the production approvals adapter
 * (`makeApprovalsArbiter`), signed in, and its file browser on the test's
 * home folder. The served product page (its own index.html and home.js) runs
 * in jsdom.
 *
 * `~/mandu-try/.env` is registered; the agent Reads its twin and then the
 * unlabelled `~/mandu-try/notes.txt`, which reaches the model as it was.
 * Then:
 *
 *   F1  the REAL session page (`/api/home/agent`): `readAsIs` lists
 *       `~/mandu-try/notes.txt` once, with its read's time and step, and
 *       not `.env`, whose read the AI got masked;
 *   F2  the served page at `/agents/<id>`: the fold "Files the AI read as
 *       they were (1)" is closed; opened, its row's *Protect it* links
 *       `/rules?file=~/mandu-try/notes.txt`, and a click opens Rules with
 *       notes.txt's row opened in the file browser, the focus on its ⋯;
 *   F3  the oracle: the fold carries paths and times only. No line of
 *       notes.txt is in the fold or in the page's `readAsIs`, and the page
 *       without the fold holds every line the page with it holds; the
 *       registered key's value is in no page, address or answer, and
 *       following the link changed no rule (policy.yaml is as it was).
 *
 * A second session Reads the `.env` twin and 35 unlabelled files:
 *
 *   F4  the page answer sends all 35 (`more` 0); the served fold draws the
 *       first 30 and "5 more files." with *Show them*; pressed, all 35
 *       rows, the focus on the 31st; the 35th row's *Protect it* opens
 *       Rules at that file; no row and no page answer carries a line of a
 *       file, `.env` is never listed, and no rule changed.
 *
 * Every request goes through `pageFetch` (a socket of its own), as a stack
 * test that runs a served page must (served-page-fetch).
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 *
 * Run: npm test  (tests/)
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const VALUE = `sk_live_readAsIs_${process.pid}_00000000`;
const NOTES_LINES = ["standup notes: ship the read-as-is fold", "the staging box is read-as-is-staging.example", "remember the Thursday demo"];
const NOTES = NOTES_LINES.join("\n") + "\n";
const FILE = "~/mandu-try/notes.txt";
const render = (s: string) => s.split("\n").slice(0, -1).map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n") + "\n";

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const fold = (doc: Doc) => doc.getElementById("agent-read-as-is");
const openRow = (doc: Doc) => doc.querySelector("#files-list .row.file.open");

type Msg = { role: string; content: unknown };

/** The real stack for `session` over a home folder holding `~/mandu-try/.env`
 *  (registered by the caller) and the files of `files` under
 *  `~/mandu-try/`: the arbiter in `secrets`, the proxy in its production
 *  wiring before a scripted model, and the dashboard signed in. */
async function stack(session: string, files: Record<string, string>) {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-read-as-is-"));
  dirs.push(tmp);
  const home = join(tmp, "home");
  mkdirSync(join(home, "mandu-try"), { recursive: true });
  const env = join(home, "mandu-try", ".env");
  writeFileSync(env, `STRIPE_KEY='${VALUE}'\nDEBUG=1\n`);
  for (const [name, text] of Object.entries(files)) writeFileSync(join(home, "mandu-try", name), text);
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const policy = join(tmp, "policy.yaml");
  const policyText = "version: 1\npaths: []\n";
  writeFileSync(policy, policyText);
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    policyPath: policy, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const gate = await open(sock);

  const sent: { bodyText: string }[] = [];
  const model = { answers: [] as MockUpstream[] };
  const upstream: UpstreamFetcher = async (a) => {
    const m = model.answers[Math.min(sent.length, model.answers.length - 1)]!;
    const res = await m.fetcher(a);
    sent.push(m.requests.at(-1)!);
    return res;
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await open(sock), await open(humanSock)), upstream, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets, "the production adapter has the secrets surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policy },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;

  const send = async (messages: Msg[]): Promise<void> => {
    const res = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 256, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
  };
  /** The session page once `ready` holds (emission is best-effort and
   *  asynchronous), with its raw answer. */
  const agentPage = async (ready: (p: AgentPageVM) => boolean): Promise<{ page: AgentPageVM | undefined; body: string }> => {
    let page: AgentPageVM | undefined;
    let body = "";
    for (let i = 0; i < 150; i++) {
      const r = await pageFetch(`${base}/api/home/agent?session=${session}`, { headers: { Cookie: ADMIN_COOKIE } });
      if (r.status === 200) {
        body = await r.text();
        page = JSON.parse(body) as AgentPageVM;
        if (ready(page)) break;
      }
      await new Promise((r) => setTimeout(r, 20));
    }
    return { page, body };
  };
  const close = async (): Promise<void> => {
    await dashboard.close();
    await proxy.close();
    for (const c of clients) c.close();
    await arbiter.close();
  };
  return { home, env, policy, policyText, gate, sent, model, send, agentPage, base, close };
}

test("a session page lists the files the AI read as they were, each with Protect it, which opens the file in Rules; never a byte of the file, nor a registered file (secrets axes, explicit)", { timeout: 240_000 }, async () => {
  const session = `read-as-is-${process.pid}`;
  const { home, env, policy, policyText, gate, sent, model, send, agentPage, base, close } = await stack(session, { "notes.txt": NOTES });
  const notes = join(home, "mandu-try", "notes.txt");
  const rendered: string[] = [];
  const addresses: string[] = [];

  try {
    // ── The session: the registered file's twin, then the unlabelled notes ──
    const reg = await gate.registerSecret({ path: env, sessionKey: session });
    assert.ok(/\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.test(reg.twin ?? ""), "the key has its own symbol");
    model.answers = [
      buildToolUseSse({ id: "toolu_env", name: "Read", input: { file_path: env } }),
      buildToolUseSse({ id: "toolu_notes", name: "Read", input: { file_path: notes } }),
      buildTextSse("Your notes say to ship the fold."),
    ].map((sse) => new MockUpstream({ sse }));
    const ask: Msg[] = [{ role: "user", content: "Read .env and my notes." }];
    await send(ask);
    const turn1: Msg[] = [
      ...ask,
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_env", name: "Read", input: { file_path: env } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_env", content: (reg.twin ?? "").split("\n").map((l, i) => `${i + 1}\t${l}`).join("\n") }] },
    ];
    await send(turn1);
    await send([
      ...turn1,
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_notes", name: "Read", input: { file_path: notes } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_notes", content: render(NOTES) }] },
    ]);
    for (const s of sent) assert.ok(!s.bodyText.includes(VALUE), "CONFIDENTIALITY VIOLATION: the key's value reached the model");
    assert.ok(sent.at(-1)!.bodyText.includes(NOTES_LINES[0]!), "notes.txt reached the model as it was: no rule asked to mask it");

    // ── F1: the real session page lists notes.txt, and not .env ──
    const { page, body } = await agentPage((p) => !!p.readAsIs && p.secrets.secrets.length > 0);
    assert.ok(page?.readAsIs, `the page lists the files read as they were: ${body.slice(0, 400)}`);
    assert.deepEqual(page.readAsIs.files.map((f) => f.path), [FILE], "notes.txt once; .env's read reached the AI masked");
    assert.equal(page.readAsIs.more, 0);
    const step = page.story.flatMap((t) => t.steps).find((s) => s.id === page!.readAsIs!.files[0]!.step);
    assert.ok(step && step.kind === "action" && step.outcome === "plain", "its time opens the notes.txt Read, a plain step");
    assert.ok(!body.includes(VALUE), "CONFIDENTIALITY VIOLATION: the session page carries the key's value");
    for (const line of NOTES_LINES) assert.ok(!JSON.stringify(page.readAsIs).includes(line), "the list carries paths and times only");

    // ── F2: the served page: the fold, and Protect it ──
    await servedProductPage(base, `/agents/${encodeURIComponent(session)}`, (doc: Doc) => fold(doc) && !fold(doc).hidden, async (doc: Doc) => {
      const f = fold(doc);
      assert.equal(f.open, false, "closed on load");
      assert.equal(f.querySelector("summary").textContent, "Files the AI read as they were (1)");
      assert.equal(f.querySelector("code").textContent, FILE);
      assert.doesNotMatch(f.textContent, /\.env/);
      const text = doc.body.textContent ?? "";
      // The oracle: the fold adds no line of the file to the page.
      for (const line of NOTES_LINES) assert.ok(!f.innerHTML.includes(line), "CONFIDENTIALITY: the fold carries a line of the file");
      const without = doc.body.cloneNode(true);
      without.querySelector("#agent-read-as-is").remove();
      for (const line of NOTES_LINES) assert.equal(text.includes(line), (without.textContent ?? "").includes(line), "the page holds no line of the file the steps do not already show");
      rendered.push(text);
      f.open = true;
      const link = f.querySelector("a.read-as-is-link");
      assert.equal(link.textContent, "Protect it");
      assert.equal(link.getAttribute("aria-label"), `Protect ${FILE} in Rules`);
      assert.equal(link.getAttribute("href"), `/rules?file=${FILE}`);
      link.focus();
      link.click();
      const w = doc.defaultView;
      await waitWhile(() => !openRow(doc), 20_000);
      addresses.push(w.location.href);
      assert.equal(w.location.pathname + w.location.search, "/rules", "the address drops ?file= once used");
      assert.equal(doc.getElementById("lock-form").hidden, false, "Add a rule's browser is open");
      const row = openRow(doc);
      assert.equal(row.getAttribute("data-path"), notes, "notes.txt's row is opened");
      await waitWhile(() => doc.activeElement !== row.querySelector(".file-more"), 5_000);
      assert.equal(doc.activeElement, row.querySelector(".file-more"), "the focus on its ⋯");
      rendered.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // ── F3: the oracle ──
    assert.equal(rendered.length, 2);
    for (const text of [...rendered, ...addresses]) {
      assert.ok(!text.includes(VALUE), "CONFIDENTIALITY VIOLATION: a page or an address carries the key's value");
      assert.doesNotMatch(text, /\$MDU:/, "nor a token");
    }
    const homeBody = await (await pageFetch(`${base}/api/home`, { headers: { Cookie: ADMIN_COOKIE } })).text();
    assert.ok(!homeBody.includes(VALUE), "CONFIDENTIALITY VIOLATION: Home carries the key's value");
    assert.equal(readFileSync(policy, "utf8"), policyText, "following the link changed no rule");
  } finally {
    await close();
  }
});

test("past 30 files the AI read as they were, Show them draws the rest in place and the last one's Protect it opens it in Rules; never a byte of a file, nor a registered file (secrets axes, explicit)", { timeout: 240_000 }, async () => {
  const session = `read-as-is-many-${process.pid}`;
  const names = Array.from({ length: 35 }, (_, i) => `file-${String(i + 1).padStart(2, "0")}.txt`);
  const lineOf = (name: string) => `the line only ${name} holds, read-as-is-many`;
  const { home, env, policy, policyText, gate, sent, model, send, agentPage, base, close } =
    await stack(session, Object.fromEntries(names.map((nm) => [nm, lineOf(nm) + "\n"])));
  const paths = names.map((nm) => join(home, "mandu-try", nm));
  const rendered: string[] = [];
  const addresses: string[] = [];

  try {
    // ── The session: the registered file's twin, then 35 unlabelled files ──
    const reg = await gate.registerSecret({ path: env, sessionKey: session });
    const reads = [{ id: "toolu_env", path: env, result: (reg.twin ?? "").split("\n").map((l, i) => `${i + 1}\t${l}`).join("\n") },
      ...names.map((nm, i) => ({ id: `toolu_f${i + 1}`, path: paths[i]!, result: render(lineOf(nm) + "\n") }))];
    model.answers = [
      ...reads.map((r) => buildToolUseSse({ id: r.id, name: "Read", input: { file_path: r.path } })),
      buildTextSse("I read them all."),
    ].map((sse) => new MockUpstream({ sse }));
    const messages: Msg[] = [{ role: "user", content: "Read .env and every file in mandu-try." }];
    await send(messages);
    for (const r of reads) {
      messages.push(
        { role: "assistant", content: [{ type: "tool_use", id: r.id, name: "Read", input: { file_path: r.path } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: r.id, content: r.result }] },
      );
      await send(messages);
    }
    for (const s of sent) assert.ok(!s.bodyText.includes(VALUE), "CONFIDENTIALITY VIOLATION: the key's value reached the model");
    assert.ok(sent.at(-1)!.bodyText.includes(lineOf(names[34]!)), "the files reached the model as they were: no rule asked to mask them");

    // ── F4: the page answer sends all 35 ──
    const { page, body } = await agentPage((p) => (p.readAsIs?.files.length ?? 0) >= names.length && p.secrets.secrets.length > 0);
    assert.ok(page?.readAsIs, `the page lists the files read as they were: ${body.slice(0, 400)}`);
    assert.deepEqual(page.readAsIs.files.map((f) => f.path), names.map((nm) => `~/mandu-try/${nm}`), "all 35, in first-read order; .env's read reached the AI masked");
    assert.equal(page.readAsIs.more, 0);
    assert.ok(!body.includes(VALUE), "CONFIDENTIALITY VIOLATION: the session page carries the key's value");
    for (const nm of names) assert.ok(!JSON.stringify(page.readAsIs).includes(lineOf(nm)), "the list carries paths and times only");

    // ── F4: the served fold, Show them, and the last row's Protect it ──
    await servedProductPage(base, `/agents/${encodeURIComponent(session)}`, (doc: Doc) => fold(doc) && !fold(doc).hidden, async (doc: Doc) => {
      const f = fold(doc);
      const rows = () => [...f.querySelectorAll("li")] as Doc[];
      const files = () => rows().filter((li) => li.querySelector("a.read-as-is-link"));
      assert.equal(f.querySelector("summary").textContent, "Files the AI read as they were (35)");
      f.open = true;
      assert.equal(files().length, 30, "the first 30");
      const last = rows().at(-1);
      assert.equal(last.querySelector("span").textContent, "5 more files.");
      const btn = last.querySelector("button.show-rest");
      assert.equal(btn.textContent, "Show them");
      btn.focus();
      btn.click();
      assert.equal(files().length, 35, "every file, in place");
      assert.equal(rows().length, 35);
      assert.equal(doc.activeElement, files()[30], "the focus on the first file it brought");
      assert.doesNotMatch(f.textContent, /\.env/);
      // The oracle: the fold adds no line of any file to the page.
      for (const nm of names) assert.ok(!f.innerHTML.includes(lineOf(nm)), "CONFIDENTIALITY: the fold carries a line of a file");
      const text = doc.body.textContent ?? "";
      const without = doc.body.cloneNode(true);
      without.querySelector("#agent-read-as-is").remove();
      for (const nm of names) assert.equal(text.includes(lineOf(nm)), (without.textContent ?? "").includes(lineOf(nm)), "the page holds no line of a file the steps do not already show");
      rendered.push(text);
      const link = files()[34].querySelector("a.read-as-is-link");
      assert.equal(link.getAttribute("href"), `/rules?file=~/mandu-try/${names[34]}`);
      link.focus();
      link.click();
      const w = doc.defaultView;
      await waitWhile(() => !openRow(doc), 20_000);
      addresses.push(w.location.href);
      assert.equal(w.location.pathname + w.location.search, "/rules", "the address drops ?file= once used");
      const row = openRow(doc);
      assert.equal(row.getAttribute("data-path"), paths[34], "the 35th file's row is opened in Rules");
      await waitWhile(() => doc.activeElement !== row.querySelector(".file-more"), 5_000);
      assert.equal(doc.activeElement, row.querySelector(".file-more"), "the focus on its ⋯");
      rendered.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    assert.equal(rendered.length, 2);
    for (const text of [...rendered, ...addresses]) {
      assert.ok(!text.includes(VALUE), "CONFIDENTIALITY VIOLATION: a page or an address carries the key's value");
      assert.doesNotMatch(text, /\$MDU:/, "nor a token");
    }
    assert.equal(readFileSync(policy, "utf8"), policyText, "following the link changed no rule");
  } finally {
    await close();
  }
});
