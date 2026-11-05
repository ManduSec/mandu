/**
 * long-name-breaks — a name longer than 24 characters breaks only after a
 * slash (a host: after a dot), never at a hyphen inside it, across the REAL
 * components and the served page (dashboard.md §4.25u *A long name breaks
 * at its slashes*). Mandu-new.
 *
 * Until 2026-10-17 a name past WHOLE_MAX (24) was a plain code the browser
 * broke where it could: headless Chromium drew the session page's Your
 * secrets card at 390 px as "token in ~/mandu-" over
 * "try/deploy/staging.conf", and Rules' lists of files the same way. Here a
 * real ArbiterServer runs at the `secrets` axes and registers
 * `~/mandu-try/deploy-keys/staging.env`; its real egress gate refuses the
 * key's send to `uploads.example-storage.net` and asks for an OK. A real
 * DashboardServer over the production adapter (`makeApprovalsArbiter`)
 * serves:
 *
 *   B1  `/api/home`: the waiting card names the long file and the long host
 *       as code (the strings are unchanged by this change);
 *   B2  the served Approvals page in jsdom under its served styles at
 *       320 px: the file is cut after each slash and the host after each
 *       dot into `.name-part`s drawn as inline boxes no wider than their
 *       line; the key stays `.code-whole`; the words read as the strings;
 *   B3  the served Home page: the short card's why line the same, and
 *       its line on which answers last the key and the host;
 *   B4  the oracle: no page or answer read here carries the key's value,
 *       and none a token (`$MDU`).
 *
 * A second test (2026-10-17, *A rule's long name breaks as elsewhere*): the
 * Rules page left two names out of that change, a rule's one-name subject
 * (its chip) and a host's name in *Who may get your secrets*, so Chromium at
 * 320 px drew `uploads.a-very-long-subdomain-name.example.com` there as
 * "uploads.a-very-" / "long-subdomain-" / "name.example.com". A real
 * arbiter holds a policy.yaml whose send rule and whose file binding name
 * that host; the served Rules page, signed in, under its served styles at
 * 320 px:
 *
 *   B5  *Sending data*: the long host's chip is cut at its dots into boxes
 *       no wider than their line, the short host's (`b.example`) stays one
 *       piece, and the row's title names the whole host;
 *   B6  *Who may get your secrets* › Hosts: the long host's name the same;
 *   B7  the oracle: neither the page, `/api/policy/panel` nor
 *       `/api/policy/by-who` carries the file's value or a minted token.
 *
 * A third test (2026-10-17, *The session's folder breaks as elsewhere*):
 * the session page's line under its title names the folder the agent
 * worked in ("…, in ~/projects/…"), and that code was left out too, so
 * Chromium at 390 px drew `~/projects/mandu-try/customer-portal-backend/
 * services` as "…, in ~/projects/mandu-try/customer-" over
 * "portal-backend/services". The REAL anthropic-proxy on its production
 * client (`new ArbiterClientAdapter(data, human)`) carries one Claude Code
 * session whose system prompt names that folder and which reads a `.env`
 * there (the proxy masks its key); the served session page under its
 * served styles at 390 px:
 *
 *   B8  the folder is cut after each slash into boxes no wider than their
 *       line, and the line reads "in ~/projects/…/services" as before;
 *   B9  the oracle: the model never got the value, and neither the page nor
 *       `/api/home/agent`, `/api/home` or `/api/home/history` carries it or
 *       a token.
 *
 * The same test (2026-10-17, *A name in a reply breaks as elsewhere*): the
 * agent's reply (its markdown) was the last text on the session page whose
 * names the browser broke where it could: Chromium at 390 px drew
 * `no-model` as "no-" over "model" and `https://api.stripe.com/v1/customers`
 * as "…/customer" over "s". The model's closing reply names such codes:
 *
 *   B10 a long name in the reply is cut after each slash into boxes no
 *       wider than their line; a short one (`no-model`,
 *       `egress:secret-unbound`) is one such box; a command with a space
 *       (`git status`) is as written; the reply's text is unchanged.
 *   B11 (*A command's code keeps to its column*) the reply keeps its
 *       spaces (`pre-wrap`), and its command's code is `break-spaces`, so
 *       a space at the end of a line takes its room instead of hanging,
 *       box and all, past the column (Chromium at 320 px: 6 px past).
 *   B12 (2026-10-28, *A session page's tab names its session*) the
 *       served page's tab title names the agent, the folder's last name
 *       and when the session started ("Mandu · Claude Code in services ·
 *       Oct 28, 04:31"), and never the prompt, a value or a token.
 *
 * A fourth test (2026-10-30, *The folder stays in sight*): a row on Home and
 * History says "<what you asked> in ~/folder" on one line, and until then a
 * prompt of about 40 characters cut the folder away on a 390 px phone. Three
 * sessions through the REAL proxy (a long prompt in `~/shop`, whose session
 * reads a `.env` the proxy masks; "Fix it." in `~/api`; a short prompt in
 * the long folder above), Home and History in a REAL headless Chromium
 * (Playwright's headless shell; none found: the test skips), signed in, at
 * 390 and 1280 px:
 *
 *   B13 every row's folder box lies inside its line, its last name in sight,
 *       and the line's words are whole in the page; the long prompt is the
 *       part cut (at 390 px), never `~/shop`;
 *   B14 a short line shows whole; the long folder is capped at half its
 *       line and cut at its start ("~" out of sight); nothing runs past the
 *       window;
 *   B15 the oracle: neither page, `/api/home` nor `/api/home/history`
 *       carries the value or a token.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is where the served page lets a name break; the stack supplies
 * the real request it names.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { Readable } from "node:stream";
import { join } from "node:path";
import type { ChildProcess } from "node:child_process";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse, sseEvent } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import type { HomeVM, HomeTextPart } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { stateAxes } from "../lib/axes.js";
import { chromiumBinary, READY, startChromium, stopChromium } from "../lib/chromium.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SESSION = `1791860000-${process.pid}`;
const VALUE = `sk_live_longNameCanary_${process.pid}_00000000`;
const HOST = "uploads.example-storage.net";
const FILE = "~/mandu-try/deploy-keys/staging.env";
const NAMES = ["STRIPE_KEY", FILE, HOST];
/** Each name as a person reads where it may break: its `.name-part`s
 *  joined by " | ", or `[name]` when kept whole. */
const CUTS = ["[STRIPE_KEY]", "~/ | mandu-try/ | deploy-keys/ | staging.env", "uploads. | example-storage. | net"];

const text = (parts: HomeTextPart[]): string => parts.map((p) => p.text).join("");
const codes = (parts: HomeTextPart[]): string[] => parts.filter((p) => p.kind === "code").map((p) => p.text);


test("a long file and a long host break only at their slashes and dots on the served pages of the real stack, short names stay whole, and no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-long-names-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "mandu-try", "deploy-keys"), { recursive: true });
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(sock); await gate.connect();
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const noValue = (body: string, where: string) => {
    assert.ok(!body.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the value`);
  };
  const served = async (f: string): Promise<string> => {
    const r = await pageFetch(base + f);
    assert.equal(r.status, 200, `${f} is served`);
    return r.text();
  };
  try {
    // A registered env file in a folder with a hyphen: its key gets its own symbol.
    const env = join(home, "mandu-try", "deploy-keys", "staging.env");
    writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const d = await gate.desymbolizationDecision({ symbol: keySym!, boundary: "network", destination: HOST, sessionKey: SESSION, scheme: "https" });
    assert.equal(d.allow, false, `the real gate refuses ${HOST}`);
    assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, "and asks for an OK");

    // ── B1: the answer the page reads ──
    const homeText = await served("/api/home");
    noValue(homeText, "/api/home");
    const vm = JSON.parse(homeText) as HomeVM;
    assert.equal(vm.waiting.length, 1, "one request waits for an OK");
    const ask = vm.waiting[0]!;
    assert.equal(text(ask.whyParts), ask.why, "why: its parts are its words");
    assert.deepEqual(codes(ask.whyParts), NAMES, "why it stopped names the key, the long file and the long host as code");

    const sheets = `${await served("/mandu.css")}\n${await served("/app.css")}`;
    const css = resolveCssVars(stylesAt(sheets, 320));
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const cuts = (node: any): string[] => {
      const win = node.ownerDocument.defaultView;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return [...node.querySelectorAll("code")].map((c: any) => {
        const parts = [...c.querySelectorAll(".name-part")];
        if (!parts.length) {
          assert.equal(c.className, "code-whole", `${c.textContent}: a name with no part is a short one, kept whole`);
          return `[${c.textContent}]`;
        }
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        for (const p of parts as any[]) {
          const st = win.getComputedStyle(p);
          assert.equal(st.display, "inline-block", `${p.textContent}: a box of its own`);
          assert.equal(st.maxWidth, "100%", `${p.textContent}: no wider than its line`);
          assert.notEqual(st.whiteSpace, "nowrap", `${p.textContent}: wraps inside when alone too wide`);
        }
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        assert.equal((parts as any[]).map((p) => p.textContent).join(""), c.textContent, "the text is the same");
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return (parts as any[]).map((p) => p.textContent).join(" | ");
      });
    };

    // ── B2: the served Approvals page under its served styles, a 320 px phone ──
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await servedProductPage(base, "/approvals", (doc: any) => doc.querySelectorAll(".ask .ask-detail .v").length === 3, (doc) => {
      const card = doc.querySelector("#approvals-waiting .ask");
      const v = card.querySelectorAll(".ask-detail .v")[0];
      assert.equal(v.textContent, ask.why, "the cell reads as the words");
      assert.deepEqual(cuts(v), CUTS, "why it stopped: the file cut at its slashes, the host at its dots, the key whole");
      assert.deepEqual(cuts(card.querySelector(".ask-sentence")), [CUTS[0], CUTS[2]], "the headline's names the same");
      noValue(doc.body.textContent, "the rendered Approvals page");
      assert.doesNotMatch(doc.body.textContent, /\$MDU/, "the rendered page carries no token");
    }, { css });

    // ── B3: the served Home page: the short card's why line ──
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await servedProductPage(base, "/", (doc: any) => !!doc.querySelector("#home-waiting .ask .ask-sub code"), (doc) => {
      const sub = doc.querySelector("#home-waiting .ask .ask-sub");
      assert.ok(sub.textContent.startsWith(`${ask.why} `), sub.textContent);
      // Then its line on which answers last (dashboard.md §4.34 *Home's card
      // says which answers last*) names the key and the host, cut the same.
      assert.deepEqual(cuts(sub), [...CUTS, CUTS[0], CUTS[2]], "the same names, the same cuts");
      assert.deepEqual(cuts(sub.querySelector(".ask-answers")), [CUTS[0], CUTS[2]]);
      noValue(doc.body.textContent, "the rendered Home page");
      assert.doesNotMatch(doc.body.textContent, /\$MDU/, "the rendered page carries no token");
    }, { css });

    // ── B4: the oracle ──
    for (const route of ["/api/home", "/api/home/history", `/api/home/agent?session=${SESSION}`, "/approvals", "/"]) {
      const body = await (await pageFetch(base + route)).text();
      noValue(body, route);
      assert.doesNotMatch(body, /\$MDU/, `${route} carries no token`);
    }
  } finally {
    await dashboard.close();
    wired?.close();
    gate.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

const LONG_HOST = "uploads.a-very-long-subdomain-name.example.com";
const LONG_CUT = "uploads. | a-very-long-subdomain-name. | example. | com";

test("Rules over the real stack: a rule's long host and a host's name under Who may get your secrets break only at their dots, a short host stays whole, and no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-long-names-rules-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "mandu-try"), { recursive: true });
  const env = join(home, "mandu-try", ".env");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "paths:",
    `  - path: ${env}`,
    "    level: no-model",
    `    bindings: [${LONG_HOST}]`,
    "user_rules:",
    `  - { id: r-0001, kind: release, to: { host: ${LONG_HOST} }, mode: allow }`,
    "  - { id: r-0002, kind: release, to: { host: b.example }, mode: block }",
    "",
  ].join("\n"));
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    policyPath, policyPollMs: 0, adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home, configEnv: { MANDU_HOME: join(tmp, "mandu-home"), MANDU_POLICY_FILE: policyPath, HOME: home },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const signedIn = { Cookie: ADMIN_COOKIE, "X-Mandu-Control": "1" };
  const clean = (body: string, where: string) => {
    assert.ok(!body.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the value`);
    // A minted token (the panel's own help text names the `$MDU:` form).
    assert.doesNotMatch(body, /\$MDU:[A-Za-z_][A-Za-z0-9_-]*\[[0-9a-f]{4,8}\]/, `${where} carries no token`);
  };
  try {
    const sheets = `${await (await pageFetch(`${base}/mandu.css`)).text()}\n${await (await pageFetch(`${base}/app.css`)).text()}`;
    const css = resolveCssVars(stylesAt(sheets, 320));
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    type Doc = any;
    /** A code as a person reads where it may break: its parts joined by
     *  " | ", each an inline box no wider than its line; or its text. */
    const cut = (c: Doc): string => {
      const parts = [...c.querySelectorAll(".name-part")] as Doc[];
      if (!parts.length) return c.textContent;
      const win = c.ownerDocument.defaultView;
      for (const p of parts) {
        const st = win.getComputedStyle(p);
        assert.equal(st.display, "inline-block", `${p.textContent}: a box of its own`);
        assert.equal(st.maxWidth, "100%", `${p.textContent}: no wider than its line`);
      }
      assert.equal(parts.map((p) => p.textContent).join(""), c.textContent, "the text is the same");
      return parts.map((p) => p.textContent).join(" | ");
    };
    const chips = (doc: Doc): Doc[] => [...doc.querySelectorAll("#rules-list .row.rule .rule-text > code")];
    await servedProductPage(base, "/rules", (doc: Doc) => chips(doc).length >= 2 && !!doc.querySelector("#by-who-list .by-who-name"), async (doc: Doc) => {
      // ── B5: Sending data ──
      const byText = new Map(chips(doc).map((c: Doc) => [c.textContent, c]));
      assert.ok(byText.has(LONG_HOST) && byText.has("b.example"), `both send rules are drawn: ${JSON.stringify([...byText.keys()])}`);
      assert.equal(cut(byText.get(LONG_HOST)), LONG_CUT, "the long host's chip is cut at its dots");
      assert.equal(cut(byText.get("b.example")), "b.example", "a short host stays one piece");
      assert.equal(byText.get(LONG_HOST).closest(".rule-text").title, LONG_HOST, "the row's title names the whole host");

      // ── B6: Who may get your secrets › Hosts ──
      doc.querySelectorAll('.by-who-tabs [role="tab"]')[1].click();
      await new Promise((r) => setTimeout(r, 50));
      const host = ([...doc.querySelectorAll("#by-who-list .by-who-subject")] as Doc[]).find((c) => c.textContent === LONG_HOST);
      assert.ok(host, "the Hosts tab names the long host");
      assert.equal(cut(host), LONG_CUT, "its name is cut at its dots");
      clean(doc.body.textContent, "the rendered Rules page");
    }, { headers: signedIn, css });

    // ── B7: the oracle ──
    for (const route of ["/api/policy/panel", "/api/policy/by-who", "/rules"]) {
      const r = await pageFetch(base + route, { headers: signedIn });
      assert.equal(r.status, 200, `${route} is served`);
      clean(await r.text(), route);
    }
  } finally {
    await dashboard.close();
    wired?.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

const FOLDER = "projects/mandu-try/customer-portal-backend/services";
const FOLDER_CUT = "~/ | projects/ | mandu-try/ | customer-portal-backend/ | services";
/** The closing reply: markdown naming a short name, a long one and a command. */
const REPLY = "The key is at `no-model`, so `egress:secret-unbound` refused `https://api.stripe.com/v1/customers`. Run `git status`.";

test("the session page's long folder breaks only at its slashes on the real stack with its served styles, and no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-long-names-folder-"));
  const home = join(tmp, "home");
  const ws = join(home, ...FOLDER.split("/"));
  mkdirSync(ws, { recursive: true });
  const env = join(ws, ".env");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  const sock = join(tmp, "arbiter.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    fileBrowserHome: home, configEnv: { MANDU_HOME: join(tmp, "mandu-home") }, log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const seen: string[] = [];
  // The first turn reads the .env; the second says it is done.
  const readTurn = sseEvent("message_start", { type: "message_start", message: { id: "msg_ln_1", role: "assistant", content: [] } })
    + sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_ln_0", name: "Read", input: {} } })
    + sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify({ file_path: env }) } })
    + sseEvent("content_block_stop", { type: "content_block_stop", index: 0 })
    + sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } })
    + sseEvent("message_stop", { type: "message_stop" });
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = seen.length === 1 ? readTurn : buildTextSse(REPLY, { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: SESSION, log: () => {} });
  const port = await proxy.listen(0);
  const ask = async (messages: unknown[]) => {
    const res = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": SESSION, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({
        model: "claude-opus-4", stream: true, max_tokens: 512, tools: [{ name: "Read", input_schema: { type: "object" } }],
        // Claude Code's own environment list names the folder it works in.
        system: [{ type: "text", text: `You are Claude Code.\n\n# Environment\n - Primary working directory: ${ws}\n - Platform: linux` }],
        messages,
      }),
    });
    assert.equal(res.status, 200, await res.text());
  };
  const clean = (body: string, where: string) => {
    assert.ok(!body.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the value`);
    assert.doesNotMatch(body, /\$MDU/, `${where} carries no token`);
  };
  try {
    const q = "Read the .env file.";
    await ask([{ role: "user", content: q }]);
    await ask([
      { role: "user", content: q },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_ln_0", name: "Read", input: { file_path: env } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_ln_0", content: `     1\tSTRIPE_KEY=${VALUE}\n` }] },
    ]);
    assert.equal(seen.length, 2, "both turns reached the model");
    assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    let agentText = "";
    for (let i = 0; i < 400; i++) {
      agentText = await (await pageFetch(`${base}/api/home/agent?session=${SESSION}`)).text();
      if ((JSON.parse(agentText) as { cwd?: string | null }).cwd === ws) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal((JSON.parse(agentText) as { cwd?: string | null }).cwd, ws, "the session's folder is the one its system prompt names");

    // ── B8: the served session page under its served styles, a 390 px phone ──
    const sheets = `${await (await pageFetch(`${base}/mandu.css`)).text()}\n${await (await pageFetch(`${base}/app.css`)).text()}`;
    const css = resolveCssVars(stylesAt(sheets, 390));
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    type Doc = any;
    await servedProductPage(base, `/agents/${SESSION}`, (doc: Doc) => !!doc.querySelector("#agent-sub .agent-when code") && !!doc.querySelector("#agent-story .reply-text code"), (doc: Doc) => {
      const line = doc.querySelector("#agent-sub .agent-when");
      const code = line.querySelector("code");
      const parts = [...code.querySelectorAll(".name-part")] as Doc[];
      assert.equal([...code.childNodes].every((n: Doc) => n.nodeType === 1 && n.classList.contains("name-part")), true, `only parts inside: ${code.outerHTML}`);
      const win = doc.defaultView;
      for (const p of parts) {
        const st = win.getComputedStyle(p);
        assert.equal(st.display, "inline-block", `${p.textContent}: a box of its own`);
        assert.equal(st.maxWidth, "100%", `${p.textContent}: no wider than its line`);
        assert.notEqual(st.whiteSpace, "nowrap", `${p.textContent}: wraps inside when alone too wide`);
      }
      assert.equal(parts.map((p) => p.textContent).join(" | "), FOLDER_CUT, "the folder is cut at its slashes");
      assert.ok(line.textContent.endsWith(`in ~/${FOLDER}`), `the line reads as before: ${line.textContent}`);
      // ── B10: the names in the reply ──
      const reply = doc.querySelector("#agent-story .reply-text");
      assert.equal(reply.textContent, REPLY.replace(/`/g, ""), "the reply reads as written");
      const codes = Object.fromEntries([...reply.querySelectorAll("code")].map((c: Doc) => [c.textContent, c]));
      for (const name of ["no-model", "egress:secret-unbound"]) {
        const st = win.getComputedStyle(codes[name]);
        assert.equal(st.display, "inline-block", `${name}: one box, never broken at its hyphen`);
        assert.equal(st.maxWidth, "100%", `${name}: no wider than its line`);
        assert.equal(codes[name].children.length, 0, `${name}: one piece`);
      }
      const url = codes["https://api.stripe.com/v1/customers"];
      const urlParts = [...url.querySelectorAll(".name-part")] as Doc[];
      assert.equal(urlParts.map((p) => p.textContent).join(" | "), "https:// | api.stripe.com/ | v1/ | customers", "the long name is cut at its slashes");
      for (const p of urlParts) assert.equal(win.getComputedStyle(p).display, "inline-block", `${p.textContent}: a box of its own`);
      assert.equal(codes["git status"].className, "", "a command with a space is as written");
      assert.equal(win.getComputedStyle(codes["git status"]).display, "inline", "a command with a space wraps at its space");
      // ── B11: a command's code keeps to its column ──
      const cmd = win.getComputedStyle(codes["git status"]);
      assert.equal(win.getComputedStyle(reply).whiteSpace, "pre-wrap", "the reply keeps its spaces");
      assert.equal(cmd.whiteSpace, "break-spaces", "a space at a line's end takes its room inside the code, never hangs past the column");
      assert.equal(cmd.overflowWrap, "anywhere", "a word alone wider than the line still wraps inside");
      clean(doc.body.textContent, "the rendered session page");
      // ── B12: the tab names the session, never what was asked ──
      const title: string = doc.title;
      assert.match(title, /(?:^|· )Mandu · Claude Code in services · [A-Z][a-z]{2} \d{1,2}(?:, \d{4})?, \d{2}:\d{2}$/, `the tab names the session: ${title}`);
      assert.ok(!title.includes(q) && !title.includes(".env"), `the tab never holds the prompt: ${title}`);
      clean(title, "the tab title");
    }, { css });

    // ── B9: the oracle ──
    for (const route of [`/api/home/agent?session=${SESSION}`, "/api/home", "/api/home/history", `/agents/${SESSION}`]) {
      const r = await pageFetch(base + route);
      assert.equal(r.status, 200, `${route} is served`);
      clean(await r.text(), route);
    }
  } finally {
    await proxy.close();
    await dashboard.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

/** A DevTools client over Node's built-in WebSocket. */
async function devtools(wsUrl: string) {
  const ws = new WebSocket(wsUrl);
  await new Promise<void>((resolve, reject) => {
    ws.addEventListener("open", () => resolve(), { once: true });
    ws.addEventListener("error", () => reject(new Error(`no DevTools at ${wsUrl}`)), { once: true });
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const waiting = new Map<number, (m: any) => void>();
  ws.addEventListener("message", (ev) => {
    const m = JSON.parse(String(ev.data));
    if (typeof m.id === "number") waiting.get(m.id)?.(m);
  });
  let id = 1;
  return {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    send(method: string, params: Record<string, unknown> = {}): Promise<any> {
      const my = id++;
      return new Promise((resolve) => { waiting.set(my, resolve); ws.send(JSON.stringify({ id: my, method, params })); });
    },
    close: () => ws.close(),
  };
}

const BIN = chromiumBinary();
/** What you asked, 120 characters; the server keeps 80 of it for the row. */
const LONG_ASK = "Read the .env file in this folder, tell me which of its keys the staging deploy still reads, and say where each one is used.";
/** The three sessions of the folder test: a long prompt in a short folder,
 *  a short prompt in a short folder, and a short prompt in the long folder. */
const ROWS = [
  { id: `1791870000-${process.pid}`, ask: LONG_ASK, folder: "shop" },
  { id: `1791870100-${process.pid}`, ask: "Fix it.", folder: "api" },
  { id: `1791870200-${process.pid}`, ask: "Run the tests.", folder: FOLDER },
] as const;
/** One row's line as drawn: its box, its prompt's and its folder's, and
 *  where the folder's first and last characters are. */
interface Line { text: string; line: [number, number]; folder: [number, number]; first: [number, number]; last: [number, number]; promptCut: boolean; folderCut: boolean }

test("Home's and History's rows keep the folder in sight in real Chromium at 390 and 1280 px: a long prompt is cut before it, a long folder at its start, a short line not at all, and no value is shown (secrets axes, explicit)", { skip: BIN === null ? "no headless Chromium (Playwright's headless shell) on this host" : false, timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-long-names-rows-"));
  const home = join(tmp, "home");
  for (const r of ROWS) mkdirSync(join(home, ...r.folder.split("/")), { recursive: true });
  const env = join(home, "shop", ".env");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  const sock = join(tmp, "arbiter.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    fileBrowserHome: home, configEnv: { MANDU_HOME: join(tmp, "mandu-home") }, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(buildTextSse("Done.", { deltas: 1 }), "utf8")]) };
  };
  // One proxy per session, as each launch starts its own.
  const proxies = ROWS.map((r) => new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: r.id, log: () => {} }));
  const clean = (body: string, where: string) => {
    assert.ok(!body.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the value`);
    assert.doesNotMatch(body, /\$MDU/, `${where} carries no token`);
  };
  const profile = join(tmp, "chrome");
  let chrome: ChildProcess | null = null;
  let page: Awaited<ReturnType<typeof devtools>> | null = null;
  try {
    for (const [i, r] of ROWS.entries()) {
      const port = await proxies[i]!.listen(0);
      const ws = join(home, ...r.folder.split("/"));
      const ask = async (messages: unknown[]) => {
        const res = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
          method: "POST",
          headers: { "content-type": "application/json", "x-mandu-session-id": r.id, "anthropic-version": "2023-06-01" },
          body: JSON.stringify({
            model: "claude-opus-4", stream: true, max_tokens: 512, tools: [{ name: "Read", input_schema: { type: "object" } }],
            system: [{ type: "text", text: `You are Claude Code.\n\n# Environment\n - Primary working directory: ${ws}\n - Platform: linux` }],
            messages,
          }),
        });
        assert.equal(res.status, 200, await res.text());
      };
      await ask([{ role: "user", content: r.ask }]);
      // The long prompt's session reads the .env: its proxy masks the key.
      if (r.folder === "shop") {
        await ask([
          { role: "user", content: r.ask },
          { role: "assistant", content: [{ type: "tool_use", id: "toolu_lr_0", name: "Read", input: { file_path: env } }] },
          { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_lr_0", content: `     1\tSTRIPE_KEY=${VALUE}\n` }] },
        ]);
      }
    }
    assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    // What each row says it asked (the server keeps the start of a long prompt).
    const titles: Record<string, string> = {};
    for (let i = 0; i < 400; i++) {
      const h = JSON.parse(await (await pageFetch(`${base}/api/home/history`, { headers: { Cookie: ADMIN_COOKIE } })).text()) as { rows: { id: string; cwd?: string | null; title?: string | null }[] };
      for (const x of h.rows) if (x.title && ROWS.some((r) => r.id === x.id && x.cwd === join(home, ...r.folder.split("/")))) titles[x.id] = x.title;
      if (Object.keys(titles).length === ROWS.length) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(Object.keys(titles).length, ROWS.length, `each session has its prompt and its folder: ${JSON.stringify(titles)}`);
    assert.ok(titles[ROWS[0].id]!.length >= 60, `the long prompt stays long on its row: ${titles[ROWS[0].id]}`);

    const started = await startChromium(BIN!, profile, `${base}${dashboard.adminLoginPath()}`);
    chrome = started.proc;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let target: any = null;
    for (let i = 0; i < 50 && target === null; i++) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const list = (await (await pageFetch(`http://127.0.0.1:${started.port}/json/list`)).json()) as any[];
      target = list.find((x) => x.type === "page") ?? null;
      if (target === null) await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(target, "the page is listed");
    page = await devtools(target.webSocketDebuggerUrl);
    const p = page;
    const evaluate = async (expression: string): Promise<unknown> => (await p.send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true })).result?.result?.value;
    const until = async (expression: string, what: string): Promise<void> => {
      for (let i = 0; i < 250; i++) {
        if (await evaluate(expression) === true) return;
        await new Promise((r) => setTimeout(r, 100));
      }
      assert.fail(`the page never showed ${what}`);
    };
    await until(`${READY} && location.pathname === "/"`, "Home after the sign-in link");
    const ids = JSON.stringify(ROWS.map((r) => r.id));
    /** The rows' lines in `lists`, once each row is drawn there with its folder. */
    const lines = async (lists: string): Promise<{ rows: Record<string, Line>; scroll: number; page: string }> => {
      const sel = (id: string) => lists.split(",").map((l) => `${l.trim()} .row.agent[data-session="${id}"] .prompt-line`).join(", ");
      await until(`${ids}.every((id) => !!document.querySelector(${JSON.stringify(sel("ID"))}.replace(/ID/g, id)))`, `the rows in ${lists}`);
      return JSON.parse(String(await evaluate(`new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(() => done(JSON.stringify((() => {
        const box = (r) => [r.left, r.right];
        const rows = {};
        for (const id of ${ids}) {
          const line = document.querySelector(${JSON.stringify(sel("ID"))}.replace(/ID/g, id));
          const prompt = line.querySelector(".prompt-text"), folder = line.querySelector(".prompt-folder"), t = folder.querySelector("bdi").firstChild;
          const range = document.createRange();
          range.setStart(t, 0); range.setEnd(t, 1);
          const first = box(range.getBoundingClientRect());
          range.setStart(t, t.length - 1); range.setEnd(t, t.length);
          rows[id] = { text: line.textContent, line: box(line.getBoundingClientRect()), folder: box(folder.getBoundingClientRect()), first, last: box(range.getBoundingClientRect()),
            promptCut: prompt.scrollWidth > prompt.clientWidth, folderCut: folder.scrollWidth > folder.clientWidth };
        }
        return { rows, scroll: document.documentElement.scrollWidth - document.documentElement.clientWidth, page: document.body.innerText };
      })())))))`)));
    };
    const [long, short, deep] = ROWS;
    const at = (where: string, width: number, drawn: Awaited<ReturnType<typeof lines>>) => {
      const say = `${where} at ${width} px`;
      for (const r of ROWS) {
        const l = drawn.rows[r.id]!;
        const folder = `~/${r.folder}`;
        assert.equal(l.text, `${titles[r.id]} in ${folder}`, `${say}: the line's words are whole in the page`);
        assert.ok(l.folder[0] >= l.line[0] - 0.5 && l.folder[1] <= l.line[1] + 0.5, `${say}: ${folder}'s box lies inside its line: ${JSON.stringify(l)}`);
        assert.ok(l.last[0] >= l.folder[0] - 0.5 && l.last[1] <= l.folder[1] + 0.5, `${say}: ${folder}'s last name is in sight: ${JSON.stringify(l)}`);
      }
      // A long prompt in a short folder: the prompt is what is cut.
      const a = drawn.rows[long.id]!;
      if (width < 600) assert.ok(a.promptCut, `${say}: the long prompt is cut`);
      assert.ok(!a.folderCut && a.first[0] >= a.folder[0] - 0.5, `${say}: ~/shop is whole: ${JSON.stringify(a)}`);
      // A short line: nothing is cut.
      const b = drawn.rows[short.id]!;
      assert.ok(!b.promptCut && !b.folderCut, `${say}: a short line shows whole: ${JSON.stringify(b)}`);
      // A folder past half its line: capped at half and cut at its start.
      const c = drawn.rows[deep.id]!;
      assert.ok(c.folderCut, `${say}: the long folder is cut: ${JSON.stringify(c)}`);
      assert.ok(c.folder[1] - c.folder[0] <= (c.line[1] - c.line[0]) / 2 + 0.5, `${say}: at most half the line: ${JSON.stringify(c)}`);
      assert.ok(c.first[1] <= c.folder[0] + 0.5, `${say}: cut at its start, "~" out of sight: ${JSON.stringify(c)}`);
      assert.ok(!c.promptCut, `${say}: the short prompt beside it is whole`);
      assert.equal(drawn.scroll, 0, `${say}: nothing runs past the window`);
      clean(drawn.page, say);
    };
    for (const [where, path, lists] of [["Home", "/", "#home-agents, #home-earlier"], ["History", "/history", "#history-list"]] as const) {
      await p.send("Page.navigate", { url: `${base}${path}` });
      await until(`${READY} && location.pathname === ${JSON.stringify(path)}`, where);
      for (const width of [390, 1280]) {
        await p.send("Emulation.setDeviceMetricsOverride", { width, height: 844, deviceScaleFactor: 1, mobile: width < 600 });
        at(where, width, await lines(lists));
      }
    }

    // The oracle: the answers the pages are drawn from.
    for (const route of ["/api/home", "/api/home/history"]) {
      const r = await pageFetch(base + route, { headers: { Cookie: ADMIN_COOKIE } });
      assert.equal(r.status, 200, `${route} is served`);
      clean(await r.text(), route);
    }
  } finally {
    page?.close();
    await stopChromium(chrome, profile);
    for (const x of proxies) await x.close().catch(() => {});
    await dashboard.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
