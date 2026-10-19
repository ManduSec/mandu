/**
 * rules-held-message-answer.test — on the Rules page a session's answer to
 * a held message reads as a message to the AI, not as a file, across the
 * REAL components (dashboard.md §4.25u *Rules names a held message's
 * answer*). Mandu-new.
 *
 * Until 2026-10-16 Rules knew a past answer only as a send, a command or
 * else a file: the session's answer to a held message (`prompt:<category>#
 * <ref>` × `model:<session>`, plan 15 §7) sat under *Your answers about
 * files* with the file icon, its tooltip the key `model:<session>`, its ⋯
 * offering "Show in the file browser" on that key, and its subject
 * "<category> in your message to the AI" one code chip, while the Approvals
 * card that made it names only the category as code.
 *
 * A real ArbiterServer (secrets) with a prompt pack whose code name asks,
 * the REAL anthropic-proxy on its production clients, a scripted fake
 * model, and the real DashboardServer over `makeApprovalsArbiter`. A
 * message holding the code name is held and answered "Send as written for
 * this session" over the real hold route, as the product answers it:
 *
 *   P1  `/api/policy/panel`, signed in and signed out: the two answers it
 *       keeps (the message's and the session's) are `where: "prompt"`, their
 *       `plain.subjectParts` the category as code and the words as text,
 *       their text the subject byte for byte;
 *   P2  the served Rules page (its own index.html and home.js in jsdom under
 *       the served styles at 320 px): each row is under *Sending data*, with
 *       the Approvals card's icon, and reads "[acme.codename] in your
 *       message to the AI" · "as you wrote it, for that session" (or "…in
 *       that one message"),
 *       its tooltip those words; no *Your answers about files* group; the
 *       session's, opened, offers Remove and no "Show in the file browser";
 *   P3  the oracle: the found text is on none of the panel (either way),
 *       `/api/home` or the rendered page;
 *   P4  each answer's effect says what went to the AI, in Approvals' words:
 *       `plain.effect` and the page say "Sent as written", the session's
 *       menu offers "Sent masked", and neither row says *Always allowed* /
 *       *Always blocked* (§4.25u *A held message's answer says what was
 *       sent*).
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { startScriptedAnthropic } from "../lib/fake-anthropic.js";
import { humanSockIn } from "../lib/human-plane.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the confidentiality axis the prompt filter serves; integrity off

const CODENAME = "kestrelmoorproject";
const CATEGORY = "acme.codename";
/** home.js `ICON.eye`'s first path: the icon Approvals draws for a held
 *  message (`FAMILY_ICON.prompt`). */
const PROMPT_ICON = "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z";

type Part = { kind: string; text: string };
type Plain = { subject: string; subjectParts?: Part[]; reach: string | null; effect: string };
type QueueRow = { id: string; where: string; status: string; scope: string; target: string; plain: Plain };
const shown = (parts: Part[] | undefined) => parts?.map((p) => (p.kind === "code" ? `[${p.text}]` : p.text)).join("") ?? null;

function post(port: number, body: unknown, session: string): Promise<{ status: number; body: string }> {
  const data = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "content-length": String(data.length), "x-mandu-session-id": session } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.end(data);
  });
}

async function waitFor<T>(what: string, f: () => Promise<T | undefined>, ms = 10_000): Promise<T> {
  const until = Date.now() + ms;
  for (;;) {
    const v = await f();
    if (v !== undefined) return v;
    if (Date.now() > until) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

test("Rules over the real arbiter: a session's answer to a held message reads as a message, not a file; the found text on no route (secrets axes, explicit)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-held-answer-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const dataSock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const packs = join(tmp, "prompt-filters");
  mkdirSync(packs);
  writeFileSync(join(packs, "acme.yaml"), `pack: acme-dlp\nversion: 1\nkeywords:\n  - category: ${CATEGORY}\n    words: [${CODENAME}]\n    level: local-model\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, "version: 1\nprompt_filters:\n  filters:\n    acme-dlp: on\n");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, humanSocketPath: humanSock, dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"),
    policyPath, policyPollMs: 0, integrity: false, confidentiality: true, log: () => {}, // the `secrets` axes, stated
    promptPackDir: packs, adminPromptPackDir: null, adminPolicyDir: null, packDir: null, packKeysDir: join(tmp, "keys"), promptHoldMs: 20_000,
  });
  await arbiter.listen();
  const data = new ArbiterClient(dataSock);
  await data.connect();
  const human = new ArbiterClient(humanSock);
  await human.connect();
  const session = `rules-held-answer-${process.pid}`;
  await data.setSessionSpec({ sessionKey: session, spec: "claude-code" });
  const fake = await startScriptedAnthropic({ script: [], fallbackText: "ok" });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstreamOrigin: fake.origin, sessionKey: session, log: () => {} });
  const proxyPort = await proxy.listen(0);
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: dataSock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home, configEnv: { MANDU_HOME: join(tmp, "mandu-home"), MANDU_POLICY_FILE: policyPath, HOME: home },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const call = async (method: "GET" | "POST", path: string, body?: unknown) => {
    const r = await pageFetch(`${base}/api/${path}`, { method, headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: r.status, body: (await r.json().catch(() => ({}))) as Record<string, any> };
  };
  const noFound = (body: string, where: string) => assert.ok(!body.includes(CODENAME), `${where} carries the found text`);
  try {
    const up = await call("POST", "policy/prompt-filters/change", { edit: { op: "set-prompt-action", category: CATEGORY, action: "ask" } });
    assert.equal(up.status, 200, JSON.stringify(up.body));

    // The session opens with a plain message, its title on Home: a title is
    // the session's first message as the AI got it, and the held one goes
    // as written, so it would be its title and carry the found text.
    const ask = (messages: unknown[]) => post(proxyPort, {
      model: "claude-sonnet-4-5", stream: true, max_tokens: 64,
      tools: [{ name: "Read", input_schema: { type: "object" } }], messages,
    }, session);
    const first = [{ role: "user", content: [{ type: "text", text: "start the plan" }] }, { role: "assistant", content: [{ type: "text", text: "ok" }] }];
    assert.equal((await ask(first.slice(0, 1))).status, 200);
    // A message holding the code name is held; the answer is Send as
    // written for this session, over the hold route the product answers on.
    const pending = ask([...first, { role: "user", content: [{ type: "text", text: `plan for ${CODENAME}` }] }]);
    const hold = await waitFor("the hold", async () => {
      const h = await call("GET", "prompt-filters/holds");
      return (h.body["holds"] as Array<{ approvalId: string }> | undefined)?.[0];
    });
    const answered = await call("POST", "prompt-filters/holds/answer", { approvalId: hold.approvalId, answer: "send", scope: "session" });
    assert.equal(answered.status, 200, JSON.stringify(answered.body));
    assert.equal((await pending).status, 200);

    // ── P1: the panel, signed in and signed out ──
    // The answer for the session keeps two standing rows (prompt-filter
    // holds.ts `answer` + `afterResolve`): the message's own and the
    // session's. Rules lists both.
    const ids: Record<"message" | "session", string> = { message: "", session: "" };
    for (const [who, headers] of [["signed in", CSRF_ADMIN], ["signed out", {}]] as const) {
      const r = await pageFetch(`${base}/api/policy/panel`, { headers });
      const body = await r.text();
      assert.equal(r.status, 200, `${who}: ${body}`);
      noFound(body, `the panel ${who}`);
      const queue = (JSON.parse(body) as { panel: { queue: QueueRow[] } }).panel.queue;
      const kept = queue.filter((q) => q.where === "prompt" && q.scope === "always" && q.status === "approved");
      const sessionRow = kept.find((q) => q.target === `model:${session}`);
      const messageRow = kept.find((q) => q.target.startsWith(`model:${session}#turn:`));
      assert.ok(sessionRow && messageRow, `${who}: the session's and the message's answers are listed: ${JSON.stringify(queue)}`);
      for (const [row, reach] of [[sessionRow!, "as you wrote it, for that session"], [messageRow!, "as you wrote it, in that one message"]] as const) {
        assert.equal(row.plain.subject, `${CATEGORY} in your message to the AI`, `${who}: the subject's words are unchanged`);
        assert.equal(shown(row.plain.subjectParts), `[${CATEGORY}] in your message to the AI`, `${who}: the category as code, as the card names it`);
        assert.equal(row.plain.subjectParts!.map((p) => p.text).join(""), row.plain.subject, `${who}: the parts are the subject, byte for byte`);
        assert.equal(row.plain.reach, reach);
        assert.equal(row.plain.effect, "Sent as written", `${who}: P4 the effect says what went to the AI`);
      }
      ids.session = sessionRow!.id;
      ids.message = messageRow!.id;
    }

    // ── P2: the served Rules page at 320 px ──
    const css = async (f: string) => {
      const r = await pageFetch(`${base}/${f}`);
      assert.equal(r.status, 200, `${f} is served`);
      return r.text();
    };
    const styles = resolveCssVars(stylesAt(`${await css("mandu.css")}\n${await css("app.css")}`, 320));
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    type Doc = any;
    const promptRow = (doc: Doc, id: string): Doc => [...doc.querySelectorAll("#rules-list .row.rule")].find((r: Doc) => r.getAttribute("data-rule") === `answer:${id}`);
    /** A node's words and names in order, each name as `[name]`. */
    const drawn = (node: Doc): string => {
      if (node.nodeType === 3) return node.textContent;
      if (node.tagName === "CODE") return `[${node.textContent}]`;
      return [...node.childNodes].map(drawn).join("");
    };
    await servedProductPage(base, "/rules", (doc: Doc) => promptRow(doc, ids.session) !== undefined && promptRow(doc, ids.message) !== undefined, async (doc: Doc) => {
      const win = doc.defaultView;
      const groups = [...doc.querySelectorAll("#rules-list .rules-group")].map((g: Doc) => g.firstChild.textContent);
      assert.ok(!groups.includes("Your answers about files"), `no file group for a message's answer: ${JSON.stringify(groups)}`);
      for (const [which, reach] of [["session", "as you wrote it, for that session"], ["message", "as you wrote it, in that one message"]] as const) {
        const row = promptRow(doc, ids[which]);
        const text = row.querySelector(".rule-text");
        assert.equal(drawn(text.firstElementChild), `[${CATEGORY}] in your message to the AI`, `${which}: the category as code, the words as words`);
        assert.equal(drawn(text.querySelector(".rule-reach")), reach);
        assert.equal(text.title, `${CATEGORY} in your message to the AI`, `${which}: the tooltip is the row's words, not the key model:<session>`);
        for (const c of text.querySelectorAll(".rule-subject code")) {
          assert.ok(c.parentElement.classList.contains("name-fit"), `${c.textContent}: kept whole in its box`);
          assert.equal(win.getComputedStyle(c.parentElement).maxWidth, "100%", `${c.textContent}: no wider than its line`);
        }
        // Its group: the heading before its list is Sending data.
        assert.match(row.parentElement.previousElementSibling.textContent, /^Sending data/, `${which}: under Sending data`);
        assert.equal(row.querySelector(".row-icon path")?.getAttribute("d"), PROMPT_ICON, `${which}: the Approvals card's icon, not the file's`);
        // P4: what went to the AI, never the file rules' Always words.
        assert.doesNotMatch(row.textContent, /Always (allowed|blocked)/, `${which}: no Always words on a message's answer`);
      }
      const menu = promptRow(doc, ids.session).querySelector("select.effect-select");
      assert.deepEqual([...menu.options].map((o: Doc) => o.textContent), ["Sent as written", "Sent masked"], "P4: the session's answer turns around in its own words");
      assert.equal(promptRow(doc, ids.message).querySelector("select.effect-select"), null, "P4: one message's answer has no menu");
      assert.equal(promptRow(doc, ids.message).querySelector(".outcome")?.textContent, "Sent as written", "P4: one message's answer says what went");
      // The session's row opened: Remove, and no file browser.
      promptRow(doc, ids.session).querySelector(".file-more").click();
      const box = await waitFor("the opened row", async () => doc.querySelector("#rules-list .rule-detail") ?? undefined);
      assert.equal(box.getAttribute("aria-label"), `About ${CATEGORY} in your message to the AI`);
      const buttons = [...box.querySelectorAll("button")].map((b: Doc) => b.getAttribute("aria-label") ?? b.textContent);
      assert.ok(buttons.includes(`Remove your answer about ${CATEGORY} in your message to the AI`), `Remove is offered: ${JSON.stringify(buttons)}`);
      assert.ok(!buttons.some((b: string) => /file browser/.test(b)), `no file browser for a message: ${JSON.stringify(buttons)}`);
      noFound(doc.body.textContent ?? "", "the Rules page");
    }, { headers: { Cookie: ADMIN_COOKIE, "X-Mandu-Control": "1" }, css: styles });

    // ── P3: the routes the page reads, signed out ──
    for (const route of ["/api/policy/panel", "/api/home", "/rules"]) {
      const r = await pageFetch(base + route);
      const body = await r.text();
      assert.equal(r.status, 200, `${route}: ${body}`);
      noFound(body, `${route} signed out`);
    }
  } finally {
    await dashboard.close();
    wired?.close();
    await proxy.close();
    await fake.close();
    data.close();
    human.close();
    await arbiter.close();
    resetCurrentPolicyForTests();
    rmSync(tmp, { recursive: true, force: true });
  }
});
