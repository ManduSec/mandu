/**
 * scroll-names.test — on the product page, a box that scrolls by itself says
 * what it holds, across the REAL components (dashboard.md §4.25 *A box that
 * scrolls says what it holds*). Mandu-new.
 *
 * Chromium makes a box that overflows and holds nothing to focus a Tab stop
 * of its own. Until 2026-10-12 none of the page's had a name: a headless
 * Chromium read the model preview's list as every name in it run together,
 * and a suggestion's policy.yaml lines as a "generic" named by all their
 * text. The served page here runs in jsdom with the served mandu.css and
 * app.css applied, so "may scroll" is the page's own computed overflow.
 *
 * Rules, signed in: a real ArbiterServer (secrets) holds a policy.yaml rule
 * on `deploy.token` and walks a work tree of 40 notes and a key the scan
 * finds, starting the arbiter's fake classifier (no model) for a preview; a
 * real DashboardServer over the production adapter serves Rules:
 *
 *   R1  the scan's suggestion, opened, with its policy.yaml lines shown: the
 *       lines are a group named "Save adds these lines to policy.yaml:";
 *   R2  Ask a model too, Names only: the preview's list of 40-odd names is
 *       named by its caption's words, and the classifier got no run;
 *   R3  the suggestion skipped and `deploy.token` made Not secret: Changes
 *       to save's impact box is named "What this changes"; Save asks first,
 *       and its two lists are named "These changes make protection weaker."
 *       and "Files that become less protected:"; Discard saves nothing;
 *   R4  every box on Rules that may scroll and holds nothing to focus has a
 *       role and a name.
 *
 * The agent page: the REAL anthropic-proxy on its production client carries
 * one turn in which a scripted model reads a `.env` and replies with a
 * fenced block; a real dashboard serves the session's page, signed in:
 *
 *   A1  the reply's fenced block is a group named "Code";
 *   A2  "Show the real value" puts the value in a group named "The real
 *       value", never named by the value.
 *
 * The oracle: the classifier's request and the model's turns carry no key,
 * and no page or answer read here carries one but the value the person
 * asked to see on the agent page.
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { request as httpRequest } from "node:http";
import { Readable } from "node:stream";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse, sseEvent } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars } from "../../dashboard/test/unit/ui/css-flatten.js";
import { boxRole, controlName, scrollFaults, scrollStops } from "../../dashboard/test/unit/ui/control-names.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const HERE = dirname(fileURLToPath(import.meta.url));
const FAKE = join(HERE, "..", "..", "arbiter", "test", "helpers", "fake-classifier.mjs");
const KEY = "sk_" + "live_scrollNamesStackCanary00000000001";
const TOKEN = "ghp_scrollNamesStackDeployToken000000000001";
const KEY_FILE = "services/payments/settlement/config/production/app.conf";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const byId = (doc: Doc, id: string) => doc.getElementById(id);

/** The served product styles, tokens resolved, to apply in jsdom. */
async function servedStyles(base: string): Promise<string> {
  const css = async (f: string) => {
    const r = await pageFetch(`${base}/${f}`);
    assert.equal(r.status, 200, `${f} is served`);
    return r.text();
  };
  return resolveCssVars((await css("mandu.css")) + "\n" + (await css("app.css")));
}

/** `box` is one of the stops under `root`, with this role and name. */
function named(root: Doc, box: Doc, role: string, name: string): void {
  assert.ok(box, `the box named "${name}" is drawn`);
  assert.ok(scrollStops(root).includes(box), `"${name}": it may scroll and holds nothing to focus`);
  assert.equal(boxRole(box), role, `"${name}": its role`);
  assert.equal(controlName(box), name);
}

test("Rules over the real arbiter: a suggestion's policy.yaml lines, the model preview's list, what Changes to save changes and the weaker-change question's lists each say what they hold; no key anywhere", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-scroll-names-"));
  const home = join(tmp, "home");
  const repo = join(home, "proj");
  mkdirSync(repo, { recursive: true });
  const gitEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
  execFileSync("git", ["init", "-q", "-b", "main"], { cwd: repo, env: gitEnv });
  const put = (rel: string, body = "ordinary text\n") => {
    mkdirSync(dirname(join(repo, rel)), { recursive: true });
    writeFileSync(join(repo, rel), body);
  };
  put("README.md", "a project\n");
  for (let i = 0; i < 40; i++) put(`notes/meeting-notes-${String(i).padStart(2, "0")}.md`);
  put(KEY_FILE, `[api]\nAPI_TOKEN=${KEY}\n`);
  put("deploy.token", `${TOKEN}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${join(repo, "deploy.token")}\n    level: no-model\n`);
  const record = join(tmp, "record.jsonl");
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {},
    policyClassifier: { argv: [process.execPath, FAKE, "ok", record] },
    policyModel: { env: { PATH: process.env["PATH"], HOME: home }, userName: "nobody-here" },
  });
  await arbiter.listen();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets && wired.policyDoc, "the production adapter has the secrets and policy surfaces");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home, policyModelOffered: true,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const bodies: string[] = [];
  const call = async (method: "GET" | "POST", path: string, body?: unknown) => {
    const r = await pageFetch(base + path, { method, headers: { ...CSRF_ADMIN, ...(body !== undefined ? { "Content-Type": "application/json" } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    const text = await r.text();
    bodies.push(text);
    return { status: r.status, body: JSON.parse(text) };
  };
  const pages: string[] = [];
  const runs = () => (existsSync(record) ? readFileSync(record, "utf8").split("\n").filter(Boolean).length : 0);
  try {
    assert.equal((await call("POST", "/api/suggestions/scan", { root: "~/proj" })).status, 200);
    const listed = (await call("GET", "/api/suggestions")).body.suggestions as Array<{ path: string }>;
    assert.deepEqual(listed.map((s) => s.path), [join(repo, KEY_FILE)], "the real scan files the key");
    const policyBefore = readFileSync(policyPath, "utf8");
    const css = await servedStyles(base);

    await servedProductPage(base, "/rules", (doc: Doc) => !!byId(doc, "suggest-open"), async (doc: Doc) => {
      // R1: the suggestion's policy.yaml lines.
      byId(doc, "suggest-open").click();
      await waitWhile(() => !doc.querySelector("#files-suggested-list .row.suggested"));
      doc.querySelector("#files-suggested-list .row.suggested .file-name").dispatchEvent(new doc.defaultView.MouseEvent("click", { bubbles: true }));
      const detail = doc.querySelector("#files-suggested-list .file-detail");
      [...detail.querySelectorAll("button")].find((b: Doc) => b.textContent === "Show in policy.yaml").click();
      const lines = detail.querySelector("pre.suggestion-yaml");
      named(detail, lines, "group", "Save adds these lines to policy.yaml:");
      assert.equal(lines.textContent, `paths:\n  - path: ${join(repo, KEY_FILE)}\n    level: no-model`);

      // R2: the model preview's list, Names only.
      const sel = byId(doc, "suggest-model-tier");
      await waitWhile(() => sel.options[1].disabled);
      byId(doc, "suggest-root").value = repo;
      sel.value = "names";
      sel.dispatchEvent(new doc.defaultView.Event("change"));
      const dialog = byId(doc, "suggest-model-preview");
      byId(doc, "suggest-model-run").click();
      await waitWhile(() => dialog.hidden && !byId(doc, "suggest-error").textContent);
      assert.equal(byId(doc, "suggest-error").textContent, "", "the preview was built");
      const list = byId(doc, "suggest-model-list");
      assert.ok(list.children.length > 40, `the names as sent (${list.children.length})`);
      assert.match(list.textContent, /meeting-notes-39\.md/);
      named(dialog, list, "list", "The names it sends, exactly as sent");
      assert.equal(byId(doc, "suggest-model-caption").textContent, "The names it sends, exactly as sent", "the caption's own words");
      assert.equal(list.getAttribute("aria-labelledby"), null, "never the caption itself: it is drawn in capitals, which a browser puts in the name");
      assert.deepEqual(scrollFaults(byId(doc, "suggested-block")), [], "R4 on Keys Mandu found");
      byId(doc, "suggest-model-cancel").click();
      await new Promise((r) => setTimeout(r, 200));
      assert.equal(runs(), 0, "the classifier got no run");

      // R3: deploy.token made Not secret, the suggestion skipped (it waits
      // ticked, and Save would store it before asking).
      const tick = doc.querySelector("#files-suggested-list .row.suggested input.file-tick");
      tick.checked = false;
      tick.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
      byId(doc, "rules-add").click();
      await waitWhile(() => !doc.querySelector("#files-list .row.file"));
      byId(doc, "lock-path").value = "~/proj/";
      byId(doc, "files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
      const row = () => [...doc.querySelectorAll("#files-list .row.file:not(.up)")].find((r: Doc) => r.querySelector(".file-name").textContent.startsWith("deploy.token"));
      await waitWhile(() => !row()?.querySelector("select.label-select"));
      const menu = row().querySelector("select.label-select");
      menu.value = "public";
      menu.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
      const bar = byId(doc, "files-pending");
      const what = byId(doc, "files-impact");
      await waitWhile(() => /Working out/.test(what.textContent));
      assert.equal(bar.hidden, false);
      assert.match(what.textContent, /^Changes the label of 1 file, 1 of them less protected\./);
      assert.equal(controlName(what), "What this changes");
      assert.equal(boxRole(what), "status");
      byId(doc, "files-save").click();
      await waitWhile(() => byId(doc, "files-confirm").hidden);
      named(bar, byId(doc, "files-confirm-list"), "list", "These changes make protection weaker.");
      assert.match(byId(doc, "files-confirm-list").textContent, /deploy\.token/);
      named(bar, doc.querySelector("#files-confirm-files ul"), "list", "Files that become less protected:");
      assert.match(doc.querySelector("#files-confirm-files ul").textContent, /deploy\.token/);

      // R4: every box on Rules that may scroll says what it holds.
      assert.deepEqual(scrollFaults(byId(doc, "page-rules")), []);
      byId(doc, "files-discard").click();
      assert.equal(bar.hidden, true);
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE }, css });
    assert.equal(readFileSync(policyPath, "utf8"), policyBefore, "Discard saved nothing");

    // The oracle.
    assert.equal(runs(), 0);
    for (const path of ["/api/suggestions", "/api/policy/panel", "/api/home", `/api/files/list?path=${encodeURIComponent("~/proj")}`]) await call("GET", path);
    for (const text of [...pages, ...bodies]) {
      assert.ok(!text.includes(KEY), "no page or answer carries the scanned key");
      assert.ok(!text.includes(TOKEN), "no page or answer carries the token under a rule");
    }
  } finally {
    await dashboard.close();
    wired.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

const SESSION = `1791500000-${process.pid}`;
const ENV_VALUE = `sk_live_scrollNamesAgentCanary_${process.pid}_00000001`;

/** The model's first answer: one Read of the file. */
function readTurn(path: string): string {
  return sseEvent("message_start", { type: "message_start", message: { id: "msg_sn_1", role: "assistant", content: [] } })
    + sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_sn_0", name: "Read", input: {} } })
    + sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify({ file_path: path }) } })
    + sseEvent("content_block_stop", { type: "content_block_stop", index: 0 })
    + sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } })
    + sseEvent("message_stop", { type: "message_stop" });
}

function post(port: number, messages: unknown[]): Promise<number> {
  const body = JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 512, tools: [{ name: "Read", input_schema: { type: "object" } }], messages });
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": SESSION } },
      (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); });
    r.on("error", reject);
    r.end(body);
  });
}

test("the agent page over the real proxy: a reply's fenced block is a group named Code, and the real value, shown, a group named by its words, never by the value", { timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-scroll-names-agent-"));
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  const envFile = join(ws, ".env");
  writeFileSync(envFile, `TOKEN=${ENV_VALUE}\n`);
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await arbiter.listen();
  const gate = new ArbiterClient(sock); await gate.connect();
  const humanClient = new ArbiterClient(human); await humanClient.connect();
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: human }), log: () => {}, ...ADMIN_OPTS });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const seen: string[] = [];
  const reply = "Run the suite with:\n```bash\nnpm test -- --reporter=spec --grep 'a pattern long enough that a narrow window cuts it'\n```\nThe token stays hidden from me.";
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = seen.length === 1 ? readTurn(envFile) : buildTextSse(reply, { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(gate, humanClient), upstream, sessionKey: SESSION, log: () => {} });
  const proxyPort = await proxy.listen(0);
  try {
    const ask = "Read the .env and tell me how to run the tests.";
    assert.equal(await post(proxyPort, [{ role: "user", content: ask }]), 200);
    assert.equal(await post(proxyPort, [
      { role: "user", content: ask },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_sn_0", name: "Read", input: { file_path: envFile } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_sn_0", content: `     1\tTOKEN=${ENV_VALUE}\n` }] },
    ]), 200);
    assert.ok(!seen.join("\n").includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");

    // Emission is best-effort and asynchronous: wait for the reply and the secret.
    let text = "";
    for (let i = 0; i < 200; i++) {
      text = await (await pageFetch(`${base}/api/home/agent?session=${SESSION}`, { headers: { Cookie: ADMIN_COOKIE } })).text();
      const page = JSON.parse(text) as AgentPageVM;
      if (page.found && /```/.test(text) && page.secrets && page.secrets.secrets.length > 0) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.match(text, /```bash/, text.slice(0, 400));
    assert.ok(!text.includes(ENV_VALUE), "the page's answer carries no value");

    const css = await servedStyles(base);
    await servedProductPage(base, `/agents/${SESSION}`, (doc: Doc) => !!doc.querySelector("#agent-story pre.code-block") && !!doc.querySelector("#agent-story button.secret-reveal"), async (doc: Doc) => {
      const story = byId(doc, "agent-story");
      // A1: the fenced block.
      const block = story.querySelector("pre.code-block");
      named(story, block, "group", "Code");
      assert.match(block.textContent, /^npm test -- --reporter=spec/);
      assert.ok(!doc.body.textContent.includes(ENV_VALUE), "no value before the click");

      // A2: the real value, shown on the person's own click.
      const show = story.querySelector("button.secret-reveal");
      assert.equal(show.textContent, "Show the real value");
      show.click();
      await waitWhile(() => !story.querySelector("pre.secret-value:not([hidden])"));
      const value = story.querySelector("pre.secret-value");
      assert.ok(value.textContent.includes(ENV_VALUE), "the value the person asked to see");
      named(story, value, "group", "The real value");
      assert.ok(!controlName(value).includes(ENV_VALUE), "never named by the value");
      assert.deepEqual(scrollFaults(story), [], "every box on the page that may scroll says what it holds");
    }, { headers: { Cookie: ADMIN_COOKIE }, css });

    // The oracle: signed out, the page's answer and the served page carry no value.
    const out = await (await pageFetch(`${base}/api/home/agent?session=${SESSION}`)).text();
    assert.ok(!out.includes(ENV_VALUE), "signed out, no value");
    assert.ok(!seen.join("\n").includes(ENV_VALUE), "the model never got the value");
  } finally {
    await proxy.close();
    await dashboard.close();
    gate.close();
    humanClient.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
