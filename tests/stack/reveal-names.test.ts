/**
 * reveal-names.test — every "Show the real value" on the agent page says
 * which secret it shows, and so does its "Hide it again", across the REAL
 * components (dashboard.md §4.25b *Show the real value names its secret*).
 * Mandu-new.
 *
 * Until 2026-10-12 a session that read two secret files drew four buttons
 * named "Show the real value" (a Your secrets card and a step for each
 * file), and a pressed one read "Hide it again" with no word of whose value
 * it shows. Here a real ArbiterServer runs at the `secrets` axes with
 * `.env` and `creds.json` at `no-model` in policy.yaml; the REAL
 * anthropic-proxy on its production client carries one session whose
 * scripted model reads both files; a real DashboardServer serves the
 * session's page (its own index.html and home.js in jsdom, signed in):
 *
 *   R1  four reveal buttons, each still reading "Show the real value",
 *       each named by its own file: a card by its heading ("Show the real
 *       value: The file …/creds.json"), a step by the file's name ("Show
 *       the real value: creds.json"); no two share a name;
 *   R2  the card button named for creds.json shows creds.json's value
 *       (not .env's), and reads "Hide it again: The file …/creds.json";
 *       a second click empties the box and gives the name back;
 *   R3  no name, before or after a click, carries a value;
 *   R4  the oracle: neither value reached the model; signed out, the
 *       page's answer and the served page carry neither, and no button.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const ENV_VALUE = "revealNamesStackEnvValue000001";
const CREDS_VALUE = "revealNamesStackCredsValue0002";
const SESSION = `reveal-names-${process.pid}`;
const SHOW = "Show the real value";
const HIDE = "Hide it again";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const nameOf = (b: Doc): string => b.getAttribute("aria-label") ?? b.textContent;
const cardButtons = (doc: Doc) => [...doc.querySelectorAll("#agent-secrets .secret-card button.secret-reveal")] as Doc[];
const stepButtons = (doc: Doc) => [...doc.querySelectorAll("#agent-story .step.split button.secret-reveal")] as Doc[];

test("the agent page: each Show the real value and its Hide it again name their own secret (real arbiter, anthropic-proxy, dashboard); no value in a name", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-reveal-names-"));
  const ws = join(tmp, "home", "ws");
  mkdirSync(ws, { recursive: true });
  const env = join(ws, ".env");
  const creds = join(ws, "creds.json");
  writeFileSync(env, `API_TOKEN=${ENV_VALUE}\n`);
  writeFileSync(creds, `{"password":"${CREDS_VALUE}"}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n  - path: ${creds}\n    level: no-model\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  // The proxy's production wiring (anthropic-proxy/src/server-main.ts).
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const human = new ArbiterClient(humanPath);
  await human.connect();
  let upstream = new MockUpstream({ sse: buildTextSse("ok") });
  const toModel: string[] = [];
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream: (x) => upstream.fetcher(x), log: () => {} });
  const proxyPort = await proxy.listen(0);
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }), log: () => {}, ...ADMIN_OPTS });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const tools = [{ name: "Read", description: "read", input_schema: { type: "object" } }];
  const turn = async (messages: unknown[], sse: string) => {
    upstream = new MockUpstream({ sse });
    const r = await pageFetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": SESSION, "user-agent": "claude-cli/2.1.289 (external, cli)" },
      body: JSON.stringify({ model: "claude-opus-4", stream: true, system: "You are Claude Code.", tools, messages }),
    });
    assert.equal(r.status, 200, await r.text());
    toModel.push(upstream.requests[0]!.bodyText);
  };
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  const rendered: string[] = [];
  try {
    // One session reads both files, each masked on its way to the model.
    const ask = { role: "user", content: "Read the env and the creds and compare them." };
    const use1 = { role: "assistant", content: [{ type: "tool_use", id: "toolu_rn_1", name: "Read", input: { file_path: env } }] };
    const res1 = { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_rn_1", content: `API_TOKEN=${ENV_VALUE}\n` }] };
    const use2 = { role: "assistant", content: [{ type: "tool_use", id: "toolu_rn_2", name: "Read", input: { file_path: creds } }] };
    const res2 = { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_rn_2", content: `{"password":"${CREDS_VALUE}"}\n` }] };
    await turn([ask], buildToolUseSse({ id: "toolu_rn_1", name: "Read", input: { file_path: env } }));
    await turn([ask, use1, res1], buildToolUseSse({ id: "toolu_rn_2", name: "Read", input: { file_path: creds } }));
    await turn([ask, use1, res1, use2, res2], buildTextSse("They hold different secrets."));
    for (const body of toModel) {
      assert.ok(!body.includes(ENV_VALUE) && !body.includes(CREDS_VALUE), "CONFIDENTIALITY VIOLATION: the model got a secret file's value");
    }

    // Emission is best-effort and asynchronous: wait for both secrets.
    let text = "";
    for (let i = 0; i < 200; i++) {
      text = await (await pageFetch(`${base}/api/home/agent?session=${SESSION}`, { headers: { Cookie: ADMIN_COOKIE } })).text();
      const page = JSON.parse(text) as AgentPageVM;
      if (page.found && page.secrets && page.secrets.secrets.filter((s) => s.ref).length === 2 && /They hold/.test(text)) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    const page = JSON.parse(text) as AgentPageVM;
    assert.equal(page.secrets?.secrets.filter((s) => s.ref).length, 2, `two secrets with a ref: ${text.slice(0, 400)}`);

    await servedProductPage(base, `/agents/${SESSION}`, (doc: Doc) => cardButtons(doc).length === 2 && stepButtons(doc).length === 2, async (doc: Doc) => {
      // R1: four buttons, one set of words, four names, each its own file.
      const cards = cardButtons(doc);
      const steps = stepButtons(doc);
      for (const b of [...cards, ...steps]) assert.equal(b.textContent, SHOW, "the eye still reads the same words");
      const cardNames = cards.map(nameOf);
      assert.ok(cardNames[0].startsWith(`${SHOW}: The file `) && cardNames[0].endsWith("/ws/.env"), `the .env card: ${cardNames[0]}`);
      assert.ok(cardNames[1].startsWith(`${SHOW}: The file `) && cardNames[1].endsWith("/ws/creds.json"), `the creds.json card: ${cardNames[1]}`);
      for (const [i, card] of cards.entries()) {
        const heading = card.closest(".secret-card").querySelector(".secret-what").textContent.replace(/\s+/g, " ").trim();
        assert.equal(cardNames[i], `${SHOW}: ${heading}`, "named by the card's own heading");
      }
      assert.deepEqual(steps.map(nameOf), [`${SHOW}: .env`, `${SHOW}: creds.json`]);
      const names = [...cardNames, ...steps.map(nameOf)];
      assert.equal(new Set(names).size, 4, `no two share a name (${JSON.stringify(names)})`);
      rendered.push(doc.documentElement.outerHTML);

      // R2: the card named for creds.json shows creds.json's value.
      const credsButton = cards.find((b: Doc) => nameOf(b).endsWith("/creds.json"));
      const box = credsButton.closest(".secret-card").querySelector("pre.secret-value");
      credsButton.click();
      await waitWhile(() => box.hidden);
      assert.equal(box.textContent, `{"password":"${CREDS_VALUE}"}\n`, "the file's own value, as text");
      assert.ok(!box.textContent.includes(ENV_VALUE), "never the other file's");
      assert.equal(credsButton.textContent, HIDE);
      assert.equal(nameOf(credsButton), `${HIDE}: ${cardNames[1].slice(SHOW.length + 2)}`);
      // R3: no name carries a value while it is shown.
      for (const x of doc.querySelectorAll("[aria-label]")) {
        const name = x.getAttribute("aria-label");
        assert.ok(!name.includes(ENV_VALUE) && !name.includes(CREDS_VALUE), `no name carries a value: ${name}`);
      }
      credsButton.click();
      assert.equal(box.hidden, true);
      assert.equal(box.textContent, "", "hidden again, the value leaves the page");
      assert.equal(nameOf(credsButton), cardNames[1], "the name comes back");
      assert.ok(!doc.body.textContent.includes(CREDS_VALUE), "no value left on the page");
    }, { headers: { Cookie: ADMIN_COOKIE } });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // R4: the oracle, signed out: no value in the answer or the served page, no button.
    const out = await (await pageFetch(`${base}/api/home/agent?session=${SESSION}`)).text();
    assert.ok(!out.includes(ENV_VALUE) && !out.includes(CREDS_VALUE), "signed out, no value in the answer");
    await servedProductPage(base, `/agents/${SESSION}`, (doc: Doc) => !!doc.querySelector("#agent-secrets .secret-card"), (doc: Doc) => {
      assert.equal(doc.querySelector("button.secret-reveal"), null, "signed out, no Show the real value");
      rendered.push(doc.documentElement.outerHTML);
    });
    for (const html of rendered) {
      assert.ok(!html.includes(ENV_VALUE) && !html.includes(CREDS_VALUE), "CONFIDENTIALITY VIOLATION: a value in a drawn page");
      assert.doesNotMatch(html, /\$MDU/, "nor a token");
    }
    for (const body of toModel) {
      assert.ok(!body.includes(ENV_VALUE) && !body.includes(CREDS_VALUE), "CONFIDENTIALITY VIOLATION: the model got a secret file's value");
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await proxy.close();
    await dashboard.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
