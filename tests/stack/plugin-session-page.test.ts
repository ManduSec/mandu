/**
 * plugin-session-page — the session page of a PLUGIN session
 * (docs/design/agents/openclaw-plugin.md §3.3; dashboard.md §4.25aj) shows
 * its steps as a launch's page does: OpenClaw's `read` of a secret file as a
 * step whose output the AI saw masked, and, signed in, **Show the real
 * value** beside it (the human-plane reveal; the promo video's dashboard
 * ending); and a command OpenClaw ran whose output printed the file's
 * value, masked in place, its chip named by the value's key as the video's
 * figure names the mask (§4.25b *A masked result's chip names its
 * secret*). Mandu-new.
 *
 * The stack, real except OpenClaw and the model, wired as `mandu serve`'s
 * pool wires one attachment session (attachment-pool.ts, in its order):
 *   - a real ArbiterServer on the `secrets` axes with its data and human
 *     sockets;
 *   - the secret file registered over the human socket (the pool's `mandu
 *     serve register-secrets`), then the attachment registered there
 *     (`beginAttachment`, kind `openclaw-plugin`), which exposes the human
 *     plane;
 *   - the real anthropic-proxy in its production wiring (data and human
 *     clients, `sessionKey: openclaw:main`, the `openclaw-agent` spec), in
 *     front of a scripted model, carrying OpenClaw's `read` of `.env`;
 *   - a real DashboardServer over the production ArbiterEventSource, its
 *     served page in jsdom.
 *
 * While the attachment is live every event the proxy writes is a claim (a
 * program in the Gateway could write the same on the exposed plane), so the
 * page says its record is unchecked; it still draws the steps, the masked
 * read and its Show the real value, scoped to the tokens the session's own
 * proxy recorded.
 *
 * The oracle: the model never received the value; signed out, no answer or
 * drawn page carries it, and no button; signed in, the button shows the
 * file's own value. Axes stated: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ATTACHMENT_COVERAGE } from "../../arbiter/policy/confinement-posture.js";
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

const SESSION = "openclaw:main";
const VALUE = "pluginSessionPageDbPass00001";
const SHOW = "Show the real value";
const DEBUG_RUN = "DEBUG=1 sh shop-app/bin/start.sh";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
/** The story's `read` step of `.env`. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const readStep = (page: AgentPageVM): any => page.story.flatMap((t) => t.steps).find((s) => s.kind === "action" && s.sentence.some((p) => p.text === ".env"));
/** The story's debug-run step (the exec whose output held the value). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const runStep = (page: AgentPageVM): any => page.story.flatMap((t) => t.steps).find((s) => s.kind === "action" && s.sentence.some((p) => p.text.includes("DEBUG=1")));
const stepButtons = (doc: Doc) => [...doc.querySelectorAll("#agent-story .step.split button.secret-reveal")] as Doc[];

test("a plugin session's page (openclaw:main, its events from the pool's proxy) draws the masked read step and, signed in, Show the real value; signed out no value anywhere", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-plugin-page-"));
  const ws = join(tmp, "home", "shop-app");
  mkdirSync(ws, { recursive: true });
  const env = join(ws, ".env");
  writeFileSync(env, `DB_USER=shop\nDB_PASSWORD=${VALUE}\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  const service = new ArbiterClient(humanPath);
  await service.connect();
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const human = new ArbiterClient(humanPath);
  await human.connect();
  let upstream = new MockUpstream({ sse: buildTextSse("ok") });
  const toModel: string[] = [];
  let proxy: AnthropicProxy | null = null;
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }), log: () => {}, ...ADMIN_OPTS });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const rendered: string[] = [];
  const answers: string[] = [];
  try {
    // The pool's order: the secret file, then the attachment, then the proxy.
    const reg = await service.registerSecret({ path: env, home: join(tmp, "home") });
    assert.ok(reg.symbol, `the file is registered: ${reg.reason}`);
    const att = await service.beginAttachment({ sessionId: SESSION, kind: "openclaw-plugin", coverage: ATTACHMENT_COVERAGE["openclaw-plugin"] });
    assert.equal(att.posture, "gated");
    assert.equal((await data.setSessionSpec({ sessionKey: SESSION, spec: "openclaw-agent", requestedBy: "plugin-session-page e2e (the pool's MANDU_INBOUND_SPEC)" })).bound, "openclaw-agent");
    proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream: (x) => upstream.fetcher(x), sessionKey: SESSION, log: () => {} });
    const port = await proxy.listen(0);
    const tools = [
      { name: "read", description: "Read a file", input_schema: { type: "object", properties: { path: { type: "string" } } } },
      { name: "exec", description: "Run a command", input_schema: { type: "object", properties: { command: { type: "string" } } } },
    ];
    const turn = async (messages: unknown[], sse: string) => {
      upstream = new MockUpstream({ sse });
      const r = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-mandu-session-id": SESSION },
        body: JSON.stringify({ model: "claude-haiku-4-5", stream: true, system: "You are a personal assistant running inside OpenClaw.", tools, messages }),
      });
      assert.equal(r.status, 200, await r.text());
      toModel.push(upstream.requests[0]!.bodyText);
    };
    const ask = { role: "user", content: "Payments started failing last night. Check the config in shop-app." };
    const use = { role: "assistant", content: [{ type: "tool_use", id: "toolu_psp_1", name: "read", input: { path: env } }] };
    const res = { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_psp_1", content: `DB_USER=shop\nDB_PASSWORD=${VALUE}\n` }] };
    await turn([ask], buildToolUseSse({ id: "toolu_psp_1", name: "read", input: { path: env } }));
    await turn([ask, use, res], buildToolUseSse({ id: "toolu_psp_2", name: "exec", input: { command: DEBUG_RUN } }));
    // The promo video's debug run: a command OpenClaw ran printed the file's value
    // (its own line, `NAME: value`), masked as the file's own secret.
    const use2 = { role: "assistant", content: [{ type: "tool_use", id: "toolu_psp_2", name: "exec", input: { command: DEBUG_RUN } }] };
    const res2 = { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_psp_2", content: `config loaded\nDB_PASSWORD: ${VALUE}\nstart: FAILED\n` }] };
    await turn([ask, use, res, use2, res2], buildTextSse("The config looks fine; the variable name in the start script is wrong."));
    for (const body of toModel) assert.ok(!body.includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the secret file's value");
    assert.ok(toModel[1]!.includes("$MDU:"), "the model saw the read masked");

    // The page's answer, signed in: the read step, masked, revealable.
    let text = "";
    for (let i = 0; i < 200; i++) {
      text = await (await pageFetch(`${base}/api/home/agent?session=${encodeURIComponent(SESSION)}`, { headers: { Cookie: ADMIN_COOKIE } })).text();
      const page = JSON.parse(text) as AgentPageVM;
      if (page.found && /variable name/.test(text) && readStep(page)) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    const page = JSON.parse(text) as AgentPageVM;
    assert.equal(page.found, true, text.slice(0, 400));
    const step = readStep(page);
    assert.ok(step, `the read step: ${text.slice(0, 600)}`);
    assert.equal(step.outcome, "secret", "the AI got the read masked");
    assert.deepEqual(step.split?.hidden?.secrets?.map((s: { name: string }) => s.name), [".env"], "its hidden output names the secret, by an opaque ref");
    // What the AI got is named as the secret it hides, the name the reveal
    // and the right half give it (dashboard.md §4.25b *A masked result's chip
    // names its secret*): the chip the film's figure spells the same way.
    assert.deepEqual(step.split?.ai?.find((p: { kind: string }) => p.kind === "masked"), { kind: "masked", text: "secret", name: ".env" });
    const ran = runStep(page);
    assert.ok(ran, `the debug run's step: ${text.slice(0, 600)}`);
    assert.equal(ran.outcome, "secret", "the AI got the command's output with the value masked");
    const ranChip = ran.split?.ai?.find((p: { kind: string }) => p.kind === "masked");
    assert.equal(ranChip?.name, "DB_PASSWORD", `the chip names the value by its key: ${JSON.stringify(ran.split)}`);
    assert.deepEqual(ran.split?.hidden?.secrets?.map((s: { name: string }) => s.name), ["DB_PASSWORD"]);
    // The page is honest about what it is: the plugin's posture, and a record
    // Mandu could not check (its proxy's records are all claims).
    assert.equal(page.secretsPosture?.gap, "openclaw-plugin");
    assert.match(page.secretsPosture?.sentence ?? "", /every model call goes through Mandu/);
    assert.equal(page.secrets?.unchecked, true);

    await servedProductPage(base, `/agents/${encodeURIComponent(SESSION)}`, (doc: Doc) => stepButtons(doc).length >= 1, async (doc: Doc) => {
      const steps = stepButtons(doc);
      assert.equal(steps[0].textContent, SHOW);
      assert.equal(steps[0].getAttribute("aria-label"), `${SHOW}: .env`, "named by the file it read");
      const step = steps[0].closest(".step");
      assert.match(step.textContent, /masked/i, "the step says the AI saw it masked");
      assert.equal(step.querySelector(".mask-chip.secret")?.textContent, ".env", "what the AI saw: a mask named for what it hides");
      const run = [...doc.querySelectorAll("#agent-story .step[data-outcome=secret]")].find((x: Doc) => x.textContent.includes("DEBUG=1"));
      assert.ok(run, "the debug run's step, drawn");
      assert.equal(run.querySelector(".mask-chip.secret")?.textContent, "DB_PASSWORD", "its mask named by the key, as the film's figure names it");
      assert.match(run.querySelector(".mask-chip.secret")?.getAttribute("title") ?? "", /^Your secret DB_PASSWORD, masked/);
      const box = step.querySelector("pre.secret-value");
      steps[0].click();
      await waitWhile(() => box.hidden);
      assert.match(box.textContent, new RegExp(`DB_PASSWORD=${VALUE}`), "signed in, the file's own value beside what the AI saw");
      steps[0].click();
      assert.equal(box.hidden, true);
      assert.ok(!doc.body.textContent.includes(VALUE), "hidden again, the value leaves the page");
      rendered.push(doc.documentElement.outerHTML);
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // Signed out: no value in the answer or the page, and no button.
    const out = await (await pageFetch(`${base}/api/home/agent?session=${encodeURIComponent(SESSION)}`)).text();
    answers.push(out);
    await servedProductPage(base, `/agents/${encodeURIComponent(SESSION)}`, (doc: Doc) => /variable name/.test(doc.body.textContent), (doc: Doc) => {
      assert.equal(doc.querySelector("button.secret-reveal"), null, "signed out, no Show the real value");
      rendered.push(doc.documentElement.outerHTML);
    });
    for (const s of [...answers, ...rendered]) {
      assert.ok(!s.includes(VALUE), "CONFIDENTIALITY VIOLATION: the value in an answer or a drawn page signed out");
      assert.doesNotMatch(s, /\$MDU/, "nor a token");
    }
    assert.equal((await service.endAttachment(att.token)).ended, true);
  } finally {
    await proxy?.close();
    await dashboard.close();
    service.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
