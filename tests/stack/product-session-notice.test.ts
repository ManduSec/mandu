/**
 * product-session-notice — a session whose commands could not run, or whose
 * terminal showed masked values, says so on the PRODUCT page, across the
 * REAL components (dashboard.md §4.21 *On the product page*). Mandu-new.
 *
 * Until this change only the developer view's health chip said a session
 * could not do its job; Home's row and the session's page looked normal.
 *
 *   a real ArbiterServer (`secrets` axes), the launcher's real
 *   `launch_posture` event, the real anthropic-proxy on its production
 *   arbiter wiring (`new ArbiterClientAdapter(new ArbiterClient(sock), …)`),
 *   a scripted model behind it, and a real DashboardServer over a real
 *   ArbiterEventSource, signed in and signed out:
 *
 *   N1  Claude Code runs two `Bash` commands and both could not start
 *       ("command not found"): `/api/home`'s row and `/api/home/agent` carry
 *       "None of the 2 commands the agent ran could start …", its command
 *       (`mandu log <session>`) as code, and the page marks it to be
 *       written out under its header, titled "This session did not work as
 *       it should."; signed out, the same;
 *   N2  a session whose reply filter recorded passthrough (the record the
 *       reply filter writes, over the human socket): the masked-values
 *       notice, written out too;
 *   N3  a clean session: no notice;
 *   N5  a session whose launch printed a line about a protection that did
 *       not start (the network proxy's port was busy; classified by the
 *       launcher's own `postureFindings`): "1 of Mandu's protections did
 *       not start …", written out under the page's header, titled "This
 *       session ran with less protection than usual.", its log and
 *       `mandu doctor` as code, and never the launch line's own words;
 *       its rows on `/api/home` and `/api/home/history` carry
 *       `lessProtection: true` (the counts line's "less protection than
 *       usual" and amber dot), the other sessions' rows none; still
 *       running, it is named in `/api/home`'s calm hero, a link to its
 *       page, and no other session is linked there; then, with a
 *       question waiting (a real held send to a host no rule names), the
 *       `waiting` hero still names it after its own sentence, its only
 *       link, signed in and out (#292);
 *   N4  the oracle: the session read a labelled secret; it reached the
 *       model only masked, no notice carries a value, a token or a
 *       command's output, and the signed-out payloads carry no value.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { emitLauncherEvent, launchPostureEvent, postureFindings } from "../../launcher/src/services/observe.js";
import { DashboardServer, type ApprovalsArbiter } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HistoryVM, HomeVM } from "../../dashboard/src/view-model/home.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const CANARY = `NOTICE_STACK_CANARY_${process.pid}_9d3a`;
const NOT_FOUND = "Exit code 127\n/bin/bash: line 1: python3: command not found";
const TOOLS = [
  { name: "Bash", description: "run", input_schema: { type: "object" } },
  { name: "Read", description: "read", input_schema: { type: "object" } },
];

test("a session whose every command could not start, one whose terminal showed masked values, and one where a protection did not start, say so on Home's row and the session page, signed in and out, with no value (secrets axes)", { timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-session-notice-"));
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  const secret = join(ws, ".env");
  writeFileSync(secret, `API_TOKEN=${CANARY}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, humanSocketPath: humanPath, adminSocketPath: join(tmp, "admin.sock"),
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };

  let up = new MockUpstream({ sse: buildTextSse("ok") });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await open(socketPath), await open(humanPath)), upstream: (a) => up.fetcher(a), log: () => {} });
  const proxyPort = await proxy.listen(0);
  // The Approvals queue, so Home sees a question once N5 raises one.
  const admin = await open(join(tmp, "admin.sock"));
  const approvalsArbiter: ApprovalsArbiter = {
    egressApprovals: (status) => admin.egressApprovals(status),
    resolveEgressApproval: (approvalId, approve, scope) => admin.resolveEgressApproval(approvalId, approve, scope),
  };
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const toModel: string[] = [];

  const turn = async (session: string, messages: unknown[], sse: string): Promise<void> => {
    up = new MockUpstream({ sse });
    const res = await fetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "user-agent": "claude-cli/2.1.289 (external, cli)" },
      body: JSON.stringify({ model: "claude-opus-4", stream: true, system: "You are Claude Code.", tools: TOOLS, messages }),
    });
    assert.equal(res.status, 200, await res.text());
    toModel.push(up.requests[0]!.bodyText);
  };
  const use = (id: string, name: string, input: Record<string, unknown>) => ({ role: "assistant", content: [{ type: "tool_use", id, name, input }] });
  const result = (id: string, content: string) => ({ role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] });
  const posture = async (scopeId: string, notes: string[] = []): Promise<void> => {
    assert.ok(await emitLauncherEvent(socketPath, launchPostureEvent({ scopeId, target: "claude", argv0: "/usr/local/bin/claude", notes })));
  };
  const read = async (path: string, signedIn: boolean): Promise<{ text: string; json: unknown }> => {
    const res = await fetch(`${base}${path}`, signedIn ? { headers: { Cookie: ADMIN_COOKIE } } : {});
    assert.equal(res.status, 200, path);
    const text = await res.text();
    return { text, json: JSON.parse(text) };
  };
  const stamp = Math.floor(Date.now() / 1000);

  try {
    // N1: every command could not start. The session also reads the
    // labelled .env, for the oracle.
    const FAIL = `${stamp}-${process.pid}-fail`;
    await posture(FAIL);
    const ask = { role: "user", content: "Read the env, then build it." };
    const readEnv = use("toolu_sn_0", "Read", { file_path: secret });
    const build = use("toolu_sn_1", "Bash", { command: "python3 build.py" });
    const test2 = use("toolu_sn_2", "Bash", { command: "python3 -m pytest" });
    const h0 = [ask];
    const h1 = [...h0, readEnv, result("toolu_sn_0", `API_TOKEN=${CANARY}\n`)];
    const h2 = [...h1, build, result("toolu_sn_1", NOT_FOUND)];
    const h3 = [...h2, test2, result("toolu_sn_2", NOT_FOUND)];
    await turn(FAIL, h0, buildToolUseSse({ id: "toolu_sn_0", name: "Read", input: { file_path: secret } }));
    await turn(FAIL, h1, buildToolUseSse({ id: "toolu_sn_1", name: "Bash", input: { command: "python3 build.py" } }));
    await turn(FAIL, h2, buildToolUseSse({ id: "toolu_sn_2", name: "Bash", input: { command: "python3 -m pytest" } }));
    await turn(FAIL, h3, buildTextSse("python3 is not installed here."));

    // N2: the reply filter ran in passthrough. Its record, as the reply
    // filter writes it (run.ts `relayModeEvent`), over the human socket.
    const RELAY = `${stamp}-${process.pid}-relay`;
    await posture(RELAY);
    const human = await open(humanPath);
    await human.emit({
      id: randomUUID(), sessionId: RELAY, turn: 0, ts: new Date().toISOString(), seq: 0, callId: null, parentId: null,
      kind: "relay_mode", view: "HumanView", boundary: "model_context", emitter: "reply-filter", mode: "passthrough",
      input: { symbolized: "reply-filter mode: PASSTHROUGH — no script(1) on PATH", original: null, differs: false, symbols: [] },
      output: null, invariant: { violatedInvariant: false },
    } as never);
    await turn(RELAY, [{ role: "user", content: "Hello." }], buildTextSse("Hello!"));

    // N3: a clean session.
    const OK = `${stamp}-${process.pid}-ok`;
    await posture(OK);
    const ls = use("toolu_ok_1", "Bash", { command: "ls" });
    await turn(OK, [{ role: "user", content: "List." }], buildToolUseSse({ id: "toolu_ok_1", name: "Bash", input: { command: "ls" } }));
    await turn(OK, [{ role: "user", content: "List." }, ls, result("toolu_ok_1", "README.md\n")], buildTextSse("Done."));

    // N5: the network proxy did not start. The launch line as the launcher's
    // service manager prints it, classified dropped by its own rules.
    const DROP = `${stamp}-${process.pid}-drop`;
    const DROP_LINE = "mandu: service 'net-proxy' is on by default but failed to start: 127.0.0.1:8790 is occupied — proceeding WITHOUT it (opt out explicitly with --no-net-proxy to silence this)";
    assert.deepEqual(postureFindings([DROP_LINE, "mandu: net-proxy LIVE — cooperative egress gate"]).dropped, [DROP_LINE]);
    await posture(DROP, [DROP_LINE]);
    await turn(DROP, [{ role: "user", content: "Hello." }], buildTextSse("Hello!"));

    // The proxy's events are best-effort and asynchronous: wait for each
    // session's last record.
    for (const [id, needle] of [[FAIL, "toolu_sn_2"], [RELAY, "tllm_call"], [OK, "toolu_ok_1"], [DROP, "tllm_call"]] as const) {
      const file = join(tmp, "events", `${id}.ndjson`);
      for (let i = 0; i < 100; i++) {
        let text = "";
        try { text = readFileSync(file, "utf8"); } catch { /* not yet */ }
        if (text.includes(needle) && (id !== FAIL || text.includes("\"tool_result\"") && text.split("python3: command not found").length > 2)) break;
        await new Promise((r) => setTimeout(r, 30));
      }
    }

    const FAIL_WORDS = `None of the 2 commands the agent ran could start: a sandbox or a missing program stopped them. Run mandu log ${FAIL} for this launch's notices.`;
    const RELAY_WORDS = "Your terminal showed masked values instead of your real ones: Mandu's reply filter was not working in this session. The AI's side was not affected. Start the agent again; if it happens again, run mandu doctor.";
    const DROP_WORDS = `1 of Mandu's protections did not start in this session, so it ran with less protection than usual. Run mandu log ${DROP} to see which, and mandu doctor to check this computer.`;
    const notices: string[] = [];
    for (const signedIn of [true, false]) {
      const who = signedIn ? "signed in" : "signed out";
      const home = await read("/api/home", signedIn);
      const rows = (home.json as HomeVM).agents;
      const row = (id: string) => {
        const r = rows.find((a) => a.id === id);
        assert.ok(r, `${who}: Home lists ${id}: ${JSON.stringify(rows.map((a) => a.id))}`);
        return r;
      };
      // N1
      assert.equal(row(FAIL).notice, FAIL_WORDS, who);
      assert.deepEqual(row(FAIL).noticeParts!.filter((p) => p.kind === "code").map((p) => p.text), [`mandu log ${FAIL}`], who);
      // N2
      assert.equal(row(RELAY).notice, RELAY_WORDS, who);
      // N3
      assert.equal(row(OK).notice, null, `${who}: a clean session says nothing`);
      // N5
      assert.equal(row(DROP).notice, DROP_WORDS, who);
      assert.deepEqual(row(DROP).noticeParts!.filter((p) => p.kind === "code").map((p) => p.text), [`mandu log ${DROP}`, "mandu doctor"], who);
      // N5: its row is marked, Home's and History's alike; no other is.
      const history = await read("/api/home/history", signedIn);
      const hrows = (history.json as HistoryVM).rows;
      for (const id of [FAIL, RELAY, OK, DROP]) {
        const h = hrows.find((a) => a.id === id);
        assert.ok(h, `${who}: History lists ${id}: ${JSON.stringify(hrows.map((a) => a.id))}`);
        // Sent only when true (dashboard.md §4.30 Payload budgets).
        assert.equal(row(id).lessProtection, id === DROP ? true : undefined, `${who}: /api/home's ${id} lessProtection`);
        assert.equal(h.lessProtection, id === DROP ? true : undefined, `${who}: /api/home/history's ${id} lessProtection`);
      }
      // N5: DROP is still running (no session_exit was recorded), so the
      // calm hero names it, a link to its page; no other session is linked.
      // The headline stays as the level makes it.
      const vm = home.json as HomeVM;
      assert.notEqual(row(DROP).state, "idle", `${who}: DROP still runs`);
      assert.equal(vm.verdict, "secrets-only", who);
      assert.equal(vm.headline, "Your secrets are guarded.", who);
      const heroLinks = vm.sentenceParts.flatMap((p) => (p.kind === "link" && p.to === "agent" ? [p.session] : []));
      assert.deepEqual(heroLinks, [DROP], `${who}: the hero links DROP only: ${vm.sentence}`);
      assert.match(vm.sentence, /runs with less protection than usual: not all of Mandu's protections started for it\./, who);

      const page = async (id: string) => {
        const p = await read(`/api/home/agent?session=${encodeURIComponent(id)}`, signedIn);
        return { ...p, vm: p.json as AgentPageVM };
      };
      const fail = await page(FAIL);
      assert.equal(fail.vm.notice, FAIL_WORDS, who);
      assert.equal(fail.vm.noticeShown, true, `${who}: written out under the header`);
      assert.equal(fail.vm.noticeTitle, "This session did not work as it should.", who);
      const relay = await page(RELAY);
      assert.equal(relay.vm.notice, RELAY_WORDS, who);
      assert.equal(relay.vm.noticeShown, true, who);
      assert.equal(relay.vm.noticeTitle, "This session did not work as it should.", who);
      const ok = await page(OK);
      assert.equal(ok.vm.notice, null, who);
      assert.equal(ok.vm.noticeShown, false, who);
      assert.equal(ok.vm.noticeTitle, null, who);
      const drop = await page(DROP);
      assert.equal(drop.vm.notice, DROP_WORDS, who);
      assert.equal(drop.vm.noticeShown, true, `${who}: a protection that did not start is written out under the header`);
      assert.equal(drop.vm.noticeTitle, "This session ran with less protection than usual.", `${who}: titled for what was lost, not as a failure`);
      // N5: the launch line's own words reach neither payload.
      for (const [where, text] of [["/api/home", home.text], ["/api/home/history", history.text], ["/api/home/agent", drop.text]] as const) {
        for (const bit of ["is on by default but failed to start", "127.0.0.1:8790", "proceeding WITHOUT it", "--no-net-proxy"]) {
          assert.ok(!text.includes(bit), `${who}: ${where} carries the launch line's ${JSON.stringify(bit)}`);
        }
      }

      notices.push(row(FAIL).notice!, row(RELAY).notice!, row(DROP).notice!, fail.vm.notice!, relay.vm.notice!, drop.vm.notice!,
        ...[row(FAIL), fail.vm, row(RELAY), relay.vm, row(DROP), drop.vm].flatMap((x) => (x.noticeParts ?? []).map((p) => p.text)));
      // N4: signed out, neither payload carries the value.
      if (!signedIn) {
        for (const [where, text] of [["/api/home", home.text], ["/api/home/history", history.text], ["/api/home/agent", fail.text]] as const) {
          assert.ok(!text.includes(CANARY), `CONFIDENTIALITY VIOLATION: signed out, ${where} carries the labelled secret`);
        }
      }
    }
    // N5 (#292): a question waits. A real held send: the labelled .env's
    // value to a host no rule names. Home's verdict is `waiting`, its
    // headline the question's, and the hero still names DROP after its own
    // sentence, its only link.
    const gate = await open(socketPath);
    const reg = await gate.registerSecret({ path: secret, sessionKey: OK });
    const sym = /\$MDU:[A-Za-z_]+\[[0-9a-f]+\]\.API_TOKEN/.exec(reg.twin ?? "")?.[0];
    assert.ok(sym, `the value has its own symbol: ${JSON.stringify(reg.twin ?? null)}`);
    const asked = await gate.desymbolizationDecision({ symbol: sym!, boundary: "network", destination: "evil.example", sessionKey: OK, scheme: "https" });
    assert.equal((asked as { requiresApproval?: boolean }).requiresApproval, true, "the send to an unbound host is held");
    for (const signedIn of [true, false]) {
      const who = `${signedIn ? "signed in" : "signed out"}, a question waiting`;
      const home = await read("/api/home", signedIn);
      const vm = home.json as HomeVM;
      assert.equal(vm.verdict, "waiting", who);
      assert.equal(vm.headline, "One question is waiting for you.", who);
      const heroLinks = vm.sentenceParts.flatMap((p) => (p.kind === "link" && p.to === "agent" ? [p.session] : []));
      assert.deepEqual(heroLinks, [DROP], `${who}: the hero links DROP only: ${vm.sentence}`);
      assert.match(vm.sentence, /^Protection is holding while you decide: what it asks for happens only if you allow it\. Untrusted content is not masked in this mode\. .+ runs with less protection than usual: not all of Mandu's protections started for it\.$/, who);
      const hero = JSON.stringify([vm.sentence, vm.sentenceParts]);
      assert.ok(!hero.includes(CANARY), `CONFIDENTIALITY VIOLATION: ${who}, the hero carries the labelled secret`);
      assert.doesNotMatch(hero, /\$MDU:|net-proxy|8790|WITHOUT/, who);
      if (!signedIn) assert.ok(!home.text.includes(CANARY), `CONFIDENTIALITY VIOLATION: ${who}, /api/home carries the labelled secret`);
    }

    // N4: no notice carries a value, a token or what a command printed.
    for (const n of notices) {
      assert.ok(!n.includes(CANARY), `CONFIDENTIALITY VIOLATION: a notice carries the labelled secret: ${n}`);
      assert.doesNotMatch(n, /\$MDU|python3|command not found|PASSTHROUGH|net-proxy|\brung\b/, n);
    }
    assert.ok(toModel.length > 0);
    for (const body of toModel) assert.ok(!body.includes(CANARY), "CONFIDENTIALITY VIOLATION: the labelled secret reached the model raw");
  } finally {
    await dashboard.close();
    await proxy.close();
    for (const c of clients) c.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
