/**
 * rules-connect-words.test — on the Rules page a connection rule names where
 * the agent's programs may connect in the words the Approvals card used
 * when the rule was asked for, across the REAL components (dashboard.md
 * §4.25u *Rules names a connection in words*). Mandu-new.
 *
 * Until 2026-10-16 Rules › *Programs and connections* drew each
 * `destinations:` allowance as one raw code: `*:2222`, `*.example.org:*`,
 * `10.0.0.0/8:53 (udp)` (the "(udp)" inside the code), while the card says
 * "any address on port `2222`" (policy-proposals.ts `connectTarget`).
 *
 * Here a real ArbiterServer (secrets) holds a policy.yaml with four
 * connection allowances, a registered key and a send of that key waiting
 * for an answer. A real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`) serves the panel and the Rules page:
 *
 *   W1  `/api/policy/panel`, signed in and signed out: each connection row's
 *       `plain.subject` is the card's words and its `subjectParts` are those
 *       words with each name a code; the compiled `subject` and the id are
 *       unchanged;
 *   W2  the served Rules page (its own index.html and home.js in jsdom under
 *       the served styles at 320 px): each row's line reads as the words,
 *       each name a code kept whole in its box, a one-name subject still
 *       its chip, the ⋯ named in the words, no "(udp)" code;
 *   W3  Remove on the `any address on port 2222` row goes through the real
 *       route with the row's id: policy.yaml loses that entry and keeps the
 *       others, and the page draws the rest;
 *   W4  the oracle: neither the panel (either way), `/api/home` nor the
 *       rendered page carries the registered key; the page and `/api/home`
 *       carry no token (the panel names the waiting send's placeholder,
 *       which is opaque);
 *   W5  (2026-10-17, *A connection rule is coloured as its answer*) on the
 *       served page each connection rule's "Always allowed, from the
 *       agent's next start" is green with a check, and a built-in
 *       protection the file sets to Block (`egress:symbol-as-command`) says
 *       "Always blocked, instead of asking you" in red with an x; neither
 *       is the grey of the reach line under it.
 *
 * Axes: secrets (stated).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const KEY = "ghp_rulesConnectWordsStackCanary0000000001";
/** A minted token (the panel's own help text names the `$MDU:` form). */
const TOKEN = /\$MDU:[A-Za-z_][A-Za-z0-9_-]*\[[0-9a-f]{4,8}\]/;

type Part = { kind: string; text: string };
type Row = { id: string; kind: string; subject: string; plain: { subject: string; subjectParts?: Part[] } };
const shown = (parts: Part[]) => parts.map((p) => (p.kind === "code" ? `[${p.text}]` : p.text)).join("");

/** Each allowance: its compiled id, its compiled subject, the card's words. */
const WANT = [
  ["connect:tcp:*:2222", "*:2222", "any address on port [2222]"],
  ["connect:tcp:*.example.org:*", "*.example.org:*", "[*.example.org] on any port"],
  ["connect:udp:10.0.0.0/8:53", "10.0.0.0/8:53 (udp)", "[10.0.0.0/8:53] over UDP"],
  ["connect:tcp:pypi.org:443", "pypi.org:443", "[pypi.org:443]"],
] as const;

test("Rules over the real arbiter: a connection rule reads as the card's words, each name a code; Remove still removes that rule; no value on the page (secrets axes, explicit)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-connect-words-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "destinations:",
    '  - { host: "*", port: 2222, connect: allow, reason: "git over ssh" }',
    '  - { host: "*.example.org", port: "*", connect: allow }',
    '  - { host: "10.0.0.0/8", port: 53, proto: udp, connect: allow }',
    "  - { host: pypi.org, connect: allow }",
    "rules:",
    "  egress:symbol-as-command: { mode: block }",
    "",
  ].join("\n"));
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    policyPath, policyPollMs: 0, adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home, configEnv: { MANDU_HOME: join(tmp, "mandu-home"), MANDU_POLICY_FILE: policyPath, HOME: home },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const noValue = (body: string, where: string) => {
    assert.ok(!body.includes(KEY), `CONFIDENTIALITY VIOLATION: ${where} carries the registered key`);
    assert.doesNotMatch(body, TOKEN, `${where} carries no token`);
  };
  try {
    // A registered key and a send of it waiting for an answer, for the
    // oracle: the stack has a value it could show, and must not.
    const reg = await data.registerEnvSecrets({ vars: [{ name: "GITHUB_TOKEN", value: KEY }] });
    const sym = reg.vars[0]?.symbol;
    assert.match(String(sym), /^\$MDU:nomodel_Env\[/, "the key has its placeholder");
    const ask = await data.desymbolizationDecision({ symbol: sym!, boundary: "network", destination: "gist.github.com", scheme: "https" });
    assert.equal((ask as { requiresApproval?: boolean }).requiresApproval, true, `the send waits for an answer: ${JSON.stringify(ask)}`);

    // ── W1: the panel, signed in and signed out ──
    for (const [who, headers] of [["signed in", CSRF_ADMIN], ["signed out", {}]] as const) {
      const r = await pageFetch(`${base}/api/policy/panel`, { headers });
      const body = await r.text();
      assert.equal(r.status, 200, `${who}: ${body}`);
      // The panel names the waiting send's placeholder, which is opaque
      // (as rules-chip-fit.test.ts reads it); never the value.
      assert.ok(!body.includes(KEY), `CONFIDENTIALITY VIOLATION: the panel ${who} carries the registered key`);
      const rows = ((JSON.parse(body) as { panel: { yourRules: Row[] } }).panel.yourRules).filter((x) => x.kind === "connect-allow");
      assert.deepEqual(rows.map((x) => [x.id, x.subject, shown(x.plain.subjectParts ?? [])]), WANT.map((w) => [...w]), `${who}: the compiled rows, in the card's words`);
      for (const x of rows) assert.equal(x.plain.subjectParts!.map((p) => p.text).join(""), x.plain.subject, `${who}, ${x.id}: the parts are the words`);
    }

    // ── W2 + W3: the served Rules page at 320 px ──
    const css = async (f: string) => {
      const r = await pageFetch(`${base}/${f}`);
      assert.equal(r.status, 200, `${f} is served`);
      return r.text();
    };
    const styles = resolveCssVars(stylesAt(`${await css("mandu.css")}\n${await css("app.css")}`, 320));
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    type Doc = any;
    const connectRows = (doc: Doc): Doc[] => [...doc.querySelectorAll("#rules-list .row.rule")].filter((r: Doc) => /your agent's programs connecting/.test(r.textContent));
    const line = (row: Doc): Doc => row.querySelector(".rule-text").firstElementChild;
    /** A line's words and names in order, each name as `[name]`. */
    const drawn = (node: Doc): string => {
      if (node.nodeType === 3) return node.textContent;
      if (node.tagName === "CODE") return `[${node.textContent}]`;
      return [...node.childNodes].map(drawn).join("");
    };
    const until = async (ok: () => boolean, what: string): Promise<void> => {
      for (let i = 0; i < 400 && !ok(); i++) await new Promise((r) => setTimeout(r, 25));
      assert.ok(ok(), `the page drew ${what}`);
    };
    await servedProductPage(base, "/rules", (doc: Doc) => connectRows(doc).length === WANT.length, async (doc: Doc) => {
      const win = doc.defaultView;
      assert.deepEqual(connectRows(doc).map((r) => drawn(line(r))), WANT.map((w) => w[2]), "each row reads as the card's words");
      for (const r of connectRows(doc)) {
        const l = line(r);
        if (l.tagName === "CODE") {
          assert.equal(win.getComputedStyle(l).alignSelf, "flex-start", `${l.textContent}: one name is its chip, as wide as its words`);
          continue;
        }
        assert.equal(l.className, "rule-subject");
        for (const c of l.querySelectorAll("code")) {
          assert.ok(c.parentElement.classList.contains("name-fit"), `${c.textContent}: kept whole in its box`);
          assert.equal(win.getComputedStyle(c.parentElement).display, "inline-block");
          assert.equal(win.getComputedStyle(c.parentElement).maxWidth, "100%", `${c.textContent}: no wider than its line`);
          assert.notEqual(win.getComputedStyle(c).whiteSpace, "nowrap", `${c.textContent}: wraps inside only where the column is narrower`);
        }
      }
      const any = connectRows(doc)[0];
      assert.equal(any.querySelector(".file-more").getAttribute("aria-label"), "More about any address on port 2222", "the ⋯ is named in the words");
      assert.ok(!doc.getElementById("rules-list").textContent.includes("(udp)"), "no protocol code on the page");
      noValue(doc.body.textContent ?? "", "the Rules page");

      // W5: the effect words in the colour of what the rule does.
      const effect = (row: Doc): Doc => row.querySelector(".rule-text").nextElementSibling;
      const colour = (node: Doc): string => win.getComputedStyle(node).color;
      const builtin = [...doc.querySelectorAll("#rules-list .row.rule")].find((r: Doc) => /a built-in protection/.test(r.textContent));
      assert.ok(builtin, "the built-in protection set to Block has its row");
      assert.equal(builtin.querySelector(".rule-text").title, "egress:symbol-as-command");
      const greens = connectRows(doc).map((r) => {
        const e = effect(r);
        assert.deepEqual([e.className, !!e.querySelector("svg"), e.textContent], ["outcome ok", true, "Always allowed, from the agent's next start"], `${drawn(line(r))}: allowed, in green with a check`);
        return colour(e);
      });
      const red = effect(builtin);
      assert.deepEqual([red.className, !!red.querySelector("svg"), red.textContent], ["outcome bad", true, "Always blocked, instead of asking you"], "the built-in: blocked, in red with an x");
      assert.equal(new Set(greens).size, 1, "every connection rule is one green");
      const grey = colour(connectRows(doc)[0].querySelector(".rule-text > .dim"));
      assert.notEqual(greens[0], colour(red), "allowed is not blocked's colour");
      for (const c of [greens[0], colour(red)]) assert.notEqual(c, grey, "a colour, not the grey of the words under it");

      // W3: Remove posts the row's id; the real route removes that entry.
      any.querySelector(".file-more").click();
      await until(() => !!connectRows(doc)[0]?.nextElementSibling?.querySelector(".rule-remove"), "the opened row");
      const remove = connectRows(doc)[0].nextElementSibling.querySelector(".rule-remove");
      assert.equal(remove.getAttribute("aria-label"), "Remove the rule for any address on port 2222");
      remove.click();
      await until(() => connectRows(doc).length === WANT.length - 1, "the rest of the rules");
      assert.deepEqual(connectRows(doc).map((r) => drawn(line(r))), WANT.slice(1).map((w) => w[2]), "the other three, as before");
      const onDisk = readFileSync(policyPath, "utf8");
      assert.doesNotMatch(onDisk, /port: 2222/, `the entry is gone from policy.yaml: ${onDisk}`);
      assert.equal(onDisk.match(/connect: allow/g)?.length, 3, `the others are kept: ${onDisk}`);
      assert.match(onDisk, /egress:symbol-as-command: \{ mode: block \}/, `the built-in's line is kept: ${onDisk}`);
      noValue(doc.body.textContent ?? "", "the Rules page after Remove");
    }, { headers: { Cookie: ADMIN_COOKIE, "X-Mandu-Control": "1" }, css: styles });

    // ── W4: the routes the page reads, after the change ──
    for (const route of ["/api/policy/panel", "/api/home", "/rules"]) {
      const r = await pageFetch(base + route);
      const body = await r.text();
      assert.equal(r.status, 200, `${route}: ${body}`);
      if (route === "/api/policy/panel") assert.ok(!body.includes(KEY), `CONFIDENTIALITY VIOLATION: ${route} signed out carries the registered key`);
      else noValue(body, `${route} signed out`);
    }
  } finally {
    await dashboard.close();
    wired?.close();
    data.close();
    await arbiter.close();
    resetCurrentPolicyForTests();
    rmSync(tmp, { recursive: true, force: true });
  }
});
