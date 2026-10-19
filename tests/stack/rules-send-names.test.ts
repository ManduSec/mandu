/**
 * rules-send-names.test — on the Rules page a row of *Sending data* names
 * its data and its sources as code, and a send rule to anywhere says
 * "anywhere" as a word, across the REAL components (dashboard.md §4.25u
 * *Rules names what a send covers*). Mandu-new.
 *
 * Until 2026-10-16 the line under each row was one text ("sending only the
 * file ~/proj/.env", "sending any masked data from docs.python.org"), while
 * the Approvals card that made the answer names the file as code, and a
 * send rule to `*` was the chip `anywhere`, a word in the code font.
 *
 * Here a real ArbiterServer (secrets) holds a policy.yaml with three send
 * rules (to anywhere from `docs.python.org`, to `api.github.com` from
 * `*.internal.example`, to `b.example` from any source) and a registered
 * `.env`; its real gate asks about the key's send to a host no rule binds
 * it to, and the answer is Block over the real route (`deny`, which is
 * kept). A real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`) serves the panel and the Rules page:
 *
 *   S1  `/api/policy/panel`, signed in and signed out: the answer's
 *       `plain.reachParts` name the file `~/proj/.env` as code; each send
 *       rule's names its source; the rule to `*` has the subject parts
 *       "anywhere" as a word; a reach that names nothing has no parts; the
 *       parts are the reach, byte for byte;
 *   S2  the served Rules page (its own index.html and home.js in jsdom under
 *       the served styles at 320 px): each line reads so, each name a code
 *       in its box, "anywhere" no code, the ⋯ named "More about anywhere";
 *   S3  the oracle: neither the panel (either way), `/api/home` nor the
 *       rendered page carries the registered value; the page and
 *       `/api/home` carry no token;
 *   S4  (2026-10-17, §4.25u *A send rule's dot is its answer's*) on the
 *       served page each send rule's menu has the dot of an answer with the
 *       same words: the two block rules and the Block answer one red, the
 *       allow rule green, and a fourth rule, expired, the grey ring.
 *
 * Axes: secrets (stated).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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

const KEY_VALUE = "sk_live_rulesSendNamesStackCanary00000001";
const SESSION = "1791210000-777";
const DEST = "uploads.example-storage.net";
/** A minted token (the panel's own help text names the `$MDU:` form). */
const TOKEN = /\$MDU:[A-Za-z_][A-Za-z0-9_-]*\[[0-9a-f]{4,8}\]/;

type Part = { kind: string; text: string };
type Plain = { subject: string; subjectParts?: Part[]; reach: string | null; reachParts?: Part[] };
type Row = { id: string; subject: string; plain: Plain };
const shown = (parts: Part[] | undefined) => parts?.map((p) => (p.kind === "code" ? `[${p.text}]` : p.text)).join("") ?? null;

/** Each send row: its subject, its subject parts, its reach as drawn. */
const WANT_RULES = [
  ["r-0004", "anywhere", "anywhere", "sending any masked data from [docs.python.org]"],
  ["r-0005", "api.github.com", null, "sending any masked data from [*.internal.example]"],
  ["r-0002", "b.example", null, null],
] as const;

test("Rules over the real arbiter: a send row names its file and sources as code, and \"anywhere\" as a word; no value on the page (secrets axes, explicit)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-send-names-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "user_rules:",
    '  - { id: r-0004, kind: release, from: { host: docs.python.org }, to: { host: "*" }, mode: allow }',
    '  - { id: r-0005, kind: release, from: { host: "*.internal.example" }, to: { host: api.github.com }, mode: block }',
    "  - { id: r-0002, kind: release, to: { host: b.example }, mode: block }",
    '  - { id: r-0006, kind: release, to: { host: old.example }, mode: block, expires: "2026-01-01T00:00:00Z" }',
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
  const gate = new ArbiterClient(socketPath);
  await gate.connect();
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
    assert.ok(!body.includes(KEY_VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the registered value`);
    assert.doesNotMatch(body, TOKEN, `${where} carries no token`);
  };
  try {
    // A registered `.env`: its key has its own symbol; the real gate asks
    // about sending it to a host no rule binds it to.
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\nDEBUG=1\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const d = await gate.desymbolizationDecision({ symbol: keySym!, boundary: "network", destination: DEST, sessionKey: SESSION, scheme: "https" });
    assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, `the send waits for an answer: ${JSON.stringify(d)}`);
    const askId = String((d as { approvalId?: string }).approvalId);
    // Block, kept: over the real route, as the Approvals page answers.
    const r0 = await pageFetch(`${base}/api/egress/approvals/${askId}/deny`, { method: "POST", headers: CSRF_ADMIN });
    assert.equal(r0.status, 200, `the answer is taken: ${await r0.text()}`);

    // ── S1: the panel, signed in and signed out ──
    for (const [who, headers] of [["signed in", CSRF_ADMIN], ["signed out", {}]] as const) {
      const r = await pageFetch(`${base}/api/policy/panel`, { headers });
      const body = await r.text();
      assert.equal(r.status, 200, `${who}: ${body}`);
      assert.ok(!body.includes(KEY_VALUE), `CONFIDENTIALITY VIOLATION: the panel ${who} carries the registered value`);
      const panel = (JSON.parse(body) as { panel: { yourRules: Row[]; queue: Array<{ id: string; status: string; plain: Plain }> } }).panel;
      const rules = Object.fromEntries(panel.yourRules.map((x) => [x.id, x]));
      assert.deepEqual(WANT_RULES.map(([id]) => [id, rules[id]!.plain.subject, shown(rules[id]!.plain.subjectParts), shown(rules[id]!.plain.reachParts)]), WANT_RULES.map((w) => [...w]), `${who}: each send rule's words`);
      assert.equal(rules["r-0002"]!.plain.reach, "sending any masked data", `${who}: a reach naming nothing is its words alone`);
      assert.equal(rules["r-0004"]!.subject, "anywhere", `${who}: the row's own subject is unchanged`);
      const answer = panel.queue.find((q) => q.id === askId);
      assert.ok(answer, `${who}: the answer is listed`);
      assert.equal(answer!.status, "denied");
      assert.equal(answer!.plain.reach, "sending only the file ~/proj/.env", `${who}: the answer names its file`);
      assert.equal(shown(answer!.plain.reachParts), "sending only the file [~/proj/.env]", `${who}: the file as code`);
      for (const p of [...Object.values(rules).map((x) => x.plain), answer!.plain]) {
        if (p.reachParts) assert.equal(p.reachParts.map((x) => x.text).join(""), p.reach, `${who}: the parts are the reach, byte for byte`);
      }
    }

    // ── S2: the served Rules page at 320 px ──
    const css = async (f: string) => {
      const r = await pageFetch(`${base}/${f}`);
      assert.equal(r.status, 200, `${f} is served`);
      return r.text();
    };
    const styles = resolveCssVars(stylesAt(`${await css("mandu.css")}\n${await css("app.css")}`, 320));
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    type Doc = any;
    const sendRows = (doc: Doc): Doc[] => [...doc.querySelectorAll("#rules-list .row.rule")].filter((r: Doc) => /sending/.test(r.querySelector(".rule-text > .dim")?.textContent ?? ""));
    /** A node's words and names in order, each name as `[name]`. */
    const drawn = (node: Doc): string => {
      if (node.nodeType === 3) return node.textContent;
      if (node.tagName === "CODE") return `[${node.textContent}]`;
      return [...node.childNodes].map(drawn).join("");
    };
    await servedProductPage(base, "/rules", (doc: Doc) => sendRows(doc).length === 5, async (doc: Doc) => {
      const win = doc.defaultView;
      const lines = sendRows(doc).map((r) => [drawn(r.querySelector(".rule-text").firstElementChild), drawn(r.querySelector(".rule-text > .dim"))]);
      assert.deepEqual(lines.sort((a, b) => a[0]!.localeCompare(b[0]!)), [
        ["[api.github.com]", "sending any masked data from [*.internal.example]"],
        ["[b.example]", "sending any masked data"],
        ["[old.example]", "sending any masked data"],
        [`[${DEST}]`, "sending only the file [~/proj/.env]"],
        ["anywhere", "sending any masked data from [docs.python.org]"],
      ], "each row names its data and sources as code, and anywhere as a word");
      for (const r of sendRows(doc)) {
        for (const c of r.querySelectorAll(".rule-text > .dim code")) {
          assert.ok(c.parentElement.classList.contains("name-fit"), `${c.textContent}: kept whole in its box`);
          assert.equal(win.getComputedStyle(c.parentElement).maxWidth, "100%", `${c.textContent}: no wider than its line`);
          assert.notEqual(win.getComputedStyle(c).whiteSpace, "nowrap", `${c.textContent}: wraps inside only where the column is narrower`);
        }
      }
      const any = sendRows(doc).find((r) => r.querySelector(".rule-text").title === "anywhere");
      assert.equal(any.querySelector(".rule-subject code"), null, "anywhere is no code");
      assert.equal(any.querySelector(".file-more").getAttribute("aria-label"), "More about anywhere");
      noValue(doc.body.textContent ?? "", "the Rules page");

      // ── S4: a send rule's dot is its answer's ──
      const byTitle = (t: string) => sendRows(doc).find((r) => r.querySelector(".rule-text").title === t);
      const menu = (t: string) => [byTitle(t).querySelector("select").options[0].textContent, byTitle(t).querySelector(".label-pick").getAttribute("data-effect")];
      assert.deepEqual(["anywhere", "api.github.com", "b.example", "old.example", DEST].map(menu), [
        ["Always allowed", "allow"],
        ["Always blocked", "block"],
        ["Always blocked", "block"],
        ["Expired, no longer used", "none"],
        ["Always blocked", "block"],
      ], "each menu's colour is what the rule does now, as the answer's is");
      const dot = (t: string) => win.getComputedStyle(byTitle(t).querySelector(".label-dot")).backgroundColor;
      assert.equal(dot("b.example"), dot(DEST), "a block rule's dot is the Block answer's");
      assert.equal(dot("api.github.com"), dot(DEST), "both block rules alike");
      assert.notEqual(dot("anywhere"), dot(DEST), "allowed is not blocked's colour");
      assert.notEqual(dot("old.example"), dot(DEST), "an expired rule's dot is not filled red");
      assert.notEqual(dot("old.example"), dot("anywhere"), "nor green");
    }, { headers: { Cookie: ADMIN_COOKIE, "X-Mandu-Control": "1" }, css: styles });

    // ── S3: the routes the page reads, signed out ──
    for (const route of ["/api/policy/panel", "/api/home", "/rules"]) {
      const r = await pageFetch(base + route);
      const body = await r.text();
      assert.equal(r.status, 200, `${route}: ${body}`);
      if (route === "/api/policy/panel") assert.ok(!body.includes(KEY_VALUE), `CONFIDENTIALITY VIOLATION: ${route} signed out carries the registered value`);
      else noValue(body, `${route} signed out`);
    }
  } finally {
    await dashboard.close();
    wired?.close();
    gate.close();
    await arbiter.close();
    resetCurrentPolicyForTests();
    rmSync(tmp, { recursive: true, force: true });
  }
});
