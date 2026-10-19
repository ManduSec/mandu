/**
 * dim-ink — the words the product page marks secondary (`.dim`: a caption,
 * a note, a status line, an empty list, where a label comes from) read as
 * secondary wherever they are, across the REAL components (dashboard.md
 * §4.25k *Secondary words read as secondary*). Mandu-new.
 *
 * Until 2026-10-16 app.css had no page-wide `.dim` rule, only a row's
 * (`--ink-4`) and two scoped ones, so a `.dim` anywhere else drew in its
 * parent's ink, mostly the full `--ink`: Approvals' "This change has no
 * limit on one side.", Your rules' Patterns and Places captions, an opened
 * rule's "Your rule, this file only", Add a rule's "This folder:", Keys
 * Mandu found's not-offered line and its empty list. jsdom draws nothing but
 * runs the cascade and inherits `color` as a browser does, so the served
 * page runs with its served stylesheets.
 *
 * A real ArbiterServer (secrets) holds a policy.yaml with a pattern rule
 * and three rules in one folder: two files (one holding a value) and a
 * folder. The agent's own channel asks the real policyPropose op to let
 * its programs connect anywhere: a wide change, held for the person. A
 * real DashboardServer over the production adapter serves Rules and
 * Approvals, signed in:
 *
 *   K1  Rules, with Keys Mandu found and Add a rule opened and the file's
 *       rule opened, light and dark: every `.dim` with words reads
 *       `--ink-4` in a row and `--ink-3` anywhere else, never the full or
 *       the second ink; the lines above and the folder's count of its
 *       rules are among them;
 *   K2  Approvals, light and dark: the wide change's "This change has no
 *       limit on one side." reads `--ink-3`, as every `.dim` there does;
 *   K3  the oracle: no page or answer read here carries the file's value or
 *       a minted token; policy.yaml is as it was, and the change still
 *       waits;
 *   K4  the faintest ink reads (§4.25k *The faintest ink reads too*): the
 *       wide change's card labels on Approvals ("This would let", "Your
 *       agent says") and Rules' column heads each read at least 4.5:1 on
 *       the ground under them, light and dark, from the served mandu.css.
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
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
import { contrastRatio, perSelector, resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const FLAG = process.env.MANDU_EXPERIMENTAL_POLICY_MODEL;
delete process.env.MANDU_EXPERIMENTAL_POLICY_MODEL; // the picker as shipped
after(() => {
  resetCurrentPolicyForTests("claude-code");
  if (FLAG !== undefined) process.env.MANDU_EXPERIMENTAL_POLICY_MODEL = FLAG;
});

const VALUE = `sk_live_dimInkCanary_${process.pid}_0`;
/** A minted token (the panel's own help text names the `$MDU:` form). */
const TOKEN = /\$MDU:[A-Za-z_][A-Za-z0-9_-]*\[[0-9a-f]{4,8}\]/;
type Theme = "light" | "dark";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

/** A color as jsdom computes it (`rgb(…)`). */
function computedColor(doc: Doc, value: string): string {
  const p = doc.createElement("i");
  p.style.color = value;
  doc.body.append(p);
  const out = doc.defaultView.getComputedStyle(p).color;
  p.remove();
  return out;
}
/** A theme's token in the served styles. */
function token(css: string, name: string, theme: Theme): string {
  return /\.token-probe \{ --probe:\s*([^;]+);/.exec(resolveCssVars(`${css}\n.token-probe { --probe: var(${name}); }`, theme))![1]!.trim();
}
const words = (e: Doc): string => e.textContent.trim().replace(/\s+/g, " ");
/** Each `.dim` with words the page draws: its words, its ink by token name,
 *  and the ink it should have (a row's own `--ink-4`, else the note's). */
function dims(doc: Doc, css: string, theme: Theme): Array<{ text: string; ink: string; want: string; where: string }> {
  const inks = new Map(["--ink", "--ink-2", "--ink-3", "--ink-4"].map((t) => [computedColor(doc, token(css, t, theme)), t]));
  return ([...doc.querySelectorAll(".dim")] as Doc[])
    .filter((e) => !e.closest("[hidden]") && e.textContent.trim())
    .map((e) => {
      const color = doc.defaultView.getComputedStyle(e).color;
      return { text: words(e), ink: inks.get(color) ?? color, want: e.parentElement.closest(".row") ? "--ink-4" : "--ink-3", where: `${e.className} in ${e.parentElement.className || e.parentElement.id}` };
    });
}

/** The color of the nearest ground under `e`: the first ancestor (or
 *  itself) with a background color of its own, else the page's. */
function groundOf(e: Doc): string {
  const win = e.ownerDocument.defaultView;
  for (let n = e; n; n = n.parentElement) {
    const bg = win.getComputedStyle(n).backgroundColor;
    if (bg && bg !== "transparent" && !/^rgba\([^)]*,\s*0\)$/.test(bg)) return bg;
  }
  return win.getComputedStyle(e.ownerDocument.body).backgroundColor;
}

test("the product page over the real arbiter: every secondary line reads the note's ink, a row's the fainter one; no value on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-dim-ink-"));
  const home = join(tmp, "home");
  const project = join(home, "mandu-try");
  mkdirSync(join(project, "notes"), { recursive: true });
  const env = join(project, ".env");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  writeFileSync(join(project, "deploy.token"), "a token\n");
  const policyPath = join(tmp, "policy.yaml");
  const policy = [
    "version: 1",
    "paths:",
    `  - { path: "${env}", level: no-model, bindings: [api.stripe.com] }`,
    `  - { path: "${join(project, "deploy.token")}", level: no-model }`,
    `  - { path: "${join(project, "notes")}", level: local-model }`,
    '  - { path: "**/*.pem", level: no-model }',
    "",
  ].join("\n");
  writeFileSync(policyPath, policy);
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  const agent = new ArbiterClient(socketPath);
  await agent.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets && wired.policyDoc, "the production adapter has the secrets and policy surfaces");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath, HOME: home },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const signedIn = { Cookie: ADMIN_COOKIE };
  const noValue = (body: string, where: string) => {
    assert.ok(!body.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the file's value`);
    assert.doesNotMatch(body, TOKEN, `${where} carries no token`);
  };
  const read = async (path: string, headers: Record<string, string>): Promise<string> => {
    const r = await pageFetch(base + path, { headers });
    const body = await r.text();
    assert.equal(r.status, 200, `${path}: ${body.slice(0, 200)}`);
    noValue(body, path);
    return body;
  };
  try {
    // The agent asks to let its programs connect anywhere: a wide change.
    const asked = await agent.policyPropose({ edits: [{ op: "allow-connect", host: "*" }], reason: "dim ink", sessionKey: "s-dim" });
    assert.ok(!asked.applied && "proposalId" in asked, `a wide change waits for the person: ${JSON.stringify(asked)}`);
    const proposalId = asked.proposalId;
    const sheets = `${await read("/mandu.css", signedIn)}\n${await read("/app.css", signedIn)}`;
    const styled = (doc: Doc, theme: Theme) => {
      const sheet = [...doc.head.querySelectorAll("style")].at(-1);
      assert.ok(sheet, "the served styles are applied");
      sheet.textContent = perSelector(resolveCssVars(stylesAt(sheets, 1280), theme));
    };
    const check = (doc: Doc, page: string, must: RegExp[]) => {
      for (const theme of ["light", "dark"] as const) {
        styled(doc, theme);
        const seen = dims(doc, sheets, theme);
        for (const d of seen) assert.equal(d.ink, d.want, `${theme}, ${page}: "${d.text.slice(0, 60)}" (${d.where}) reads ${d.want}`);
        for (const m of must) {
          const hit = seen.find((d) => m.test(d.text));
          assert.ok(hit, `${theme}: ${page} draws ${m}: ${JSON.stringify(seen.map((d) => d.text))}`);
          assert.equal(hit.ink, "--ink-3", `${theme}: ${page}'s ${m} reads the note's ink`);
        }
      }
    };
    /** K4: each of `selector` with words reads 4.5:1 on its ground, both themes. */
    const readsAA = (doc: Doc, page: string, selector: string, must: string[]) => {
      for (const theme of ["light", "dark"] as const) {
        styled(doc, theme);
        const seen = ([...doc.querySelectorAll(selector)] as Doc[]).filter((e) => !e.closest("[hidden]") && e.textContent.trim());
        for (const e of seen) {
          const ratio = contrastRatio(doc.defaultView.getComputedStyle(e).color, groundOf(e));
          assert.ok(ratio >= 4.5, `${theme}, ${page}: ${selector} "${words(e)}" reads ${ratio.toFixed(2)}:1, under 4.5:1`);
        }
        for (const w of must) assert.ok(seen.some((e) => words(e) === w), `${theme}, ${page} draws ${selector} "${w}": ${JSON.stringify(seen.map(words))}`);
      }
    };

    // ── K1: Rules ──
    await servedProductPage(base, "/rules", (doc: Doc) => !!doc.querySelector(`#files-tree .row.file-rule[data-path="${env}"]`), async (doc: Doc) => {
      doc.getElementById("suggest-open").click();
      await waitWhile(() => doc.getElementById("files-suggested-view").hidden || !doc.getElementById("suggest-model-why").textContent || !doc.querySelector("#files-suggested-list .empty-row"));
      doc.getElementById("rules-add").click();
      await waitWhile(() => !doc.querySelector("#files-list .row.file") || doc.getElementById("files-self").hidden);
      doc.querySelector(`#files-tree .row.file-rule[data-path="${env}"] .file-more`).click();
      await waitWhile(() => !doc.querySelector("#files-tree .file-detail .detail-label"));
      check(doc, "Rules", [
        /^apply to every file that matches$/,
        /^a rule inside a folder rule is more specific, so it wins for its own files$/,
        /^\d+ rules$/,
        /^Your rule, this file only$/,
        /^This folder:$/,
        /^Asking a model to suggest rules is not offered yet: it is still being tested\.$/,
        /^No suggestions\. Press Scan for keys/,
      ]);
      // ── K4: Rules' column heads ──
      readsAA(doc, "Rules", ".files-heads span", ["File or folder", "Which AI may read it", "Where it may be sent"]);
      noValue(doc.body.textContent, "the rendered Rules page");
    }, { headers: signedIn, css: "" });

    // ── K2: Approvals ──
    await servedProductPage(base, "/approvals", (doc: Doc) => !!doc.querySelector("#approvals-proposals .proposal-confirm"), async (doc: Doc) => {
      check(doc, "Approvals", [/^This change has no limit on one side\.$/]);
      // ── K4: the card's labels ──
      readsAA(doc, "Approvals", "#approvals-proposals .proposal-k", ["This would let", "Your agent says"]);
      noValue(doc.body.textContent, "the rendered Approvals page");
    }, { headers: signedIn, css: "" });

    // ── K3: the oracle ──
    for (const route of ["/api/home", "/api/policy/panel", "/api/secrets", "/api/suggestions", "/api/policy/proposals?status=pending", "/rules", "/approvals", "/"]) await read(route, route.startsWith("/api/") ? CSRF_ADMIN : signedIn);
    const pending = JSON.parse(await read("/api/policy/proposals?status=pending", CSRF_ADMIN)) as { proposals: Array<{ id: string; overBroad: boolean }> };
    assert.deepEqual(pending.proposals.map((p) => [p.id, p.overBroad]), [[proposalId, true]], "the wide change still waits");
    assert.equal(readFileSync(policyPath, "utf8"), policy, "nothing was saved");
  } finally {
    await dashboard.close();
    wired.close();
    agent.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
