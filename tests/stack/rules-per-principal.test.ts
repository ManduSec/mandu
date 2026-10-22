/**
 * rules-per-principal e2e — the Rules page's "Who may get your secrets"
 * card (dashboard.md §4.25aa, confidentiality plan 13 §5.3) through the
 * PRODUCTION wiring: `makeApprovalsArbiter(dataSock, () => ({ socketPath:
 * adminSock }))` over a REAL ArbiterServer with a file-backed law, and a real
 * DashboardServer serving `GET /api/policy/by-who`.
 *
 * The view reads the same rules per program, per host and per AI. It is read
 * only, so what it must prove is that it says what the arbiter enforces:
 *
 *   1. per program: the `readers:` lists, each entry as the arbiter judges it
 *      (a database shell never gets the real file), and a label made on the
 *      page (no list) giving every program a masked copy;
 *   2. per host: a host the view says gets a file's value without asking is
 *      one the egress gate releases that file's key to, and "Any other host"
 *      is one it does not (the invariant's network half);
 *   3. per AI: the levels as the arbiter reads them for each path;
 *   4. the answer never carries a value;
 *   5. the served page, as a 1280 px screen and a 390 px phone apply its
 *      styles: a file in the Programs tab opens its rule's row under Your
 *      rules (dashboard.md §4.25aa *Where*), unfolding the folder above it,
 *      with the keyboard focus on the row's ⋯, and the page shows no value.
 */
import { test, after } from "node:test";
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
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const SECRET = "sk-live-BYWHO-NEVER-SHOWN";

test("per principal over the real arbiter: programs, hosts and AI read back as the arbiter enforces them, a file opens its rule in Your rules, never a value", { timeout: 120_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-by-who-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const ws = join(home, "ws");
  mkdirSync(ws, { recursive: true });
  const envPath = join(ws, ".env");
  const notesPath = join(ws, "notes.md");
  const contractPath = join(ws, "contract.txt");
  const memoPath = join(ws, "memo.txt");
  writeFileSync(envPath, `STRIPE_KEY=${SECRET}\n`);
  writeFileSync(notesPath, "notes\n");
  writeFileSync(contractPath, "contract\n");
  writeFileSync(memoPath, "memo\n");

  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "models:",
    "  - { name: vllm-1, url: \"http://127.0.0.1:8000/v1\", wire: openai-chat, local: true }",
    "paths:",
    `  - { path: "${envPath}", level: no-model, recursive: false, bindings: [api.stripe.com], readers: [{ app: deploy, prints: nothing }, psql] }`,
    `  - { path: "${notesPath}", level: any-model, recursive: false }`,
    `  - { path: "${contractPath}", level: local-model, recursive: false }`,
    "",
  ].join("\n"));
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath, policyPollMs: 0, integrity: false, confidentiality: true, log: () => {},
  });
  await arbiter.listen();
  const gate = new ArbiterClient(dataSock);
  await gate.connect();
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets && wired.policyDoc);
  const server = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: dataSock }),
    approvalsArbiter: wired.arbiter,
    secretsArbiter: wired.secrets,
    policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    log: () => {},
    ...ADMIN_OPTS,
  });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}`;
  const byWho = async () => {
    const r = await pageFetch(`${base}/api/policy/by-who`, { headers: CSRF_ADMIN });
    assert.equal(r.status, 200);
    const raw = await r.text();
    assert.ok(!raw.includes(SECRET), "the view never carries a value");
    return (JSON.parse(raw) as any).byWho;
  };
  const lists = (rows: any[], name: string) => {
    const row = rows.find((x) => x.name === name);
    assert.ok(row, `a row for ${name}: ${rows.map((x) => x.name).join(" | ")}`);
    return Object.fromEntries(row.groups.map((g: any) => [g.label, g.items.map((i: any) => i.path + (i.how ? ` (${i.how})` : ""))]));
  };
  const reg = await gate.registerSecret({ path: envPath, sessionKey: "by-who" });
  const token = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
  assert.ok(token, "the key has its own symbol");
  const egress = (host: string) => gate.desymbolizationDecision({ symbol: token!, boundary: "network", destination: host, sessionKey: "by-who", scheme: "https" });

  try {
    // A label made on the page (not in policy.yaml) joins the view.
    const made = await pageFetch(`${base}/api/secrets/label`, {
      method: "POST", headers: { ...CSRF_ADMIN, "Content-Type": "application/json" },
      body: JSON.stringify({ path: memoPath, confidentiality: "any-model", bindings: ["api.example.com"], recursive: false }),
    });
    assert.equal(made.status, 200, await made.clone().text());

    const v = await byWho();
    assert.equal(v.available, true);
    assert.equal(v.partial, false, "both places rules live were read");

    // 1. Per program, as the arbiter judges each entry.
    assert.deepEqual(v.programs.rows.map((r: any) => r.name), ["deploy", "psql", "Any other program"]);
    // Only what differs from Any other program (§4.25aa *Only what differs*):
    // the masked files moved to the closing row, and a line counts them.
    assert.deepEqual(lists(v.programs.rows, "deploy"), { "Opens the real file": ["~/ws/.env (your word)"] });
    assert.equal(v.programs.rows.find((r: any) => r.name === "deploy").rest, "The rest (3): as any other program, below.");
    assert.deepEqual(lists(v.programs.rows, "psql"), { "Never gets the real file: it prints or runs what it reads": ["~/ws/.env"] });
    assert.deepEqual(lists(v.programs.rows, "Any other program"), {
      "Gets a masked copy": ["~/ws/contract.txt", "~/ws/memo.txt", "~/ws/notes.md"],
      "Refused": ["~/ws/.env"],
    });
    // Every secret file is in a named row's lists or counted by its rest.
    for (const r of v.programs.rows.filter((x: any) => x.kind === "named")) {
      const shown = r.groups.flatMap((g: any) => g.items.map((i: any) => i.rule));
      const rest = Number(/^The rest \((\d+)\)/.exec(r.rest ?? "")?.[1] ?? 0);
      assert.equal(new Set(shown).size + rest, v.secretCount, `${r.name}: ${shown.join(", ")} + ${rest}`);
    }
    assert.equal(v.secretCount, 4);

    // 2. Per host, and the egress gate agrees.
    assert.deepEqual(v.hosts.rows.map((r: any) => r.name), ["api.example.com", "api.stripe.com", "Any other host"]);
    assert.deepEqual(lists(v.hosts.rows, "api.stripe.com"), { "Gets the real value without asking": ["~/ws/.env"] });
    assert.deepEqual(lists(v.hosts.rows, "api.example.com"), { "Gets the real value without asking": ["~/ws/memo.txt"] });
    assert.equal((await egress("api.stripe.com")).allow, true, "the host the view names gets the key");
    assert.equal((await egress("api.example.com")).allow, false, "a host named for another file does not");
    assert.equal((await egress("paste.example")).allow, false, "any other host does not");

    // 3. Per AI, and the arbiter reads the same levels.
    assert.deepEqual(v.models.rows.map((r: any) => r.name), ["Any AI", "vllm-1"]);
    assert.deepEqual(lists(v.models.rows, "Any AI"), {
      "May read it when it asks": ["~/ws/memo.txt", "~/ws/notes.md"],
      "Always sees it masked": ["~/ws/.env", "~/ws/contract.txt"],
    });
    assert.deepEqual(lists(v.models.rows, "vllm-1")["May read it when it asks"], ["~/ws/contract.txt", "~/ws/memo.txt", "~/ws/notes.md"]);
    assert.equal((await gate.pathLevel(envPath)).level, "no-model");
    assert.equal((await gate.pathLevel(notesPath)).level, "any-model");
    assert.equal((await gate.pathLevel(contractPath)).level, "local-model");
    assert.equal((await gate.pathLevel(memoPath)).level, "any-model");

    // 5. The served page: a file opens its rule's row under Your rules.
    const signedIn = { Cookie: ADMIN_COOKIE };
    const sheets = `${await (await pageFetch(`${base}/mandu.css`, { headers: signedIn })).text()}\n${await (await pageFetch(`${base}/app.css`, { headers: signedIn })).text()}`;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    type Doc = any;
    const envRow = (doc: Doc) => ([...doc.querySelectorAll("#files-tree .row.file-rule")] as Doc[]).find((r) => r.getAttribute("data-path") === envPath);
    const wsFolder = (doc: Doc) => ([...doc.querySelectorAll("#files-tree .rules-folder")] as Doc[]).find((f) => f.title === "~/ws");
    for (const width of [1280, 390]) {
      const where = `the Rules page at ${width}px`;
      await servedProductPage(base, "/rules", (doc: Doc) => !!envRow(doc) && !!doc.querySelector("#by-who-list .by-who-link"), async (doc: Doc) => {
        assert.equal(doc.getElementById("by-who-tab-programs").getAttribute("aria-selected"), "true");
        const deploy = ([...doc.querySelectorAll("#by-who-list .by-who-row")] as Doc[]).find((r) => r.querySelector(".by-who-name > :first-child").textContent === "deploy");
        assert.ok(deploy, `${where}: a row for deploy`);
        const link = ([...deploy.querySelectorAll("button.by-who-link")] as Doc[]).find((b) => b.textContent === "~/ws/.env");
        assert.ok(link, `${where}: deploy's ~/ws/.env is a button`);
        assert.equal(deploy.querySelector(".by-who-rest")?.textContent, "The rest (3): as any other program, below.", `${where}: deploy's rest line`);
        assert.equal(link.getAttribute("aria-label"), "Show the rule for ~/ws/.env in Your rules");
        // The rule sits under the folder heading ~/ws, folded shut first.
        assert.ok(wsFolder(doc), `${where}: Your rules has the heading ~/ws`);
        wsFolder(doc).click();
        assert.notEqual(envRow(doc).closest("[hidden]"), null, `${where}: folded out of sight`);
        link.focus();
        link.click();
        await waitWhile(() => !doc.querySelector("#files-tree .file-detail"));
        const row = envRow(doc);
        assert.equal(wsFolder(doc).getAttribute("aria-expanded"), "true", `${where}: the folder above it is unfolded`);
        assert.ok(row.classList.contains("open"), `${where}: its row is open`);
        assert.ok(row.nextElementSibling?.classList.contains("file-detail"), `${where}: what the rules say is under it`);
        assert.equal(row.closest("[hidden]"), null, `${where}: in sight`);
        assert.equal(doc.activeElement, row.querySelector(".file-more"), `${where}: the focus is on its ⋯`);
        assert.ok(!doc.body.textContent.includes(SECRET), `CONFIDENTIALITY VIOLATION: ${where} shows the value`);
      }, { headers: signedIn, css: resolveCssVars(stylesAt(sheets, width)) });
    }
  } finally {
    await server.close();
    wired.close();
    gate.close();
    await arbiter.close();
  }
});
