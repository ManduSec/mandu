/**
 * home-js-change-history-agent.test — a row of Approvals › *Rule changes*
 * that your agent made, or asked for and you approved, links the agent that
 * did it (public/js/home.js `loadRuleHistory`; dashboard.md §4.25 *A rule
 * change and the agent that asked*).
 *
 * Until 2026-10-12 the history's projection dropped the change's session
 * (view-model/policy-proposals.ts `toChangeRow`), so "Your agent tightened
 * your rules" and "You approved a change your agent asked for" led nowhere,
 * while the same change's line on the Rules page, an *Answered earlier* row
 * and the waiting request's card each say "See what the agent was doing".
 * Now the row carries `session` for those two kinds, and its line under the
 * words ends with that link, to the agent page at its top:
 *
 *   - the link's address, its click opening the agent's page;
 *   - no link on a row of yours, an Undo, an older server's row (no
 *     `session`) or one with none recorded; the moment still drawn;
 *   - the row is still named by its sentence, never by the link;
 *   - Undo on such a row still works and keeps the focus on the row; a
 *     poll that draws the history again keeps a focus on the link;
 *   - (#92, 2026-10-23) a row whose server says `who` names the agent Home
 *     lists for its session, "Claude Code tightened your rules", and its
 *     folder after the moment; a session Home does not list keeps the
 *     server's words; the row's name and Undo's follow the sentence.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts); across the real arbiter and dashboard,
 * tests/stack/change-history-agent-link.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, CLOCK, T, home, load, tick } from "./home-js-fixtures.js";

const APPROVALS = "http://127.0.0.1:4500/mandu/approvals";
const CHANGES = "GET policy/changes?limit=21";
const LINK = "See what the agent was doing";

const change = (id: string, sentence: string, over: Record<string, unknown> = {}) => ({
  id, sentence, rows: [[T("Hide "), { kind: "code", text: "~/proj/x.pem" }, T(" from the AI")]],
  createdAt: Date.now() - 60_000, undone: false, undoable: true, session: null, ...over,
});
const TIGHTENED = change("pc-000003", "Your agent tightened your rules", { session: "s1" });
const APPROVED = change("pc-000002", "You approved a change your agent asked for", { session: "s2", undoable: false });
const YOURS = change("pc-000001", "You changed a rule on the Rules page");

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const rowOf = (doc: Doc, id: string) => [...doc.querySelectorAll("#approvals-rule-history .row")].find((r: Doc) => r.dataset.id === id);
const linkOf = (doc: Doc, id: string) => rowOf(doc, id).querySelector("a.ask-link");
const whenOf = (doc: Doc, id: string) => rowOf(doc, id).querySelector(".answered-when");
const nameOf = (doc: Doc, row: Doc) => (row.getAttribute("aria-labelledby") || "").split(" ").map((i: string) => doc.getElementById(i)?.textContent ?? "").join(" ");
const quiet = () => home({ waiting: [], verdict: "protected", headline: "Your secrets are guarded." });
async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}

test("a change your agent made, or asked for: the line under its words ends with 'See what the agent was doing', to that agent's page", async () => {
  const { doc } = load({ url: APPROVALS, homeVm: quiet(), routes: { [CHANGES]: { changes: [TIGHTENED, APPROVED, YOURS] } } });
  await tick(40);
  assert.equal(doc.getElementById("approvals-rule-history-block").hidden, false);
  for (const [id, session] of [["pc-000003", "s1"], ["pc-000002", "s2"]] as const) {
    const a = linkOf(doc, id);
    assert.ok(a, `${id}: the row links the agent`);
    assert.equal(a.textContent, LINK);
    assert.equal(a.getAttribute("href"), `/mandu/agents/${session}`, "the agent page at its top: no ask");
    assert.equal(a.dataset.session, session);
    assert.equal(a.dataset.pageLink, "agent");
    assert.equal(a.hasAttribute("data-ask"), false);
    // The moment, then the link, on the one line under the words.
    assert.ok(whenOf(doc, id).contains(a), "on the moment's line");
    assert.match(whenOf(doc, id).textContent, new RegExp(`^${CLOCK} · [^.]+\\. ${LINK}$`));
  }
});

test("a row of yours, an Undo, an older server's row or one with no session recorded: no link, the moment as before", async () => {
  const rows = [
    YOURS,
    change("pc-000004", "You undid an earlier change", { undoable: false }),
    change("pc-000005", "Your agent tightened your rules", { session: undefined }),
    change("pc-000006", "You approved a change your agent asked for", { session: "" }),
  ];
  const { doc } = load({ url: APPROVALS, homeVm: quiet(), routes: { [CHANGES]: { changes: rows } } });
  await tick(40);
  for (const r of rows) {
    assert.ok(rowOf(doc, r.id), `${r.id}: drawn`);
    assert.equal(linkOf(doc, r.id), null, `${r.id}: no link`);
    assert.match(whenOf(doc, r.id).textContent, new RegExp(`^${CLOCK} · [^.]+$`), `${r.id}: the moment alone`);
  }
});

test("the row is still named by its sentence, never by the link", async () => {
  const { doc } = load({ url: APPROVALS, homeVm: quiet(), routes: { [CHANGES]: { changes: [TIGHTENED] } } });
  await tick(40);
  const row = rowOf(doc, TIGHTENED.id);
  assert.equal(row.getAttribute("role"), "group");
  assert.equal(nameOf(doc, row), "Your agent tightened your rules");
  assert.ok(row.contains(linkOf(doc, TIGHTENED.id)), "the link is in the row, outside its name");
});

test("the link opens the agent's page", async () => {
  const { doc } = load({ url: APPROVALS, homeVm: quiet(), routes: { [CHANGES]: { changes: [TIGHTENED] }, "GET home/agent?session=s1": { ...AGENT, waiting: [] } } });
  await tick(40);
  linkOf(doc, TIGHTENED.id).click();
  await tick(40);
  assert.equal(doc.getElementById("page-agent").hidden, false);
  assert.equal(doc.getElementById("page-approvals").hidden, true);
  assert.equal(doc.getElementById("agent-name").textContent, "Claude Code");
  assert.equal(doc.defaultView.location.pathname, "/mandu/agents/s1");
});

test("Undo on an agent's change still works: the row keeps the focus, drawn again as undone with its link", async () => {
  let changes = [TIGHTENED];
  const { doc, calls } = load({ url: APPROVALS, homeVm: quiet(), routes: {
    [CHANGES]: () => ({ changes }),
    "POST policy/changes/pc-000003/undo": () => ((changes = [{ ...TIGHTENED, undone: true, undoable: false }]), {}),
  } });
  await tick(40);
  const undo = [...rowOf(doc, TIGHTENED.id).querySelectorAll("button")].find((b: Doc) => b.textContent === "Undo");
  undo.focus();
  undo.click();
  await tick(40);
  assert.ok(calls.some((c) => c.method === "POST" && c.url === "/mandu/api/policy/changes/pc-000003/undo"));
  const row = rowOf(doc, TIGHTENED.id);
  assert.match(row.textContent, /Undone/);
  assert.equal(doc.activeElement, row, "the row keeps the focus");
  assert.equal(linkOf(doc, TIGHTENED.id).getAttribute("href"), "/mandu/agents/s1", "an undone change still links its agent");
});

test("a poll that draws the history again keeps a focus on the link", async () => {
  let changes = [TIGHTENED, YOURS];
  const { doc } = load({ url: APPROVALS, homeVm: quiet(), routes: { [CHANGES]: () => ({ changes }) } });
  await tick(40);
  const old = linkOf(doc, TIGHTENED.id);
  old.focus();
  // Another change lands above it: the history is drawn again.
  changes = [change("pc-000007", "You changed your rules"), TIGHTENED, YOURS];
  await poll(doc);
  assert.ok(rowOf(doc, "pc-000007"), "the new change is drawn");
  assert.notEqual(linkOf(doc, TIGHTENED.id), old, "drawn again");
  assert.equal(doc.activeElement, linkOf(doc, TIGHTENED.id), "the same row's link keeps the focus, never <body>");
});

// ── #92: the row names the agent Home knows ──────────────────────────────────
// The server's row says `who` and the words around the agent (`named`); the
// page names the agent of a session Home lists, and its folder after the
// moment (§4.25 *A rule change and the agent that asked*).
const MADE = { who: "agent", named: { before: "", after: " tightened your rules" } };
const ASKED = { who: "agent-approved", named: { before: "You approved a change ", after: " asked for" } };
const NAMED_TIGHT = change("pc-000013", "Your agent tightened your rules", { session: "s1", ...MADE });
const NAMED_APPROVED = change("pc-000012", "You approved a change your agent asked for", { session: "s2", undoable: false, ...ASKED });
const UNKNOWN = change("pc-000011", "Your agent tightened your rules", { session: "s9", ...MADE });
const undoOf = (doc: Doc, id: string) => [...rowOf(doc, id).querySelectorAll("button")].find((b: Doc) => b.textContent === "Undo");

test("a change of an agent Home lists names it: 'Claude Code tightened your rules', its moment '· from Claude Code in ~/ws', the link kept", async () => {
  const { doc } = load({ url: APPROVALS, homeVm: quiet(), routes: { [CHANGES]: { changes: [NAMED_TIGHT, NAMED_APPROVED, UNKNOWN, YOURS] } } });
  await tick(40);
  const row = rowOf(doc, NAMED_TIGHT.id);
  assert.equal(nameOf(doc, row), "Claude Code tightened your rules", "the row's name follows the sentence");
  assert.match(whenOf(doc, NAMED_TIGHT.id).textContent, new RegExp(`^${CLOCK} · [^.]+ · from Claude Code in ~/ws\\. ${LINK}$`));
  assert.equal(whenOf(doc, NAMED_TIGHT.id).querySelector(".ask-from code").textContent, "~/ws");
  assert.equal(linkOf(doc, NAMED_TIGHT.id).getAttribute("href"), "/mandu/agents/s1");
  assert.equal(linkOf(doc, NAMED_TIGHT.id).getAttribute("aria-label"), `${LINK}: Hide ~/proj/x.pem from the AI`, "named by what it changed");
  // A second agent's row names that agent; Home has no folder for it.
  assert.equal(nameOf(doc, rowOf(doc, NAMED_APPROVED.id)), "You approved a change Codex CLI asked for");
  assert.match(whenOf(doc, NAMED_APPROVED.id).textContent, new RegExp(`^${CLOCK} · [^.]+\\. ${LINK}$`), "no folder known: none");
  // A session Home does not list, and a row of yours: today's words.
  assert.equal(nameOf(doc, rowOf(doc, UNKNOWN.id)), "Your agent tightened your rules");
  assert.match(whenOf(doc, UNKNOWN.id).textContent, new RegExp(`^${CLOCK} · [^.]+\\. ${LINK}$`));
  assert.equal(nameOf(doc, rowOf(doc, YOURS.id)), "You changed a rule on the Rules page");
  // A row without `who` (the rows above this part) keeps the server's words.
  const old = load({ url: APPROVALS, homeVm: quiet(), routes: { [CHANGES]: { changes: [TIGHTENED] } } });
  await tick(40);
  assert.equal(nameOf(old.doc, rowOf(old.doc, TIGHTENED.id)), "Your agent tightened your rules");
});

test("a named row that lists nothing: its Undo and link are named by the new sentence; Undo still works", async () => {
  const bare = { ...NAMED_TIGHT, rows: [] };
  let changes = [bare];
  const { doc, calls } = load({ url: APPROVALS, homeVm: quiet(), routes: {
    [CHANGES]: () => ({ changes }),
    "POST policy/changes/pc-000013/undo": () => ((changes = [{ ...bare, undone: true, undoable: false }]), {}),
  } });
  await tick(40);
  assert.equal(undoOf(doc, bare.id).getAttribute("aria-label"), "Undo: Claude Code tightened your rules");
  assert.equal(linkOf(doc, bare.id).getAttribute("aria-label"), `${LINK}: Claude Code tightened your rules`);
  undoOf(doc, bare.id).focus();
  undoOf(doc, bare.id).click();
  await tick(40);
  assert.ok(calls.some((c) => c.method === "POST" && c.url === "/mandu/api/policy/changes/pc-000013/undo"));
  assert.match(rowOf(doc, bare.id).textContent, /Undone/);
  assert.equal(nameOf(doc, rowOf(doc, bare.id)), "Claude Code tightened your rules", "still named after the Undo");
});

test("Home lists the session after the history drew: the next poll names the agent", async () => {
  const all = quiet() as { agents: Array<Record<string, unknown>> };
  const { doc, setHome } = load({ url: APPROVALS, homeVm: { ...all, agents: [] }, routes: { [CHANGES]: { changes: [NAMED_TIGHT] } } });
  await tick(40);
  assert.equal(nameOf(doc, rowOf(doc, NAMED_TIGHT.id)), "Your agent tightened your rules");
  setHome(all);
  await poll(doc);
  assert.equal(nameOf(doc, rowOf(doc, NAMED_TIGHT.id)), "Claude Code tightened your rules");
  assert.match(whenOf(doc, NAMED_TIGHT.id).textContent, / · from Claude Code in ~\/ws\. /);
});
