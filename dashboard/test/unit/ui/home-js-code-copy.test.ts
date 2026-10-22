/**
 * home-js-code-copy.test — a fenced block in the agent's reply or in your
 * question has a Copy button (public/js/home.js `markdownNode`,
 * `copyButton`; dashboard.md §4.25b *A code block has a Copy button*).
 *
 * Agents often end a reply with a command for the person to run, and the
 * block that holds it scrolls sideways: at 390 px two thirds of the tour's
 * `! curl …` command were out of sight, and the page had no copy control.
 * Pins:
 *   - a reply's fenced command gets one Copy, in a `div.code-wrap` beside
 *     the `pre` (never in the box that scrolls); pressed, it writes the
 *     block's text exactly (its lines, no fence or language line, no
 *     trailing newline), reads "Copied" and says so in a polite status,
 *     keeps the focus, and reads "Copy" again two seconds later;
 *   - a block holding a chip has none (its text is not the value), and
 *     neither has inline code, What was hidden or the real value; the
 *     clipboard never gets a secret's value;
 *   - no `navigator.clipboard` (not a secure context): no button; a
 *     refused write reads "Could not copy";
 *   - the `pre` keeps `role="group"` and its name "Code";
 *   - the question's fenced block gets one too;
 *   - a poll that draws the page again while it reads "Copied" gives the
 *     focus to the Copy drawn at its place.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts), with a stubbed clipboard. Axes: none (display
 * only). Mandu-new test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, M, T, load, tick } from "./home-js-fixtures.js";

const PAGE = "http://127.0.0.1:4500/mandu/agents/s1";
const VALUE = "sk-live-codeCopyValue-000";
const CMD = `! curl -v https://api.stripe.com/v1/customers -G -d limit=1 -u "$(grep STRIPE_KEY .env | cut -d\\' -f2):"`;
const BLOCK = `${CMD}\n  echo "  done"`;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

/** The agent page of s1: the first turn's reply ends with a command in a
 *  fenced block, then a masked block and inline code; the second turn's
 *  question holds a fenced block; `more` turns: the agent did more since. */
function agentPage(more = 0): unknown {
  const page = JSON.parse(JSON.stringify(AGENT));
  page.waiting = [];
  page.story[0].reply = {
    ts: "2026-09-25T10:00:04.000Z", ai: null,
    parts: [T("Run it yourself:\n```bash\n" + BLOCK + "\n```\nThe file held:\n```\nSTRIPE_KEY='"), M("secret"), T("'\nDEBUG=1\n```\nThen run `npm test`.")],
  };
  page.story[1].prompt = "Run this for me:\n```\nls -la ~/ws\n```";
  for (let i = 0; i < more; i++) page.story.push({ ...page.story[1], id: `turn:more${i}`, prompt: `Go on ${i}`, steps: [], reply: null });
  return page;
}

/** The page over `read()`, its clipboard `mode`: writes kept in `wrote`;
 *  the two-second timers held in `later`, to run when the test says. */
function open(mode: "ok" | "refuse" | "none", read: () => unknown = () => agentPage()) {
  const wrote: string[] = [];
  const later: Array<() => void> = [];
  const page = load({ url: PAGE, routes: { "GET home/agent?session=s1": () => read(), "POST home/reveal": { value: VALUE } }, before: (w: Doc) => {
    assert.equal(w.navigator.clipboard, undefined, "jsdom has no clipboard of its own");
    if (mode !== "none") {
      Object.defineProperty(w.navigator, "clipboard", { configurable: true, value: {
        writeText: (t: string) => (mode === "ok" ? (wrote.push(t), w.Promise.resolve()) : w.Promise.reject(new w.DOMException("Write permission denied.", "NotAllowedError"))),
      } });
    }
    const st = w.setTimeout;
    w.setTimeout = (fn: () => void, ms?: number, ...a: unknown[]) => (ms === 2000 ? (later.push(fn), 0) : st(fn, ms, ...a));
  } });
  return { ...page, wrote, later };
}
const story = (doc: Doc) => doc.getElementById("agent-story");
const copies = (doc: Doc) => [...story(doc).querySelectorAll("button.code-copy")] as Doc[];
const blocks = (doc: Doc) => [...story(doc).querySelectorAll("pre.code-block")] as Doc[];
const said = (btn: Doc) => btn.parentElement.querySelector(".code-copy-said");

async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}

test("a reply's fenced command has one Copy beside its box: pressed, the block's exact text goes to the clipboard, it reads Copied, says so, keeps the focus, and reads Copy again", async () => {
  const { doc, wrote, later } = open("ok");
  await tick(40);
  const [cmd, masked] = blocks(doc);
  assert.equal(cmd.textContent, BLOCK, "the block as drawn");
  // The box keeps its role and name (home-js-scroll-names.test.ts).
  assert.equal(cmd.getAttribute("role"), "group");
  assert.equal(cmd.getAttribute("aria-label"), "Code");
  const wrap = cmd.parentElement;
  assert.ok(wrap.classList.contains("code-wrap"), "the block is in a wrapper");
  const btn = wrap.querySelector("button.code-copy");
  assert.ok(btn, "the command has a Copy button");
  assert.equal(btn.parentElement, wrap, "beside the box, never in it");
  assert.equal(cmd.querySelector("button"), null);
  assert.equal(btn.getAttribute("type"), "button");
  assert.equal(btn.textContent, "Copy");
  const status = said(btn);
  assert.equal(status.getAttribute("role"), "status", "a polite live region, drawn before it speaks");
  assert.equal(status.textContent, "");

  btn.focus();
  btn.click();
  await tick();
  assert.deepEqual(wrote, [BLOCK], "its lines as written: no fence, no language line, no trailing newline");
  assert.equal(btn.textContent, "Copied");
  assert.equal(status.textContent, "Copied");
  assert.equal(doc.activeElement, btn, "the focus stays on the button");
  assert.equal(later.length, 1, "it goes back after two seconds");
  later.shift()!();
  assert.equal(btn.textContent, "Copy");
  assert.equal(status.textContent, "");

  // The masked block, inline code: no button.
  assert.ok(masked.querySelector(".mask-chip"), "the second block holds a chip");
  assert.equal(masked.parentElement.classList.contains("code-wrap"), false, "a block with a chip is not wrapped");
  const inline = [...story(doc).querySelectorAll(".reply-text code")].find((c: Doc) => c.textContent === "npm test");
  assert.ok(inline && !inline.closest(".code-wrap"), "inline code has none");
  const reply = cmd.closest(".step.reply");
  assert.equal(reply.querySelectorAll("button.code-copy").length, 1, "one button in the reply");
});

test("the question's fenced block has one too; no button sits in What was hidden or the real value, and the clipboard never gets a value", async () => {
  const { doc, wrote } = open("ok");
  await tick(40);
  const q = [...story(doc).querySelectorAll(".q-text pre.code-block")] as Doc[];
  assert.equal(q.length, 1, "the question's block");
  const qBtn = q[0].parentElement.querySelector("button.code-copy");
  assert.ok(qBtn, "the question's block has Copy");
  qBtn.click();
  await tick();
  assert.deepEqual(wrote, ["ls -la ~/ws"]);

  // Show what was hidden, and every Show the real value.
  story(doc).querySelector(".step.split button.reveal").click();
  for (const b of [...story(doc).querySelectorAll("button.secret-reveal")] as Doc[]) b.click();
  for (const b of [...doc.querySelectorAll("#agent-secrets button.secret-reveal")] as Doc[]) b.click();
  await tick(40);
  const shown = [...doc.querySelectorAll("pre.hidden-text")].filter((p: Doc) => !p.hidden) as Doc[];
  assert.ok(shown.some((p) => p.textContent === VALUE), "a real value is shown");
  for (const p of doc.querySelectorAll("pre.hidden-text")) {
    assert.equal(p.parentElement.querySelector("button.code-copy"), null, "no Copy beside a revealed box");
    assert.equal(p.closest(".code-wrap"), null);
  }
  for (const b of doc.querySelectorAll("button.code-copy")) {
    assert.ok(b.parentElement.querySelector(":scope > pre.code-block"), "every Copy is a code block's");
    assert.equal(b.closest("#agent-secrets"), null, "none in Your secrets");
    b.click();
  }
  await tick();
  assert.ok(wrote.length >= 3);
  assert.ok(wrote.every((t) => !t.includes(VALUE)), "the clipboard never gets the real value");
});

test("no clipboard (not a secure context): no button; a refused write reads Could not copy", async () => {
  const none = open("none");
  await tick(40);
  assert.equal(blocks(none.doc).length, 3, "the blocks are drawn");
  assert.equal(copies(none.doc).length, 0, "no Copy without a clipboard");
  assert.equal(none.doc.querySelector(".code-wrap"), null);
  assert.equal(blocks(none.doc)[0].getAttribute("aria-label"), "Code");

  const refused = open("refuse");
  await tick(40);
  const btn = copies(refused.doc)[0];
  btn.focus();
  btn.click();
  await tick();
  assert.equal(btn.textContent, "Could not copy");
  assert.equal(said(btn).textContent, "Could not copy");
  assert.equal(refused.doc.activeElement, btn);
  refused.later.shift()!();
  assert.equal(btn.textContent, "Copy", "it can be tried again");
});

test("a poll that draws the page again while Copy reads Copied gives the focus to the Copy drawn at its place", async () => {
  let vm = agentPage();
  const { doc } = open("ok", () => vm);
  await tick(40);
  const btn = copies(doc)[0];
  btn.focus();
  btn.click();
  await tick();
  assert.equal(btn.textContent, "Copied");
  vm = agentPage(1);
  await poll(doc);
  assert.equal(btn.isConnected, false, "the page was drawn again");
  const now = copies(doc)[0];
  assert.equal(doc.activeElement, now, "the focus is on the Copy drawn now, never the heading");
  assert.equal(now.parentElement.querySelector("pre").textContent, BLOCK);
  assert.equal(now.textContent, "Copy");
});
