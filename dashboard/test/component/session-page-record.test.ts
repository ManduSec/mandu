/**
 * session-page-record.test — the served session page (`/agents/<id>`,
 * dashboard.md §4.25b) over a recorded live session, end to end: the REAL
 * DashboardServer over a FileEventSource holding the first-session tour of
 * 2026-10-05 (test/fixtures/tour-1791164083-1418381.ndjson, fake secrets), its
 * times moved so its last event (the agent's exit) was 30 seconds ago; the
 * served index.html and home.js run in jsdom with fetch bridged to it.
 *
 * Pins (the unit contracts are test/unit/view-model/session-page-record):
 * - /api/home/agent: the second curl is under "I allowed it once", the 10:36
 *   question has no step, the 10:41 Read is "raw" (masked only later), the
 *   file is one entry in Your secrets, and the session is not running even
 *   though its listing's recent-activity rule says so;
 * - the served page draws the 10:41 Read with its "Masked only later" tag
 *   and a `<time>` for the moment masking began, Your secrets' warn line
 *   with both moments as `<time>`s, then the line that the AI's own words
 *   are not masked (never "only a placeholder"), then "If it holds a key or
 *   a password, change it" (STRIPE_KEY's card, masked from the start, has
 *   no such line), and "ended", never "running now";
 * - its tiles count what the page shows: 1 secret masked before the AI saw
 *   it, 1 the AI read before it was marked (amber), the blocked send and
 *   the one let out; never "3 items masked before the AI saw them";
 * - Home counts the session the same way: /api/home's row carries the
 *   page's secret counts, blocked steps and sends, and the served row reads
 *   "1 secret masked, 1 secret read before it was marked, 1 action blocked,
 *   1 send with a real value filled in", never "3 items masked" (the
 *   lineage's tokens: the file masked twice), and never without the 10:39
 *   send the page's tile counts;
 * - with the server's home folder the recorded one (/home/user), Your
 *   secrets names the file `~/mandu-try/deploy/staging.conf`, in the payload
 *   and on the served card, never the account name, and so does the 10:42
 *   step for the agent's call to Mandu's rule tool (§4.34); the agent's own
 *   reply is quoted as it wrote it;
 * - the agent's markdown reads as formatting (§4.25b): the 10:35 reply's two
 *   variables are list items with their names in bold code, the 10:38
 *   options a numbered list, the 10:42 labels bold, no `**` drawn as text,
 *   chips still chips, and no token or value;
 * - a reply whose masked items are all secrets is one card (§4.25b, "Two
 *   halves only where the views differ"): the 10:36 and 10:42 replies, which
 *   the page cannot fill in, read once, with no "You saw, with the masked
 *   items filled in" half, and a line naming the secret each held
 *   (`STRIPE_KEY`, `staging.conf`), in the payload and on the served card;
 * - the 10:38 curl, whose result is Mandu's refusal naming the placeholder
 *   the AI sent (§4.25b, "a refusal is not a mask"), draws as a plain step
 *   with no "Secret hidden" tag and no halves, and its turn reads "Mandu
 *   blocked 1 request that carried your secret STRIPE_KEY.", never "hid
 *   your secret"; the 10:35 Read of .env keeps its tag;
 * - Your secrets tells STRIPE_KEY's blocked send (10:38) before the send
 *   let out after the person's OK (10:39), each line with its `<time>`, in
 *   the payload and on the served card: never "allowed to go" above
 *   "blocked" for the same host with no time (§4.25b); the block line says
 *   Mandu asked for your OK in Approvals, its last word a link to the row
 *   the block's `net_action` recorded (egr-1), and the send line never
 *   claims your answer (§4.25b, "A block says Mandu asked you"); each
 *   card time (10:38, 10:39, 10:41) opens the served step it tells of, the
 *   block, the send and the Read the AI got as it was, and "from 10:42 on",
 *   a model request, opens none (§4.25b, "A time opens its step");
 * - the 10:39 send, let out on the person's one-time OK, claims no
 *   standing permission (§4.25b, "A send claims no standing permission"):
 *   its card line reads "where it was allowed to go", never "is allowed",
 *   its turn's one request is not "each", and the sends tile's title says
 *   "It went", in the payload and on the served page;
 * - each card's level tag agrees with its first line (§4.25b, "The tag
 *   agrees with the card"): `staging.conf`'s, read at 10:41 before its
 *   label, is amber and reads "No AI since 10:42",
 *   the card's own "From … on" moment as a `<time>`, in the payload
 *   (`saw`, `since`) and on the served card; `STRIPE_KEY`'s stays green,
 *   with no "since";
 * - the 10:38 block says why, from the rule its `net_action` recorded
 *   (§4.25b, "A block says why": `egress:secret-unbound` → "No rule lets
 *   this secret go to `api.stripe.com`. …"), under its note, and the
 *   10:39 send let out says none;
 * - the turns say of `staging.conf` what its card says (§4.25b, "A secret
 *   the AI read before it was marked"): the 10:41 summary names it, and at
 *   10:42, under the reply in which the AI says it never saw the file, the
 *   line and every chip of the file (the Read's and the reply's) say the AI
 *   read its real value at 10:41, as a `<time>` and in the chip's title;
 *   STRIPE_KEY's chips keep "the AI never got the real value";
 * - the agent's call to Mandu's own rule tool (§4.25b, "Mandu's own tools")
 *   reads what it asked ("Asked Mandu to make `…/staging.conf` a secret
 *   hidden from the AI") and Mandu's recorded answer (applied at once, undo
 *   under Rule changes in Approvals), in the payload and on the served
 *   step, never the tool's name.
 * - signed out, the page's sign-in lines (the banner and each Read whose
 *   value it cannot show) name `mandu dashboard` as code, never quoted
 *   (§4.25 "Refusals"), and no real value of the tour's two secrets is on
 *   the page (§6).
 *
 * Axes: none (display only; the mode is the session's recorded one, and no
 * arbiter runs).
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { JSDOM } from "jsdom";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import { tmpDir } from "../unit/tmp-dir.js";
import { waitWhile } from "../unit/page-wait.js";
import { pageFetch } from "../unit/page-fetch.js";

const ID = "1791164083-1418381";
const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", `tour-${ID}.ndjson`);

let server: DashboardServer;
let base: string;
let dir: string;
/** The recorded moments, moved with the session. */
let shift = 0;
const moved = (iso: string) => new Date(Date.parse(iso) + shift).toISOString();

before(async () => {
  dir = tmpDir("mandu-session-record-");
  const events = readFileSync(FIXTURE, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as { ts: string });
  shift = Date.now() - 30_000 - Date.parse(events[events.length - 1]!.ts);
  writeFileSync(join(dir, `${ID}.ndjson`), events.map((e) => JSON.stringify({ ...e, ts: moved(e.ts) })).join("\n") + "\n");
  // The recorded session's home folder, so the page's `~` does not depend
  // on the host's HOME.
  server = new DashboardServer({ source: new FileEventSource(dir), configEnv: { MANDU_HOME: tmpDir("mandu-session-record-home-") }, fileBrowserHome: "/home/user", log: () => {} });
  base = `http://127.0.0.1:${await server.listen(0)}`;
});

after(async () => {
  await server.close();
  rmSync(dir, { recursive: true, force: true });
});

interface Part { kind: string; text: string; ask?: string; step?: string }
interface Served {
  running: boolean;
  story: { prompt: string | null; steps: { kind: string; id: string; outcome?: string; later?: Part[] }[] }[];
  secrets: { secrets: { what: Part[]; level: string; saw?: string; since?: string; lines: { tone: string; parts: Part[] }[] }[] };
}
const words = (parts: Part[]) => parts.map((p) => (p.kind === "time" ? `<${p.text}>` : p.text)).join("");
/** A moment as the page draws it: this process's local clock, as jsdom's. */
const hhmm = (iso: string) => { const d = new Date(iso); return String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0"); };

test("/api/home/agent: each call under its question, the raw read, the file once, and the exit", async () => {
  const res = await pageFetch(`${base}/api/home/agent?session=${ID}`);
  assert.equal(res.status, 200);
  const page = (await res.json()) as Served;
  const turn = (re: RegExp) => page.story.find((t) => t.prompt !== null && re.test(t.prompt))!;
  assert.deepEqual(turn(/^Show me the lines/).steps.filter((s) => s.kind === "action"), []);
  assert.equal(turn(/^I allowed it once/).steps[0]!.id, "tool:toolu_01Y4C8xBRgh4FkkEEQe9zRZ1");
  const read = turn(/^What is in deploy/).steps[0]!;
  assert.equal(read.outcome, "raw");
  assert.equal(words(read.later!), `Masked from <${moved("2026-10-05T01:42:05.942Z")}> on, after it was marked a secret.`);
  const files = page.secrets.secrets.filter((s) => /staging\.conf/.test(words(s.what)));
  assert.equal(files.length, 1, "one file, one entry");
  assert.equal(files[0]!.lines[0]!.tone, "warn");
  assert.equal(page.running, false, "the agent exited 30 seconds ago");
  assert.doesNotMatch(JSON.stringify(page), /\$MDU:|FAKE-STAGING-TOKEN-0000|FAKE-STRIPE-KEY-0000/);
});

/** The served product page at `path` in jsdom, fetch bridged to the server;
 *  `fn` runs once `ready` holds, then the window closes. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function servedPage(path: string, ready: (doc: any) => boolean, fn: (doc: any) => void): Promise<void> {
  const html = await (await pageFetch(`${base}${path}`)).text();
  const js = await (await pageFetch(`${base}/js/home.js`)).text();
  const dom = new JSDOM(html.replace(/<script type="module"[^>]*><\/script>/, ""), { url: `${base}${path}`, runScripts: "outside-only", pretendToBeVisual: true });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const w = dom.window as any;
  let closed = false;
  const gate = <T>(p: Promise<T>): Promise<T> =>
    p.then((v) => (closed ? new Promise<T>(() => {}) : v), (e) => (closed ? new Promise<T>(() => {}) : Promise.reject(e)));
  w.fetch = (url: string, { signal: _signal, ...init }: RequestInit = {}) =>
    gate(pageFetch(new URL(url, base).href, init).then(async (res) => {
      const body = await res.text();
      return { ok: res.ok, status: res.status, json: () => gate(Promise.resolve().then(() => JSON.parse(body))) };
    }));
  w.setInterval = () => 0;
  w.scrollTo = () => {};
  w.eval(js);
  try {
    const doc = w.document;
    await waitWhile(() => !ready(doc));
    fn(doc);
  } finally {
    closed = true;
    w.close();
  }
}

test("the served page: the raw read with its later-mask time, the warn line, and ended", async () => {
  await servedPage(`/agents/${ID}`, (doc) => doc.querySelectorAll("#agent-story .turn").length > 0 && !!doc.querySelector("#agent-secrets .secret-card"), (doc) => {
    const raw = doc.querySelector('#agent-story .step.raw[data-step-id="tool:toolu_01TsLEVYKVQrwjEgsbrZ1vEf"]') as HTMLElement;
    assert.ok(raw, "the 10:41 Read draws as raw");
    assert.equal(raw.querySelector(".tag.raw")!.textContent, "Masked only later");
    assert.match(raw.querySelector(".what .note")!.textContent!, /^The AI got this as it was/);
    const later = raw.querySelector(".note.later") as HTMLElement;
    assert.match(later.textContent!, /^Masked from \d{2}:\d{2} on, after it was marked a secret\.$/);
    assert.equal(later.querySelector("time")!.getAttribute("datetime"), moved("2026-10-05T01:42:05.942Z"));
    const summary = raw.closest(".turn")!.querySelector(".turn-summary") as HTMLElement;
    assert.equal(summary.textContent, "The AI read your secret staging.conf as it was: it was marked secret only later.");
    assert.equal(summary.querySelector("code")!.textContent, "staging.conf", "named as code, as the step names it");
    const cards = [...doc.querySelectorAll("#agent-secrets .secret-card")] as HTMLElement[];
    const conf = cards.filter((c) => /staging\.conf/.test(c.textContent!));
    assert.equal(conf.length, 1);
    const [warn, ownWords, changeIt, ...moreWarn] = [...conf[0]!.querySelectorAll(".secret-line.warn")] as HTMLElement[];
    assert.match(warn!.textContent!, /^The AI read its real value at \d{2}:\d{2}, before it was marked a secret\. From \d{2}:\d{2} on it got a placeholder in its place, in 2 requests\.$/);
    assert.equal(warn!.querySelectorAll("time").length, 2);
    // The AI's 10:41 reply quoted the file, and Mandu forwards the AI's own
    // replies as written: the card says so, next, never "only a placeholder".
    assert.equal(ownWords?.textContent, "Anything the AI wrote from its real value went back to the AI as written with each later request: Mandu does not mask the AI's own words.");
    // Then what to do about it, in the later label's words (§4.25b).
    assert.equal(changeIt?.textContent, "If it holds a key or a password, change it: the AI saw it as it was.");
    assert.deepEqual(moreWarn, []);
    assert.doesNotMatch(conf[0]!.textContent!, /only a placeholder/);
    // STRIPE_KEY, masked from the start, says nothing of the kind.
    const stripe = cards.filter((c) => /STRIPE_KEY/.test(c.querySelector(".secret-what")!.textContent!));
    assert.equal(stripe.length, 1);
    assert.doesNotMatch(stripe[0]!.textContent!, /change it|Change this key/);
    const when = doc.querySelector("#page-agent .agent-when").textContent as string;
    assert.match(when, /ended/);
    assert.doesNotMatch(when, /running now/);
    assert.doesNotMatch(doc.getElementById("page-agent").textContent, /\$MDU:|FAKE-STAGING-TOKEN-0000/);
  });
});

test("the served page's tiles count what its cards and steps show, never the file read before its label as masked", async () => {
  await servedPage(`/agents/${ID}`, (doc) => doc.querySelectorAll("#agent-facts .tile").length > 0 && !!doc.querySelector("#agent-secrets .secret-card"), (doc) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tiles = [...doc.querySelectorAll("#agent-facts .tile")] as any[];
    assert.deepEqual(tiles.map((t) => `${t.querySelector(".big").textContent} ${t.querySelector(".lbl").textContent}`), [
      "1 secret masked before the AI saw it",
      "1 secret the AI read before it was marked a secret",
      "1 action blocked",
      "1 send with a real value filled in",
    ]);
    assert.ok(tiles[1].classList.contains("warn"));
    const facts = doc.getElementById("agent-facts").textContent as string;
    assert.doesNotMatch(facts, /items masked before the AI saw them|of them secrets/);
    // The cards under the tiles: two secrets, the second read before its label.
    const cards = [...doc.querySelectorAll("#agent-secrets .secret-card")] as HTMLElement[];
    assert.equal(cards.length, 2);
    assert.equal(cards.filter((c) => c.querySelector(".secret-line")!.classList.contains("good")).length, 1);
    assert.equal(cards.filter((c) => c.querySelector(".secret-line")!.classList.contains("warn")).length, 1);
    // And the story's steps: one blocked send, one let out.
    assert.equal(doc.querySelectorAll("#agent-story .step.sent").length, 1);
    assert.equal(doc.querySelectorAll("#agent-story .step.blocked").length, 1);
  });
});

test("the served page's 10:38 curl: Mandu's refusal is not drawn as a hidden secret, and the turn says only what Mandu blocked", async () => {
  await servedPage(`/agents/${ID}`, (doc) => doc.querySelectorAll("#agent-story .turn").length > 0, (doc) => {
    const turns = [...doc.querySelectorAll("#agent-story .turn")] as HTMLElement[];
    const turn = (re: RegExp) => turns.find((t) => re.test(t.querySelector(".q-text")?.textContent ?? ""))!;
    const stripe = turn(/^Use the Stripe key/);
    assert.equal(stripe.querySelector(".turn-summary")!.textContent, "Mandu blocked 1 request that carried your secret STRIPE_KEY.");
    const curl = stripe.querySelector('[data-step-id="tool:toolu_01P6KYMYqXT3w6qfrvV1aZfL"]') as HTMLElement;
    assert.ok(curl, "the curl is a step of its turn");
    assert.ok(curl.classList.contains("plain") && !curl.classList.contains("split"), curl.className);
    assert.equal(curl.querySelector(".tag"), null, "no \"Secret hidden\" tag");
    assert.equal(curl.querySelector(".what .note")!.textContent, "The AI used the masked version of your secret, not its real value.");
    assert.equal(stripe.querySelector(".step.blocked .tag.blocked")!.textContent, "Blocked");
    assert.doesNotMatch(stripe.textContent!, /Secret hidden|hid your secret|The result held/);
    // The Read of .env at 10:35 kept the value from the AI: its tag stays.
    const env = turn(/^What is in \.env\?/);
    assert.equal(env.querySelector(".step.split.secret .tag.secret")!.textContent, "Secret hidden");
    assert.equal(env.querySelector(".turn-summary")!.textContent, "Mandu hid your secret STRIPE_KEY from the AI.");
    assert.doesNotMatch(doc.getElementById("agent-story").textContent, /\$MDU:|FAKE-STRIPE-KEY-0000/);
  });
});

test("the 10:38 block says why, from the rule its event recorded; the 10:39 send let out says none (§4.25b)", async () => {
  const page = (await (await pageFetch(`${base}/api/home/agent?session=${ID}`)).json()) as { story: { prompt: string | null; steps: { kind: string; outcome?: string; why?: Part[] }[] }[] };
  const steps = (re: RegExp) => page.story.find((t) => t.prompt !== null && re.test(t.prompt))!.steps;
  const block = steps(/^Use the Stripe key/).find((s) => s.outcome === "blocked")!;
  assert.equal(words(block.why!), "No rule lets this secret go to api.stripe.com. Mandu sends a secret only where a rule lets it go, or with your OK.");
  assert.deepEqual(block.why!.filter((p) => p.kind === "code").map((p) => p.text), ["api.stripe.com"]);
  const sent = steps(/^I allowed it once/).find((s) => s.outcome === "sent")!;
  assert.ok(sent && !("why" in sent), "the send let out has no why");
  assert.equal(page.story.flatMap((t) => t.steps).filter((s) => s.why).length, 1, "only the block has a why");
  await servedPage(`/agents/${ID}`, (doc) => doc.querySelectorAll("#agent-story .turn").length > 0, (doc) => {
    const turns = [...doc.querySelectorAll("#agent-story .turn")] as HTMLElement[];
    const stripe = turns.find((t) => /^Use the Stripe key/.test(t.querySelector(".q-text")?.textContent ?? ""))!;
    const why = stripe.querySelector(".step.blocked .what .note.why") as HTMLElement;
    assert.ok(why, "the blocked send draws its why");
    assert.equal(why.textContent, "Why: No rule lets this secret go to api.stripe.com. Mandu sends a secret only where a rule lets it go, or with your OK.");
    assert.equal(why.previousElementSibling!.textContent, "The request never left this machine.", "under the note");
    assert.equal(doc.querySelectorAll("#agent-story .note.why").length, 1);
  });
});

test("the 10:38 block says Mandu asked for your OK in Approvals, linking to the row its event recorded (egr-1); no other step says so (§4.25b)", async () => {
  const page = (await (await pageFetch(`${base}/api/home/agent?session=${ID}`)).json()) as { story: { prompt: string | null; steps: { kind: string; outcome?: string; askId?: string }[] }[] };
  const asked = page.story.flatMap((t) => t.steps).filter((s) => s.askId);
  assert.deepEqual(asked.map((s) => [s.outcome, s.askId]), [["blocked", "egr-1"]], "only the 10:38 block filed a row");
  const block = page.story.find((t) => t.prompt !== null && /^Use the Stripe key/.test(t.prompt))!.steps.find((s) => s.outcome === "blocked")!;
  assert.equal(block.askId, "egr-1", "the step in the 10:38 turn");
  await servedPage(`/agents/${ID}`, (doc) => doc.querySelectorAll("#agent-story .turn").length > 0, (doc) => {
    const lines = [...doc.querySelectorAll("#agent-story .note.asked")] as HTMLElement[];
    assert.equal(lines.length, 1);
    assert.equal(lines[0]!.textContent, "Mandu asked for your OK in Approvals.");
    assert.ok(lines[0]!.previousElementSibling!.classList.contains("why"), "under the why");
    assert.ok(lines[0]!.closest(".step.blocked"), "on the blocked send");
    assert.equal(lines[0]!.querySelector("a")!.getAttribute("href"), "/approvals/egr-1");
  });
});

test("Your secrets tells STRIPE_KEY's block and its later send in the order they happened, each with its time (§4.25b)", async () => {
  const page = (await (await pageFetch(`${base}/api/home/agent?session=${ID}`)).json()) as Served;
  const stripe = page.secrets.secrets.find((s) => /STRIPE_KEY/.test(words(s.what)))!;
  assert.deepEqual(stripe.lines.map((l) => words(l.parts)).slice(1, 3), [
    `Mandu blocked 1 attempt to send it to api.stripe.com, at <${moved("2026-10-05T01:38:07.123Z")}>, and asked for your OK in Approvals. The request never left this machine.`,
    `Mandu sent its real value only to api.stripe.com (1 request, at <${moved("2026-10-05T01:39:24.292Z")}>), where it was allowed to go.`,
  ]);
  await servedPage(`/agents/${ID}`, (doc) => !!doc.querySelector("#agent-secrets .secret-card"), (doc) => {
    const cards = [...doc.querySelectorAll("#agent-secrets .secret-card")] as HTMLElement[];
    const card = cards.find((c) => /STRIPE_KEY/.test(c.querySelector(".secret-what")!.textContent!))!;
    const lines = [...card.querySelectorAll(".secret-line")] as HTMLElement[];
    const block = lines.findIndex((l) => /^Mandu blocked/.test(l.textContent!));
    const send = lines.findIndex((l) => /^Mandu sent its real value/.test(l.textContent!));
    assert.ok(block > 0 && send === block + 1, "the block, then the send");
    assert.match(lines[block]!.textContent!, /^Mandu blocked 1 attempt to send it to api\.stripe\.com, at \d{2}:\d{2}, and asked for your OK in Approvals\. The request never left this machine\.$/);
    assert.match(lines[send]!.textContent!, /^Mandu sent its real value only to api\.stripe\.com \(1 request, at \d{2}:\d{2}\), where it was allowed to go\.$/);
    assert.equal(lines[block]!.querySelector("time")!.getAttribute("datetime"), moved("2026-10-05T01:38:07.123Z"));
    assert.equal(lines[send]!.querySelector("time")!.getAttribute("datetime"), moved("2026-10-05T01:39:24.292Z"));
    assert.doesNotMatch(card.textContent!, /\$MDU:|FAKE-STRIPE-KEY-0000|T\d{2}:\d{2}:\d{2}/, "no token, value or raw ISO time");
  });
});

test("Your secrets: staging.conf's tag is amber and says since when, the card's own From moment; STRIPE_KEY's stays green (§4.25b)", async () => {
  const page = (await (await pageFetch(`${base}/api/home/agent?session=${ID}`)).json()) as Served;
  const MASKED = moved("2026-10-05T01:42:05.942Z");
  assert.deepEqual(page.secrets.secrets.map((s) => [words(s.what), s.level, s.saw, s.since ?? null]), [
    ["STRIPE_KEY in ~/mandu-try/.env", "No AI", "masked", null],
    ["The file ~/mandu-try/deploy/staging.conf", "No AI", "early", MASKED],
  ]);
  const conf = page.secrets.secrets[1]!;
  assert.ok(words(conf.lines[0]!.parts).includes(`From <${MASKED}> on`), "the tag's moment is the card's own");
  await servedPage(`/agents/${ID}`, (doc) => !!doc.querySelector("#agent-secrets .secret-card"), (doc) => {
    const cards = [...doc.querySelectorAll("#agent-secrets .secret-card")] as HTMLElement[];
    const tagOf = (re: RegExp) => cards.find((c) => re.test(c.querySelector(".secret-what")!.textContent!))!.querySelector(".secret-head .tag") as HTMLElement;
    const stripe = tagOf(/STRIPE_KEY/);
    assert.equal(stripe.className, "tag level secret", "green: the AI got only a placeholder");
    assert.equal(stripe.textContent, "No AI");
    const tag = tagOf(/staging\.conf/);
    assert.equal(tag.className, "tag level raw", "amber, as the line under it: the AI read its real value first");
    assert.equal(tag.textContent, `No AI since ${hhmm(MASKED)}`);
    assert.equal(tag.querySelector("time")!.getAttribute("datetime"), MASKED);
    const from = [...tag.closest(".secret-card")!.querySelectorAll(".secret-line.warn time")].map((t: any) => t.getAttribute("datetime"));
    assert.ok(from.includes(MASKED), "the same moment as the card's \"From … on\"");
    assert.doesNotMatch(tag.textContent!, /\$MDU:|FAKE-STAGING-TOKEN-0000|T\d{2}:\d{2}:\d{2}/);
  });
});

test("Your secrets says the 10:38 block asked for your OK, linking the row its event recorded (egr-1); the 10:39 send claims no answer (§4.25b)", async () => {
  const page = (await (await pageFetch(`${base}/api/home/agent?session=${ID}`)).json()) as Served;
  const stripe = page.secrets.secrets.find((s) => /STRIPE_KEY/.test(words(s.what)))!;
  const asks = page.secrets.secrets.flatMap((s) => s.lines.flatMap((l) => l.parts.filter((p) => p.ask)));
  assert.deepEqual(asks, [{ kind: "text", text: "Approvals", ask: "egr-1" }], "one ask, on STRIPE_KEY's block, by the queue's id");
  const send = stripe.lines.find((l) => /^Mandu sent/.test(words(l.parts)))!;
  assert.doesNotMatch(words(send.parts), /OK|Approvals|answer/, "the send says nothing of an answer");
  await servedPage(`/agents/${ID}`, (doc) => !!doc.querySelector("#agent-secrets .secret-card"), (doc) => {
    // The cards' own lines link one Approvals row; each file's card also
    // links its file to Rules (§4.25b *A card opens its file in Rules*).
    const rules = [...doc.querySelectorAll("#agent-secrets a.secret-rule-link")] as HTMLAnchorElement[];
    assert.deepEqual(rules.map((a) => a.getAttribute("href")).sort(), ["/rules?file=~/mandu-try/.env", "/rules?file=~/mandu-try/deploy/staging.conf"], "the tour's two files, each its card's own link");
    assert.equal([...doc.querySelectorAll("#agent-secrets a")].length, rules.length + 1, "and no other link");
    const links = [...doc.querySelectorAll("#agent-secrets .secret-line a")] as HTMLAnchorElement[];
    assert.equal(links.length, 1, "one link in Your secrets' lines");
    const line = links[0]!.closest(".secret-line")!;
    assert.match(line.textContent!, /^Mandu blocked 1 attempt to send it to api\.stripe\.com/, "on the block line");
    assert.ok(/STRIPE_KEY/.test(line.closest(".secret-card")!.querySelector(".secret-what")!.textContent!), "of STRIPE_KEY's card");
    assert.equal(links[0]!.textContent, "Approvals");
    assert.equal(links[0]!.getAttribute("href"), "/approvals/egr-1", "the row the step links");
    assert.equal(links[0]!.dataset.pageLink, "approvals");
    assert.equal(links[0]!.dataset.ask, "egr-1");
  });
});

test("the 10:39 send, let out on the person's one-time OK, claims no standing permission: its card line, its turn and its tile (§4.25b)", async () => {
  const page = (await (await pageFetch(`${base}/api/home/agent?session=${ID}`)).json()) as Omit<Served, "story"> & { story: { prompt: string | null; summary: string | null }[] };
  const stripe = page.secrets.secrets.find((s) => /STRIPE_KEY/.test(words(s.what)))!;
  const send = words(stripe.lines.find((l) => /^Mandu sent/.test(words(l.parts)))!.parts);
  assert.match(send, /, where it was allowed to go\.$/);
  assert.doesNotMatch(send, /is allowed/, "the OK was for one request: no permission still holds");
  // The turn's one request is not "each".
  const allowed = page.story.find((t) => t.prompt !== null && /^I allowed it once/.test(t.prompt))!;
  assert.equal(allowed.summary, "1 request left this machine with your secret STRIPE_KEY filled in, to a destination allowed to receive it.");
  await servedPage(`/agents/${ID}`, (doc) => doc.querySelectorAll("#agent-story .turn").length > 0 && !!doc.querySelector("#agent-secrets .secret-card"), (doc) => {
    const turns = [...doc.querySelectorAll("#agent-story .turn")] as HTMLElement[];
    const turn = turns.find((t) => /^I allowed it once/.test(t.querySelector(".q-text")?.textContent ?? ""))!;
    assert.equal(turn.querySelector(".turn-summary")!.textContent, "1 request left this machine with your secret STRIPE_KEY filled in, to a destination allowed to receive it.");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tile = ([...doc.querySelectorAll("#agent-facts .tile")] as any[]).find((t) => /^1 send with a real value filled in$/.test(`${t.querySelector(".big").textContent} ${t.querySelector(".lbl").textContent}`));
    assert.ok(tile, "the sends tile");
    assert.equal(tile.getAttribute("title"), "It went to a destination allowed to receive it. Press to go to it under What happened.");
    // A press goes to the send (§4.25 *A tile takes you to what it counts*).
    assert.equal(tile.tagName, "BUTTON");
    tile.click();
    assert.equal(doc.activeElement!.getAttribute("data-outcome"), "sent", "the press lands on the send");
    assert.ok(doc.activeElement!.classList.contains("shown"));
    assert.doesNotMatch(doc.getElementById("agent-secrets").textContent, /is allowed to go/);
    assert.doesNotMatch(doc.getElementById("agent-story").textContent, /1 request left this machine[^.]*each to/);
  });
});

test("Your secrets: 10:38, 10:39 and 10:41 open the block, the send and the Read under What happened; a click marks that step (§4.25b)", async () => {
  const page = (await (await pageFetch(`${base}/api/home/agent?session=${ID}`)).json()) as Served;
  const steps = new Map(page.story.flatMap((t) => t.steps.map((s) => [s.id, s] as const)));
  const opened = page.secrets.secrets.flatMap((s) => s.lines.flatMap((l) => l.parts.filter((p) => p.kind === "time")))
    .map((p) => `${p.text} -> ${p.step ? `${p.step} ${steps.get(p.step)?.outcome}` : "-"}`);
  assert.deepEqual(opened, [
    `${moved("2026-10-05T01:38:07.123Z")} -> os:${ID}:muukyx77:hqia blocked`,
    `${moved("2026-10-05T01:39:24.292Z")} -> os:${ID}:muul0kqs:78so sent`,
    `${moved("2026-10-05T01:41:29.686Z")} -> tool:toolu_01TsLEVYKVQrwjEgsbrZ1vEf raw`,
    `${moved("2026-10-05T01:42:05.942Z")} -> -`,
  ], "each time opens the step its line tells of; the first masked request is no step");
  await servedPage(`/agents/${ID}`, (doc) => !!doc.querySelector("#agent-secrets .secret-card") && !!doc.querySelector("#agent-story [data-step-id]"), (doc) => {
    const links = [...doc.querySelectorAll("#agent-secrets .step-link")] as HTMLButtonElement[];
    assert.deepEqual(links.map((b) => b.textContent), [hhmm(moved("2026-10-05T01:38:07.123Z")), hhmm(moved("2026-10-05T01:39:24.292Z")), hhmm(moved("2026-10-05T01:41:29.686Z"))]);
    const stepOf = (b: HTMLButtonElement) => [...doc.querySelectorAll("#agent-story [data-step-id]")].find((x: any) => x.dataset.stepId === b.dataset.opens) as HTMLElement | undefined;
    assert.ok(links.every((b) => stepOf(b)), "each opens a step the page draws");
    const shown = () => ([...doc.querySelectorAll("#agent-story .step.shown")] as HTMLElement[]).map((x) => x.textContent!);
    links[0]!.click();
    assert.equal(shown().length, 1);
    assert.match(shown()[0]!, /^Mandu blocked a request to api\.stripe\.com that carried your secret STRIPE_KEY/);
    links[1]!.click();
    assert.match(shown()[0]!, /^Sent a request to api\.stripe\.com with your secret STRIPE_KEY filled in/);
    links[2]!.click();
    assert.deepEqual(shown().map((x) => /^Read staging\.conf/.test(x) && /Masked only later/.test(x)), [true], "the Read the AI got as it was");
  });
});

test("Home counts the session as its page's tiles do: its row says 1 secret masked and 1 read before it was marked, never 3 items masked", async () => {
  const home = (await (await pageFetch(`${base}/api/home`)).json()) as { agents: { id: string; secrets: { masked: number; early: number }; stats: { flows: number } }[] };
  const page = (await (await pageFetch(`${base}/api/home/agent?session=${ID}`)).json()) as { secrets: { counts: { masked: number; early: number } } };
  const row = home.agents.find((a) => a.id === ID)!;
  assert.ok(row, "the tour is a Home row");
  assert.equal(row.stats.flows, 3, "three masked tokens");
  assert.deepEqual(row.secrets, page.secrets.counts);
  assert.deepEqual(row.secrets, { masked: 1, early: 1 });
  await servedPage("/", (doc) => !!doc.querySelector(`#home-earlier [data-session="${ID}"]`), (doc) => {
    const served = doc.querySelector(`#home-earlier [data-session="${ID}"]`).closest(".row.agent");
    assert.equal(served.querySelector(".agent-counts").textContent, "1 secret masked, 1 secret read before it was marked, 1 action blocked, 1 send with a real value filled in");
    assert.doesNotMatch(doc.getElementById("page-home").textContent, /items? masked(?! before)/);
  });
});

test("Home's row for the tour says the send its page's tile counts: STRIPE_KEY's real value left for api.stripe.com at 10:39", async () => {
  const home = (await (await pageFetch(`${base}/api/home`)).json()) as { agents: { id: string; blocked: number; sent: number }[] };
  const page = (await (await pageFetch(`${base}/api/home/agent?session=${ID}`)).json()) as { blocked: number; sent: number };
  const row = home.agents.find((a) => a.id === ID)!;
  assert.deepEqual({ blocked: row.blocked, sent: row.sent }, { blocked: page.blocked, sent: page.sent }, "the row and its page count the same");
  assert.deepEqual({ blocked: row.blocked, sent: row.sent }, { blocked: 1, sent: 1 }, "the 10:38 block and the 10:39 send");
  await servedPage("/", (doc) => !!doc.querySelector(`#home-earlier [data-session="${ID}"]`), (doc) => {
    const counts = doc.querySelector(`#home-earlier [data-session="${ID}"]`).closest(".row.agent").querySelector(".agent-counts").textContent;
    assert.match(counts, /, 1 send with a real value filled in$/, "after the blocked count, as the page's tiles");
  });
  await servedPage(`/agents/${ID}`, (doc) => doc.querySelectorAll("#agent-facts .tile").length > 0, (doc) => {
    const tiles = [...doc.querySelectorAll("#agent-facts .tile")].map((t) => `${t.querySelector(".big").textContent} ${t.querySelector(".lbl").textContent}`);
    assert.ok(tiles.includes("1 send with a real value filled in"), `the page's tile, in the row's words (${tiles.join(" | ")})`);
  });
});

test("Your secrets names the files under the home folder ~/mandu-try/.env and ~/mandu-try/deploy/staging.conf, never the account name", async () => {
  const page = (await (await pageFetch(`${base}/api/home/agent?session=${ID}`)).json()) as Served;
  assert.deepEqual(page.secrets.secrets.map((s) => words(s.what)), ["STRIPE_KEY in ~/mandu-try/.env", "The file ~/mandu-try/deploy/staging.conf"]);
  assert.doesNotMatch(JSON.stringify(page.secrets), /\/home\/user/);
  await servedPage(`/agents/${ID}`, (doc) => !!doc.querySelector("#agent-secrets .secret-card"), (doc) => {
    const cards = [...doc.querySelectorAll("#agent-secrets .secret-card")] as HTMLElement[];
    const conf = cards.find((c) => /staging\.conf/.test(c.textContent!))!;
    assert.equal(conf.querySelector("code")!.textContent, "~/mandu-try/deploy/staging.conf");
    assert.doesNotMatch(doc.getElementById("agent-secrets").textContent, /\/home\/user/);
    // The agent's own reply is a quote: it keeps the path as the agent wrote it.
    assert.match(doc.getElementById("agent-story").textContent, /I locked \/home\/user\/mandu-try\/deploy\/staging\.conf/);
  });
});

test("the served page draws the agent's markdown as formatting: the tour's lists and bold labels, no raw ** left, no token", async () => {
  await servedPage(`/agents/${ID}`, (doc) => doc.querySelectorAll("#agent-story .reply-text").length > 0, (doc) => {
    const replies = [...doc.querySelectorAll("#agent-story .reply-text")] as HTMLElement[];
    assert.equal(replies.length, 6, "each turn's reply once: none of the tour's is split");
    for (const r of replies) assert.doesNotMatch(r.textContent!, /\*\*/, "no bold marker is drawn as text");
    const turn = (re: RegExp) => ([...doc.querySelectorAll("#agent-story .turn")] as HTMLElement[]).find((t) => re.test(t.querySelector(".q-text")?.textContent ?? ""))!;
    // 10:35: ".env sets two variables:" then two items, each a bold name as code.
    const env = turn(/^What is in \.env\?/).querySelector(".reply-text")!;
    const items = [...env.querySelectorAll(".md-li")];
    assert.deepEqual(items.map((i) => i.querySelector(".md-mark")!.textContent), ["•", "•"]);
    assert.deepEqual(items.map((i) => i.querySelector(".md-body > strong > code")!.textContent), ["STRIPE_KEY", "DEBUG=1"]);
    // 10:38: the two options are a numbered list, each opening in bold.
    const opts = [...turn(/^Use the Stripe key/).querySelectorAll(".reply-text .md-li")];
    assert.deepEqual(opts.map((i) => i.querySelector(".md-mark")!.textContent), ["1.", "2."]);
    assert.equal(opts[0]!.querySelector("strong")!.textContent, "Approve this request");
    // 10:42: the bold labels, in the one card the reply is (it held only a secret).
    const halves = [...turn(/^Use Mandu's policy tools/).querySelectorAll(".step.reply .reply-text")];
    assert.equal(halves.length, 1);
    for (const h of halves) {
      assert.deepEqual([...h.querySelectorAll(":scope > strong")].map((s) => s.textContent), ["The lock:", "What I see now:"]);
      assert.ok(h.querySelector(".mask-chip.secret"), "the masked file is still a chip");
    }
    assert.equal(doc.querySelector("#agent-story b, #agent-story em, #agent-story a[href^='http']"), null, "formatting only: no markup, no links");
    assert.doesNotMatch(doc.getElementById("agent-story").textContent, /\$MDU:|FAKE-STAGING-TOKEN-0000|FAKE-STRIPE-KEY-0000/);
  });
});

test("a reply whose masked items are all secrets is one card with a line naming them, never a \"filled in\" half that fills in nothing", async () => {
  // The 10:42 line also says when the AI read the file (its own test below).
  const READ = moved("2026-10-05T01:41:29.686Z");
  const KEPT = {
    "Show me the lines": "The reply held your secret STRIPE_KEY. The AI wrote it masked, and this page keeps it masked.",
    "Use Mandu's policy tools": `The reply held your secret staging.conf. The AI wrote it masked, and this page keeps it masked. The AI read its real value at <${READ}>, before it was marked a secret.`,
  };
  const page = (await (await pageFetch(`${base}/api/home/agent?session=${ID}`)).json()) as {
    story: { prompt: string | null; reply: { ai: Part[] | null; kept?: Part[]; unresolved?: boolean } | null }[];
  };
  for (const [q, line] of Object.entries(KEPT)) {
    const reply = page.story.find((t) => t.prompt?.startsWith(q))!.reply!;
    assert.equal(reply.ai, null, `${q}: one card`);
    assert.equal(words(reply.kept!), line);
    assert.equal(reply.unresolved, undefined);
  }
  // The other replies held no placeholder: no line.
  assert.deepEqual(page.story.filter((t) => t.reply?.kept).map((t) => Object.keys(KEPT).find((q) => t.prompt?.startsWith(q))), Object.keys(KEPT));
  await servedPage(`/agents/${ID}`, (doc) => doc.querySelectorAll("#agent-story .reply-text").length > 0, (doc) => {
    const turn = (re: RegExp) => ([...doc.querySelectorAll("#agent-story .turn")] as HTMLElement[]).find((t) => re.test(t.querySelector(".q-text")?.textContent ?? ""))!;
    for (const [q, line] of Object.entries(KEPT)) {
      const card = turn(new RegExp("^" + q))!.querySelector(".step.reply")!;
      assert.ok(card.classList.contains("wide"), `${q}: one card`);
      assert.equal(card.querySelector(".half"), null);
      assert.doesNotMatch(card.textContent!, /You saw, with the masked items filled in/);
      assert.ok(card.querySelector(".reply-text .mask-chip.secret"), "the secret is still a chip");
      assert.equal(card.querySelector(".reply-kept")!.textContent, line.replace(`<${READ}>`, hhmm(READ)));
    }
    // 10:36 has no step, so no column heads are left over its one card.
    assert.equal(turn(/^Show me the lines/).querySelector(".cols-head"), null);
    assert.doesNotMatch(doc.getElementById("agent-story")!.textContent!, /\$MDU:|FAKE-STAGING-TOKEN-0000|FAKE-STRIPE-KEY-0000/);
  });
});

test("signed out, the served page says to sign in with its command as code, never quoted, and shows no real value (§4.25 \"Refusals\", §6)", async () => {
  await servedPage(`/agents/${ID}`, (doc) => doc.getElementById("agent-values-note")?.hidden === false && doc.querySelectorAll("#agent-story .values-withheld").length > 0, (doc) => {
    const codes = (n: Element) => [...n.querySelectorAll("code")].map((c) => c.textContent);
    const note = doc.getElementById("agent-values-note");
    assert.equal(note.textContent, "Sign in to see real values: reload this page and sign in with your dashboard account.");
    assert.deepEqual(codes(note), []);
    // The 10:35 Read of .env and the 10:42 Read of staging.conf, signed out.
    const lines = [...doc.querySelectorAll("#agent-story .values-withheld")] as Element[];
    assert.equal(lines.length, 2);
    for (const l of lines) assert.deepEqual(codes(l), []);
    const all = doc.getElementById("page-agent").textContent;
    assert.doesNotMatch(all, /"mandu dashboard"|`mandu dashboard`/);
    assert.doesNotMatch(all, /FAKE-STRIPE-KEY-0000|FAKE-STAGING-TOKEN-0000/, "signed out, no real value on the page");
  });
});

test("the agent's call to Mandu's rule tool says what it asked and what Mandu answered, never the tool's name", async () => {
  const STEP = "tool:toolu_014TbrrRqbyKEeE2yrALZJWq";
  // The file under the server's home reads ~/…, as on Approvals and Rules (§4.34).
  const SENTENCE = "Asked Mandu to make ~/mandu-try/deploy/staging.conf a secret no AI may read";
  const ANSWER = "Mandu applied it at once, because it only adds protection. You can undo it in Approvals.";
  const page = (await (await pageFetch(`${base}/api/home/agent?session=${ID}`)).json()) as {
    story: { prompt: string | null; steps: { id: string; icon?: string; outcome?: string; note?: string | null; sentence?: Part[] }[] }[];
  };
  const turn = page.story.find((t) => t.prompt !== null && /^Use Mandu's policy tools/.test(t.prompt))!;
  const step = turn.steps.find((s) => s.id === STEP)!;
  assert.ok(step, "the 10:42 call is a step of its turn");
  assert.equal(words(step.sentence!), SENTENCE);
  assert.deepEqual(step.sentence!.filter((p) => p.kind === "code").map((p) => p.text), ["~/mandu-try/deploy/staging.conf"]);
  assert.equal(step.icon, "shield");
  assert.equal(step.outcome, "plain", "a rule change does not change the turn's counts or tone");
  assert.equal(step.note, ANSWER);
  assert.doesNotMatch(JSON.stringify(page.story), /mandu_policy_propose|hide it from the model/, "neither the tool's name nor the agent's reason");
  await servedPage(`/agents/${ID}`, (doc) => !!doc.querySelector(`#agent-story [data-step-id="${STEP}"]`), (doc) => {
    const el = doc.querySelector(`#agent-story [data-step-id="${STEP}"]`) as HTMLElement;
    assert.ok(el.classList.contains("plain"));
    const what = el.querySelector(".what") as HTMLElement;
    assert.equal(what.firstElementChild!.textContent, SENTENCE);
    assert.equal(what.querySelector("code")!.textContent, "~/mandu-try/deploy/staging.conf");
    assert.equal(what.querySelector(".note")!.textContent, ANSWER);
    // Its last word links the change it made, which Approvals marks (§4.25b).
    const link = what.querySelector(".note a") as HTMLAnchorElement;
    assert.equal(link.textContent, "Approvals");
    assert.match(link.getAttribute("href")!, /\/approvals\/pc-\d{6}$/);
    const story = doc.getElementById("agent-story").textContent as string;
    assert.doesNotMatch(story, /mandu_policy_propose|Used mandu-policy/);
  });
});

test("the 10:42 turn says what the file's card says: the AI read staging.conf's real value at 10:41; its chips never say never, STRIPE_KEY's still do", async () => {
  const READ = moved("2026-10-05T01:41:29.686Z");
  const page = (await (await pageFetch(`${base}/api/home/agent?session=${ID}`)).json()) as {
    story: { prompt: string | null; steps: { kind: string; split?: { ai: (Part & { early?: string })[] } | null }[]; reply: { parts: (Part & { early?: string })[]; kept?: Part[] } | null }[];
  };
  const t = page.story.find((x) => x.prompt?.startsWith("Use Mandu's policy tools"))!;
  const chips = [...t.steps.flatMap((s) => s.split?.ai ?? []), ...t.reply!.parts].filter((p) => p.kind === "masked");
  assert.deepEqual(chips.map((p) => p.early), [READ, READ, READ], "the Read's chip and the reply's two");
  assert.ok(page.story.filter((x) => x !== t).flatMap((x) => [...x.steps.flatMap((s) => s.split?.ai ?? []), ...(x.reply?.parts ?? [])]).every((p) => p.early === undefined));
  assert.doesNotMatch(JSON.stringify(page), /\$MDU:|FAKE-STAGING-TOKEN-0000|FAKE-STRIPE-KEY-0000/);
  await servedPage(`/agents/${ID}`, (doc) => doc.querySelectorAll("#agent-story .reply-kept").length >= 2, (doc) => {
    const turns = [...doc.querySelectorAll("#agent-story .turn")] as HTMLElement[];
    const at = turns.find((x) => /^Use Mandu's policy tools/.test(x.querySelector(".q-text")?.textContent ?? ""))!;
    const line = at.querySelector(".reply-kept") as HTMLElement;
    assert.match(line.textContent!, new RegExp(`The AI read its real value at ${hhmm(READ)}, before it was marked a secret\\.$`));
    assert.equal(line.querySelector("time")!.getAttribute("datetime"), READ);
    const titles = ([...at.querySelectorAll(".mask-chip.secret")] as HTMLElement[]).map((c) => c.title);
    assert.equal(titles.length, 3);
    for (const title of titles) assert.equal(title, `A secret, masked here. The AI read its real value at ${hhmm(READ)}, before it was marked a secret.`);
    const others = turns.filter((x) => x !== at).flatMap((x) => ([...x.querySelectorAll(".mask-chip.secret")] as HTMLElement[]).map((c) => c.title));
    assert.ok(others.length >= 4);
    for (const title of others) assert.match(title, /masked: the AI never got the real value$/);
    assert.doesNotMatch(at.textContent!, /\$MDU:|FAKE-STAGING-TOKEN-0000/);
  });
});
