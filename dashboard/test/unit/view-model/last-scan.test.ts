/**
 * last-scan — the last `mandu scan` on the product page (dashboard.md
 * §4.25ai; confidentiality-plan-17-past-sessions-scan.md §3 item 12):
 *
 *   - the record is read again field by field (`parseLastScan`): what it
 *     does not name is dropped, a bad record reads as none;
 *   - Home's card: no scan yet says how to run one; a scan leads with how
 *     many of your secrets left this computer in your agents' requests (a
 *     session known to be under Mandu does not count), the top ones by name
 *     and file, the sends worth a look, rules waiting, and the commands;
 *   - the Scan page: each finding tells its story (where it lived, what the
 *     agent did with when, project and agent, that it left in the request to
 *     the agent's provider, what happened next, what Mandu would have done),
 *     the Mandu status a footnote; the tiers, the long one folded with a
 *     filter; the sends, the other hosts first, each naming its masked
 *     URLs; the riskier sessions; the
 *     caps; and the detail panel's examples, date range and projects; the
 *     optional fields of plan 17 phase 2 degrade when absent;
 *   - a finding or a send whose secret lives in a `~/…` or absolute file
 *     names it for Rules' link (`file`, Home's `ruleFile`); a key not in
 *     your files, a relative path or none names no file;
 *   - the copy is product vocabulary, and no 8-character run of a planted
 *     value is in any of it.
 * Axes: none (display only; the record is a `secrets`-mode scan). Mandu-new test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { homeScanCard, parseLastScan, scanFigure, scanPageVM, type LastScanWire } from "../../../src/view-model/last-scan.js";


const STRIPE = `${"sk" + "_live_"}51Qz7Kp2Lm9Xw3Rt6Yv8Nb4C`;
const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter)\b|\$MDU:|\b[Pp]laceholders?\b/i;

function record(over: Partial<LastScanWire> = {}): LastScanWire {
  return {
    version: 1,
    ranAt: "2026-10-21T09:00:00.000Z",
    sessions: { "claude-code": 812, codex: 16 },
    from: "2026-09-29T00:00:00.000Z",
    to: "2026-10-21T00:00:00.000Z",
    duringMandu: 1,
    known: 6,
    findings: [
      {
        kind: "known", preview: "STRIPE_KEY in ~/shop/.env", source: { path: "~/shop/.env", name: "STRIPE_KEY" }, sessions: 3, agents: ["claude-code"],
        first: "2026-10-01T10:00:00.000Z", last: "2026-10-19T10:00:00.000Z", how: { "command-output": 3, "ai-wrote": 1 }, projects: ["~/shop", "~/shop-api"], projectCount: 2, duringMandu: 0,
        examples: [
          { at: "2026-10-19T10:00:00.000Z", agent: "claude-code", how: "command-output", command: "cat .env | grep STRIPE", project: "~/shop", mandu: "without" },
          { at: "2026-10-02T10:00:00.000Z", agent: "claude-code", how: "read-file", file: "~/shop/.env", project: "~/shop-api", mandu: "by-time" },
        ],
      },
      { kind: "known", preview: "token in ~/.config/cli/config.yml", source: { path: "~/.config/cli/config.yml", name: "token" }, sessions: 1, agents: ["codex"], last: "2026-10-05T10:00:00.000Z", how: { "read-file": 1 }, projects: [], duringMandu: 1, sessionsUnderMandu: 1 },
      ...Array.from({ length: 12 }, (_, i) => ({ kind: "github-token", preview: "ghp_…", sessions: 1, agents: ["codex"], last: "2026-10-02T09:00:00.000Z", how: { "your-message": 1 }, projects: [`~/fixtures-${i}`], duringMandu: 0 })),
      { kind: "credential-assignment", preview: "DB_PASSWORD=…", sessions: 2, agents: ["claude-code"], how: { "command-output": 2 }, projects: [], duringMandu: 0 },
    ],
    dropped: 0,
    capped: { overTime: 0, overBytes: 0, tooBig: 1, overFiles: 0, readFailed: 0 },
    risk: { skippedPrompts: 371, skippedWithSecret: 1, envDumps: 8 },
    sends: [
      { kind: "known", preview: "STRIPE_KEY in ~/shop/.env", source: { path: "~/shop/.env", name: "STRIPE_KEY" }, to: "own-service", host: "api.stripe.com", sessions: 2, ran: 2, stoppedByMandu: 0, via: ["curl"], by: ["variable"], agents: ["claude-code"], last: "2026-10-19T10:00:00.000Z", duringMandu: 0 },
      { kind: "known", preview: "STRIPE_KEY in ~/shop/.env", source: { path: "~/shop/.env", name: "STRIPE_KEY" }, to: "other-host", host: "hooks.vendor.dev", sessions: 1, ran: 0, stoppedByMandu: 0, via: ["curl"], by: ["variable"], agents: ["claude-code"], last: "2026-10-19T10:00:00.000Z", duringMandu: 0 },
    ],
    sendsDropped: 0,
    suggestions: { pending: 1, filed: 1, covered: 1 },
    ...over,
  };
}

const allCopy = (x: unknown): string => JSON.stringify(x);

test("parseLastScan: field by field; a bad record reads as none", () => {
  const raw = { ...record(), secret: STRIPE, findings: [{ ...record().findings[0]!, raw: STRIPE }] };
  const r = parseLastScan(JSON.parse(JSON.stringify(raw)))!;
  assert.ok(!allCopy(r).includes(STRIPE.slice(8, 16)));
  assert.equal(r.findings[0]!.examples!.length, 2);
  assert.equal(parseLastScan({ version: 2 }), null);
  assert.equal(parseLastScan(null), null);
  assert.equal(parseLastScan({ ...record(), ranAt: "soon" }), null);
});

test("every agent the scan reads, by name and in order: the Scan page's sessions, Home's past sessions, a story's agent and provider", () => {
  const sessions = { openclaw: 4, goose: 3, opencode: 2, codex: 1, "claude-code": 5 };
  const f = record().findings[0]!;
  const r = record({
    sessions,
    findings: [{ ...f, agents: ["opencode", "goose"], examples: [{ at: "2026-10-19T10:00:00.000Z", agent: "opencode", how: "command-output", command: "grep OPENAI .env", project: "~/shop", mandu: "without", provider: "other" }] }],
  });
  const page = allCopy(scanPageVM(r));
  assert.match(page, /Mandu read 5 Claude Code, 1 Codex, 2 OpenCode, 3 Goose and 4 OpenClaw sessions on this computer/);
  assert.match(page, /OpenCode's next request to the model provider/);
  assert.match(homeScanCard(r).when ?? "", /15 past sessions/);
});

test("Home's card: how to run one, before any scan", () => {
  const c = homeScanCard(null);
  assert.equal(c.ran, false);
  assert.equal(c.headline, "Did your agents already send a secret to the AI?");
  assert.deepEqual(c.parts.filter((p) => p.kind === "code").map((p) => p.text), ["mandu scan"]);
  assert.match(c.sentence, /runs on this computer and sends nothing/);
  assert.equal(c.link, null);
});

test("Home's card: what left this computer, with the way to stop it, the top findings, the sends worth a look and rules waiting", () => {
  const c = homeScanCard(record());
  assert.equal(c.headline, "1 of your secrets left this computer in your agents' requests", "the config's one session ran under Mandu");
  assert.deepEqual(c.parts.filter((p) => p.kind === "code").map((p) => p.text), ["mandu claude", "mandu codex"]);
  assert.equal(c.when, "Scanned 21 Oct · 828 past sessions");
  assert.deepEqual(c.top, [{ name: "STRIPE_KEY", file: "~/shop/.env", ruleFile: "~/shop/.env", how: "a command printed it, the AI wrote it out · Claude Code · 3 sessions, last 19 Oct" }]);
  assert.equal(c.worthWords, "1 send to a host Mandu cannot tie to the key's own service is worth a look.");
  assert.match(c.suggested ?? "", /^1 file that holds them has no rule yet/);
  assert.deepEqual(c.againParts.map((p) => p.text), ["Run it again: ", "mandu scan"]);
  assert.equal(c.link, "scan");
  const none = homeScanCard(record({ findings: [] }));
  assert.equal(none.headline, "None of your secrets left this computer in your agents' requests");
});

test("the Scan page: each finding's story, its footnote, its examples; the tiers, the sends and the riskier sessions", () => {
  const r = record();
  // Part D's fields: the examples by way, the hosts, the provider.
  const f0 = r.findings[0]!;
  f0.examples![0]!.provider = "anthropic";
  f0.sentToHosts = ["hooks.vendor.dev", "api.stripe.com"];
  f0.examplesByHow = {
    "read-file": [{ at: "2026-10-02T10:00:00.000Z", agent: "claude-code", how: "read-file", file: "~/shop/.env", project: "~/shop-api", mandu: "by-time" }],
    "command-output": [{ at: "2026-10-19T10:00:00.000Z", agent: "claude-code", how: "command-output", command: "cat .env | grep STRIPE", project: "~/shop", mandu: "without" }],
  };
  const p = scanPageVM(r);
  assert.equal(p.read, "Mandu read 812 Claude Code and 16 Codex sessions on this computer (29 Sep to 21 Oct), on 21 Oct. Nothing left this computer for the scan, and no secret's value is shown here.");
  assert.deepEqual(p.notes, ["1 session record over 512 MiB not read."]);
  assert.deepEqual(p.sections.map((s) => [s.id, s.items.length, s.folded, s.filter]), [
    ["yours", 1, false, false], ["looks", 12, true, true], ["named", 1, true, false], ["kept", 1, true, false], ["sends-other", 1, false, false], ["sends-own", 1, false, false],
  ]);
  const stripe = p.sections[0]!.items[0]!;
  assert.equal(stripe.title, "STRIPE_KEY in ~/shop/.env");
  assert.equal(stripe.summary, "3 sessions, 1 Oct to 19 Oct, 2 projects · a command printed it, the AI wrote it out · Claude Code");
  assert.deepEqual(stripe.story.map((s) => s.step), ["lived", "when", "did", "went", "next", "next", "instead"]);
  assert.deepEqual(stripe.story.map((s) => s.text), [
    "It lives in ~/shop/.env as STRIPE_KEY.",
    "The newest: 19 Oct · ~/shop · Claude Code",
    "The agent ran: cat .env | grep STRIPE",
    "The output, with the secret in it, went to the AI: it left this computer in Claude Code's next request to Anthropic.",
    "The AI also wrote it out, in its text or a command (1 session).",
    "A command also sent it on over the network, to hooks.vendor.dev, api.stripe.com (below).",
    "With Mandu, the AI would have seen the secret masked in that output; the command itself would still have run.",
  ]);
  assert.deepEqual(stripe.story[2]!.parts.filter((x) => x.kind === "code").map((x) => x.text), ["cat .env | grep STRIPE"], "the command is code");
  assert.equal(stripe.footnote, "3 sessions without Mandu.");
  assert.deepEqual(stripe.detail, {
    range: "1 Oct to 19 Oct",
    projects: "2 projects: ~/shop, ~/shop-api",
    groups: [
      { title: "A command printed it (3 sessions)", examples: [{ head: "19 Oct · ~/shop · Claude Code", did: "The agent ran:", code: "cat .env | grep STRIPE", mandu: "without Mandu" }] },
      { title: "The agent read the file", examples: [{ head: "2 Oct · ~/shop-api · Claude Code", did: "The agent read:", code: "~/shop/.env", mandu: "while Mandu ran (by the time only)" }] },
    ],
  });
  // Seen only under Mandu: kept from the AI, its own folded list. Codex, no
  // examples (before part D): the counts tell it, and the provider is the agent's.
  const cfg = p.sections.find((s) => s.id === "kept")!.items[0]!;
  assert.equal(cfg.story.find((s) => s.step === "did")!.text, "The agent read: ~/.config/cli/config.yml");
  // Seen only under Mandu: told so, in green (before 2026-10-22 the story
  // made from the counts said it had left).
  const cfgWent = cfg.story.find((s) => s.step === "went")!;
  assert.equal(cfgWent.text, "This session ran under Mandu: the AI saw it masked; only the record on disk holds the value.");
  assert.equal(cfgWent.tone, "ok");
  assert.equal(cfg.footnote, "1 session with Mandu, where the AI saw it masked.");
  assert.deepEqual(cfg.detail.groups, []);
  // The looks-like tier: what it is, and a filter over its projects.
  const look = p.sections[1]!.items[0]!;
  assert.match(look.story[0]!.text, /^It looks like a GitHub token \(ghp_…\), but it is not in your files now/);
  assert.equal(look.story.find((s) => s.step === "went")!.text, "Your message, with the key in it, left this computer in Codex's request to OpenAI.");
  assert.equal(look.story.at(-1)!.text, "With Mandu, a key like this is masked when it is in a file or variable Mandu protects; one it does not hold reaches the AI as before.");
  assert.ok(look.filter.includes("~/fixtures-0"));
  // The sends: the host first, by variable, failed.
  const other = p.sections.find((s) => s.id === "sends-other")!.items[0]!;
  assert.equal(other.title, "STRIPE_KEY in ~/shop/.env → hooks.vendor.dev");
  assert.equal(other.story.find((s) => s.step === "went")!.text, "The command used its variable, so the AI saw only the name; the command sent the value to hooks.vendor.dev. It failed or was refused.");
  assert.equal(other.story.at(-1)!.text, "With Mandu, the real value is filled in only for a host the secret may go to, or after you say yes.");
  assert.deepEqual(p.risk, [
    "371 sessions ran with the agent's permission prompts off: every command ran without asking you (in 1 of them one of your secrets reached the AI).",
    "8 sessions printed your whole environment to the AI (env, printenv, …): every variable in it, secrets too, went into the request.",
  ]);
  assert.deepEqual(p.stopParts.filter((x) => x.kind === "code").map((x) => x.text), ["mandu claude", "mandu codex"]);
  // A provider the record names "other", and the newest example under Mandu.
  f0.examples = [{ at: "2026-10-20T10:00:00.000Z", agent: "opencode", how: "read-file", file: "~/shop/.env", mandu: "under", provider: "other" }];
  const q = scanPageVM(r).sections[0]!.items[0]!;
  assert.equal(q.story.find((s) => s.step === "went")!.text, "This session ran under Mandu: the AI saw it masked; only the record on disk holds the value.");
  f0.examples[0]!.mandu = "without";
  assert.equal(scanPageVM(r).sections[0]!.items[0]!.story.find((s) => s.step === "went")!.text, "The file's content, with the secret in it, went to the AI: it left this computer in OpenCode's next request to the model provider.");
});

test("the Scan page: a web fetch's story names the URL it fetched, as code; the AI writing a key into one too; the URL in the filter and the detail", () => {
  const r = record();
  const f0 = r.findings[0]!;
  f0.how = { "tool-result": 1, "ai-wrote": 1 };
  f0.examples = [{ at: "2026-10-19T10:00:00.000Z", agent: "claude-code", how: "tool-result", tool: "WebFetch", url: "https://docs.vendor.dev/setup?key=…", project: "~/shop", mandu: "without", provider: "anthropic" }];
  f0.examplesByHow = { "ai-wrote": [{ at: "2026-10-18T10:00:00.000Z", agent: "openclaw", how: "ai-wrote", tool: "web_fetch", url: "https://hooks.vendor.dev/in?token=…", mandu: "without", provider: "other" }] };
  const item = scanPageVM(parseLastScan(JSON.parse(JSON.stringify(r)))).sections[0]!.items[0]!;
  const did = item.story.find((s) => s.step === "did")!;
  assert.equal(did.text, "The agent fetched (WebFetch): https://docs.vendor.dev/setup?key=…");
  assert.deepEqual(did.parts.filter((x) => x.kind === "code").map((x) => x.text), ["https://docs.vendor.dev/setup?key=…"], "the URL is code");
  assert.equal(item.story.find((s) => s.step === "went")!.text, "The page it fetched, with the secret in it, went to the AI: it left this computer in Claude Code's next request to Anthropic.");
  assert.deepEqual(item.detail.groups[0]!.examples[0], { head: "18 Oct · OpenClaw", did: "The AI wrote it into a web fetch (web_fetch):", code: "https://hooks.vendor.dev/in?token=…", mandu: "without Mandu" });
  assert.ok(item.filter.includes("docs.vendor.dev/setup"), "Find one finds it by its URL");
  // A URL that is not a string is not read.
  const bad = JSON.parse(JSON.stringify(r)) as { findings: Array<{ examples: Array<Record<string, unknown>> }> };
  bad.findings[0]!.examples[0]!["url"] = { href: "x" };
  assert.equal(parseLastScan(bad)!.findings[0]!.examples![0]!.url, undefined);
});

test("the Scan page: a send names the URLs at its host as the arbiter masked them; the record keeps five strings, each cut", () => {
  const r = record();
  r.sends![1]!.urls = ["https://hooks.vendor.dev/in?k=$STRIPE_KEY", "https://…@hooks.vendor.dev/up?src=…"];
  const parsed = parseLastScan(JSON.parse(JSON.stringify({ ...r, sends: [{ ...r.sends![1]!, urls: [...r.sends![1]!.urls!, 7, `https://x.dev/${"a".repeat(400)}`, "a", "b", "c", "d"] }] })))!;
  assert.equal(parsed.sends![0]!.urls!.length, 5);
  assert.equal(parsed.sends![0]!.urls![2]!.length, 161, "cut");
  const item = scanPageVM(r).sections.find((s) => s.id === "sends-other")!.items[0]!;
  const went = item.story.find((s) => s.step === "went")!;
  assert.equal(went.text, "The command used its variable, so the AI saw only the name; the command sent the value to https://hooks.vendor.dev/in?k=$STRIPE_KEY and https://…@hooks.vendor.dev/up?src=…. It failed or was refused.");
  assert.deepEqual(went.parts.filter((x) => x.kind === "code").map((x) => x.text), r.sends![1]!.urls, "each URL as code");
  assert.equal(item.title, "STRIPE_KEY in ~/shop/.env → hooks.vendor.dev", "the host grouping stays");
  assert.ok(item.filter.includes("/up?src="), "the filter finds a send by its URL");
});

test("the Scan page: a time-only mark without part B, an older scan with no sends, and none kept", () => {
  const r = record();
  r.findings[0]!.duringMandu = 1;
  const p = scanPageVM({ ...r, sends: undefined } as unknown as LastScanWire);
  assert.equal(p.sections[0]!.items[0]!.footnote, "2 sessions without Mandu; 1 session while Mandu ran the same agent (by the time only: the AI may have seen it masked there).");
  assert.ok(!p.sections.some((s) => s.id.startsWith("sends")), "no sends section when the scan kept none");
  const none = scanPageVM(null);
  assert.equal(none.ran, false);
  assert.deepEqual(none.sections, []);
});

test("every word is product vocabulary, and no planted value is in any of it", () => {
  const r = record();
  r.findings[0]!.examples![0]!.command = `curl -u "$STRIPE_KEY:" https://api.stripe.com # ${"sk" + "_live_"}…`;
  for (const x of [homeScanCard(null), homeScanCard(r), scanPageVM(null), scanPageVM(r)]) {
    const text = allCopy(x);
    assert.doesNotMatch(text.replace(/"(id|step|kind)":"[a-z-]+"/g, ""), FORBIDDEN);
    for (let i = 0; i + 8 <= STRIPE.length; i++) {
      const piece = STRIPE.slice(i, i + 8);
      if (piece !== "sk_live_") assert.ok(!text.includes(piece), piece);
    }
  }
});

test("an agent Mandu does not run (plan 17 §4 phase 3): its story says Mandu could not have kept it, the way to stop it names the agents Mandu runs, and the chats not read are counted", () => {
  const f = record().findings[0]!;
  const r = record({
    sessions: { "claude-code": 5, gemini: 2, copilot: 1 },
    notRead: { cursor: 4 },
    findings: [{ ...f, agents: ["gemini"], examples: [{ at: "2026-10-19T10:00:00.000Z", agent: "gemini", how: "command-output", command: "cat .env", project: "~/shop", mandu: "without", provider: "google" }] }],
  });
  const page = scanPageVM(r);
  assert.match(page.read ?? "", /Mandu read 5 Claude Code, 2 Gemini CLI and 1 Copilot CLI sessions/);
  const story = page.sections[0]!.items[0]!.story;
  assert.match(story.find((s) => s.step === "went")!.text, /Gemini CLI's next request to Google\./);
  assert.equal(story.find((s) => s.step === "instead")!.text, "Mandu does not run Gemini CLI yet, so there it could not have kept the secret from the AI.");
  const stop = page.stopParts.map((p) => p.text).join("");
  assert.match(stop, /Mandu does not run Gemini CLI and Copilot CLI yet; the agents it runs: mandu claude, mandu codex, .*mandu goose\./);
  assert.ok(page.stopParts.some((p) => p.kind === "code" && p.text === "mandu goose"), "each command as code");
  assert.match(homeScanCard(r).sentence, /Mandu does not run Gemini CLI and Copilot CLI yet/);
  assert.ok(page.notes.includes("4 Cursor chats not read: Mandu cannot read its chat store reliably yet."));
  assert.equal(parseLastScan(JSON.parse(JSON.stringify(r)))!.notRead?.["cursor"], 4, "kept through the file");
  const plain = scanPageVM(record());
  assert.ok(!allCopy(plain).includes("does not run"), "nothing said when only agents Mandu runs were read");
  assert.ok(!FORBIDDEN.test(allCopy(page)), "product vocabulary only");
  // Only agents Mandu does not run: no green promise, and the figure is
  // told in general (never as if Mandu would have kept Gemini CLI's secret).
  const gemini = record({ sessions: { gemini: 3 }, findings: [{ ...f, agents: ["gemini"], examples: [{ at: "2026-10-19T10:00:00.000Z", agent: "gemini", how: "command-output", command: "cat .env", mandu: "without", provider: "google" }] }] });
  assert.equal(homeScanCard(gemini).safeLine, null);
  assert.equal(scanFigure(gemini).leaked, false);
  assert.equal(scanFigure(gemini).agent, null);
  assert.equal(scanPageVM(gemini).sections[0]!.items[0]!.story.at(-1)!.tone, "plain", "no green where Mandu could not have kept it");
});

test("color with meaning (§4.25ai): the tones come from the server, each with its word", () => {
  const r = record();
  const card = homeScanCard(r);
  assert.equal(card.tone, "bad");
  assert.equal(card.safeLine, "With Mandu, this secret stays safe: the AI sees only its mask, and your agent still does its work.");
  const page = scanPageVM(r);
  assert.equal(page.tone, "bad");
  assert.equal(page.safeLine, card.safeLine);
  assert.deepEqual(page.sections.map((s) => [s.id, s.tone]), [
    ["yours", "bad"], ["looks", "warn"], ["named", "warn"], ["kept", "ok"], ["sends-other", "bad"], ["sends-own", "plain"],
  ]);
  assert.deepEqual(page.sections.map((s) => s.items[0]?.badge), ["Reached the AI", "Not in your files now", "Not in your files now", "Kept from the AI", "Sent to another host", "Sent to its own service"]);
  const stripe = page.sections[0]!.items[0]!;
  assert.equal(stripe.tone, "bad");
  assert.deepEqual(stripe.story.map((s) => [s.step, s.tone]), [["lived", "plain"], ["when", "plain"], ["did", "plain"], ["went", "bad"], ["next", "bad"], ["next", "bad"], ["instead", "ok"]]);
  assert.deepEqual(stripe.flow, { file: "~/shop/.env", agent: "Claude Code", provider: "Anthropic", reached: "real" });
  assert.deepEqual(stripe.footnoteParts, [{ text: "3 sessions without Mandu.", tone: "bad" }]);
  assert.deepEqual(page.sections.find((s) => s.id === "kept")!.items[0]!.flow, { file: "~/.config/cli/config.yml", agent: "Codex", provider: "OpenAI", reached: "masked" });
  // A key-shaped value Mandu may not hold: its "with Mandu" is said plainly.
  assert.equal(page.sections[1]!.items[0]!.story.at(-1)!.tone, "plain");
  assert.equal(page.sections[1]!.items[0]!.flow, null);
  // To its own service: no red, not even "without Mandu".
  const own = page.sections.find((s) => s.id === "sends-own")!.items[0]!;
  assert.equal(own.story.find((s) => s.step === "went")!.tone, "plain");
  assert.deepEqual(own.footnoteParts, [{ text: "2 sessions without Mandu.", tone: "plain" }]);
  assert.equal(page.sections.find((s) => s.id === "sends-other")!.items[0]!.story.find((s) => s.step === "went")!.tone, "bad");
  // The footnote's parts, each its own tone, join to the footnote.
  const mixed = scanPageVM(record({ findings: [{ ...r.findings[0]!, sessions: 4, sessionsUnderMandu: 1, sessionsByTime: 1 }] })).sections[0]!.items[0]!;
  assert.deepEqual(mixed.footnoteParts!.map((p) => p.tone), ["bad", "ok", "warn"]);
  assert.equal(mixed.footnoteParts!.map((p) => p.text).join(""), mixed.footnote);
});

test("nothing left: green headline, no achievement in an empty list, and no riskier session says a secret reached the AI", () => {
  const r = record({ findings: record().findings.filter((f) => f.kind !== "known" || (f.sessionsUnderMandu ?? 0) >= f.sessions), sends: [] });
  const page = scanPageVM(r);
  assert.equal(page.tone, "ok");
  assert.equal(homeScanCard(r).tone, "ok");
  assert.equal(page.safeLine, "With Mandu, your secrets stay safe: the AI sees only their masks, and your agent still does its work.");
  const yours = page.sections.find((s) => s.id === "yours")!;
  assert.equal(yours.tone, "plain", "an empty list is no achievement");
  assert.equal(yours.emptyTone, "ok", "its line, none reached the AI, is green");
  assert.equal(page.sections.find((s) => s.id === "sends-other")!.tone, "plain");
  // The record counts a prompts-off session with one of your secrets in it,
  // under Mandu or not: with none left, the page does not say one reached the AI.
  assert.equal(r.risk!.skippedWithSecret, 1);
  assert.equal(page.risk[0], "371 sessions ran with the agent's permission prompts off: every command ran without asking you.");
  assert.match(scanPageVM(record()).risk[0]!, /\(in 1 of them one of your secrets reached the AI\)/);
  // The figure is told in general.
  const fig = page.figure!;
  assert.equal(fig.leaked, false);
  assert.equal(fig.title, "What Mandu does with a secret your agent reads");
  assert.deepEqual([fig.file, fig.name, fig.agent, fig.provider], [null, null, null, null]);
});

test("the figure: the newest of your secrets that reached the AI, its file, agent and provider, without Mandu and with it", () => {
  const r = record();
  r.findings[0]!.examples![0]!.provider = "anthropic";
  const fig = scanFigure(r);
  assert.equal(fig.title, "What happened, and what Mandu does instead");
  assert.equal(fig.leaked, true);
  assert.deepEqual([fig.file, fig.name, fig.agent, fig.provider], ["~/shop/.env", "STRIPE_KEY", "Claude Code", "Anthropic"]);
  assert.equal(fig.without.label, "Without Mandu: what happened");
  assert.deepEqual(fig.without.steps, [
    "STRIPE_KEY lives in ~/shop/.env.",
    "Claude Code ran a command that printed it.",
    "Its next request took the real value to Anthropic's AI model: it left this computer.",
  ]);
  assert.equal(fig.with.label, "With Mandu");
  assert.deepEqual(fig.with.steps, [
    "Mandu masks it on its way into Claude Code.",
    "Anthropic's AI model sees only the mask, and Claude Code still does its work.",
    "The real value is put back only for a host the secret belongs to, or after you say yes.",
  ]);
  assert.deepEqual(homeScanCard(r).figure, fig, "Home's card carries the same");
  assert.deepEqual(scanPageVM(r).figure, fig);
  // A provider the record does not know: "the AI model", and no name.
  r.findings[0]!.examples![0]!.provider = "other";
  assert.equal(scanFigure(r).provider, null);
  assert.equal(scanFigure(r).without.steps[2], "Its next request took the real value to the AI model: it left this computer.");
  assert.equal(scanFigure(r).with.steps[1], "The AI model sees only the mask, and Claude Code still does its work.");
  assert.equal(homeScanCard(null).figure, null);
  assert.equal(scanPageVM(null).figure, null);
  assert.ok(!FORBIDDEN.test(allCopy(fig)), "product vocabulary only");
  for (let i = 0; i + 8 <= STRIPE.length; i++) assert.ok(!allCopy(fig).includes(STRIPE.slice(i, i + 8)));
});

test("parseLastScan: a send's channel and the test-value mark read back (plan 17 §3 items 11, 14); an MCP tool is not called a host", () => {
  const r = record();
  const mcp = { ...r.sends![1]!, host: "mcp__notes__save", via: ["MCP"], channel: "mcp" as const };
  const raw = JSON.parse(JSON.stringify({
    ...r,
    findings: [{ ...r.findings[0]!, looksLikeTest: true }, { ...r.findings[2]!, looksLikeTest: true }],
    sends: [mcp, { ...r.sends![0]!, channel: "smoke-signal" }, { ...r.sends![0]!, kind: "openai-key", preview: "sk-…", channel: "ssh", host: "prod", looksLikeTest: true }],
  }));
  const parsed = parseLastScan(raw)!;
  assert.deepEqual(parsed.findings.map((f) => f.looksLikeTest), [undefined, true], "one of your secrets is never marked");
  assert.deepEqual(parsed.sends!.map((s) => [s.channel, s.looksLikeTest]), [["mcp", undefined], [undefined, undefined], ["ssh", true]]);
  // A finding whose only send went to an MCP tool: its story names no host.
  const vm = scanPageVM({ ...r, findings: [r.findings[0]!], sends: [mcp] });
  const story = vm.sections.flatMap((s) => s.items).find((i) => i.title === r.findings[0]!.preview)!.story;
  assert.ok(!story.some((s) => s.text.includes("over the network")), "an MCP tool is not a host on the network");
  const item = vm.sections.flatMap((s) => s.items).find((i) => i.title.endsWith("mcp__notes__save"))!;
  assert.equal(item.story.find((s) => s.step === "did")!.text, "The agent gave it to an MCP server's tool, mcp__notes__save.");
});

test("the Scan page's tones: a test-looking value is told plainly with its own badge, never red; a send's tone follows its section, an MCP send's too", () => {
  const r = record();
  const keys = r.findings.filter((f) => f.kind === "github-token");
  keys[0]!.looksLikeTest = true;
  keys[0]!.examples = [{ at: "2026-10-02T09:00:00.000Z", agent: "codex", how: "your-message", mandu: "without" }];
  r.sends = [...r.sends!, { ...r.sends![1]!, host: "mcp__notes__save", via: ["MCP"], channel: "mcp" }, { kind: "github-token", preview: "ghp_…", to: "own-service", host: "api.github.com", sessions: 1, ran: 1, stoppedByMandu: 0, via: ["curl"], by: ["value"], agents: ["codex"], duringMandu: 0, looksLikeTest: true }];
  const vm = scanPageVM(r);
  const looks = vm.sections.find((s) => s.id === "looks")!.items;
  const test = looks.find((i) => i.badge === "Looks like a test value")!;
  assert.ok(test, "the marked value has its own badge");
  assert.equal(test.tone, "plain");
  assert.ok(test.story.every((s) => s.tone !== "bad"), "no step of its story is red");
  assert.ok(looks.filter((i) => i !== test).every((i) => i.tone === "warn"), "the others keep the section's tone");
  const mcp = vm.sections.find((s) => s.id === "sends-other")!.items.find((i) => i.title.endsWith("mcp__notes__save"))!;
  assert.equal(mcp.tone, "bad", "a send's tone follows its section");
  const own = vm.sections.find((s) => s.id === "sends-own")!.items.find((i) => i.title === "ghp_… → api.github.com")!;
  assert.equal(own.tone, "plain");
  assert.match(own.story.find((s) => s.step === "lived")!.text, /and like a test value\.$/);
});

test("a finding's file for Change it in Rules (§4.25ai): a known secret's or a send's ~/… or absolute file; none for a key not in your files, a relative path or no source", () => {
  const r = record();
  const abs = { ...r.findings[0]!, preview: "API_KEY in /srv/app/.env", source: { path: "/srv/app/.env", name: "API_KEY" } };
  const rel = { ...r.findings[0]!, preview: "API_KEY in app/.env", source: { path: "app/.env", name: "API_KEY" } };
  const nameless = { ...r.findings[0]!, preview: "known…", source: undefined };
  const p = scanPageVM(record({ findings: [r.findings[0]!, abs, rel, nameless, ...r.findings.slice(1)] }));
  const yours = p.sections.find((s) => s.id === "yours")!.items;
  assert.deepEqual(yours.map((i) => [i.title, i.file]), [
    ["STRIPE_KEY in ~/shop/.env", "~/shop/.env"], ["API_KEY in /srv/app/.env", "/srv/app/.env"], ["API_KEY in app/.env", null], ["known…", null],
  ]);
  for (const id of ["looks", "named"]) {
    const items = p.sections.find((s) => s.id === id)!.items;
    assert.ok(items.length > 0 && items.every((i) => i.file === null), `${id}: a key not in your files names no file`);
  }
  assert.equal(p.sections.find((s) => s.id === "kept")!.items[0]!.file, "~/.config/cli/config.yml", "kept by Mandu: its file still opens in Rules");
  // The sends: a source file, else none.
  const s0 = r.sends![0]!;
  const sends = scanPageVM(record({ sends: [s0, { ...s0, host: "x.example", source: { path: "conf/keys.env" } }, { ...s0, kind: "github-token", preview: "ghp_…", host: "y.example", source: undefined }] }));
  const own = sends.sections.find((s) => s.id === "sends-own")!.items;
  assert.deepEqual(own.map((i) => i.file), ["~/shop/.env", null, null]);
  // Home's top: the same rule, its `file` kept as the record says.
  const top = homeScanCard(record({ findings: [r.findings[0]!, abs, rel, nameless] })).top;
  assert.deepEqual(top.map((t) => [t.file, t.ruleFile]), [["~/shop/.env", "~/shop/.env"], ["/srv/app/.env", "/srv/app/.env"], ["app/.env", null]]);
});
