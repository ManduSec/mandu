/**
 * scan-command.test — `mandu scan`'s own parts (launcher/src/scan-command.ts;
 * confidentiality-plan-17-past-sessions-scan.md): the options, the compact
 * report and the long one (`--all`): what leaked to the AI, what only looks
 * like a key, what a cap left unread, the sessions under Mandu; the words
 * per output ("leaked" in the terminal report and --show, "reached" in
 * --share and --json), the colours (a terminal only, NO_COLOR, FORCE_COLOR),
 * the share text (counts only), and the exit codes with a stand-in arbiter. The scan itself and its production
 * wiring: arbiter/test/unit/transcript-scan.test.ts and
 * tests/stack/transcript-scan.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { dashboardLine, dashboardWhere, manduCommand, numberedFindings, parseScanArgs, ranThroughNpx, renderScan, renderShow, runScan, scanCallTimeoutMs, shareText, shortCommand, type ExampleWire, type FindingWire, type ScanWire, type SendWire } from "../../src/scan-command.js";
import { ANSI, colorOn, colors, PLAIN, stripAnsi } from "../../src/term-style.js";
import type { Layout } from "../../src/services/layout.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the report words a `secrets`-mode scan; no axis is read

const NOW = Date.parse("2026-10-21T00:00:00Z");

function finding(over: Partial<FindingWire>): FindingWire {
  return { kind: "known", preview: "STRIPE_KEY in ~/shop/.env", sessions: 1, agents: ["claude-code"], last: "2026-10-19T10:00:00Z", how: { "read-file": 1 }, projects: [], duringMandu: 0, ...over };
}

function wire(over: Partial<ScanWire>): ScanWire {
  return {
    axis: true, sessions: { "claude-code": 3, codex: 1 }, duringMandu: 0, from: "2026-09-29T00:00:00Z", to: "2026-10-21T00:00:00Z",
    findings: [], dropped: 0, known: 4, bytes: 1000, capped: { overTime: 0, overBytes: 0, tooBig: 0, overFiles: 0, readFailed: 0 }, ms: 10, ...over,
  };
}

test("parseScanArgs: the flags, --since in days or as a date, and a refusal for anything else", () => {
  assert.deepEqual(parseScanArgs([], NOW), { json: false, share: false, all: false });
  assert.deepEqual(parseScanArgs(["--json", "--all"], NOW), { json: true, share: false, all: true });
  assert.deepEqual(parseScanArgs(["--since", "30d"], NOW), { json: false, share: false, all: false, since: NOW - 30 * 86_400_000 });
  assert.deepEqual(parseScanArgs(["--since=2026-09-01"], NOW), { json: false, share: false, all: false, since: Date.parse("2026-09-01T00:00:00Z") });
  assert.match((parseScanArgs(["--since", "soon"], NOW) as { error: string }).error, /not a number of days/);
  assert.match((parseScanArgs(["--since"], NOW) as { error: string }).error, /wants a number of days/);
  assert.match((parseScanArgs(["--fix"], NOW) as { error: string }).error, /unknown option '--fix'/);
});

test("renderScan: a secret that leaked to the AI, compact by default, long with --all (an older arbiter's answer, with no example)", () => {
  const r = wire({ findings: [finding({ sessions: 2, how: { "read-file": 2, "command-output": 1 }, agents: ["claude-code", "codex"], duringMandu: 1 })] });
  const out = renderScan(r, { all: false });
  assert.match(out, /^mandu scan · 4 sessions · Claude Code, Codex · 29 Sep – 21 Oct\nNothing was sent anywhere; no secret value is shown\.\n\n/);
  assert.match(out, /\n✗ 1 of your secrets leaked to the AI\n\n {2}1 {2}STRIPE_KEY in ~\/shop\/\.env\n {5}2 sessions, last 19 Oct · the agent read the file, a command printed it\n\n {2}→ Rotate it now, where it was issued\.\n/);
  assert.ok(!out.includes("1 while Mandu ran"), "with or without Mandu is a footnote, not a column");
  assert.ok(!out.includes("reached the AI"), "the terminal report says leaked");
  assert.match(out, /\n✓ With Mandu, this secret stays safe: the AI sees only a \$MDU:… placeholder, and your agent still does its work\.\n {2}Protect your agents: {2}mandu claude {2}\(or mandu codex\)\n {2}One in full: {10}mandu scan --show 1 {3}Everything: mandu scan --all\n$/);
  const long = renderScan(r, { all: true });
  assert.match(long, /^mandu scan: read 3 Claude Code and 1 Codex sessions on this computer \(29 Sep to 21 Oct\)\.\n/);
  assert.match(long, /Nothing left this computer, and no secret's value is shown below\./);
  assert.match(long, /1 of your secrets leaked to the AI:\n\n {2}1\. STRIPE_KEY in ~\/shop\/\.env\n {5}2 sessions, last 19 Oct · the agent read the file, a command printed it · Claude Code and Codex\n/);
  assert.match(long, /It is still where it was found: change it where it was issued\./);
  assert.match(long, /mandu claude \(or mandu codex\)/);
});

test("renderScan: the compact report as the maintainer laid it out: name and file, sessions, the ways (three at most), the one command shortened, the HTTP send", () => {
  const dash = finding({
    preview: "DASHBOARD_BASIC_AUTH in ~/.mandu/dashboard.env", source: { path: "~/.mandu/dashboard.env", name: "DASHBOARD_BASIC_AUTH" },
    sessions: 6, last: "2026-10-16T10:00:00Z", how: { "ai-wrote": 2, "your-message": 4, "command-output": 3, "read-file": 1 }, sentToHosts: ["dash.example.dev"],
    examples: [ex({ how: "your-message" })],
  });
  const cred = finding({
    preview: "accessToken in ~/.config/mandu-ci/claude-credential.json", source: { path: "~/.config/mandu-ci/claude-credential.json", name: "accessToken" },
    how: { "command-output": 1 }, examples: [ex({ command: "python3 - <<'EOF' …" })],
  });
  const glab = finding({
    preview: "hosts.git.example.dev.token in ~/.config/glab-cli/config.yml", source: { path: "~/.config/glab-cli/config.yml", name: "hosts.git.example.dev.token" },
    last: "2026-10-05T10:00:00Z", how: { "command-output": 1 }, examples: [ex({ command: "cd ~/work/infra && python3 -c 'import yaml; print(open(\"x\").read())'" })],
  });
  const keys = [
    ...Array.from({ length: 4 }, () => finding({ kind: "openai-key", preview: "sk-…" })),
    ...Array.from({ length: 2 }, () => finding({ kind: "stripe-key", preview: "sk_live_…" })),
    finding({ kind: "github-token", preview: "ghp_…" }), finding({ kind: "aws-key", preview: "AKIA…" }),
    finding({ kind: "slack-token", preview: "xoxb-…" }), finding({ kind: "google-key", preview: "AIza…" }),
  ];
  const r = wire({
    sessions: { "claude-code": 800, codex: 34 }, to: "2026-10-22T00:00:00Z", findings: [dash, cred, glab, ...keys],
    sends: [{ kind: "known", preview: dash.preview, source: dash.source!, to: "other-host", host: "dash.example.dev", sessions: 1, ran: 1, stoppedByMandu: 0, via: ["curl"], by: ["value"], agents: ["claude-code"], duringMandu: 0 }],
    risk: { skippedPrompts: 371, skippedWithSecret: 0, envDumps: 8 },
  });
  assert.equal(renderScan(r, { all: false, dashboard: "http://127.0.0.1:4500/scan (sign in with its password)" }), [
    "mandu scan · 834 sessions · Claude Code, Codex · 29 Sep – 22 Oct",
    "Nothing was sent anywhere; no secret value is shown.",
    "",
    "✗ 3 of your secrets leaked to the AI",
    "",
    "  1  DASHBOARD_BASIC_AUTH   ~/.mandu/dashboard.env",
    "     6 sessions, last 16 Oct · you pasted it, a command printed it, the AI wrote it",
    "     also sent over HTTP to dash.example.dev",
    "  2  accessToken   ~/.config/mandu-ci/claude-credential.json",
    "     1 session, 19 Oct · a command printed it: python3 - <<'EOF' …",
    "  3  hosts.git.example.dev.token   ~/.config/glab-cli/config.yml",
    "     1 session, 5 Oct · a command printed it: cd ~/work/infra && python3 -c 'import …",
    "",
    "  → Rotate these 3 now, where they were issued.",
    "",
    "! 10 more key-shaped values leaked (not in your files now: old",
    "  keys, someone else's, or test values)",
    "  sk-… ×4 · sk_live_… ×2 · AIza… ×1 · AKIA… ×1 · ghp_… ×1 · …",
    "",
    "! Risky sessions",
    "  371 ran with permission prompts off",
    "  8 printed your whole environment to the AI",
    "",
    "✓ With Mandu, these 3 secrets stay safe: the AI sees only a $MDU:… placeholder, and your agent still does its work.",
    "  Protect your agents:  mandu claude  (or mandu codex)",
    "  One in full:          mandu scan --show 1   Everything: mandu scan --all",
    "  Dashboard:            http://127.0.0.1:4500/scan (sign in with its password)",
    "",
  ].join("\n"));
  // The numbers: your secrets 1 to 3 as shown; --show and --all agree.
  const order = numberedFindings(r);
  assert.deepEqual(order.slice(0, 3), [dash, cred, glab]);
  assert.match(renderShow(r, 2)!, /\n2\. accessToken in ~\/\.config\/mandu-ci\/claude-credential\.json: one of your secrets, leaked to the AI \(still where it was found\)\n/);
  const long = renderScan(r, { all: true });
  assert.match(long, /\n {2}1\. DASHBOARD_BASIC_AUTH in ~\/\.mandu\/dashboard\.env\n/);
  assert.match(long, /\n {2}13\. AIza…\n/, "the key-shaped values keep their numbers, listed by --all");
  assert.match(long, /To a host Mandu cannot tie to the key's own service \(worth a look\):\n {4}DASHBOARD_BASIC_AUTH in ~\/\.mandu\/dashboard\.env → dash\.example\.dev\n/, "the sends in full are --all's");
});

test("shortCommand: a path the cut falls in is shortened by its middle or cut after a /, never mid-name; the redaction kept", () => {
  assert.equal(shortCommand("cat ~/.config/some-cli/profiles/default/credential.json"), "cat ~/.config/some-cli/…/credential.json");
  assert.equal(shortCommand("cat /home/user/project/app/config/secrets/production.env | head"), "cat /home/user/project/…/production.env …");
  assert.equal(shortCommand("curl -s https://api.vendor.dev/v1/accounts/acct/keys?page=…"), "curl -s https://api.vendor.dev/…/keys?page=…", "a URL keeps its host");
  assert.equal(shortCommand("sed -n 1,140p tests/fixtures/keys/very-long-file-name-for-keys-fixture.ts"), "sed -n 1,140p tests/fixtures/keys/ …", "a last part too long even shortened: cut after a /");
  // A last part too long to fit: cut after the last / that fits.
  assert.equal(shortCommand("cat ~/a/b/c/an-extremely-long-file-name-that-will-not-fit-in-forty.json"), "cat ~/a/b/c/ …");
  // No path: the arguments that fit, never half a word.
  assert.equal(shortCommand("PGPASSWORD=‹DB_PASSWORD› psql --host=db.shop.internal.example --port 5432"), "PGPASSWORD=‹DB_PASSWORD› psql …");
  // One long word: cut after a separator, never inside a mask.
  assert.equal(shortCommand("TOKEN=‹GITHUB_TOKEN›,OTHER=‹A_VERY_LONG_SECRET_NAME_HERE›"), "TOKEN=‹GITHUB_TOKEN›,OTHER= …");
  for (const c of ["cat ~/.config/some-cli/profiles/default/credential.json", "TOKEN=‹GITHUB_TOKEN›,OTHER=‹A_VERY_LONG_SECRET_NAME_HERE›"]) {
    const out = shortCommand(c);
    assert.equal((out.match(/‹/g) ?? []).length, (out.match(/›/g) ?? []).length, "no mask is cut in half");
  }
});

test("shortCommand: the first line, cut at a space near 40 characters, with … where something was left out", () => {
  assert.equal(shortCommand("cat .env"), "cat .env");
  assert.equal(shortCommand("cat > deploy.sh <<'EOF' …"), "cat > deploy.sh <<'EOF' …", "no second …");
  assert.equal(shortCommand("set -a\n. ./.env"), "set -a …");
  assert.equal(shortCommand("PGPASSWORD=‹DB_PASSWORD› psql -h db.shop.io -c 'select 1' && curl -H \"Authorization: Bearer …\""), "PGPASSWORD=‹DB_PASSWORD› psql -h …");
  assert.equal(shortCommand("x".repeat(60)), `${"x".repeat(40)} …`);
});

test("renderScan: a send by the secret's variable says so; a host every send failed at is 'tried'; none, no line", () => {
  const src = { path: "~/shop/.env", name: "STRIPE_KEY" };
  const f = finding({ source: src });
  const send = (over: Partial<SendWire>): SendWire => ({ kind: "known", preview: f.preview, source: src, to: "own-service", host: "api.stripe.com", sessions: 1, ran: 1, stoppedByMandu: 0, via: ["curl"], by: ["variable"], agents: ["claude-code"], duringMandu: 0, ...over });
  const out = renderScan(wire({ findings: [f], sends: [send({}), send({ to: "other-host", host: "hooks.vendor.dev", ran: 0 })] }), { all: false });
  assert.match(out, /\n {5}also sent over HTTP to api\.stripe\.com · tried hooks\.vendor\.dev \(through its variable\)\n/);
  const failed = renderScan(wire({ findings: [f], sends: [send({ ran: 0, by: ["value"] })] }), { all: false });
  assert.match(failed, /\n {5}a command tried to send it over HTTP to api\.stripe\.com \(it failed or was refused\)\n/);
  assert.ok(!renderScan(wire({ findings: [f], sends: [] }), { all: false }).includes("over HTTP"));
});

const ex = (over: Partial<ExampleWire>): ExampleWire => ({ at: "2026-10-19T10:00:00Z", agent: "claude-code", how: "command-output", project: "~/project/mandu", mandu: "without", provider: "anthropic", ...over });

test("renderScan --all: each of your secrets as a story: where it lived, what the agent did, that it left and to whom, what Mandu would have done", () => {
  const cred = finding({
    preview: "accessToken in ~/.config/mandu-ci/claude-credential.json", how: { "command-output": 1 },
    examples: [ex({ command: "cat ~/.config/mandu-ci/claude-credential.json", tool: "Bash" })],
  });
  const stripe = finding({
    sessions: 3, first: "2026-10-01T00:00:00Z", projectCount: 2, how: { "read-file": 2, "ai-wrote": 1 }, agents: ["claude-code", "codex"], sentToHosts: ["hooks.vendor.dev"],
    examples: [ex({ at: "2026-10-19T09:00:00Z", agent: "codex", how: "read-file", file: "~/shop/.env", tool: "Read", project: "~/shop", provider: "other" })],
  });
  const out = renderScan(wire({ findings: [cred, stripe] }), { all: true });
  assert.match(out, /\n2 of your secrets leaked to the AI:\n\n {2}1\. accessToken in ~\/\.config\/mandu-ci\/claude-credential\.json\n {5}19 Oct · ~\/project\/mandu · Claude Code\n {7}The agent ran: {2}cat ~\/\.config\/mandu-ci\/claude-credential\.json\n {7}The output, with the secret in it, went to the AI: it left this computer in Claude Code's next request to Anthropic\.\n {5}With Mandu, the AI would have seen a placeholder \(\$MDU:…\) where the secret is in that output; the command itself would still have run\.\n/);
  assert.match(out, /\n {2}2\. STRIPE_KEY in ~\/shop\/\.env\n {5}3 sessions, 1 Oct to 19 Oct, 2 projects \(the agent read the file in 2, the AI wrote it out in 1\)\. The newest:\n {5}19 Oct · ~\/shop · Codex\n {7}The agent read: {2}~\/shop\/\.env\n {7}The file's content, with the secret in it, went to the AI: it left this computer in Codex's next request to the model provider\.\n {7}The AI also wrote it out, in its text or a command \(1 session\)\.\n {7}A command also sent it on over the network, to hooks\.vendor\.dev \(listed below\)\.\n {5}With Mandu, the agent would have read a placeholder/);
  assert.ok(out.endsWith("To see one finding in full (every way it got there, up to 10 examples each): mandu scan --show <n>, n from 1 to 2\n"));
});

test("renderScan --all: what Mandu would have done, by how it got there; a session by time says so instead of 'it left'", () => {
  const story = (e: ExampleWire): string => renderScan(wire({ findings: [finding({ how: { [e.how]: 1 }, examples: [e] })] }), { all: true });
  assert.match(story(ex({ how: "your-message" })), /It was in your message to the agent[^\n]*\n {7}Your message, with the secret in it, left this computer in Claude Code's request to Anthropic\.\n {5}With Mandu, the AI would have received a placeholder \(\$MDU:…\) instead: a secret Mandu holds \(12 characters or longer\) is replaced in what you type\./);
  assert.match(story(ex({ how: "ai-wrote", command: "PGPASSWORD=‹DB_PASSWORD› psql" })), /The AI wrote it into a command: {2}PGPASSWORD=‹DB_PASSWORD› psql\n {7}So the AI had it already, and Claude Code sent it back to Anthropic with each later request of the session\.\n {5}With Mandu, the AI would have known only a placeholder/);
  assert.match(story(ex({ how: "context", file: "~/shop/.env" })), /The agent attached: {2}~\/shop\/\.env\n[^\n]*\n {5}With Mandu, the AI would have seen a placeholder \(\$MDU:…\) instead: a secret Mandu holds is replaced in what the agent attaches too\./);
  assert.match(story(ex({ how: "tool-result", tool: "WebFetch", agent: "codex", provider: "openai" })), /The agent used WebFetch, and it returned it\.\n {7}The result, with the secret in it, went to the AI: it left this computer in Codex's next request to OpenAI\./);
  assert.match(story(ex({ mandu: "by-time", command: "cat .env" })), /The agent ran: {2}cat \.env\n {7}This session ran while Mandu ran Claude Code, so the request may have carried a placeholder instead; the record on disk holds the value\./);
});

test("renderScan --all: a web fetch names the URL it fetched, as the arbiter masked it; the story's next lines as before", () => {
  const story = (e: ExampleWire, over: Partial<FindingWire> = {}): string => renderScan(wire({ findings: [finding({ how: { [e.how]: 1 }, examples: [e], ...over })] }), { all: true });
  assert.match(story(ex({ how: "tool-result", tool: "WebFetch", url: "https://docs.vendor.dev/setup?key=…" })), /\n {7}The agent fetched: {2}https:\/\/docs\.vendor\.dev\/setup\?key=… \(WebFetch\)\n {7}The page it fetched, with the secret in it, went to the AI: it left this computer in Claude Code's next request to Anthropic\.\n/);
  assert.match(story(ex({ how: "ai-wrote", agent: "openclaw", tool: "web_fetch", url: "https://hooks.vendor.dev/in?token=…", provider: "other" }), { agents: ["openclaw"], sentToHosts: ["hooks.vendor.dev"] }),
    /\n {7}The AI wrote it into a web fetch: {2}https:\/\/hooks\.vendor\.dev\/in\?token=… \(web_fetch\)\n {7}So the AI had it already, and OpenClaw sent it back to the model provider with each later request of the session\.\n {7}A command also sent it on over the network, to hooks\.vendor\.dev \(listed below\)\.\n/);
  // --show draws the same line under its way.
  const shown = renderShow(wire({ findings: [finding({ how: { "tool-result": 1 }, examples: [ex({ how: "tool-result", tool: "webfetch", agent: "opencode", url: "https://x.dev/a?sig=…" })] })] }), 1)!;
  assert.match(shown, /\n {7}The agent fetched: {2}https:\/\/x\.dev\/a\?sig=… \(webfetch\)\n/);
});

test("renderScan: key-like values, one line by prefix by default; --all tells the first three as stories, the rest as rows with their examples", () => {
  const rows = Array.from({ length: 5 }, (_, i) => finding({
    kind: "openai-key", preview: "sk-…", sessions: 9 - i, first: "2026-10-01T00:00:00Z", projectCount: 3, how: { "command-output": 9 - i },
    examples: [ex({ command: `node --test test/unit/k${i}.test.ts` }), ex({ at: "2026-10-18T00:00:00Z", command: "npm test" }), ex({ at: "2026-10-17T00:00:00Z", command: "npm run typecheck", mandu: "by-time" })],
  }));
  const compact = renderScan(wire({ findings: rows }), { all: false });
  assert.match(compact, /\n✓ None of your secrets leaked to the AI \(Mandu found 4 on this computer\)\n\n! 5 key-shaped values leaked \(not in your files now: old\n {2}keys, someone else's, or test values\)\n {2}sk-… ×5\n/);
  assert.ok(!compact.includes("node --test"), "no row of them by default");
  const out = renderScan(wire({ findings: rows }), { all: true });
  assert.match(out, /5 more values look like keys and leaked to the AI, but are not in your files now \(an old key, someone else's, or a test value; the project and command tell which\):\n\n {2}1\. sk-…\n {5}9 sessions, 1 Oct to 19 Oct, 3 projects \(a command printed it in 9\)\. The newest:\n {5}19 Oct · ~\/project\/mandu · Claude Code\n {7}The agent ran: {2}node --test test\/unit\/k0\.test\.ts\n {7}The output, with the key in it, went to the AI/);
  assert.match(out, /\n\n {2}4\. sk-…\n {5}6 sessions, 1 Oct to 19 Oct, 3 projects · a command printed it · Claude Code\n {7}19 Oct · ~\/project\/mandu · the agent ran: {2}node --test test\/unit\/k3\.test\.ts\n/);
  assert.match(out, /\nWith Mandu, a key like these is masked when it is in a file or variable Mandu protects; one it does not hold reaches the AI as before\.\n/);
  assert.match(out, / {7}19 Oct · ~\/project\/mandu · the agent ran: {2}node --test test\/unit\/k4\.test\.ts\n {7}18 Oct · ~\/project\/mandu · the agent ran: {2}npm test\n {7}17 Oct · ~\/project\/mandu · the agent ran: {2}npm run typecheck\n/);
});

test("renderScan: sessions under Mandu are a footnote; a finding seen only there is not counted as leaked", () => {
  const leaked = finding({ sessions: 2, duringMandu: 1, sessionsByTime: 1, sessionsUnderMandu: 0 });
  const byTime = finding({ preview: "token in ~/.config/x.yml", duringMandu: 1, sessionsByTime: 1, sessionsUnderMandu: 0 });
  const kept = finding({ preview: "API_KEY in ~/app/.env", duringMandu: 1, sessionsUnderMandu: 1, sessionsByTime: 0 });
  const out = renderScan(wire({ duringMandu: 3, findings: [leaked, byTime, kept] }), { all: false });
  assert.match(out, /\n✗ 2 of your secrets leaked to the AI\n/);
  assert.ok(!out.includes("API_KEY"), "kept from the AI: not listed without --all, never called leaked");
  assert.match(out, /\n {2}2 {2}token in ~\/\.config\/x\.yml\n {5}1 session, 19 Oct · the agent read the file \(only while Mandu ran, by time\)\n/);
  assert.match(out, /\n3 sessions ran while Mandu ran the same agent: there the AI may have seen a placeholder; 1 finding above was seen only there\.\nMandu kept 1 more value from the AI \(only in sessions under Mandu, where the AI saw a placeholder\): mandu scan --all\n/);
  const all = renderScan(wire({ duringMandu: 3, findings: [leaked, byTime, kept] }), { all: true });
  assert.match(all, /\n3 sessions ran while Mandu ran the same agent: there the AI may have seen a placeholder where the record on disk shows the value\. 1 of the findings above was seen only in such sessions\.\n/);
  assert.match(all, /\nMandu kept 1 more value from the AI: it was only in sessions under Mandu, where the AI saw a placeholder:\n {2}3\. API_KEY in ~\/app\/\.env\n/);
  assert.equal(numberedFindings(wire({ findings: [kept, leaked] }))[0], leaked, "the numbers: what reached the AI first, what Mandu kept last");
  // With the exact join's totals, the two kinds of session each get their line.
  const exactShort = renderScan(wire({ duringMandu: 3, sessionsUnderMandu: 1, sessionsByTime: 2, findings: [leaked, byTime, kept] }), { all: false });
  assert.match(exactShort, /\n1 session ran under Mandu: there the AI saw placeholders, not the values\.\n2 sessions ran while Mandu ran \(by time\): there the AI may have seen a placeholder; 1 finding above was seen only there\.\n/);
  const exact = renderScan(wire({ duringMandu: 3, sessionsUnderMandu: 1, sessionsByTime: 2, findings: [leaked, byTime, kept] }), { all: true });
  assert.match(exact, /\n1 session ran under Mandu: there Mandu masked the secrets it holds before the AI saw them, though the record on disk shows the values\.\n2 sessions ran while Mandu ran \(by time\): there the AI may have seen a placeholder where the record on disk shows the value\. 1 of the findings above was seen only in such sessions\.\n/);
});

test("renderShow: one finding in full: sessions, dates, projects, with and without Mandu, every way with up to ten examples", () => {
  const many = Array.from({ length: 12 }, (_, i) => ex({ at: `2026-10-${String(19 - i).padStart(2, "0")}T00:00:00Z`, command: `cat f${i}`, ...(i === 1 ? { mandu: "by-time" as const } : {}) }));
  const f = finding({
    kind: "openai-key", preview: "sk-…", sessions: 39, first: "2026-09-29T00:00:00Z", projects: ["~/project/mandu", "~/x"], projectCount: 4,
    how: { "command-output": 36, "read-file": 5 }, duringMandu: 5, sessionsByTime: 5, sessionsUnderMandu: 0, sentToHosts: ["api.openai.com"],
    examplesByHow: { "command-output": many.slice(0, 10), "read-file": [ex({ how: "read-file", file: "~/project/mandu/tests/fixtures/keys.txt", tool: "Read" })] },
  });
  const out = renderShow(wire({ findings: [finding({}), f] }), 2)!;
  assert.match(out, /^mandu scan: finding 2 of 2\. No secret's value is shown below\.\n\n2\. sk-…: a key-shaped value, leaked to the AI \(in no file now\)\n {3}39 sessions, 29 Sep to 19 Oct, 4 projects: ~\/project\/mandu, ~\/x, … · Claude Code\n {3}34 without Mandu, 5 while Mandu ran \(by time only, so there the AI may have seen a placeholder\)\n/);
  assert.match(out, /\n {3}A command printed it, in 36 sessions; the newest 10:\n {5}19 Oct · ~\/project\/mandu · Claude Code\n {7}The agent ran: {2}cat f0\n {5}18 Oct · ~\/project\/mandu · Claude Code · while Mandu ran \(by time only\)\n {7}The agent ran: {2}cat f1\n/);
  assert.ok(out.includes("cat f9") && !out.includes("cat f10"), "ten examples at most");
  assert.match(out, /\n {3}The agent read the file, in 5 sessions; the newest 1:\n {5}19 Oct · ~\/project\/mandu · Claude Code\n {7}The agent read: {2}~\/project\/mandu\/tests\/fixtures\/keys\.txt\n {5}Each time, the key left this computer in the agent's next request: Claude Code's to Anthropic\.\n/);
  assert.match(out, /\n {3}A command also sent it on over the network, to api\.openai\.com \(listed below\)\.\n/);
  assert.ok(!out.includes("With Mandu ("), "what Mandu would have done is for your own secrets");
  assert.match(renderShow(wire({ findings: [finding({ how: { "read-file": 1 } })] }), 1)!, /\n {3}With Mandu \(the agent read the file\), the agent would have read a placeholder/);
  assert.equal(renderShow(wire({ findings: [f] }), 2), null);
});

test("runScan --show: the finding in full, its JSON with its number, and exit 2 for a number past the end", async () => {
  const deps = {
    arbiter: async () => ({ sock: "/tmp/x.sock", kind: "throwaway" as const, axisOn: true, stop: async () => {} }),
    call: async () => wire({ findings: [finding({ examples: [ex({ how: "read-file", file: "~/shop/.env" })] })] }),
    now: () => NOW,
  };
  const env = { HOME: "/home/u", MANDU_HOME: "/home/u/.mandu" };
  const run = async (args: string[]): Promise<{ code: number; out: string; err: string }> => {
    let out = "";
    let err = "";
    const code = await runScan(args, env, {} as Layout, deps, { out: (s) => { out += s; }, err: (s) => { err += s; } });
    return { code, out, err };
  };
  assert.match((await run(["--show", "1"])).out, /^mandu scan: finding 1 of 1\./);
  assert.deepEqual(JSON.parse((await run(["--show=1", "--json"])).out).number, 1);
  const past = await run(["--show", "2"]);
  assert.equal(past.code, 2);
  assert.match(past.err, /there is no finding 2: the report numbers them 1 to 1/);
  assert.match((parseScanArgs(["--show", "x"], NOW) as { error: string }).error, /--show wants the number of a finding/);
  assert.match((parseScanArgs(["--show", "1", "--share"], NOW) as { error: string }).error, /--share holds counts only/);
});

test("shareText: still counts only when the findings carry examples", () => {
  const s = shareText(wire({ findings: [finding({ examples: [ex({ command: "cat ~/secret-project/.env", file: "~/secret-project/.env" })], sentToHosts: ["hooks.vendor.dev"] })] }));
  for (const leak of ["~/", "cat ", "secret-project", "hooks.vendor.dev", "Claude Code"]) assert.ok(!s.includes(leak), leak);
});

test("renderScan: the agents in a fixed order, whatever order the answer lists them in", () => {
  const out = renderScan(wire({ sessions: { codex: 1, "claude-code": 1 } as ScanWire["sessions"] }), { all: false });
  assert.match(out, /^mandu scan · 2 sessions · Claude Code, Codex · /);
  assert.match(renderScan(wire({ sessions: { codex: 1, "claude-code": 1 } as ScanWire["sessions"] }), { all: true }), /^mandu scan: read 1 Claude Code and 1 Codex sessions on this computer/);
  assert.match(renderScan(wire({ sessions: {} }), { all: false }), /^mandu scan · no agent sessions\n/);
  // Every agent the scan reads, by its name, in the report's order (plan 17 §4).
  const sessions = { openclaw: 4, goose: 3, opencode: 2, codex: 1, "claude-code": 5 } as ScanWire["sessions"];
  assert.match(renderScan(wire({ sessions }), { all: false }), /^mandu scan · 15 sessions · Claude Code, Codex, OpenCode, Goose, OpenClaw · /);
  const all = renderScan(wire({ sessions }), { all: true });
  assert.match(all, /^mandu scan: read 5 Claude Code, 1 Codex, 2 OpenCode, 3 Goose and 4 OpenClaw sessions on this computer/);
  const f = renderScan(wire({ findings: [finding({ agents: ["goose", "openclaw", "opencode"] })] }), { all: true });
  assert.match(f, / · OpenCode, Goose and OpenClaw\n/);
});

test("renderScan: none of yours in green words, key-like values one line, named values one dim line; --all lists every one", () => {
  const shaped = Array.from({ length: 12 }, (_, i) => finding({ kind: "openai-key", preview: "sk-…", sessions: 12 - i }));
  const named = finding({ kind: "credential-assignment", preview: "DB_PASSWORD=…" });
  const out = renderScan(wire({ findings: [...shaped, named] }), { all: false });
  assert.match(out, /\n✓ None of your secrets leaked to the AI \(Mandu found 4 on this computer\)\n/);
  assert.match(out, /\n! 12 key-shaped values leaked \(not in your files now: old\n {2}keys, someone else's, or test values\)\n {2}sk-… ×12\n {2}1 more value named like a secret \(DB_PASSWORD=…, a password in a URL\): mandu scan --all\n/);
  assert.ok(!/\d+\. (sk-|DB_PASSWORD)/.test(out), "no numbered row of them by default");
  assert.match(out, /One in full: {10}mandu scan --show 1/);
  assert.match(renderScan(wire({ known: 0 }), { all: false }), /\n✓ None of your secrets leaked to the AI \(Mandu found none on this computer\)\n/);
  assert.match(renderScan(wire({}), { all: false }), /\n✓ With Mandu, your secrets stay safe: the AI sees only a \$MDU:… placeholder, and your agent still does its work\.\n[^\n]*\n {2}Everything: {11}mandu scan --all\n$/, "nothing found: no promise of what Mandu would have changed, no --show");
  const one = renderScan(wire({ findings: [finding({}), shaped[0]!] }), { all: false });
  assert.match(one, /\n! 1 more key-shaped value leaked \(not in your files now: an old\n {2}key, someone else's, or a test value\)\n/);
  const all = renderScan(wire({ findings: [...shaped, named] }), { all: true });
  assert.match(all, /None of the 4 secrets Mandu found on this computer leaked to the AI in these sessions\./);
  assert.equal(all.split("\n").filter((l) => /^ {2}\d+\. sk-…$/.test(l)).length, 12);
  assert.match(all, /\n {2}13\. DB_PASSWORD=…\n/);
});

test("renderScan: what the caps left unread and the sessions under Mandu are said, never hidden", () => {
  const out = renderScan(wire({ duringMandu: 2, capped: { overTime: 3, overBytes: 1, tooBig: 0, overFiles: 0, readFailed: 2 } }), { all: false });
  assert.match(out, /note: 3 older transcripts not read: the scan's time ran out/);
  assert.match(out, /note: 1 older transcript not read: over the scan's size budget/);
  assert.match(out, /note: 2 transcripts could not be read/);
  assert.match(out, /2 sessions ran while Mandu ran the same agent: there the AI may have seen a placeholder/);
});

test("shareText: counts only, never a path, a mask, a name or a project", () => {
  const r = wire({ findings: [finding({ projects: ["~/secret-project"] }), finding({ kind: "github-token", preview: "ghp_…" }), finding({ kind: "credential-assignment", preview: "DB_PASSWORD=…" })] });
  const s = shareText(r);
  assert.equal(s, "I checked 4 AI agent sessions on my computer with mandu scan: 1 of my secrets had reached the AI, and 1 more value that looks like a key. Check yours (it runs on your computer and sends nothing): npx @mandusec/mandu scan\n");
  for (const leak of ["~/", "STRIPE", "ghp_", "DB_PASSWORD", "secret-project"]) assert.ok(!s.includes(leak), leak);
  assert.match(shareText(wire({})), /none of my current secrets had reached the AI\. Check yours/);
});

test("runScan: exit 0 with the report, 1 when the scan cannot run, 2 on a bad option; the arbiter always stopped", async () => {
  let stopped = 0;
  let asked: Record<string, unknown> | null = null;
  const deps = {
    arbiter: async () => ({ sock: "/tmp/x.sock", kind: "throwaway" as const, axisOn: true, stop: async () => { stopped++; } }),
    call: async (_s: string, req: Record<string, unknown>) => { asked = req; return wire({}); },
    now: () => NOW,
  };
  const io = { out: () => {}, err: () => {} };
  const env = { HOME: "/home/u", MANDU_HOME: "/home/u/.mandu" };
  assert.equal(await runScan(["--since", "7d"], env, {} as Layout, deps, io), 0);
  assert.deepEqual(asked, { home: "/home/u", eventsDir: "/home/u/.mandu/events", since: NOW - 7 * 86_400_000 });
  assert.equal(await runScan([], env, {} as Layout, { ...deps, call: async () => { throw new Error("socket closed"); } }, io), 1);
  assert.equal(stopped, 2);
  assert.equal(await runScan(["--bogus"], env, {} as Layout, deps, io), 2);
  assert.equal(stopped, 2, "a bad option starts no arbiter");
});

// ── The report's last line: where to see it in the dashboard (plan 17 §3
// item 12; dashboard.md §4.25ai) ─────────────────────────────────────────

test("ranThroughNpx: npm exec's own variables, for the command npx ran; a mandu under some other npx command is not", () => {
  // What npm 9 sets for `npx @mandusec/mandu scan` (and `npm exec`).
  assert.equal(ranThroughNpx({ npm_command: "exec", npm_lifecycle_event: "npx", npm_lifecycle_script: "mandu" }), true);
  assert.equal(ranThroughNpx({ npm_command: "exec", npm_lifecycle_event: "npx", npm_lifecycle_script: "/home/u/.npm/_npx/ab12/node_modules/.bin/mandu" }), true);
  assert.equal(ranThroughNpx({ npm_lifecycle_event: "npx", npm_lifecycle_script: "@mandusec/mandu" }), true);
  assert.equal(ranThroughNpx({ npm_command: "exec" }), true, "an npm that names no command: npx");
  // Not npx: a plain shell, an npm script, and a mandu started by another
  // command npx ran (a checkout's `npx tsx src/run.ts`, a shell).
  assert.equal(ranThroughNpx({}), false);
  assert.equal(ranThroughNpx({ npm_command: "run-script", npm_lifecycle_event: "start", npm_lifecycle_script: "tsx src/run.ts" }), false);
  assert.equal(ranThroughNpx({ npm_command: "exec", npm_lifecycle_event: "npx", npm_lifecycle_script: "tsx" }), false);
  assert.equal(ranThroughNpx({ npm_command: "exec", npm_lifecycle_event: "npx", npm_lifecycle_script: "bash -c x" }), false);
  assert.equal(manduCommand({ npm_command: "exec", npm_lifecycle_script: "mandu" }, "dashboard"), "npx @mandusec/mandu dashboard");
  assert.equal(manduCommand({}, "dashboard"), "mandu dashboard");
});

test("dashboardLine: a running dashboard's Scan page under its base path; none, the command that opens one, as it was typed", () => {
  assert.equal(dashboardLine({}, [{ host: "127.0.0.1", port: 40123, basePath: "" }]), "This report is in your dashboard too: http://127.0.0.1:40123/scan");
  // An entry from before base paths were recorded was served under /mandu;
  // a wildcard bind is reached on loopback; the newest dashboard first.
  assert.equal(dashboardLine({}, [{ host: "0.0.0.0", port: 4500 }, { host: "127.0.0.1", port: 1 }]), "This report is in your dashboard too: http://127.0.0.1:4500/mandu/scan");
  assert.equal(dashboardLine({}, [{ host: "127.0.0.1", port: 4500, basePath: "/m/" }]), "This report is in your dashboard too: http://127.0.0.1:4500/m/scan");
  assert.equal(dashboardLine({}, []), "This report is kept for your dashboard: run mandu dashboard and open Scan.");
  assert.equal(dashboardLine({ npm_command: "exec", npm_lifecycle_event: "npx", npm_lifecycle_script: "mandu" }, []), "This report is kept for your dashboard: run npx @mandusec/mandu dashboard and open Scan.");
});

test("dashboardWhere: the compact report's Dashboard row, the words dashboardLine ends with", () => {
  assert.equal(dashboardWhere({}, [{ host: "127.0.0.1", port: 4500, basePath: "", passwordFirst: true }]), "http://127.0.0.1:4500/scan (sign in with its password)");
  // The dashboard account (registry signInMode `account`): the launch line's words.
  assert.equal(dashboardWhere({}, [{ host: "127.0.0.1", port: 4500, basePath: "", passwordFirst: true, signInWith: "account" }]), "http://127.0.0.1:4500/scan (sign in with your Mandu dashboard account)");
  assert.equal(dashboardWhere({}, [{ host: "127.0.0.1", port: 4500, basePath: "", passwordFirst: true, signInWith: "basic" }]), "http://127.0.0.1:4500/scan (sign in with its username and password)");
  assert.equal(dashboardWhere({}, [{ host: "127.0.0.1", port: 4500, basePath: "", passwordFirst: true, signInWith: "no-account" }]), "http://127.0.0.1:4500/scan (no account yet; set one: mandu dashboard --set-password)");
  assert.equal(dashboardWhere({}, [{ host: "127.0.0.1", port: 4500, basePath: "" }]), "http://127.0.0.1:4500/scan");
  assert.equal(dashboardWhere({}, []), "run mandu dashboard and open Scan");
});

test("dashboardLine: a dashboard that asks for its password before any page says so (the maintainer, 2026-10-22: the bare URL answered Unauthorized)", () => {
  assert.equal(
    dashboardLine({}, [{ host: "127.0.0.1", port: 4500, basePath: "", passwordFirst: true }]),
    "This report is in your dashboard too: http://127.0.0.1:4500/scan (sign in with its password)",
  );
  // A dashboard on one-time links serves its pages: the bare URL opens.
  assert.equal(dashboardLine({}, [{ host: "127.0.0.1", port: 4500, basePath: "" }]), "This report is in your dashboard too: http://127.0.0.1:4500/scan");
});

test("runScan: the dashboard line ends the report and --show, never --json or --share, and only for a report kept", async () => {
  const kept: string[] = [];
  const keep = { resident: async () => null, suggest: async () => ({}), write: (p: string) => { kept.push(p); } };
  let dashboards: { host: string; port: number; basePath?: string }[] = [];
  const deps = {
    arbiter: async () => ({ sock: "/tmp/x.sock", kind: "throwaway" as const, axisOn: true, stop: async () => {} }),
    call: async () => wire({ findings: [finding({})] }),
    now: () => NOW,
    keep,
    dashboards: () => dashboards,
  };
  const env: Record<string, string> = { HOME: "/home/u", MANDU_HOME: "/home/u/.mandu" };
  const run = async (args: string[], over: Record<string, unknown> = {}, e: Record<string, string> = env): Promise<string> => {
    let out = "";
    assert.equal(await runScan(args, e, {} as Layout, { ...deps, ...over } as typeof deps, { out: (s) => { out += s; }, err: () => {} }), 0);
    return out;
  };
  const last = (s: string): string => s.trimEnd().split("\n").pop()!;
  // The compact report's last row; --all and --show end with the sentence.
  assert.equal(last(await run([])), "  Dashboard:            run mandu dashboard and open Scan");
  assert.equal(last(await run(["--all"])), "This report is kept for your dashboard: run mandu dashboard and open Scan.");
  assert.equal(last(await run([], {}, { ...env, npm_command: "exec", npm_lifecycle_event: "npx", npm_lifecycle_script: "mandu" })), "  Dashboard:            run npx @mandusec/mandu dashboard and open Scan");
  assert.equal(last(await run(["--all"], {}, { ...env, npm_command: "exec", npm_lifecycle_event: "npx", npm_lifecycle_script: "mandu" })), "This report is kept for your dashboard: run npx @mandusec/mandu dashboard and open Scan.");
  dashboards = [{ host: "127.0.0.1", port: 40123, basePath: "" }];
  assert.equal(last(await run([])), "  Dashboard:            http://127.0.0.1:40123/scan");
  assert.equal(last(await run(["--all"])), "This report is in your dashboard too: http://127.0.0.1:40123/scan");
  assert.equal(last(await run(["--show", "1"])), "This report is in your dashboard too: http://127.0.0.1:40123/scan");
  assert.ok(!(await run(["--json"])).includes("This report"), "--json is the answer alone");
  assert.ok(!(await run(["--show", "1", "--json"])).includes("This report"));
  assert.ok(!(await run(["--share"])).includes("This report"), "--share is a text to post");
  // Not kept (a write that failed, or no keeping at all): no line.
  for (const over of [{ keep: { ...keep, write: () => { throw new Error("read-only"); } } }, { keep: undefined }]) {
    assert.ok(!(await run([], over)).includes("Dashboard:"));
    assert.ok(!(await run(["--all"], over)).includes("This report"));
  }
  // A registry that cannot be read: the command, never a failed scan.
  assert.match(last(await run(["--all"], { dashboards: () => { throw new Error("EACCES"); } })), /run mandu dashboard and open Scan\.$/);
  assert.match(last(await run([], { dashboards: () => { throw new Error("EACCES"); } })), /Dashboard: +run mandu dashboard and open Scan$/);
  assert.ok(kept.length > 0);
});

test("scanCallTimeoutMs: the scan's own deadline plus a minute", () => {
  assert.equal(scanCallTimeoutMs({}), 360_000);
  assert.equal(scanCallTimeoutMs({ MANDU_TRANSCRIPT_SCAN_TIMEOUT_S: "60" }), 120_000);
});

test("renderScan: the riskier sessions, one line each, and none when there are none or the arbiter is older", () => {
  const out = renderScan(wire({ risk: { skippedPrompts: 371, skippedWithSecret: 2, envDumps: 8 } }), { all: false });
  assert.match(out, /\n! Risky sessions\n {2}371 ran with permission prompts off \(in 2, one of your secrets leaked\)\n {2}8 printed your whole environment to the AI\n/);
  const long = renderScan(wire({ risk: { skippedPrompts: 371, skippedWithSecret: 2, envDumps: 8 } }), { all: true });
  assert.match(long, /\nRiskier sessions:\n {2}371 sessions ran with the agent's permission prompts off: every command ran without asking you \(in 2 of them one of your secrets leaked to the AI\)\.\n {2}8 sessions printed your whole environment to the AI/);
  assert.match(renderScan(wire({ risk: { skippedPrompts: 1, skippedWithSecret: 0, envDumps: 0 } }), { all: true }), /\n {2}1 session ran with the agent's permission prompts off: every command ran without asking you\.\n/);
  for (const all of [false, true]) {
    assert.ok(!/Risk/.test(renderScan(wire({ risk: { skippedPrompts: 0, skippedWithSecret: 0, envDumps: 0 } }), { all })));
    assert.ok(!/Risk/.test(renderScan(wire({}), { all })));
  }
});

test("renderScan --all: the sends, hosts the scan cannot tie to the key first, with how each ran; one line when there are none", () => {
  const send = (over: Partial<SendWire>): SendWire => ({ kind: "known", preview: "STRIPE_KEY in ~/shop/.env", to: "own-service", host: "api.stripe.com", sessions: 1, ran: 1, stoppedByMandu: 0, via: ["curl"], by: ["variable"], agents: ["claude-code"], last: "2026-10-19T10:00:00Z", duringMandu: 0, ...over });
  const out = renderScan(wire({ sends: [
    send({ to: "other-host", host: "hooks.vendor.dev", by: ["value"], sessions: 2, ran: 1 }),
    send({ agents: ["claude-code", "codex"], sessions: 2, stoppedByMandu: 1, duringMandu: 1, ran: 1 }),
    send({ kind: "github-token", preview: "ghp_…", host: "api.github.com", ran: 0, by: ["value"] }),
  ] }), { all: true });
  assert.match(out, /\nSecrets the agents sent on \(curl, wget, HTTPie, xh, a web fetch; ssh, scp, sftp, rsync; git with a credential in its URL; a python, node, ruby or perl one-liner's HTTP call; an MCP tool's input\):\n\n {2}To a host Mandu cannot tie to the key's own service \(worth a look\):\n {4}STRIPE_KEY in ~\/shop\/\.env → hooks\.vendor\.dev\n {8}2 sessions, last 19 Oct · curl · the AI wrote the value into the command · Claude Code · 1 failed or refused\n\n {2}To the key's own service:\n/);
  assert.match(out, / {4}STRIPE_KEY in ~\/shop\/\.env → api\.stripe\.com\n {8}2 sessions, last 19 Oct · curl · the command used its variable, so the AI saw only the name · Claude Code and Codex · 1 failed or refused · 1 stopped by Mandu · 1 while Mandu ran\n/);
  assert.match(out, / {4}ghp_… → api\.github\.com\n {8}1 session, 19 Oct · curl · the AI wrote the value into the command · Claude Code · it failed or was refused\n/);
  assert.ok(out.indexOf("hooks.vendor.dev") < out.indexOf("api.stripe.com"));
  assert.match(renderScan(wire({ sends: [] }), { all: true }), /\nNo command or tool sent one of these secrets on in these sessions \(curl, wget/);
  assert.ok(!renderScan(wire({}), { all: true }).includes("over HTTP"), "an older arbiter's answer says nothing about sends");
  assert.ok(!renderScan(wire({ sends: [] }), { all: false }).includes("over HTTP"), "the compact report has no sends section");
});

test("renderScan --all and renderShow: a send names the URLs at its host as the arbiter masked them, under the host, and --show lists the finding's sends", () => {
  const stripe = { path: "~/shop/.env", name: "STRIPE_KEY" };
  const send = (over: Partial<SendWire>): SendWire => ({ kind: "known", preview: "STRIPE_KEY in ~/shop/.env", to: "other-host", host: "hooks.vendor.dev", sessions: 1, ran: 1, stoppedByMandu: 0, via: ["curl"], by: ["variable"], agents: ["claude-code"], last: "2026-10-19T10:00:00Z", duringMandu: 0, ...over });
  const urls = ["https://hooks.vendor.dev/in/v2?k=$STRIPE_KEY", "https://…@hooks.vendor.dev/up?src=…"];
  const r = wire({
    findings: [finding({ kind: "known", preview: "STRIPE_KEY in ~/shop/.env", source: { path: "~/shop/.env", name: "STRIPE_KEY" }, sentToHosts: ["hooks.vendor.dev"] }), finding({ kind: "github-token", preview: "ghp_…" })],
    sends: [send({ source: stripe, urls }), send({ kind: "github-token", preview: "ghp_…", host: "api.github.com", to: "own-service" }), send({ preview: "OTHER in ~/x/.env", source: { path: "~/x/.env", name: "OTHER" } })],
  });
  const out = renderScan(r, { all: true });
  assert.ok(out.includes("    STRIPE_KEY in ~/shop/.env → hooks.vendor.dev\n        https://hooks.vendor.dev/in/v2?k=$STRIPE_KEY\n        https://…@hooks.vendor.dev/up?src=…\n        1 session, 19 Oct · curl"), out);
  assert.ok(out.includes("    ghp_… → api.github.com\n        1 session"), "an older arbiter's send, with no URLs, reads as before");
  const shown = renderShow(r, 1)!;
  assert.ok(shown.includes("   Sent on over HTTP, by host, with the URLs (their query values and credentials masked):\n     STRIPE_KEY in ~/shop/.env → hooks.vendor.dev\n         https://hooks.vendor.dev/in/v2?k=$STRIPE_KEY\n         https://…@hooks.vendor.dev/up?src=…\n         1 session, 19 Oct"), shown);
  assert.ok(!shown.includes("OTHER in") && !shown.includes("api.github.com"), "only this finding's sends");
  const ghShown = renderShow(r, 2)!;
  assert.ok(ghShown.includes("     ghp_… → api.github.com\n"), "a mask's sends by its mask");
  assert.ok(!renderShow(wire({ findings: [finding({})] }), 1)!.includes("Sent on over HTTP"), "no sends, no section");
});

test("renderScan: an agent Mandu does not run (plan 17 §4 phase 3): its story says so, and the closing names the agents Mandu runs", () => {
  const gem = finding({
    preview: "STRIPE_KEY in ~/shop/.env", agents: ["gemini"], how: { "command-output": 1 },
    examples: [ex({ agent: "gemini", command: "cat .env", tool: "run_shell_command", project: "~/shop", provider: "google" })],
  });
  const short = renderScan(wire({ sessions: { gemini: 2, copilot: 1 }, findings: [gem], notRead: { cursor: 4 } }), { all: false });
  assert.match(short, /^mandu scan · 3 sessions · Gemini CLI, Copilot CLI · [^\n]*\nNothing was sent anywhere; no secret value is shown\.\n {2}note: 4 Cursor chats not read: /);
  assert.match(short, /\nMandu does not run Gemini CLI and Copilot CLI yet; the agents it runs: mandu claude, mandu codex, [^\n]*mandu goose\.\n/);
  assert.ok(!short.includes("With Mandu") && !short.includes("Protect your agents"), "only agents Mandu does not run were read: no promise for them");
  assert.match(renderScan(wire({ sessions: { "claude-code": 3, copilot: 1 } }), { all: false }), /Mandu does not run Copilot CLI yet[^\n]*\n\n✓ With Mandu, your secrets stay safe[^\n]*\n {2}Protect your agents:/);
  const out = renderScan(wire({ sessions: { gemini: 2, copilot: 1 }, findings: [gem], notRead: { cursor: 4 } }), { all: true });
  assert.match(out, /^mandu scan: read 2 Gemini CLI and 1 Copilot CLI sessions on this computer/);
  assert.match(out, /\n {2}note: 4 Cursor chats not read: Mandu cannot read its chat store reliably yet/);
  assert.match(out, /\n {5}19 Oct · ~\/shop · Gemini CLI\n {7}The agent ran: {2}cat \.env\n {7}The output, with the secret in it, went to the AI: it left this computer in Gemini CLI's next request to Google\.\n {5}Mandu does not run Gemini CLI yet, so there it could not have kept the secret from the AI\.\n/);
  assert.ok(!/With Mandu, (this secret stays|these \d+ secrets stay) safe/.test(out), "no 'with Mandu' for an agent Mandu does not run");
  assert.match(out, /\nMandu does not run Gemini CLI and Copilot CLI yet; the agents it runs: mandu claude, mandu codex, [^\n]*mandu goose\.\n/);
  assert.ok(!out.includes("To keep your secrets from the AI from now on: mandu claude"), "only agents Mandu does not run were read: no promise for them");
  const both = renderScan(wire({ sessions: { "claude-code": 3, copilot: 1 } }), { all: true });
  assert.match(both, /Mandu does not run Copilot CLI yet; the agents it runs: mandu claude/);
  assert.match(both, /To keep your secrets from the AI from now on: mandu claude \(or mandu codex\)\./);
  for (const all of [false, true]) assert.ok(!renderScan(wire({}), { all }).includes("does not run"), "nothing said when only agents Mandu runs were read");
  const shown = renderShow(wire({ sessions: { gemini: 1 }, findings: [gem] }), 1)!;
  assert.match(shown, /Mandu does not run Gemini CLI yet: there it could not have kept the secret from the AI \(the agents it runs: mandu claude/);
  assert.ok(!shown.includes("With Mandu ("), "no 'with Mandu' for a finding only in agents Mandu does not run");
  assert.match(renderScan(wire({ findings: [finding({ agents: ["copilot"], examples: [ex({ agent: "copilot", provider: "github" })] })] }), { all: true }), /Copilot CLI's next request to GitHub\./);
});

// ── Colours and words per output (the maintainer, 2026-10-22: "leaked" in
// the terminal report only; colour only where it can be seen) ─────────────

test("colorOn: a terminal without NO_COLOR or TERM=dumb; FORCE_COLOR forces it (0 and false do not); a pipe never otherwise", () => {
  assert.equal(colorOn(true, {}), true);
  assert.equal(colorOn(false, {}), false, "a pipe");
  assert.equal(colorOn(true, { NO_COLOR: "1" }), false);
  assert.equal(colorOn(true, { NO_COLOR: "" }), true, "an empty NO_COLOR is unset (no-color.org)");
  assert.equal(colorOn(true, { TERM: "dumb" }), false);
  assert.equal(colorOn(false, { FORCE_COLOR: "1" }), true);
  assert.equal(colorOn(false, { FORCE_COLOR: "3", NO_COLOR: "1", TERM: "dumb" }), true, "FORCE_COLOR ahead of NO_COLOR, as Node reads it");
  assert.equal(colorOn(true, { FORCE_COLOR: "0" }), false);
  assert.equal(colorOn(true, { FORCE_COLOR: "false" }), false);
  assert.equal(colorOn(false, { FORCE_COLOR: "" }), false);
  assert.equal(colors(true), ANSI);
  assert.equal(colors(false), PLAIN);
});

test("renderScan and renderShow: the colours (red the leaked secrets, yellow the warnings, dim the files, cyan the commands, bold the headline), and the same text without them", () => {
  const src = { path: "~/shop/.env", name: "STRIPE_KEY" };
  const r = wire({
    findings: [finding({ source: src, sentToHosts: ["hooks.vendor.dev"] }), finding({ kind: "openai-key", preview: "sk-…" })],
    risk: { skippedPrompts: 1, skippedWithSecret: 0, envDumps: 0 },
  });
  const plain = renderScan(r, { all: false });
  const colored = renderScan(r, { all: false, style: ANSI });
  assert.ok(!plain.includes("\x1b"));
  assert.equal(stripAnsi(colored), plain, "the colours add nothing but colour");
  assert.ok(colored.includes("\x1b[1m\x1b[31m✗ 1 of your secrets leaked to the AI\x1b[39m\x1b[22m"));
  assert.ok(colored.includes("  \x1b[31m1\x1b[39m  STRIPE_KEY   \x1b[2m~/shop/.env\x1b[22m"));
  assert.ok(colored.includes("\x1b[33malso sent over HTTP to hooks.vendor.dev\x1b[39m"));
  assert.ok(colored.includes("\x1b[33m! 1 more key-shaped value leaked\x1b[39m"));
  assert.ok(colored.includes("\x1b[33m! Risky sessions\x1b[39m"));
  assert.ok(colored.includes("\x1b[36mmandu claude\x1b[39m"));
  assert.ok(renderScan(wire({}), { all: false, style: ANSI }).includes("\x1b[1m\x1b[32m✓ None of your secrets leaked to the AI\x1b[39m\x1b[22m"));
  const long = renderScan(r, { all: true, style: ANSI });
  assert.equal(stripAnsi(long), renderScan(r, { all: true }));
  assert.ok(long.includes("\x1b[31m1. of your") === false && long.includes("\x1b[1m\x1b[31m1 of your secrets leaked to the AI:"));
  const shown = renderShow(r, 1, ANSI)!;
  assert.equal(stripAnsi(shown), renderShow(r, 1));
  assert.ok(shown.includes("\x1b[31mone of your secrets, leaked to the AI (still where it was found)\x1b[39m"));
});

test("runScan: colour on a terminal only, never with NO_COLOR, --json or --share, forced by FORCE_COLOR; 'leaked' in the report and --show, 'reached' in --share and --json", async () => {
  const r = wire({ findings: [finding({ examples: [ex({ how: "read-file", file: "~/shop/.env" })] })] });
  const run = async (args: string[], tty: boolean, env: Record<string, string> = {}): Promise<string> => {
    let out = "";
    const deps = {
      arbiter: async () => ({ sock: "/tmp/x.sock", kind: "throwaway" as const, axisOn: true, stop: async () => {} }),
      call: async () => r, now: () => NOW, isTTY: () => tty,
    };
    assert.equal(await runScan(args, { HOME: "/home/u", MANDU_HOME: "/home/u/.mandu", ...env }, {} as Layout, deps, { out: (s) => { out += s; }, err: () => {} }), 0);
    return out;
  };
  const sgr = /\x1b\[/;
  assert.match(await run([], true), sgr, "a terminal");
  assert.doesNotMatch(await run([], false), sgr, "a pipe");
  assert.doesNotMatch(await run([], true, { NO_COLOR: "1" }), sgr);
  assert.doesNotMatch(await run([], true, { TERM: "dumb" }), sgr);
  assert.match(await run([], false, { FORCE_COLOR: "1" }), sgr, "forced, piped");
  assert.match(await run(["--all"], true), sgr);
  assert.match(await run(["--show", "1"], true), sgr);
  for (const args of [["--json"], ["--share"], ["--show", "1", "--json"]]) assert.doesNotMatch(await run(args, true, { FORCE_COLOR: "1" }), sgr, args.join(" "));
  // The words per output.
  assert.match(await run([], false), /✗ 1 of your secrets leaked to the AI\n/);
  assert.match(await run(["--show", "1"], false), /: one of your secrets, leaked to the AI \(still where it was found\)\n/);
  const share = await run(["--share"], false);
  assert.match(share, /1 of my secrets had reached the AI/);
  assert.doesNotMatch(share, /leaked/);
  assert.doesNotMatch(await run(["--json"], false), /leaked/);
});

// ── `mandu scan --open` (plan 17 §3 item 12, the maintainer 2026-10-22):
// after the report, this user's dashboard (started if none runs) and its
// Scan page opened in the browser ─────────────────────────────────────────

test("parseScanArgs --open: with the report, --all and --show; refused with --json and --share, outputs for a program and for pasting", () => {
  assert.deepEqual(parseScanArgs(["--open"], NOW), { json: false, share: false, all: false, open: true });
  assert.deepEqual(parseScanArgs(["--all", "--open"], NOW), { json: false, share: false, all: true, open: true });
  assert.deepEqual(parseScanArgs(["--show", "2", "--open"], NOW), { json: false, share: false, all: false, show: 2, open: true });
  assert.equal((parseScanArgs(["--open", "--json"], NOW) as { error: string }).error, "--open opens the dashboard for you to read: it does not go with --json, the answer for a program");
  assert.equal((parseScanArgs(["--share", "--open"], NOW) as { error: string }).error, "--open opens the dashboard for you to read: it does not go with --share, the text to post");
  assert.match((parseScanArgs(["--show", "1", "--json", "--open"], NOW) as { error: string }).error, /does not go with --json/);
});

test("runScan --open: reuses a live dashboard or starts one, opens the plain Scan URL once, after the report and the arbiter's stop; the exit code never changes", async () => {
  const events: string[] = [];
  type D = { host: string; port: number; basePath?: string; passwordFirst?: boolean };
  type Outcome = import("../../src/browser-open.js").OpenOutcome;
  const base = {
    arbiter: async () => ({ sock: "/tmp/x.sock", kind: "throwaway" as const, axisOn: true, stop: async () => { events.push("arbiter stopped"); } }),
    call: async () => wire({ findings: [finding({})] }),
    now: () => NOW,
  };
  const env: Record<string, string> = { HOME: "/home/u", MANDU_HOME: "/home/u/.mandu" };
  const run = async (args: string[], dash: { d: D; started: boolean } | null | (() => never), outcome: Outcome | (() => never)) => {
    events.length = 0;
    const opened: string[] = [];
    let out = "";
    let err = "";
    const deps = {
      ...base,
      openDashboard: async () => { events.push("dashboard"); return typeof dash === "function" ? dash() : dash; },
      browse: async (url: string) => { events.push("browse"); opened.push(url); return typeof outcome === "function" ? outcome() : outcome; },
    };
    const code = await runScan(args, env, {} as Layout, deps, { out: (s) => { out += s; events.push("out"); }, err: (s) => { err += s; } });
    return { code, out, err, opened, lines: out.trimEnd().split("\n") };
  };
  const live = { d: { host: "127.0.0.1", port: 40123, basePath: "" }, started: false };
  const fresh = { d: { host: "127.0.0.1", port: 40555, basePath: "" }, started: true };

  // A live dashboard: reused, its Scan page opened.
  const a = await run(["--open"], live, { kind: "opened", cmd: "xdg-open" });
  assert.equal(a.code, 0);
  assert.deepEqual(a.opened, ["http://127.0.0.1:40123/scan"], "once, the plain URL");
  assert.equal(a.lines.at(-1), "Opened the dashboard's Scan page: http://127.0.0.1:40123/scan");
  const firstOpen = events.indexOf("dashboard");
  assert.ok(events.indexOf("arbiter stopped") < firstOpen && events.slice(0, firstOpen).includes("out"), `the report and the stop come first: ${events.join(", ")}`);

  // None live: one started, and the line says so.
  const b = await run(["--open"], fresh, { kind: "opened", cmd: "xdg-open" });
  assert.deepEqual(b.opened, ["http://127.0.0.1:40555/scan"]);
  assert.equal(b.lines.at(-1), "Started the dashboard and opened its Scan page: http://127.0.0.1:40555/scan");

  // --all and --show end with it too.
  assert.equal((await run(["--all", "--open"], live, { kind: "opened", cmd: "open" })).lines.at(-1), "Opened the dashboard's Scan page: http://127.0.0.1:40123/scan");
  const shown = await run(["--show", "1", "--open"], live, { kind: "opened", cmd: "open" });
  assert.match(shown.out, /^mandu scan: finding 1 of 1\./);
  assert.equal(shown.lines.at(-1), "Opened the dashboard's Scan page: http://127.0.0.1:40123/scan");
  // A --show past the end: exit 2 and nothing opened.
  const past = await run(["--show", "9", "--open"], live, { kind: "opened", cmd: "open" });
  assert.equal(past.code, 2);
  assert.deepEqual(past.opened, []);
  assert.ok(!events.includes("dashboard"));

  // A dashboard that asks for its password: the browser still gets the
  // plain URL (it shows the sign-in page); the line says to sign in.
  const pw = await run(["--open"], { d: { ...live.d, passwordFirst: true }, started: false }, { kind: "opened", cmd: "open" });
  assert.deepEqual(pw.opened, ["http://127.0.0.1:40123/scan"]);
  assert.equal(pw.lines.at(-1), "Opened the dashboard's Scan page: http://127.0.0.1:40123/scan (sign in with its password)");
  const acct = await run(["--open"], { d: { ...fresh.d, passwordFirst: true, signInWith: "account" } as D, started: true }, { kind: "opened", cmd: "open" });
  assert.deepEqual(acct.opened, ["http://127.0.0.1:40555/scan"], "the account's sign-in page, never its credentials, in the URL");
  assert.equal(acct.lines.at(-1), "Started the dashboard and opened its Scan page: http://127.0.0.1:40555/scan (sign in with your Mandu dashboard account)");

  // No browser here: the URL and the one line; over SSH, the tunnel (no real host).
  const local = await run(["--open"], fresh, { kind: "no-browser", ssh: false });
  assert.deepEqual(local.lines.slice(-2), ["Started the dashboard; its Scan page: http://127.0.0.1:40555/scan", "No browser here: open this URL on your computer"]);
  const ssh = await run(["--open"], live, { kind: "no-browser", ssh: true });
  assert.deepEqual(ssh.lines.slice(-3), [
    "The dashboard's Scan page: http://127.0.0.1:40123/scan",
    "No browser here: open this URL on your computer",
    "Over SSH, forward its port first: ssh -L 40123:127.0.0.1:40123 <this machine>",
  ]);
  assert.equal(ssh.code, 0);
  // A dashboard bound to another address is reached there: no tunnel line.
  const lan = await run(["--open"], { d: { host: "10.0.0.5", port: 4500, basePath: "" }, started: false }, { kind: "no-browser", ssh: true });
  assert.equal(lan.lines.at(-1), "No browser here: open this URL on your computer");

  // The browser would not start (or threw): the URL printed instead, exit 0.
  const failed = await run(["--open"], live, { kind: "failed", cmd: "xdg-open", why: "spawn xdg-open ENOENT" });
  assert.equal(failed.code, 0);
  assert.equal(failed.lines.at(-1), "The dashboard's Scan page: http://127.0.0.1:40123/scan");
  assert.ok(failed.err.endsWith("\nmandu scan: could not open a browser (xdg-open: spawn xdg-open ENOENT): open the URL above yourself\n"), failed.err);
  const threw = await run(["--open"], live, () => { throw new Error("EPERM"); });
  assert.equal(threw.code, 0);
  assert.equal(threw.lines.at(-1), "The dashboard's Scan page: http://127.0.0.1:40123/scan");
  assert.match(threw.err, /could not open a browser \(the browser: EPERM\)/);

  // No dashboard could start: said, nothing opened, exit 0.
  const none = await run(["--open"], null, { kind: "opened", cmd: "open" });
  assert.equal(none.code, 0);
  assert.deepEqual(none.opened, []);
  assert.ok(none.err.endsWith("\nmandu scan: --open: the dashboard did not start, so nothing was opened (mandu dashboard to try again)\n"), none.err);
  const boom = await run(["--open"], () => { throw new Error("registry unreadable"); }, { kind: "opened", cmd: "open" });
  assert.equal(boom.code, 0);
  assert.match(boom.err, /\nmandu scan: --open: registry unreadable\n/);

  // Without --open: no dashboard asked for, no browser.
  const plain = await run([], live, { kind: "opened", cmd: "open" });
  assert.deepEqual(plain.opened, []);
  assert.ok(!events.includes("dashboard"));
  // The scan failed: exit 1, nothing opened.
  const deps = { ...base, call: async () => { throw new Error("socket closed"); }, openDashboard: async () => { throw new Error("must not be asked"); } };
  assert.equal(await runScan(["--open"], env, {} as Layout, deps, { out: () => {}, err: () => {} }), 1);
});

test("the sends over ssh, git, a script and to an MCP tool: the compact line per way, --all's MCP group, --show's header", () => {
  const f = finding({ kind: "known", preview: "STRIPE_KEY in ~/shop/.env", source: { path: "~/shop/.env", name: "STRIPE_KEY" } });
  const send = (over: Partial<SendWire>): SendWire => ({ kind: "known", preview: "STRIPE_KEY in ~/shop/.env", source: { path: "~/shop/.env", name: "STRIPE_KEY" }, to: "other-host", host: "prod", sessions: 1, ran: 1, stoppedByMandu: 0, via: ["ssh"], channel: "ssh", by: ["value"], agents: ["claude-code"], last: "2026-10-19T10:00:00Z", duringMandu: 0, ...over });
  const sends = [
    send({ host: "api.stripe.com", to: "own-service", via: ["curl"], channel: "http" }),
    send({}),
    send({ host: "git.vendor.dev", via: ["git push"], channel: "git", ran: 0 }),
    send({ host: "mcp__notes__save", via: ["MCP"], channel: "mcp" }),
  ];
  const compact = renderScan(wire({ findings: [f], sends }), { all: false });
  assert.match(compact, /\n {5}also sent over HTTP to api\.stripe\.com · over ssh to prod · to an MCP server's tool mcp__notes__save · tried with git to git\.vendor\.dev\n/);
  const long = renderScan(wire({ findings: [f], sends }), { all: true });
  assert.match(long, /\n {2}To a host Mandu cannot tie to the key's own service \(worth a look\):\n {4}STRIPE_KEY in ~\/shop\/\.env → prod\n {8}1 session, 19 Oct · ssh · /);
  assert.match(long, /\n {2}To an MCP server's tool \(worth a look: the server may run here or elsewhere, and Mandu cannot see where it sent it\):\n {4}STRIPE_KEY in ~\/shop\/\.env → an MCP server's tool mcp__notes__save\n {8}1 session, 19 Oct · MCP · /);
  assert.ok(long.indexOf("→ git.vendor.dev") < long.indexOf("To an MCP server's tool"), "the hosts first, then the MCP tools, then the keys' own services");
  assert.ok(long.indexOf("To an MCP server's tool") < long.indexOf("To the key's own service"));
  const shown = renderShow(wire({ findings: [f], sends }), 1)!;
  assert.ok(shown.includes("   Sent on, by where it went (a host, or an MCP server's tool), with the URLs (their query values and credentials masked):\n"), shown);
  // An older answer's sends hold no channel: they are HTTP.
  const old = renderScan(wire({ findings: [f], sends: [{ ...send({ host: "hooks.vendor.dev", via: ["curl"] }), channel: undefined }] }), { all: false });
  assert.match(old, /\n {5}also sent over HTTP to hooks\.vendor\.dev\n/);
  // Nothing went: every way tried.
  const tried = renderScan(wire({ findings: [f], sends: [send({ ran: 0 }), send({ host: "api.vendor.dev", channel: "script", via: ["python3"], ran: 0 })] }), { all: false });
  assert.match(tried, /\n {5}a command tried to send it over ssh to prod · by a script to api\.vendor\.dev \(it failed or was refused\)\n/);
});

test("a key-shaped value that looks like a test value is listed apart and not counted as leaked; one of your secrets never is", () => {
  const keys = Array.from({ length: 3 }, (_, i) => finding({ kind: "openai-key", preview: "sk-…", sessions: 1, how: { "command-output": 1 }, ...(i === 0 ? { looksLikeTest: true } : {}) }));
  const mine = finding({ kind: "known", preview: "STRIPE_KEY in ~/shop/.env", source: { path: "~/shop/.env", name: "STRIPE_KEY" }, looksLikeTest: true });
  const r = wire({ findings: [mine, ...keys] });
  const compact = renderScan(r, { all: false });
  assert.match(compact, /✗ 1 of your secrets leaked to the AI/, "a mark on one of your secrets is never read");
  assert.match(compact, /\n! 2 more key-shaped values leaked \(not in your files now: old\n/);
  assert.match(compact, /\n {2}1 more value looks like a test value \(a test word, a straight or repeated run, a documented example\), not counted: mandu scan --all\n/);
  // The numbers: yours, the leaks, then the test values.
  assert.equal(numberedFindings(r)[3], keys[0]);
  const long = renderScan(r, { all: true });
  assert.match(long, /\n1 value looks like a key, but reads as a test value \(a test word, a straight or repeated run, a documented example\), so it is not counted as leaked; the project and command tell for sure:\n {2}4\. sk-…\n/);
  assert.match(long, /2 more values look like keys and leaked to the AI/);
  assert.match(renderShow(r, 4)!, /^mandu scan: finding 4 of 4[^\n]*\n\n4\. sk-…: a key-shaped value that looks like a test value, sent to the AI \(not counted as leaked\)\n/);
  assert.match(shareText(r), /1 of my secrets had reached the AI, and 2 more values that look like keys\./);
  const onlyTests = renderScan(wire({ findings: [keys[0]!] }), { all: false });
  assert.match(onlyTests, /\n {2}1 key-shaped value looks like a test value \(/);
  assert.ok(!onlyTests.includes("key-shaped value leaked"), "a test value alone is no leak");
  // A send of one says so.
  const sent = renderScan(wire({ sends: [{ kind: "openai-key", preview: "sk-…", to: "own-service", host: "api.openai.com", sessions: 1, ran: 1, stoppedByMandu: 0, via: ["curl"], by: ["value"], agents: ["claude-code"], duringMandu: 0, looksLikeTest: true }] }), { all: true });
  assert.match(sent, / {4}sk-… → api\.openai\.com \(looks like a test value\)\n/);
});
