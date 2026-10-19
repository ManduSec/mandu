/**
 * policy-suggest-contents.test — `mandu policy suggest --model contents`
 * (confidentiality-plan-14 §14.5, §14.11) over mocked seams: the flag, the
 * experimental gate, the preview's words ("This sends the text of N files
 * (X KB) to your own model <name> (this computer)"), the files with their
 * sizes and never their text ([v]iew the files), [y] sends the preview's
 * digest, [N] nothing, `--dry-run --json` names the command to repeat with
 * `--yes-send`, another digest sends nothing, the run's summary, the row of a
 * document your model read (Skip only below hidden from the AI), the launch
 * notice's words, and the doctor row saying whether T2 has a model to use.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CONSENT_PROMPT_FILES, CONTENTS_NOT_OFFERED, HUMAN_ONLY_LINE, kbWords, launchSuggestionNotice, modelPreviewLine, modelPreviewNotes, modelRunLine,
  parsePolicySuggestArgs, renderModelFiles, renderSuggestion, runPolicySuggest, whyNotApplicable,
  type ModelPreviewWire, type ModelRunWire, type PolicySuggestDeps, type SuggestPolicyWire, type SuggestionViewWire,
} from "../../src/policy-suggest.js";
import { policyModelRows, type ModelsFacts } from "../../src/doctor.js";
import type { Layout } from "../../src/services/layout.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const HOME = "/home/u";
const REPO = `${HOME}/proj`;
const DIGEST = "c".repeat(64);
const ENV = { HOME, NO_COLOR: "1", MANDU_EXPERIMENTAL_POLICY_MODEL: "1" };
const TEXT_CANARY = "DOCUMENT-TEXT-CANARY";

const preview = (over: Partial<ModelPreviewWire> = {}): ModelPreviewWire => ({
  axis: true, tier: "contents", digest: DIGEST,
  destination: { kind: "declared", name: "ollama", location: "local", placement: "host", vendor: "127.0.0.1" },
  roots: [{ index: 1, root: REPO, files: 7 }],
  items: 2, bytes: 389_120, requests: 2, names: [],
  files: [{ root: 1, name: "docs/contract.md", bytes: 16_384, truncated: true }, { root: 1, name: "notes/meeting.txt", bytes: 900, truncated: false }],
  left: { covered: 1, labelled: 1, tooLong: 0, personal: 0, overCap: 0, detector: 0, registered: 0, flagged: 1, unread: 2 },
  promptVersion: "contents-1", confine: { live: true }, expiresAt: 1, walk: { examined: 9, covered: 1, capped: [] },
  ...over,
});

const contentsView = (over: Partial<SuggestionViewWire> = {}): SuggestionViewWire => ({
  id: "pp-000011", kind: "suggestion", status: "pending", requestedBy: "mandu:scan",
  findingKey: `model-contents:path:${REPO}/docs/contract.md`, source: "model-contents", repoRoot: REPO,
  edits: [{ op: "lock-path", path: `${REPO}/docs/contract.md`, level: "no-model" }],
  sentence: "Make ~/proj/docs/contract.md a secret no AI may read (read by your own model ollama: looks like legal documents)",
  evidence: { paths: ["docs/contract.md"], blobs: [], findings: [], historyOnly: false },
  impact: { historicalVersions: 0, workingTreeChanges: true, files: ["docs/contract.md"] },
  historyOnly: false, rotate: false, applicable: true, humanOnly: false,
  model: { endpoint: "ollama", level: "no-model", reason: "legal", reasonWords: "looks like legal documents", candidate: "file", files: 1, covers: [] },
  createdAt: 5, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
  ...over,
});
const payView = contentsView({
  id: "pp-000012", findingKey: `model-contents:path:${REPO}/hr.csv`, edits: [{ op: "lock-path", path: `${REPO}/hr.csv`, level: "local-model" }],
  sentence: "Make ~/proj/hr.csv a secret only your own AI may read (read by your own model ollama: looks like personnel records)",
  evidence: { paths: ["hr.csv"], blobs: [], findings: [], historyOnly: false }, humanOnly: true,
  model: { endpoint: "ollama", level: "local-model", reason: "personnel", reasonWords: "looks like personnel records", candidate: "file", files: 1, covers: [] },
});

const run = (over: Partial<ModelRunWire> = {}): ModelRunWire => ({
  axis: true, running: false, digest: DIGEST, destination: preview().destination,
  sent: { requests: 2, items: 2, bytes: 389_120 },
  counts: { rules: 2, kept: 2, dropped: 0, merged: 0, tooBroad: 0, covered: 0, filed: 2, alreadyPending: 0, dismissed: 0, overCap: 0, failedRequests: 0, public: 0 },
  filed: ["pp-000011", "pp-000012"], suggestions: [contentsView(), payView], error: null, ms: 900,
  ...over,
});

const scanned: SuggestPolicyWire = {
  axis: true, running: false, suggestions: [], filed: [], covered: [],
  counts: { findings: 0, suggested: 0, filed: 0, alreadyPending: 0, dismissed: 0, overCap: 0, covered: 0, dropped: 0, superseded: 0 },
  scan: { repos: [{ root: REPO, repoRoot: REPO }], counts: { blobs: 1, scanned: 1, classified: 0 }, capped: { lines: [] }, ms: 10 },
};

interface H { deps: PolicySuggestDeps; out: string[]; err: string[]; previews: Array<Record<string, unknown>>; sends: string[]; applied: string[] }

function harness(o: { tty?: boolean; keys?: string[]; preview?: ModelPreviewWire } = {}): H {
  const h: H = { deps: undefined as unknown as PolicySuggestDeps, out: [], err: [], previews: [], sends: [], applied: [] };
  const keys = [...(o.keys ?? [])];
  h.deps = {
    arbiter: async () => ({ sock: "/run/a.sock", kind: "resident", axisOn: true, stop: async () => {} }),
    suggest: async () => scanned,
    apply: async (_s, id) => { h.applied.push(id); return { applied: true, changeId: "pc-000001", suggestion: contentsView({ status: "approved" }) }; },
    preview: async (_s, _r, _h, opts) => { h.previews.push(opts); return o.preview ?? preview(); },
    send: async (_s, digest) => { h.sends.push(digest); return run(); },
    cwd: () => REPO,
    platform: "linux", // the wording under test is the Linux one on any host
    isTTY: () => o.tty ?? true,
    readKey: async () => keys.shift() ?? "",
    readLine: async () => "",
    now: () => 0,
    sleep: async () => {},
    out: (s) => h.out.push(s),
    err: (s) => h.err.push(s),
  };
  return h;
}
const layout = {} as Layout;

test("the flag: --model contents with or without --endpoint; not offered without the experimental flag", async () => {
  const a = parsePolicySuggestArgs(["--model", "contents", "--endpoint", "ollama"]);
  assert.deepEqual([a.model, a.endpoint, a.errors], ["contents", "ollama", []]);
  assert.deepEqual(parsePolicySuggestArgs(["--model=contents", "--yes-send", DIGEST]).errors, []);
  const h = harness();
  assert.equal(await runPolicySuggest(["--model", "contents"], { HOME, NO_COLOR: "1" }, layout, h.deps), 2);
  assert.match(h.err.join(""), /--model contents is not offered yet/);
  assert.equal(h.previews.length, 0);
  assert.match(CONTENTS_NOT_OFFERED, /MANDU_EXPERIMENTAL_POLICY_MODEL=1/);
});

test("the preview in words: the text of N files (X KB) to your own model, where it is; what was left out; files and sizes, never text", () => {
  assert.equal(modelPreviewLine(preview()),
    "This sends the text of 2 files (380 KB) to your own model ollama (this computer), one file per request, at most the first 16 KB of each.");
  assert.match(modelPreviewLine(preview({ destination: { ...preview().destination, placement: "network" } })), /\(your organization's network\)/);
  const notes = modelPreviewNotes(preview()).join("\n");
  assert.match(notes, /Only documents \(\.md \.txt \.rst \.org \.tex \.csv \.tsv \.rtf \.html, and the text of Word, Excel and PowerPoint files\) your policy calls public/);
  assert.match(notes, /Not sent: 2 documents your policy or a sensitivity label protects, 1 document that holds something like a key, 2 documents the scan could not read whole/);
  assert.match(notes, /network confine live/);
  const files = renderModelFiles(preview(), HOME);
  assert.equal(files, [
    "  root 1 = ~/proj (not sent)",
    "  root 1  docs/contract.md  16 KB (the first 16 KB)",
    "  root 1  notes/meeting.txt  900 bytes",
    "",
  ].join("\n"));
  assert.equal(kbWords(1023), "1,023 bytes");
  assert.equal(kbWords(389_120), "380 KB");
});

test("a terminal: [v] shows the files, [y] sends the preview's digest; the documents join the review; Skip only below hidden from the AI", async () => {
  const h = harness({ keys: ["v", "y", "a", "s", "q"] });
  assert.equal(await runPolicySuggest(["--model", "contents"], ENV, layout, h.deps), 0, h.err.join(""));
  const out = h.out.join("");
  assert.deepEqual(h.previews, [{ tier: "contents" }]);
  assert.ok(out.includes(CONSENT_PROMPT_FILES));
  assert.match(out, /root 1 {2}docs\/contract\.md {2}16 KB/);
  assert.deepEqual(h.sends, [DIGEST]);
  assert.match(out, /Your model answered: 2 documents answered, 2 filed for your review \(1 only you can approve, in the dashboard\), 0 not sensitive\./);
  assert.match(out, /suggested by your model ollama, which read the file on your side: looks like legal documents/);
  assert.deepEqual(h.applied, ["pp-000011"], "the no-model one applies; the local-model one is Skip only");
  assert.ok(out.includes(HUMAN_ONLY_LINE));
  assert.ok(!out.includes(TEXT_CANARY));
});

test("[N] sends nothing; --endpoint rides the preview; --dry-run --json prints the command to repeat; another digest sends nothing", async () => {
  const n = harness({ keys: ["n"] });
  assert.equal(await runPolicySuggest(["--model", "contents", "--endpoint", "ollama"], ENV, layout, n.deps), 0);
  assert.deepEqual(n.previews, [{ endpoint: "ollama", tier: "contents" }]);
  assert.deepEqual(n.sends, []);
  const dry = harness({ tty: false });
  assert.equal(await runPolicySuggest(["--model", "contents", "--dry-run", "--json"], ENV, layout, dry.deps), 0);
  const j = JSON.parse(dry.out.join("")) as { model: { preview: ModelPreviewWire; note: string } };
  assert.equal(j.model.preview.digest, DIGEST);
  assert.equal(j.model.note, `--dry-run: nothing was sent. To send exactly these files without a terminal: mandu policy suggest --model contents --yes-send ${DIGEST}`);
  assert.deepEqual(dry.sends, []);
  const other = harness({ tty: false });
  assert.equal(await runPolicySuggest(["--model", "contents", "--json", "--yes-send", "e".repeat(64)], ENV, layout, other.deps), 1);
  assert.match(other.err.join(""), /the files to send changed since that preview/);
  assert.deepEqual(other.sends, []);
  const yes = harness({ tty: false });
  assert.equal(await runPolicySuggest(["--model", "contents", "--json", "--yes-send", DIGEST], ENV, layout, yes.deps), 0);
  assert.deepEqual(yes.sends, [DIGEST]);
  const none = harness({ preview: preview({ digest: "", items: 0, files: [] }) });
  assert.equal(await runPolicySuggest(["--model", "contents"], ENV, layout, none.deps), 0);
  assert.match(none.out.join(""), /No document to send/);
});

test("the run's summary, the row's screen, whyNotApplicable, and the launch notice's words", () => {
  assert.equal(modelRunLine(run({ counts: { ...run().counts, filed: 1, public: 39, rules: 40, alreadyPending: 1 }, filed: ["pp-000011"] }), "contents"),
    "Your model answered: 40 documents answered, 1 filed for your review, 39 not sensitive, 1 already waiting.");
  assert.equal(modelRunLine(run({ error: "the model run took longer than 30 minutes and was stopped", counts: { ...run().counts, rules: 0 } }), "contents"),
    "The model run did not complete: the model run took longer than 30 minutes and was stopped. Nothing was filed.");
  const screen = renderSuggestion(payView, 1, 1, { home: HOME, color: false });
  assert.match(screen, /a secret only your own AI may read/);
  assert.match(screen, /hides: this file, from the next launch/);
  assert.ok(!/rotate/i.test(screen));
  assert.equal(whyNotApplicable(payView), HUMAN_ONLY_LINE);
  assert.equal(whyNotApplicable(contentsView()), null);
  const notice = launchSuggestionNotice({ ...scanned, suggestions: [contentsView(), payView] }, REPO);
  assert.equal(notice, "mandu: 2 files your model called sensitive in this project are not protected: run `mandu policy suggest` or open Keys Mandu found in the dashboard");
});

test("doctor: whether T2 has a model of your own to use", () => {
  const facts = (endpoints: Array<{ name: string; local: boolean; model?: string }>): ModelsFacts =>
    ({ source: "arbiter", endpoints: endpoints.map((e) => ({ ...e, url: "http://127.0.0.1:11434", wire: "openai-chat", hostClass: "loopback", host: "127.0.0.1", reachable: null })), declaredInFile: true, localModelLines: [], policyPath: null } as unknown as ModelsFacts);
  const on = { offered: true, mode: "auto", apiKey: false };
  assert.match(policyModelRows(on, { claude: true, codex: false }, facts([]))[1]!, /✗ file contents .*no model of your own is declared, so it cannot run/);
  assert.match(policyModelRows(on, { claude: true, codex: false }, facts([{ name: "ollama", local: true, model: "qwen2.5:7b" }]))[1]!, /on request, after you see every file it would read; it would use only your own model ollama$/);
  assert.match(policyModelRows(on, { claude: true, codex: false }, facts([{ name: "a", local: true }, { name: "b", local: true }]))[1]!, /the one you name with --endpoint \(a, b\)/);
  assert.match(policyModelRows(on, { claude: true, codex: false }, facts([{ name: "c", local: true, model: "gpt-oss:120b-cloud" }, { name: "o", local: false }]))[1]!, /no model of your own is declared/);
  assert.match(policyModelRows({ ...on, offered: false }, { claude: true, codex: false }, facts([{ name: "ollama", local: true }]))[1]!, /not offered yet .*; it would use only your own model ollama/);
});
