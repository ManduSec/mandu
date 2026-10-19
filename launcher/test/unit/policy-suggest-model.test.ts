/**
 * policy-suggest-model.test — `mandu policy suggest --model names`
 * (confidentiality-plan-14 §14.5) over mocked seams: the flags, the
 * experimental gate ("not offered yet"), the preview's rendering and the
 * consent ([v]iew the names, [y]es, [N]o), `--dry-run --json` printing the
 * digest and `--yes-send <digest>` sending only that digest, no terminal
 * refusing, a throwaway arbiter refusing, the model rows' screen, the run's
 * summary; the doctor row naming what T1 would use; the launcher's arbiter
 * flags for the classifier.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  destinationWords, modelImpactLine, modelPreviewLine, modelPreviewNotes, modelRunLine, parsePolicySuggestArgs, readConsentKey,
  renderModelNames, renderSuggestion, runPolicySuggest, MODEL_NOT_OFFERED,
  type ModelPreviewWire, type ModelRunWire, type PolicySuggestDeps, type SuggestPolicyWire, type SuggestionViewWire,
} from "../../src/policy-suggest.js";
import { defaultHelperWords, policyModelRows } from "../../src/doctor.js";
import { arbiterClassifierArgs, arbiterPluginArgs } from "../../src/arbiter.js";
import { Layout } from "../../src/services/layout.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const HOME = "/home/u";
const REPO = `${HOME}/proj`;
const DIGEST = "d".repeat(64);
const ENV = { HOME, NO_COLOR: "1", MANDU_EXPERIMENTAL_POLICY_MODEL: "1" };

const preview = (over: Partial<ModelPreviewWire> = {}): ModelPreviewWire => ({
  axis: true, tier: "names", digest: DIGEST,
  destination: { kind: "default", name: "Claude (claude -p)", location: "external", placement: "network", vendor: "Anthropic" },
  roots: [{ index: 1, root: REPO, files: 12 }],
  items: 3, bytes: 240, requests: 1,
  names: ['d1 root 1 "clients/"', 'f1 root 1 "clients/contract.docx" size=under1KB ext=docx', 'f2 root 1 "README.md" size=under1KB ext=md'],
  left: { covered: 2, labelled: 1, tooLong: 0, personal: 0, overCap: 0, detector: 1, registered: 0 },
  promptVersion: "names-1", confine: { live: true }, expiresAt: 1, walk: { examined: 16, covered: 2, capped: [] },
  ...over,
});

const modelView = (over: Partial<SuggestionViewWire> = {}): SuggestionViewWire => ({
  id: "pp-000007", kind: "suggestion", status: "pending", requestedBy: "mandu:scan",
  findingKey: `model-names:path:${REPO}/clients`, source: "model-names", repoRoot: REPO,
  edits: [{ op: "lock-path", path: `${REPO}/clients`, level: "no-model" }],
  sentence: "Make ~/proj/clients a secret no AI may read: covers 1 suggestion below",
  evidence: { paths: ["clients"], blobs: [], findings: [], historyOnly: false },
  impact: { historicalVersions: 0, workingTreeChanges: true, files: ["clients"] },
  historyOnly: false, rotate: false, applicable: true,
  model: { endpoint: "Claude (claude -p)", level: "local-model", reason: "customer-data", reasonWords: "looks like customer data", candidate: "folder", files: 4, covers: ["pp-000003"] },
  createdAt: 5, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
  ...over,
});

const run = (over: Partial<ModelRunWire> = {}): ModelRunWire => ({
  axis: true, running: false, digest: DIGEST, destination: preview().destination,
  sent: { requests: 1, items: 3, bytes: 240 },
  counts: { rules: 2, kept: 1, dropped: 3, merged: 0, tooBroad: 1, covered: 0, filed: 1, alreadyPending: 0, dismissed: 0, overCap: 0, failedRequests: 0 },
  filed: ["pp-000007"], suggestions: [modelView()], error: null, ms: 900,
  ...over,
});

const scanned: SuggestPolicyWire = {
  axis: true, running: false, suggestions: [], filed: [], covered: [],
  counts: { findings: 0, suggested: 0, filed: 0, alreadyPending: 0, dismissed: 0, overCap: 0, covered: 0, dropped: 0, superseded: 0 },
  scan: { repos: [{ root: REPO, repoRoot: REPO }], counts: { blobs: 1, scanned: 1, classified: 0 }, capped: { lines: [] }, ms: 10 },
};

interface H { deps: PolicySuggestDeps; out: string[]; err: string[]; previews: Array<{ endpoint?: string; includeHome?: boolean }>; sends: string[]; applied: string[] }

function harness(o: { tty?: boolean; keys?: string[]; kind?: "resident" | "throwaway"; preview?: ModelPreviewWire; run?: ModelRunWire; previewError?: string; runningFirst?: number } = {}): H {
  const h: H = { deps: undefined as unknown as PolicySuggestDeps, out: [], err: [], previews: [], sends: [], applied: [] };
  const keys = [...(o.keys ?? [])];
  let running = o.runningFirst ?? 0;
  h.deps = {
    arbiter: async () => ({ sock: "/run/a.sock", kind: o.kind ?? "resident", axisOn: true, stop: async () => {} }),
    suggest: async () => scanned,
    apply: async (_s, id) => { h.applied.push(id); return { applied: true, changeId: "pc-000001", suggestion: modelView({ status: "approved" }) }; },
    preview: async (_s, _r, _h, opts) => { h.previews.push(opts); if (o.previewError) throw new Error(o.previewError); return o.preview ?? preview(); },
    send: async (_s, digest) => { h.sends.push(digest); if (running > 0) { running--; return run({ running: true, filed: [], suggestions: [] }); } return o.run ?? run(); },
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

test("flags: --model names|contents, --endpoint, --yes-send; the combinations that contradict", () => {
  const a = parsePolicySuggestArgs(["--model", "names", "--endpoint=cloud", "--yes-send", DIGEST]);
  assert.deepEqual([a.model, a.endpoint, a.yesSend, a.errors], ["names", "cloud", DIGEST, []]);
  assert.equal(parsePolicySuggestArgs(["--model=names"]).model, "names");
  assert.deepEqual(parsePolicySuggestArgs(["--model", "contents", "--endpoint", "own"]).errors, [], "built in 4c (policy-suggest-contents.test.ts)");
  assert.match(parsePolicySuggestArgs(["--endpoint", "x"]).errors[0]!, /give --model too/);
  assert.match(parsePolicySuggestArgs(["--model", "names", "--yes-send", "abc"]).errors[0]!, /digest/);
  assert.match(parsePolicySuggestArgs(["--yes-send", DIGEST]).errors[0]!, /give --model names or --model contents too/);
  assert.match(parsePolicySuggestArgs(["--model", "names", "--dry-run", "--yes-send", DIGEST]).errors[0]!, /pick one/);
  assert.match(parsePolicySuggestArgs(["--model", "names", "--apply-all"]).errors[0]!, /separately/);
});

test("not offered yet without MANDU_EXPERIMENTAL_POLICY_MODEL=1: refused before any scan", async () => {
  const h = harness();
  assert.equal(await runPolicySuggest(["--model", "names"], { HOME, NO_COLOR: "1" }, layout, h.deps), 2);
  assert.match(h.err.join(""), /not offered yet/);
  assert.equal(h.previews.length, 0);
  assert.match(MODEL_NOT_OFFERED, /MANDU_EXPERIMENTAL_POLICY_MODEL=1/);
});

test("the preview in words: what leaves, where to, what was left out, the confine; the names with their roots", () => {
  assert.equal(modelPreviewLine(preview()), "This sends 3 file and folder names from 1 folder to Claude (claude -p) (Anthropic, outside this computer), in 1 request (240 bytes). No file's content is sent.");
  assert.equal(destinationWords({ kind: "declared", name: "ollama", location: "local", placement: "host", vendor: "127.0.0.1" }), "ollama (127.0.0.1, your own model, on this computer)");
  assert.deepEqual(modelPreviewNotes(preview()), [
    "Not sent: 3 names your policy protects, 1 name that look like a key.",
    "The call can reach only the model's own port (network confine live).",
  ]);
  assert.match(modelPreviewNotes(preview({ confine: { live: false, note: "this kernel has no Landlock TCP rules" } }))[1]!, /^Note: this kernel has no Landlock TCP rules\.$/);
  assert.equal(renderModelNames(preview(), HOME), [
    "  root 1 = ~/proj (not sent)",
    '  d1 root 1 "clients/"',
    '  f1 root 1 "clients/contract.docx" size=under1KB ext=docx',
    '  f2 root 1 "README.md" size=under1KB ext=md',
  ].join("\n") + "\n");
  assert.deepEqual(["v", "V", "y", "yes", "", "n", "x"].map(readConsentKey), ["view", "view", "yes", "yes", "no", "no", "no"]);
});

test("a terminal: [v] shows every name, [y] sends the preview's digest; the model's rule joins the review and [a] applies it", async () => {
  const h = harness({ keys: ["v", "y", "a"] });
  assert.equal(await runPolicySuggest(["--model", "names"], ENV, layout, h.deps), 0, h.err.join(""));
  const screen = h.out.join("");
  assert.ok(screen.includes("This sends 3 file and folder names from 1 folder to Claude (claude -p)"), screen);
  assert.ok(screen.includes('  f1 root 1 "clients/contract.docx"'), "[v] listed the names");
  assert.deepEqual(h.sends, [DIGEST]);
  assert.match(screen, /The model answered: 2 rules came back, 1 filed for your review, 1 too broad, 3 answer parts dropped/);
  assert.match(screen, /\[1\/1\] Make ~\/proj\/clients a secret no AI may read: covers 1 suggestion below/);
  assert.match(screen, /suggested by your model Claude \(claude -p\): looks like customer data, from the file names/);
  assert.match(screen, /hides: this folder and everything in it \(4 files the scan listed\), from the next launch; closes the 1 suggestion it covers/);
  assert.deepEqual(h.applied, ["pp-000007"]);
});

test("a terminal: [N] (or anything else) sends nothing", async () => {
  const h = harness({ keys: ["n"] });
  assert.equal(await runPolicySuggest(["--model", "names"], ENV, layout, h.deps), 0);
  assert.deepEqual(h.sends, []);
  assert.match(h.out.join(""), /Nothing was sent\./);
});

test("a run still going is polled until it ends", async () => {
  const h = harness({ keys: ["y", "q"], runningFirst: 2 });
  assert.equal(await runPolicySuggest(["--model", "names"], ENV, layout, h.deps), 0);
  assert.deepEqual(h.sends, [DIGEST, DIGEST, DIGEST]);
});

test("--dry-run --json prints the preview and its digest and sends nothing; --json --yes-send <that digest> sends it", async () => {
  const d = harness({ tty: false });
  assert.equal(await runPolicySuggest(["--model", "names", "--dry-run", "--json", "--endpoint", "cloud"], ENV, layout, d.deps), 0);
  const j = JSON.parse(d.out.join("")) as { model: { preview: ModelPreviewWire; run: null; note: string } };
  assert.equal(j.model.preview.digest, DIGEST);
  assert.equal(j.model.run, null);
  assert.match(j.model.note, new RegExp(`--endpoint cloud --yes-send ${DIGEST}`));
  assert.deepEqual(d.previews, [{ endpoint: "cloud" }]);
  assert.deepEqual(d.sends, []);

  const s = harness({ tty: false });
  assert.equal(await runPolicySuggest(["--model", "names", "--json", "--yes-send", DIGEST], ENV, layout, s.deps), 0);
  const js = JSON.parse(s.out.join("")) as { model: { run: ModelRunWire }; suggestions: SuggestionViewWire[] };
  assert.deepEqual(s.sends, [DIGEST]);
  assert.equal(js.model.run.filed[0], "pp-000007");
  assert.ok(js.suggestions.some((v) => v.source === "model-names"));
});

test("--yes-send with another digest sends nothing and fails; no terminal without it sends nothing", async () => {
  const other = harness({ tty: false, preview: preview({ digest: "e".repeat(64) }) });
  assert.equal(await runPolicySuggest(["--model", "names", "--yes-send", DIGEST], ENV, layout, other.deps), 1);
  assert.match(other.err.join(""), /changed since that preview/);
  assert.deepEqual(other.sends, []);

  const none = harness({ tty: false });
  assert.equal(await runPolicySuggest(["--model", "names"], ENV, layout, none.deps), 0);
  assert.match(none.out.join(""), new RegExp(`no terminal to ask on: nothing was sent.*--yes-send ${DIGEST}`));
  assert.deepEqual(none.sends, []);
});

test("a throwaway arbiter, a preview error, and nothing to send", async () => {
  const t = harness({ kind: "throwaway" });
  assert.equal(await runPolicySuggest(["--model", "names", "--dry-run"], ENV, layout, t.deps), 1);
  assert.match(t.err.join(""), /runs only with the running Mandu service/);
  const e = harness({ previewError: "unknown op: modelSuggestPreview" });
  assert.equal(await runPolicySuggest(["--model", "names"], ENV, layout, e.deps), 1);
  assert.match(e.err.join(""), /older than this command/);
  const n = harness({ preview: preview({ items: 0, digest: "", names: [] }) });
  assert.equal(await runPolicySuggest(["--model", "names"], ENV, layout, n.deps), 0);
  assert.match(n.out.join(""), /No file or folder name to send/);
  assert.deepEqual(n.sends, []);
});

test("the model row's screen and the run's summary; a failed run in the arbiter's words", () => {
  const screen = renderSuggestion(modelView(), 1, 1, { home: HOME, color: false });
  assert.ok(!/rotate/i.test(screen), "no rotation advice: no key was found");
  assert.equal(modelImpactLine(modelView({ model: { ...modelView().model!, candidate: "file", covers: [] } })), "hides: this file, from the next launch");
  assert.equal(modelRunLine(run({ error: "the model run took longer than 5 minutes and was stopped", counts: { ...run().counts, rules: 0 } })),
    "The model run did not complete: the model run took longer than 5 minutes and was stopped. Nothing was filed.");
});

test("doctor: what T1 would use, and what T2 would", () => {
  assert.equal(defaultHelperWords({ offered: true, mode: "auto", apiKey: true }, { claude: true, codex: false }), "Claude through the Anthropic API (ANTHROPIC_API_KEY)");
  assert.equal(defaultHelperWords({ offered: true, mode: "auto", apiKey: false }, { claude: true, codex: false }), "Claude through `claude -p` (your Claude Code login)");
  assert.equal(defaultHelperWords({ offered: true, mode: "api", apiKey: false }, { claude: true, codex: false }), null);
  assert.equal(defaultHelperWords({ offered: true, mode: "auto", apiKey: false }, { claude: false, codex: true }), "Codex through `codex exec` (your Codex login)");
  const rows = policyModelRows({ offered: false, mode: "auto", apiKey: false }, { claude: true, codex: false }, undefined);
  assert.match(rows[0]!, /not offered yet .* it would use Claude through `claude -p`/);
  assert.match(rows[1]!, /not offered yet .*; no model of your own is declared, so it cannot run: declare one with local: true/);
  assert.deepEqual(policyModelRows(undefined, { claude: true, codex: false }, undefined), []);
});

test("the launcher's arbiter flags: --classifier from the layout, --landlock-apply when built; none without the runtime", () => {
  const fake = { policyClassifier: () => ["/usr/bin/node", "/x/classify-main.ts"] };
  assert.deepEqual(arbiterClassifierArgs(fake, () => "/bin/lla"), ["--classifier", '["/usr/bin/node","/x/classify-main.ts"]', "--landlock-apply", "/bin/lla"]);
  assert.deepEqual(arbiterClassifierArgs(fake, () => null), ["--classifier", '["/usr/bin/node","/x/classify-main.ts"]']);
  assert.deepEqual(arbiterClassifierArgs({ policyClassifier: () => null }, () => "/bin/lla"), []);
  assert.equal(Layout.dev("/nonexistent-repo").policyClassifier(() => false), null);
  const argv = Layout.dev("/r").policyClassifier(() => true)!;
  assert.equal(argv[0], process.execPath);
  assert.equal(argv.at(-1), "/r/interceptors/inspect-mcp/src/classify-main.ts");
});

test("the launcher's arbiter flags for the prompt filter plugins (plan 15 §4.3): --net-guard when built, --landlock-apply unless already passed", () => {
  const bins = (n: string): string | null => (n === "mandu-net-guard" ? "/b/ng" : "/b/lla");
  assert.deepEqual(arbiterPluginArgs([], bins), ["--net-guard", "/b/ng", "--landlock-apply", "/b/lla"]);
  assert.deepEqual(arbiterPluginArgs(["--landlock-apply", "/b/lla"], bins), ["--net-guard", "/b/ng"]);
  assert.deepEqual(arbiterPluginArgs([], () => null), []);
});
