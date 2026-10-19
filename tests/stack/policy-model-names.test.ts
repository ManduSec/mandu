/**
 * policy-model-names e2e — the canary oracle of the names-only model
 * (confidentiality-plan-14-policy-suggestions.md §14.7 "4b", §9 "the model
 * tiers") over the PRODUCTION wiring:
 *
 *   - a REAL ArbiterServer with a file-backed law that declares a mock
 *     "cloud" model (`local: false`) and labels a folder whose names are
 *     canaries;
 *   - the REAL classifier process (inspect-mcp classify-main.ts), started
 *     from the argv the launcher's layout gives the arbiter (`--classifier`,
 *     Layout.policyClassifier), talking to a mock Anthropic endpoint that
 *     records every request;
 *   - the launcher's `realPolicySuggestDeps()` (its narrow client:
 *     modelSuggestPreview / modelSuggest over ndjsonCall; this is its parity
 *     test against the real server) for `mandu policy suggest`;
 *   - the dashboard's GET /api/suggestions handler over the production
 *     ArbiterClient.
 *
 * The fixture: canary keys in a file (`deploy/staging.conf`, on disk), in
 * history (a deploy key committed then deleted) and inline (a token once in
 * `config.py`, since removed); a labelled folder whose name and file names
 * are canaries; a marker string in every file's text.
 *
 * The oracle:
 *   - T0 (`mandu policy suggest` without --model) makes no request;
 *   - a T1 run to the mock: no request holds a key canary byte or any
 *     8-character run of one, the marker, a labelled name, or the home path;
 *     the bytes sent equal the preview's; a stale digest sends nothing;
 *   - the mock answers a valid rule, a rule over an unknown id, a free-text
 *     reason and a canary in every string field: only the valid rule is
 *     filed, and no canary appears in the store, the events, the terminal
 *     output, `--json` or the dashboard's suggestions API;
 *   - the closed answer's enums and bounds are the same in the arbiter and
 *     the classifier (the two packages ship standalone).
 *
 * Axes stated: secrets.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ServerResponse } from "node:http";

import Database from "../../arbiter/db/sqlite.js";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import type { ModelSuggestPreviewResult, ModelSuggestResult } from "../../arbiter/ipc/protocol.js";
import {
  MODEL_RULE_LEVELS as A_LEVELS, REASON_CODES as A_REASONS, T1_BATCHES_MAX, T1_PROMPT_VERSION, T1_RULES_MAX,
} from "../../arbiter/policy/policy-model.js";
import {
  BATCHES_MAX, CLASSIFY_PROMPT_VERSION, MODEL_RULE_LEVELS as C_LEVELS, REASON_CODES as C_REASONS, RULES_MAX,
} from "../../interceptors/inspect-mcp/src/classify.js";
import {
  realPolicySuggestDeps, runPolicySuggest,
  type ModelPreviewWire, type ModelRunWire, type PolicySuggestDeps, type SuggestionViewWire,
} from "../../launcher/src/policy-suggest.js";
import { Layout } from "../../launcher/src/services/layout.js";
import { getSuggestions } from "../../dashboard/src/server/suggestion-routes.js";
import { stateAxes } from "../../arbiter/test/axes.js";
import { randomSecretBody } from "../../arbiter/test/helpers/random-secret.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

// The launcher's wire mirror takes the arbiter's types as they are (a
// compile-time parity check: `npm run typecheck` fails when they drift).
const wireParity = (p: ModelSuggestPreviewResult, r: ModelSuggestResult): [ModelPreviewWire, ModelRunWire] => [p, r];
void wireParity;

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

const alnum = (n: number): string => {
  let s = "";
  while (s.length < n) s += randomBytes(64).toString("base64").replace(/[^A-Za-z0-9]/g, "");
  return s.slice(0, n);
};
const KEY_BODY = alnum(96);
const PEM = "-----BEGIN OPENSSH " + `PRIVATE KEY-----\n${KEY_BODY}\n-----END OPENSSH PRIVATE KEY-----\n`;
const INLINE_BODY = randomSecretBody(36); // a digit, no placeholder run (random-secret.ts)
const FILE_BODY = randomSecretBody(36);
const MARKER = `MARKER${alnum(12)}`;
const LABELLED = `hrcanary${alnum(10).toLowerCase()}`;
const LABELLED_FILE = `salarycanary${alnum(10).toLowerCase()}.txt`;
const ANSWER_CANARY = `ANSWERCANARY${alnum(16)}`;
const KEY_RUNS = [KEY_BODY, INLINE_BODY, FILE_BODY].flatMap((b) => Array.from({ length: b.length - 7 }, (_, i) => b.slice(i, i + 8)));

function noKey(what: string, s: string): void {
  assert.ok(!s.includes(KEY_BODY) && !s.includes(INLINE_BODY) && !s.includes(FILE_BODY), `${what} carries a key`);
  const hit = KEY_RUNS.find((r) => s.includes(r));
  assert.equal(hit, undefined, `${what} carries an 8-character run of a key`);
}

const dirs: string[] = [];
const servers: Server[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const s of servers) s.close();
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

test("parity: the closed answer's enums and bounds are the same in the arbiter and the classifier", () => {
  assert.deepEqual([...A_LEVELS], [...C_LEVELS]);
  assert.deepEqual([...A_REASONS], [...C_REASONS]);
  assert.equal(T1_RULES_MAX, RULES_MAX);
  assert.equal(T1_PROMPT_VERSION, CLASSIFY_PROMPT_VERSION);
  assert.equal(T1_BATCHES_MAX, BATCHES_MAX);
});

test("the names-only model over the production wiring: T0 sends nothing; T1 sends only gated names, the bytes consent bound; only the valid rule is filed; no canary anywhere", async (t) => {
  const classifier = Layout.dev(REPO_ROOT).policyClassifier();
  if (classifier === null) { t.skip("inspect-mcp has no node_modules (npm install in interceptors/inspect-mcp)"); return; }

  // ── the mock "cloud" model: records every request; answers every shape
  const requests: Array<{ path: string; body: Record<string, unknown> }> = [];
  const mock = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      const parsed = JSON.parse(body) as Record<string, unknown>;
      requests.push({ path: req.url ?? "", body: parsed });
      const user = ((parsed["messages"] as Array<{ content: string }>)[0]?.content) ?? "";
      const clients = /^(d\d+) root \d+ "clients\/"$/m.exec(user)?.[1] ?? null;
      const rules: unknown[] = [
        ...(clients ? [{ candidate: clients, level: "no-model", reason: "customer-data", why: ANSWER_CANARY }] : []),
        { candidate: "f98765", level: "no-model", reason: "credentials" },
        { candidate: clients ?? "d1", level: "no-model", reason: `because ${ANSWER_CANARY}` },
        { candidate: ANSWER_CANARY, level: ANSWER_CANARY, reason: ANSWER_CANARY },
      ];
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        id: ANSWER_CANARY, model: ANSWER_CANARY, stop_reason: ANSWER_CANARY,
        content: [{ type: "text", text: `${ANSWER_CANARY}\n${JSON.stringify({ rules, note: ANSWER_CANARY })}` }],
      }));
    });
  });
  await new Promise<void>((r) => mock.listen(0, "127.0.0.1", r));
  servers.push(mock);
  const mockUrl = `http://127.0.0.1:${(mock.address() as AddressInfo).port}`;

  // ── the fixture
  const dir = mkdtempSync(join(tmpdir(), "mdu-model-oracle-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const repo = join(home, "proj");
  mkdirSync(repo, { recursive: true });
  const gitEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
  const git = (...a: string[]): string => execFileSync("git", a, { cwd: repo, env: gitEnv, encoding: "utf8" });
  const put = (rel: string, body = ""): void => { mkdirSync(dirname(join(repo, rel)), { recursive: true }); writeFileSync(join(repo, rel), `${MARKER}\n${body}`); };
  git("init", "-q", "-b", "main");
  put("README.md", "a project\n");
  put("config.py", `API_TOKEN = "${"gh" + "p_" + INLINE_BODY}"\n`);
  for (let i = 0; i < 10; i++) put(`src/mod${i}.ts`, `export const x = ${i};\n`);
  put("docs/guide.md");
  git("add", "."); git("commit", "-qm", "init");
  put("deploy/id_ed25519", PEM);
  git("add", "."); git("commit", "-qm", "add deploy key");
  git("rm", "-q", "deploy/id_ed25519");
  put("config.py", "import os\nAPI_TOKEN = os.environ['API_TOKEN']\n");
  git("add", "."); git("commit", "-qm", "remove the key");
  put("deploy/staging.conf", `[api]\nAPI_TOKEN=${"gh" + "p_" + FILE_BODY}\n`);
  put("clients/acme/contract.docx", "the contract\n");
  put("clients/acme/invoice-2026.xlsx");
  put("clients/beta/nda.pdf");
  put(`${LABELLED}/${LABELLED_FILE}`, "salaries\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, [
    "version: 1",
    "paths:",
    `  - path: ${join(repo, LABELLED)}`,
    "    level: no-model",
    "models:",
    "  - name: mock-cloud",
    `    url: ${mockUrl}`,
    "    wire: anthropic",
    "    model: mock-model-1",
    "    local: false",
    "",
  ].join("\n"));

  const sock = join(dir, "arbiter.sock");
  const logs: string[] = [];
  const server = new ArbiterServer({
    socketPath: sock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath: policy, policyPollMs: 0, confidentiality: true, integrity: false, log: (m) => logs.push(m),
    // What `--classifier` carries in a checkout (server-args.ts, Layout).
    policyClassifier: { argv: classifier, landlockApply: null },
  });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  const outputs: string[] = [];
  const env = { HOME: home, NO_COLOR: "1", PATH: process.env["PATH"] ?? "/usr/bin:/bin", MANDU_EXPERIMENTAL_POLICY_MODEL: "1" };
  const deps = (o: { tty: boolean; keys?: string[] }): { d: PolicySuggestDeps; out: string[]; err: string[] } => {
    const out: string[] = [], err: string[] = [];
    const keys = [...(o.keys ?? [])];
    return {
      out, err,
      d: {
        ...realPolicySuggestDeps(),
        arbiter: async () => ({ sock, kind: "resident" as const, axisOn: true, stop: async () => {} }),
        cwd: () => repo,
        isTTY: () => o.tty,
        readKey: async () => keys.shift() ?? "",
        readLine: async () => "",
        out: (s) => { out.push(s); outputs.push(s); },
        err: (s) => { err.push(s); outputs.push(s); },
      },
    };
  };
  const layout = Layout.dev(REPO_ROOT);
  try {
    // ── T0: the scans alone make no model request
    const t0 = deps({ tty: false });
    assert.equal(await runPolicySuggest(["--json"], env, layout, t0.d), 0, t0.err.join(""));
    assert.equal(requests.length, 0, "T0 makes no request");

    // ── T1 preview (--dry-run --json): the digest, nothing sent
    const pv = deps({ tty: false });
    assert.equal(await runPolicySuggest(["--model", "names", "--endpoint", "mock-cloud", "--dry-run", "--json"], env, layout, pv.d), 0, pv.err.join(""));
    const previewJson = JSON.parse(pv.out.join("")) as { model: { preview: ModelPreviewWire } };
    const preview = previewJson.model.preview;
    assert.match(preview.digest, /^[0-9a-f]{64}$/);
    assert.deepEqual(preview.destination, { kind: "declared", name: "mock-cloud", location: "external", placement: "host", vendor: "127.0.0.1" });
    assert.equal(requests.length, 0, "a preview sends nothing");
    assert.ok(preview.names.some((n) => n.includes('"clients/"')), preview.names.join("\n"));

    // ── a stale digest sends nothing
    await assert.rejects(client.modelSuggest("0".repeat(64)), /look again/);
    const stale = deps({ tty: false });
    assert.equal(await runPolicySuggest(["--model", "names", "--endpoint", "mock-cloud", "--json", "--yes-send", "1".repeat(64)], env, layout, stale.d), 1);
    assert.equal(requests.length, 0, "a digest that is not this preview's sends nothing");

    // ── T1 send (--json --yes-send <digest>)
    const sd = deps({ tty: false });
    assert.equal(await runPolicySuggest(["--model", "names", "--endpoint", "mock-cloud", "--json", "--yes-send", preview.digest], env, layout, sd.d), 0, sd.err.join(""));
    const sent = JSON.parse(sd.out.join("")) as { model: { run: ModelRunWire }; suggestions: SuggestionViewWire[] };
    assert.ok(requests.length >= 1, "the run reached the mock");
    const texts = requests.map((r) => ((r.body["messages"] as Array<{ content: string }>)[0]!.content));
    assert.equal(texts.reduce((n, s) => n + Buffer.byteLength(s), 0), preview.bytes, "the bytes sent equal the preview's");
    for (const n of preview.names) assert.ok(texts.some((x) => x.split("\n").includes(n)), `sent: ${n}`);
    for (const r of requests) {
      const raw = JSON.stringify(r.body);
      noKey("a model request", raw);
      assert.ok(!raw.includes(MARKER), "no file's text in a request");
      assert.ok(!raw.includes(LABELLED) && !raw.includes(LABELLED_FILE), "no labelled name in a request");
      assert.ok(!raw.includes(home) && !raw.includes(dir), "no home path in a request");
      assert.ok(!("tools" in r.body), "no tools");
      assert.equal(r.path, "/v1/messages");
    }
    // Only the valid rule is filed.
    const run = sent.model.run;
    assert.equal(run.error, null, run.error ?? "");
    assert.equal(run.filed.length, 1);
    const filed = sent.suggestions.filter((v) => v.source === "model-names");
    assert.equal(filed.length, 1);
    assert.deepEqual(filed[0]!.edits, [{ op: "lock-path", path: join(repo, "clients"), level: "no-model" }]);
    assert.equal(filed[0]!.model?.endpoint, "mock-cloud");
    assert.equal(filed[0]!.model?.reasonWords, "looks like customer data");
    assert.ok(run.counts.dropped >= 3, JSON.stringify(run.counts));

    // ── a terminal session: [v] shows the names, [N] sends nothing more
    const before = requests.length;
    const tt = deps({ tty: true, keys: ["v", "n", "q"] });
    assert.equal(await runPolicySuggest(["--model", "names", "--endpoint", "mock-cloud"], env, layout, tt.d), 0, tt.err.join(""));
    assert.equal(requests.length, before, "[N] sends nothing");
    assert.match(tt.out.join(""), /This sends \d+ file and folder names from 1 folder to mock-cloud \(127\.0\.0\.1, an outside model, reached through this computer\)/);

    // ── the dashboard's suggestions API
    let api = "";
    const res = { writeHead: () => res, end: (b: string) => { api = b; } } as unknown as ServerResponse;
    await getSuggestions({ arbiter: { policySuggestions: (s) => client.policySuggestions(s) as never, resolvePolicyProposal: (async () => { throw new Error("unused"); }) as never }, home, workspaces: async () => [] }, res);
    const rows = (JSON.parse(api) as { suggestions: Array<{ source: string; by: string }> }).suggestions;
    assert.ok(rows.some((r) => r.source === "model-names" && r.by === "Suggested by your model mock-cloud"), api);

    // ── no canary anywhere: the store, the events, the outputs, --json, the API, the log
    const parts = [outputs.join("\n"), api, logs.join("\n"), readFileSync(policy, "utf8")];
    const db = new Database(join(dir, "mandu.db"));
    try { parts.push(JSON.stringify(db.prepare("SELECT * FROM policy_proposals").all())); } finally { db.close(); }
    const ev = join(dir, "events");
    const walk = (d: string): void => {
      if (!existsSync(d)) return;
      for (const f of readdirSync(d, { withFileTypes: true })) {
        const p = join(d, f.name);
        if (f.isDirectory()) walk(p); else parts.push(readFileSync(p, "utf8"));
      }
    };
    walk(ev);
    const everything = parts.join("\n");
    assert.ok(!everything.includes(ANSWER_CANARY), "no answer canary in the store, the events, the terminal, --json, the API or the log");
    noKey("the outputs, the store and the events", everything);
    const calls = everything.split("\n").filter((l) => l.includes('"policy_model_call"'));
    assert.equal(calls.length, 1, "one policy_model_call event for the one run");
    assert.ok(!calls[0]!.includes("clients"), "the event carries counts only");
  } finally {
    client.close();
    await server.close();
  }
});
