/**
 * rules-by-who.test — the Rules page's per-principal view (dashboard.md
 * §4.25aa, confidentiality plan 13 §5.3 and Figure 7): the same file rules
 * read per program (the `readers:` lists), per host (the rules' hosts) and
 * per AI (the levels), in the product's closed vocabulary.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import type { PolicyDocumentRow } from "../../../src/policy-model.js";
import { toPolicyPanelViewModel } from "../../../src/view-model/policy-panel.js";
import { BY_WHO_WORDS, byWhoRules, pathOpeners, toByWhoVM, type ByWhoRow, type ByWhoVM } from "../../../src/view-model/rules-by-who.js";

const HOME = "/home/u";
type Paths = PolicyDocumentRow["paths"];

/** Plan 13 Figure 3's example, as policy.yaml rules. */
const PATHS: Paths = [
  { path: "/home/u/proj/README.md", level: "public", bindings: [], recursive: false },
  { path: "/home/u/proj/contract.pdf", level: "any-model", bindings: ["smtp.gmail.com"], recursive: false },
  { path: "/home/u/proj/customers.csv", level: "local-model", bindings: [], recursive: false, readers: [{ app: "python3", script: "/home/u/proj/report.py", prints: "nothing" }] },
  { path: "/home/u/proj/.env", level: "no-model", bindings: ["github.com", "api.stripe.com"], recursive: false, readers: [{ app: "python3", script: "/home/u/proj/report.py", prints: "nothing" }, "psql"] },
  { path: "/home/u/.my.cnf", level: "no-model", bindings: ["db.internal:5432"], recursive: false, readers: ["mysql"], readersAdmitNothing: [false], readersReadTwin: [false] },
  { path: "/home/u/.ssh", level: "no-model", bindings: [], recursive: true, readers: ["ssh"], others: "twin" },
];
const MODELS = [
  { name: "vllm-1", url: "http://127.0.0.1:8000/v1", wire: "openai-chat", local: true },
  { name: "openai", url: "https://api.openai.com/v1", wire: "openai-chat", local: false },
];

const row = (rows: readonly ByWhoRow[], name: string) => {
  const r = rows.find((x) => x.name === name);
  assert.ok(r, `a row for ${name}: ${rows.map((x) => x.name).join(" | ")}`);
  return r;
};
/** A row's lists as `label: path (more), …`, the way a person reads them. */
const lists = (r: ByWhoRow) => Object.fromEntries(r.groups.map((g) => [g.label, g.items.map((i) => i.path + (i.reach || i.how ? ` (${[i.reach, i.how].filter(Boolean).join(", ")})` : ""))]));

const vm = (): ByWhoVM => toByWhoVM(byWhoRules(PATHS, []), MODELS, { home: HOME });

test("pathOpeners: each reader entry as the arbiter judges it; no readers: list is null", () => {
  assert.equal(pathOpeners({ path: "/x", level: "no-model", bindings: [], recursive: false }), null);
  assert.deepEqual(pathOpeners({ path: "/x", level: "no-model", bindings: [], recursive: false, readers: ["ssh", { app: "deploy", prints: "nothing" }, "psql", "aws", "bash"] }), [
    { name: "ssh", script: null, how: "checked" },
    { name: "deploy", script: null, how: "word" },
    { name: "psql", script: null, how: "never" },
    { name: "aws", script: null, how: "masked" },
    { name: "bash", script: null, how: "never" },
  ]);
  // The arbiter's per-entry judgment wins over the name rule (a renamed copy of a printer).
  assert.deepEqual(pathOpeners({ path: "/x", level: "no-model", bindings: [], recursive: false, readers: ["mytool"], readersAdmitNothing: [true] })?.[0]?.how, "never");
  assert.deepEqual(pathOpeners({ path: "/x", level: "no-model", bindings: [], recursive: false, readers: [{ app: "python3", script: "/opt/r.py" }] })?.[0], { name: "python3", script: "/opt/r.py", how: "masked" }, "a pinned script is no vetted program: it needs the human's word");
});

test("per program: what each may open raw and how, what it gets masked, never gets, or is refused (Figure 7 (b))", () => {
  const { programs } = vm();
  assert.deepEqual(programs.rows.map((r) => r.name), ["mysql", "psql", "python3 running ~/proj/report.py", "ssh", "Any other program"]);
  assert.deepEqual(lists(row(programs.rows, "python3 running ~/proj/report.py")), {
    [BY_WHO_WORDS.opens]: ["~/proj/.env (your word)", "~/proj/customers.csv (your word)"],
    [BY_WHO_WORDS.masked]: ["~/.ssh (and everything inside)", "~/proj/contract.pdf"],
    [BY_WHO_WORDS.refused]: ["~/.my.cnf"],
  });
  assert.deepEqual(lists(row(programs.rows, "mysql")), {
    [BY_WHO_WORDS.opens]: ["~/.my.cnf (checked by Mandu)"],
    [BY_WHO_WORDS.masked]: ["~/.ssh (and everything inside)", "~/proj/contract.pdf"],
    [BY_WHO_WORDS.refused]: ["~/proj/.env", "~/proj/customers.csv"],
  });
  // A database shell is never a reader: it prints what it reads.
  assert.deepEqual(lists(row(programs.rows, "psql"))[BY_WHO_WORDS.never], ["~/proj/.env"]);
  assert.equal(lists(row(programs.rows, "psql"))[BY_WHO_WORDS.opens], undefined);
  assert.deepEqual(lists(row(programs.rows, "ssh"))[BY_WHO_WORDS.opens], ["~/.ssh (and everything inside, checked by Mandu)"]);
  // Any other program: a masked copy where there is no list or `others: twin`, else refused.
  const any = row(programs.rows, "Any other program");
  assert.equal(any.kind, "any");
  assert.deepEqual(lists(any), {
    [BY_WHO_WORDS.masked]: ["~/.ssh (and everything inside)", "~/proj/contract.pdf"],
    [BY_WHO_WORDS.refused]: ["~/.my.cnf", "~/proj/.env", "~/proj/customers.csv"],
  });
  assert.equal(programs.note, BY_WHO_WORDS.programsNote);
});

test("per host: which files reach it without asking (the rules' hosts); any other host gets no secret (Figure 7 (a))", () => {
  const { hosts } = vm();
  assert.deepEqual(hosts.rows.map((r) => r.name), ["api.stripe.com", "db.internal:5432", "github.com", "smtp.gmail.com", "Any other host"]);
  assert.deepEqual(lists(row(hosts.rows, "api.stripe.com")), { [BY_WHO_WORDS.sends]: ["~/proj/.env"] });
  assert.deepEqual(lists(row(hosts.rows, "smtp.gmail.com")), { [BY_WHO_WORDS.sends]: ["~/proj/contract.pdf"] });
  const any = row(hosts.rows, "Any other host");
  assert.equal(any.about, BY_WHO_WORDS.anyHostAbout);
  assert.deepEqual(lists(any), { [BY_WHO_WORDS.notSecretAnywhere]: ["~/proj/README.md"] });
  assert.match(hosts.note, /may send only where both may go/, "the join is intersection (plan 13 D1)");
});

test("per AI: any AI reads Not secret, may read any-model when it asks; your own AI also reads local-model (Figure 7 (a))", () => {
  const { models } = vm();
  assert.deepEqual(models.rows.map((r) => r.name), ["Any AI", "vllm-1"], "an outside model declared is one of any AI");
  assert.deepEqual(lists(row(models.rows, "Any AI")), {
    [BY_WHO_WORDS.asWritten]: ["~/proj/README.md"],
    [BY_WHO_WORDS.whenAsks]: ["~/proj/contract.pdf"],
    [BY_WHO_WORDS.alwaysMasked]: ["~/.my.cnf", "~/.ssh (and everything inside)", "~/proj/.env", "~/proj/customers.csv"],
  });
  const own = row(models.rows, "vllm-1");
  assert.equal(own.about, "Your own AI, on this computer.");
  assert.deepEqual(lists(own), {
    [BY_WHO_WORDS.asWritten]: ["~/proj/README.md"],
    [BY_WHO_WORDS.whenAsks]: ["~/proj/contract.pdf", "~/proj/customers.csv"],
    [BY_WHO_WORDS.alwaysMasked]: ["~/.my.cnf", "~/.ssh (and everything inside)", "~/proj/.env"],
  });
  // No own AI declared: the local-model files are read by no AI, and the row says so.
  const none = toByWhoVM(byWhoRules(PATHS, []), [], { home: HOME }).models.rows;
  assert.deepEqual(none.map((r) => r.name), ["Any AI", "Your own AI"]);
  assert.equal(row(none, "Your own AI").about, BY_WHO_WORDS.noOwnAIAbout);
  assert.deepEqual(lists(row(none, "Your own AI")), { [BY_WHO_WORDS.alwaysMasked]: ["~/proj/customers.csv"] });
});

test("an unknown level reads as no AI (fail closed); labels made on the page join, one per path, policy.yaml first", () => {
  const rules = byWhoRules(
    [{ path: "/home/u/odd", level: "mystery", bindings: [], recursive: false }],
    [
      { path: "/home/u/odd", level: "public", bindings: [], recursive: false, source: "user" },
      { path: "/home/u/ws/.env", level: "any-model", bindings: ["api.example.com"], recursive: false, source: "user" },
      { path: "/home/u/from-yaml", level: "public", bindings: [], recursive: false, source: "policy-file" },
      { path: "**/secrets/**", level: "no-model", bindings: [], recursive: true, glob: true, source: "user" },
    ],
  );
  assert.deepEqual(rules.map((r) => r.path), ["/home/u/odd", "/home/u/ws/.env", "**/secrets/**"], "the policy file's labels come from paths:, once");
  const v = toByWhoVM(rules, null, { home: HOME });
  assert.deepEqual(lists(row(v.models.rows, "Any AI")), {
    [BY_WHO_WORDS.whenAsks]: ["~/ws/.env"],
    [BY_WHO_WORDS.alwaysMasked]: ["**/secrets/** (every matching file)", "~/odd"],
  });
  assert.deepEqual(lists(row(v.hosts.rows, "api.example.com")), { [BY_WHO_WORDS.sends]: ["~/ws/.env"] });
  assert.deepEqual(v.programs.rows.map((r) => r.name), ["Any other program"]);
  assert.equal(row(v.programs.rows, "Any other program").about, BY_WHO_WORDS.noProgram);
  assert.equal(v.secretCount, 3);
});

test("unread is not empty: no rules gives available false; no secret rule gives empty lists; partial is said", () => {
  const unread = toByWhoVM(null, null);
  assert.equal(unread.available, false);
  const none = toByWhoVM([], null);
  assert.equal(none.available, true);
  assert.deepEqual([none.programs.rows, none.hosts.rows, none.models.rows], [[], [], []]);
  assert.equal(toByWhoVM([], null, { partial: true }).partial, true);
});

test("the words: the closed vocabulary, no inspector term, no retired word, never a value", () => {
  // The home page's sweep (home-view-model.test.ts) and the retired words of §4.25d / §4.25u.
  const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter)\b|\$MDU:/i;
  const RETIRED = /placeholder|twin|taint|binding|reader|opener|principal|level|policy\.yaml|no-model|any-model|local-model/i;
  const v = vm();
  const copy = [
    ...Object.values(BY_WHO_WORDS),
    ...[v.programs, v.hosts, v.models].flatMap((t) => [t.note, ...t.rows.flatMap((r) => [r.name, r.about ?? "", ...r.groups.flatMap((g) => [g.label, ...g.items.map((i) => `${i.reach ?? ""} ${i.how ?? ""}`)])])]),
  ].join("\n");
  assert.doesNotMatch(copy, FORBIDDEN);
  assert.doesNotMatch(copy, RETIRED);
  assert.match(BY_WHO_WORDS.masked, /masked/);
});

test("the Rules row's Opens it line and the per-program view read the same judgment", () => {
  const doc = { lists: {}, rules: {}, userRules: [], paths: PATHS, models: MODELS } as unknown as PolicyDocumentRow;
  const panel = toPolicyPanelViewModel({ specId: "x", rules: [], document: doc } as never);
  const env = panel.yourRules!.find((r) => r.id === "lock:/home/u/proj/.env")!;
  assert.equal(env.plain?.opens, "python3 (your word) may open the real file. psql never gets the real file: it prints or runs what it reads. Other programs are refused.");
  const programs = vm().programs.rows;
  assert.ok(lists(row(programs, "python3 running ~/proj/report.py"))[BY_WHO_WORDS.opens]!.includes("~/proj/.env (your word)"));
  assert.deepEqual(lists(row(programs, "psql"))[BY_WHO_WORDS.never], ["~/proj/.env"]);
});

test("per host, plan 13 §5.2: a rule with values: names each value at its own hosts, the file's own hosts only for the values with no entry, and the whole file only where every value may go", () => {
  const paths: Paths = [
    { path: "/home/u/ws/app/.env", level: "no-model", bindings: ["files.example"], recursive: false,
      values: [{ key: "STRIPE_KEY", bindings: ["api.stripe.com"] }, { key: "AWS_*", bindings: ["amazonaws.com"] }], wholeBindings: [] },
    { path: "/home/u/ws/shared.env", level: "no-model", bindings: ["api.stripe.com"], recursive: false,
      values: [{ key: "SHARED_KEY", bindings: ["api.stripe.com", "hooks.example.com"] }], wholeBindings: ["api.stripe.com"] },
  ];
  const { hosts } = toByWhoVM(byWhoRules(paths, []), [], { home: HOME });
  assert.deepEqual(hosts.rows.map((r) => r.name), ["amazonaws.com", "api.stripe.com", "files.example", "hooks.example.com", "Any other host"]);
  assert.deepEqual(lists(row(hosts.rows, "api.stripe.com")), { [BY_WHO_WORDS.sends]: ["~/ws/app/.env: STRIPE_KEY", "~/ws/shared.env"] },
    "a value, not the whole file; a file whose every value goes there, whole");
  assert.deepEqual(lists(row(hosts.rows, "amazonaws.com")), { [BY_WHO_WORDS.sends]: ["~/ws/app/.env: AWS_*"] });
  assert.deepEqual(lists(row(hosts.rows, "files.example")), { [BY_WHO_WORDS.sends]: ["~/ws/app/.env: any other value"] }, "the file's own host: the values with no entry");
  assert.deepEqual(lists(row(hosts.rows, "hooks.example.com")), { [BY_WHO_WORDS.sends]: ["~/ws/shared.env: SHARED_KEY"] });
});

test("dashboard.md §4.25f a rule on a file reads as a file: a rule reaching everything inside a file is listed as that file, from policy.yaml or the page", () => {
  const paths: Paths = [
    // As a saved Keys Mandu found suggestion writes it: no `recursive:` key.
    { path: "/home/u/proj/deploy/staging.conf", level: "no-model", bindings: [], recursive: true },
    { path: "/home/u/proj/secrets", level: "no-model", bindings: [], recursive: true },
  ];
  const labels = [{ path: "/home/u/proj/inspector.token", level: "no-model", bindings: [], recursive: true, source: "user" }];
  const masked = (files?: ReadonlySet<string>) =>
    lists(row(toByWhoVM(byWhoRules(paths, labels, files), null, { home: HOME }).programs.rows, "Any other program"))[BY_WHO_WORDS.masked];
  // What server/path-kinds.ts found on disk.
  assert.deepEqual(masked(new Set(["/home/u/proj/deploy/staging.conf", "/home/u/proj/inspector.token"])),
    ["~/proj/deploy/staging.conf", "~/proj/inspector.token", "~/proj/secrets (and everything inside)"],
    "a file alone; a folder keeps its reach");
  // Not looked at: the words the rule says, as before.
  assert.deepEqual(masked(),
    ["~/proj/deploy/staging.conf (and everything inside)", "~/proj/inspector.token (and everything inside)", "~/proj/secrets (and everything inside)"]);
});

test("dashboard.md §4.25aa: every item carries its rule's own path, so the page can open that rule's row: a per-value item its file's, a pattern and a page label theirs", () => {
  const paths: Paths = [
    ...PATHS,
    { path: "/home/u/ws/app/.env", level: "no-model", bindings: ["files.example"], recursive: false,
      values: [{ key: "STRIPE_KEY", bindings: ["api.stripe.com"] }], wholeBindings: [] },
    { path: "**/secrets/**", level: "no-model", bindings: [], recursive: true },
  ];
  const labels = [{ path: "/home/u/ws/memo.txt", level: "any-model", bindings: ["api.example.com"], recursive: false, source: "user" }];
  const v = toByWhoVM(byWhoRules(paths, labels), MODELS, { home: HOME });
  const known = new Set([...paths.map((p) => p.path), ...labels.map((l) => l.path)]);
  const items = [v.programs, v.hosts, v.models].flatMap((t) => t.rows.flatMap((r) => r.groups.flatMap((g) => g.items)));
  assert.ok(items.length > 20);
  for (const i of items) {
    assert.ok(known.has(i.rule), `${i.path}: ${i.rule} is a rule's own path`);
    // The path shown is the rule's, with the home as ~ and maybe ": KEY".
    assert.ok(i.path.startsWith(i.rule.replace(HOME, "~")), `${i.path} shows ${i.rule}`);
  }
  const at = (host: string) => row(v.hosts.rows, host).groups.flatMap((g) => g.items);
  assert.deepEqual(at("api.stripe.com").map((i) => [i.path, i.rule]), [
    ["~/proj/.env", "/home/u/proj/.env"],
    ["~/ws/app/.env: STRIPE_KEY", "/home/u/ws/app/.env"],
  ], "a value opens its file's rule");
  assert.deepEqual(at("files.example").map((i) => i.rule), ["/home/u/ws/app/.env"]);
  assert.deepEqual(at("api.example.com").map((i) => i.rule), ["/home/u/ws/memo.txt"], "a label made on the page");
  const masked = row(v.models.rows, "Any AI").groups.find((g) => g.label === BY_WHO_WORDS.alwaysMasked)!.items;
  assert.equal(masked.find((i) => i.path === "**/secrets/**")?.rule, "**/secrets/**", "a pattern");
});
