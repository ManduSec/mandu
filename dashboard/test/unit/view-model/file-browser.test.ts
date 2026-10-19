/**
 * file-browser view model (dashboard.md §4.25m): the words for each listed
 * file's label and where it came from, and the plan that turns the page's
 * pending changes into policy.yaml edits and in-place changes to rules kept in
 * the page's own store.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  fileLabel,
  levelRank,
  looseningWords,
  maskedCopyWords,
  pageKey,
  pageLooseningWords,
  planFileChanges,
  tildePath,
  whyWords,
  type PathLevelsEntryWire,
  type WhyPathWire,
} from "../../../src/view-model/file-browser.js";
import { TERMS } from "../../../src/view-model/rule-words.js";

const HOME = "/home/u";
const e = (path: string, level: string, rule: string | null, store: PathLevelsEntryWire["store"] = null, bindings: string[] = []): PathLevelsEntryWire =>
  ({ path, level, bindings, rule, store });
const resolve = (p: string) => (p.startsWith("~/") ? HOME + p.slice(1) : p.startsWith("/") || p.startsWith("**/") ? p : null);

test("tildePath: HOME becomes ~, a sibling that shares the prefix does not", () => {
  assert.equal(tildePath("/home/u", HOME), "~");
  assert.equal(tildePath("/home/u/ws/.env", HOME), "~/ws/.env");
  assert.equal(tildePath("/home/user2/x", HOME), "/home/user2/x");
  assert.equal(tildePath("/etc/x", "/"), "/etc/x");
});

test("fileLabel: each source in the page's words, and only the person's own rule on the path is removable", () => {
  const yours = fileLabel(e("/home/u/ws/config", "no-model", "label:/home/u/ws/config", "policy"), HOME);
  assert.deepEqual([yours.source, yours.words, yours.from, yours.removable, yours.levelClass], ["yours", TERMS.hidden, "Your rule", true, "strict"]);
  const page = fileLabel(e("/home/u/ws/notes.md", "any-model", "label:/home/u/ws/notes.md", "page", ["api.example.com"]), HOME);
  assert.equal(page.source, "yours");
  assert.equal(page.store, "page");
  assert.equal(page.words, `${TERMS.readable}; may be sent to api.example.com`);
  const inherited = fileLabel(e("/home/u/ws/config/db.yaml", "no-model", "label:/home/u/ws/config", "policy"), HOME);
  assert.deepEqual([inherited.source, inherited.from, inherited.removable], ["inherited", "From your rule on ~/ws/config", false]);
  const pattern = fileLabel(e("/home/u/ws/k.pem", "any-model", "label:**/*.pem", "policy"), HOME);
  assert.deepEqual([pattern.source, pattern.from, pattern.removable], ["pattern", "Matches your rule **/*.pem", false]);
  const builtin = fileLabel(e("/home/u/ws/.env", "no-model", "shape:.env*"), HOME);
  assert.deepEqual([builtin.source, builtin.from], ["builtin", "Built in: environment files"]);
  assert.equal(fileLabel(e("/home/u/.ssh", "no-model", "prefix:~/.ssh"), HOME).from, "Built in: ~/.ssh");
  assert.equal(fileLabel(e("/home/u/x", "no-model", "shape:new-shape"), HOME).from, "Built in: new-shape", "an unknown built-in still names itself");
  // the catalog's content tier and the 2026-10-19 shapes (secret-discovery.md §2.6)
  const found = fileLabel(e("/home/u/ws/accounts/power.yaml", "no-model", "content:secret-key"), HOME);
  assert.deepEqual([found.source, found.from, found.removable], ["builtin", "Built in: a saved password or key Mandu found in it", false]);
  // a personal document (§2.7)
  assert.equal(fileLabel(e("/home/u/ws/bank/statement.md", "no-model", "content:personal-document"), HOME).from, "Built in: a personal document Mandu recognised");
  assert.equal(fileLabel(e("/home/u/ws/.launchdeck/auth.json", "no-model", "shape:tool-login-file"), HOME).from, "Built in: a tool's saved sign-in");
  assert.equal(fileLabel(e("/home/u/ws/api/http-client.private.env.json", "no-model", "shape:*.private.env.json"), HOME).from, "Built in: HTTP client private settings");
  const written = fileLabel(e("/home/u/ws/out.txt", "any-model", "derived:/home/u/ws/out.txt"), HOME);
  assert.deepEqual([written.source, written.from], ["written", "Written by the AI after it read a secret"]);
  const key = fileLabel(e("/home/u/.config/k", "no-model", "label:/home/u/.config/k", "models"), HOME);
  assert.deepEqual([key.source, key.removable], ["model-key", false]);
  const none = fileLabel(e("/home/u/ws/README.md", "public", null), HOME);
  assert.deepEqual([none.source, none.words, none.from, none.levelClass], ["none", "Like any other file", "", "public"]);
  const declass = fileLabel(e("/home/u/ws/test/.env", "public", "label:/home/u/ws/test/.env", "policy"), HOME);
  assert.equal(declass.words, TERMS.notSecret);
  // An unknown level never reads as public.
  assert.equal(fileLabel(e("/x", "weird", "label:/x", "policy"), HOME).levelClass, "unknown");
});

test("levelRank: public < any-model < local-model < no-model; unknown is the strictest", () => {
  assert.deepEqual(["public", "any-model", "local-model", "no-model", "weird"].map(levelRank), [0, 1, 2, 3, 3]);
});

test("planFileChanges: policy.yaml edits by default; a folder covers what is inside, a file only itself; patterns as written", () => {
  const plan = planFileChanges([
    { path: "~/ws/config", level: "no-model", recursive: true },
    { path: "/home/u/ws/.env", level: "public", recursive: false },
    { path: "**/*.pem", level: "any-model", bindings: ["api.example.com"] },
    { path: "/home/u/ws/old", level: null },
  ], resolve, []);
  assert.ok(typeof plan !== "string");
  assert.deepEqual(plan.edits, [
    { op: "lock-path", path: "/home/u/ws/config", level: "no-model" },
    { op: "lock-path", path: "/home/u/ws/.env", level: "public", recursive: false },
    { op: "lock-path", path: "**/*.pem", level: "any-model", bindings: ["api.example.com"] },
    { op: "unlock-path", path: "/home/u/ws/old" },
  ]);
  assert.deepEqual(plan.page, []);
  assert.deepEqual(plan.pageLoosens, []);
});

test("planFileChanges: a rule kept in the page's store is changed there, in place; loosening it is named for confirmation", () => {
  const page = [
    { path: "/home/u/ws/notes.md", level: "no-model", bindings: [], recursive: false },
    { path: "/home/u/ws/pub", level: "public", bindings: [], recursive: true },
    { path: "/home/u/ws/keys", level: "any-model", bindings: ["a.example"], recursive: false },
  ];
  const plan = planFileChanges([
    { path: "/home/u/ws/notes.md", level: "any-model", recursive: false }, // weaker
    { path: "/home/u/ws/pub/", level: null },                               // removing a public rule: not weaker
    { path: "/home/u/ws/keys", level: "any-model", bindings: ["b.example"], recursive: false }, // a new place to send to
  ], resolve, page);
  assert.ok(typeof plan !== "string");
  assert.deepEqual(plan.edits, []);
  assert.deepEqual(plan.page, [
    { act: "set", path: "/home/u/ws/notes.md", level: "any-model", bindings: [], recursive: false },
    { act: "remove", path: "/home/u/ws/pub" },
    { act: "set", path: "/home/u/ws/keys", level: "any-model", bindings: ["b.example"], recursive: false },
  ]);
  assert.deepEqual(plan.pageLoosens.map((l) => l.key), [pageKey("/home/u/ws/notes.md"), pageKey("/home/u/ws/keys")]);
  // Stricter in place: nothing to confirm; widening a strict rule's reach is stricter too.
  const tight = planFileChanges([{ path: "/home/u/ws/pub", level: "no-model", recursive: true }], resolve, page);
  assert.ok(typeof tight !== "string");
  assert.deepEqual(tight.pageLoosens, []);
  // Removing a secret rule kept there is weaker.
  const rm = planFileChanges([{ path: "/home/u/ws/notes.md", level: null }], resolve, page);
  assert.ok(typeof rm !== "string");
  assert.equal(rm.pageLoosens.length, 1);
  // Widening a non-strict rule to everything inside is weaker.
  const reach = planFileChanges([{ path: "/home/u/ws/keys", level: "any-model", bindings: ["a.example"], recursive: true }], resolve, page);
  assert.ok(typeof reach !== "string");
  assert.equal(reach.pageLoosens.length, 1);
});

test("planFileChanges: refuses what is not a list of valid changes", () => {
  const bad: Array<[unknown, RegExp]> = [
    [[], /non-empty/],
    ["x", /non-empty/],
    [Array.from({ length: 201 }, (_, i) => ({ path: `/a/${i}`, level: "no-model" })), /at most 200/],
    [[{ path: "relative", level: "no-model" }], /must start with/],
    [[{ path: "/a", level: "secret" }], /level must be one of/],
    [[{ path: "/a", level: undefined }], /level must be one of/],
    [[{ path: "/a", level: "no-model", bindings: ["bad host/path"] }], /host names/],
    [[{ path: "/a", level: "no-model", recursive: "yes" }], /true or false/],
    [[{ path: "/a", level: "no-model" }, { path: "/a/", level: "public" }], /listed twice/],
    [[null], /must be an object/],
  ];
  for (const [raw, re] of bad) {
    const r = planFileChanges(raw, resolve, []);
    assert.equal(typeof r, "string", JSON.stringify(raw)?.slice(0, 60));
    assert.match(r as string, re);
  }
});

test("looseningWords: rebuilt from the edit, in the page's terms, never the inspector's", () => {
  const edits = [
    { op: "lock-path" as const, path: "/home/u/ws", level: "public" as const },
    { op: "lock-path" as const, path: "/home/u/ws/k.txt", level: "any-model" as const, recursive: false },
    { op: "unlock-path" as const, path: "/home/u/ws/old" },
  ];
  const a = looseningWords({ facet: "paths", subject: "/home/u/ws" }, edits, HOME);
  assert.equal(a.subject, "~/ws");
  assert.match(a.detail, /^Becomes Not secret, even where Mandu treats a file as secret by default.*everything inside/);
  assert.match(looseningWords({ facet: "paths", subject: "/home/u/ws/k.txt" }, edits, HOME).detail, /^Becomes Any AI, when it asks, which lets more reach/);
  assert.doesNotMatch(looseningWords({ facet: "paths", subject: "/home/u/ws/k.txt" }, edits, HOME).detail, /everything inside/);
  assert.match(looseningWords({ facet: "paths", subject: "/home/u/ws/old" }, edits, HOME).detail, /^Loses its own rule/);
  assert.match(looseningWords({ facet: "paths", subject: "**/ws-*/**" }, edits, HOME).detail, /takes over from your rule here/);
  for (const r of [a]) assert.doesNotMatch(r.detail, /\b(lock|catalog|no-model|any-model|arbiter)\b/);
});

// dashboard.md §4.25f *A rule on a file reads as a file*: a rule reaching
// everything inside a path that is a FILE (a saved Keys Mandu found
// suggestion: no `recursive:` key) was asked about as a folder, "This covers
// everything inside it that has no rule of its own". Words only: the plan's
// keys are the same.
test("looseningWords / pageLooseningWords: a rule reaching everything inside a file is asked about as that file; a folder keeps its words", () => {
  const edits = [
    { op: "lock-path" as const, path: "/home/u/ws/.env", level: "any-model" as const },
    { op: "lock-path" as const, path: "/home/u/ws/deploy.conf", level: "public" as const },
    { op: "lock-path" as const, path: "/home/u/ws/secrets", level: "any-model" as const },
    { op: "lock-path" as const, path: "/home/u/ws/k.txt", level: "any-model" as const, recursive: false },
  ];
  const files = new Set(["/home/u/ws/.env", "/home/u/ws/deploy.conf", "/home/u/ws/k.txt"]);
  const words = (subject: string, f?: ReadonlySet<string>) => looseningWords({ facet: "paths", subject }, edits, HOME, f).detail;
  assert.equal(words("/home/u/ws/.env", files), "Becomes Any AI, when it asks, which lets more reach an AI or leave this computer than now.");
  assert.equal(words("/home/u/ws/deploy.conf", files), `Becomes ${TERMS.notSecret}, even where Mandu treats a file as secret by default (a .env file or a key, for example).`);
  assert.equal(words("/home/u/ws/secrets", files), "Becomes Any AI, when it asks, which lets more reach an AI or leave this computer than now. This covers everything inside it that has no rule of its own.", "a folder keeps its words");
  assert.equal(words("/home/u/ws/k.txt", files), words("/home/u/ws/k.txt"), "a rule on that path only says nothing of an inside either way");
  // No set (a stat that did not answer): the words the rule says, as before.
  assert.match(words("/home/u/ws/.env"), /This covers everything inside it that has no rule of its own\.$/);
  assert.match(words("/home/u/ws/.env", new Set()), /This covers everything inside it/);

  // The page's own store: the same for an older rule made on the page.
  const page = [
    { path: "/home/u/ws/notes.md", level: "no-model", bindings: [], recursive: true },
    { path: "/home/u/ws/old", level: "no-model", bindings: [], recursive: true },
    { path: "/home/u/ws/one.txt", level: "no-model", bindings: [], recursive: false },
  ];
  const plan = planFileChanges([
    { path: "/home/u/ws/notes.md", level: "any-model" },
    { path: "/home/u/ws/old", level: "any-model" },
    { path: "/home/u/ws/one.txt", level: "any-model", recursive: false },
  ], resolve, page);
  assert.ok(typeof plan !== "string");
  assert.deepEqual(plan.pageLoosens.map((l) => l.key), [pageKey("/home/u/ws/notes.md"), pageKey("/home/u/ws/old"), pageKey("/home/u/ws/one.txt")], "the same three to confirm");
  const pageFiles = new Set(["/home/u/ws/notes.md", "/home/u/ws/one.txt"]);
  const [notes, old, one] = plan.pageLoosens.map((l) => pageLooseningWords(l, HOME, pageFiles));
  // Each with its words as parts too (no host here: one text; §4.25u).
  const said = (subject: string, detail: string) => ({ subject, detail, detailParts: [{ kind: "text", text: detail }] });
  assert.deepEqual(notes, said("~/ws/notes.md", "Becomes Any AI, when it asks."));
  assert.deepEqual(old, said("~/ws/old", "Becomes Any AI, when it asks, and so does everything inside it that has no rule of its own."), "a folder keeps its words");
  assert.deepEqual(one, said("~/ws/one.txt", "Becomes Any AI, when it asks."));
  assert.equal(pageLooseningWords(plan.pageLoosens[0]!, HOME).detail, "Becomes Any AI, when it asks, and so does everything inside it that has no rule of its own.", "no set: the words the rule says");
  // Removing a rule: the same words for a file and a folder.
  const rm = planFileChanges([{ path: "/home/u/ws/notes.md", level: null }], resolve, page);
  assert.ok(typeof rm !== "string");
  assert.match(pageLooseningWords(rm.pageLoosens[0]!, HOME, pageFiles).detail, /^Loses its own rule/);
});

// 2026-10-09: "only the values are hidden" was said of every file whose
// path has a structured shape (a labelled .mcp.json whose list values
// stayed raw, a .json the arbiter in fact hid whole). The arbiter now says
// what it made of the file, and the page says that.
test("whyWords: the masked copy line says what the arbiter makes of the file, not what its path suggests", () => {
  const base: WhyPathWire = { path: "/home/u/w/.mcp.json", axis: true, level: "no-model", rule: "label:/home/u/w/.mcp.json", bindings: [], outranked: [], readers: [], others: null, consumers: [], twinShape: "json-keys", verdicts: [] };
  const entry = e("/home/u/w/.mcp.json", "no-model", "label:/home/u/w/.mcp.json", "policy");
  const copy = (w: WhyPathWire) => whyWords(w, entry, [], HOME).lines.find((l) => l.term === "The masked copy")?.text;
  assert.equal(copy({ ...base, twin: { form: "structured", shape: "json-keys", fields: 4 } }), "Keeps the file's shape and names; each secret value Mandu recognizes is hidden (4 now).");
  // Also true of a file whose only recognized secret is a list item (2026-10-10).
  assert.equal(copy({ ...base, twin: { form: "whole-file", shape: "json-keys", fields: 0 } }), "Hides the whole file: Mandu finds no secret value in it that it can hide in place.");
  assert.equal(copy({ ...base, twinShape: "ssh-config", twin: { form: "own-text", shape: "ssh-config", fields: 0 } }), "Is the file as it is: Mandu recognizes no secret value in it.");
  // An older arbiter: the path's shape, and what it depends on; no shape, no line.
  assert.match(copy(base)!, /^Keeps the file's shape and names when Mandu recognizes a secret value in it, and hides each value it recognizes; otherwise the whole file is hidden\.$/);
  assert.equal(copy({ ...base, twinShape: null }), undefined);
  assert.equal(maskedCopyWords({ twinShape: null }), null);
  for (const w of [base, { ...base, twin: { form: "structured" as const, shape: "json-keys", fields: 1 } }]) {
    assert.doesNotMatch(copy(w)!, /only the values are hidden/);
    assert.doesNotMatch(copy(w)!, /\b(symbol|twin|arbiter|catalog)\b/i, "the page's plain words");
  }
});

test("whyWords: an ssh config's withheld commands, by line and keyword, with why and the way out (plan 10 §11.13.3)", () => {
  const base: WhyPathWire = { path: "/home/u/.ssh/config", axis: true, level: "no-model", rule: "prefix:~/.ssh", bindings: [], outranked: [], readers: [], others: null, consumers: [], twinShape: "ssh-config", verdicts: [] };
  const vm = whyWords({ ...base, withheld: [{ line: 7, keyword: "ProxyCommand" }] }, e("/home/u/.ssh/config", "no-model", "prefix:~/.ssh"), [], HOME);
  const line = vm.lines.find((l) => l.term === "Commands left out")!;
  assert.match(line.text, /^line 7 \(ProxyCommand\)\. Programs the AI runs get this file without that command, because .*run code holding one/);
  assert.match(line.text, /ProxyJump/);
  assert.match(line.text, /readers: in policy\.yaml/);
  assert.match(line.text, /outside the AI\.$/);
  assert.doesNotMatch(line.text, /\b(symbol|twin|arbiter|catalog)\b/i, "the page's plain words");
  assert.ok(!whyWords(base, e("/home/u/.ssh/config", "no-model", "prefix:~/.ssh"), [], HOME).lines.some((l) => l.term === "Commands left out"), "an older arbiter, or nothing withheld");
  // the programs holding the real file are still listed beside it
  const both = whyWords({ ...base, withheld: [{ line: 3, keyword: "RemoteCommand" }] }, e("/home/u/.ssh/config", "no-model", "prefix:~/.ssh"), [{ app: "ssh", since: 0 }], HOME);
  assert.match(both.lines.find((l) => l.term === "Programs that read the real file")!.text, /^ssh/);
  assert.match(both.lines.find((l) => l.term === "Commands left out")!.text, /^line 3 \(RemoteCommand\)\./);
});

test("whyWords (plan 13 D8, 2026-10-03): the page says what the ARBITER decides per entry, a renamed copy by its hash included; the name rule is only the fallback", () => {
  const base: WhyPathWire = { path: "/home/u/ws/.env", axis: true, level: "no-model", rule: "label:/home/u/ws/.env", bindings: [], outranked: [], readers: [], others: "twin", consumers: [], twinShape: null, verdicts: [] };
  const entry = e("/home/u/ws/.env", "no-model", "label:/home/u/ws/.env", "policy");
  const readers = [{ app: "mytool", path: "/home/u/bin/mytool", sha256: "a".repeat(64), output: "clear", prints: "nothing" }, { app: "mycat", path: "/home/u/bin/mycat", sha256: "b".repeat(64), prints: "nothing" }, "ssh-add"];
  // the code before: by name, mytool and mycat looked like leaf programs
  const byName = whyWords({ ...base, readers }, entry, [], HOME);
  assert.equal(byName.lines.find((l) => l.term === "Programs that get the real file")!.text, "mytool, mycat, ssh-add");
  // the arbiter's judgment: mytool is python3.12 and mycat is cat, byte for byte
  const judged = whyWords({ ...base, readers, readersAdmitNothing: [true, true, false], readersPrint: [false, true, false], readersCopyOf: ["python3.12", "cat", null] }, entry, [], HOME);
  assert.equal(judged.lines.find((l) => l.term === "Programs that get the real file")!.text, "mytool (a copy of python3.12) (admits nothing), mycat (a copy of cat) (admits nothing), ssh-add");
  const warn = judged.lines.find((l) => l.term === "Warning")!.text;
  assert.match(warn, /^mytool \(a copy of python3\.12\) runs any code it is given, so it reads nothing here: .*inline code \(mytool -c …\) included\. .*\{ app: python3\.12, script: \/absolute\/path\/of\/the\/script \}/);
  assert.match(warn, /mycat \(a copy of cat\) prints or copies what it reads/);
  assert.equal(judged.lines.find((l) => l.term === "What the AI sees of their output")!.text, "Masked as a whole, for every program above.", "an inert entry's output rule is not shown");
  // and the arbiter's word wins the other way too: a name the mirror marks,
  // the arbiter does not (it is the one that decides)
  const lenient = whyWords({ ...base, readers: ["bash"], readersAdmitNothing: [false], readersPrint: [false], readersCopyOf: [null] }, entry, [], HOME);
  assert.equal(lenient.lines.find((l) => l.term === "Programs that get the real file")!.text, "bash");
  assert.ok(!lenient.lines.some((l) => l.term === "Warning"));
});

test("whyWords: without a reader list, the programs known to need it, else a placeholder for every program; a plain file says only where its label comes from", () => {
  const base: WhyPathWire = { path: "/home/u/.pgpass", axis: true, level: "no-model", rule: "prefix:~/.pgpass", bindings: [], outranked: [], readers: [], others: null, consumers: ["ssh-add"], twinShape: null, verdicts: [] };
  const known = whyWords(base, e("/home/u/.pgpass", "no-model", "prefix:~/.pgpass"), [], HOME);
  assert.deepEqual(known.lines.map((l) => l.term), ["Where the label comes from", "Programs that get the real file", "May be sent to"]);
  assert.match(known.lines[1]!.text, /^ssh-add \(known to need it\)\. Any other program gets a masked copy\.$/);
  const none = whyWords({ ...base, consumers: [] }, e("/home/u/.pgpass", "no-model", "prefix:~/.pgpass"), [], HOME);
  assert.match(none.lines[1]!.text, /^None listed\. Programs get a masked copy/);
  const readers = whyWords({ ...base, readers: ["ssh-add"], others: null }, e("/home/u/.pgpass", "no-model", "label:/home/u/.pgpass", "policy", ["db.internal:5432"]), [], HOME);
  assert.equal(readers.lines.find((l) => l.term === "Any other program")!.text, "Is refused.");
  assert.equal(readers.lines.find((l) => l.term === "May be sent to")!.text, "db.internal:5432");
  assert.equal(readers.lines[0]!.text, "Your rule (~/.pgpass)");
  assert.ok(!readers.lines.some((l) => l.term === "Warning"), "ssh-add is a leaf program: no warning");
  assert.equal(readers.lines.find((l) => l.term === "What the AI sees of their output")!.text, "Masked as a whole, for every program above.");
  // Plan 13 D3: a reader entry's output rule is about this file only
  const cleared = whyWords({ ...base, readers: [{ app: "ssh-add", output: "clear" }, "ssh", { app: "bash", output: "clear" }], others: null }, e("/home/u/.pgpass", "no-model", "label:/home/u/.pgpass", "policy"), [], HOME);
  assert.equal(cleared.lines.find((l) => l.term === "What the AI sees of their output")!.text,
    "ssh-add: shown as printed (a value from this file is still hidden). Any other program above: masked as a whole. This is about this file only.");
  // Plan 13 D8: a shell reader runs the agent's scripts; the page says so
  const shell = whyWords({ ...base, readers: ["bash"], others: "twin" }, e("/home/u/ws/.env", "no-model", "label:/home/u/ws/.env", "policy"), [], HOME);
  assert.match(shell.lines.find((l) => l.term === "Warning")!.text, /^bash runs any code it is given, so it reads nothing here: no bash gets the real file through this entry, inline code \(bash -c …\) included\. .*\{ app: bash, script: \/absolute\/path\/of\/the\/script \}/);
  // plan 13 §8 decision (b): the entry itself says it admits nothing
  assert.equal(shell.lines.find((l) => l.term === "Programs that get the real file")!.text, "bash (admits nothing)");
  // Plan 13 R5: an interpreter pinned with its script is that program
  const script = whyWords({ ...base, readers: [{ app: "python3", script: "/opt/tools/report.py", output: "clear", prints: "nothing" }], others: null }, e("/home/u/.pgpass", "no-model", "label:/home/u/.pgpass", "policy"), [], HOME);
  assert.ok(!script.lines.some((l) => l.term === "Warning"), "a script pin earns no code-running warning");
  assert.match(script.lines.find((l) => l.term === "What the AI sees of their output")!.text, /^python3 running \/opt\/tools\/report\.py: shown as printed/);
  assert.ok(script.lines.some((l) => /python3 running \/opt\/tools\/report\.py/.test(l.text) && l.term !== "What the AI sees of their output"), JSON.stringify(script.lines));
  // Plan 13 D8 (12): a program neither vetted nor vouched for reads the
  // placeholder copy; the entry and the warning say so, and name the fix
  const unvetted = whyWords({ ...base, readers: ["deploy", "ssh-add"], others: null }, e("/home/u/.pgpass", "no-model", "label:/home/u/.pgpass", "policy"), [], HOME);
  assert.equal(unvetted.lines.find((l) => l.term === "Programs that get the real file")!.text, "deploy (reads the placeholder copy), ssh-add");
  assert.equal(unvetted.lines.find((l) => l.term === "Warning")!.text, "deploy is not a program Mandu knows keeps a file's contents out of what it prints, so it reads the placeholder copy. If you are sure it does, write { app: deploy, prints: nothing }.");
  // the arbiter's word wins (its readersReadTwin)
  const judgedTwin = whyWords({ ...base, readers: ["deploy"], readersReadTwin: [false], others: null }, e("/home/u/.pgpass", "no-model", "label:/home/u/.pgpass", "policy"), [], HOME);
  assert.equal(judgedTwin.lines.find((l) => l.term === "Programs that get the real file")!.text, "deploy");
  // an old answer about an unvetted program says it no longer applies
  const old = whyWords({ ...base, verdicts: [{ kind: "open", app: "deploy", exe: "/usr/bin/deploy", status: "approved", scope: "always", unvetted: true }] }, e("/home/u/.pgpass", "no-model", "prefix:~/.pgpass"), [], HOME);
  assert.match(old.lines.find((l) => l.term === "Your answer")!.text, /no longer applies: the question did not say deploy may print what it reads; you will be asked again/);
  // and an answer names the binary it is about
  const answered = whyWords({ ...base, verdicts: [{ app: "ssh-add", exe: "/usr/bin/ssh-add", status: "approved", scope: "always" }, { app: "cat", status: "denied", scope: "always" }] }, e("/home/u/.pgpass", "no-model", "prefix:~/.pgpass"), [], HOME);
  assert.deepEqual(answered.lines.filter((l) => l.term === "Your answer").map((l) => l.text), ["/usr/bin/ssh-add: allowed", "cat: blocked"]);
  // plan 13 §8 decision (c): an interpreter's answer names its script; one
  // naming the interpreter alone says it no longer applies
  const scripted = whyWords({ ...base, verdicts: [
    { app: "python3.12", exe: "/usr/bin/python3.12", status: "approved", scope: "always", script: "/opt/tools/report.py" },
    { app: "python3.12", exe: "/usr/bin/python3.12", status: "approved", scope: "always", stale: true },
  ] }, e("/home/u/.pgpass", "no-model", "prefix:~/.pgpass"), [], HOME);
  assert.deepEqual(scripted.lines.filter((l) => l.term === "Your answer").map((l) => l.text), [
    "/usr/bin/python3.12 running /opt/tools/report.py: allowed",
    "/usr/bin/python3.12: allowed (no longer applies: it names the interpreter, not the script it runs; you will be asked again)",
  ]);
  // plan 13 D8, printers admit nothing (2026-10-03): a printer reader is
  // marked, warned about (pinned too), and its cleared output is not shown;
  // an answer about it no longer applies and is never asked again
  const printers = whyWords({ ...base, readers: [{ app: "cat", output: "clear" }, { app: "head", path: "/usr/bin/head", sha256: "a".repeat(64) }, "ssh-add"], others: "twin", verdicts: [
    { app: "cat", exe: "/usr/bin/cat", status: "approved", scope: "always", printer: true },
  ] }, e("/home/u/ws/.env", "no-model", "label:/home/u/ws/.env", "policy"), [], HOME);
  assert.equal(printers.lines.find((l) => l.term === "Programs that get the real file")!.text, "cat (admits nothing), head (admits nothing), ssh-add");
  assert.match(printers.lines.find((l) => l.term === "Warning")!.text, /^cat, head print or copy what they read to whatever reads their output, which can be the AI's own code, so they read nothing here: each gets the masked copy \(or is refused\), even pinned\. Name the program that uses the secret instead/);
  assert.equal(printers.lines.find((l) => l.term === "What the AI sees of their output")!.text, "Masked as a whole, for every program above.");
  assert.deepEqual(printers.lines.filter((l) => l.term === "Your answer").map((l) => l.text), [
    "/usr/bin/cat: allowed (no longer applies: cat prints the file to whatever reads its output, so it never gets the real file and you will not be asked again)",
  ]);
  const plain = whyWords({ ...base, level: "public", rule: null }, e("/home/u/a.txt", "public", null), [], HOME);
  assert.deepEqual(plain.lines, []);
  assert.equal(whyWords({ ...base, axis: false }, e("/home/u/.pgpass", "no-model", "prefix:~/.pgpass"), [], HOME).off, true);
  const dir = whyWords({ ...base, consumers: [] }, e("/home/u/.ssh", "no-model", "prefix:~/.ssh"), [], HOME, true);
  assert.deepEqual(dir.lines.map((l) => l.term), ["Where the label comes from", "Programs that get the real files", "May be sent to"]);
  assert.match(dir.lines[1]!.text, /^Decided for each file inside/);
});

test("whyWords (plan 13 §4.9, 2026-10-04): a known program that prints (curl, scp, and now git and its credential helper) is no default reader; the page says it gets the masked copy, by the arbiter's word or the name rule", () => {
  const creds = "/home/u/.git-credentials";
  const base: WhyPathWire = { path: creds, axis: true, level: "no-model", rule: "prefix:~/.git-credentials", bindings: [], outranked: [], readers: [], others: null, consumers: ["git", "git-credential-store"], twinShape: "git-credentials", verdicts: [] };
  const entry = e(creds, "no-model", base.rule);
  const want = "None. git, git-credential-store print what they read, so they get a masked copy too. Any other program gets a masked copy.";
  for (const consumersPrint of [[true, true], undefined]) {
    const w = whyWords({ ...base, ...(consumersPrint ? { consumersPrint } : {}) }, entry, [], HOME);
    assert.equal(w.lines.find((l) => l.term === "Programs that get the real file")!.text, want, String(consumersPrint));
  }
  const key = whyWords({ ...base, path: "/home/u/.ssh/id_ed25519", consumers: ["ssh", "git", "scp", "ssh-add"], consumersPrint: [false, true, true, false] }, e("/home/u/.ssh/id_ed25519", "no-model", "prefix:~/.ssh/id_*"), [], HOME);
  assert.equal(key.lines.find((l) => l.term === "Programs that get the real file")!.text,
    "ssh, ssh-add (known to need it). git, scp print what they read, so they get a masked copy too. Any other program gets a masked copy.");
  // ssh-add prints nothing it is not asked to: unchanged
  const pg = whyWords({ ...base, path: "/home/u/.pgpass", consumers: ["ssh-add"], consumersPrint: [false] }, e("/home/u/.pgpass", "no-model", "prefix:~/.pgpass"), [], HOME);
  assert.match(pg.lines[1]!.text, /^ssh-add \(known to need it\)\. Any other program gets a masked copy\.$/);
  // listed as a reader: marked, and the warning says how it prints and what still works
  const listed = whyWords({ ...base, readers: ["git"], readersAdmitNothing: [true], readersPrint: [true], readersCopyOf: [null] }, entry, [], HOME);
  assert.equal(listed.lines.find((l) => l.term === "Programs that get the real file")!.text, "git (admits nothing)");
  assert.match(listed.lines.find((l) => l.term === "Warning")!.text, /git prints or copies what it reads.*git prints any file it is pointed at \(git diff --no-index\); with TLS inspection on it still logs in/);
});
