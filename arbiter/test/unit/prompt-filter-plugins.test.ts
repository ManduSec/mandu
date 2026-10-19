/**
 * prompt-filter-plugins.test — the plugin half of plan 15 phase 3, pure parts
 * (confidentiality-plan-15-prompt-filter.md §4.3, §5, §12 2026-10-03).
 * Mandu-new.
 *
 * Proves, with no process and no privilege:
 *   - a plugin pack validates (pin, args, cost, endpoint, deadline, declared
 *     categories), and is refused when it mixes patterns with a plugin, pins
 *     badly, or declares a built-in filter's category;
 *   - the answer's closed shape: every deviation refuses the WHOLE answer;
 *     findings only carry declared categories and the PACK's levels;
 *   - the confinement plan: the guard is required, the legs compose in
 *     order, the read roots are the fixed baseline, the endpoint becomes an
 *     address-only allow list, the environment is an allowlist;
 *   - the pin: a mismatch, a swap after pinning, and the private copy; the
 *     check yields the event loop between reads (CI #8373), and concurrent
 *     cold checks share one copy; `modules:` are pinned the same way into
 *     one verified tree, a tampered, swapped or missing module fails the
 *     check, and the plugin reads its copies only, never the directory it
 *     was installed in (P0 item 13);
 *   - `endpoint:` in the policy: validated against the effective models,
 *     held by a locked administrator's row, and ANY change is a relaxation.
 *
 * Axes: secrets (stated; nothing here reads the axis).
 */
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { isCloudBackedModel } from "../../policy/cloud-model.js";
import { packToYaml, parsePackText, validatePack } from "../../prompt-filter/packs.js";
import { buildPluginRequest, parsePluginAnswer } from "../../prompt-filter/plugin-protocol.js";
import { endpointAllowSpecs, NO_LEGS, planPluginArgv, pluginEnv, PLUGIN_READ_ROOTS, type ConfineLegs } from "../../prompt-filter/plugin-confine.js";
import { PIN_CHUNK_BYTES, PluginPins } from "../../prompt-filter/plugin-pin.js";
import { PluginFilter } from "../../prompt-filter/plugin-filter.js";
import type { ModelEndpoint } from "../../policy/compiled-policy.js";
import { checkPromptEndpoints, checkPromptFilters, comparePromptFilters, effectivePromptConfig, promptConfigDigest, promptLockProblems } from "../../prompt-filter/policy.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const H = "a".repeat(64);
const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

const PLUGIN_PACK = `pack: acme-classifier
version: 1
plugin:
  exec: /usr/bin/node
  sha256: ${H}
  script: /opt/acme/classify.mjs
  script_sha256: ${"b".repeat(64)}
  args: [--strict]
  endpoint: required
  deadline_ms: 3000
categories:
  - category: pii.person
    level: local-model
  - acme.codename
`;

test("a plugin pack validates: the pin, the settings, the declared categories with their levels", () => {
  const r = parsePackText(PLUGIN_PACK);
  assert.ok("doc" in r, JSON.stringify(r));
  const d = r.doc;
  assert.deepEqual(d.plugin, { exec: "/usr/bin/node", sha256: H, script: "/opt/acme/classify.mjs", scriptSha256: "b".repeat(64), args: ["--strict"], cost: "model", endpoint: "required", deadlineMs: 3000 });
  assert.deepEqual(d.categories, [{ category: "pii.person", level: "local-model" }, { category: "acme.codename" }]);
  assert.deepEqual(d.patterns, []);
  // Defaults.
  const min = parsePackText(`pack: p\nversion: 1\nplugin: { exec: /x/f, sha256: ${H} }\ncategories: [a.b]\n`);
  assert.ok("doc" in min);
  assert.deepEqual(min.doc.plugin, { exec: "/x/f", sha256: H, args: [], cost: "model", endpoint: "none", deadlineMs: 5000 });
});

test("a plugin pack is refused: mixed with patterns, a bad pin, a built-in category, no categories", () => {
  const bad = (doc: unknown): string => {
    const r = validatePack(doc);
    assert.ok("problems" in r, `expected a refusal: ${JSON.stringify(doc)}`);
    return r.problems.join("; ");
  };
  const base = { pack: "p", version: 1, plugin: { exec: "/x/f", sha256: H }, categories: ["a.b"] };
  assert.match(bad({ ...base, patterns: [{ id: "x", category: "a.b", regex: "x" }] }), /patterns and keywords, or a plugin, not both/);
  assert.match(bad({ ...base, plugin: { exec: "x/f", sha256: H } }), /plugin\.exec: must be an absolute path/);
  assert.match(bad({ ...base, plugin: { exec: "/x/../f", sha256: H } }), /plugin\.exec/);
  assert.match(bad({ ...base, plugin: { exec: "/x/f", sha256: "abc" } }), /plugin\.sha256/);
  assert.match(bad({ ...base, plugin: { exec: "/x/f", sha256: H, script: "/s.py" } }), /plugin\.script_sha256/);
  assert.match(bad({ ...base, plugin: { exec: "/x/f", sha256: H, deadline_ms: 60_000 } }), /deadline_ms: must be 100 to 30000/);
  assert.match(bad({ ...base, plugin: { exec: "/x/f", sha256: H, env: { A: "1" } } }), /plugin\.env: unknown key/);
  assert.match(bad({ ...base, categories: ["secret.registered"] }), /built-in filter's category/);
  assert.match(bad({ ...base, categories: ["secret.shape.github-token"] }), /built-in filter's category/);
  assert.match(bad({ ...base, categories: ["secret"] }), /built-in filter's category/);
  assert.match(bad({ ...base, categories: [] }), /declares 1 to 64 categories/);
  assert.match(bad({ pack: "p", version: 1, categories: ["a.b"], patterns: [{ id: "x", category: "a.b", regex: "x" }] }), /only a plugin pack declares categories/);
});

test("modules: each pinned file under the script's directory (else the program's) validates and round-trips; anything else is refused", () => {
  const ok = parsePackText(`${PLUGIN_PACK.replace("  args: [--strict]\n", `  modules:\n    - { path: /opt/acme/lib/rules.mjs, sha256: "${"C".repeat(64)}" }\n    - { path: /opt/acme/words.txt, sha256: "${"d".repeat(64)}" }\n  args: [--strict]\n`)}`);
  assert.ok("doc" in ok, JSON.stringify(ok));
  assert.deepEqual(ok.doc.plugin!.modules, [{ path: "/opt/acme/lib/rules.mjs", sha256: "c".repeat(64) }, { path: "/opt/acme/words.txt", sha256: "d".repeat(64) }]);
  const again = parsePackText(packToYaml(ok.doc));
  assert.ok("doc" in again);
  assert.deepEqual(again.doc.plugin, ok.doc.plugin, "the pack editor's writer keeps the pins");
  // No script: the program's directory.
  const bin = validatePack({ pack: "p", version: 1, plugin: { exec: "/opt/b/run", sha256: H, modules: [{ path: "/opt/b/model.bin", sha256: H }] }, categories: ["a.b"] });
  assert.ok("doc" in bin, JSON.stringify(bin));
  const bad = (modules: unknown, plugin: Record<string, unknown> = { exec: "/usr/bin/node", sha256: H, script: "/opt/acme/c.mjs", script_sha256: H }): string => {
    const r = validatePack({ pack: "p", version: 1, plugin: { ...plugin, modules }, categories: ["a.b"] });
    assert.ok("problems" in r, `expected a refusal: ${JSON.stringify(modules)}`);
    return r.problems.join("; ");
  };
  assert.match(bad([{ path: "/opt/other/x.mjs", sha256: H }]), /modules\[0\]\.path: must be a file under \/opt\/acme/);
  assert.match(bad([{ path: "/opt/acmex/x.mjs", sha256: H }]), /under \/opt\/acme/, "a sibling directory with the same prefix is not under it");
  assert.match(bad([{ path: "/opt/acme/c.mjs", sha256: H }]), /other than the script/);
  assert.match(bad([{ path: "/opt/acme/../etc/x", sha256: H }]), /absolute path/);
  assert.match(bad([{ path: "/opt/acme/x.mjs", sha256: "zz" }]), /modules\[0\]\.sha256/);
  assert.match(bad([{ path: "/opt/acme/x.mjs", sha256: H }, { path: "/opt/acme/x.mjs", sha256: H }]), /listed twice/);
  assert.match(bad([{ path: "/opt/acme/x.mjs", sha256: H, exec: true }]), /modules\[0\]\.exec: unknown key/);
  assert.match(bad(["/opt/acme/x.mjs"]), /modules\[0\]: must be a mapping/);
  assert.match(bad([]), /modules: must be a list of 1 to 256/);
  assert.match(bad(Array.from({ length: 257 }, (_, i) => ({ path: `/opt/acme/m${i}`, sha256: H }))), /1 to 256/);
});

const CATS = [{ category: "pii.person", level: "local-model" as const }, { category: "acme.codename" }];
const REQ = buildPluginRequest({ filter: "acme", segments: [{ id: "s1", origin: "human", text: "Kim met Falcon" }, { id: "s2", origin: "harness", text: "abc" }], categories: CATS, deadlineMs: 5000 });

test("the request carries the segments, the declared categories, the deadline and (only when needed) the endpoint", () => {
  assert.deepEqual(REQ, {
    protocol: "mandu-prompt-filter/1", filter: "acme",
    segments: [{ id: "s1", origin: "human", text: "Kim met Falcon" }, { id: "s2", origin: "harness", text: "abc" }],
    categories: ["pii.person", "acme.codename"], deadlineMs: 5000,
  });
  const withEp = buildPluginRequest({ filter: "a", segments: [], categories: CATS, deadlineMs: 1, endpoint: { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2" } });
  assert.deepEqual(withEp.endpoint, { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2" });
});

test("the answer's closed shape: a good answer maps to findings with the pack's levels; every deviation refuses the whole answer", () => {
  const ok = parsePluginAnswer(JSON.stringify({ findings: [
    { segment: "s1", start: 0, end: 3, category: "pii.person", confidence: 0.9 },
    { segment: "s1", start: 8, end: 14, category: "acme.codename" },
  ] }), REQ, CATS);
  assert.ok(ok.ok);
  assert.deepEqual(ok.findings.get("s1"), [
    { start: 0, end: 3, category: "pii.person", rule: "plugin", level: "local-model" },
    { start: 8, end: 14, category: "acme.codename", rule: "plugin" },
  ]);
  assert.deepEqual(ok.findings.get("s2"), []);
  const refuse = (answer: string, why: RegExp): void => {
    const r = parsePluginAnswer(answer, REQ, CATS);
    assert.ok(!r.ok, `expected a refusal: ${answer}`);
    assert.match(r.why, why);
  };
  const f = (x: Record<string, unknown>): string => JSON.stringify({ findings: [{ segment: "s1", start: 0, end: 3, category: "pii.person", ...x }] });
  refuse("not json", /not JSON/);
  refuse("[]", /not a JSON object/);
  refuse(JSON.stringify({ findings: [], note: "hi" }), /key the protocol does not know \(note\)/);
  refuse(JSON.stringify({}), /no findings list/);
  refuse(f({ level: "any-model" }), /key the protocol does not know \(level\)/);
  refuse(f({ text: "Kim" }), /key the protocol does not know \(text\)/);
  refuse(f({ segment: "s9" }), /names no segment/);
  refuse(f({ start: 1.5 }), /not a whole number/);
  refuse(f({ start: 3, end: 3 }), /outside its segment/);
  refuse(f({ end: 15 }), /outside its segment/);
  refuse(f({ start: -1 }), /outside its segment/);
  refuse(f({ category: "pii" }), /category the pack does not declare/);
  refuse(f({ category: "secret.registered" }), /category the pack does not declare/);
  refuse(f({ confidence: 2 }), /confidence outside/);
  refuse(JSON.stringify({ findings: ["x"] }), /not an object/);
  refuse("x".repeat(1024 * 1024 + 1), /larger than/);
});

const LEGS: ConfineLegs = { guard: true, landlock: true, seccomp: true, namespaces: false, notes: [] };
const TOOLS = { netGuard: "/b/mandu-net-guard", landlockApply: "/b/mandu-landlock-apply", bwrap: "/usr/bin/bwrap" };

test("the confinement plan: guard outermost (inside bwrap when on), Landlock clean with the seccomp filter, the fixed read roots", () => {
  const argv = planPluginArgv({ legs: LEGS, tools: TOOLS, allow: ["tcp:127.0.0.1:11434"], readDirs: ["/opt/acme", "/state/pinned/aa"], scratch: "/state/run-1", target: ["/state/pinned/aa/node", "/state/pinned/bb/classify.mjs"] });
  const reads = [...PLUGIN_READ_ROOTS, "/opt/acme", "/state/pinned/aa"].flatMap((r) => ["--read", r]);
  assert.deepEqual(argv, [
    "/b/mandu-net-guard", "--allow", "tcp:127.0.0.1:11434", "--",
    "/b/mandu-landlock-apply", "--clean", "--seccomp-deny", ...reads, "--rw", "/state/run-1", "--",
    "/state/pinned/aa/node", "/state/pinned/bb/classify.mjs",
  ]);
  assert.deepEqual(PLUGIN_READ_ROOTS, ["/usr", "/lib", "/lib32", "/lib64", "/libx32", "/bin", "/sbin", "/etc"], "the baseline of §12 (no home)");
  // No model: the guard gets NO allow at all (every connect denied).
  const none = planPluginArgv({ legs: LEGS, tools: TOOLS, allow: [], readDirs: [], scratch: "/s", target: ["/p"] });
  assert.deepEqual(none.slice(0, 2), ["/b/mandu-net-guard", "--"]);
  // Without Landlock the deny filter alone; without both, the guard alone.
  assert.deepEqual(planPluginArgv({ legs: { ...LEGS, landlock: false }, tools: TOOLS, allow: [], readDirs: [], scratch: "/s", target: ["/p"] }),
    ["/b/mandu-net-guard", "--", "/b/mandu-landlock-apply", "--seccomp-only", "--", "/p"]);
  assert.deepEqual(planPluginArgv({ legs: { ...LEGS, landlock: false, seccomp: false }, tools: TOOLS, allow: [], readDirs: [], scratch: "/s", target: ["/p"] }),
    ["/b/mandu-net-guard", "--", "/p"]);
  // Namespaces: bwrap outermost, binding only the read roots, the tools and the scratch.
  const ns = planPluginArgv({ legs: { ...LEGS, namespaces: true }, tools: TOOLS, allow: [], readDirs: [], scratch: "/s", target: ["/p"] });
  assert.equal(ns[0], "/usr/bin/bwrap");
  for (const f of ["--unshare-pid", "--unshare-ipc", "--unshare-uts", "--die-with-parent", "--new-session"]) assert.ok(ns.includes(f), f);
  assert.ok(!ns.includes("--unshare-net"), "the guard needs the host's network namespace");
  assert.ok(!ns.some((a) => a.startsWith("/home")), "no home bound");
  assert.equal(ns[ns.indexOf("--") + 1], "/b/mandu-net-guard");
  // The guard is required.
  assert.throws(() => planPluginArgv({ legs: NO_LEGS, tools: TOOLS, allow: [], readDirs: [], scratch: "/s", target: ["/p"] }), /network guard/);
  assert.throws(() => planPluginArgv({ legs: LEGS, tools: { ...TOOLS, netGuard: null }, allow: [], readDirs: [], scratch: "/s", target: ["/p"] }), /network guard/);
});

test("the endpoint becomes an address-only allow list; a name outside the perimeter is refused", () => {
  assert.deepEqual(endpointAllowSpecs({ url: "http://127.0.0.1:11434" }), { specs: ["tcp:127.0.0.1:11434"] });
  assert.deepEqual(endpointAllowSpecs({ url: "http://localhost:11434/v1" }), { specs: ["tcp:127.0.0.1:11434", "tcp:[::1]:11434"] });
  assert.deepEqual(endpointAllowSpecs({ url: "https://[::1]/" }), { specs: ["tcp:[::1]:443"] });
  assert.deepEqual(endpointAllowSpecs({ url: "http://10.1.2.3" }), { specs: ["tcp:10.1.2.3:80"] });
  assert.deepEqual(endpointAllowSpecs({ url: "https://llm.acme.internal:8443", perimeter: ["10.0.0.0/8", "fd00::/8"] }), { specs: ["tcp:10.0.0.0/8:8443", "tcp:[fd00::]/8:8443"] });
  assert.match((endpointAllowSpecs({ url: "https://llm.example.com" }) as { why: string }).why, /outside any perimeter/);
  assert.match((endpointAllowSpecs({ url: "ftp://127.0.0.1" }) as { why: string }).why, /not http/);
});

test("the plugin's environment is an allowlist: PATH, LANG, LC_ALL, HOME = TMPDIR = scratch, the endpoint, its token", () => {
  const host = { PATH: "/home/u/bin:/usr/bin", HOME: "/home/u", LANG: "en_US.UTF-8", LC_ALL: "C", ANTHROPIC_API_KEY: "sk-x", OLLAMA_TOKEN: "t0k", LD_PRELOAD: "/tmp/x.so", NODE_OPTIONS: "--require /tmp/x" };
  assert.deepEqual(pluginEnv({ scratch: "/s", hostEnv: host, endpointUrl: "http://127.0.0.1:11434", tokenEnv: "OLLAMA_TOKEN" }), {
    PATH: "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", HOME: "/s", TMPDIR: "/s", LANG: "en_US.UTF-8", LC_ALL: "C",
    MANDU_PROMPT_FILTER_ENDPOINT: "http://127.0.0.1:11434", OLLAMA_TOKEN: "t0k",
  });
  assert.deepEqual(Object.keys(pluginEnv({ scratch: "/s", hostEnv: host })).sort(), ["HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"]);
});

test("the pin: a match runs the private copy; a mismatch, or a swap after pinning, is an error; the copy is out of the way", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-plugin-pin-"));
  dirs.push(dir);
  const exec = join(dir, "plugin");
  writeFileSync(exec, "#!/bin/sh\necho one\n", { mode: 0o755 });
  const sha = createHash("sha256").update(readFileSync(exec)).digest("hex");
  const pins = new PluginPins(join(dir, "private"));
  const v = await pins.verify({ exec, sha256: sha });
  assert.equal(v.exec, join(dir, "private", sha, "plugin"));
  assert.equal(readFileSync(v.exec, "utf8"), "#!/bin/sh\necho one\n");
  assert.equal(statSync(v.exec).mode & 0o777, 0o500);
  assert.equal(statSync(join(dir, "private")).mode & 0o777, 0o700);
  assert.deepEqual(v.copyDirs, [join(dir, "private", sha)], "the plugin reads its copy, not the directory it was installed in");
  // A swap at the pinned path (same size, so only the content tells).
  writeFileSync(exec, "#!/bin/sh\necho two\n");
  await assert.rejects(() => pins.verify({ exec, sha256: sha }), /changed since it was pinned/);
  await assert.rejects(() => pins.verify({ exec: join(dir, "absent"), sha256: sha }), /cannot be read/);
  // A script pin, checked the same way.
  writeFileSync(exec, "#!/bin/sh\necho one\n");
  const script = join(dir, "s.mjs");
  writeFileSync(script, "console.log(1)\n");
  const ssha = createHash("sha256").update("console.log(1)\n").digest("hex");
  const vs = await pins.verify({ exec, sha256: sha, script, scriptSha256: ssha });
  assert.equal(readFileSync(vs.script!, "utf8"), "console.log(1)\n");
  await assert.rejects(() => pins.verify({ exec, sha256: sha, script, scriptSha256: "0".repeat(64) }), /s\.mjs changed since it was pinned/);
  // A swap after the copy was made is caught too (the source is read every time).
  writeFileSync(script, "console.log(2)\n");
  await assert.rejects(() => pins.verify({ exec, sha256: sha, script, scriptSha256: ssha }), /s\.mjs changed since it was pinned/);
  assert.deepEqual(readdirSync(join(dir, "private", ssha)), ["s.mjs"], "no temporary copy is left behind");
});

// P0 item 13 (b): the files a plugin imported loaded unpinned from the
// directory it was installed in, which stayed readable to it.
test("modules: pinned into one verified tree beside the script; a tampered, swapped or missing module fails the check; the install directory is never a read root", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-plugin-mod-"));
  dirs.push(dir);
  const shaOf = (b: string): string => createHash("sha256").update(b).digest("hex");
  const exec = join(dir, "node");
  writeFileSync(exec, "#!/bin/sh\n", { mode: 0o755 });
  const app = join(dir, "app");
  mkdirSync(join(app, "lib"), { recursive: true });
  const script = join(app, "main.mjs");
  const mod = join(app, "lib", "rules.mjs");
  const helper = join(app, "helper.sh");
  writeFileSync(script, "import './lib/rules.mjs';\n");
  writeFileSync(mod, "export const r = 1;\n");
  writeFileSync(helper, "#!/bin/sh\n", { mode: 0o755 });
  const spec = {
    exec, sha256: shaOf("#!/bin/sh\n"), script, scriptSha256: shaOf("import './lib/rules.mjs';\n"),
    modules: [{ path: mod, sha256: shaOf("export const r = 1;\n") }, { path: helper, sha256: shaOf("#!/bin/sh\n") }],
  };
  const pins = new PluginPins(join(dir, "private"));
  const v = await pins.verify(spec);
  const root = dirname(v.script!);
  assert.equal(dirname(root), join(dir, "private", "tree"), "the script runs from the tree");
  assert.equal(readFileSync(join(root, "lib", "rules.mjs"), "utf8"), "export const r = 1;\n", "the module sits at its path below the script");
  assert.equal(statSync(join(root, "lib", "rules.mjs")).mode & 0o777, 0o400);
  assert.equal(statSync(join(root, "helper.sh")).mode & 0o777, 0o500, "a module keeps its execute bit");
  assert.deepEqual(v.copyDirs.sort(), [dirname(v.exec), root].sort());
  for (const d of v.copyDirs) assert.ok(d.startsWith(join(dir, "private")), `${d} is a private copy, never the install directory`);
  // Warm: the same tree.
  assert.equal((await pins.verify(spec)).script, v.script);
  // A tampered module (same size): refused, and no copy of it is made.
  writeFileSync(mod, "export const r = 2;\n");
  await assert.rejects(() => pins.verify(spec), /rules\.mjs changed since it was pinned/);
  writeFileSync(mod, "export const r = 1;\n");
  await pins.verify(spec);
  // A missing module: refused.
  rmSync(mod);
  await assert.rejects(() => pins.verify(spec), /rules\.mjs cannot be read/);
  writeFileSync(mod, "export const r = 1;\n");
  // Another module set: another tree, the first left as it was.
  const spec2 = { ...spec, modules: [spec.modules[0]!] };
  const v2 = await pins.verify(spec2);
  assert.notEqual(dirname(v2.script!), root);
  assert.ok(!readdirSync(dirname(v2.script!)).includes("helper.sh"), "a module the pack does not pin is not in its tree");
  // No modules: the script alone in its copy directory (nothing beside it loads).
  const v3 = await pins.verify({ exec: spec.exec, sha256: spec.sha256, script, scriptSha256: spec.scriptSha256 });
  assert.deepEqual(readdirSync(dirname(v3.script!)), ["main.mjs"]);
  // A module outside the script's directory never reaches the tree (packs.ts refuses it first).
  await assert.rejects(() => pins.verify({ ...spec, modules: [{ path: join(dir, "node"), sha256: spec.sha256 }] }), /is not under/);
});

// CI pipeline #8373: the pin check read and hashed a ~120 MB node three times
// SYNCHRONOUSLY on the arbiter's event loop; on a loaded machine that held
// filterPrompt's progress frames past the proxy's 5 s idle deadline, and the
// call failed closed. The check must yield between reads.
test("the pin check never holds the event loop: a large program is read in chunks, the loop runs between them", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-plugin-pin-big-"));
  dirs.push(dir);
  const exec = join(dir, "big");
  // 24 chunks (sparse: no disk blocks): a header, then zeros.
  writeFileSync(exec, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  truncateSync(exec, 24 * PIN_CHUNK_BYTES);
  const sha = createHash("sha256").update(readFileSync(exec)).digest("hex");
  const pins = new PluginPins(join(dir, "private"));
  const turns = async (p: () => Promise<unknown>): Promise<number> => {
    let n = 0;
    let on = true;
    const spin = (): void => { if (on) { n++; setImmediate(spin); } };
    setImmediate(spin);
    try { await p(); } finally { on = false; }
    return n;
  };
  // Cold: the source read once (and copied), the copy read once.
  const cold = await turns(() => pins.verify({ exec, sha256: sha }));
  assert.ok(cold >= 24, `the loop ran ${cold} times during a cold check of 24 chunks`);
  const v = await pins.verify({ exec, sha256: sha });
  assert.equal(createHash("sha256").update(readFileSync(v.exec)).digest("hex"), sha, "the copy is the bytes hashed");
  // Warm: the source is still read every time, and still in chunks.
  const warm = await turns(() => pins.verify({ exec, sha256: sha }));
  assert.ok(warm >= 12, `the loop ran ${warm} times during a warm check of 24 chunks`);
});

test("the pin check: concurrent cold checks of one plugin all get the one verified copy", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-plugin-pin-conc-"));
  dirs.push(dir);
  const exec = join(dir, "plugin");
  writeFileSync(exec, "#!/bin/sh\n", { mode: 0o755 });
  truncateSync(exec, 3 * PIN_CHUNK_BYTES + 17);
  const sha = createHash("sha256").update(readFileSync(exec)).digest("hex");
  const pins = new PluginPins(join(dir, "private"));
  const all = await Promise.all([1, 2, 3, 4].map(() => pins.verify({ exec, sha256: sha })));
  for (const v of all) assert.equal(v.exec, join(dir, "private", sha, "plugin"));
  assert.deepEqual(readdirSync(join(dir, "private", sha)), ["plugin"]);
  assert.equal(createHash("sha256").update(readFileSync(all[0]!.exec)).digest("hex"), sha);
  // A failing check does not wedge the next one.
  await assert.rejects(() => pins.verify({ exec, sha256: "0".repeat(64) }), /changed since it was pinned/);
  assert.equal((await pins.verify({ exec, sha256: sha })).exec, all[0]!.exec);
});

const MODELS = [
  { name: "ollama", local: true, model: "llama3.2" },
  { name: "cloudish", local: true, model: "gpt-oss:120b-cloud" },
  { name: "claude", local: false, model: "claude-x" },
];

test("endpoint: validated against the effective models (local: true, not cloud-backed)", () => {
  const out: string[] = [];
  checkPromptFilters({ filters: { cls: { on: true, endpoint: "ollama" } } }, "prompt_filters", out);
  assert.deepEqual(out, []);
  checkPromptFilters({ filters: { cls: { on: true, endpoint: "has space" } } }, "prompt_filters", out);
  assert.match(out.join(), /endpoint: must name a models: entry/);
  const e: string[] = [];
  const pf = (endpoint: string): unknown => ({ filters: { cls: { on: true, endpoint } } });
  checkPromptEndpoints(pf("ollama"), MODELS, "prompt_filters", e, isCloudBackedModel);
  assert.deepEqual(e, []);
  checkPromptEndpoints(pf("nope"), MODELS, "prompt_filters", e, isCloudBackedModel);
  checkPromptEndpoints(pf("claude"), MODELS, "prompt_filters", e, isCloudBackedModel);
  checkPromptEndpoints(pf("cloudish"), MODELS, "prompt_filters", e, isCloudBackedModel);
  assert.match(e[0]!, /no model named 'nope'/);
  assert.match(e[1]!, /'claude' is not declared local: true/);
  assert.match(e[2]!, /cloud-backed model/);
});

test("endpoint: any change is a relaxation; it is in the digest; a locked administrator's endpoint holds", () => {
  const delta = (b: unknown, a: unknown) => comparePromptFilters(b, a).filter((c) => /sends|names a model|no longer names/.test(c.detail));
  const on = { filters: { cls: { on: true } } };
  const ep = (e: string) => ({ filters: { cls: { on: true, endpoint: e } } });
  assert.deepEqual(delta(on, ep("ollama")).map((c) => c.direction), ["relax"], "set");
  assert.deepEqual(delta(ep("ollama"), ep("other")).map((c) => c.direction), ["relax"], "changed");
  assert.deepEqual(delta(ep("ollama"), on).map((c) => c.direction), ["relax"], "removed");
  assert.deepEqual(delta(ep("ollama"), ep("ollama")), []);
  assert.notEqual(promptConfigDigest(effectivePromptConfig(ep("a"))), promptConfigDigest(effectivePromptConfig(ep("b"))));
  const admin = [{ file: "/etc/mandu/policy.d/10.yaml", config: { filters: { cls: { on: true, endpoint: "corp-llm", locked: true } } } }];
  const cfg = effectivePromptConfig(ep("ollama"), admin as never);
  assert.equal(cfg.filters.get("cls")!.endpoint, "corp-llm", "a locked endpoint holds");
  assert.match(promptLockProblems(ep("ollama"), admin as never).join(), /endpoint: corp-llm; it cannot be relaxed here/);
  // Unlocked: the administrator's endpoint is a default the person may name another for.
  const soft = [{ file: "/etc/mandu/policy.d/10.yaml", config: { filters: { cls: { on: true, endpoint: "corp-llm" } } } }];
  assert.equal(effectivePromptConfig(on, soft as never).filters.get("cls")!.endpoint, "corp-llm");
  assert.equal(effectivePromptConfig(ep("ollama"), soft as never).filters.get("cls")!.endpoint, "ollama");
});

test("PluginFilter: the endpoint is checked again at every spawn; the run gets the guard's allow list, the env and the request", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-plugin-filter-"));
  dirs.push(dir);
  const exec = join(dir, "plugin");
  writeFileSync(exec, "#!/bin/sh\n", { mode: 0o755 });
  const pack = parsePackText(`pack: cls\nversion: 1\nplugin: { exec: ${exec}, sha256: "${createHash("sha256").update("#!/bin/sh\n").digest("hex")}", endpoint: required }\ncategories: [{ category: acme.codename, level: local-model }]\n`);
  assert.ok("doc" in pack, JSON.stringify(pack));
  let models: ModelEndpoint[] = [{ name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true, tokenEnv: "OLLAMA_TOKEN" }];
  const calls: Array<{ argv: readonly string[]; input: string; env: NodeJS.ProcessEnv }> = [];
  const stats = { runs: 0, errors: 0 };
  const f = new PluginFilter({ doc: pack.doc, source: "user", file: join(dir, "cls.yaml"), signedBy: null, digest: "d" }, {
    pins: new PluginPins(join(dir, "private")), legs: async () => ({ guard: true, landlock: true, seccomp: true, namespaces: false, notes: [] }),
    tools: { netGuard: "/b/guard", landlockApply: "/b/lla", bwrap: null }, models: () => models, scratchRoot: dir, stats,
    hostEnv: { OLLAMA_TOKEN: "t", SECRET: "x" },
    run: async (argv, input, opts) => {
      calls.push({ argv, input, env: opts.env });
      const req = JSON.parse(input) as { segments: Array<{ id: string; text: string }> };
      const s = req.segments[0]!;
      const i = s.text.indexOf("Falcon");
      return { code: 0, signal: null, timedOut: false, overflow: false, stdout: JSON.stringify({ findings: i < 0 ? [] : [{ segment: s.id, start: i, end: i + 6, category: "acme.codename" }] }) };
    },
  });
  const res = await f.scan("go Falcon", { origin: "human", endpoint: "ollama" });
  assert.deepEqual(res.findings, [{ start: 3, end: 9, category: "acme.codename", rule: "plugin", level: "local-model" }]);
  const c = calls[0]!;
  assert.deepEqual(c.argv.slice(0, 4), ["/b/guard", "--allow", "tcp:127.0.0.1:11434", "--"]);
  assert.equal(c.env.OLLAMA_TOKEN, "t");
  assert.equal(c.env.SECRET, undefined);
  assert.equal(c.env.MANDU_PROMPT_FILTER_ENDPOINT, "http://127.0.0.1:11434");
  assert.deepEqual(JSON.parse(c.input).endpoint, { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", tokenEnv: "OLLAMA_TOKEN" });
  assert.equal(stats.runs, 1);
  // The models change under the running arbiter: refused at the next spawn.
  models = [{ ...models[0]!, local: false }];
  await assert.rejects(() => f.scan("go Falcon", { origin: "human", endpoint: "ollama" }), /not declared local: true/);
  models = [{ ...models[0]!, local: true, model: "gpt-oss:120b-cloud" }];
  await assert.rejects(() => f.scan("go Falcon", { origin: "human", endpoint: "ollama" }), /cloud-backed/);
  models = [{ name: "ollama", url: "https://llm.example.com", wire: "openai-chat", local: true }];
  await assert.rejects(() => f.scan("go Falcon", { origin: "human", endpoint: "ollama" }), /outside any perimeter/);
  await assert.rejects(() => f.scan("go Falcon", { origin: "human" }), /names none/);
  assert.equal(calls.length, 1, "no refused spawn ran");
  assert.equal(stats.errors, 4);
  assert.match((stats as { lastError?: string }).lastError!, /names none/);
});
