/**
 * flow-taint — plan 10's decision core (confidentiality-plan-10-flow-taint.md
 * §2, §3, §11): the open verdict, the output rules and the fold.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  appRuleRefusal, consumerWireRelease, CONSUMER_TABLE, decideOpen, foldRules, knownConsumers, matchReader, readerOutputRule,
} from "../../policy/flow-taint.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

// Plan 13 D8: the guard reports a system binary run with a clean loader environment
const SYS = { exeSystem: true, loaderEnv: [] as string[] };
const anc = (...names: string[]) => names.map((n) => ({ exe: `/usr/bin/${n}`, trusted: true }));
const PSQL = { exe: "/usr/bin/ssh-add", sha256: "a".repeat(64), ...SYS };
const PIN = { app: "ssh-add", path: "/usr/bin/ssh-add", sha256: "a".repeat(64) };

test("no reader list: a program outside the consumer table gets the twin; the agent's process always does; an untrusted lineage is denied", () => {
  assert.equal(decideOpen("/h/.ssh/id_test", {}, { exe: "/usr/bin/cat", ...SYS }).verdict, "twin");
  assert.equal(decideOpen("/h/.ssh/id_test", { readers: [PIN] }, { ...PSQL, isAgent: true }).verdict, "twin");
  assert.equal(decideOpen("/h/.ssh/id_test", { readers: [PIN] }, { ...PSQL, integrityTainted: true }).verdict, "deny");
});

test("a reader list is exhaustive: the pinned reader gets raw, everyone else EACCES, `others: twin` restores the twin", () => {
  const raw = decideOpen("/h/.ssh/id_test", { readers: [PIN] }, PSQL);
  assert.equal(raw.verdict, "raw");
  assert.equal(raw.pinNeeded, false);
  assert.deepEqual(raw.reader, PIN);
  assert.equal(decideOpen("/h/.ssh/id_test", { readers: [PIN] }, { exe: "/usr/bin/cat", ...SYS }).verdict, "deny");
  assert.equal(decideOpen("/h/.ssh/id_test", { readers: [PIN], others: "twin" }, { exe: "/usr/bin/cat", ...SYS }).verdict, "twin");
});

test("a pin is path AND hash: a rebuilt binary misses; a bare name matches the basename and asks to be pinned", () => {
  assert.equal(decideOpen("/h/.ssh/id_test", { readers: [PIN] }, { ...PSQL, sha256: "b".repeat(64) }).verdict, "deny");
  assert.equal(decideOpen("/h/.ssh/id_test", { readers: [PIN] }, { exe: "/opt/ssh-add", sha256: PIN.sha256 }).verdict, "deny");
  const bare = decideOpen("/h/.ssh/id_test", { readers: ["ssh-add"] }, PSQL);
  assert.equal(bare.verdict, "raw");
  assert.equal(bare.pinNeeded, true);
  // an agent-writable copy named ssh-add matches the bare NAME too; decideOpen
  // refuses to pin it (Plan 13 D8, below), and a written pin never matches it
  assert.equal(matchReader(["ssh-add"], { exe: "/ws/ssh-add" })?.pinNeeded, true);
  assert.equal(matchReader([PIN], { exe: "/ws/ssh-add", sha256: "c".repeat(64) }), null);
});

// ── Plan 13 D8: a reader's identity is its pin, its location and its environment ──
test("Plan 13 D8 TOFU: a first-use pin is taken only from a binary out of the agent's reach; a copy in the workspace asks (known/always) or is no reader (never)", () => {
  const COPY = { exe: "/home/u/ws/ssh-add", sha256: "a".repeat(64), exeSystem: false, loaderEnv: [] as string[] };
  // a bare-name reader
  const bare = decideOpen("/h/.ssh/id_test", { readers: ["ssh-add"] }, COPY, { ask: "known" });
  assert.equal(bare.verdict, "ask", "the workspace copy is not pinned without the human");
  assert.match(bare.why, /in a place the agent can write/);
  assert.equal(decideOpen("/h/.ssh/id_test", { readers: ["ssh-add"] }, COPY, { ask: "always" }).verdict, "ask");
  assert.equal(decideOpen("/h/.ssh/id_test", { readers: ["ssh-add"] }, COPY, { ask: "never" }).verdict, "deny", "no prompt: a non-reader of a listed file");
  assert.equal(decideOpen("/h/.ssh/id_test", { readers: ["ssh-add"], others: "twin" }, COPY, { ask: "never" }).verdict, "twin");
  assert.equal(decideOpen("/h/.ssh/id_test", { readers: ["ssh-add"] }, PSQL, { ask: "never" }).verdict, "raw", "the system's ssh-add is still pinned on first use");
  // the consumer table's default reader (no list)
  assert.equal(decideOpen("/h/.ssh/id_test", {}, COPY, { ask: "known" }).verdict, "ask");
  assert.equal(decideOpen("/h/.ssh/id_test", {}, COPY, { ask: "never" }).verdict, "twin");
  assert.equal(decideOpen("/h/.ssh/id_test", {}, PSQL, { ask: "never" }).verdict, "raw");
  // unknown location counts as reachable
  const unknown = { exe: "/usr/bin/ssh-add", sha256: "a".repeat(64), loaderEnv: [] as string[] };
  assert.notEqual(decideOpen("/h/.ssh/id_test", {}, unknown, { ask: "never" }).verdict, "raw", "no exeSystem fact: not pinned");
  // a full pin the human wrote or approved needs no reach fact: it names the file
  const selfBuilt = { app: "tool", path: "/home/u/bin/tool", sha256: "f".repeat(64), prints: "nothing" as const };
  assert.equal(decideOpen("/h/.ssh/id_test", { readers: [selfBuilt] }, { exe: "/home/u/bin/tool", sha256: "f".repeat(64), exeSystem: false, loaderEnv: [] }).verdict, "raw");
});

test("Plan 13 D8 env: an opener run with a loader or interpreter variable the launch did not give is no reader, pinned or not, and never prompts", () => {
  const PRELOADED = { ...PSQL, loaderEnv: ["LD_PRELOAD"] };
  const listed = decideOpen("/h/.ssh/id_test", { readers: [PIN] }, PRELOADED, { ask: "always" });
  assert.equal(listed.verdict, "deny", "a pinned reader with LD_PRELOAD set is refused raw, with no prompt");
  assert.match(listed.why, /LD_PRELOAD set to a value the launch did not give/);
  assert.equal(decideOpen("/h/.ssh/id_test", { readers: [PIN], others: "twin" }, PRELOADED).verdict, "twin");
  assert.equal(decideOpen("/h/.ssh/id_test", { readers: ["ssh-add"] }, PRELOADED).verdict, "deny");
  assert.equal(decideOpen("/h/.ssh/id_test", {}, PRELOADED, { ask: "known" }).verdict, "twin", "a default reader: the twin");
  assert.equal(decideOpen("/h/.ssh/id_test", {}, { ...PSQL, loaderEnv: ["PYTHONPATH", "NODE_OPTIONS"] }).verdict, "twin");
  const unchecked = { exe: "/usr/bin/ssh-add", sha256: "a".repeat(64), exeSystem: true };
  assert.notEqual(decideOpen("/h/.ssh/id_test", { readers: [PIN] }, unchecked).verdict, "raw", "an environment nobody checked is not clean");
  assert.match(decideOpen("/h/.ssh/id_test", { readers: [PIN] }, unchecked).why, /not checked/);
  assert.equal(decideOpen("/h/.ssh/id_test", { readers: [PIN] }, PSQL).verdict, "raw", "clean: the pin holds");
  // a library the agent can write, mapped into the pinned program (the guard
  // reads /proc/<pid>/maps: a preload that scrubbed its environment still shows)
  const mapped = decideOpen("/h/.ssh/id_test", { readers: [PIN] }, { ...PSQL, loaderEnv: ["code:/home/u/ws/evil.so"] });
  assert.equal(mapped.verdict, "deny");
  assert.match(mapped.why, /code loaded from \/home\/u\/ws\/evil\.so, a file the agent can write/);
  assert.equal(decideOpen("/h/.ssh/id_test", { readers: [PIN] }, { ...PRELOADED, isAgent: true }).verdict, "twin", "the agent is the twin before anything");
});

test("Plan 13 D8 from: the parent counts only when it is TRUSTED (out of reach, clean environment); a renamed shell called git is not git", () => {
  const readers = [{ app: "ssh", from: "git" }];
  const SSH = { exe: "/usr/bin/ssh", ...SYS };
  assert.ok(matchReader(readers, { ...SSH, ancestors: [{ exe: "/usr/bin/git", trusted: true }] }));
  assert.equal(matchReader(readers, { ...SSH, ancestors: [{ exe: "/home/u/ws/git", trusted: false }, { exe: "/usr/bin/bash", trusted: true }] }), null, "a copy of sh named git in the workspace");
  assert.equal(matchReader(readers, { ...SSH, ancestors: [{ exe: "/usr/bin/git", trusted: false }] }), null, "the system's git run with LD_PRELOAD");
  assert.equal(matchReader(readers, { ...SSH, ancestors: [{ exe: "/usr/bin/git" }] }), null, "no trust fact: not trusted");
  assert.equal(decideOpen("/h/.ssh/id_ed25519", { readers }, { ...SSH, ancestors: [{ exe: "/tmp/x/git", trusted: false }] }).verdict, "deny");
});

test("a known consumer of a listless file is a DEFAULT reader (§11.3): raw, pinned on first use; an unknown program gets the twin; `always` asks", () => {
  const d = decideOpen("/h/.ssh/id_test", {}, PSQL);
  assert.equal(d.verdict, "raw");
  assert.equal(d.pinNeeded, true);
  assert.equal(d.reader?.app, "ssh-add");
  assert.equal(decideOpen("/h/.ssh/id_test", {}, PSQL, { ask: "known" }).verdict, "raw");
  assert.equal(decideOpen("/h/.ssh/id_test", {}, PSQL, { ask: "always" }).verdict, "ask");
  assert.equal(decideOpen("/h/.ssh/id_test", {}, { exe: "/usr/bin/mytool", ...SYS }, { ask: "known" }).verdict, "twin");
  assert.equal(decideOpen("/h/.ssh/id_test", {}, { exe: "/usr/bin/mytool", ...SYS }, { ask: "always" }).verdict, "ask");
  assert.equal(decideOpen("/ws/.env", {}, { exe: "/bin/bash", ...SYS }).verdict, "twin", ".env has no canonical consumer: the twin");
  assert.equal(decideOpen("/h/.ssh/id_test", { readers: ["ssh"] }, PSQL, { ask: "known" }).verdict, "ask", "a list exists and ssh-add is not on it: a known consumer asks");
  assert.equal(decideOpen("/h/.ssh/id_test", { readers: ["ssh"] }, PSQL).verdict, "deny", "with prompting off, the list is exhaustive");
  assert.equal(decideOpen("/h/.ssh/id_test", { readers: ["ssh"] }, { exe: "/usr/bin/mytool", ...SYS }, { ask: "always" }).verdict, "ask");
  assert.equal(decideOpen("/h/.ssh/id_test", { readers: ["ssh"] }, { exe: "/usr/bin/mytool", ...SYS }, { ask: "never" }).verdict, "deny");
  assert.deepEqual([...knownConsumers("/h/.aws/credentials")], ["aws"]);
  assert.deepEqual([...knownConsumers("/ws/.env")], []);
});

test("output rules: default secret; an interpreter is always secret; the fold takes the strictest and unions masks", () => {
  // Plan 13 D3: the rule is the reader entry's on one file (readerOutputRule;
  // reader-output-rule.test.ts covers the pair, the binary and the legacy table).
  const row = (app: string) => ({ path: "/h/f", app, exe: `/usr/bin/${app}`, via: "reader" as const });
  const readers = [
    { app: "ssh-add", output: "clear" as const },
    { app: "aws", output: "mask" as const, mask: ["AKIA[0-9A-Z]{16}"] },
    { app: "gh", output: "mask" as const, mask: ["gh[po]_[A-Za-z0-9]+"] },
    { app: "bash", output: "clear" as const }, // the validator refuses this; the runtime ignores it too
  ];
  assert.equal(readerOutputRule(row("ssh-add"), readers).output, "clear");
  assert.equal(readerOutputRule(row("node"), readers).output, "secret");
  assert.equal(readerOutputRule(row("bash"), readers).output, "secret", "an interpreter can never be clear");
  assert.equal(foldRules([]).output, "secret");
  assert.equal(foldRules([{ app: "ssh-add", output: "clear" }]).output, "clear");
  assert.equal(foldRules([{ app: "ssh-add", output: "clear" }, { app: "bash", output: "secret" }]).output, "secret");
  const m = foldRules([readerOutputRule(row("aws"), readers), readerOutputRule(row("gh"), readers), { app: "ssh-add", output: "clear" }]);
  assert.equal(m.output, "mask");
  assert.deepEqual(m.mask, ["AKIA[0-9A-Z]{16}", "gh[po]_[A-Za-z0-9]+"]);
  assert.match(appRuleRefusal({ app: "python3", output: "clear" })!, /interpreter/);
  assert.equal(appRuleRefusal({ app: "ssh-add", output: "mask", mask: ["x"] }), null);
  assert.equal(appRuleRefusal({ app: "bash", output: "secret" }), null);
});

test("the consumer table carries the TLS compatibility verdict (confidentiality-plan-13-reader-set-labels.md): HTTP bearer consumers are served by the wire, signers, daemons, pinners and non-HTTP protocols are readers", () => {
  for (const row of CONSUMER_TABLE) assert.ok(row.wire.why.length > 0, row.apps.join(","));
  assert.equal(consumerWireRelease("/h/.config/gh/hosts.yml")!.served, true);
  assert.equal(consumerWireRelease("/h/.npmrc")!.served, true);
  assert.equal(consumerWireRelease("/h/.cargo/credentials.toml")!.served, true);
  assert.equal(consumerWireRelease("/h/.netrc")!.served, true);
  assert.equal(consumerWireRelease("/h/.pypirc")!.served, true);
  assert.equal(consumerWireRelease("/h/.pgpass")!.served, false);
  assert.match(consumerWireRelease("/h/.aws/credentials")!.why, /SigV4/);
  assert.equal(consumerWireRelease("/h/.docker/config.json")!.served, false);
  assert.equal(consumerWireRelease("/h/.kube/config")!.served, false);
  assert.equal(consumerWireRelease("/h/.ssh/id_ed25519")!.served, false);
  assert.equal(consumerWireRelease("/ws/.env"), null);
});

test("a lineage-conditional reader (from:) matches only under that app; unknown ancestry never matches", () => {
  const readers = [{ app: "ssh", from: "git" }];
  assert.ok(matchReader(readers, { exe: "/usr/bin/ssh", ancestors: anc("git", "bash") }), "git's ssh reads the key");
  assert.equal(matchReader(readers, { exe: "/usr/bin/ssh", ancestors: anc("bash", "claude") }), null, "an ssh the agent runs directly does not");
  assert.equal(matchReader(readers, { exe: "/usr/bin/ssh", ...SYS }), null, "no ancestry reported: no match (fail toward the twin)");
  const pinned = [{ app: "ssh", path: "/usr/bin/ssh", from: "git" }];
  assert.equal(matchReader(pinned, { exe: "/usr/bin/ssh", ancestors: anc("zsh") }), null, "a pin keeps the condition");
  assert.deepEqual(matchReader(pinned, { exe: "/usr/bin/ssh", ancestors: anc("git") })?.pinNeeded, false);
});

test("appNameMatches: exact, or the versioned file a name resolves to; never a different program", async () => {
  const { appNameMatches } = await import("../../policy/flow-taint.js");
  assert.equal(appNameMatches("python3.12", "python3"), true);
  assert.equal(appNameMatches("python3", "python3"), true);
  assert.equal(appNameMatches("ssh2", "ssh"), false);
  assert.equal(appNameMatches("sshd", "ssh"), false);
  assert.equal(appNameMatches("python3.12-config", "python3"), false);
  assert.equal(appNameMatches("nc.openbsd", "nc"), true, "a Debian alternatives target");
  assert.ok(matchReader([{ app: "ssh-add", from: "python3" }], { exe: "/usr/bin/ssh-add", ancestors: anc("python3.12") }));
});

test("plan 10 §11.13: git (its `store` credential helper) is the known consumer of ~/.git-credentials and the XDG store; a printer since 2026-10-04 (plan 13 §4.9), it gets the twin the wire release serves, and without it what any other program gets", () => {
  for (const p of ["/h/.git-credentials", "/h/.config/git/credentials"]) {
    assert.deepEqual([...knownConsumers(p)], ["git", "git-credential-store"], p);
    assert.deepEqual([...knownConsumers("/h/.netrc")], ["curl", "git", "git-remote-http", "git-remote-https", "git-http-fetch", "git-http-push"], "git's opener of .netrc is its HTTP transport (and, since 2026-10-07, the dumb-HTTP fetch and WebDAV push programs it starts)");
    const git = decideOpen(p, {}, { exe: "/usr/bin/git", ...SYS });
    assert.equal(git.verdict, "twin", p);
    assert.match(git.why, /prints or copies/);
    assert.equal(decideOpen(p, {}, { exe: "/usr/lib/git-core/git-credential-store", ...SYS }).verdict, "twin", p);
    const wire = { wireTwin: { why: "git: GIT_SSL_CAINFO; basic auth in a header" } };
    assert.equal(decideOpen(p, { readers: ["ssh-add"] }, { exe: "/usr/bin/git", ...SYS }, { ask: "known", ...wire }).verdict, "twin", "listed or not, the wire release's twin");
    assert.equal(decideOpen(p, { readers: ["git"] }, { exe: "/usr/bin/git", ...SYS }, { ask: "known" }).verdict, "deny", "without it, a listed git reads nothing");
    assert.equal(decideOpen(p, {}, { exe: "/usr/bin/cat", ...SYS }).verdict, "twin", p);
    assert.equal(decideOpen(p, {}, { exe: "/usr/bin/git", isAgent: true, ...SYS }).verdict, "twin", "the agent's own process never reads raw");
    assert.equal(consumerWireRelease(p)!.served, true);
  }
  assert.deepEqual([...knownConsumers("/h/.ssh/config")], [], "ssh reads its config as the twin, which is its own text");
  assert.deepEqual([...knownConsumers("/h/.config/pip/pip.conf")], [], "pip runs as python, an interpreter: never a default reader");
});

// Plan 13 §8 decision (b): node runs code it is given, so it is a reader only
// as the script it runs, when R5's checks pin it (`NPM_CLI`); running inline
// code (`NODE_E`) it is none.
const NPM_CLI = { path: "/usr/lib/node_modules/npm/bin/npm-cli.js", sha256: "c".repeat(64), system: true, isolated: true, traced: false };
const NODE_E = { exe: "/usr/bin/node", ...SYS, scriptProblem: "inline code (node -e)" };

// Plan 10 §11.13.1: npm reads the `.npmrc` twin when the wire carries its token.
test("wireTwin: a known consumer of a file with no reader list gets the twin, not raw; nothing else moves", () => {
  const NODE = { exe: "/usr/bin/node", ...SYS, script: NPM_CLI };
  const wire = { wireTwin: { why: "the session proxy puts every token back at its own registry (registry.npmjs.org)" } };
  // Plan 13 D8 (12): node (npm) is no vetted reader, so without the wire it
  // is asked about with the warning (`ask: known`) or gets the twin.
  const def = decideOpen("/h/.npmrc", {}, NODE, { ask: "known" });
  assert.equal(def.verdict, "ask", "without it: the warning question");
  assert.equal(def.unvetted, true);
  assert.equal(decideOpen("/h/.npmrc", {}, NODE, { ask: "never" }).verdict, "twin");
  // node running inline code is no default reader, and is not asked about
  for (const ask of ["known", "always", "never"] as const) {
    const e = decideOpen("/h/.npmrc", {}, NODE_E, { ask });
    assert.equal(e.verdict, "twin", `${ask}: ${e.why}`);
    assert.match(e.why, /pinned script/);
  }
  const d = decideOpen("/h/.npmrc", {}, NODE, { ask: "known", ...wire });
  assert.equal(d.verdict, "twin");
  assert.match(d.why, /node is a known consumer of \.npmrc, served its twin: the session proxy/);
  assert.equal(decideOpen("/h/.npmrc", {}, { exe: "/usr/bin/npm", ...SYS }, { ask: "never", ...wire }).verdict, "twin");
  assert.equal(decideOpen("/h/.npmrc", {}, { exe: "/usr/bin/cat", ...SYS }, wire).verdict, "twin", "a non-consumer gets the twin either way");
  assert.equal(decideOpen("/h/.npmrc", {}, NODE, { ask: "always", ...wire }).verdict, "ask", "`always` still asks");
  // A LISTED known consumer too: the default reader's first raw read pins it
  // into the list (§11.2), so the list names node on any host where npm ran.
  const PIN_NODE = { app: "node", path: "/usr/bin/node", sha256: "d".repeat(64), script: NPM_CLI.path, scriptSha256: NPM_CLI.sha256 };
  assert.equal(decideOpen("/h/.npmrc", { readers: [PIN_NODE] }, { ...NODE, sha256: "d".repeat(64) }, { ask: "known", ...wire }).verdict, "twin");
  assert.equal(decideOpen("/h/.npmrc", { readers: [PIN_NODE] }, { ...NODE, sha256: "d".repeat(64) }, { ask: "known" }).verdict, "twin", "without the wire: the pin, Mandu's, is no vouch (D8 (12))");
  assert.equal(decideOpen("/h/.npmrc", { readers: [{ ...PIN_NODE, prints: "nothing" as const }] }, { ...NODE, sha256: "d".repeat(64) }, { ask: "known" }).verdict, "raw", "the human's word reads raw");
  // The interpreter pinned alone (as written before decision b) admits nothing.
  const OLD_PIN = { app: "node", path: "/usr/bin/node", sha256: "d".repeat(64) };
  assert.equal(decideOpen("/h/.npmrc", { readers: [OLD_PIN] }, { ...NODE, sha256: "d".repeat(64) }, { ask: "never" }).verdict, "deny", "an interpreter pin without its script names no program");
  // ...but a listed program that is no known consumer of the file keeps its raw read.
  assert.equal(decideOpen("/h/.npmrc", { readers: [{ app: "mytool", prints: "nothing" }] }, { exe: "/usr/bin/mytool", ...SYS }, { ask: "known", ...wire }).verdict, "raw");
  assert.equal(decideOpen("/h/.npmrc", { readers: ["mytool"] }, { exe: "/usr/bin/mytool", ...SYS }, { ask: "known", ...wire }).verdict, "twin", "unvetted, no word: the twin (D8 (12))");
  // (curl, a printer since the !437 leftover (1), 2026-10-03, admits nothing.)
  assert.equal(decideOpen("/h/.npmrc", { readers: ["curl"] }, { exe: "/usr/bin/curl", ...SYS }, { ask: "known", ...wire }).verdict, "deny", "curl prints any file it is pointed at");
  assert.equal(decideOpen("/h/.npmrc", { readers: ["bun"] }, { exe: "/usr/bin/bun", ...SYS }, { ask: "known", ...wire }).verdict, "deny", "bun runs code it is given: no reader by name (decision b)");
  assert.equal(decideOpen("/h/.npmrc", {}, { ...NODE, integrityTainted: true }, { ask: "known", ...wire }).verdict, "deny");
});

test("an explicit `others: twin` wins over `secrets-ask = known`'s prompt for a known consumer; `always` still asks", () => {
  const NODE = { exe: "/usr/bin/node", ...SYS, script: NPM_CLI };
  assert.equal(decideOpen("/h/.npmrc", { readers: [], others: "twin" }, NODE, { ask: "known" }).verdict, "twin");
  assert.equal(decideOpen("/h/.npmrc", { readers: ["yarn"], others: "twin" }, NODE, { ask: "known" }).verdict, "twin");
  assert.equal(decideOpen("/h/.npmrc", { readers: [], others: "twin" }, NODE, { ask: "always" }).verdict, "ask");
  // Without `others: twin` the known consumer is still held for the human, and anyone else denied.
  assert.equal(decideOpen("/h/.npmrc", { readers: [] }, NODE, { ask: "known" }).verdict, "ask");
  // Plan 13 §8 decision (b): node running inline code is never asked about.
  assert.equal(decideOpen("/h/.npmrc", { readers: [] }, NODE_E, { ask: "known" }).verdict, "deny");
  assert.equal(decideOpen("/h/.npmrc", { readers: [] }, NODE_E, { ask: "always" }).verdict, "deny");
  assert.equal(decideOpen("/h/.npmrc", { readers: [], others: "twin" }, NODE_E, { ask: "always" }).verdict, "twin");
  assert.equal(decideOpen("/h/.npmrc", { readers: [] }, { exe: "/usr/bin/cat", ...SYS }, { ask: "known" }).verdict, "deny");
  assert.equal(decideOpen("/h/.pgpass", { readers: ["pg_dump"], others: "twin" }, PSQL, { ask: "known" }).verdict, "twin");
});

// Plan 13 D8: the Inbox subject of a held open names the binary, not its name.
test("openVerdictSubject: a verdict is keyed by the executable's path and hash; the parts read back, old rows included", async () => {
  const { openVerdictSubject, openVerdictParts } = await import("../../policy/flow-taint.js");
  const h = "a".repeat(64);
  assert.equal(openVerdictSubject("/usr/bin/ssh-add", h), `open:/usr/bin/ssh-add#${h}`);
  assert.equal(openVerdictSubject("/usr/bin/ssh-add"), "open:/usr/bin/ssh-add", "no hash: the path alone, as a pin without sha256");
  assert.notEqual(openVerdictSubject("/tmp/x/psql", h), openVerdictSubject("/usr/bin/ssh-add", h), "another path is another key");
  assert.notEqual(openVerdictSubject("/usr/bin/ssh-add", "b".repeat(64)), openVerdictSubject("/usr/bin/ssh-add", h), "a rebuilt binary is another key");
  assert.deepEqual(openVerdictParts(`open:/usr/bin/ssh-add#${h}`), { app: "ssh-add", exe: "/usr/bin/ssh-add", sha256: h });
  assert.deepEqual(openVerdictParts("open:/usr/bin/ssh-add"), { app: "ssh-add", exe: "/usr/bin/ssh-add" });
  assert.deepEqual(openVerdictParts("open:ssh-add"), { app: "ssh-add" }, "a row written before the change names the program only");
});

// The D8 follow-up: a write verdict names the binary the same way, and the
// subject is one-to-one, so no file name can spell another binary's key.
test("binaryVerdictSubject: write verdicts by path and hash; a name that ends like a hash, or in '#', cannot pose as path + hash", async () => {
  const { binaryVerdictSubject, binaryVerdictParts, writeVerdictSubject, openVerdictSubject } = await import("../../policy/flow-taint.js");
  const h = "a".repeat(64);
  assert.equal(writeVerdictSubject("/usr/bin/vim", h), `write:/usr/bin/vim#${h}`);
  assert.equal(writeVerdictSubject("/usr/bin/vim"), "write:/usr/bin/vim");
  assert.notEqual(writeVerdictSubject("/tmp/x/vim", h), writeVerdictSubject("/usr/bin/vim", h));
  assert.notEqual(writeVerdictSubject("/usr/bin/vim", h), openVerdictSubject("/usr/bin/vim", h), "a read verdict is not a write verdict");
  // Unhashed files whose names spell a hashed key get an escaped key.
  const spoofs = [`/w/tool#${h}`, "/w/tool#", `/w/tool#${h}#`];
  const keys = new Set([writeVerdictSubject("/w/tool", h), writeVerdictSubject("/w/tool"), ...spoofs.map((s) => writeVerdictSubject(s))]);
  assert.equal(keys.size, 2 + spoofs.length, [...keys].join(" | "));
  for (const s of spoofs) assert.deepEqual(binaryVerdictParts(writeVerdictSubject(s)!), { kind: "write", app: s.slice(s.lastIndexOf("/") + 1), exe: s }, s);
  assert.deepEqual(binaryVerdictParts(`write:/usr/bin/vim#${h}`), { kind: "write", app: "vim", exe: "/usr/bin/vim", sha256: h });
  assert.deepEqual(binaryVerdictParts("write:vim"), { kind: "write", app: "vim" }, "a row from before the change names the program only");
  // A hash that is not 64 hex digits is no hash.
  assert.equal(binaryVerdictSubject("write", "/usr/bin/vim", "zz"), null);
  assert.equal(binaryVerdictSubject("write", "/usr/bin/vim", h.toUpperCase()), `write:/usr/bin/vim#${h}`);
});

// Plan 13 §8 decision (c): an interpreter's verdict names its script, or one run.
test("binaryVerdictSubject with a program: the script (path, hash) or the run is part of the key; every subject reads back one way; a path spelling a marker gets none", async () => {
  const { binaryVerdictSubject, binaryVerdictParts, staleInterpreterVerdict, verdictProgramOf } = await import("../../policy/flow-taint.js");
  const h = "a".repeat(64), sh = "b".repeat(64);
  const A = { script: "/opt/tools/a.py", scriptSha256: sh };
  const a = binaryVerdictSubject("open", "/usr/bin/python3.12", h, A)!;
  assert.equal(a, `open:/usr/bin/python3.12#${h}#script:%2Fopt%2Ftools%2Fa.py#${sh}`);
  assert.deepEqual(binaryVerdictParts(a), { kind: "open", app: "python3.12", exe: "/usr/bin/python3.12", sha256: h, script: "/opt/tools/a.py", scriptSha256: sh });
  const keys = new Set([
    a,
    binaryVerdictSubject("open", "/usr/bin/python3.12", h),
    binaryVerdictSubject("open", "/usr/bin/python3.12", h, { script: "/opt/tools/b.py", scriptSha256: sh }),
    binaryVerdictSubject("open", "/usr/bin/python3.12", h, { script: "/opt/tools/a.py", scriptSha256: "c".repeat(64) }),
    binaryVerdictSubject("write", "/usr/bin/python3.12", h, A),
    binaryVerdictSubject("write", "/usr/bin/bash", h, { run: "123-456" }),
    binaryVerdictSubject("write", "/usr/bin/bash", h, { run: "123-457" }),
  ]);
  assert.equal(keys.size, 7, [...keys].join(" | "));
  const run = binaryVerdictSubject("write", "/usr/bin/bash", h, { run: "123-456" })!;
  assert.equal(run, `write:/usr/bin/bash#${h}#run:123-456`);
  assert.deepEqual(binaryVerdictParts(run), { kind: "write", app: "bash", exe: "/usr/bin/bash", sha256: h, run: "123-456" });
  // a script path with '#' or spaces is encoded, and reads back
  const odd = binaryVerdictSubject("open", "/usr/bin/node", undefined, { script: "/opt/x #1/s.js", scriptSha256: sh })!;
  assert.equal(binaryVerdictParts(odd).script, "/opt/x #1/s.js");
  // no binary's path may spell a program's key: a path with a marker has no subject
  assert.equal(binaryVerdictSubject("open", `/w/py#${h}#script:%2Fopt%2Ftools%2Fa.py`, sh), null);
  assert.equal(binaryVerdictSubject("write", "/w/bash#run:123-456"), null);
  // malformed script hashes and empty runs answer null
  assert.equal(binaryVerdictSubject("open", "/usr/bin/python3", h, { script: "/opt/a.py", scriptSha256: "zz" }), null);
  assert.equal(binaryVerdictSubject("open", "/usr/bin/python3", h, { script: "a.py", scriptSha256: sh }), null);
  assert.equal(binaryVerdictSubject("write", "/usr/bin/bash", h, { run: "" }), null);
  // a row written before the decision names the interpreter alone: stale
  assert.equal(staleInterpreterVerdict(`open:/usr/bin/python3.12#${h}`), true);
  assert.equal(staleInterpreterVerdict(`write:/usr/bin/bash#${h}`), true);
  assert.equal(staleInterpreterVerdict(a), false);
  assert.equal(staleInterpreterVerdict(run), false);
  assert.equal(staleInterpreterVerdict(`open:/usr/bin/ssh-add#${h}`), false, "a leaf program's verdict stands");
  // what a verdict names, per opener
  const SYS = { exeSystem: true, loaderEnv: [] as string[] };
  assert.equal(verdictProgramOf({ exe: "/usr/bin/ssh-add", ...SYS }), undefined, "a leaf program: its binary");
  assert.deepEqual(verdictProgramOf({ exe: "/usr/bin/python3.12", ...SYS, script: { path: "/opt/tools/a.py", sha256: sh, system: true, isolated: true, traced: false } }), A);
  assert.equal(verdictProgramOf({ exe: "/usr/bin/python3.12", ...SYS, scriptProblem: "inline code (python -c)" }), null, "inline code: no reusable verdict");
  assert.equal(verdictProgramOf({ exe: "/usr/bin/python3.12", ...SYS, script: { path: "/home/u/a.py", sha256: sh, system: false, isolated: true, traced: false } }), null, "an agent-writable script: none either");
  assert.equal(verdictProgramOf({ exe: "/usr/bin/ruby", ...SYS }), null, "an interpreter with no script pin at all");
});

test("readerRunsCode: shells, interpreters and launchers run any code they are given; a leaf program does not", async () => {
  const { readerRunsCode } = await import("../../policy/flow-taint.js");
  for (const n of ["bash", "sh", "dash", "zsh", "node", "python3", "python3.12", "/usr/bin/perl", "ruby", "env", "xargs", "busybox", "awk", "make"]) assert.equal(readerRunsCode(n), true, n);
  for (const n of ["ssh-add", "aws", "ssh", "git", "cat", "docker-compose", "pg_dump", "ssh-add", "nodejs-thing", "bashful"]) assert.equal(readerRunsCode(n), false, n);
});
