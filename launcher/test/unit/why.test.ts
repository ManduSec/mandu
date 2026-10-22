/**
 * why — the pure half of `mandu why` (comparisons.md §3.2): what counts
 * as a host, how the default connect-guard set is matched, and the words a
 * reader sees. The arbiter ops are proven over the real server in
 * tests/stack/why-cli.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  categoryWords, filterWords, guardAdmits, mayGoLines, parseSymbolArg, renderSymbolProvenance, renderWhyHost, renderWhyPath, renderWhySymbol, twinWords, whyTargetKind,
  type WhyHostAnswer, type WhyPathAnswer, type WhySymbolAnswer,
} from "../../src/why.js";
import { computeNetGuardSpecs } from "../../src/net-guard.js";

test("whyTargetKind: paths by shape or existence, hosts by name", () => {
  const none = (): boolean => false;
  assert.equal(whyTargetKind("~/.pgpass", none, "/w"), "path");
  assert.equal(whyTargetKind(".env", none, "/w"), "path", "no dot-separated labels: not a host");
  assert.equal(whyTargetKind("cloud/credentials", none, "/w"), "path");
  assert.equal(whyTargetKind("api.stripe.com", none, "/w"), "host");
  assert.equal(whyTargetKind("db.internal:5432", none, "/w"), "host");
  assert.equal(whyTargetKind("notes.md", (p) => p === "/w/notes.md", "/w"), "path", "an existing file wins over a host-shaped name");
});

test("guardAdmits: the default launch admits any host on 443 through the fallback; strict does not", () => {
  const base = { targetProxyPort: 8788, netProxyPort: null, ullmForwarderPort: null, apiHost: "api.anthropic.com" };
  assert.equal(guardAdmits(computeNetGuardSpecs({ ...base, strict: false }), "example.com", 443), "tcp:*:443");
  assert.equal(guardAdmits(computeNetGuardSpecs({ ...base, strict: true }), "example.com", 443), null);
  assert.equal(guardAdmits(computeNetGuardSpecs({ ...base, strict: true }), "api.anthropic.com", 443), "tcp:api.anthropic.com:443");
  assert.equal(guardAdmits(computeNetGuardSpecs({ ...base, strict: true, extraAllow: ["tcp:db.internal:5432"] }), "db.internal", 5432), "tcp:db.internal:5432");
});

const P: WhyPathAnswer = {
  path: "/h/.pgpass", axis: true, level: "no-model", rule: "prefix:~/.pgpass", bindings: [], outranked: [],
  readers: [], others: null, consumers: ["psql", "pg_dump"], wire: { served: false, why: "the Postgres wire protocol" },
  twinShape: "pgpass", verdicts: [{ app: "cat", status: "denied", scope: "always" }],
};

test("renderWhyPath names the deciding rule, the twin, the readers and the way out", () => {
  const out = renderWhyPath(P, "/h");
  assert.match(out, /^~\/\.pgpass/);
  assert.match(out, /the built-in catalog \(prefix:~\/\.pgpass\)/);
  assert.match(out, /keeps the file's structure \(pgpass\)/);
  // the catalog's content tier (secret-discovery.md §2.6) says what it read
  const found = renderWhyPath({ ...P, path: "/h/ws/accounts/power.yaml", rule: "content:secret-key", twinShape: "yaml-keys" }, "/h");
  assert.match(found, /because +Mandu found a saved password or key in this config file \(content:secret-key\); a label of yours decides instead/);
  // a personal document (secret-discovery.md §2.7)
  const doc = renderWhyPath({ ...P, path: "/h/ws/bank/statement.md", rule: "content:personal-document", twinShape: "extract" }, "/h");
  assert.match(doc, /because +Mandu read this file and found a personal document \(a statement, a tax return, a lab report, household codes: content:personal-document\); the AI reads its labels, each value is a placeholder; a label of yours decides instead/);
  assert.match(out, /its usual programs read it by default: psql, pg_dump/);
  assert.match(out, /these programs need the real file \(the Postgres wire protocol\)/);
  assert.match(out, /no host \(any send is held for your OK\)/);
  assert.match(out, /cat opening it: denied \(always\)/);
  assert.match(renderWhyPath({ ...P, level: "public", rule: null }, "/h"), /Not secret \(public\): the AI reads it as is/);
  assert.match(out, /level +No AI \(no-model\)/, "the glossary's words, the level name kept");
  assert.match(renderWhyPath({ ...P, level: "any-model" }, "/h"), /level +Any AI, when it asks \(any-model\); it is sent only where a rule or your OK allows/);
  assert.match(renderWhyPath({ ...P, axis: false }, "/h"), /secrets protection is off/);
});

test("renderWhyPath: an agent's login is raw only where that agent runs, a placeholder copy elsewhere, with the opt-out; an agent's own data is raw in every session (secret-discovery.md §1.10)", () => {
  const codex: WhyPathAnswer = {
    ...P, path: "/h/.codex/auth.json", rule: "prefix:~/.codex", consumers: [], wire: null, twinShape: "json-keys", verdicts: [],
    agentFile: { kind: "login", agent: "codex" },
  };
  const out = renderWhyPath(codex, "/h");
  assert.match(out, /login +Codex's login\. Left raw in a session that runs Codex \(mandu codex and mandu openclaw\), because the agent logs in/);
  assert.match(out, /there programs read the real file, it may go to the agent's own services, and a command that names/);
  assert.match(out, /elsewhere +in every other session it is masked like any credential file, as below; MANDU_OTHER_AGENT_LOGINS=raw leaves/);
  assert.match(out, /keeps the file's structure \(json-keys\)/, "the placeholder copy of the other sessions follows");
  const claude = renderWhyPath({ ...codex, path: "/h/.claude.json", agentFile: { kind: "login", agent: "claude" } }, "/h");
  // The exact rule (agent-login.ts loginKeptWhere): both variables that
  // select the helper's API mode, and --no-mcp, which turns it off.
  assert.match(claude, /Claude Code's login\. Left raw in a session that runs Claude Code \(mandu claude, a plain command \(mandu -- <command>\) and mandu openclaw, and mandu goose or mandu opencode while Mandu's AI helper runs claude \(neither ANTHROPIC_API_KEY nor MANDU_ULLM_API_KEY set, and no --no-mcp\)\)/);
  assert.match(renderWhyPath({ ...codex, path: "/h/.local/share/opencode/auth.json", agentFile: { kind: "login", agent: "opencode" } }, "/h"), /OpenCode's login\. Left raw in a session that runs OpenCode \(mandu opencode\)/);
  // A login CODEX_HOME moved out of the catalog's places (rule agent-login).
  const moved = renderWhyPath({ ...codex, path: "/srv/cx/auth.json", rule: "agent-login:codex" }, "/h");
  assert.match(moved, /because +Codex's login file, where your environment moved it \(agent-login:codex\)/);
  assert.match(moved, /Codex's login\. Left raw in a session that runs Codex/);

  const store: WhyPathAnswer = { ...codex, path: "/h/.claude/projects/s.jsonl", rule: "prefix:~/.claude", twinShape: null, agentFile: { kind: "store", agent: "claude" } };
  const s = renderWhyPath(store, "/h");
  assert.match(s, /left raw +Claude Code's own data \(its sessions, settings, tool outputs\): left raw in every session, because the agent/);
  assert.match(s, /the AI +sees a placeholder for what a command that names this path prints/);
  assert.ok(!/placeholder copy|readers +none|gets the placeholder/.test(s), `never the promise of a placeholder copy for a file left raw:\n${s}`);
  assert.match(renderWhyPath({ ...store, path: "/h/.local/state/goose/logs/llm_request.0.jsonl", agentFile: { kind: "store", agent: "goose" } }, "/h"), /Goose's own data/);
  // A user's `public` label wins: nothing about agents is said.
  assert.ok(!/login|left raw/.test(renderWhyPath({ ...codex, level: "public", rule: "label:/h/.codex/auth.json" }, "/h")));
  // secret-discovery.md §2.10: `.claude.json` and Codex's `config.toml` are
  // also the agent's MCP config, whose servers' credentials are registered.
  assert.match(claude, /MCP config Claude Code's MCP servers too: when one holds a credential, every launch registers this file/);
  assert.match(claude, /a session that runs Claude Code leaves the file/);
  assert.ok(!/MCP config/.test(out), "auth.json is no MCP config");
  const toml = renderWhyPath({ ...store, path: "/h/.codex/config.toml", rule: "prefix:~/.codex", agentFile: { kind: "store", agent: "codex" } }, "/h");
  assert.match(toml, /MCP config Codex's MCP servers too/);
  assert.match(toml, /read it as it is \(but for its MCP servers', below\)/);
  assert.ok(!/its values are not registered/.test(toml), "never that its values are not registered");
  assert.match(s, /its values are not registered/, "another store file keeps the line");
});

// 2026-10-09: the line said "each value is a placeholder" of every file
// whose PATH has a structured shape, so of a labelled .mcp.json whose list
// values stayed raw, and of a .json the arbiter in fact hid whole. Now it
// says what the arbiter made of the file as it is.
test("renderWhyPath: the AI line says what the registration makes of the file, not what its path suggests", () => {
  const mcp: WhyPathAnswer = { ...P, path: "/h/w/.mcp.json", rule: "label:/h/w/.mcp.json", consumers: [], wire: null, twinShape: "json-keys", verdicts: [] };
  const line = (a: WhyPathAnswer) => renderWhyPath(a, "/h").split("\n").find((l) => l.startsWith("  the AI"))!;
  assert.equal(line({ ...mcp, twin: { form: "structured", shape: "json-keys", fields: 4 } }),
    "  the AI     sees a placeholder copy that keeps the file's structure (json-keys); each secret value Mandu recognizes is a placeholder (4 in the file now)");
  assert.equal(line({ ...mcp, twin: { form: "whole-file", shape: "json-keys", fields: 0 } }),
    "  the AI     sees a whole-file placeholder (one placeholder for the whole file): Mandu finds no secret value it can hide in place in this json-keys file, so it hides all of it");
  assert.equal(line({ ...mcp, path: "/h/w/notes.md", twinShape: null, twin: { form: "whole-file", shape: null, fields: 0 } }),
    "  the AI     sees a whole-file placeholder (one placeholder for the whole file)");
  assert.equal(line({ ...mcp, path: "/h/.ssh/config", twinShape: "ssh-config", twin: { form: "own-text", shape: "ssh-config", fields: 0 } }),
    "  the AI     sees the file as it is (ssh-config): it holds no secret value Mandu recognizes");
  // An older arbiter (no `twin`): the path's shape, and what it depends on.
  assert.match(line(mcp), /keeps the file's structure \(json-keys\) when Mandu recognizes a secret value in it, each secret value it recognizes a placeholder; otherwise a whole-file placeholder/);
  assert.match(line({ ...mcp, twinShape: null }), /sees a whole-file placeholder \(one placeholder for the whole file\)$/);
  for (const a of [mcp, { ...mcp, twin: { form: "structured" as const, shape: "json-keys", fields: 1 } }]) assert.doesNotMatch(renderWhyPath(a, "/h"), /each value is a placeholder/);
  assert.equal(twinWords({ twinShape: "dotenv", twin: { form: "structured", shape: "dotenv", fields: 1 } }),
    "a placeholder copy that keeps the file's structure (dotenv); each secret value Mandu recognizes is a placeholder (1 in the file now)");
});

test("renderWhyPath: an ssh config's withheld commands, by line and keyword, with why and the way out (plan 10 §11.13.3)", () => {
  const ssh: WhyPathAnswer = {
    ...P, path: "/h/.ssh/config", rule: "prefix:~/.ssh", consumers: [], wire: null, twinShape: "ssh-config", verdicts: [],
    withheld: [{ line: 7, keyword: "ProxyCommand" }, { line: 12, keyword: "RemoteCommand" }],
  };
  const out = renderWhyPath(ssh, "/h");
  assert.match(out, /withheld +line 7 \(ProxyCommand\), line 12 \(RemoteCommand\): programs the agent runs get this file without those commands/);
  assert.match(out, /why +Mandu cannot vouch for a command .*would run code holding one/);
  assert.match(out, /way out +use ProxyJump/);
  assert.match(out, /name ssh a reader of ~\/\.ssh\/config \(readers: \[ssh\], others: twin;/);
  assert.match(out, /\{ app: bash, script: \/absolute\/path\/of\/the\/script \}/);
  assert.match(out, /or run this ssh outside the agent/);
  assert.doesNotMatch(renderWhyPath({ ...ssh, withheld: [] }, "/h"), /withheld/, "nothing withheld, no line");
  assert.doesNotMatch(renderWhyPath({ ...ssh, withheld: undefined }, "/h"), /withheld/, "an older arbiter");
  assert.match(renderWhyPath({ ...ssh, withheld: [{ line: 3, keyword: "Match exec" }] }, "/h"), /without that command/);
});

test("renderWhyPath: a shell or an interpreter named alone admits nothing, and the note names the script pin (plan 13 §8 decision (b))", () => {
  const env: WhyPathAnswer = {
    ...P, path: "/h/ws/.env", rule: "label:/h/ws/.env", consumers: [], wire: null, twinShape: "dotenv", others: "deny",
    readers: ["bash", "psql", { app: "python3", script: "/opt/tools/report.py" }], readersAdmitNothing: [true, false, false],
  };
  const out = renderWhyPath(env, "/h");
  assert.match(out, /readers +bash \(admits nothing\), psql, python3 running \/opt\/tools\/report\.py/);
  assert.match(out, /note +bash runs any code given to it, so no program reads the file through that entry, inline code \(bash -c …\) included; .*\{ app: bash, script: \/absolute\/path\/of\/the\/script \}/);
  // an older arbiter (no flags): the list as written, no note
  const old = renderWhyPath({ ...env, readersAdmitNothing: undefined }, "/h");
  assert.match(old, /readers +bash, psql/);
  assert.doesNotMatch(old, /admits nothing/);
});

test("renderWhyPath: a printer reader admits nothing, pinned or not, and its note says why; an answer about it no longer applies (plan 13 D8, 2026-10-03)", () => {
  const env: WhyPathAnswer = {
    ...P, path: "/h/ws/.env", rule: "label:/h/ws/.env", consumers: [], wire: null, twinShape: "dotenv", others: "twin",
    readers: ["cat", { app: "head", path: "/usr/bin/head", sha256: "a".repeat(64) }, "bash", "psql"],
    readersAdmitNothing: [true, true, true, false], readersPrint: [true, true, false, false],
    verdicts: [{ kind: "open", app: "cat", exe: "/usr/bin/cat", status: "approved", scope: "always", printer: true }],
  };
  const out = renderWhyPath(env, "/h");
  assert.match(out, /readers +cat \(admits nothing\), head \(admits nothing\), bash \(admits nothing\), psql/);
  assert.match(out, /note +cat, head print the file to whatever reads their output \(which can be the agent's own code\), so no program reads the file through those entries, pinned or not; name the program that uses the secret instead/);
  assert.match(out, /note +bash runs any code given to it/, "the code-running note names only the shell");
  assert.doesNotMatch(out, /cat, head, bash runs/);
  assert.match(out, /decided +\/usr\/bin\/cat opening it: approved \(always\) — no longer applies: cat prints the file to whatever reads its output, so it never gets the real file; you will not be asked again/);
  assert.doesNotMatch(out, /readers +none/, "a listed file does not also say none are listed");
});

test("renderWhyPath: a renamed copy of an interpreter or a printer, pinned by its hash, says what it is a copy of (2026-10-03)", () => {
  const env: WhyPathAnswer = {
    ...P, path: "/h/ws/.env", rule: "label:/h/ws/.env", consumers: [], wire: null, twinShape: "dotenv", others: "twin",
    readers: [{ app: "mytool", path: "/h/bin/mytool", sha256: "a".repeat(64) }, { app: "mycat", path: "/h/bin/mycat", sha256: "b".repeat(64) }, "bash", "psql"],
    readersAdmitNothing: [true, true, true, false], readersPrint: [false, true, false, false], readersCopyOf: ["python3.12", "cat", null, null],
    verdicts: [],
  };
  const out = renderWhyPath(env, "/h");
  assert.match(out, /readers +mytool \(admits nothing\), mycat \(admits nothing\), bash \(admits nothing\), psql/);
  assert.match(out, /note +mytool is a copy of python3\.12 \(byte for byte, by its sha256\), which runs any code given to it, so no program reads the file through that entry, whatever its name/);
  assert.match(out, /\{ app: python3\.12, script: \/absolute\/path\/of\/the\/script \}/, "the script form names the installed interpreter, not the copy");
  assert.match(out, /note +mycat is a copy of cat \(byte for byte, by its sha256\), which prints the file/);
  assert.match(out, /note +bash runs any code given to it/, "the generic note names only the shell");
  assert.doesNotMatch(out, /mytool, bash run|mycat print the file/, "a copy is not also in the generic notes");
  // an older arbiter (no readersCopyOf): the generic notes, as before
  const old = renderWhyPath({ ...env, readersCopyOf: undefined }, "/h");
  assert.match(old, /note +mytool, bash run any code/);
});

test("renderWhyPath: an interpreter's answer names its script, a run's says so, and one naming the interpreter alone says it no longer applies (plan 13 §8 decision (c))", () => {
  const rc: WhyPathAnswer = {
    ...P, path: "/h/.bashrc", level: "public", rule: null, consumers: [], wire: null, twinShape: null,
    verdicts: [
      { kind: "write", app: "python3.12", exe: "/usr/bin/python3.12", script: "/opt/tools/fix.py", status: "approved", scope: "always" },
      { kind: "write", app: "bash", exe: "/usr/bin/bash", run: true, status: "pending", scope: "always" },
      { kind: "write", app: "bash", exe: "/usr/bin/bash", stale: true, status: "approved", scope: "always" },
    ],
  };
  const out = renderWhyPath(rc, "/h");
  assert.match(out, /decided +\/usr\/bin\/python3\.12 running \/opt\/tools\/fix\.py changing it: approved \(always\)\n/);
  assert.match(out, /decided +\/usr\/bin\/bash running its own code \(that change only\) changing it: pending/);
  assert.match(out, /decided +\/usr\/bin\/bash changing it: approved \(always\) — no longer applies: it names the interpreter, not the script it runs; you will be asked again/);
});

test("renderWhyPath: a held change's verdict names the binary by its path, on any level and with the axis off (write-protection.md §2.1)", () => {
  const rc: WhyPathAnswer = {
    ...P, path: "/h/.bashrc", level: "public", rule: null, consumers: [], wire: null, twinShape: null,
    verdicts: [{ kind: "write", app: "vim", exe: "/usr/bin/vim", status: "approved", scope: "always" }, { kind: "write", app: "vim", status: "denied", scope: "once" }],
  };
  const out = renderWhyPath(rc, "/h");
  assert.match(out, /decided +\/usr\/bin\/vim changing it: approved \(always\)/);
  assert.match(out, /decided +vim changing it: denied \(once\)/, "a row from before 2026-10-02 names the program only");
  assert.doesNotMatch(out, /opening it/);
  assert.match(renderWhyPath({ ...rc, axis: false }, "/h"), /\/usr\/bin\/vim changing it: approved/, "write protection holds with the secrets axis off");
});

test("renderWhyHost names bound secrets and both release answers", () => {
  const H: WhyHostAnswer = {
    host: "api.stripe.com", axis: true,
    bound: [{ path: "/h/p/.env", level: "no-model", binding: ["api.stripe.com"], source: "label" }],
    release: {
      bound: { decision: { allow: true, ruleRef: { id: "egress:secret-bound-trusted" } }, stage: "rule" },
      unbound: { decision: { allow: false, requiresApproval: true, reason: "unbound" }, stage: "rule" },
    },
    destinations: [], verdicts: [],
  };
  const out = renderWhyHost(H, "/h", { spec443: "tcp:*:443" });
  assert.match(out, /yes on :443 \(guard rule tcp:\*:443, the default any-host HTTPS rule\)/);
  assert.match(out, /bound {6}~\/p\/\.env \(no AI may read it, from your label\)/);
  assert.match(out, /a bound secret sent here: +released \(rule egress:secret-bound-trusted\): the real value goes out/);
  assert.match(out, /an unbound secret sent here: +held for your OK.*: you answer it on the dashboard's Approvals page \(`mandu dashboard`\)/);
  assert.doesNotMatch(out, /§|declassification|symbol/, "the arbiter's internal reason stays in --json (release checklist d5)");
  assert.doesNotMatch(out, /issuer/, "an older arbiter says nothing of an issuer");
});

test("renderWhyHost: an issuer's API host says which key formats go there without asking, and the switch (confidentiality.md §2.3)", () => {
  const H: WhyHostAnswer = {
    host: "api.stripe.com", axis: true, bound: [],
    release: { bound: null, unbound: { decision: { allow: false, requiresApproval: true, reason: "unbound" }, stage: "rule" } },
    destinations: [], verdicts: [],
    issuer: { id: "stripe", name: "Stripe", shapes: ["sk_live_…", "sk_test_…"], on: true },
  };
  const on = renderWhyHost(H, "/h", { spec443: null });
  assert.match(on, /issuer {5}Stripe's API host: a key in Stripe's format \(sk_live_…, sk_test_…\) from your files or environment is sent here without asking, in the Authorization header over HTTPS only \(issuer_bindings in policy\.yaml turns it off\)/);
  const off = renderWhyHost({ ...H, issuer: { ...H.issuer!, on: false } }, "/h", { spec443: null });
  assert.match(off, /issuer {5}Stripe's API host: sending a Stripe key here asks you first/);
});

test("runWhy: a resident arbiter older than `why` is replaced by a fresh one over the same law", async () => {
  const { runWhy } = await import("../../src/why.js");
  const calls: string[] = [];
  let stopped = 0;
  const answer: WhyPathAnswer = { ...P, path: "/h/.pgpass" };
  const deps = {
    arbiter: async () => ({ sock: "old.sock", kind: "resident" as const, axisOn: true, stop: async () => { stopped++; } }),
    fresh: async () => ({ sock: "new.sock", kind: "throwaway" as const, axisOn: true, stop: async () => { stopped++; } }),
    call: async <T>(sock: string, op: string): Promise<T> => {
      calls.push(`${sock}:${op}`);
      if (sock === "old.sock") throw new Error(`unknown op: ${op}`);
      return answer as T;
    },
    exists: () => false,
    cwd: () => "/h",
    // stdout through the sink: patching process.stdout.write would swallow
    // the test runner's report, which shares the stream.
    out: (s: string) => { out.push(s); },
  };
  const out: string[] = [];
  const err: string[] = [];
  const ew = process.stderr.write.bind(process.stderr);
  (process.stderr as unknown as { write: (s: string) => boolean }).write = (s) => { err.push(s); return true; };
  try {
    assert.equal(await runWhy(["~/.pgpass"], { HOME: "/h" }, {} as never, deps), 0);
  } finally {
    (process.stderr as unknown as { write: typeof ew }).write = ew;
  }
  assert.deepEqual(calls, ["old.sock:whyPath", "new.sock:whyPath"]);
  // The login variables ride along, so a moved login is named (secret-discovery.md §1.10).
  const args: Array<Record<string, unknown>> = [];
  const deps2 = {
    ...deps,
    arbiter: async () => ({ sock: "x.sock", kind: "resident" as const, axisOn: true, stop: async () => {} }),
    call: async <T>(_s: string, _op: string, a: Record<string, unknown>): Promise<T> => { args.push(a); return answer as T; },
  };
  const ew2 = process.stderr.write.bind(process.stderr);
  (process.stderr as unknown as { write: (s: string) => boolean }).write = () => true;
  try {
    assert.equal(await runWhy(["/data/cx/auth.json"], { HOME: "/h", CODEX_HOME: "/data/cx", OPENAI_API_KEY: "sk-x" }, {} as never, deps2), 0);
  } finally {
    (process.stderr as unknown as { write: typeof ew2 }).write = ew2;
  }
  assert.deepEqual(args[0], { path: "/data/cx/auth.json", home: "/h", loginEnv: { CODEX_HOME: "/data/cx" } });
  assert.equal(stopped, 2, "both arbiters are released (the throwaway is removed)");
  assert.match(err.join(""), /predates `mandu why`/);
  assert.match(out.join(""), /~\/\.pgpass/);
  // Tour item 17: a temporary service reads policy.yaml as written, so it
  // says what it cannot see.
  assert.match(err.join(""), /no Mandu service is running here, so this answer reads policy\.yaml as it is on disk; a change in it that still waits for your OK in Approvals reads as if it were in force/);
});

test("tour 17: renderWhyPath / renderWhyHost say a change waits in Approvals, from whom, what it would make the file, and that the lines above are in force", () => {
  const out = renderWhyPath({ ...P, pending: [
    { id: "pp-000003", from: "file", level: "no-model", bindings: ["api.stripe.com"], rule: "label:/h/.pgpass" },
    { id: "pp-000004", from: "agent", level: "any-model", bindings: [], rule: "label:/h/.pgpass" },
    { id: "pp-000005", from: "scan", level: "public", bindings: [], rule: null },
  ] }, "/h");
  assert.match(out, /waiting +a change to this file's rule waits for your OK in Approvals \(pp-000003: policy\.yaml was changed on disk\); approved, the file is a secret no AI may read \(no-model\) and may go to api\.stripe\.com/);
  assert.match(out, /\(pp-000004: your agent asked for it\); approved, the file is a secret any AI may read when it asks \(any-model\) and goes nowhere without your OK/);
  assert.match(out, /\(pp-000005: Mandu's scan suggests it\); approved, the file is public \(not a secret\)/);
  assert.match(out, /until you answer it on the dashboard's Approvals page \(`mandu dashboard`\), the lines above are what Mandu enforces\n$/);
  assert.doesNotMatch(renderWhyPath(P, "/h"), /waiting/, "nothing pending: no line");
  assert.doesNotMatch(renderWhyPath({ ...P, pending: [] }, "/h"), /waiting/);
  const host: WhyHostAnswer = { host: "api.stripe.com", axis: true, bound: [], release: { bound: null, unbound: null }, destinations: [], verdicts: [], pending: [{ id: "pp-000007", from: "other" }] };
  assert.match(renderWhyHost(host, "/h", { spec443: null }), /waiting +a change to what may go to this host waits for your OK in Approvals \(pp-000007: asked for on the dashboard\)\n/);
});

test("renderWhyPath --to: a remembered answer decided (tour 1): says so, and where it is removed; the law's answers unchanged", () => {
  const allow = renderWhyPath(P, "/h", { host: "collector.example", egress: { decision: { allow: true, reason: "human-approved", ruleRef: { id: "verdict:eg_7" } }, stage: "verdict" } });
  assert.match(allow, /send to collector\.example: released by your remembered answer \(verdict:eg_7\): the real value goes out; it is listed under "Where data may go" on the dashboard's Rules page/);
  const deny = renderWhyPath(P, "/h", { host: "collector.example", egress: { decision: { allow: false, requiresApproval: false, reason: "human-denied", ruleRef: { id: "verdict:eg_8" } }, stage: "verdict" } });
  assert.match(deny, /send to collector\.example: blocked by your remembered answer \(verdict:eg_8\)/);
  const held = renderWhyPath(P, "/h", { host: "collector.example", egress: { decision: { allow: false, requiresApproval: true, ruleRef: { id: "egress:secret-unbound" } }, stage: "built-in" } });
  assert.match(held, /send to collector\.example: held for your OK \(rule egress:secret-unbound\)/);
  assert.doesNotMatch(held, /remembered/);
  assert.match(renderWhyPath(P, "/h", { host: "x.example", egress: null, answersUnknown: true }), /your remembered answers were not consulted/);
});

test("runWhy --to: the host as the gate keys it (lowercase, no port); a throwaway service says it knows no answers", async () => {
  const { runWhy } = await import("../../src/why.js");
  for (const kind of ["resident", "throwaway"] as const) {
    const asked: Array<Record<string, unknown>> = [];
    const out: string[] = [];
    const deps = {
      arbiter: async () => ({ sock: "a.sock", kind, axisOn: true, stop: async () => {} }),
      fresh: async () => { throw new Error("not asked"); },
      call: async <T>(_sock: string, op: string, args: Record<string, unknown>): Promise<T> => {
        if (op === "testFlow") { asked.push(args); return { egress: { decision: { allow: true, ruleRef: { id: "verdict:eg_1" } }, stage: "verdict" } } as T; }
        return { ...P, path: "/h/.env" } as T;
      },
      exists: () => false,
      cwd: () => "/h",
      out: (s: string) => { out.push(s); },
    };
    assert.equal(await runWhy(["/h/.env", "--to", "Collector.Example:443"], { HOME: "/h" }, {} as never, deps), 0);
    assert.deepEqual(asked, [{ source: { tool: "Read", origin: "/h/.env" }, destination: "collector.example" }]);
    assert.match(out.join(""), /send to collector\.example: released by your remembered answer/);
    if (kind === "throwaway") assert.match(out.join(""), /your remembered answers were not consulted/);
    else assert.doesNotMatch(out.join(""), /not consulted/);
  }
});

// ── `mandu why '$MDU:…'` (plan 15 §13.8) ─────────────────────────────────────

const SYM = "$MDU:localmodel_prompt_filter[1a2b]";
const S: WhySymbolAnswer = {
  symbol: SYM, axis: true, known: true, source: "prompt-filter", level: "local-model", tool: "prompt_filter", origin: null, field: null,
  session: "sess-1", createdAt: 1, obsolete: false, searched: 1,
  findings: [{
    session: "sess-1", firstTs: "2026-10-03T10:00:00.000Z", lastTs: "2026-10-03T10:02:00.000Z", turn: 3, requests: 3, agent: "claude-code",
    origin: "human", filterId: "acme-dlp", category: "acme.codename", action: "mask", segmentAction: "rewrite", enforcing: true,
    ref: "a".repeat(32), turnRef: "b".repeat(32),
  }],
  verdicts: [],
  policy: [{ category: "acme.codename", action: "mask", row: "acme.codename", setBy: "you", locked: null, exceptions: 0 }],
  filters: [{ id: "acme-dlp", kind: "pack", description: "Acme's data-loss patterns" }],
};

test("parseSymbolArg / whyTargetKind: a placeholder as typed, quoted or after the shell ate `$MDU`", () => {
  assert.equal(parseSymbolArg(SYM), SYM);
  assert.equal(parseSymbolArg("MDU:localmodel_prompt_filter[1a2b]"), SYM);
  assert.equal(parseSymbolArg(":localmodel_prompt_filter[1a2b]"), SYM, "bash expands an unquoted $MDU to nothing");
  assert.equal(parseSymbolArg("$MDU:Secret[ab12].STRIPE_KEY"), "$MDU:Secret[ab12].STRIPE_KEY");
  for (const no of ["localmodel_prompt_filter[1a2b]", "$MDU:x", "$MDU:x[zz]", "~/.pgpass", "api.stripe.com"]) assert.equal(parseSymbolArg(no), null, no);
  const none = (): boolean => false;
  assert.equal(whyTargetKind(SYM, none, "/w"), "symbol");
  assert.equal(whyTargetKind(":x[ab12]", (p) => p === "/w/:x[ab12]", "/w"), "path", "an existing file wins");
});

test("renderWhySymbol: a prompt finding in plain words, with the ways out; never a value", () => {
  const out = renderWhySymbol(S, "/h");
  assert.match(out, /^\$MDU:localmodel_prompt_filter\[1a2b\]\n/);
  assert.match(out, /what +part of your own message to the AI was hidden from it/);
  assert.match(out, /found by +the pack acme-dlp \("Acme's data-loss patterns"\)/);
  assert.match(out, /category +acme\.codename/);
  assert.match(out, /action +mask: hidden: the AI read this placeholder in its place/);
  assert.match(out, /session +sess-1, model request 4, 2026-10-03 10:00:00 UTC; carried again by 2 later requests/);
  assert.match(out, /policy now acme\.codename: mask \(your policy\.yaml \(prompt_filters\.actions\.acme\.codename\)\)/);
  assert.match(out, /way out +let it through: on the dashboard \(`mandu dashboard`\): the note under your message.*\n +for that message or the rest of the session/);
  assert.doesNotMatch(out, /\/dev\/|developer view/, "the way out names the product page only");
  assert.match(out, /change what Mandu does with acme\.codename: the dashboard's Settings › Prompt filters, or in policy\.yaml\n +prompt_filters: actions: \{ acme\.codename: log \}/);
  assert.match(out, /add an exception: Settings › Prompt filters, or prompt_filters: exceptions:\n +\[\{ category: acme\.codename, match: "<the text, \* and \? as wildcards>" \}\]/);
  assert.doesNotMatch(out, /Inbox \(Approvals\): send as written/, "no held message: no Inbox line");
});

test("renderWhySymbol: an ask's ending and the answers on file", () => {
  const held = { ...S.findings[0]!, action: "ask", hold: { state: "pending", approvalId: "ea-1" } };
  const out = renderWhySymbol({ ...S, findings: [held], verdicts: [{ approvalId: "ea-1", session: "sess-1", category: "acme.codename", scope: "message", status: "pending", resolvedAt: null }] }, "/h");
  assert.match(out, /action +ask: held for your answer: the message waits in the dashboard's Inbox/);
  assert.match(out, /answer +acme\.codename for that message: waiting for your answer in the Inbox/);
  assert.match(out, /a message still held is answered in the Inbox \(Approvals\)/);
  for (const [state, words] of [["sent", /you answered: send it as written/], ["masked", /you answered: send it masked/], ["cancelled", /you cancelled the message/], ["timed-out", /no answer came in time/], ["default", /without asking/]] as const) {
    assert.match(renderWhySymbol({ ...S, findings: [{ ...held, hold: { state } }] }, "/h"), words, state);
  }
  assert.match(renderWhySymbol({ ...S, findings: [{ ...S.findings[0]!, let: "session" }] }, "/h"), /you let it through as written, for the rest of the session/);
  assert.match(renderWhySymbol({ ...S, verdicts: [{ approvalId: "ea-2", session: "sess-1", category: "acme.codename", scope: "session", status: "approved", resolvedAt: 2 }] }, "/h"), /answer +acme\.codename for the rest of the session: goes as written/);
});

test("renderWhySymbol: a registered value and a locked category have no way out here", () => {
  const reg: WhySymbolAnswer = {
    ...S, source: "secret", tool: "Read", origin: "/h/proj/.env", field: "STRIPE_KEY", level: "no-model",
    findings: [{ ...S.findings[0]!, filterId: "registered-value", category: "secret.registered" }],
    policy: [{ category: "secret.registered", action: "mask", row: "secret.registered", setBy: "default", locked: null, exceptions: 0 }], filters: [],
  };
  const r = renderWhySymbol(reg, "/h");
  assert.match(r, /a secret Mandu already holds was in your own message to the AI/);
  assert.match(r, /secret +~\/proj\/\.env \(STRIPE_KEY\)/);
  assert.match(r, /found by +the registered-value filter/);
  assert.match(r, /the prompt filter never lets a secret Mandu holds through as written/);
  assert.match(r, /mandu why ~\/proj\/\.env says who may read it/);
  assert.doesNotMatch(r, /let it through: on the dashboard/);
  const locked = renderWhySymbol({ ...S, policy: [{ ...S.policy[0]!, action: "block", locked: { action: "block", file: "/etc/mandu/policy.d/org.yaml" } }] }, "/h");
  assert.match(locked, /way out +none here: your administrator set acme\.codename to block and locked it \(\/etc\/mandu\/policy\.d\/org\.yaml\)/);
  assert.doesNotMatch(locked, /let it through: on the dashboard/);
});

test("renderWhySymbol: under a locked administrator's ask row, the ways out say that message only and why (plan 15 §12, 2026-10-04)", () => {
  const ORG = "/etc/mandu/policy.d/org.yaml";
  const held = { ...S.findings[0]!, action: "ask", hold: { state: "pending", approvalId: "ea-1" } };
  // The arbiter's `onceOnly` (a locked `ask` row covers it, even under a narrower row that decides the action).
  const out = renderWhySymbol({ ...S, findings: [held], policy: [{ ...S.policy[0]!, action: "ask", onceOnly: { file: ORG } }] }, "/h");
  assert.match(out, /way out +let it through: on the dashboard \(`mandu dashboard`\): the note under your message.*\n +for that message only\n/);
  assert.match(out, /your administrator set acme\.codename to ask every time \(\/etc\/mandu\/policy\.d\/org\.yaml\), so it takes no answer for the rest of the session/);
  assert.doesNotMatch(out, /for that message or the rest of the session/);
  assert.match(out, /a message still held is answered in the Inbox \(Approvals\): send as written, send masked, or cancel/);
  // An older arbiter (no `onceOnly`): a locked `ask` that decides the action says it too.
  const older = renderWhySymbol({ ...S, policy: [{ ...S.policy[0]!, action: "ask", locked: { action: "ask", file: ORG } }] }, "/h");
  assert.match(older, /for that message only\n +your administrator set acme\.codename to ask every time \(\/etc\/mandu\/policy\.d\/org\.yaml\)/);
  // No lock: the session is offered.
  assert.match(renderWhySymbol(S, "/h"), /for that message or the rest of the session/);
});

test("renderWhySymbol: not from the prompt filter, unknown, and the data plane's answer", () => {
  const bare = { ...S, findings: [], policy: [], filters: [] };
  assert.match(renderWhySymbol({ ...bare, source: "secret", origin: "/h/.pgpass" }, "/h"), /not from the prompt filter: a secret Mandu holds, ~\/\.pgpass/);
  assert.match(renderWhySymbol({ ...bare, source: "secret", origin: "env:STRIPE_API_KEY" }, "/h"), /the environment variable STRIPE_API_KEY/);
  assert.match(renderWhySymbol({ ...bare, source: "other", tool: "WebFetch", level: "public" }, "/h"), /data a program gave the AI \(WebFetch\)/);
  assert.match(renderWhySymbol({ ...bare, known: false, source: "unknown" }, "/h"), /holds no such placeholder/);
  const p = renderSymbolProvenance(SYM, { tool: "prompt_filter" });
  assert.match(p, /Mandu's prompt filter made it/);
  assert.match(p, /shown only outside the agent/);
});

test("renderWhySymbol --session (!422's hint, 2026-10-09): with no finding it offers the flag and the count searched; a named session with no finding says so", () => {
  const bare: WhySymbolAnswer = { ...S, findings: [], policy: [], filters: [], searched: 24 };
  const HINT = /searched 24 sessions for a message that carried it; for a message in another session, ask again with --session <id> \(the dashboard lists your sessions\)/;
  assert.match(renderWhySymbol(bare, "/h"), HINT, "a prompt-filter placeholder with no finding");
  assert.match(renderWhySymbol(bare, "/h"), /no record of the message was found: its session log is gone, or it is not among the sessions searched/);
  assert.match(renderWhySymbol({ ...bare, source: "secret", origin: "/h/.env", field: "K" }, "/h"), HINT, "a secret: its prompt finding may be in another session");
  assert.match(renderWhySymbol({ ...bare, known: false, source: "unknown" }, "/h"), HINT, "unknown: the session log may still be there");
  assert.match(renderWhySymbol({ ...bare, searched: 1 }, "/h"), /searched 1 session for/);
  assert.doesNotMatch(renderWhySymbol(S, "/h"), /--session/, "a finding: no hint");
  // The flag given: no hint; a note when the named session holds no finding.
  const named = renderWhySymbol(bare, "/h", { session: "old-7" });
  assert.doesNotMatch(named, /ask again with --session/);
  assert.match(named, /note +no finding names this placeholder in session old-7 \(or this Mandu service has no such session\)/);
  const hit = renderWhySymbol(S, "/h", { session: "sess-1" });
  assert.doesNotMatch(hit, /no finding names/, "the named session holds the finding");
  assert.match(hit, /session +sess-1, model request 4/);
  assert.match(renderWhySymbol(S, "/h", { session: "other" }), /no finding names this placeholder in session other/, "found elsewhere, not in the named one");
});

test("runWhy --session: sent as the whySymbol hint; a usage error with no id, a flag for an id, an id too long, or a host target", async () => {
  const { runWhy } = await import("../../src/why.js");
  const sent: Array<Record<string, unknown>> = [];
  const out: string[] = [];
  const resident = async () => ({ sock: "data.sock", kind: "resident" as const, axisOn: true, stop: async () => {} });
  const deps = {
    fresh: async () => { throw new Error("never a fresh arbiter"); },
    exists: () => false,
    cwd: () => "/h",
    out: (s: string) => { out.push(s); },
    arbiter: resident,
    humanSock: async () => "human.sock",
    call: async <T>(_sock: string, op: string, args?: Record<string, unknown>): Promise<T> => {
      sent.push({ op, ...(args ?? {}) });
      return { ...S, findings: [], searched: 2 } as T;
    },
  };
  const err: string[] = [];
  const ew = process.stderr.write.bind(process.stderr);
  (process.stderr as unknown as { write: (s: string) => boolean }).write = (s) => { err.push(s); return true; };
  try {
    assert.equal(await runWhy(["--session", "old-7", SYM], { HOME: "/h" }, {} as never, deps), 0, "the flag before the target");
    assert.deepEqual(sent, [{ op: "whySymbol", symbol: SYM, session: "old-7" }]);
    assert.match(out.join(""), /no finding names this placeholder in session old-7/);
    sent.length = 0;
    assert.equal(await runWhy([SYM], { HOME: "/h" }, {} as never, deps), 0);
    assert.deepEqual(sent, [{ op: "whySymbol", symbol: SYM }], "no flag: no hint sent");
    sent.length = 0;
    for (const bad of [[SYM, "--session"], [SYM, "--session", "--json"], [SYM, "--session", "x".repeat(257)], ["api.example.com", "--session", "s1"]]) {
      assert.equal(await runWhy(bad, { HOME: "/h" }, {} as never, deps), 2, bad.join(" "));
    }
    assert.deepEqual(sent, [], "nothing asked on a usage error");
    assert.match(err.join(""), /--session applies to a placeholder or a file, not to a host/);
  } finally {
    (process.stderr as unknown as { write: typeof ew }).write = ew;
  }
});

test("runWhy <file> --session: sent as whyPath's session (plan 10 §11.13, the launch HOME); none without the flag", async () => {
  const { runWhy } = await import("../../src/why.js");
  const sent: Array<Record<string, unknown>> = [];
  const out: string[] = [];
  const deps = {
    fresh: async () => { throw new Error("never a fresh arbiter"); },
    exists: () => false,
    cwd: () => "/h",
    out: (s: string) => { out.push(s); },
    arbiter: async () => ({ sock: "data.sock", kind: "resident" as const, axisOn: true, stop: async () => {} }),
    humanSock: async () => "human.sock",
    call: async <T>(_sock: string, op: string, args?: Record<string, unknown>): Promise<T> => {
      sent.push({ op, ...(args ?? {}) });
      return { ...P, path: "/tmp/x/.ssh/config", launch: { session: "s1", home: "/tmp/x", newest: false } } as T;
    },
  };
  assert.equal(await runWhy(["/tmp/x/.ssh/config", "--session", "s1"], { HOME: "/h" }, {} as never, deps), 0);
  assert.deepEqual(sent, [{ op: "whyPath", path: "/tmp/x/.ssh/config", home: "/h", session: "s1" }]);
  assert.match(out.join(""), /home +also judged under \/tmp\/x, the HOME session s1 was started with\n/);
  sent.length = 0;
  assert.equal(await runWhy(["/tmp/x/.ssh/config"], { HOME: "/h" }, {} as never, deps), 0);
  assert.deepEqual(sent, [{ op: "whyPath", path: "/tmp/x/.ssh/config", home: "/h" }], "no flag: no session sent (the arbiter takes the newest running launch)");
});

test("launchHomeLines: the running session's HOME when it is not yours, the newest one's with the flag to name another, a session not running said so", async () => {
  const { launchHomeLines } = await import("../../src/why.js");
  assert.deepEqual(launchHomeLines(undefined, "/h"), []);
  assert.deepEqual(launchHomeLines({ session: "s1", home: "/h", newest: true }, "/h"), [], "your own HOME: nothing to add");
  assert.match(launchHomeLines({ session: "s1", home: "/tmp/x", newest: true }, "/h").join(""), /also judged under \/tmp\/x, the HOME session s1 was started with \(the newest running session; for another, ask again with --session <id>\)/);
  assert.doesNotMatch(launchHomeLines({ session: "s1", home: "/tmp/x", newest: false }, "/h").join(""), /newest/);
  assert.match(launchHomeLines({ session: "gone", home: null, newest: false }, "/h").join(""), /session gone is not running on this Mandu service, so only your HOME \(\/h\) was used/);
});

test("categoryWords / filterWords: plain words, the id kept", () => {
  assert.equal(categoryWords("pii.payment-card"), "a payment card number (pii.payment-card)");
  assert.equal(categoryWords("secret.shape.github-token"), "something shaped like a key or password (github-token) (secret.shape.github-token)");
  assert.equal(categoryWords("acme.codename"), "acme.codename");
  assert.equal(filterWords("key-shapes"), "the key-shapes filter (credentials by their format)");
  assert.equal(filterWords("local-classifier", [{ id: "local-classifier", kind: "plugin" }]), "the plugin local-classifier");
});

test("runWhy '$MDU:…': asked on the human plane; walled off, the data plane's answer; a throwaway knows none", async () => {
  const { runWhy } = await import("../../src/why.js");
  const calls: string[] = [];
  const out: string[] = [];
  const base = {
    fresh: async () => { throw new Error("never a fresh arbiter for a placeholder"); },
    exists: () => false,
    cwd: () => "/h",
    out: (s: string) => { out.push(s); },
  };
  const resident = async () => ({ sock: "data.sock", kind: "resident" as const, axisOn: true, stop: async () => {} });
  const err: string[] = [];
  const ew = process.stderr.write.bind(process.stderr);
  (process.stderr as unknown as { write: (s: string) => boolean }).write = (s) => { err.push(s); return true; };
  try {
    // The human plane answers.
    const ok = await runWhy([SYM], { HOME: "/h" }, {} as never, {
      ...base, arbiter: resident, humanSock: async () => "human.sock",
      call: async <T>(sock: string, op: string): Promise<T> => { calls.push(`${sock}:${op}`); return S as T; },
    });
    assert.equal(ok, 0);
    assert.deepEqual(calls, ["human.sock:whySymbol"]);
    assert.match(out.join(""), /found by +the pack acme-dlp/);
    // Walled off (the agent's world): symbolProvenance on the data socket.
    calls.length = 0;
    out.length = 0;
    const walled = await runWhy([SYM], { HOME: "/h" }, {} as never, {
      ...base, arbiter: resident, humanSock: async () => "human.sock",
      call: async <T>(sock: string, op: string): Promise<T> => {
        calls.push(`${sock}:${op}`);
        if (sock === "human.sock") throw Object.assign(new Error("connect EACCES human.sock"), { code: "EACCES" });
        return { tool: "prompt_filter", field: null, callId: null, toolName: null, toolInput: { secret: "never printed" } } as T;
      },
    });
    assert.equal(walled, 0);
    assert.deepEqual(calls, ["human.sock:whySymbol", "data.sock:symbolProvenance"]);
    assert.match(out.join(""), /shown only outside the agent/);
    assert.doesNotMatch(out.join(""), /never printed/);
    // No human socket named: the data plane's answer too, never whySymbol there.
    calls.length = 0;
    await runWhy([SYM, "--json"], { HOME: "/h" }, {} as never, {
      ...base, arbiter: resident, humanSock: async () => null,
      call: async <T>(sock: string, op: string): Promise<T> => { calls.push(`${sock}:${op}`); return { tool: "prompt_filter" } as T; },
    });
    assert.deepEqual(calls, ["data.sock:symbolProvenance"]);
    // A throwaway arbiter (none running) knows no placeholder.
    let stopped = 0;
    const none = await runWhy([SYM], { HOME: "/h" }, {} as never, {
      ...base, arbiter: async () => ({ sock: "t.sock", kind: "throwaway" as const, axisOn: true, stop: async () => { stopped++; } }),
      call: async <T>(): Promise<T> => { throw new Error("not asked"); },
    });
    assert.equal(none, 1);
    assert.equal(stopped, 1);
    assert.match(err.join(""), /no Mandu service is running here/);
    // --to makes no sense for a placeholder.
    assert.equal(await runWhy([SYM, "--to", "x.com"], { HOME: "/h" }, {} as never, { ...base, arbiter: resident, call: async <T>(): Promise<T> => ({}) as T }), 2);
  } finally {
    (process.stderr as unknown as { write: typeof ew }).write = ew;
  }
});

test("renderWhyPath (plan 13 §4.9, 2026-10-04): a usual program that prints (git for .git-credentials, curl and git for .netrc) is no default reader; it says so", () => {
  const creds: WhyPathAnswer = {
    ...P, path: "/h/.git-credentials", rule: "prefix:~/.git-credentials", consumers: ["git", "git-credential-store"], consumersPrint: [true, true],
    wire: { served: true, why: "git: GIT_SSL_CAINFO; basic auth in a header" }, twinShape: "git-credentials", verdicts: [],
  };
  const out = renderWhyPath(creds, "/h");
  assert.match(out, /readers +none listed; none of its usual programs reads it by default/);
  assert.match(out, /note +git, git-credential-store print the files they are pointed at, so they get the placeholder copy too, never the real file/);
  assert.match(out, /over HTTPS a placeholder these programs send is put back at a bound host/);
  assert.doesNotMatch(out, /read it by default: git/);
  // the ssh keys: ssh and ssh-add still read them; git and scp print
  const key = renderWhyPath({ ...creds, path: "/h/.ssh/id_ed25519", consumers: ["ssh", "git", "scp", "ssh-add"], consumersPrint: [false, true, true, false] }, "/h");
  assert.match(key, /its usual programs read it by default: ssh, ssh-add\n/);
  assert.match(key, /note +git, scp print the files they are pointed at/);
  // an older arbiter (no consumersPrint): as before
  assert.match(renderWhyPath(P, "/h"), /its usual programs read it by default: psql, pg_dump/);
});

test("mandu why <file>: per-value bindings (plan 13 §5.2) read one line per value, then the whole file's", () => {
  assert.deepEqual(mayGoLines({ bindings: ["a.example"] }), ["  may go to  a.example"], "no values: as before");
  assert.deepEqual(mayGoLines({ bindings: [], fileBindings: [], values: [{ key: "STRIPE_KEY", bindings: ["api.stripe.com"] }, { key: "AWS_*", bindings: [] }] }), [
    "  value      STRIPE_KEY may go to api.stripe.com",
    "  value      AWS_* may go to no host (any send is held for your OK)",
    "  value      any other may go to no host (any send is held for your OK)",
    "  may go to  no host, for a program holding the whole file (where every value may go)",
  ]);
});

// ── no Mandu running: the store read, read-only (comparisons.md §3.2) ────────

test("whyArbiter: the resident one; axis off, a throwaway; none running, a throwaway seeded from the store, else the unseeded one of before", async () => {
  const { whyArbiter, residentStorePath } = await import("../../src/why.js");
  type Opts = { seedFrom?: string } | undefined;
  const calls: Opts[] = [];
  const t = (fail = false) => async (_e: unknown, _l: unknown, opts?: { seedFrom?: string }) => {
    calls.push(opts);
    if (fail && opts?.seedFrom !== undefined) throw new Error("a throwaway arbiter refused to start: --seed-from: written by another Mandu version");
    return { sock: "t.sock", kind: "throwaway" as const, axisOn: true, ...(opts?.seedFrom !== undefined ? { seeded: true } : {}), stop: async () => {} };
  };
  const env = { HOME: "/h" };
  const store = "/h/.mandu/state/mandu.db";
  assert.equal(residentStorePath(env), store);
  assert.equal(residentStorePath({ HOME: "/h", MANDU_HOME: "/m" }), "/m/state/mandu.db", "MANDU_HOME moves it, as it moves the arbiter's");

  const r = await whyArbiter(env, {} as never, { resident: async () => ({ sock: "r.sock", axisOn: true }), throwaway: t(), exists: () => true });
  assert.deepEqual([r.sock, r.kind, r.seeded], ["r.sock", "resident", undefined]);
  assert.deepEqual(calls, [], "a running arbiter: nothing spawned, nothing read");

  const off = await whyArbiter(env, {} as never, { resident: async () => ({ sock: "r.sock", axisOn: false }), throwaway: t(), exists: () => true });
  assert.deepEqual([off.kind, off.axisOn, off.seeded], ["throwaway", false, undefined]);
  assert.deepEqual(calls.splice(0), [undefined], "axis off: an unseeded throwaway, as doctor --secrets");

  const seeded = await whyArbiter(env, {} as never, { resident: async () => null, throwaway: t(), exists: (p) => p === store });
  assert.deepEqual([seeded.kind, seeded.seeded], ["throwaway", true]);
  assert.deepEqual(calls.splice(0), [{ seedFrom: store }]);

  const refused = await whyArbiter(env, {} as never, { resident: async () => null, throwaway: t(true), exists: () => true });
  assert.deepEqual([refused.kind, refused.seeded], ["throwaway", undefined]);
  assert.deepEqual(calls.splice(0), [{ seedFrom: store }, undefined], "a refused seed: asked again unseeded");

  const absent = await whyArbiter(env, {} as never, { resident: async () => null, throwaway: t(), exists: () => false });
  assert.equal(absent.seeded, undefined);
  assert.deepEqual(calls.splice(0), [undefined], "no store: no seed attempted");
});

test("runWhy on a seeded throwaway: the remembered answer and the waiting change stand without the 'not consulted' note; the note says the store was read", async () => {
  const { runWhy, SEEDED_NOTE, THROWAWAY_NOTE } = await import("../../src/why.js");
  for (const seeded of [true, false]) {
    const out: string[] = [];
    const err: string[] = [];
    const deps = {
      arbiter: async () => ({ sock: "t.sock", kind: "throwaway" as const, axisOn: true, ...(seeded ? { seeded: true } : {}), stop: async () => {} }),
      fresh: async () => { throw new Error("not asked"); },
      call: async <T>(_sock: string, op: string): Promise<T> => {
        if (op === "testFlow") return { egress: { decision: { allow: true, ruleRef: { id: "verdict:eg_1" } }, stage: "verdict" } } as T;
        return { ...P, path: "/h/.env", pending: [{ id: "pp-1", from: "file", level: "no-model", bindings: ["api.stripe.com"], rule: "label:/h/.env" }] } as T;
      },
      exists: () => false,
      cwd: () => "/h",
      out: (s: string) => { out.push(s); },
    };
    const ew = process.stderr.write.bind(process.stderr);
    (process.stderr as unknown as { write: (s: string) => boolean }).write = (s) => { err.push(String(s)); return true; };
    try {
      assert.equal(await runWhy(["/h/.env", "--to", "collector.example"], { HOME: "/h" }, {} as never, deps), 0);
    } finally {
      (process.stderr as unknown as { write: typeof ew }).write = ew;
    }
    assert.match(out.join(""), /send to collector\.example: released by your remembered answer/);
    assert.match(out.join(""), /waiting +a change to this file's rule waits for your OK in Approvals \(pp-1: policy\.yaml was changed on disk\)/);
    if (seeded) {
      assert.doesNotMatch(out.join(""), /not consulted/);
      assert.equal(err.join(""), SEEDED_NOTE);
    } else {
      assert.match(out.join(""), /your remembered answers were not consulted/);
      assert.equal(err.join(""), THROWAWAY_NOTE);
    }
  }
});
