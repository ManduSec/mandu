/**
 * A CATALOG file the launch did not register (a `.env` created mid-session,
 * deeper than the discovery walk's MAX_DEPTH, past its MAX_FILES, outside
 * HOME and the workspace), read by a recursive or indirect read
 * (confidentiality.md §6 "Read by a program the launch did not see",
 * 2026-10-17), across the REAL ArbiterServer in `secrets` and the REAL
 * anthropic-proxy in production wiring (`new ArbiterClientAdapter(new
 * ArbiterClient(sock), human)`), a mock model behind it.
 *
 * The repro (2026-10-17): with no launch walk ever seeing the file and no
 * gate at the open, every program read it raw, and of the tool results that
 * printed its line only a `cat` naming its path reached the model masked:
 * `grep -r`, `rg`, `tar`, `find -exec cat`, a script reading it reached the
 * model in clear (the text scan cannot place a path it is not shown, and the
 * value was no registered secret).
 *
 * The fix is the guard's: it learns the catalog from the arbiter
 * (`labelRootsSince`: the prefixes as roots, the basename shapes as a
 * prefilter of name anchors), asks about a candidate (`labelledLevel`, the
 * walk's own rule and prunes) and serves its twin from `registerSecret`,
 * which registers the file, so the value backstop knows its values for any
 * print that still carries them. This test plays the guard's half of that
 * protocol over the human socket, as `label_index` / `labelled_entry` do it
 * (the kernel half is net-supervisor's catalog_open_integration and the
 * sandbox suite's secret-catalog-opens), then sends each program's output to
 * the model: the twin a gated program prints, and the raw line too (the
 * agent's own process is not gated at the open; its result is caught by the
 * value backstop the registration armed). Red before the change: the
 * arbiter shipped no catalog, so the guard asked nothing, registered
 * nothing, and every raw print reached the model.
 *
 * Controls: a `.env.example` is no catalog secret by the walk's rule (no
 * content check): it is not registered and its text reaches the model; a
 * `.env` inside `node_modules` is not a candidate (the walk never enters it).
 * A source file named like a credential (`src/auth/providers/credentials.ts`,
 * 2026-10-17) is no candidate either (the `*credentials*` anchor's
 * `notSuffixes`), `labelledLevel` calls it public for a guard that asks, and
 * its text reaches the model; its `credentials.json` sibling is gated.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import type { GuardCatalogWire, LabelRootsSinceResultWire } from "../../arbiter/ipc/protocol.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

/** The values, assembled at run time. */
const VALUE = ["q7Vt", "Rz2m", "Kp9x", "Lw4c", "Hn8b"].join("");
const SAMPLE = ["sample", "only", "8f1e"].join("-");
const SOURCE = ["SOURCE", "CONTROL", "c0de"].join("-");

/** The guard's prefilter (label_index.rs `candidate`): under a literal root,
 *  or a name a catalog anchor admits with no skipped directory below the
 *  deepest catalog home holding it (below `/` outside every one). */
function candidate(path: string, r: LabelRootsSinceResultWire): boolean {
  const under = (root: string, p: string): string | null => (p === root ? "" : p.startsWith(root.replace(/\/$/, "") + "/") ? p.slice(root.replace(/\/$/, "").length + 1) : root === "/" ? p.slice(1) : null);
  const walkSkip = new Set(r.skipDirs);
  for (const root of r.roots) {
    const rest = under(root.path, path);
    if (rest === null) continue;
    const segs = rest.split("/").filter(Boolean);
    if (segs.slice(0, -1).some((d) => walkSkip.has(d))) continue;
    if (!root.shape) return true;
  }
  const c: GuardCatalogWire | undefined = r.catalog;
  if (!c) return false;
  const name = basename(path);
  const fold = (s: string, ci?: boolean): string => (ci ? s.toLowerCase() : s);
  const admits = c.names.some((a) => {
    const n = fold(name, a.ci);
    return (a.exact !== undefined || a.prefix !== undefined || a.suffix !== undefined || a.contains !== undefined)
      && (a.exact === undefined || n === fold(a.exact, a.ci)) && (a.prefix === undefined || n.startsWith(fold(a.prefix, a.ci)))
      && (a.suffix === undefined || n.endsWith(fold(a.suffix, a.ci))) && (a.contains === undefined || n.includes(fold(a.contains, a.ci)))
      && !(a.notSuffixes ?? []).some((x) => n.endsWith(fold(x, a.ci)));
  });
  if (!admits) return false;
  const base = c.homes.filter((h) => under(h, path) !== null).sort((a, b) => b.length - a.length)[0] ?? "/";
  const dirs = (under(base, path) ?? "").split("/").filter(Boolean).slice(0, -1);
  return !dirs.some((d) => walkSkip.has(d) || c.skipDirs.includes(d));
}

test("a catalog file the launch did not register: the guard's protocol gates it, and no print of it reaches the model in clear (secrets axes, explicit)", { timeout: 60_000 }, async () => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-catalog-")));
  const ws = join(tmp, "ws");
  const deep = join(ws, "a", "b", "c", "d", "e");
  for (const d of [deep, join(ws, "node_modules", "pkg")]) mkdirSync(d, { recursive: true });
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, "version: 1\n");
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    policyPath: policy, policyPollMs: 50, log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const guard = await open(humanSock);
  const human = await open(humanSock);
  const session = `catalog-${process.pid}`;
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await open(sock), human), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  let n = 0;
  /** One Bash call whose result is `output`; what the model received. */
  const bashCall = async (command: string, output: string, cwd: string): Promise<string> => {
    const id = `toolu_cat_${n++}`;
    await human.recordCallCommand({ callId: id, command, sessionKey: session });
    await guard.recordExecRoot({ procKey: `sh-${id}`, ancestors: ["agent-cat-0"], session, callRoot: true, argv: ["/bin/bash", "-c", command], cwd });
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5", stream: true, max_tokens: 256,
        tools: [{ name: "Bash", input_schema: { type: "object" } }],
        messages: [
          { role: "user", content: "go" },
          { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
          { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: output }] },
        ],
      }),
    });
    assert.equal(res.status, 200, await res.text());
    const body = upstream.requests.at(-1)!.json() as { messages: Array<{ content: Array<{ content?: unknown }> }> };
    return JSON.stringify(body.messages[2]!.content[0]!.content);
  };
  try {
    // MID-SESSION: the files appear after any launch walk; nothing registers them.
    const env = join(deep, ".env");
    writeFileSync(env, `DB_PASSWORD=${VALUE}\n`);
    const example = join(ws, ".env.example");
    writeFileSync(example, `DB_PASSWORD=${SAMPLE}\n`);
    const dep = join(ws, "node_modules", "pkg", ".env");
    writeFileSync(dep, "FIXTURE=1\n");
    const plain = join(ws, "main.py");
    writeFileSync(plain, "print('hi')\n");
    // A source file named like a credential, deeper than the walk (2026-10-17):
    // program source, no catalog shape; and its data sibling, still one.
    const providers = join(deep, "src", "auth", "providers");
    mkdirSync(providers, { recursive: true });
    const source = join(providers, "credentials.ts");
    writeFileSync(source, `export const PROVIDER = "${SOURCE}";\n`);
    const credJson = join(providers, "credentials.json");
    writeFileSync(credJson, `{"token":"${VALUE}-json"}\n`);

    // The guard's half, as label_index / labelled_entry do it at the open.
    const roots = await guard.labelRootsSince({ session });
    assert.ok(roots.catalog, "the arbiter ships the catalog's name prefilter");
    const gate = async (p: string): Promise<{ candidate: boolean; level: string | null; twin: string | null }> => {
      if (!candidate(p, roots)) return { candidate: false, level: null, twin: null };
      const { level } = await guard.labelledLevel({ path: p, session });
      if (level === "public") return { candidate: true, level, twin: null };
      const reg = await guard.registerSecret({ path: p });
      assert.ok(reg.symbol, `the twin of ${p} is minted: ${reg.reason}`);
      return { candidate: true, level, twin: reg.twin ?? `${reg.symbol}\n` };
    };
    const g = await gate(env);
    assert.deepEqual([g.candidate, g.level], [true, "no-model"], "the deep .env is a candidate and classifies secret");
    assert.ok(g.twin !== null && !g.twin.includes(VALUE), "its twin holds no value");
    assert.deepEqual([(await gate(example)).candidate, (await gate(example)).level], [true, "public"], "a template: the walk's rule, not twinned");
    assert.equal((await gate(dep)).candidate, false, "a .env in node_modules: no round trip");
    assert.equal((await gate(plain)).candidate, false, "a file no anchor admits: no round trip");
    assert.equal((await gate(source)).candidate, false, "a source file named like a credential: no round trip (the anchor's notSuffixes)");
    assert.equal((await guard.labelledLevel({ path: source, session })).level, "public", "and a guard that predates notSuffixes, asking, gets public");
    const gj = await gate(credJson);
    assert.deepEqual([gj.candidate, gj.level], [true, "no-model"], "its data sibling credentials.json is gated");

    const line = `DB_PASSWORD=${VALUE}`;
    const twin = g.twin!.trimEnd();
    const cases: Array<[string, string]> = [
      // what each gated program prints: the twin
      ["cat a/b/c/d/e/.env", `${twin}\n`],
      ["grep -r '' .", `./a/b/c/d/e/.env:${twin}\n`],
      ["tar cf - . | tar xOf -", `${twin}\n`],
      // and a print that still carries the value (the agent's own process,
      // or a reader the human named): the value backstop the registration armed
      ["grep -r DB_PASSWORD .", `./a/b/c/d/e/.env:${line}\n`],
      ["rg DB_PASSWORD", `a/b/c/d/e/.env\n1:${line}\n`],
      ["tar cf - . | tar xOf -", `${line}\n`],
      ["find . -type f -exec cat {} +", `${line}\n`],
      ["python3 run.py", `${line}\n`],
    ];
    const report: string[] = [];
    for (const [cmd, out] of cases) {
      const seen = await bashCall(cmd, out, ws);
      report.push(`${seen.includes(VALUE) ? "LEAK  " : "masked"} | ${cmd} | ${out.includes(VALUE) ? "raw line" : "twin"}`);
    }
    assert.ok(report.every((r) => r.startsWith("masked")), report.join("\n"));
    // The control: a template's sample value is no secret and reaches the model.
    const seen = await bashCall("cat .env.example", `DB_PASSWORD=${SAMPLE}\n`, ws);
    assert.ok(seen.includes(SAMPLE), `a .env.example is not masked (the walk's rule): ${seen}`);
    // The source file a compiler or a test runner read raw, and the model
    // sees it too: a command naming its path is no catalog read.
    const src = await bashCall("cat a/b/c/d/e/src/auth/providers/credentials.ts", `export const PROVIDER = "${SOURCE}";\n`, ws);
    assert.ok(src.includes(SOURCE), `a source file named like a credential is not masked: ${src}`);
    const tsc = await bashCall("npx tsc --noEmit", `a/b/c/d/e/src/auth/providers/credentials.ts(1,14): ${SOURCE}\n`, ws);
    assert.ok(tsc.includes(SOURCE), `a compiler's diagnostic quoting it is not masked: ${tsc}`);
  } finally {
    await proxy.close();
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
