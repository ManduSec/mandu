/**
 * mcp-server-taint — plan 10 §11.13's per-server MCP rule over the REAL
 * components, end to end:
 *
 *   the agent's MCP config on disk (a fixture HOME: `~/.claude.json`,
 *   `~/.codex/config.toml`) → the LAUNCHER's reader and its registration on
 *   the arbiter's HUMAN socket (`registerLaunchMcpServers`, the real
 *   `ndjsonCall`) → the guard's exec records (written as the guard writes
 *   them: `recordExecRoot` with the argv, `taintProcessSecret`) → the real
 *   ArbiterServer in `secrets` → both proxies over the PRODUCTION adapters.
 *
 * The session read a secret raw (a listed reader). Per wire, the leak oracle:
 *   - a server whose OWN tree read a secret raw: its result never reaches the
 *     model (Claude Code masks it now; before, it went raw);
 *   - a clean server: Claude Code forwards it as before; Codex now forwards
 *     it raw too (before, !281's session rule masked it);
 *   - an unmapped server (configured over HTTP, so not registered): masked
 *     by the session on both wires (rule (c); on Claude Code since
 *     2026-10-03, maintainer; before, raw there).
 * Red with the per-server rule removed from either proxy, or rule (c) from
 * either proxy.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { registerLaunchMcpServers } from "../../launcher/src/mcp-server-config.js";
import { ndjsonCall } from "../../launcher/src/secret-setup.js";
import { rewriteRequest as rewriteMessages } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import type { MessagesRequest } from "../../interceptors/anthropic-proxy/src/messages-types.js";
import { rewriteRequest as rewriteResponses } from "../../interceptors/openai-proxy/src/rewrite-request.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import type { ResponsesRequest } from "../../interceptors/openai-proxy/src/responses-types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const BATTERY = { type: "additional_tools", role: "developer", tools: [{ type: "namespace", name: "functions", tools: [{ type: "custom", name: "exec", description: "- Evaluates the provided JavaScript code in a fresh V8 isolate as an async module." }] }] };

test("a tainted MCP server's result is masked on both wires; a clean one is raw in a tainted session; an unmapped one is masked by the session on both wires (real launcher reader, real arbiter, production adapters)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-mcp-srv-e2e-"));
  const home = join(tmp, "home");
  const work = join(tmp, "work");
  mkdirSync(join(home, ".codex"), { recursive: true });
  mkdirSync(work, { recursive: true });
  // the agents' own MCP config, as the user wrote it
  writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: {
    "dirty-store": { command: "npx", args: ["-y", "@acme/dirty-store"] },
    "clean-notes": { command: "node", args: ["/opt/notes/server.js"] },
    "remote-docs": { type: "http", url: "https://docs.example/mcp" },
  } }));
  writeFileSync(join(home, ".codex", "config.toml"), [
    "[mcp_servers.dirty-store]", 'command = "npx"', 'args = ["-y", "@acme/dirty-store"]',
    "[mcp_servers.clean-notes]", 'command = "node"', 'args = ["/opt/notes/server.js"]',
    "[mcp_servers.remote-docs]", 'url = "https://docs.example/mcp"', "",
  ].join("\n"));

  const human = join(tmp, "human", "h.sock");
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({ socketPath, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const guard = new ArbiterClient(human); await guard.connect(); // the guard reports on the human socket (plan 13 D9)
  const realHuman = new ArbiterClient(human); await realHuman.connect(); // the proxies' second client (server-main)
  const realA = new ArbiterClient(socketPath); await realA.connect();
  const realO = new ArbiterClient(socketPath); await realO.connect();
  try {
    const leaks: string[] = [];
    for (const target of ["claude", "codex"] as const) {
      const session = `mcp-srv-${target}-${process.pid}`;
      // the launcher's registration, on the human socket
      const reg = await registerLaunchMcpServers(
        { target, scopeId: session, humanCwd: work, cwd: work, arbiterHumanSock: human, effectiveAxes: { integrity: false, confidentiality: true }, confidentiality: true } as never,
        { HOME: home },
        { home, call: (sock, op, args) => ndjsonCall<unknown>(sock, op, args, 5_000), log: () => {} },
      );
      assert.deepEqual(reg, { status: "registered", registered: 2 }, "the two stdio servers; the HTTP one is not a process");
      // what the guard saw: the agent spawned both servers; npx read ~/.npmrc raw
      // (node is a default reader of it) before it ran the package; and a
      // listed reader elsewhere in the session read a secret raw
      await guard.recordExecRoot({ procKey: `${target}-agent`, argv: [target], session });
      await guard.recordExecRoot({ procKey: `${target}-npx`, parentKey: `${target}-agent`, argv: ["npx", "-y", "@acme/dirty-store"], session });
      await guard.taintProcessSecret({ procKey: `${target}-npx`, path: join(home, ".npmrc"), level: "no-model", app: "node", session });
      await guard.recordExecRoot({ procKey: `${target}-notes`, parentKey: `${target}-agent`, argv: ["node", "/opt/notes/server.js"], session });
      await guard.taintProcessSecret({ procKey: `${target}-psql`, path: join(home, ".pgpass"), level: "no-model", app: "psql", session });

      const rows = { dirty: `dirty-row-${target}-7c1e`, clean: `clean-row-${target}-8d2f`, remote: `remote-row-${target}-9e3a` };
      const tools = (ns: (n: string) => string): Record<string, string> => ({ dirty: `mcp__${ns("dirty-store")}__get`, clean: `mcp__${ns("clean-notes")}__list`, remote: `mcp__${ns("remote-docs")}__search` });
      if (target === "claude") {
        const names = tools((n) => n);
        const adapter = new ArbiterClientAdapter(realA, realHuman);
        const out: Record<string, string> = {};
        for (const [k, name] of Object.entries(names)) {
          const req: MessagesRequest = { model: "claude-sonnet-5", messages: [
            { role: "user", content: "go" },
            { role: "assistant", content: [{ type: "tool_use", id: `tu_${k}`, name, input: { key: "x" } }] },
            { role: "user", content: [{ type: "tool_result", tool_use_id: `tu_${k}`, content: rows[k as keyof typeof rows] }] },
          ] };
          out[k] = JSON.stringify((await rewriteMessages(req, { arbiter: adapter, sessionKey: session })).request.messages[2]!.content);
        }
        if (out["dirty"]!.includes(rows.dirty)) leaks.push("claude: the tainted server's result");
        assert.match(out["dirty"]!, /\[mandu:secret\] masked: node read .*\.npmrc/);
        assert.ok(out["clean"]!.includes(rows.clean), "Claude Code: a clean server is forwarded as before");
        // rule (c) on Claude Code since 2026-10-03 (was: forwarded raw)
        if (out["remote"]!.includes(rows.remote)) leaks.push("claude: the unmapped server's result in a session holding a raw read");
      } else {
        const names = tools((n) => n.replace(/-/g, "_"));
        const adapter = new OpenAiProxyArbiterAdapter(realO, realHuman);
        const input: unknown[] = [BATTERY];
        for (const [k, name] of Object.entries(names)) {
          const [, ns, tool] = /^(mcp__[^_].*?)__([^_].*)$/.exec(name)!;
          input.push({ type: "function_call", call_id: `f_${k}`, namespace: ns, name: tool, arguments: "{\"key\":\"x\"}" });
          input.push({ type: "function_call_output", call_id: `f_${k}`, output: [{ type: "input_text", text: "Wall time: 0.1 seconds\nOutput:" }, { type: "input_text", text: rows[k as keyof typeof rows] }] });
        }
        const { request } = await rewriteResponses({ model: "m", input } as unknown as ResponsesRequest, { arbiter: adapter, sessionKey: session, skipPromptInjection: true });
        const out = (k: string) => JSON.stringify((request.input as Array<Record<string, unknown>>).find((i) => i["type"] === "function_call_output" && i["call_id"] === `f_${k}`)!["output"]);
        if (out("dirty").includes(rows.dirty)) leaks.push("codex: the tainted server's result");
        assert.ok(out("clean").includes(rows.clean), "Codex: a server proven clean is raw in a tainted session (was masked by the session rule)");
        assert.ok(!out("remote").includes(rows.remote), "Codex: an unmapped server keeps the session rule");
      }
    }
    assert.deepEqual(leaks, [], "CONFIDENTIALITY VIOLATION: a tainted MCP server's result reached the model");
  } finally {
    guard.close(); realHuman.close(); realA.close(); realO.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

// 2026-10-02: the sources plan 10 §11.13 left unmapped (a plugin's server, a
// server given on the agent's own argv) are read by the launcher too. On
// Claude Code an unmapped server's result was forwarded raw unless its input
// carried a command, so a plugin server whose own tree read a secret raw
// handed it to the model; mapped, it is masked by the per-server rule.
test("a plugin's MCP server and an --mcp-config server whose trees read a secret raw are masked on Claude Code; a Codex -c server proven clean is raw (real launcher reader, real arbiter, production adapters)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-mcp-src-e2e-"));
  const home = join(tmp, "home");
  const work = join(tmp, "work");
  const plugin = join(home, ".claude", "plugins", "cache", "mkt", "vault", "1.0.0");
  mkdirSync(join(plugin, ".claude-plugin"), { recursive: true });
  mkdirSync(work, { recursive: true });
  writeFileSync(join(home, ".claude", "plugins", "installed_plugins.json"), JSON.stringify({ version: 2, plugins: { "vault@mkt": [{ scope: "user", installPath: plugin, version: "1.0.0" }] } }));
  writeFileSync(join(plugin, ".mcp.json"), JSON.stringify({ mcpServers: { secrets: { command: "${CLAUDE_PLUGIN_ROOT}/bin/vault-mcp", args: ["--stdio"] } } }));
  writeFileSync(join(work, "extra-mcp.json"), JSON.stringify({ mcpServers: { "db-dump": { command: "dbdump-mcp", args: [] } } }));
  const human = join(tmp, "human", "h.sock");
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({ socketPath, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const guard = new ArbiterClient(human); await guard.connect();
  const realHuman = new ArbiterClient(human); await realHuman.connect();
  const realA = new ArbiterClient(socketPath); await realA.connect();
  const realO = new ArbiterClient(socketPath); await realO.connect();
  try {
    const plan = (target: "claude" | "codex", session: string, argv: string[]) =>
      ({ target, scopeId: session, humanCwd: work, cwd: work, arbiterHumanSock: human, effectiveAxes: { integrity: false, confidentiality: true }, confidentiality: true, argv }) as never;
    const deps = { home, call: (sock: string, op: string, args: Record<string, unknown>) => ndjsonCall<unknown>(sock, op, args, 5_000), log: () => {} };
    // Claude Code
    const cs = `mcp-src-claude-${process.pid}`;
    const reg = await registerLaunchMcpServers(plan("claude", cs, ["claude", "--mcp-config", "extra-mcp.json"]), { HOME: home }, deps);
    assert.deepEqual(reg, { status: "registered", registered: 2 }, "the plugin's server and the --mcp-config one");
    await guard.recordExecRoot({ procKey: "c-agent", argv: ["claude"], session: cs });
    await guard.recordExecRoot({ procKey: "c-vault", parentKey: "c-agent", argv: [join(plugin, "bin", "vault-mcp"), "--stdio"], session: cs });
    await guard.taintProcessSecret({ procKey: "c-vault", path: join(home, ".pgpass"), level: "no-model", app: "vault-mcp", session: cs });
    await guard.recordExecRoot({ procKey: "c-db", parentKey: "c-agent", argv: ["dbdump-mcp"], session: cs });
    await guard.taintProcessSecret({ procKey: "c-db", path: join(home, ".netrc"), level: "no-model", app: "dbdump-mcp", session: cs });
    const adapter = new ArbiterClientAdapter(realA, realHuman);
    const leaks: string[] = [];
    for (const [name, row] of [["mcp__plugin_vault_secrets__get", "vault-row-41c2"], ["mcp__db-dump__rows", "db-row-52d3"]] as const) {
      const req: MessagesRequest = { model: "claude-sonnet-5", messages: [
        { role: "user", content: "go" },
        { role: "assistant", content: [{ type: "tool_use", id: `tu_${name.length}`, name, input: { key: "x" } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: `tu_${name.length}`, content: row }] },
      ] };
      const out = JSON.stringify((await rewriteMessages(req, { arbiter: adapter, sessionKey: cs })).request.messages[2]!.content);
      // MASTER: unmapped, no command in the input: forwarded raw
      if (out.includes(row)) leaks.push(`claude: ${name}: ${out}`);
      else assert.match(out, /\[mandu:secret\] masked: /, out);
    }
    assert.deepEqual(leaks, [], "CONFIDENTIALITY VIOLATION: a tainted plugin or --mcp-config server's result reached the model");
    // Codex: a -c server, one clean process, in a session holding a raw read
    const xs = `mcp-src-codex-${process.pid}`;
    await registerLaunchMcpServers(plan("codex", xs, ["codex", "-c", 'mcp_servers.notes.command="notes-mcp"']), { HOME: home }, deps);
    await guard.recordExecRoot({ procKey: "x-agent", argv: ["codex"], session: xs });
    await guard.recordExecRoot({ procKey: "x-notes", parentKey: "x-agent", argv: ["notes-mcp"], session: xs });
    await guard.taintProcessSecret({ procKey: "x-psql", path: join(home, ".pgpass"), level: "no-model", app: "psql", session: xs });
    const { request } = await rewriteResponses({ model: "m", input: [BATTERY,
      { type: "function_call", call_id: "f_n", namespace: "mcp__notes", name: "list", arguments: "{\"key\":\"x\"}" },
      { type: "function_call_output", call_id: "f_n", output: [{ type: "input_text", text: "Wall time: 0.1 seconds\nOutput:" }, { type: "input_text", text: "notes-row-63e4" }] },
    ] } as unknown as ResponsesRequest, { arbiter: new OpenAiProxyArbiterAdapter(realO, realHuman), sessionKey: xs, skipPromptInjection: true });
    const out = JSON.stringify((request.input as Array<Record<string, unknown>>).find((i) => i["type"] === "function_call_output")!["output"]);
    assert.ok(out.includes("notes-row-63e4"), `utility: a -c server proven clean is raw (was masked by the session rule): ${out}`);
  } finally {
    guard.close(); realHuman.close(); realA.close(); realO.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

// 2026-10-03 (maintainer): plan 10 §11.13's rule (c) on Claude Code, reversing
// "not adopted". A secret read raw by the session, then echoed by an MCP
// server Mandu cannot map (an HTTP server, a registered server the guard never
// saw spawned, a resource read), reached the model raw on master (no command in
// the input, no tree to ask). Now the session decides: masked whole while it
// holds a raw read. A mapped server proven clean, and Mandu's own tools, are as
// before; before any raw read nothing is masked.
test("Claude Code: a secret read raw, then echoed by an unmapped MCP server, reaches the model only masked; a clean mapped server and Mandu's own tool are as before (real launcher reader, real arbiter, production adapter)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-mcp-unmapped-e2e-"));
  const home = join(tmp, "home");
  const work = join(tmp, "work");
  mkdirSync(home, { recursive: true });
  mkdirSync(work, { recursive: true });
  const pgpass = `db.internal:5432:*:app:Pg-${process.pid}-c7f3a9e1`;
  writeFileSync(join(home, ".pgpass"), `${pgpass}\n`, { mode: 0o600 });
  writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: {
    "clean-notes": { command: "node", args: ["/opt/notes/server.js"] },
    "idle-store": { command: "store-mcp", args: ["--stdio"] },
    "remote-docs": { type: "http", url: "https://docs.example/mcp" },
  } }));
  const human = join(tmp, "human", "h.sock");
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({ socketPath, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const guard = new ArbiterClient(human); await guard.connect();
  const realHuman = new ArbiterClient(human); await realHuman.connect();
  const realA = new ArbiterClient(socketPath); await realA.connect();
  try {
    const session = `mcp-unmapped-claude-${process.pid}`;
    const reg = await registerLaunchMcpServers(
      { target: "claude", scopeId: session, humanCwd: work, cwd: work, arbiterHumanSock: human, effectiveAxes: { integrity: false, confidentiality: true }, confidentiality: true } as never,
      { HOME: home },
      { home, call: (sock, op, args) => ndjsonCall<unknown>(sock, op, args, 5_000), log: () => {} },
    );
    assert.deepEqual(reg, { status: "registered", registered: 2 }, "the two stdio servers; the HTTP one is not a process");
    // the guard saw the agent spawn clean-notes; idle-store was never spawned
    await guard.recordExecRoot({ procKey: "u-agent", argv: ["claude"], session });
    await guard.recordExecRoot({ procKey: "u-notes", parentKey: "u-agent", argv: ["node", "/opt/notes/server.js"], session });
    const adapter = new ArbiterClientAdapter(realA, realHuman);
    let n = 0;
    const forward = async (name: string, input: Record<string, unknown>, content: string): Promise<string> => {
      const id = `tu_u${++n}`;
      const req: MessagesRequest = { model: "claude-sonnet-5", messages: [
        { role: "user", content: "go" },
        { role: "assistant", content: [{ type: "tool_use", id, name, input }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
      ] };
      return JSON.stringify((await rewriteMessages(req, { arbiter: adapter, sessionKey: session })).request.messages[2]!.content);
    };
    // before any raw read: a server Mandu has no mapping for (the HTTP one)
    // is masked whole all the same (plan 10 §11.18, 2026-10-07); a registered
    // one is not
    const early = "docs-before-any-read-1b2c";
    const earlyOut = await forward("mcp__remote-docs__search", { q: "x" }, early);
    assert.ok(!earlyOut.includes(early), "§11.18: an MCP server Mandu has no mapping for is masked whole in a session that read nothing");
    assert.match(earlyOut, /no mapping for the tool mcp__remote-docs__search.*mcp:remote-docs.*mapped_tools/);
    // (another text: the masked result above is now a registered value, §11.18 cost)
    const early2 = "store-before-any-read-5e6f";
    assert.ok((await forward("mcp__idle-store__get", { key: "x" }, early2)).includes(early2), "a registered server: nothing to mask before a raw read");

    // psql reads ~/.pgpass raw (a listed reader, as the guard reports it)
    await guard.recordExecRoot({ procKey: "u-psql", parentKey: "u-agent", argv: ["psql"], session });
    await guard.taintProcessSecret({ procKey: "u-psql", path: join(home, ".pgpass"), level: "no-model", app: "psql", session });

    // the secret comes back through servers Mandu cannot map
    const leaks: string[] = [];
    for (const [name, input] of [
      ["mcp__remote-docs__get", { key: "pg" }],
      ["mcp__idle-store__get", { key: "pg" }],
      ["ReadMcpResourceTool", { server: "remote-docs", uri: "docs://pg" }],
    ] as const) {
      const out = await forward(name, input, `stored: ${pgpass}`);
      if (out.includes(pgpass) || out.includes("c7f3a9e1")) leaks.push(`${name}: ${out}`);
      // a registered server takes the session rule (§11.13 (c)); the others have no mapping (§11.18)
      else if (name === "mcp__idle-store__get") assert.match(out, /MCP server whose state Mandu cannot see, and programs in this session read \.pgpass raw/, out);
      else assert.match(out, new RegExp(`no mapping for the tool ${name}`), out);
    }
    assert.deepEqual(leaks, [], "CONFIDENTIALITY VIOLATION: a secret read raw reached the model through an unmapped MCP server");

    // mapped, proven clean: as before (raw in a tainted session)
    const notes = "notes-row-3d4e";
    assert.ok((await forward("mcp__clean-notes__list", { key: "x" }, notes)).includes(notes), "a mapped server proven clean is raw, as before");
    // Mandu's own policy tool: the arbiter answers it empty (as before)
    const own = "No rules match.";
    assert.ok((await forward("mcp__mandu-policy__mandu_policy_read", {}, own)).includes(own), "Mandu's own tool is not masked by the session");
  } finally {
    guard.close(); realHuman.close(); realA.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

// 2026-10-03: Codex's own MCP resource tools (`read_mcp_resource`,
// `list_mcp_resources`, `list_mcp_resource_templates`), in the wire recorded
// off codex-cli 0.159.1 against a fake Responses server: a bare function_call,
// its output one JSON string. They are not `mcp__` tools and carry no command,
// so on master the session was never asked and a resource carrying a secret
// read raw reached the model. Now the session decides, whatever the server's
// own verdict (here: mapped and clean). The same server's own tool stays raw.
test("Codex: a secret read raw, then served as an MCP resource, reaches the model only masked; the clean server's own tool is raw (real launcher reader, real arbiter, production adapter)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-mcp-res-e2e-"));
  const home = join(tmp, "home");
  const work = join(tmp, "work");
  mkdirSync(join(home, ".codex"), { recursive: true });
  mkdirSync(work, { recursive: true });
  const pgpass = `db.internal:5432:*:app:Pg-${process.pid}-a8d4e2b7`;
  writeFileSync(join(home, ".pgpass"), `${pgpass}\n`, { mode: 0o600 });
  writeFileSync(join(home, ".codex", "config.toml"), ["[mcp_servers.res]", 'command = "node"', 'args = ["/opt/res/server.js"]', ""].join("\n"));
  const human = join(tmp, "human", "h.sock");
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({ socketPath, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const guard = new ArbiterClient(human); await guard.connect();
  const realHuman = new ArbiterClient(human); await realHuman.connect();
  const realO = new ArbiterClient(socketPath); await realO.connect();
  try {
    const session = `mcp-res-codex-${process.pid}`;
    const reg = await registerLaunchMcpServers(
      { target: "codex", scopeId: session, humanCwd: work, cwd: work, arbiterHumanSock: human, effectiveAxes: { integrity: false, confidentiality: true }, confidentiality: true } as never,
      { HOME: home },
      { home, call: (sock, op, args) => ndjsonCall<unknown>(sock, op, args, 5_000), log: () => {} },
    );
    assert.deepEqual(reg, { status: "registered", registered: 1 });
    await guard.recordExecRoot({ procKey: "r-agent", argv: ["codex"], session });
    await guard.recordExecRoot({ procKey: "r-res", parentKey: "r-agent", argv: ["node", "/opt/res/server.js"], session });
    const adapter = new OpenAiProxyArbiterAdapter(realO, realHuman);
    const resource = (text: string) => JSON.stringify({ server: "res", uri: "res://pg", contents: [{ uri: "res://pg", mimeType: "text/plain", text }] });
    const turn = async (text: string, id: string) => {
      const input: unknown[] = [BATTERY,
        { type: "function_call", call_id: `${id}_read`, name: "read_mcp_resource", arguments: JSON.stringify({ server: "res", uri: "res://pg" }) },
        { type: "function_call_output", call_id: `${id}_read`, output: resource(text) },
        { type: "function_call", call_id: `${id}_list`, name: "list_mcp_resources", arguments: "{}" },
        { type: "function_call_output", call_id: `${id}_list`, output: JSON.stringify({ resources: [{ server: "res", uri: "res://pg", name: text }] }) },
        { type: "function_call", call_id: `${id}_tpl`, name: "list_mcp_resource_templates", arguments: "{}" },
        { type: "function_call_output", call_id: `${id}_tpl`, output: JSON.stringify({ resourceTemplates: [{ uriTemplate: "res://{id}", name: text }] }) },
        { type: "custom_tool_call", call_id: `${id}_cell`, name: "exec", input: 'text(await tools.read_mcp_resource({server: "res", uri: "res://pg"}))' },
        { type: "custom_tool_call_output", call_id: `${id}_cell`, output: [{ type: "input_text", text: "Script completed\nWall time 0.0 seconds\nOutput:\n" }, { type: "input_text", text: resource(text) }] },
        { type: "function_call", call_id: `${id}_own`, namespace: "mcp__res", name: "get", arguments: "{}" },
        { type: "function_call_output", call_id: `${id}_own`, output: [{ type: "input_text", text: "Wall time: 0.1 seconds\nOutput:" }, { type: "input_text", text: "res-own-row-6f0a" }] },
      ];
      const { request } = await rewriteResponses({ model: "m", input } as unknown as ResponsesRequest, { arbiter: adapter, sessionKey: session, skipPromptInjection: true });
      return (k: string) => JSON.stringify((request.input as Array<Record<string, unknown>>).find((i) => String(i["type"]).endsWith("_output") && i["call_id"] === `${id}_${k}`)!["output"]);
    };
    // before any raw read: the resource tools have no mapping, so they are
    // masked whole all the same (plan 10 §11.18, 2026-10-07); the cell that
    // calls one is asked about it as the direct call is (§11.18, a cell's
    // resource tools, 2026-10-11), so it is masked whole too, for that tool
    const early = await turn("res-before-any-read-2c3d", "e");
    for (const k of ["read", "list", "tpl"]) assert.ok(!early(k).includes("res-before-any-read-2c3d"), `${k}: §11.18 masked whole in a session that read nothing`);
    // the cell carries the same resource text, which the masked reads above
    // registered as a value (the §11.18 cost), so the note is what shows the
    // cell's own ask answered
    assert.match(early("cell"), /this cell calls read_mcp_resource.*no mapping for the tool read_mcp_resource/, "cell: masked for the resource tool it calls");

    await guard.recordExecRoot({ procKey: "r-psql", parentKey: "r-agent", argv: ["psql"], session });
    await guard.taintProcessSecret({ procKey: "r-psql", path: join(home, ".pgpass"), level: "no-model", app: "psql", session });

    const out = await turn(pgpass, "t");
    const leaks = ["read", "list", "tpl", "cell"].filter((k) => out(k).includes(pgpass) || out(k).includes("a8d4e2b7"));
    assert.deepEqual(leaks, [], "CONFIDENTIALITY VIOLATION: a secret read raw reached the model as an MCP resource");
    assert.match(out("read"), /no mapping for the tool read_mcp_resource.*mapped_tools/);
    assert.ok(out("own").includes("res-own-row-6f0a"), "the mapped clean server's own tool is raw, as before");
  } finally {
    guard.close(); realHuman.close(); realO.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
