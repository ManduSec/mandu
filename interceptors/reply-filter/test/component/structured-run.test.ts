/** Real arbiter + actual wrapper subprocess. The executable named claude is a
 * local benign stdout fixture, not a model/CLI invocation; no provider calls. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)
const PKG = join(dirname(fileURLToPath(import.meta.url)), "../..");
const REPO = join(PKG, "../..");
const RAW = 'Benign project notes: "quoted" \\ folder\nsecond line\ttab\r\n雪 😀';
interface Client {
  connect(): Promise<void>;
  close(): void;
  symbolize(args: { tool: string; value: string; field?: string; derivedFrom?: string }): Promise<string>;
  events(sessionId: string): Promise<Array<{ kind: string; input?: { symbolized: string }; output?: { symbolized: string; original: string } }>>;
}
interface Server { listen(): Promise<void>; close(): Promise<void> }
async function run(cmd: string[], env: Record<string, string | undefined>): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const child = spawn(join(PKG, 'node_modules/.bin/tsx'), [join(PKG, 'src/run.ts'), '--', ...cmd], {
    cwd: PKG,
    env: { ...process.env, MANDU_REPLY_FILTER_PTY: undefined, MANDU_REPLY_FILTER_FORCE: undefined, MANDU_ARBITER_CLIENT_MODULE: undefined, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const timer = setTimeout(() => child.kill('SIGKILL'), 15000);
  let stdout = ''; let stderr = '';
  child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data', (s: string) => { stdout += s; });
  child.stderr.on('data', (s: string) => { stderr += s; });
  try { const [code] = await once(child, 'close'); return { code, stdout, stderr }; }
  finally { clearTimeout(timer); }
}

test('real arbiter structured subprocess: nested originals, JSON framing, metadata, source evidence and events', async () => {
  // Runtime imports preserve this package's standalone narrow dependency types.
  const { ArbiterServer } = await import(join(REPO, 'arbiter/ipc/server.ts')) as { ArbiterServer: new (opts: { socketPath: string; humanSocketPath?: string; dbPath: string; eventDir: string }) => Server };
  const { ArbiterClient } = await import(join(REPO, 'arbiter/ipc/client.ts')) as { ArbiterClient: new (path: string) => Client };
  const dir = mkdtempSync(join(tmpdir(), 'mdu-structured-reply-'));
  const socket = join(dir, 'arbiter.sock');
  // The filter resolves over the HUMAN plane (arbiter-human-plane.md); the
  // test reads events back over it too (events carry originals).
  const humanSocket = join(dir, 'human', 'h.sock');
  const server = new ArbiterServer({ socketPath: socket, humanSocketPath: humanSocket, dbPath: join(dir, 'symbols.sqlite'), eventDir: join(dir, 'events') });
  const client = new ArbiterClient(humanSocket);
  try {
    await server.listen(); await client.connect();
    const inner = await client.symbolize({ tool: 'Read', field: 'result', value: RAW });
    const symbol = await client.symbolize({ tool: 'inspect', field: 'result', value: inner, derivedFrom: inner });
    const cli = join(dir, 'claude');
    writeFileSync(cli, '#!' + process.execPath + '\n' + `
const fs = require('node:fs');
const bytes = fs.readFileSync(process.env.FIXTURE_INPUT);
fs.writeFileSync(process.env.FIXTURE_BEFORE, bytes);
(async () => {
  for (let i = 0; i < bytes.length; i += 7) {
    if (!process.stdout.write(bytes.subarray(i, i + 7))) await new Promise(r => process.stdout.once('drain', r));
    await new Promise(r => setImmediate(r));
  }
  process.exitCode = 3;
})();
`, { mode: 0o700 });
    const metadata = `"uuid":"${symbol}","count":900719925474099312345,"ratio":1.00e+003`;
    const assistant = `{"type":"assistant",${metadata},"message":{"role":"assistant","id":"${symbol}","content":[{"type":"text","text":"${symbol}"},{"type":"tool_use","id":"${symbol}","input":{"text":"${symbol}"}}]}}`;
    const result = `{"type":"result",${metadata},"result":"${symbol}","result_symbol":"${symbol}","is_error":false}`;
    const delta = JSON.stringify({ type: 'stream_event', event: { delta: { type: 'text_delta', text: symbol } } });
    // A --verbose json array also holds the tool results as the agent
    // process got them: text the model only ever saw as a symbol.
    const TOOL_RAW = 'tool-output-the-model-never-saw-5d1e';
    const user = JSON.stringify({ type: 'user', message: { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: `${TOOL_RAW} ${symbol}` }] } });
    const malformed = '{"type":"result","result":"' + symbol + '"';
    for (const format of ['stream-json', 'json'] as const) {
      const source = format === 'stream-json' ? assistant + '\r\n' + delta + '\n' + malformed + '\n' + result + '\n' : '[\n' + assistant + ',\n' + result + ',\n' + user + '\n]\n';
      const expected = source.replace(`"text":"${symbol}"`, `"text":${JSON.stringify(RAW)}`).replace(`"result":"${symbol}","result_symbol"`, `"result":${JSON.stringify(RAW)},"result_symbol"`);
      const input = join(dir, format + '-input'); const before = join(dir, format + '-before');
      writeFileSync(input, source);
      const session = 'reply-json-' + format;
      const r = await run([cli, format === 'stream-json' ? '--resume' : '-r', '--output-format', format, '-p'], { MANDU_ARBITER_SOCK: socket, MANDU_ARBITER_HUMAN_SOCK: humanSocket, MANDU_SCOPE_ID: session, FIXTURE_INPUT: input, FIXTURE_BEFORE: before });
      assert.equal(r.code, 3, r.stderr);
      assert.equal(readFileSync(before, 'utf8'), source, 'native pre-filter bytes are untouched');
      assert.ok(!readFileSync(before, 'utf8').includes(RAW), 'agent-side fixture remains symbolic');
      assert.equal(r.stdout, expected, 'only allowlisted content string spans change');
      const records = format === 'json' ? JSON.parse(r.stdout) : [JSON.parse(r.stdout.split('\n')[0]!), JSON.parse(r.stdout.trim().split('\n').at(-1)!)];
      assert.equal(records[0].message.content[0].text, RAW);
      assert.equal(records[0].message.content[1].input.text, symbol);
      assert.equal(records[1].result, RAW);
      assert.equal(records[1].result_symbol, symbol);
      const events = (await client.events(session)).filter(e => e.kind === 'desymbolize');
      assert.equal(events.length, format === 'json' ? 1 : 2);
      for (const event of events) {
        // The AgentView form is the placeholder named, never the record
        // (the dashboard's signed-out projection keeps every `symbolized`,
        // dashboard.md §6); the record the human got is the original.
        assert.equal(event.input!.symbolized, symbol);
        assert.equal(event.output!.symbolized, symbol);
        assert.doesNotThrow(() => JSON.parse(event.output!.original));
      }
      if (format === 'json') assert.ok(events[0]!.output!.original.includes(TOOL_RAW), 'the json array went whole into the original');
      if (format === 'stream-json') assert.match(r.stderr, /malformed-record/);
    }
    const input = join(dir, 'failure-input'); const before = join(dir, 'failure-before');
    const source = result + '\n'; writeFileSync(input, source);
    const r = await run([cli, '--output-format=stream-json'], { MANDU_ARBITER_SOCK: socket, MANDU_ARBITER_HUMAN_SOCK: join(dir, 'absent.sock'), MANDU_SCOPE_ID: '', FIXTURE_INPUT: input, FIXTURE_BEFORE: before });
    assert.equal(r.stdout, source); assert.equal(r.code, 3);

    // A closed downstream consumer used to reject the queue and leave its
    // paused child alive. Keep this benign child alive through SIGTERM so the
    // bounded SIGKILL cleanup is exercised, without running candidate code.
    const pidPath = join(dir, 'writer.pid');
    writeFileSync(cli, '#!' + process.execPath + '\n' + `
const fs = require('node:fs');
fs.writeFileSync(process.env.FIXTURE_PID, String(process.pid));
process.on('SIGTERM', () => {});
process.stdout.on('error', () => {});
const record = fs.readFileSync(process.env.FIXTURE_INPUT);
setInterval(() => process.stdout.write(record), 10);
`, { mode: 0o700 });
    const wrapper = spawn(join(PKG, 'node_modules/.bin/tsx'), [join(PKG, 'src/run.ts'), '--', cli, '--resume', '--output-format', 'stream-json', '-p'], {
      cwd: PKG,
      env: { ...process.env, MANDU_ARBITER_SOCK: socket, MANDU_ARBITER_HUMAN_SOCK: humanSocket, MANDU_SCOPE_ID: '', MANDU_REPLY_FILTER_PTY: undefined, MANDU_REPLY_FILTER_FORCE: undefined, MANDU_ARBITER_CLIENT_MODULE: undefined, FIXTURE_INPUT: input, FIXTURE_PID: pidPath },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let writerPid: number | undefined;
    let failureStderr = '';
    wrapper.stderr.setEncoding('utf8');
    wrapper.stderr.on('data', (chunk: string) => { failureStderr += chunk; });
    const wrapperClosed = once(wrapper, 'close');
    const timeout = setTimeout(() => wrapper.kill('SIGKILL'), 10000);
    try {
      await once(wrapper.stdout, 'data');
      writerPid = Number(readFileSync(pidPath, 'utf8'));
      wrapper.stdout.destroy();
      const [code, signal] = await wrapperClosed;
      assert.equal(signal, null, failureStderr);
      assert.equal(code, 1, failureStderr);
      assert.match(failureStderr, /output delivery failed; stopping wrapped child/);
      assert.doesNotMatch(failureStderr, /Unhandled|ERR_UNHANDLED/);
      assert.throws(() => process.kill(writerPid!, 0), { code: 'ESRCH' }, 'the paused child was terminated and reaped');
    } finally {
      clearTimeout(timeout);
      wrapper.kill('SIGKILL');
      if (writerPid !== undefined) { try { process.kill(writerPid, 'SIGKILL'); } catch { /* already reaped */ } }
    }
  } finally { client.close(); await server.close(); rmSync(dir, { recursive: true, force: true }); }
});
