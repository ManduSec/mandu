/** Launcher prefix composition through real processes. Supervisor fixtures only
 * verify argv preservation; native kernel-stack coverage lives in eval e2e. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { applyReplyFilter } from '../../src/reply-filter.js';
import { emptyMutation } from '../../src/backend/types.js';
import { Layout } from '../../src/services/layout.js';
import { buildFinalArgv } from '../../src/spawn.js';
import type { LaunchPlan } from '../../src/types.js';
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const SYMBOL = '$MDU:Read[ab12].result';
const ORIGINAL = 'Benign "quoted" text\nsecond \\ line\ttab';

test('original Claude format reaches reply-filter through intact nested supervisor prefixes', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mdu-reply-composition-'));
  const socket = join(dir, 'arbiter.sock');
  const trace = join(dir, 'prefix-trace');
  const argvEvidence = join(dir, 'child-argv.json');
  const calls: string[] = [];
  const server = createServer(connection => {
    let tail = '';
    connection.setEncoding('utf8');
    connection.on('data', (chunk: string) => {
      tail += chunk;
      let nl: number;
      while ((nl = tail.indexOf('\n')) >= 0) {
        const req = JSON.parse(tail.slice(0, nl)); tail = tail.slice(nl + 1);
        if (req.op === 'desymbolize') calls.push(req.text);
        const result = req.op === 'desymbolize' ? { text: req.text.replaceAll(SYMBOL, ORIGINAL) } : { seq: 1 };
        connection.write(JSON.stringify({ id: req.id, ok: true, result }) + '\n');
      }
    });
  });
  server.listen(socket); await once(server, 'listening');
  try {
    const cli = join(dir, 'claude');
    writeFileSync(cli, '#!' + process.execPath + '\n' + `
const fs = require('node:fs');
fs.writeFileSync(process.env.ARGV_EVIDENCE, JSON.stringify(process.argv.slice(2)));
fs.writeFileSync(process.env.ARGV_EVIDENCE + '.human', process.env.MANDU_ARBITER_HUMAN_SOCK === undefined ? 'unset' : 'SET');
process.stdout.write(JSON.stringify({type:'result', result:process.env.SYMBOL, result_symbol:process.env.SYMBOL}) + '\\n');
`, { mode: 0o700 });
    const prefix: string[] = [];
    for (const name of ['secret-twins', 'net-guard', 'landlock-net']) {
      const supervisor = join(dir, name);
      writeFileSync(supervisor, '#!' + process.execPath + '\n' + `
const fs = require('node:fs');
if (process.argv[2] !== '--fixture-guard' || process.argv[3] !== '--') process.exit(20);
fs.appendFileSync(process.env.PREFIX_TRACE, ${JSON.stringify(name + '\n')});
const [command, ...args] = process.argv.slice(4);
const child = require('node:child_process').spawnSync(command, args, {stdio:'inherit'});
process.exit(child.status ?? 21);
`, { mode: 0o700 });
      prefix.push(supervisor, '--fixture-guard', '--');
    }
    for (const format of ['json', 'stream-json']) {
      writeFileSync(trace, '');
      const argv = [cli, '--resume', '--output-format', format, '-p', 'benign prompt'];
      // The filter resolves over the arbiter's HUMAN plane (arbiter-human-plane.md):
      // the fixture arbiter answers there; the launch hands the path to the
      // filter only.
      const plan = { argv, replyFilter: true, arbiterHumanSock: socket } as LaunchPlan;
      const mut = emptyMutation(); mut.launchPrefix = [...prefix]; mut.argvPrefix = ['--settings', '{}'];
      applyReplyFilter(plan, Layout.dev(ROOT), mut, undefined, () => {});
      const final = buildFinalArgv(argv, mut.argvPrefix, { prefix: [], detached: false }, mut.launchPrefix);
      // Locate the supervisor chain instead of assuming its offset: the reply
      // filter's own head (runtime, script, --mandu-output-format=…, --)
      // has grown before, and a fixed index then compared the wrong window.
      const at = final.indexOf(prefix[0]!);
      assert.ok(at > 0, `supervisor chain missing from final argv: ${JSON.stringify(final)}`);
      assert.equal(final[at - 1], '--', 'the supervisor chain starts right after the reply filter\'s --');
      assert.equal(final[at - 2], `--mandu-output-format=${format}`, 'reply filter is told the output format');
      assert.deepEqual(final.slice(at, at + prefix.length), prefix, 'security wrapper arguments stay intact');
      const child = spawn(final[0]!, final.slice(1), {
        cwd: dir,
        env: { ...process.env, ...mut.env, MANDU_ARBITER_SOCK: join(dir, 'no-data-socket.sock'), MANDU_SCOPE_ID: '', MANDU_REPLY_FILTER_PTY: undefined, MANDU_REPLY_FILTER_FORCE: undefined, MANDU_ARBITER_CLIENT_MODULE: undefined, PREFIX_TRACE: trace, ARGV_EVIDENCE: argvEvidence, SYMBOL },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      const timeout = setTimeout(() => child.kill('SIGKILL'), 15000);
      let stdout = ''; let stderr = '';
      child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
      child.stdout.on('data', (s: string) => { stdout += s; }); child.stderr.on('data', (s: string) => { stderr += s; });
      try {
        const [code] = await once(child, 'close'); assert.equal(code, 0, stderr);
        assert.equal(stdout.trim().split('\n').length, 1, 'resolved newline remains escaped within one JSON record');
        assert.deepEqual(JSON.parse(stdout), { type: 'result', result: ORIGINAL, result_symbol: SYMBOL });
        assert.deepEqual(JSON.parse(readFileSync(argvEvidence, 'utf8')), ['--settings', '{}', ...argv.slice(1)], 'internal format option is absent from agent argv');
        assert.equal(readFileSync(trace, 'utf8'), 'secret-twins\nnet-guard\nlandlock-net\n');
        assert.equal(readFileSync(argvEvidence + '.human', 'utf8'), 'unset', 'the agent under the filter never inherits the human socket');
      } finally { clearTimeout(timeout); }
    }
    assert.deepEqual(calls, [SYMBOL, SYMBOL], 'only decoded human content reaches desymbolization');
  } finally { server.close(); rmSync(dir, { recursive: true, force: true }); }
});
