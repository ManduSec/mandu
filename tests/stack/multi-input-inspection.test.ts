/** Multi-source quarantine -> arbiter label inheritance -> real model proxy.
 * Benign distinct markers exercise completeness and model-boundary re-entry.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { ArbiterServer } from '../../arbiter/ipc/server.js';
import { ArbiterClient } from '../../arbiter/ipc/client.js';
import { handleRpc } from '../../interceptors/inspect-mcp/src/mcp-server.js';
import { inspectSymbol, NEXT_STEP_BY_KIND } from '../../interceptors/inspect-mcp/src/inspect-symbol.js';
import { ArbiterClientAdapter as InspectAdapter } from '../../interceptors/inspect-mcp/src/arbiter-client.js';
import { AnthropicProxy } from '../../interceptors/anthropic-proxy/src/proxy.js';
import { ArbiterClientAdapter as ProxyAdapter } from '../../interceptors/anthropic-proxy/src/arbiter-client.js';
import { MockUpstream, buildToolUseSse } from '../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js';
import { INSPECT_NEXT_STEP_BY_KIND } from '../../arbiter/policy/claude-code-inbound.js';
import { createInspectSymbolPluginTool } from '../../interceptors/openclaw-inspect-plugin/src/inspect-tool.js';
import { ViewSync } from '../../fs-sync/src/view-sync.js';
import { extractSymbols } from '../../fs-sync/src/arbiter-client.js';
import { makeTempRepo, gitIn } from '../../fs-sync/test/helpers/temp-repo.js';
import { humanSockIn } from '../lib/human-plane.js';

async function rig() {
  const dir=mkdtempSync(join(tmpdir(),'mdu-multi-'));
  const server=new ArbiterServer({socketPath:join(dir,'a.sock'),humanSocketPath:humanSockIn(dir),dbPath:join(dir,'s.db'),eventDir:join(dir,'events'),confidentiality:true,integrity:true,log:()=>{}});
  await server.listen();const client=new ArbiterClient(join(dir,'a.sock'));await client.connect();
  // The human plane (arbiter-human-plane.md): fs-sync's ViewSync and the test's
  // reads of ORIGINALS (desymbolize, shallow resolve) ride the human socket.
  const human=new ArbiterClient(humanSockIn(dir));await human.connect();
  return {client,human,server,close:async()=>{client.close();human.close();await server.close();rmSync(dir,{recursive:true,force:true});}};
}

function createProxy(client: ArbiterClient) {
  const upstream = new MockUpstream({ sse: buildToolUseSse({ id: 'done', name: 'Read', input: { file_path: 'result.json' } }) });
  const proxy = new AnthropicProxy({ arbiter: new ProxyAdapter({
    connect: () => client.connect(), classify: (v) => client.classify(v as never) as never, symbolize: (v) => client.symbolize(v),
    handlingPrompt: (mode, caps) => client.handlingPrompt(mode as never, caps), recordToolCall: (v) => client.recordToolCall(v),
    fsPathDecision: (v) => client.fsPathDecision(v as never) as never, execGate: (v) => client.execGate(v as never) as never,
    emit: async (v) => ({ seq: await client.emit(v as never) }), close: () => {},
    filterPrompt: (v) => client.filterPrompt(v), // the prompt filter (confidentiality-plan-15 §3.2)
  }), upstream: upstream.fetcher, log: () => {} });
  return { proxy, upstream };
}

async function forwardResult(port: number, content: string, symbols: string[]) {
  const post = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({
      model: 'mock', stream: true, system: 'Native client prefix',
      tools: [{ name: 'mcp__mandu-inspect__inspect_symbol', input_schema: { type: 'object' } }], messages: [
        { role: 'user', content: 'Merge the files.' },
        { role: 'assistant', content: [{ type: 'tool_use', id: 'inspect', name: 'mcp__mandu-inspect__inspect_symbol', input: { symbols, instruction: 'merge', output_format: 'json' } }] },
        { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'inspect', content }] },
      ],
    }),
  });
  await post.text();
  assert.equal(post.status, 200);
}

function forwardedResult(bodyText: string): string {
  const messages = JSON.parse(bodyText).messages as { content: unknown }[];
  for (const message of messages) {
    if (!Array.isArray(message.content)) continue;
    for (const block of message.content) {
      if (block.type !== 'tool_result') continue;
      return typeof block.content === 'string' ? block.content : block.content.map((c: { text?: string }) => c.text ?? '').join('');
    }
  }
  assert.fail('no forwarded tool result');
}

test('all fixed inspection directives match the arbiter trusted metadata contract', () => {
  assert.deepEqual(Object.keys(NEXT_STEP_BY_KIND).sort(), ['as_requested', 'auth_wall', 'empty', 'error_or_refusal', 'substantive', 'unknown', 'wrong_content']);
  assert.deepEqual(NEXT_STEP_BY_KIND, INSPECT_NEXT_STEP_BY_KIND);
});

test('nested file inputs pass through real views and proxy into one complete quarantined transformation', async () => {
  const r = await rig();
  const repo = makeTempRepo();
  const { proxy, upstream } = createProxy(r.client);
  const sources = [
    { path: 'bin/north-inventory.json', value: '[{"sku":"NESTED_NORTH_481","quantity":4}]\n' },
    { path: 'src/남쪽 stock.json', value: '[{"sku":"NESTED_SOUTH_732","quantity":2}]\n' },
  ];
  const markerPattern = /NESTED_NORTH_481|NESTED_SOUTH_732/;
  try {
    for (const source of sources) {
      mkdirSync(dirname(join(repo.workspacePath, source.path)), { recursive: true });
      writeFileSync(join(repo.workspacePath, source.path), source.value);
    }
    gitIn(repo.workspacePath, ['add', '-A']);
    gitIn(repo.workspacePath, ['commit', '-q', '-m', 'seed nested inventories']);
    const views = new ViewSync({ workspacePath: repo.workspacePath, stateBase: repo.stateBase, arbiter: r.human });
    await views.initialize();
    const port = await proxy.listen(0);
    const readSymbols: string[] = [];
    for (const [index, source] of sources.entries()) {
      const symbolicFile = (await views.readForAgent(source.path)).toString('utf8');
      assert.doesNotMatch(symbolicFile, markerPattern);
      const fileSymbols = extractSymbols(symbolicFile);
      assert.equal(fileSymbols.length, 1);
      assert.equal(symbolicFile.trim(), fileSymbols[0], 'the whole allocated file token must be scannable');
      assert.equal(await r.human.resolve(fileSymbols[0]!), source.value);
      const id = `nested-read-${index}`;
      const response = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({
          model: 'mock', stream: true, system: 'Native client prefix',
          tools: [{ name: 'Read', input_schema: { type: 'object' } }],
          messages: [
            { role: 'user', content: 'Combine the inventories into result.json.' },
            { role: 'assistant', content: [{ type: 'tool_use', id, name: 'Read', input: { file_path: join(repo.workspacePath, source.path) } }] },
            { role: 'user', content: [{ type: 'tool_result', tool_use_id: id, content: `1\t${symbolicFile}` }] },
          ],
        }),
      });
      await response.text();
      assert.equal(response.status, 200);
      const wire = upstream.requests.at(-1)!.bodyText;
      assert.doesNotMatch(wire, markerPattern);
      // The Read of a whole-file twin is forwarded AS IS since 2026-09-21
      // (read-result-rendering.md §5): digits and an arbiter-minted name, no
      // wrapper symbol. The model therefore holds the twin's OWN token — what it
      // inspects, and the only old_string an Edit of that file can match.
      const outer = forwardedResult(wire);
      assert.equal(outer.trim(), `1\t${fileSymbols[0]}`);
      readSymbols.push(fileSymbols[0]!);
    }
    let transformations = 0;
    const result = await inspectSymbol({
      arbiter: new InspectAdapter(r.client), sessionId: 'nested-file-inspection',
      ullm: { async complete(call: { system: string; user: string }) {
        if (call.system.includes('quarantined content classifier')) return { text: 'substantive', model: 'mock' };
        transformations++;
        for (const source of sources) assert.ok(call.user.includes(source.value.trimEnd()), 'complete original must reach quarantine');
        assert.match(call.system, /completeness against every supplied original/);
        // Derive the result from the received data, so a missing source cannot
        // be hidden by a mock that always returns a preselected complete result.
        const arrays = [...call.user.matchAll(/\[\{"sku":"NESTED_[^\n]+?\}\]/g)].map(match => JSON.parse(match[0]) as unknown[]);
        assert.equal(arrays.length, 2);
        return { text: JSON.stringify(arrays.flat()), model: 'mock' };
      } },
    }, { symbols: readSymbols, instruction: 'Combine all records from both inventories into one JSON array.', output_format: 'json' });
    assert.equal(result.ok, true);
    assert.equal(transformations, 1);
    assert.doesNotMatch(JSON.stringify(result), markerPattern);
    await forwardResult(port, JSON.stringify({ result_symbol: result.resultSymbol, model: result.model, content_kind: result.contentKind }), readSymbols);
    assert.doesNotMatch(upstream.requests.at(-1)!.bodyText, markerPattern);
    views.captureAgentWrite('result.json', result.resultSymbol);
    assert.ok((await views.syncToHuman({ toolName: 'Write', callId: 'nested-result' })).includes('result.json'));
    assert.deepEqual(JSON.parse(readFileSync(join(repo.workspacePath, 'result.json'), 'utf8')), sources.flatMap(source => JSON.parse(source.value)));
    assert.doesNotMatch((await views.readForAgent('result.json')).toString('utf8'), markerPattern);
    for (const source of sources) assert.equal(readFileSync(join(repo.workspacePath, source.path), 'utf8'), source.value);
  } finally { await proxy.close(); await r.close(); repo.cleanup(); }
});

test('both originals and candidate reach quarantine; fenced JSON is normalized and only symbol plus fixed guidance reach model', async () => {
  const r = await rig();
  const { proxy, upstream } = createProxy(r.client);
  try {
    const a = await r.client.symbolize({ tool: 'Read', value: '[{"sku":"NORTH_MARKER","quantity":4}]' });
    const b = await r.client.symbolize({ tool: 'Read', value: '[{"sku":"SOUTH_MARKER","quantity":2}]' });
    const candidate = await r.client.symbolize({ tool: 'Read', value: '[{"sku":"NORTH_MARKER","quantity":4}]', origin: 'candidate.json' });
    const sources = [a, b, candidate];
    const expected = '[{"sku":"NORTH_MARKER","quantity":4},{"sku":"SOUTH_MARKER","quantity":2}]';
    let transformations = 0;
    const ullm = { async complete(call: { system: string; user: string }) {
      if (call.system.includes('quarantined content classifier')) return { text: 'substantive', model: 'mock' };
      transformations++;
      assert.match(call.user, /NORTH_MARKER/); assert.match(call.user, /SOUTH_MARKER/); assert.match(call.user, /Input 3/);
      assert.match(call.system, /completeness against every supplied original/);
      assert.match(call.system, /exactly one valid JSON value/);
      return { text: '```json\n' + expected + '\n```', model: 'mock' };
    } };
    const deps = { arbiter: new InspectAdapter(r.client), ullm, sessionId: 'multi-e2e' };
    const args = { symbols: sources, instruction: 'Merge first two original inventories; verify and correct the third candidate; return complete JSON.', output_format: 'json' };
    const response = await handleRpc({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'inspect_symbol', arguments: args } }, deps);
    const result = response!.result as any;
    assert.equal(result.isError, false);
    const envelope = result.structuredContent;
    assert.equal(await r.human.desymbolize(envelope.result_symbol), expected);
    assert.equal(envelope.next_step, NEXT_STEP_BY_KIND.substantive);
    assert.doesNotMatch(JSON.stringify(response), /NORTH_MARKER|SOUTH_MARKER/);
    // The plugin and MCP mounts enforce the same explicit output format.
    const plugin = await createInspectSymbolPluginTool(async () => deps).execute('plugin-call', args);
    const pluginEnvelope = plugin.details as typeof envelope;
    assert.equal(await r.human.desymbolize(pluginEnvelope.result_symbol), expected);
    assert.equal(pluginEnvelope.next_step, NEXT_STEP_BY_KIND.substantive);
    assert.doesNotMatch(JSON.stringify(plugin), /NORTH_MARKER|SOUTH_MARKER/);
    assert.equal(transformations, 2);
    const port = await proxy.listen(0);
    await forwardResult(port, JSON.stringify(envelope), sources);
    const forwarded = upstream.requests.at(-1)!;
    assert.doesNotMatch(forwarded.bodyText, /NORTH_MARKER|SOUTH_MARKER/);
    assert.equal(forwardedResult(forwarded.bodyText), JSON.stringify(envelope), 'valid fixed guidance must stay readable without double wrapping');
    assert.match(forwarded.bodyText, /provide ALL original symbols together/);
    // Result text outside the exact fixed literal takes the ordinary opaque
    // path, even under the real inspection tool name and a valid content kind.
    for (const next_step of [envelope.next_step + ' UNTRUSTED_NOTE', 'UNTRUSTED_NOTE']) {
      const forged = JSON.stringify({ ...envelope, next_step });
      await forwardResult(port, forged, sources);
      const wire = upstream.requests.at(-1)!.bodyText;
      assert.doesNotMatch(wire, /UNTRUSTED_NOTE|NORTH_MARKER|SOUTH_MARKER/);
      const opaque = forwardedResult(wire);
      assert.notEqual(opaque, forged);
      assert.match(opaque, /^\$MDU:/);
      assert.equal((await r.human.resolveFull(opaque, { deep: false })).value, forged);
    }
  } finally { await proxy.close(); await r.close(); }
});

test('invalid quarantined JSON returns a generic refusal and no artifact across MCP, plugin, and model proxy', async () => {
  const r = await rig();
  const { proxy, upstream } = createProxy(r.client);
  try {
    const a = await r.client.symbolize({ tool: 'Read', value: '{"sku":"NORTH_MARKER"}' });
    const b = await r.client.symbolize({ tool: 'Read', value: '{"sku":"SOUTH_MARKER"}' });
    const ullm = { async complete(call: { system: string; user: string }) {
      if (call.system.includes('quarantined content classifier')) return { text: 'substantive', model: 'mock' };
      return { text: '```json\n{"sku":"INVALID_OUTPUT_MARKER",}\n```', model: 'mock' };
    } };
    const deps = { arbiter: new InspectAdapter(r.client), ullm };
    const args = { symbols: [a, b], instruction: 'Produce the merged JSON artifact.', output_format: 'json' };
    const response = await handleRpc({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'inspect_symbol', arguments: args } }, deps);
    const result = response!.result as any;
    assert.equal(result.isError, true);
    assert.equal(result.structuredContent, undefined);
    assert.equal(result.content[0].text, 'inspect_symbol: output is not valid JSON; no artifact returned');
    assert.doesNotMatch(JSON.stringify(response), /INVALID_OUTPUT_MARKER|NORTH_MARKER|SOUTH_MARKER/);
    const plugin = await createInspectSymbolPluginTool(async () => deps).execute('invalid-call', args);
    assert.equal(plugin.details, undefined);
    assert.deepEqual(plugin.content, result.content);
    const port = await proxy.listen(0);
    await forwardResult(port, result.content[0].text, [a, b]);
    const wire = upstream.requests.at(-1)!.bodyText;
    assert.doesNotMatch(wire, /INVALID_OUTPUT_MARKER|NORTH_MARKER|SOUTH_MARKER/);
    const opaque = forwardedResult(wire);
    assert.match(opaque, /^\$MDU:/);
    assert.equal(await r.human.desymbolize(opaque), result.content[0].text);
  } finally { await proxy.close(); await r.close(); }
});

test('mixed labels cannot be downgraded; every confidential binding constrains the result in either order',async()=>{
  const r=await rig();try {
    const pub=await r.client.symbolize({tool:'Read',value:'public-source'});
    const a=await r.client.symbolize({tool:'Read',value:'MODEL_OK_A',confidentiality:'any-model',bindings:['a.example','shared.example']});
    const b=await r.client.symbolize({tool:'Read',value:'MODEL_OK_B',confidentiality:'any-model',bindings:['b.example','shared.example']});
    const strict=await r.client.symbolize({tool:'Read',value:'STRICT_SOURCE',confidentiality:'no-model'});
    for(const sources of [[pub,a,b],[b,a,pub]]) {
      const sym=await r.client.symbolizeDerived({tool:'inspect_symbol',value:'DERIVED',sourceSymbols:sources,confidentiality:'public',integrity:'trusted',origin:pub,bindings:['shared.example','outside.example']});
      const resolved=await r.client.resolveFull(sym,{deep:true});
      assert.equal(resolved.confidentiality,'any-model');assert.deepEqual(resolved.bindings,['shared.example']);
    }
    // Identical output/primary origin with DIFFERENT source restrictions may
    // not reuse a previously broader binding set.
    const first=await r.client.symbolizeDerived({tool:'inspect_symbol',value:'same-result',sourceSymbols:[pub,a],origin:pub});
    const second=await r.client.symbolizeDerived({tool:'inspect_symbol',value:'same-result',sourceSymbols:[pub,a,b],origin:pub});
    assert.notEqual(first,second);assert.deepEqual((await r.client.resolveFull(second,{deep:true})).bindings,['shared.example']);
    await assert.rejects(r.client.symbolizeDerived({tool:'inspect_symbol',value:'no',sourceSymbols:[pub,'$MDU:Read[0000]']}));
    let calls=0;const deps={arbiter:new InspectAdapter(r.client),ullm:{async complete(){calls++;return{text:'must not run',model:'mock'};}}};
    for(const sources of [[pub,strict],[strict,pub],[pub,'$MDU:Read[0000]']]) assert.equal((await inspectSymbol(deps,{symbols:sources,instruction:'merge'})).ok,false);
    assert.equal(calls,0);
  }finally{await r.close();}
});

test('deeply resolved model-ok inputs retain labels and bindings through a public wrapper, alone and in either multi-input order', async () => {
  const r = await rig();
  const { proxy, upstream } = createProxy(r.client);
  try {
    const nested = await r.client.symbolize({
      tool: 'Read', value: '{"sku":"NESTED_MODEL_OK_MARKER","quantity":4}',
      confidentiality: 'any-model', bindings: ['nested.example', 'shared.example'],
    });
    const wrapper = await r.client.symbolize({ tool: 'Read', value: `Nested inventory: ${nested}`, confidentiality: 'public' });
    const publicSecond = await r.client.symbolize({ tool: 'Read', value: '{"sku":"PUBLIC_SECOND_MARKER","quantity":2}' });
    const restrictedSecond = await r.client.symbolize({
      tool: 'Read', value: '{"sku":"RESTRICTED_SECOND_MARKER","quantity":2}',
      confidentiality: 'any-model', bindings: ['second.example', 'shared.example'],
    });
    assert.equal((await r.human.resolveFull(wrapper, { deep: false })).confidentiality ?? 'public', 'public');
    const port = await proxy.listen(0);
    const cases = [
      { sources: [wrapper], markers: ['NESTED_MODEL_OK_MARKER'], bindings: ['nested.example', 'shared.example'] },
      ...[publicSecond, restrictedSecond].flatMap(second => {
        const marker = second === publicSecond ? 'PUBLIC_SECOND_MARKER' : 'RESTRICTED_SECOND_MARKER';
        const bindings = second === publicSecond ? ['nested.example', 'shared.example'] : ['shared.example'];
        return [[wrapper, second], [second, wrapper]].map(sources => ({ sources, markers: ['NESTED_MODEL_OK_MARKER', marker], bindings }));
      }),
    ];
    for (const { sources, markers, bindings } of cases) {
      let transformations = 0;
      const expected = JSON.stringify({ combined: markers });
      const deps = {
        arbiter: new InspectAdapter(r.client),
        ullm: { async complete(call: { system: string; user: string }) {
          if (call.system.includes('quarantined content classifier')) return { text: 'substantive', model: 'mock' };
          transformations++;
          for (const marker of markers) assert.ok(call.user.includes(marker));
          // The public wrapper is deeply resolved before quarantine: the
          // nested row's restrictions must follow the data actually read.
          assert.ok(!call.user.includes(nested));
          return { text: expected, model: 'mock' };
        } },
      };
      const response = await handleRpc({
        jsonrpc: '2.0', id: 1, method: 'tools/call', params: {
          name: 'inspect_symbol', arguments: {
            ...(sources.length === 1 ? { symbol: sources[0] } : { symbols: sources }),
            instruction: 'Combine the supplied inventory records into JSON.', output_format: 'json',
          },
        },
      }, deps);
      const result = response!.result as any;
      assert.equal(result.isError, false);
      assert.equal(transformations, 1);
      assert.doesNotMatch(JSON.stringify(result), /NESTED_MODEL_OK_MARKER|PUBLIC_SECOND_MARKER|RESTRICTED_SECOND_MARKER/);
      const derived = await r.client.resolveFull(result.structuredContent.result_symbol, { deep: true });
      assert.equal(derived.value, expected);
      assert.equal(derived.confidentiality, 'any-model');
      assert.deepEqual(derived.bindings, bindings);
      await forwardResult(port, JSON.stringify(result.structuredContent), sources);
      const wire = upstream.requests.at(-1)!.bodyText;
      assert.doesNotMatch(wire, /NESTED_MODEL_OK_MARKER|PUBLIC_SECOND_MARKER|RESTRICTED_SECOND_MARKER/);
      assert.equal(forwardedResult(wire), JSON.stringify(result.structuredContent));
    }
  } finally { await proxy.close(); await r.close(); }
});
