import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inspectSymbol, type InspectSymbolParams } from '../../src/inspect-symbol.js';
import { handleRpc } from '../../src/mcp-server.js';
import { MockArbiter } from '../helpers/mock-arbiter.js';
import { MockUllm } from '../helpers/mock-ullm.js';
import type { SymbolizeArgs } from '../../src/arbiter-client.js';

const first = '$MDU:Read[aaa1]', second = '$MDU:Read[bbb2]';
class MultiArbiter extends MockArbiter {
  derived: (SymbolizeArgs & { sourceSymbols: string[] })[] = [];
  async symbolizeDerived(args: SymbolizeArgs & { sourceSymbols: string[] }): Promise<string> {
    this.derived.push(args); return this.symbolize(args);
  }
}
function rig() {return new MultiArbiter().seed(first, 'NORTH_ORIGINAL').seed(second, 'SOUTH_ORIGINAL');}

test('multi-input MCP passes both original values to one transformation and returns only its symbol', async () => {
  const arbiter = rig(), ullm = new MockUllm({ reply: 'MERGED_ORIGINAL' });
  const response = await handleRpc({jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'inspect_symbol',arguments:{symbols:[first,second],instruction:'Combine both inputs and return the complete artifact.'}}}, {arbiter,ullm});
  assert.ok(response);
  assert.equal(ullm.mainCalls.length, 1);
  assert.match(ullm.mainCalls[0].user, /NORTH_ORIGINAL/);
  assert.match(ullm.mainCalls[0].user, /SOUTH_ORIGINAL/);
  assert.match(ullm.mainCalls[0].system, /completeness against every supplied original/);
  assert.deepEqual(arbiter.derived[0].sourceSymbols,[first,second]);
  assert.equal(arbiter.emitted[0].input!.symbols.length,2);
  assert.doesNotMatch(JSON.stringify(response), /NORTH_ORIGINAL|SOUTH_ORIGINAL|MERGED_ORIGINAL/);
});

test('multi-input frames are numbered only — no symbol handle (its hash) reaches the quarantined model', async () => {
  // watch-20260918T194546 U6: `## Input 3 ($MDU:Read[0657])` labels were the
  // only digits in an otherwise empty input set, and the U-LLM answered
  // `RC-0657-2168` — two label hashes. Numbers carry the framing; the handle
  // added nothing the instruction uses.
  const arbiter = rig(), ullm = new MockUllm({ reply: 'MERGED_ORIGINAL' });
  await inspectSymbol({ arbiter, ullm }, { symbols: [first, second], instruction: 'merge' });
  const user = ullm.mainCalls[0].user;
  assert.match(user, /## Input 1\nNORTH_ORIGINAL/);
  assert.match(user, /## Input 2\nSOUTH_ORIGINAL/);
  assert.doesNotMatch(user, /\$MDU:/, 'no symbol name in the quarantined input');
  assert.doesNotMatch(user, /aaa1|bbb2/, 'no handle hash in the quarantined input');
});

test('unknown or refused second input prevents ALL quarantine calls and partial output', async () => {
  const arbiter=rig(), ullm=new MockUllm();
  const response=await inspectSymbol({arbiter,ullm},{symbols:[first,'$MDU:nomodel_Read[cccc]'],instruction:'merge'});
  assert.equal(response.ok,false);assert.equal(ullm.calls.length,0);assert.equal(arbiter.derived.length,0);
  assert.doesNotMatch(JSON.stringify(response),/NORTH_ORIGINAL/);
});

test('bad/ambiguous lists are refused before resolution; old arbiters have no fallback', async () => {
  for (const params of [{symbol:first,symbols:[second]}, {symbols:[]}, {symbols:[first,first]}, {symbols:[first,3]}, {symbols:Array(17).fill(first)}]) {
    const arbiter=rig(),ullm=new MockUllm();
    const r=await inspectSymbol({arbiter,ullm},{...params,instruction:'merge'} as InspectSymbolParams);
    assert.equal(r.ok,false);assert.equal(arbiter.resolveCalls.length,0);assert.equal(ullm.calls.length,0);
  }
  const old=new MockArbiter().seed(first,'NORTH_ORIGINAL').seed(second,'SOUTH_ORIGINAL'),ullm=new MockUllm();
  assert.equal((await inspectSymbol({arbiter:old,ullm},{symbols:[first,second],instruction:'merge'})).ok,false);
  assert.equal(ullm.calls.length,0);assert.equal(old.symbolizeCalls.length,0);
});

test('triage caches a complete input set, and multi-output failures stay symbolic', async () => {
  const arbiter=rig(), ullm=new MockUllm({reply:'DERIVED_DATA'}),triageCache=new Map();
  await inspectSymbol({arbiter,ullm,triageCache},{symbol:first,instruction:'extract'});
  await inspectSymbol({arbiter,ullm,triageCache},{symbols:[first,second],instruction:'merge'});
  assert.equal(ullm.triageCalls.length,2,'a first-file verdict cannot stand for the combined data');
  arbiter.symbolizeDerived=async()=>{throw new Error('unavailable');};
  const failed=await inspectSymbol({arbiter,ullm},{symbols:[first,second],instruction:'merge'});
  assert.equal(failed.ok,false);assert.doesNotMatch(JSON.stringify(failed),/DERIVED_DATA/);
});
