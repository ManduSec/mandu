import { test } from 'node:test';
import assert from 'node:assert/strict';
import { allocateSymbol, MAX_DEEP_RESOLVE_DEPTH, type SymbolMap } from '../../symbol-table/symbol-table.js';
import { sourceLabel } from '../../symbol-table/source-label.js';

test('derived labels join every parent and intersect confidential bindings independent of order', () => {
  const map: SymbolMap = { symbols: new Map() };
  const pub = allocateSymbol(map, { tool: 'Read', value: 'public' });
  const a = allocateSymbol(map, { tool: 'Read', value: 'secret-a', confidentiality: 'any-model', bindings: ['a.example', 'shared.example'] });
  const b = allocateSymbol(map, { tool: 'Read', value: 'secret-b', confidentiality: 'any-model', bindings: ['shared.example', 'b.example'] });
  for (const symbols of [[pub, a, b], [b, a, pub]]) assert.deepEqual(sourceLabel(map, symbols), { level: 'any-model', bindings: ['shared.example'] });
  const strict = allocateSymbol(map, { tool: 'Read', value: 'strict', confidentiality: 'no-model' });
  assert.deepEqual(sourceLabel(map, [pub, strict, a]), { level: 'no-model', bindings: [] });
  assert.deepEqual(sourceLabel(map, [pub]), { level: 'public' });
  for (const bad of [[], ['unknown'], [pub, 'unknown'], [3], Array(17).fill(pub), null]) assert.throws(() => sourceLabel(map, bad));
});

test('public wrappers inherit every expanded nested model-ok source and its destination restrictions', () => {
  const map: SymbolMap = { symbols: new Map() };
  const a = allocateSymbol(map, { tool: 'Read', value: 'nested record a', confidentiality: 'any-model', bindings: ['a.example', 'shared.example'] });
  const b = allocateSymbol(map, { tool: 'Read', value: 'nested record b', confidentiality: 'any-model', bindings: ['shared.example', 'b.example'] });
  const inner = allocateSymbol(map, { tool: 'Read', value: b });
  const wrapper = allocateSymbol(map, { tool: 'Read', value: `records: ${a}\n${inner}` });
  const publicSource = allocateSymbol(map, { tool: 'Read', value: 'public record' });
  for (const sources of [[wrapper, publicSource], [publicSource, wrapper]]) {
    assert.deepEqual(sourceLabel(map, sources), { level: 'any-model', bindings: ['shared.example'] });
  }
  // A model-ok wrapper's own standing release rule also constrains its children.
  const restricted = allocateSymbol(map, { tool: 'Read', value: wrapper, confidentiality: 'any-model', bindings: ['private.example'] });
  assert.deepEqual(sourceLabel(map, [restricted]), { level: 'any-model', bindings: [] });
});

test('nested field-tail tokens use the same resolution candidates and inherit unbound source restrictions', () => {
  const map: SymbolMap = { symbols: new Map() };
  const nested = allocateSymbol(map, { tool: 'Read', value: 'nested record', confidentiality: 'any-model' });
  const wrapper = allocateSymbol(map, { tool: 'Read', value: `${nested}.record.` });
  assert.deepEqual(sourceLabel(map, [wrapper]), { level: 'any-model', bindings: [] });
});

test('strict nested data remains unexpanded while its restriction is inherited conservatively', () => {
  const map: SymbolMap = { symbols: new Map() };
  const strict = allocateSymbol(map, { tool: 'Read', value: 'strict record', confidentiality: 'no-model', bindings: ['owner.example'] });
  Object.defineProperty(map.symbols.get(strict)!, 'value', {
    get() { throw new Error('strict value must never be read by label traversal'); },
  });
  const wrapper = allocateSymbol(map, { tool: 'Read', value: strict });
  assert.deepEqual(sourceLabel(map, [wrapper]), { level: 'no-model', bindings: ['owner.example'] });
  assert.deepEqual(sourceLabel(map, [strict]), { level: 'no-model', bindings: ['owner.example'] });
});

test('cyclic wrappers stop at the quarantine resolver depth bound', () => {
  const map: SymbolMap = { symbols: new Map() };
  const a = allocateSymbol(map, { tool: 'Read', value: '', confidentiality: 'any-model', bindings: ['a.example', 'shared.example'] });
  const b = allocateSymbol(map, { tool: 'Read', value: a, confidentiality: 'any-model', bindings: ['shared.example', 'b.example'] });
  let valueReads = 0;
  Object.defineProperty(map.symbols.get(a)!, 'value', { get() { valueReads++; return b; } });
  Object.defineProperty(map.symbols.get(b)!, 'value', { get() { valueReads++; return a; } });
  assert.deepEqual(sourceLabel(map, [a]), { level: 'any-model', bindings: ['shared.example'] });
  assert.equal(valueReads, MAX_DEEP_RESOLVE_DEPTH + 1, 'initial source read plus bounded nested expansions');
});
