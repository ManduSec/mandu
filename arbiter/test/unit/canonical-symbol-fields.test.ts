import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  MDU_SYM_FORMAT, CANONICAL_FIELD_PREFIX, canonicalSymbolField,
  allocateSymbol, allocateDerivedSymbol, resolveSymbol, resolveAllSymbolsDeep,
  loadSymbolMap, saveSymbolMap, findReusableSymbol, type SymbolMap,
} from '../../symbol-table/index.js';

const unusual = ['bin/report.mjs', 'src/config.mjs', 'a-b', 'a b', 'a/b', 'a_b',
  '문서/설정.json', '123', '', '__mdu_field_002f', '/', '\\', '\ud800', '\ud801', '\ufffd', 'a\nb', 'trailing\n', 'trailing\r\n', '.hidden'];
function assertScannedWhole(symbol: string): void {
  assert.deepEqual(`before ${symbol} after`.match(MDU_SYM_FORMAT.pattern), [symbol]);
}

test('ordinary fields preserve names; missing and empty fields remain distinct', () => {
  for (const field of ['result', 'notes.md', 'body.__mdu_split[0]', 'a[0].b']) {
    assert.equal(canonicalSymbolField(field), field);
    assert.equal(MDU_SYM_FORMAT.generate({ tool: 'Read', hash: 'a1b2', field }), `$MDU:Read[a1b2].${field}`);
  }
  assert.equal(MDU_SYM_FORMAT.generate({ tool: 'Read', hash: 'a1b2' }), '$MDU:Read[a1b2]');
  assert.equal(canonicalSymbolField(''), CANONICAL_FIELD_PREFIX);
  assert.equal(canonicalSymbolField('/'), `${CANONICAL_FIELD_PREFIX}002f`);
});

test('reserved UTF-16 encoding is injective and every new field is scanned and resolved whole', () => {
  const map: SymbolMap = { symbols: new Map() };
  const names = unusual.map((field, i) => {
    const name = allocateSymbol(map, { tool: 'Read', hash: 'a1b2', field, value: `source ${i}` });
    assertScannedWhole(name);
    assert.equal(resolveSymbol(map, name), `source ${i}`);
    assert.equal(resolveAllSymbolsDeep(`value: ${name}`, map), `value: source ${i}`);
    assert.equal(map.symbols.get(name)!.field, field);
    assert.equal(MDU_SYM_FORMAT.extractFieldPath(name), canonicalSymbolField(field));
    return name;
  });
  assert.equal(new Set(names).size, unusual.length, 'same tool/hash must not merge distinct fields');
  assert.equal(canonicalSymbolField('\ud800'), `${CANONICAL_FIELD_PREFIX}d800`);
  assert.notEqual(canonicalSymbolField('/'), canonicalSymbolField('__mdu_field_002f'));
  const fields = Array.from({ length: 65536 }, (_, unit) => String.fromCharCode(unit));
  assert.equal(new Set(fields.map(canonicalSymbolField)).size, fields.length);
});

test('allocation and splitting preserve source metadata and labels through SQLite reload', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mdu-canonical-fields-'));
  try {
    const db = join(dir, 'symbols.db');
    const map: SymbolMap = { symbols: new Map() };
    const parent = allocateSymbol(map, {
      tool: 'Read', field: 'src/config-data.mjs', value: 'first\nsecond\n',
      origin: 'file:///workspace/src/config-data.mjs', sessionKey: 'session', callId: 'read-1',
      confidentiality: 'any-model', bindings: ['owner.example'], integrity: 'untrusted',
    }, db);
    const child = allocateDerivedSymbol(map, { parentSymName: parent, value: 'second\n', lineStart: 1, lineEnd: 2, splitIndex: 1 }, db);
    const p = map.symbols.get(parent)!;
    const c = map.symbols.get(child)!;
    assertScannedWhole(parent);
    assertScannedWhole(child);
    assert.equal(c.field, 'src/config-data.mjs.__mdu_split[1]');
    assert.equal(c.derived_from, parent);
    assert.equal(c.line_range, '1:2');
    for (const key of ['tool', 'origin', 'session_key', 'call_id', 'confidentiality', 'bindings', 'integrity'] as const) assert.deepEqual(c[key], p[key], key);
    const loaded = loadSymbolMap(db);
    assert.deepEqual(loaded.symbols.get(parent), p);
    assert.deepEqual(loaded.symbols.get(child), c);
    assert.equal(resolveAllSymbolsDeep(child, loaded), 'second\n');
    assert.equal(resolveAllSymbolsDeep(parent, loaded, 8, entry => entry.confidentiality !== 'public'), parent);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('legacy identifiers are never renamed or decoded, including literal reserved-prefix fields', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mdu-legacy-fields-'));
  try {
    const db = join(dir, 'symbols.db');
    const map: SymbolMap = { symbols: new Map() };
    const opts = { tool: 'Read', field: 'bin/report.mjs', value: 'legacy source', origin: 'file:///bin/report.mjs' };
    const fresh = allocateSymbol(map, opts);
    const row = map.symbols.get(fresh)!;
    map.symbols.delete(fresh);
    const legacy = '$MDU:Read[beef].bin/report.mjs';
    const literal = '$MDU:Read[abcd].__mdu_field_002f';
    map.symbols.set(legacy, row);
    map.symbols.set(literal, { ...row, field: '__mdu_field_002f', value: 'literal source' });
    saveSymbolMap(map, db);
    const loaded = loadSymbolMap(db);
    assert.deepEqual([...loaded.symbols.keys()].sort(), [legacy, literal].sort());
    assert.equal(resolveSymbol(loaded, legacy), 'legacy source');
    assert.equal(resolveAllSymbolsDeep(legacy, loaded), legacy, 'legacy scanner limitation remains explicit');
    assert.equal(resolveAllSymbolsDeep(literal, loaded), 'literal source');
    assert.equal(MDU_SYM_FORMAT.extractFieldPath(literal), '__mdu_field_002f');
    assert.equal(findReusableSymbol(loaded, opts), null);
    const allocated = allocateSymbol(loaded, opts, db);
    assertScannedWhole(allocated);
    assert.equal(findReusableSymbol(loaded, opts), allocated);
    assert.equal(findReusableSymbol(loaded, { ...opts, field: '__mdu_field_002f', value: 'literal source' }), literal);
    assert.equal(loaded.symbols.get(legacy)!.field, opts.field);
    assert.equal(resolveAllSymbolsDeep(allocated, loaded), opts.value);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
