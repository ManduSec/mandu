import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ArbiterServer } from '../../ipc/server.js';
import { ArbiterClient } from '../../ipc/client.js';
import { MDU_SYM_FORMAT, loadSymbolMap, allocateSymbol, saveSymbolMap, type SymbolMap } from '../../symbol-table/index.js';
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

// `human` is the human-plane client (arbiter-human-plane.md): desymbolize and
// SHALLOW resolve return originals and are refused on the data socket.
async function rig(run: (client: ArbiterClient, db: string, human: ArbiterClient) => Promise<void>, seed?: (db: string) => void, confidentiality = true): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), 'mdu-field-ipc-'));
  const db = join(dir, 'symbols.db');
  seed?.(db);
  const server = new ArbiterServer({ socketPath: join(dir, 'arbiter.sock'), humanSocketPath: join(dir, 'human', 'h.sock'), dbPath: db, eventDir: join(dir, 'events'), confidentiality, log: () => {} });
  const client = new ArbiterClient(join(dir, 'arbiter.sock'));
  const human = new ArbiterClient(join(dir, 'human', 'h.sock'));
  await server.listen();
  try { await run(client, db, human); }
  finally { client.close(); human.close(); await server.close(); rmSync(dir, { recursive: true, force: true }); }
}

test('real IPC preserves original fields and nested source delivery while AgentView stays opaque', async () => {
  await rig(async (client, _db, human) => {
    // The model proxy records a call on the human socket, where it is
    // believed (arbiter-human-plane.md §10.2: from the data socket a claim,
    // which symbolProvenance does not answer).
    await human.recordToolCall({ toolUseId: 'canonical-read', name: 'Read', input: { file_path: '/workspace/bin/report.mjs' } });
    for (const field of ['bin/report.mjs', 'a-b.md', 'two words.md', '문서/기록.md', '123.json', '__mdu_field_002f', '', 'notes.md']) {
      const raw = `Harmless source record for ${field}: 37 items.`;
      const inner = await client.symbolize({ tool: 'Read', field, value: raw, origin: `file:///workspace/${field}`, callId: 'canonical-read' });
      assert.deepEqual(inner.match(MDU_SYM_FORMAT.pattern), [inner]);
      const provenance = await client.symbolProvenance(inner);
      assert.equal(provenance.field, field);
      assert.equal(provenance.callId, 'canonical-read');
      assert.equal(provenance.toolName, 'Read');
      const outer = await client.symbolize({ tool: 'Read', value: `1\t${inner}\n` });
      const modelText = `Read result: ${outer}`;
      assert.ok(!modelText.includes(raw));
      assert.deepEqual(modelText.match(MDU_SYM_FORMAT.pattern), [outer]);
      assert.equal(await client.resolve(outer, { deep: true }), `1\t${raw}\n`);
      assert.equal(await human.desymbolize(modelText), `Read result: 1\t${raw}\n`);
    }
    const noField = await client.symbolize({ tool: 'Read', value: 'no field source' });
    assert.equal((await client.symbolProvenance(noField)).field, null);
    assert.deepEqual(await client.symbolProvenance('$MDU:Read[ffff].unknown'), { tool: null, callId: null, toolName: null });
  });
});

test('encoded nested fields preserve derived labels, binding intersection, and strict exclusion over IPC', async () => {
  await rig(async (client, db) => {
    const sources: string[] = [];
    for (const [field, bindings] of [['src/a-b.mjs', ['one.example', 'shared.example']], ['문서/비공개.md', ['shared.example', 'two.example']]] as const) {
      sources.push(await client.symbolize({ tool: 'Read', field, value: `source ${field}`, confidentiality: 'any-model', bindings: [...bindings] }));
    }
    const outer = await client.symbolize({ tool: 'Read', value: sources.join('\n') });
    const resolved = await client.resolveFull(outer, { deep: true });
    assert.equal(resolved.value, 'source src/a-b.mjs\nsource 문서/비공개.md');
    // resolveFull reports the outer row; symbolizeDerived independently joins
    // every nested source, so this advisory public label cannot launder them.
    assert.equal(resolved.confidentiality, 'public');
    const derived = await client.symbolizeDerived({ tool: 'inspect_symbol', field: 'result/report.json', value: 'transformed record', sourceSymbols: [outer] });
    const entry = loadSymbolMap(db).symbols.get(derived)!;
    assert.equal(entry.field, 'result/report.json');
    assert.equal(entry.confidentiality, 'any-model');
    assert.deepEqual(entry.bindings, ['shared.example']);
    const gate = await client.desymbolizationDecision({ symbol: derived, boundary: 'network', destination: 'unbound.example' });
    assert.equal(gate.allow, false);
    const strict = await client.symbolize({ tool: 'Read', field: 'private/key-data', value: 'STRICT_ONLY_RECORD', confidentiality: 'no-model' });
    assert.equal(await client.resolve(strict, { deep: true }), null);
    const wrapper = await client.symbolize({ tool: 'Read', value: `wrapped ${strict}` });
    const expanded = await client.resolve(wrapper, { deep: true });
    assert.equal(expanded, `wrapped ${strict}`);
    assert.ok(!expanded!.includes('STRICT_ONLY_RECORD'));
    const strictDerived = await client.symbolizeDerived({ tool: 'inspect_symbol', field: 'result/strict', value: 'opaque transformation', sourceSymbols: [wrapper] });
    assert.equal(loadSymbolMap(db).symbols.get(strictDerived)!.confidentiality, 'no-model');
    assert.equal(await client.resolve(strictDerived, { deep: true }), null);
  });
});

test('persisted malformed reuse candidates get canonical rows without losing old labels or exact lookup', async () => {
  const cases = [
    { callId: 'old-public', level: 'public', bindings: [] },
    { callId: 'old-model', level: 'any-model', bindings: ['shared.example', 'first.example'] },
    { callId: 'old-strict', level: 'no-model', bindings: ['owner.example'] },
  ] as const;
  const oldNames = new Map<string, string>();
  const opts = (callId: string) => ({ tool: 'Read', field: 'bin/report.mjs', value: `record ${callId}`, origin: 'file:///workspace/bin/report.mjs', sessionKey: 'old-session', callId });
  let before: SymbolMap;
  await rig(async (client, db, human) => {
    for (const item of cases) {
      const old = oldNames.get(item.callId)!;
      const canonical = await client.symbolize({ ...opts(item.callId), confidentiality: 'public', integrity: 'trusted' });
      assert.notEqual(canonical, old);
      assert.deepEqual(canonical.match(MDU_SYM_FORMAT.pattern), [canonical]);
      assert.equal(await client.symbolize(opts(item.callId)), canonical, 'later requests reuse the canonical row');
      assert.equal(await human.resolve(old), opts(item.callId).value, 'legacy exact lookup remains available (human plane)');
      const map = loadSymbolMap(db);
      for (const [name, row] of before.symbols) assert.deepEqual(map.symbols.get(name), row, 'old rows remain unchanged');
      const replacement = map.symbols.get(canonical)!;
      assert.equal(replacement.confidentiality, item.level);
      assert.equal(replacement.integrity, 'untrusted');
      assert.equal(replacement.derived_from, '$MDU:Read[aaaa].parent');
      assert.equal(replacement.line_range, '0:1');
      assert.equal(replacement.field, opts(item.callId).field);
      assert.deepEqual(replacement.bindings, item.callId === 'old-model' ? ['shared.example'] : [...item.bindings]);
      assert.equal(await client.resolve(canonical, { deep: true }), item.level === 'no-model' ? null : opts(item.callId).value);
      if (item.level !== 'public') {
        const denied = await client.desymbolizationDecision({ symbol: canonical, boundary: 'network', destination: 'unbound.example' });
        assert.equal(denied.allow, false);
      }
    }
  }, db => {
    const map: SymbolMap = { symbols: new Map() };
    for (const [index, item] of cases.entries()) {
      const temporary = allocateSymbol(map, { ...opts(item.callId), confidentiality: item.level, bindings: [...item.bindings], integrity: 'untrusted', derivedFrom: '$MDU:Read[aaaa].parent', lineRange: '0:1' });
      const row = map.symbols.get(temporary)!;
      map.symbols.delete(temporary);
      const old = `$MDU:Read[abc${index}].bin/report.mjs`;
      map.symbols.set(old, row);
      oldNames.set(item.callId, old);
      if (item.callId === 'old-model') map.symbols.set('$MDU:Read[abcd].bin/report.mjs', { ...row, bindings: ['shared.example', 'second.example'] });
    }
    saveSymbolMap(map, db);
    before = loadSymbolMap(db);
  });
});

test('axis OFF retains persisted restrictions for both valid reuse and malformed replacement; deep resolve still refuses the no-model rows', async () => {
  const fields = ['notes.md', 'bin/report.mjs'];
  const originals = new Map<string, string>();
  const returned: string[] = [];
  const opts = (field: string) => ({ tool: 'Read', field, value: `stored record ${field}`, sessionKey: 'off-compat', callId: `read-${field}` });
  let before: SymbolMap;
  await rig(async (client, db) => {
    for (const field of fields) {
      const result = await client.symbolizeFull({ ...opts(field), confidentiality: 'public', bindings: ['other.example'] });
      assert.deepEqual(result, { symbol: result.symbol }, 'OFF adds no confidentiality response field');
      returned.push(result.symbol);
      assert.deepEqual(result.symbol.match(MDU_SYM_FORMAT.pattern), [result.symbol]);
      assert.match(result.symbol, /^\$MDU:nomodel_Read\[/, 'persisted strict marker remains');
      if (field === 'notes.md') assert.equal(result.symbol, originals.get(field));
      else assert.notEqual(result.symbol, originals.get(field));
      const row = loadSymbolMap(db).symbols.get(result.symbol)!;
      assert.equal(row.confidentiality, 'no-model');
      assert.deepEqual(row.bindings, ['owner.example']);
      // arbiter-human-plane.md §4: deep resolve is the data-plane U-LLM read,
      // and its level gate holds whatever the axis says — a persisted
      // no-model row is refused even with confidentiality OFF.
      assert.equal(await client.resolve(result.symbol, { deep: true }), null, 'OFF still refuses a stored no-model row on deep resolve');
      assert.equal((await client.desymbolizationDecision({ symbol: result.symbol, boundary: 'model_context' })).allow, true);
    }
    const fresh = await client.symbolizeFull({ tool: 'Read', field: 'fresh-path.mjs', value: 'new record', confidentiality: 'no-model', bindings: ['requested.example'] });
    assert.deepEqual(fresh, { symbol: fresh.symbol });
    assert.match(fresh.symbol, /^\$MDU:Read\[/, 'fresh OFF allocation has no secret marker');
    const map = loadSymbolMap(db);
    assert.equal(map.symbols.get(fresh.symbol)!.confidentiality, 'public');
    assert.equal(map.symbols.get(fresh.symbol)!.bindings, null);
    for (const [name, row] of before.symbols) assert.deepEqual(map.symbols.get(name), row);

    // The existing daemon keeps OFF semantics. A separate in-memory dispatcher
    // reloads the DB with the axis ON to verify persistence for the next start.
    const on = new ArbiterServer({ socketPath: join(db, '..', 'on.sock'), dbPath: db, eventDir: join(db, '..', 'on-events'), confidentiality: true, log: () => {} });
    try {
      for (const symbol of returned) {
        const result = on.dispatch({ id: 'reload', op: 'resolve', symbol, deep: true }) as { ok: boolean; result: { value: string | null } };
        assert.equal(result.ok, true);
        assert.equal(result.result.value, null, 'ON reload enforces retained strict labels');
      }
    } finally { await on.close(); }
  }, db => {
    const map: SymbolMap = { symbols: new Map() };
    for (const field of fields) {
      let name = allocateSymbol(map, { ...opts(field), confidentiality: 'no-model', bindings: ['owner.example'] });
      if (field.includes('/')) {
        const row = map.symbols.get(name)!;
        map.symbols.delete(name);
        name = '$MDU:nomodel_Read[abcd].bin/report.mjs';
        map.symbols.set(name, row);
      }
      originals.set(field, name);
    }
    saveSymbolMap(map, db);
    before = loadSymbolMap(db);
  }, false);
});
