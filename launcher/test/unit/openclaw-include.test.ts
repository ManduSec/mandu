/**
 * openclaw-include.test — `$include` in the user's openclaw.json, resolved
 * the way OpenClaw resolves it (services/openclaw-include.ts; semantics read
 * from src/config/includes.ts in OpenClaw 2026.7.1 and 2026.9.6). Real files
 * in a temp dir: the path rules (relative to the including file, inside the
 * config directory, symlinks, hardlinks) are the point.
 *
 * The "OpenClaw's own answer" case is pinned to what `openclaw config get
 * agents --json` printed for the same files on OpenClaw 2026.9.6 and 2026.7.1
 * (2026-09-28); the refusal cases were checked with `openclaw config validate`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  IncludeError,
  MAX_INCLUDE_DEPTH,
  MAX_INCLUDE_FILE_BYTES,
  includeMerge,
  includeRoots,
  protoKeyPath,
  resolveOpenclawIncludes,
} from "../../src/services/openclaw-include.js";
import { parseJson5 } from "../../src/services/json5.js";

function withDir(fn: (dir: string, cfg: string) => void): void {
  const root = mkdtempSync(join(tmpdir(), "mandu-oc-include-"));
  const dir = join(root, "state");
  mkdirSync(dir);
  try { fn(dir, join(dir, "openclaw.json")); } finally { rmSync(root, { recursive: true, force: true }); }
}

const resolveText = (text: string, cfg: string, env: Record<string, string> = {}): unknown =>
  resolveOpenclawIncludes(parseJson5(text), cfg, { env, home: "/nonexistent-home" });

const refused = (fn: () => unknown, re: RegExp): void => {
  assert.throws(fn, (e: unknown) => e instanceof IncludeError && re.test(e.message), String(re));
};

test("openclaw-include: a doc with no $include comes back as it is", () => {
  const doc = { agents: { defaults: { model: "anthropic/x" } }, list: [1, 2] };
  assert.equal(resolveOpenclawIncludes(doc, "/nowhere/openclaw.json"), doc);
});

test("openclaw-include: OpenClaw's own answer for a split config (array merge, arrays concat, siblings last, nested relative)", () => {
  withDir((dir, cfg) => {
    mkdirSync(join(dir, "parts", "sub"), { recursive: true });
    writeFileSync(join(dir, "parts", "a.json5"),
      "{ defaults: { model: { primary: 'anthropic/claude-sonnet-4-6', fallbacks: ['anthropic/a1'] } }, list: [{ id: 'one', $include: './sub/one.json5' }] }");
    writeFileSync(join(dir, "parts", "b.json5"), "{ defaults: { model: { fallbacks: ['openai/gpt-5.5'] } } }");
    writeFileSync(join(dir, "parts", "sub", "one.json5"), "{ model: 'anthropic/claude-opus-4-8' }");
    const got = resolveText(`// main
{ agents: { $include: ['./parts/a.json5', './parts/b.json5'], defaults: { model: { fallbacks: ['anthropic/claude-haiku-4-5'] } } } }`, cfg);
    assert.deepEqual(got, { agents: {
      defaults: { model: { primary: "anthropic/claude-sonnet-4-6", fallbacks: ["anthropic/a1", "openai/gpt-5.5", "anthropic/claude-haiku-4-5"] } },
      list: [{ id: "one", model: "anthropic/claude-opus-4-8" }],
    } });
  });
});

test("openclaw-include: a single include replaces the object; siblings override its keys; a primitive include stands alone", () => {
  withDir((dir, cfg) => {
    writeFileSync(join(dir, "m.json5"), "{ primary: 'anthropic/a', x: { k: 1 } }");
    writeFileSync(join(dir, "s.json5"), "'anthropic/plain'");
    writeFileSync(join(dir, "arr.json5"), "['a', 'b']");
    assert.deepEqual(
      resolveText("{ m: { $include: './m.json5', primary: 'anthropic/b', x: { j: 2 } }, s: { $include: 's.json5' }, l: [{ $include: './arr.json5' }] }", cfg),
      { m: { primary: "anthropic/b", x: { k: 1, j: 2 } }, s: "anthropic/plain", l: [["a", "b"]] },
    );
    refused(() => resolveText("{ s: { $include: './s.json5', other: 1 } }", cfg), /need the included content to be an object/);
  });
});

test("openclaw-include: an absolute path inside the config directory is fine; outside it is refused", () => {
  withDir((dir, cfg) => {
    writeFileSync(join(dir, "in.json5"), "{ a: 1 }");
    writeFileSync(join(dir, "..", "out.json5"), "{ a: 2 }");
    assert.deepEqual(resolveText(`{ x: { $include: ${JSON.stringify(join(dir, "in.json5"))} } }`, cfg), { x: { a: 1 } });
    refused(() => resolveText("{ x: { $include: '../out.json5' } }", cfg), /outside the config directory/);
    refused(() => resolveText(`{ x: { $include: ${JSON.stringify(join(dir, "..", "out.json5"))} } }`, cfg), /outside the config directory/);
  });
});

test("openclaw-include: OPENCLAW_INCLUDE_ROOTS admits absolute and ~ roots; a relative entry admits nothing", () => {
  withDir((dir, cfg) => {
    const shared = join(dir, "..", "shared");
    mkdirSync(shared);
    writeFileSync(join(shared, "s.json5"), "{ a: 1 }");
    const text = "{ x: { $include: '../shared/s.json5' } }";
    assert.deepEqual(resolveText(text, cfg, { OPENCLAW_INCLUDE_ROOTS: `/elsewhere:${shared}` }), { x: { a: 1 } });
    refused(() => resolveText(text, cfg, { OPENCLAW_INCLUDE_ROOTS: "../shared" }), /outside the config directory/);
    assert.deepEqual(
      resolveOpenclawIncludes(parseJson5(text), cfg, { env: { OPENCLAW_INCLUDE_ROOTS: "~/shared" }, home: join(dir, "..") }),
      { x: { a: 1 } },
    );
  });
  assert.deepEqual(includeRoots({ OPENCLAW_INCLUDE_ROOTS: " /a : ~/b :rel: ~ :/a" }, "/h"), ["/a", "/h/b", "/h"]);
  assert.deepEqual(includeRoots({}, "/h"), []);
});

test("openclaw-include: a symlink is followed while its target stays inside; one pointing out is refused", () => {
  withDir((dir, cfg) => {
    writeFileSync(join(dir, "real.json5"), "{ a: 1 }");
    symlinkSync(join(dir, "real.json5"), join(dir, "link.json5"));
    writeFileSync(join(dir, "..", "secret.json5"), "{ a: 2 }");
    symlinkSync(join(dir, "..", "secret.json5"), join(dir, "escape.json5"));
    assert.deepEqual(resolveText("{ x: { $include: './link.json5' } }", cfg), { x: { a: 1 } });
    refused(() => resolveText("{ x: { $include: './escape.json5' } }", cfg), /resolves through a symlink/);
  });
});

test("openclaw-include: a hardlinked file, a directory, a file over 2 MiB, a missing file are refused", () => {
  withDir((dir, cfg) => {
    writeFileSync(join(dir, "h.json5"), "{ a: 1 }");
    linkSync(join(dir, "h.json5"), join(dir, "h2.json5"));
    mkdirSync(join(dir, "d"));
    writeFileSync(join(dir, "big.json5"), `{ a: "${"x".repeat(MAX_INCLUDE_FILE_BYTES)}" }`);
    refused(() => resolveText("{ x: { $include: './h.json5' } }", cfg), /hard link/);
    refused(() => resolveText("{ x: { $include: './d' } }", cfg), /not a regular file/);
    refused(() => resolveText("{ x: { $include: './big.json5' } }", cfg), /larger than/);
    refused(() => resolveText("{ x: { $include: './nope.json5' } }", cfg), /does not exist/);
  });
});

test("openclaw-include: a cycle, the config including itself, and more than 10 levels are refused; 10 levels are fine", () => {
  withDir((dir, cfg) => {
    writeFileSync(join(dir, "a.json5"), "{ $include: './b.json5' }");
    writeFileSync(join(dir, "b.json5"), "{ $include: './a.json5' }");
    refused(() => resolveText("{ x: { $include: './a.json5' } }", cfg), /circular include/);
    refused(() => resolveText("{ x: { $include: './openclaw.json' } }", cfg), /circular include/);
    for (let i = 1; i <= MAX_INCLUDE_DEPTH + 1; i++) {
      writeFileSync(join(dir, `l${i}.json5`), i === MAX_INCLUDE_DEPTH + 1 ? "{ end: true }" : `{ $include: './l${i + 1}.json5' }`);
    }
    // l1 .. l10 are 10 levels: l10 includes l11, the 11th.
    refused(() => resolveText("{ x: { $include: './l1.json5' } }", cfg), /more than 10 nested include levels/);
    writeFileSync(join(dir, `l${MAX_INCLUDE_DEPTH}.json5`), "{ end: true }");
    assert.deepEqual(resolveText("{ x: { $include: './l1.json5' } }", cfg), { x: { end: true } });
  });
});

test("openclaw-include: a malformed $include value or included file is refused", () => {
  withDir((dir, cfg) => {
    writeFileSync(join(dir, "bad.json5"), "{ a: ");
    refused(() => resolveText("{ x: { $include: 3 } }", cfg), /not a path or a list of paths/);
    refused(() => resolveText("{ x: { $include: null } }", cfg), /null, not a path/);
    refused(() => resolveText("{ x: { $include: ['./ok.json5', 4] } }", cfg), /does not exist|list item/);
    refused(() => resolveText("{ x: { $include: [4] } }", cfg), /list item is a number/);
    refused(() => resolveText("{ x: { $include: './bad.json5' } }", cfg), /not JSON5/);
    refused(() => resolveText(`{ x: { $include: ${JSON.stringify("a\u0000b")} } }`, cfg), /null byte/);
  });
});

test("openclaw-include: a __proto__ key in the config or an included file is refused", () => {
  withDir((dir, cfg) => {
    writeFileSync(join(dir, "p.json5"), '{ "__proto__": { model: "openai/gpt-5.5" } }');
    refused(() => resolveText('{ "__proto__": { agents: {} } }', cfg), /__proto__ key \(__proto__\)/);
    refused(() => resolveText("{ x: { $include: './p.json5' } }", cfg), /__proto__ key/);
  });
  assert.equal(protoKeyPath(parseJson5('{ a: [{ b: { "__proto__": 1 } }] }')), "a[0].b.__proto__");
  assert.equal(protoKeyPath({ a: { b: 1 } }), null);
});

test("openclaw-include: the merge (objects recurse, arrays concat, later wins, prototype keys skipped)", () => {
  assert.deepEqual(includeMerge({ a: [1], o: { x: 1, y: 1 }, p: 1 }, { a: [2], o: { y: 2 }, p: { q: 1 } }), { a: [1, 2], o: { x: 1, y: 2 }, p: { q: 1 } });
  assert.deepEqual(includeMerge({ a: 1 }, { constructor: { x: 1 }, prototype: 2, b: 2 }), { a: 1, b: 2 });
  assert.equal(includeMerge([1], { a: 1 }) instanceof Array, false);
});
