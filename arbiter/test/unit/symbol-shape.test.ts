/**
 * symbolShape op (reply-row-reservation.md §3.3) through `dispatch`, no
 * socket: the line count of ONE token's deep-resolved value, and nothing else.
 * Mandu-new, no reference origin. The socket path over the production client
 * is pinned in test/component/reply-row-reservation.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { parseShapeLayout, shapeLines, shapeRows, shapeRowsLast, SHAPE_MAX_WIDTH, SHAPE_MIN_WIDTH } from "../../ipc/reply-reservation.js";
import { layoutRows } from "../../ipc/reserve-layout.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

type Res = { ok: boolean; error?: string; result?: unknown };

function withServer(fn: (srv: ArbiterServer) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "mandu-symbolshape-"));
  const srv = new ArbiterServer({
    socketPath: join(dir, "a.sock"), dbPath: join(dir, "symbols.db"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyDocument: {}, policyPollMs: 0,
  });
  try { fn(srv); } finally { srv.close().catch(() => {}); rmSync(dir, { recursive: true, force: true }); }
}

function mint(srv: ArbiterServer, value: string, extra: Record<string, unknown> = {}): string {
  const r = srv.dispatch(
    { id: 1, op: "symbolize", tool: "Bash", value, ...extra } as never, { channel: "data" },
  ) as Res;
  assert.equal(r.ok, true, r.error);
  return (r.result as { symbol: string }).symbol;
}

function shape(srv: ArbiterServer, token: unknown, layout: Record<string, unknown> = {}): Res {
  return srv.dispatch({ id: 2, op: "symbolShape", token, ...layout } as never, { channel: "human" }) as Res;
}

test("shapeLines: drops exactly one trailing line break, then counts", () => {
  assert.equal(shapeLines(""), 1);
  assert.equal(shapeLines("a"), 1);
  assert.equal(shapeLines("a\n"), 1);
  assert.equal(shapeLines("a\nb"), 2);
  assert.equal(shapeLines("a\nb\n"), 2);
  assert.equal(shapeLines("a\nb\n\n"), 3, "only ONE trailing break is dropped");
  assert.equal(shapeLines("a\r\nb\r\n"), 2, "CRLF is one break");
  assert.equal(shapeLines("a\rb\r"), 2, "a bare CR is a break");
  assert.equal(shapeLines("\n"), 1);
  assert.equal(shapeLines("\n\n"), 2);
});

test("symbolShape: a multi-line value's line count", () => {
  withServer((srv) => {
    const t = mint(srv, "line one\nline two\nline three\n");
    assert.deepEqual(shape(srv, t), { id: 2, ok: true, result: { lines: 3 } });
  });
});

test("symbolShape: one trailing break only — 'a\\nb\\n\\n' is 3; CRLF counts once per line", () => {
  withServer((srv) => {
    assert.deepEqual(shape(srv, mint(srv, "a\nb\n\n")).result, { lines: 3 });
    assert.deepEqual(shape(srv, mint(srv, "k1=v1\r\nk2=v2\r\nk3=v3\r\n")).result, { lines: 3 });
    assert.deepEqual(shape(srv, mint(srv, "single")).result, { lines: 1 });
  });
});

test("symbolShape: resolves DEEPLY — a nested chain counts the fully expanded value", () => {
  withServer((srv) => {
    const inner = mint(srv, "i1\ni2\ni3\n");
    const middle = mint(srv, `m1\n${inner}`);
    const outer = mint(srv, `o1\n${middle}\no-last`);
    // o1 / m1 / i1 / i2 / i3 / "" (inner's own trailing break, mid-value) / o-last
    assert.deepEqual(shape(srv, outer).result, { lines: 7 });
    // The same count desymbolize's expansion yields.
    const text = (srv.dispatch({ id: 3, op: "desymbolize", text: outer }, { channel: "human" }) as Res)
      .result as { text: string };
    assert.equal(shapeLines(text.text), 7);
  });
});

test("symbolShape: a `.field` path token resolves to that field's value", () => {
  withServer((srv) => {
    const t = mint(srv, "f1\nf2\n", { field: "stdout" });
    assert.match(t, /\.stdout$/, "precondition: the name carries the field path");
    assert.deepEqual(shape(srv, t).result, { lines: 2 });
  });
});

test("symbolShape: a Markdown-escaped token is normalized first", () => {
  withServer((srv) => {
    const r = srv.dispatch(
      { id: 1, op: "symbolize", tool: "web_fetch", value: "w1\nw2\nw3\nw4", field: "most_mentioned" } as never,
      { channel: "data" },
    ) as Res;
    const t = (r.result as { symbol: string }).symbol;
    const escaped = "\\" + t.replace(/_/g, "\\_");
    assert.notEqual(escaped, t);
    assert.deepEqual(shape(srv, escaped).result, { lines: 4 });
  });
});

test("symbolShape: unknown tokens, non-tokens and text around a token → null", () => {
  withServer((srv) => {
    const t = mint(srv, "a\nb");
    for (const token of [
      "$MDU:Bash[deadbeef]",   // well-formed, never minted
      "not a symbol",
      "",
      `see ${t}`,               // a token inside text is not a token
      `${t} `,
    ]) {
      assert.deepEqual(shape(srv, token), { id: 2, ok: true, result: null }, JSON.stringify(token));
    }
  });
});

test("symbolShape: a non-string token is refused", () => {
  withServer((srv) => {
    for (const token of [undefined, 7, null, ["$MDU:Bash[abcd]"]]) {
      const r = shape(srv, token);
      assert.equal(r.ok, false);
      assert.match(r.error!, /token must be a string/);
    }
  });
});

test("symbolShape: the response carries the count only — no substring of the value", () => {
  withServer((srv) => {
    const secret = "AKIAQWERTYUIOPASDFGH\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nregion=ap-northeast-2\n";
    const t = mint(srv, secret, { confidentiality: "no-model" });
    const r = shape(srv, t);
    assert.deepEqual(r.result, { lines: 3 });
    assert.deepEqual(Object.keys(r.result as object), ["lines"], "no length, widths or label");
    const json = JSON.stringify(r);
    // Every substring of length ≥ 4 of every line (the count itself is 1 char,
    // so shorter windows would only match digits/JSON punctuation by chance).
    for (const line of secret.split("\n").filter(Boolean)) {
      for (let i = 0; i + 4 <= line.length; i++) {
        const piece = line.slice(i, i + 4);
        assert.ok(!json.includes(piece), `the response holds a piece of the value: ${piece}`);
      }
    }
    assert.ok(!json.includes("no-model") && !json.includes("nomodel"), "no label");
  });
});

test("symbolShape: follows desymbolize's exposure — refused on data, served on human and admin", () => {
  withServer((srv) => {
    const t = mint(srv, "x\ny");
    assert.equal(shape(srv, t).ok, true, "human channel");
    const data = srv.dispatch({ id: 2, op: "symbolShape", token: t } as never, { channel: "data" }) as Res;
    assert.equal(data.ok, false, "the data socket the agent's tools reach refuses it");
    assert.match(data.error ?? "", /human-plane/);
    const admin = srv.dispatch({ id: 2, op: "symbolShape", token: t }) as Res;
    assert.deepEqual(admin.result, { lines: 2 });
  });
});

// ── v2: rows at a width (reply-row-reservation.md §11.5) ────────────────────

test("parseShapeLayout: absent → null; width alone → first = width; the valid edges", () => {
  assert.equal(parseShapeLayout({}), null, "no width, no first: v1, a line count only");
  assert.deepEqual(parseShapeLayout({ width: 80 }), { width: 80, first: 80 });
  assert.deepEqual(parseShapeLayout({ width: SHAPE_MIN_WIDTH }), { width: 20, first: 20 });
  assert.deepEqual(parseShapeLayout({ width: SHAPE_MAX_WIDTH }), { width: 1000, first: 1000 });
  assert.deepEqual(parseShapeLayout({ width: 80, first: 0 }), { width: 80, first: 0 });
  assert.deepEqual(parseShapeLayout({ width: 80, first: 40 }), { width: 80, first: 40 }, "⌈80/2⌉ = 40");
  assert.deepEqual(parseShapeLayout({ width: 80, first: 80 }), { width: 80, first: 80 });
  assert.deepEqual(parseShapeLayout({ width: 79, first: 40 }), { width: 79, first: 40 }, "⌈79/2⌉ = 40");
});

test("parseShapeLayout: every out-of-range or malformed width/first is an error string", () => {
  const bad: Array<[Record<string, unknown>, RegExp]> = [
    [{ width: 19 }, /^symbolShape: width must be an integer from 20 to 1000$/],
    [{ width: 1001 }, /width must be an integer from 20 to 1000/],
    [{ width: 80.5 }, /width must be an integer/],
    [{ width: "80" }, /width must be an integer/],
    [{ width: null }, /width must be an integer/],
    [{ width: Number.NaN }, /width must be an integer/],
    [{ width: Number.POSITIVE_INFINITY }, /width must be an integer/],
    [{ width: 0 }, /width must be an integer/],
    [{ width: -80 }, /width must be an integer/],
    [{ first: 40 }, /^symbolShape: first requires width$/],
    [{ first: 0 }, /first requires width/],
    [{ width: 80, first: 1 }, /^symbolShape: first must be 0 or an integer from 40 to 80$/],
    [{ width: 80, first: 39 }, /first must be 0 or an integer from 40 to 80/],
    [{ width: 79, first: 39 }, /first must be 0 or an integer from 40 to 79/],
    [{ width: 80, first: 81 }, /first must be 0 or an integer from 40 to 80/],
    [{ width: 80, first: -1 }, /first must be 0 or an integer/],
    [{ width: 80, first: 60.5 }, /first must be 0 or an integer/],
    [{ width: 80, first: "60" }, /first must be 0 or an integer/],
    [{ width: 80, first: null }, /first must be 0 or an integer/],
  ];
  for (const [req, re] of bad) {
    const r = parseShapeLayout(req);
    assert.equal(typeof r, "string", JSON.stringify(req));
    assert.match(r as string, re, JSON.stringify(req));
  }
});

test("shapeRows: the length of layoutRows on the value, nothing else", () => {
  const z = "Z".repeat(120);
  assert.equal(shapeRows(z, { width: 78, first: 78 }), 2, "the probe's unbroken case: 78 + 42");
  assert.equal(shapeRows(z, { width: 78, first: 0 }), 3, "first 0 adds the empty head row");
  assert.equal(shapeRows("a\nb", { width: 20, first: 20 }), 2);
  assert.equal(shapeRows("a\nb", { width: 20, first: 0 }), 3);
  assert.equal(shapeRows("", { width: 20, first: 20 }), 1, "an empty value is one empty row");
  const v = "word ".repeat(30).trim();
  assert.equal(shapeRows(v, { width: 40, first: 20 }), layoutRows(v, 40, 20).length);
});

test("symbolShape with width: a wrapped one-line value → lines 1, rows ≥ 2", () => {
  withServer((srv) => {
    const t = mint(srv, "Z".repeat(120) + "\n");
    assert.deepEqual(shape(srv, t, { width: 78 }), { id: 2, ok: true, result: { lines: 1, rows: 2, last: 42 } });
    assert.deepEqual(shape(srv, t, { width: 78, first: 78 }).result, { lines: 1, rows: 2, last: 42 });
    assert.deepEqual(shape(srv, t, { width: 120 }).result, { lines: 1, rows: 1, last: 120 }, "fits: one row");
    assert.deepEqual(shape(srv, t, { width: 78, first: 0 }).result, { lines: 1, rows: 3, last: 42 }, "first 0: the empty head row");
  });
});

test("symbolShape with width: a multi-line value with one long line", () => {
  withServer((srv) => {
    const value = "short\n" + "a".repeat(50) + " " + "b".repeat(50) + "\nend\n";
    const t = mint(srv, value);
    // short / aaaa…(40) / aaaaaaaaaa bbbb…(40) / bbb…(21) / end
    assert.deepEqual(shape(srv, t, { width: 40 }).result, { lines: 3, rows: 5, last: 3 });
    assert.deepEqual(shape(srv, t, { width: 40, first: 0 }).result, { lines: 3, rows: 6, last: 3 });
    assert.deepEqual(shape(srv, t).result, { lines: 3 }, "without width: exactly v1's answer");
    assert.deepEqual(Object.keys(shape(srv, t).result as object), ["lines"], "no rows key without width");
  });
});

test("symbolShape with width: field paths and nested chains are resolved before the layout", () => {
  withServer((srv) => {
    const f = mint(srv, "f1\n" + "x".repeat(100) + "\n", { field: "stdout" });
    assert.match(f, /\.stdout$/);
    assert.deepEqual(shape(srv, f, { width: 40 }).result, { lines: 2, rows: 4, last: 20 }, "f1 / 40 / 40 / 20");

    const inner = mint(srv, "Q".repeat(90));
    const outer = mint(srv, `head\n${inner}`);
    // The token is far shorter than 40 columns; the resolved line is 90 wide.
    assert.deepEqual(shape(srv, outer, { width: 40 }).result, { lines: 2, rows: 4, last: 10 }, "head / 40 / 40 / 10");
  });
});

test("symbolShape: a bad width/first is refused (ok:false) — for known and unknown tokens alike", () => {
  withServer((srv) => {
    const t = mint(srv, "a\nb");
    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ width: 19 }, /width must be an integer from 20 to 1000/],
      [{ width: 1001 }, /width must be an integer from 20 to 1000/],
      [{ width: 80.5 }, /width must be an integer/],
      [{ width: 80, first: 1 }, /first must be 0 or an integer from 40 to 80/],
      [{ width: 80, first: 39 }, /first must be 0 or an integer from 40 to 80/],
      [{ width: 80, first: 81 }, /first must be 0 or an integer from 40 to 80/],
      [{ first: 40 }, /first requires width/],
    ];
    for (const token of [t, "$MDU:Bash[deadbeef]"]) {
      for (const [layout, re] of cases) {
        const r = shape(srv, token, layout);
        assert.equal(r.ok, false, `${token} ${JSON.stringify(layout)}`);
        assert.match(r.error ?? "", re);
        assert.equal(r.result, undefined, "a refusal carries no count");
      }
    }
    // The token check still comes first.
    assert.match(shape(srv, 7, { width: 19 }).error ?? "", /token must be a string/);
  });
});

test("symbolShape with width: an unknown token is still null", () => {
  withServer((srv) => {
    assert.deepEqual(shape(srv, "$MDU:Bash[deadbeef]", { width: 80 }), { id: 2, ok: true, result: null });
  });
});

test("symbolShape with width: counts only — no substring of the value, keys exactly lines/rows/last", () => {
  withServer((srv) => {
    const secret = "sk-ant-api03-" + "Kq7xY2mN9pL4vR8sT1wZ".repeat(6) + "\nregion=ap-northeast-2\n";
    const t = mint(srv, secret, { confidentiality: "no-model" });
    const r = shape(srv, t, { width: 40, first: 20 });
    assert.equal(r.ok, true, r.error);
    assert.deepEqual(Object.keys(r.result as object).sort(), ["last", "lines", "rows"]);
    const json = JSON.stringify(r);
    for (const line of secret.split("\n").filter(Boolean)) {
      for (let i = 0; i + 4 <= line.length; i++) {
        assert.ok(!json.includes(line.slice(i, i + 4)), `the response holds a piece of the value: ${line.slice(i, i + 4)}`);
      }
    }
  });
});

test("symbolShape with width: still refused on data, served on human and admin", () => {
  withServer((srv) => {
    const t = mint(srv, "Z".repeat(120));
    const data = srv.dispatch({ id: 2, op: "symbolShape", token: t, width: 78 } as never, { channel: "data" }) as Res;
    assert.equal(data.ok, false);
    assert.match(data.error ?? "", /human-plane/);
    assert.equal(data.result, undefined);
    assert.deepEqual(shape(srv, t, { width: 78 }).result, { lines: 1, rows: 2, last: 42 });
    const admin = srv.dispatch({ id: 2, op: "symbolShape", token: t, width: 78 } as never) as Res;
    assert.deepEqual(admin.result, { lines: 1, rows: 2, last: 42 });
  });
});

test("shapeRowsLast (§14): the row count and the display width of the last row, trailing spaces and wide glyphs counted", () => {
  const z = "Z".repeat(120);
  assert.deepEqual(shapeRowsLast(z, { width: 78, first: 78 }), { rows: 2, last: 42 });
  assert.deepEqual(shapeRowsLast("a\nbb\n", { width: 20, first: 20 }), { rows: 2, last: 2 }, "the trailing newline makes no row");
  assert.deepEqual(shapeRowsLast("ab  ", { width: 20, first: 20 }), { rows: 1, last: 4 }, "a value's own trailing spaces are painted");
  assert.deepEqual(shapeRowsLast("한글", { width: 20, first: 20 }), { rows: 1, last: 4 });
  assert.deepEqual(shapeRowsLast("x", { width: 20, first: 0 }), { rows: 2, last: 1 });
  assert.equal(shapeRowsLast(z, { width: 40, first: 20 }).rows, shapeRows(z, { width: 40, first: 20 }));
});

// ── §17: the `terminal` wrap rule (Goose) ────────────────────────────────────

/** fidelity-echo-wrap's long line (differential-interactive.md §32). */
const GOOSE_LONG = "DIFFWRAP_LONG " + Array.from({ length: 14 }, (_, i) => `SEGW${String(i + 1).padStart(2, "0")}`).join(" ");

test("parseShapeLayout (§17): rule is stored only when given, refused unless ink/terminal, needs width", () => {
  assert.deepEqual(parseShapeLayout({ width: 80, rule: "terminal" }), { width: 80, first: 80, rule: "terminal" });
  assert.deepEqual(parseShapeLayout({ width: 80, first: 67, rule: "ink" }), { width: 80, first: 67, rule: "ink" });
  assert.deepEqual(parseShapeLayout({ width: 80 }), { width: 80, first: 80 }, "absent stays absent (ink)");
  for (const rule of ["word", "", "TERMINAL", 1, null, {}]) {
    assert.equal(parseShapeLayout({ width: 80, rule }), "symbolShape: rule must be one of ink, terminal", JSON.stringify(rule));
  }
  assert.equal(parseShapeLayout({ rule: "terminal" }), "symbolShape: rule requires width");
  assert.equal(parseShapeLayout({ width: 80, first: 1, rule: "terminal" }), "symbolShape: first must be 0 or an integer from 40 to 80",
    "the rule never widens F's range");
});

test("shapeRows / shapeRowsLast (§17): the terminal rule counts Goose's character wrap at the full width", () => {
  const value = "DIFFWRAP_A short\n" + GOOSE_LONG + "\nDIFFWRAP_C end\n";
  // ink at cols − 2 = 78: the long line breaks before SEGW10 (the old divergence).
  assert.deepEqual(shapeRowsLast(value, { width: 78, first: 78 }), { rows: 4, last: 14 });
  // terminal at cols = 80: the long line breaks inside SEGW10, as vanilla Goose.
  assert.deepEqual(shapeRowsLast(value, { width: 80, first: 80, rule: "terminal" }), { rows: 4, last: 14 });
  assert.equal(layoutRows(GOOSE_LONG, 80, 80, "terminal")[1]!.text, "W10 SEGW11 SEGW12 SEGW13 SEGW14");
  // A row count the two rules disagree on: 81 Z's are 2 rows either way at
  // 80, but a 79-column word after a space is 1 terminal row and 2 ink rows.
  const tight = "a " + "Z".repeat(77);
  assert.equal(shapeRows(tight, { width: 80, first: 80, rule: "terminal" }), 1);
  assert.equal(shapeRows(tight, { width: 78, first: 78 }), 2);
});

test("symbolShape (§17): `rule` reaches the count over dispatch; still human plane only; a bad rule is refused before the lookup", () => {
  withServer((srv) => {
    const t = mint(srv, GOOSE_LONG);
    assert.deepEqual(shape(srv, t, { width: 80, first: 80, rule: "terminal" }).result, { lines: 1, rows: 2, last: 31 },
      "terminal: the row breaks inside SEGW10");
    assert.deepEqual(shape(srv, t, { width: 80, first: 80 }).result, { lines: 1, rows: 2, last: 34 },
      "ink: SEGW10 moves whole to the second row");
    const data = srv.dispatch({ id: 2, op: "symbolShape", token: t, width: 80, rule: "terminal" } as never, { channel: "data" }) as Res;
    assert.equal(data.ok, false);
    assert.match(data.error ?? "", /human-plane/);
    for (const tok of [t, "$MDU:secret_x[0000]"]) {
      const bad = shape(srv, tok, { width: 80, rule: "char" });
      assert.equal(bad.ok, false);
      assert.equal(bad.error, "symbolShape: rule must be one of ink, terminal");
    }
  });
});

test("parseShapeLayout (§11.2): indent is stored only when given, an integer 0..10000, and needs width", () => {
  assert.deepEqual(parseShapeLayout({ width: 78, indent: 2 }), { width: 78, first: 78, indent: 2 });
  assert.deepEqual(parseShapeLayout({ width: 78, first: 0, indent: 0 }), { width: 78, first: 0, indent: 0 });
  assert.deepEqual(parseShapeLayout({ width: 80, rule: "terminal", indent: 0 }), { width: 80, first: 80, rule: "terminal", indent: 0 });
  assert.deepEqual(parseShapeLayout({ width: 78, indent: 10000 }), { width: 78, first: 78, indent: 10000 });
  assert.deepEqual(parseShapeLayout({ width: 78 }), { width: 78, first: 78 }, "absent stays absent (0)");
  for (const indent of [-1, 1.5, "2", null, 10001, Number.NaN]) {
    assert.equal(parseShapeLayout({ width: 78, indent }), "symbolShape: indent must be an integer from 0 to 10000", String(indent));
  }
  assert.equal(parseShapeLayout({ indent: 2 }), "symbolShape: indent requires width");
});

test("shapeRows / shapeRowsLast (§11.2): a TAB's stop counts from the content area's column, as the terminal's does", () => {
  // The differential capture (differential-interactive.md §19): with the
  // reply at column 2, vanilla puts `port` at column 8 and `owner` at 16.
  const tsv = "name\tport\towner\n";
  assert.deepEqual(shapeRowsLast(tsv, { width: 118, first: 118 }), { rows: 1, last: 21 }, "from the value's own column 0");
  assert.deepEqual(shapeRowsLast(tsv, { width: 118, first: 118, indent: 2 }), { rows: 1, last: 19 }, "from the terminal's");
  // Only a TAB moves: a value without one counts the same at every indent.
  for (const indent of [0, 2, 4, 7]) assert.equal(shapeRows(GOOSE_LONG, { width: 78, first: 78, indent }), 2);
  // A row count it changes: nine tabbed cells of 7 take 71 columns from
  // column 0, 77 from column 2 (the first TAB is 7 wide, not 1), past W = 72.
  const cells = Array.from({ length: 9 }, () => "abcdefg").join("\t");
  assert.equal(shapeRows(cells, { width: 72, first: 72 }), 1);
  assert.equal(shapeRows(cells, { width: 72, first: 72, indent: 2 }), 2);
});

test("symbolShape (§11.2): `indent` reaches the count over dispatch, refused before the lookup when malformed", () => {
  withServer((srv) => {
    const t = mint(srv, "name\tport\towner\n");
    assert.deepEqual(shape(srv, t, { width: 118, first: 118 }).result, { lines: 1, rows: 1, last: 21 });
    assert.deepEqual(shape(srv, t, { width: 118, first: 118, indent: 2 }).result, { lines: 1, rows: 1, last: 19 });
    for (const tok of [t, "$MDU:secret_x[0000]"]) {
      const bad = shape(srv, tok, { width: 118, indent: -2 });
      assert.equal(bad.ok, false);
      assert.equal(bad.error, "symbolShape: indent must be an integer from 0 to 10000");
    }
  });
});
