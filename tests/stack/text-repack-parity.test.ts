/**
 * text-repack-parity.test.ts — ONE text-delta token repacker in two model
 * proxies (docs/design/architecture/architecture-map.md §9 ①, "The text-delta
 * repacker").
 *
 * anthropic-proxy (the routed OpenClaw / OpenCode OpenAI wires, and the
 * token grammar its Messages repacker cuts by) and openai-proxy (Codex,
 * Kimi) ship standalone, so src/text-repack.ts and its unit suite
 * test/unit/text-repack.test.ts are copied verbatim into each. A drift would
 * let one proxy hand an agent a token cut in two that the other rejoins, and
 * the reply filter downstream can only restore contiguous bytes. This file:
 *   - holds both pairs byte-identical (the drift check);
 *   - runs ONE table of split-token cases through both packages' exports and
 *     requires the same bytes out, every token whole in one delta: tokens the
 *     arbiter really mints (symbol-format.ts `generate`, every level marker,
 *     a canonical-encoded field) split at every boundary, one delta per
 *     character, and a seeded corpus for `danglingTokenStart`;
 *   - keeps the Messages repacker and the reply filter on the same grammar.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { stateAxes } from "../lib/axes.js";
import * as anthropic from "../../interceptors/anthropic-proxy/src/text-repack.js";
import * as openai from "../../interceptors/openai-proxy/src/text-repack.js";
import { MDU_SYM_FORMAT } from "../../arbiter/symbol-table/symbol-format.js";

stateAxes("secrets"); // the repacker reads no axis; a secret's symbol is what it keeps whole

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const read = (p: string): string => readFileSync(join(ROOT, p), "utf8");

type Json = Record<string, unknown>;
/** What the table drives in each package (the two copies' classes are
 *  distinct nominal types, so the table reads them structurally). */
interface Repacker { feed(chunk: string): string; end(): string }
interface Pkg {
  ChatTextRepacker: new () => Repacker;
  ResponsesTextRepacker: new () => Repacker;
  danglingTokenStart: (text: string) => number;
  REPACK_HOLD_CAP: number;
}
const PKGS: Array<[string, Pkg]> = [["anthropic-proxy", anthropic], ["openai-proxy", openai]];

test("the two copies of text-repack.ts and of its unit suite are byte-identical", () => {
  for (const f of ["src/text-repack.ts", "test/unit/text-repack.test.ts"]) {
    const master = read(`interceptors/anthropic-proxy/${f}`);
    assert.equal(read(`interceptors/openai-proxy/${f}`), master,
      `interceptors/openai-proxy/${f} drifted from interceptors/anthropic-proxy/${f}; copy the anthropic-proxy file out again`);
  }
});

test("the Messages repacker and the reply filter cut by the same token grammar", () => {
  const sse = read("interceptors/anthropic-proxy/src/sse-text-repack.ts");
  assert.match(sse, /^import \{ danglingTokenStart \} from "\.\/text-repack\.js";$/m, "sse-text-repack.ts takes its grammar from the shared module");
  assert.doesNotMatch(sse, /TOKEN_CONTINUATION_RE|TOKEN_HEAD|function danglingTokenStart/, "sse-text-repack.ts keeps no grammar of its own");
  const constLine = (src: string, name: string): string => {
    const m = new RegExp(`^const ${name} = .*;$`, "m").exec(src);
    assert.ok(m, `${name} is declared`);
    return m[0];
  };
  const shared = read("interceptors/anthropic-proxy/src/text-repack.ts");
  const filter = read("interceptors/reply-filter/src/filter.ts");
  for (const name of ["TOKEN_HEAD", "TOKEN_CONTINUATION_RE"]) {
    assert.equal(constLine(filter, name), constLine(shared, name), `reply-filter's ${name} matches the repacker's`);
  }
});

// ── one table, both packages ─────────────────────────────────────────────────

/** Tokens the arbiter mints: every level marker, a field, a canonical-encoded
 *  field, an MCP tool tag; plus the Markdown-escaped spelling a model writes. */
const MINTED = [
  MDU_SYM_FORMAT.generate({ tool: "exec_command", hash: "695b" }),
  MDU_SYM_FORMAT.generate({ tool: "Read", hash: "5e1a", level: "no-model" }),
  MDU_SYM_FORMAT.generate({ tool: "Read", hash: "5e1a", level: "local-model", field: "DB_PASSWORD" }),
  MDU_SYM_FORMAT.generate({ tool: "Bash", hash: "0c3d9e2f", level: "any-model", field: "stdout" }),
  MDU_SYM_FORMAT.generate({ tool: "mcp__github__get_file", hash: "a1b2", field: "api-key" }),
  MDU_SYM_FORMAT.generate({ tool: "inspect_symbol", hash: "8c1d", field: "result" }),
];
const TOKENS = [...MINTED, "\\$MDU:web\\_fetch[8c1d]"];

function payloads(sse: string): Json[] {
  return sse.split("\n\n").flatMap((e) => {
    const line = e.split("\n").find((l) => l.startsWith("data: "));
    return line && line !== "data: [DONE]" ? [JSON.parse(line.slice(6)) as Json] : [];
  });
}

interface Wire {
  name: string;
  make: (p: Pkg) => Repacker;
  stream: (pieces: string[], full: string) => string;
  texts: (sse: string) => string[];
}
const WIRES: Wire[] = [
  {
    name: "chat",
    make: (p) => new p.ChatTextRepacker(),
    stream: (pieces) => {
      const chunk = (delta: Json, finish: string | null = null): string =>
        `data: ${JSON.stringify({ id: "c1", object: "chat.completion.chunk", created: 1, model: "m", choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
      return chunk({ role: "assistant", content: "" }) + pieces.map((p) => chunk({ content: p })).join("") + chunk({}, "stop") + "data: [DONE]\n\n";
    },
    texts: (sse) => payloads(sse).flatMap((p) => ((p["choices"] as Json[] | undefined) ?? [])
      .map((c) => (c["delta"] as Json | undefined)?.["content"]).filter((t): t is string => typeof t === "string")),
  },
  {
    name: "responses",
    make: (p) => new p.ResponsesTextRepacker(),
    stream: (pieces, full) => {
      let n = 0;
      const ev = (type: string, data: Json): string => `event: ${type}\ndata: ${JSON.stringify({ type, sequence_number: n++, ...data })}\n\n`;
      return pieces.map((p) => ev("response.output_text.delta", { item_id: "m", output_index: 0, content_index: 0, delta: p })).join("")
        + ev("response.output_text.done", { item_id: "m", output_index: 0, content_index: 0, text: full });
    },
    texts: (sse) => payloads(sse).filter((p) => p["type"] === "response.output_text.delta").map((p) => p["delta"] as string),
  },
];

/** The stream through one package's repacker, fed whole or byte by byte. */
function run(w: Wire, p: Pkg, sse: string, bytewise: boolean): string {
  const r = w.make(p);
  let out = "";
  if (bytewise) for (const c of sse) out += r.feed(c);
  else out += r.feed(sse);
  return out + r.end();
}

/** Both packages give the same bytes, the text is kept, the token is whole. */
function check(w: Wire, sse: string, full: string, tok: string, at: string): void {
  for (const bytewise of [false, true]) {
    const outs = PKGS.map(([, p]) => run(w, p, sse, bytewise));
    assert.equal(outs[1], outs[0], `${w.name}: the two packages diverge (${at}${bytewise ? ", bytewise" : ""})`);
    const texts = w.texts(outs[0]!);
    assert.equal(texts.join(""), full, `${w.name}: text preserved (${at})`);
    assert.equal(texts.filter((t) => t.includes(tok)).length, 1, `${w.name}: ${tok} whole in one delta (${at}): ${JSON.stringify(texts)}`);
  }
}

test("every minted token, split at every boundary, comes out the same and whole from both packages", () => {
  for (const w of WIRES) {
    for (const tok of TOKENS) {
      const full = `The value is ${tok}, as asked.`;
      for (let k = 1; k < full.length; k++) {
        check(w, w.stream([full.slice(0, k), full.slice(k)], full), full, tok, `split after ${JSON.stringify(full.slice(0, k))}`);
      }
      check(w, w.stream([...full], full), full, tok, "one delta per character");
    }
  }
});

test("danglingTokenStart answers alike in both packages over a seeded corpus", () => {
  assert.equal(openai.REPACK_HOLD_CAP, anthropic.REPACK_HOLD_CAP);
  const alphabet = ["$", "M", "D", "U", ":", "\\", "_", "[", "]", ".", "a", "0", "f", " ", "\n", "é"];
  let seed = 0x2f6e2b1;
  const rand = (n: number): number => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed % n;
  };
  const corpus = [...TOKENS.flatMap((t) => [...t].map((_, i) => `x ${t.slice(0, i + 1)}`)), "$MDU:" + "a".repeat(anthropic.REPACK_HOLD_CAP)];
  for (let i = 0; i < 5000; i++) {
    let s = "";
    const len = 1 + rand(24);
    for (let j = 0; j < len; j++) s += alphabet[rand(alphabet.length)];
    corpus.push(s);
  }
  for (const s of corpus) assert.equal(openai.danglingTokenStart(s), anthropic.danglingTokenStart(s), JSON.stringify(s));
});
