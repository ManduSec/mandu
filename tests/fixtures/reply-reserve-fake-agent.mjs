// reply-reserve-fake-agent.mjs — a FAKE AGENT for
// tests/stack/reply-row-reservation.test.ts (docs/design/ui/reply-row-reservation.md
// §6, integration e2e). It stands where Claude Code stands: it talks to the
// model through the anthropic-proxy (ANTHROPIC_BASE_URL) and prints the
// assistant's text on its terminal, line by line, like a simple TUI. It runs
// under the reply filter's PTY relay, so what it prints is what the human's
// terminal receives after the filter.
//
// Env:
//   RR_PROXY_URL   the proxy's base URL (http://127.0.0.1:<port>)
//   RR_SESSION     the x-mandu-session-id header (the events' session)
//   RR_GO_FILE     waits until this file exists before the first request (the
//                  test creates it once the filter's relay report reached the
//                  arbiter, so the proxy reads a set relay)
//   RR_OUT_DIR     writes the raw response bytes of turn i to raw<i>.sse and
//                  the assistant text to text<i>.txt (the agent's world)
//   RR_TURNS       1 or 2: turn 2 sends turn 1's reply back as assistant
//                  history, as Claude Code does, and prints only a marker
//   RR_RENDER      `tail-alt`: paint only rows 3..N of the block on the
//                  alternate screen (the head never shown), from column 2 as
//                  Claude Code's content indent, then stay there;
//                  `md-spans`: print each line without its backticks, as a
//                  Markdown renderer draws code spans (reply-row-reservation.md §12);
//                  `indent2`: print each line two columns in, as Claude Code
//                  lays its reply out (the proxy's W = cols − 2, §11.2)
//
// Mandu-new test fixture (no reference origin). Plain Node, no dependencies.
import { request } from "node:http";
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const base = new URL(process.env.RR_PROXY_URL);
const outDir = process.env.RR_OUT_DIR;
const turns = Number(process.env.RR_TURNS ?? "1");

async function waitGo() {
  const file = process.env.RR_GO_FILE;
  const deadline = Date.now() + 15000;
  while (file && !existsSync(file)) {
    if (Date.now() > deadline) throw new Error(`no go file: ${file}`);
    await new Promise((r) => setTimeout(r, 20));
  }
}

function post(body) {
  const data = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: base.hostname, port: base.port, method: "POST", path: "/v1/messages",
        headers: {
          "content-type": "application/json", "content-length": String(data.length),
          "anthropic-version": "2023-06-01", "x-mandu-session-id": process.env.RR_SESSION ?? "",
        },
      },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, raw: buf }));
      },
    );
    req.on("error", reject);
    req.end(data);
  });
}

/** The concatenated text_delta text of an SSE body. */
function textOf(raw) {
  let text = "";
  for (const ev of raw.split("\n\n")) {
    const line = ev.split("\n").find((l) => l.startsWith("data: "));
    if (!line) continue;
    let p;
    try { p = JSON.parse(line.slice(6)); } catch { continue; }
    if (p.type === "content_block_delta" && p.delta?.type === "text_delta") text += p.delta.text;
  }
  return text;
}

const USER = { role: "user", content: "show me my ssh config" };
const MODEL = "claude-opus-4";

await waitGo();
const r1 = await post({ model: MODEL, stream: true, max_tokens: 1024, messages: [USER] });
writeFileSync(join(outDir, "raw1.sse"), r1.raw);
const text1 = textOf(r1.raw);
writeFileSync(join(outDir, "text1.txt"), text1);
if (r1.status !== 200) process.stdout.write(`AGENT-HTTP-${r1.status}\n`);
if (process.env.RR_RENDER === "tail-alt") {
  // A fullscreen renderer showing only the TAIL of a block taller than its
  // viewport (reply-row-reservation.md §3.8): the alternate screen, rows 3..N
  // of the block painted from the top, so the head row (and row 2) never
  // reach the terminal. The screen stays on the alternate buffer. Rows start
  // at column 2 (1-based 3), where Claude Code's reply text starts.
  const lines = text1.split("\n");
  const head = lines.findIndex((l) => /\/1:\d/.test(l));
  let row = 1;
  process.stdout.write("\x1b[?1049h\x1b[H");
  for (const line of lines.slice(head + 2)) process.stdout.write(`\x1b[${row++};3H${line}`);
  await new Promise((r) => setTimeout(r, 300)); // the filter's first reconcile asks the arbiter
  process.stdout.write(`\x1b[${row};1HAGENT-END`);
  await new Promise((r) => setTimeout(r, 600));
  process.exit(0);
}
const shown = process.env.RR_RENDER === "md-spans" ? (l) => l.replace(/`/g, "")
  : process.env.RR_RENDER === "indent2" ? (l) => `  ${l}` : (l) => l;
for (const line of text1.split("\n")) process.stdout.write(shown(line) + "\n");

if (turns >= 2) {
  const r2 = await post({
    model: MODEL, stream: true, max_tokens: 1024,
    messages: [USER, { role: "assistant", content: [{ type: "text", text: text1 }] }, { role: "user", content: "thanks" }],
  });
  writeFileSync(join(outDir, "raw2.sse"), r2.raw);
  writeFileSync(join(outDir, "text2.txt"), textOf(r2.raw));
  process.stdout.write(`TURN2-${r2.status}\n`);
}
process.stdout.write("AGENT-END\n");
// Stay a moment so the relay drains and the reconciler settles while alive.
await new Promise((r) => setTimeout(r, 600));
