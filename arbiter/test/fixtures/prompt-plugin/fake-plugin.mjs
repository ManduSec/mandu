#!/usr/bin/env node
/**
 * fake-plugin — a TEST prompt filter plugin (confidentiality-plan-15 §4.3),
 * the protocol's other end with no model. No imports beyond node builtins:
 * it runs from the arbiter's private copy.
 *
 *   --find <word> <category>   a finding for every occurrence of <word>
 *                              (repeatable)
 *   --sleep <ms>               wait before answering (a deadline test)
 *   --exit <n>                 exit with <n> and no answer
 *   --raw <json>               answer exactly <json> (a closed-shape test)
 *   --probe <port> <file>      before answering: try to connect to
 *                              127.0.0.1:<port> and to read <file>; exit 9
 *                              if EITHER works (confinement tests)
 *   --model                    ask the endpoint of the request (an
 *                              OpenAI-shaped /v1/chat/completions) which
 *                              words to find; the model answers a JSON list
 *                              of {word, category}
 *   --log-env <file>           (unconfined tests only) write the env keys
 */
import { readFileSync, writeFileSync } from "node:fs";
import net from "node:net";

const args = process.argv.slice(2);
const finds = [];
let sleep = 0;
let exitCode = null;
let raw = null;
let probe = null;
let model = false;
let logEnv = null;
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "--find") { finds.push({ word: args[i + 1], category: args[i + 2] }); i += 2; }
  else if (a === "--sleep") { sleep = Number(args[++i]); }
  else if (a === "--exit") { exitCode = Number(args[++i]); }
  else if (a === "--raw") { raw = args[++i]; }
  else if (a === "--probe") { probe = { port: Number(args[i + 1]), file: args[i + 2] }; i += 2; }
  else if (a === "--model") { model = true; }
  else if (a === "--log-env") { logEnv = args[++i]; }
}

const input = readFileSync(0, "utf8");
const req = JSON.parse(input);

const tryConnect = (port) => new Promise((resolve) => {
  const s = net.connect(port, "127.0.0.1");
  s.on("connect", () => { s.destroy(); resolve(true); });
  s.on("error", () => resolve(false));
  setTimeout(() => { s.destroy(); resolve(false); }, 2000);
});

async function main() {
  if (logEnv) writeFileSync(logEnv, JSON.stringify(Object.keys(process.env).sort()));
  if (probe) {
    const connected = await tryConnect(probe.port);
    let read = false;
    try { readFileSync(probe.file); read = true; } catch { /* denied: good */ }
    if (connected || read) process.exit(9);
  }
  if (sleep > 0) await new Promise((r) => setTimeout(r, sleep));
  if (exitCode !== null) process.exit(exitCode);
  if (raw !== null) { process.stdout.write(raw); return; }
  let words = finds;
  if (model) {
    const url = `${req.endpoint.url.replace(/\/$/, "")}/v1/chat/completions`;
    const res = await fetch(url, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: req.endpoint.model ?? "x", messages: req.segments.map((s) => ({ role: "user", content: s.text })) }),
    });
    const body = await res.json();
    words = JSON.parse(body.choices[0].message.content);
  }
  const findings = [];
  for (const s of req.segments) {
    for (const f of words) {
      let i = s.text.indexOf(f.word);
      while (i >= 0) {
        findings.push({ segment: s.id, start: i, end: i + f.word.length, category: f.category });
        i = s.text.indexOf(f.word, i + 1);
      }
    }
  }
  process.stdout.write(JSON.stringify({ findings }));
}

main().catch(() => process.exit(5));
