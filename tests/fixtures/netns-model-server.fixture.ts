/**
 * netns-model-server.fixture — the model on "the other machine" (the peer
 * namespace of tests/lib/netns.ts). An https stand-in with the test CA's
 * server certificate, listening on every address of the peer (so on
 * 10.77.0.2 AND on 203.0.113.9), answering both wires the declared models
 * use: OpenAI chat (the helper) and Anthropic Messages (a main model).
 *
 * Every request is appended to MODEL_LOG as one JSON line with the LOCAL
 * address it arrived on: the test's wire oracle for "which address did the
 * client connect to".
 *
 * With MODEL_UPSTREAM (the live leg: http://10.0.2.2:11434, the host's
 * Ollama as the peer reaches it) every request is relayed there and the real
 * model's answer returned; the log is written the same way.
 *
 * env: MODEL_CERT, MODEL_KEY (PEM paths), MODEL_PORT, MODEL_LOG, MODEL_READY,
 * MODEL_UPSTREAM (optional).
 * PROVENANCE: NEW Mandu test code.
 */
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { createServer } from "node:https";

const env = (k: string): string => {
  const v = process.env[k];
  if (!v) throw new Error(`${k} is required`);
  return v;
};

const sse = (text: string): string => [
  `event: message_start\ndata: ${JSON.stringify({ type: "message_start", message: { id: "msg_netns", type: "message", role: "assistant", model: "netns", content: [], stop_reason: null, usage: { input_tokens: 1, output_tokens: 0 } } })}\n\n`,
  `event: content_block_start\ndata: ${JSON.stringify({ type: "content_block_start", index: 0, content_block: { type: "text", text: "" } })}\n\n`,
  `event: content_block_delta\ndata: ${JSON.stringify({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text } })}\n\n`,
  `event: content_block_stop\ndata: ${JSON.stringify({ type: "content_block_stop", index: 0 })}\n\n`,
  `event: message_delta\ndata: ${JSON.stringify({ type: "message_delta", delta: { stop_reason: "end_turn" }, usage: { output_tokens: 1 } })}\n\n`,
  `event: message_stop\ndata: ${JSON.stringify({ type: "message_stop" })}\n\n`,
].join("");

const server = createServer({ cert: readFileSync(env("MODEL_CERT")), key: readFileSync(env("MODEL_KEY")) }, (req, res) => {
  let body = "";
  req.on("data", (d) => { body += d; });
  req.on("end", () => {
    appendFileSync(env("MODEL_LOG"), JSON.stringify({ local: req.socket.localAddress, host: req.headers.host, method: req.method, path: req.url, body }) + "\n");
    const upstream = process.env["MODEL_UPSTREAM"];
    if (upstream) {
      const u = new URL(req.url ?? "/", upstream);
      const up = httpRequest(u, { method: req.method, headers: { "content-type": req.headers["content-type"] ?? "application/json" } }, (r) => {
        res.writeHead(r.statusCode ?? 502, { "content-type": r.headers["content-type"] ?? "application/json" });
        r.pipe(res);
      });
      up.on("error", (e) => { res.writeHead(502); res.end(String(e.message)); });
      up.end(body);
      return;
    }
    if (req.url?.endsWith("/messages")) {
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end(sse("netns-main-model-answer"));
      return;
    }
    const text = body.includes("quarantined content classifier") ? "substantive" : "A summary from the model on the other machine.";
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ model: "qwen", choices: [{ message: { role: "assistant", content: text } }] }));
  });
});
server.on("tlsClientError", () => { /* a refused handshake is a test's point */ });
server.listen(Number(env("MODEL_PORT")), "0.0.0.0", () => writeFileSync(env("MODEL_READY"), "up\n"));
process.on("SIGTERM", () => server.close(() => process.exit(0)));
