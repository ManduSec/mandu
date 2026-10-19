/**
 * text-repack.test.ts — E2E (2026-09-29): a `$MDU:` token the model splits
 * across two `response.output_text.delta` events reaches Codex WHOLE in one
 * delta through the real proxy (src/text-repack.ts), with the exec gate on
 * (the rewriter's stream) and off (the stream the gate leaves alone). The
 * text is byte-identical and the events and their sequence numbers are the
 * upstream's, in order. Without the repacker the two halves relay as sent,
 * and Codex paints them with other rows between them.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { OpenAiProxy } from "../../src/proxy.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream } from "../helpers/mock-upstream.js";

type Json = Record<string, unknown>;
const TOKEN = "$MDU:exec_command[695b].output";
const FULL = `The file holds ${TOKEN}.`;

const ev = (type: string, data: Json): string => `event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`;
const delta = (n: number, d: string): string =>
  ev("response.output_text.delta", { sequence_number: n, item_id: "msg_1", output_index: 0, content_index: 0, delta: d });
const MSG = { type: "message", id: "msg_1", role: "assistant", content: [{ type: "output_text", text: FULL }] };
const SSE = ev("response.created", { sequence_number: 0, response: { id: "r1", output: [] } })
  + ev("response.output_item.added", { sequence_number: 1, output_index: 0, item: { ...MSG, content: [] } })
  + delta(2, "The file holds $MDU") + delta(3, ":exec_command[69") + delta(4, "5b].output.")
  + ev("response.output_text.done", { sequence_number: 5, item_id: "msg_1", output_index: 0, content_index: 0, text: FULL })
  + ev("response.output_item.done", { sequence_number: 6, output_index: 0, item: MSG })
  + ev("response.completed", { sequence_number: 7, response: { id: "r1", output: [MSG] } });

function call(port: number): Promise<{ status: number; body: string }> {
  const body = JSON.stringify({
    model: "gpt-5", stream: true, instructions: "You are Codex.",
    input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "what is in notes.md?" }] }],
  });
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/responses", headers: { "content-type": "application/json" } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

for (const execGate of [true, false]) {
  for (const chunkInto of [1, 9]) {
    test(`a symbol token split across output_text deltas reaches Codex whole (exec gate ${execGate ? "on" : "off"}, ${chunkInto} chunk(s))`, async () => {
      const arbiter = new MockArbiter();
      const upstream = new MockUpstream({ sse: SSE, chunkInto });
      const proxy = new OpenAiProxy({ arbiter, upstream: upstream.fetcher, log: () => {}, ...(execGate ? {} : { execGate: false }) });
      const port = await proxy.listen(0);
      let res: { status: number; body: string };
      try {
        res = await call(port);
      } finally {
        await proxy.close();
      }
      assert.equal(res.status, 200);
      const events = res.body.split("\n\n").filter((e) => e.includes("data: ")).map((e) => JSON.parse(e.slice(e.indexOf("data: ") + 6)) as Json);
      const texts = events.filter((e) => e["type"] === "response.output_text.delta").map((e) => e["delta"] as string);
      assert.equal(texts.join(""), FULL, "the text is byte-identical");
      assert.ok(texts.some((t) => t.includes(TOKEN)), `the token is whole in one delta: ${JSON.stringify(texts)}`);
      assert.deepEqual(events.map((e) => e["sequence_number"]), [0, 1, 2, 3, 4, 5, 6, 7], "the upstream's events, in order");
      const tllm = arbiter.eventsOfKind("tllm_call");
      assert.equal(tllm.length, 1);
      assert.equal(tllm[0]!.output!.symbolized, FULL, "the tllm_call reads the model's answer, unchanged");
    });
  }
}
