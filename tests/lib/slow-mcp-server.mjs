#!/usr/bin/env node
// slow-mcp-server.mjs — a stdio MCP server with ONE tool (`slow_answer`, or
// SLOW_MCP_TOOL_NAME) that answers after SLOW_MCP_DELAY_MS (default 5000)
// with `SLOW_MCP_DONE after <ms> ms; auto-background=<a>; ullm-timeout=<u>`:
// <a> is the CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS it inherited from its agent,
// <u> the MANDU_ULLM_ENDPOINT_TIMEOUT_MS its entry or agent handed it
// ("unset" when none). A stand-in for inspect_symbol at a slow local model
// (model-endpoints.md §1.9): Claude Code moves an MCP call that runs past
// its auto-background window to the background, and the test reads which
// happened off the tool_result the model gets.
//
// Hand-rolled JSON-RPC over newline-delimited stdio (no SDK dependency):
// initialize, notifications/initialized, tools/list, tools/call, ping.
// Mandu-new test helper.
import { createInterface } from "node:readline";

const delayMs = Number(process.env.SLOW_MCP_DELAY_MS ?? "5000");
const toolName = process.env.SLOW_MCP_TOOL_NAME ?? "slow_answer";
const send = (msg) => process.stdout.write(`${JSON.stringify(msg)}\n`);

createInterface({ input: process.stdin }).on("line", (line) => {
  let req;
  try { req = JSON.parse(line); } catch { return; }
  if (req === null || typeof req !== "object" || req.id === undefined) return; // a notification
  const reply = (result) => send({ jsonrpc: "2.0", id: req.id, result });
  switch (req.method) {
    case "initialize":
      reply({
        protocolVersion: req.params?.protocolVersion ?? "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name: "slow-mcp", version: "1.0.0" },
      });
      return;
    case "tools/list":
      reply({
        tools: [{
          name: toolName,
          description: "Answers after a fixed delay.",
          inputSchema: { type: "object", properties: {}, additionalProperties: false },
        }],
      });
      return;
    case "tools/call": {
      const started = Date.now();
      const knob = process.env.CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS ?? "unset";
      const ullm = process.env.MANDU_ULLM_ENDPOINT_TIMEOUT_MS ?? "unset";
      setTimeout(() => {
        reply({ content: [{ type: "text", text: `SLOW_MCP_DONE after ${Date.now() - started} ms; auto-background=${knob}; ullm-timeout=${ullm}` }] });
      }, delayMs);
      return;
    }
    case "ping":
      reply({});
      return;
    default:
      send({ jsonrpc: "2.0", id: req.id, error: { code: -32601, message: `no method ${req.method}` } });
  }
});
