/** Budgeted observer for the benign suite. No automatic provider retries.
 * PROVENANCE: NEW Mandu code; shares the scripted observer's capture contract.
 */
import { createServer, request } from "node:https";
import type { AddressInfo } from "node:net";
import type { TlsMaterial } from "../tls.js";
import type { CapturedModelRequest } from "./paired-observer.js";
import { BatchBudget, PAID_MODEL } from "./paired-budget.js";

export interface ProviderReply { status: number; contentType: string; text: string }
export type ProviderTransport = (body: Record<string, unknown>, countOnly: boolean, signal: AbortSignal) => Promise<ProviderReply>;
const MAX_BYTES = 2 * 1024 * 1024;
const BODY_KEYS = new Set(["model", "messages", "system", "tools", "tool_choice", "metadata", "max_tokens", "thinking", "context_management", "output_config", "stream", "temperature", "top_p", "top_k", "stop_sequences", "cache_control", "service_tier"]);

/** Only the pinned first-party service in production; loopback TLS seam for tests. */
export function providerTransport(apiKey: string, fixture?: { origin: string; ca: Buffer }): ProviderTransport {
  const origin = fixture ? new URL(fixture.origin) : new URL("https://api.anthropic.com");
  if (origin.protocol !== "https:" || (fixture && origin.hostname !== "127.0.0.1")) throw new Error("Provider fixture must use loopback HTTPS");
  return (body, countOnly, signal) => new Promise((resolve, reject) => {
    const bytes = JSON.stringify(body);
    const req = request(new URL(countOnly ? "/v1/messages/count_tokens" : "/v1/messages", origin), {
      method: "POST", signal, ca: fixture?.ca,
      headers: { "content-type": "application/json", "content-length": Buffer.byteLength(bytes), "x-api-key": apiKey, "anthropic-version": "2023-06-01", ...(body.context_management ? { "anthropic-beta": "context-management-2025-06-27" } : {}) },
    }, (res) => {
      const chunks: Buffer[] = []; let size = 0;
      res.on("data", (b: Buffer) => {
        size += b.length;
        if (size > 8 * MAX_BYTES) { res.destroy(); reject(new Error("Provider response size limit")); return; }
        chunks.push(b);
      });
      res.on("error", () => reject(new Error("Provider response interrupted")));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, contentType: String(res.headers["content-type"] ?? ""), text: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", () => reject(new Error("Provider request failed or timed out")));
    req.end(bytes);
  });
}

export function approvedBody(body: Record<string, unknown>, maxOutput: number, countOnly: boolean): Record<string, unknown> {
  if (body.model !== PAID_MODEL) throw new Error("Unapproved request model");
  if (Object.keys(body).some((key) => !BODY_KEYS.has(key))) throw new Error("Unsupported provider request field");
  if (!Array.isArray(body.messages)) throw new Error("Messages required");
  if (body.tools !== undefined && (!Array.isArray(body.tools) || body.tools.some((t: any) => !t || (t.type !== undefined && t.type !== "custom") || !t.input_schema))) throw new Error("Only custom client tools are permitted");
  if (body.service_tier !== undefined && body.service_tier !== "standard_only") throw new Error("Only standard service is approved");
  if (body.context_management !== undefined) {
    const edits = (body.context_management as any)?.edits;
    if (!Array.isArray(edits) || edits.some((e: any) => e?.type !== "clear_thinking_20251015")) throw new Error("Only thinking-block clearing is supported; no server compaction");
  }
  const b = structuredClone(body);
  if (!countOnly) {
    if (!Number.isSafeInteger(b.max_tokens) || (b.max_tokens as number) < 1) throw new Error("Valid max_tokens required");
    b.max_tokens = Math.min(b.max_tokens as number, maxOutput);
    b.service_tier = "standard_only";
    const thinking = b.thinking as any;
    if (thinking && thinking.type !== "disabled" && (thinking.type !== "enabled" || !Number.isSafeInteger(thinking.budget_tokens) || thinking.budget_tokens >= (b.max_tokens as number))) throw new Error("Thinking configuration exceeds approved output or model support");
  }
  return b;
}

/** Require terminal evidence before releasing a streaming request reservation. */
export function replyUsage(reply: ProviderReply, countOnly: boolean): unknown {
  if (reply.status !== 200) throw new Error("Provider returned non-success status");
  if (!reply.contentType.includes("text/event-stream")) {
    const parsed = JSON.parse(reply.text);
    if (countOnly) return parsed;
    if (parsed.type !== "message" || parsed.model !== PAID_MODEL || !parsed.stop_reason) throw new Error("Incomplete provider message");
    return parsed.usage;
  }
  let usage: Record<string, unknown> | undefined; let stopped = false; let delta = false;
  for (const frame of reply.text.replace(/\r\n/g, "\n").split("\n\n")) {
    const text = frame.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart()).join("\n");
    if (!text) continue;
    const event = JSON.parse(text);
    if (event.type === "error") throw new Error("Provider stream error");
    if (event.type === "message_start") {
      if (usage || event.message?.model !== PAID_MODEL) throw new Error("Unexpected provider stream start");
      usage = event.message.usage;
    }
    if (event.type === "message_delta") {
      if (!usage || !event.usage || !event.delta?.stop_reason) throw new Error("Incomplete stream usage");
      usage = { ...usage, ...event.usage }; delta = true;
    }
    if (event.type === "message_stop") stopped = true;
  }
  if (!stopped || !delta || !usage) throw new Error("Incomplete provider stream");
  return usage;
}

export async function startBudgetObserver(tls: TlsMaterial, budget: BatchBudget, leg: string,
  channel: CapturedModelRequest["channel"], send: ProviderTransport,
): Promise<{ origin: string; requests: CapturedModelRequest[]; errors: string[]; receipts: unknown[]; close(): Promise<void> }> {
  const requests: CapturedModelRequest[] = []; const errors: string[] = []; const receipts: unknown[] = [];
  const active = new Set<AbortController>();
  const handlers = new Set<Promise<void>>();
  const server = createServer(tls, (req, res) => {
    const handle = async () => {
      let reservation: number | undefined;
      let control: AbortController | undefined;
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        if (req.method !== "POST" || !/^\/v1\/messages(?:\/count_tokens)?(?:\?[^#]*)?$/.test(req.url ?? "")) throw new Error("Unsupported observer route");
        const chunks: Buffer[] = []; let bytes = 0;
        for await (const part of req) {
          bytes += part.length;
          if (bytes > MAX_BYTES) throw new Error("Request size limit");
          chunks.push(Buffer.from(part));
        }
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("Invalid request body");
        requests.push({ channel, path: req.url!, body });
        const countOnly = req.url!.split("?")[0].endsWith("/count_tokens");
        const forwarded = approvedBody(body, budget.approval.maxOutputTokens, countOnly);
        reservation = budget.reserve(leg, channel, countOnly ? 1 : forwarded.max_tokens as number, countOnly);
        control = new AbortController(); active.add(control);
        timer = setTimeout(() => control!.abort(), Math.min(60_000, budget.remainingMs()));
        res.once("close", () => { if (!res.writableEnded) control!.abort(); });
        const reply = await send(forwarded, countOnly, control.signal);
        // Receipt contains no headers, key, or provider error payload.
        const usage = replyUsage(reply, countOnly);
        budget.settle(reservation, usage);
        receipts.push({ reservation, status: reply.status, forwarded, usage });
        if (budget.snapshot().requests[reservation].state !== "settled") throw new Error("Provider usage could not be validated");
        res.writeHead(200, { "content-type": reply.contentType }); res.end(reply.text);
      } catch (e) {
        if (reservation !== undefined) budget.uncertain(reservation);
        else budget.stop("Observer rejected an unsupported request");
        errors.push(e instanceof SyntaxError ? "Invalid provider/observer JSON" : String(e));
        if (!res.destroyed) { res.writeHead(502, { "content-type": "application/json" }); res.end('{"type":"error","error":{"type":"api_error","message":"Benign evaluation stopped; inspect budget.json and observer artifacts"}}'); }
      } finally {
        if (timer) clearTimeout(timer);
        if (control) active.delete(control);
      }
    };
    // A local artifact-write failure must also stop forwarding without an
    // unhandled rejection or disclosure of a provider response/error body.
    const promise = handle().catch(() => { errors.push("Observer could not persist budget evidence"); res.destroy(); }); handlers.add(promise);
    void promise.finally(() => handlers.delete(promise));
  });
  server.requestTimeout = 15_000;
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  return { origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, requests, errors, receipts,
    close: async () => {
      for (const c of active) c.abort();
      await new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => resolve()); });
      await Promise.allSettled([...handlers]);
    } };
}
