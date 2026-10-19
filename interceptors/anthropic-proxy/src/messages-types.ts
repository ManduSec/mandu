/**
 * messages-types — the subset of the Anthropic Messages API the proxy parses.
 *
 * Mandu Track A (interceptors/anthropic-proxy). These mirror the public
 * `POST /v1/messages` request/response shapes. We model only the fields the
 * proxy must read or rewrite (model, system, messages, tools, stream, and the
 * tool_use / tool_result content blocks); everything else is preserved verbatim
 * via index signatures so we never drop unknown fields on the floor when we
 * re-serialize the rewritten request.
 *
 * Refs: Anthropic Messages API. We deliberately keep these permissive (lots of
 * optionals + passthrough) because the proxy must be robust to version drift in
 * the Claude Code request shape (implementation-plan.md §10.3).
 */

// ── Content blocks ────────────────────────────────────────────────────────────

export interface TextBlock {
  type: "text";
  text: string;
  [k: string]: unknown;
}

/** Assistant tool_use block — the model's tool-call decision. */
export interface ToolUseBlock {
  type: "tool_use";
  id: string;
  name: string;
  input: unknown;
  [k: string]: unknown;
}

/** A nested content block inside a tool_result (Anthropic allows text/image). */
export interface ToolResultContentBlock {
  type: string;
  /** present when type === "text" */
  text?: string;
  [k: string]: unknown;
}

/** User tool_result block — a tool's output re-entering the model context. */
export interface ToolResultBlock {
  type: "tool_result";
  tool_use_id: string;
  /** Either a plain string or an array of nested content blocks. */
  content?: string | ToolResultContentBlock[];
  is_error?: boolean;
  [k: string]: unknown;
}

export type ContentBlock =
  | TextBlock
  | ToolUseBlock
  | ToolResultBlock
  | ({ type: string } & Record<string, unknown>);

// ── Messages ──────────────────────────────────────────────────────────────────

export interface Message {
  role: "user" | "assistant" | string;
  /** A string (shorthand) or an array of content blocks. */
  content: string | ContentBlock[];
  [k: string]: unknown;
}

/** A system prompt block (the array form of `system`). */
export interface SystemBlock {
  type: "text";
  text: string;
  [k: string]: unknown;
}

export interface MessagesRequest {
  model: string;
  /** A string, an array of system blocks, or absent. */
  system?: string | SystemBlock[];
  messages: Message[];
  tools?: unknown[];
  stream?: boolean;
  [k: string]: unknown;
}

// ── Non-streaming response ────────────────────────────────────────────────────

export interface MessagesResponse {
  id?: string;
  type?: "message";
  role?: "assistant";
  content?: ContentBlock[];
  [k: string]: unknown;
}

// ── Type guards ───────────────────────────────────────────────────────────────

export function isToolUseBlock(b: unknown): b is ToolUseBlock {
  return !!b && typeof b === "object" && (b as { type?: string }).type === "tool_use";
}

export function isToolResultBlock(b: unknown): b is ToolResultBlock {
  return !!b && typeof b === "object" && (b as { type?: string }).type === "tool_result";
}

export function isTextBlock(b: unknown): b is TextBlock {
  return !!b && typeof b === "object" && (b as { type?: string }).type === "text";
}
