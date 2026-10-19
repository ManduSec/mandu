# Webhook Symbolization

## Overview

Webhooks are agent inbound data from external HTTP endpoints (GitHub, CI,
monitoring, etc.). The webhook provider is authenticated, but the data it
carries may be partially untrusted (e.g., a GitHub issue body is user-written,
but the author and labels are GitHub-generated).

Mandu uses the `transform_webhook_content` hook to apply per-field
symbolization before the LLM sees the message. See the inbound data spec in
[inbound-outbound-spec.md](inbound-outbound-spec.md) for how webhooks fit
into the overall classification.

## Security Model

Webhook senders are trusted. They are authenticated infrastructure components
(e.g., GitHub via webhook secret, CI pipelines via service tokens). However,
the data they deliver can be partially untrusted. For example, a GitHub webhook
for a new issue is sent by GitHub (trusted sender), but the issue body is
written by an arbitrary user (untrusted data).

We expect webhook senders to specify the trust level of each data field via the
`security` field in the payload. Fields not specified default to UNTRUSTED.

## Payload Format

### `data` (required)

The structured payload fields. Each field is symbolized or passed through
based on the security schema.

```json
{
  "data": {
    "number": 42,
    "author": "alice",
    "title": "Fix bug",
    "body": "When web_fetch fails, retry with backoff."
  }
}
```

Without a `security` field, all string fields in `data` default to UNTRUSTED.

### `security` (optional)

Per-field trust schema. Maps field names to `TRUSTED` or `UNTRUSTED`. Fields
not listed default to `UNTRUSTED` (deny-by-default).

```json
{
  "data": {
    "number": 42,
    "author": "alice",
    "title": "Fix bug",
    "body": "When web_fetch fails, retry with backoff."
  },
  "security": {
    "number": "TRUSTED",
    "author": "TRUSTED",
    "title": "UNTRUSTED",
    "body": "UNTRUSTED"
  }
}
```

### `template` (optional)

A Mustache-style template string with `{{field}}` references into `data`. When
provided, Mandu renders the template with symbolized data values to produce a
human-readable message.

```json
{
  "template": "Email from {{from}}\nSubject: {{subject}}\n{{body}}",
  "data": {
    "from": "alice@example.com",
    "subject": "Meeting tomorrow",
    "body": "Hi, please review the attached document..."
  },
  "security": {
    "from": "TRUSTED",
    "subject": "UNTRUSTED",
    "body": "UNTRUSTED"
  }
}
```

Output (symbolize mode):
```
[Mandu:SYMBOLIZED source="webhook" job="gmail"]
Email from alice@example.com
Subject: $MDU:webhook[a1b2].subject
$MDU:webhook[a1b2].body
```

Without a `template`, the output is a tagged JSON block with symbolized
fields.

### Backward compatibility

If the payload has no `data` field, the hook treats the entire JSON object as
data fields (excluding `template`, `data`, `security` keys). This supports
existing webhook senders that have not adopted the new format.

### Non-JSON fallback

If the webhook content is not valid JSON, the entire text is symbolized as a
single variable.

## Preprocessing

Before Mandu processes the webhook payload, OpenClaw wraps the raw content with
`<<<EXTERNAL_UNTRUSTED_CONTENT id="...">>>` markers and a security notice.
Mandu strips these markers before extracting the JSON payload.

The stripping finds the first `<<<EXTERNAL_UNTRUSTED_CONTENT` marker and the
last matching `<<<END_EXTERNAL_UNTRUSTED_CONTENT` marker with the same ID.
Content outside these markers is discarded. This means an untrusted value
cannot forge the JSON structure by injecting fake markers, because the parser
matches by ID and only uses the outermost pair.

We also expect webhook senders to properly escape quotation marks in field
values, so untrusted content cannot break out of JSON string boundaries.

## Security Considerations

### JSON boundary safety

Webhook payloads are parsed by `JSON.parse` in the plugin, not by the LLM. The
JSON parser guarantees that field values are isolated. An attacker controlling
an untrusted field (e.g., email body) cannot inject content that corrupts other
fields or escapes the field boundary. This is a fundamental advantage over
flat-text template rendering, where field delimiters can be spoofed.

### Template field trust

The `template` field is treated as trusted because it originates from the
webhook sender's code, not from user-controlled data. If the webhook sender is
compromised, the template could contain malicious formatting, but this is
equivalent to compromising any other piece of infrastructure code.

## Related

- Inbound data spec: [inbound-outbound-spec.md](inbound-outbound-spec.md)
- Symbol format: `plugin/adfi/adfi-symbol-format.ts`
