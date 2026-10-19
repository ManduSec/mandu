# gws exec inbound/outbound data spec

Planning doc for per-subcommand inbound data spec for `gws` (Google Workspace CLI).

## Background

`gws` is a multi-modal CLI covering Gmail, Calendar, Drive, Sheets, Docs, and more. Each subcommand returns a different JSON shape with different trust characteristics. A flat `EXEC_RESULT_TRUST["gws"]` entry cannot capture this. gws needs per-subcommand dispatch (#177) or, as a Phase 1 workaround, separate fixture entries per subcommand pattern.

Related issues: #175 (umbrella), #177 (per-subcommand dispatch), #181 (verify-then-encode gws).

## gws command surface

### Helpers (high-level, agent-friendly)

| Command | Type | Description |
|---|---|---|
| `gws gmail +triage` | read | Unread inbox summary (from, subject, date, id) |
| `gws gmail +send` | write | Send email |
| `gws gmail +reply` | write | Reply to a message |
| `gws gmail +reply-all` | write | Reply-all to a message |
| `gws gmail +forward` | write | Forward a message |
| `gws calendar +agenda` | read | Upcoming events across calendars |
| `gws calendar +insert` | write | Create a new event |
| `gws drive +upload` | write | Upload a file |
| `gws sheets +read` | read | Read values from a spreadsheet |
| `gws sheets +append` | write | Append a row to a spreadsheet |

### Raw API (low-level)

| Command | Type | Description |
|---|---|---|
| `gws gmail users messages list` | read | List message IDs |
| `gws gmail users messages get` | read | Get message content |
| `gws gmail users messages send` | write | Send (raw API) |
| `gws calendar events list` | read | List events |
| `gws drive files list` | read | List files |
| `gws drive files get` | read | Get file metadata |

## Inbound data spec per subcommand

### gmail +triage

Real output shape:
```json
{
  "messages": [
    { "date": "Fri, 3 Apr 2026 18:10:33 +0000", "from": "Name <email>", "id": "19d548a2b76de9ac", "subject": "..." }
  ],
  "query": "is:unread",
  "resultSizeEstimate": 201
}
```

| Field | Classification | Rationale |
|---|---|---|
| `query` | TRUSTED | Agent-supplied search query |
| `resultSizeEstimate` | TRUSTED | Gmail platform metadata |
| `messages[].id` | TRUSTED | Gmail-generated message ID |
| `messages[].date` | TRUSTED | SMTP Date header (RFC 2822, set by sending MTA) |
| `messages[].from` | UNTRUSTED | Display name is sender-controlled (e.g. `"Your Bank" <phish@evil.com>`) |
| `messages[].subject` | UNTRUSTED | Sender-written, primary prompt injection vector |

### gmail users messages list

Real output shape:
```json
{
  "messages": [{ "id": "...", "threadId": "..." }],
  "nextPageToken": "...",
  "resultSizeEstimate": 201
}
```

| Field | Classification | Rationale |
|---|---|---|
| All fields | TRUSTED | Only contains Gmail-generated IDs and pagination metadata |

### gmail users messages get (format=metadata)

Real output shape:
```json
{
  "id": "...", "threadId": "...", "historyId": "...",
  "internalDate": "1775239833000",
  "labelIds": ["CATEGORY_PROMOTIONS", "INBOX"],
  "sizeEstimate": 90536,
  "snippet": "First ~100 chars of body...",
  "payload": {
    "headers": [
      { "name": "Date", "value": "..." },
      { "name": "From", "value": "Name <email>" },
      { "name": "To", "value": "..." },
      { "name": "Subject", "value": "..." }
    ],
    "mimeType": "multipart/alternative"
  }
}
```

| Field | Classification | Rationale |
|---|---|---|
| `id`, `threadId`, `historyId` | TRUSTED | Gmail-generated |
| `internalDate` | TRUSTED | Gmail-generated timestamp |
| `labelIds` | TRUSTED | User/Gmail label assignments |
| `sizeEstimate` | TRUSTED | Gmail metadata |
| `snippet` | UNTRUSTED | Extracted from email body, sender-written |
| `payload.mimeType` | TRUSTED | MIME metadata |
| `payload.headers[name=Subject].value` | UNTRUSTED | Sender-written |
| `payload.headers[name=From].value` | UNTRUSTED | Display name is sender-controlled |
| `payload.headers[name=Date].value` | TRUSTED | Set by sending MTA |
| `payload.headers[name=To].value` | TRUSTED | Recipient address |

Note: `payload.headers` is an array of `{name, value}` pairs. Trust depends on which header. This requires either a custom handler or treating the entire headers array as UNTRUSTED (conservative). Phase 1 should treat `snippet` and the full `payload` as UNTRUSTED since we can't do per-header-name dispatch.

### calendar +agenda

Real output shape:
```json
{
  "count": 15,
  "events": [
    {
      "calendar": "Work",
      "end": "2026-04-06T17:00:00+09:00",
      "location": "301-1020",
      "start": "2026-04-06T14:00:00+09:00",
      "summary": "Event title"
    }
  ],
  "timeMax": "2026-04-13T...",
  "timeMin": "2026-04-06T..."
}
```

| Field | Classification | Rationale |
|---|---|---|
| `count` | TRUSTED | Count metadata |
| `timeMin`, `timeMax` | TRUSTED | Query range metadata |
| `events[].calendar` | TRUSTED | Calendar name, set by calendar owner |
| `events[].start`, `events[].end` | TRUSTED | Timestamps set by event creator, but structurally constrained (ISO 8601) |
| `events[].summary` | UNTRUSTED | On shared calendars, other users can create events with arbitrary titles |
| `events[].location` | UNTRUSTED | Freeform text, attacker-settable on shared calendars |

### drive files list

Real output shape:
```json
{
  "files": [
    {
      "id": "...",
      "mimeType": "application/vnd.google-apps.spreadsheet",
      "modifiedTime": "2026-04-06T03:47:16.663Z",
      "name": "File name",
      "owners": [{ "displayName": "...", "emailAddress": "..." }],
      "size": "174271920"
    }
  ],
  "nextPageToken": "..."
}
```

| Field | Classification | Rationale |
|---|---|---|
| `files[].id` | TRUSTED | Drive-generated |
| `files[].mimeType` | TRUSTED | Drive-detected |
| `files[].modifiedTime` | TRUSTED | Drive-generated timestamp |
| `files[].size` | TRUSTED | Drive metadata |
| `files[].name` | UNTRUSTED | File name on shared drives can be set by any collaborator |
| `files[].owners[].displayName` | UNTRUSTED | Google account display name, user-settable |
| `files[].owners[].emailAddress` | TRUSTED | Google-enforced email |
| `nextPageToken` | TRUSTED | Pagination metadata |

## Outbound data spec

| Command | Outbound fields | Resolution |
|---|---|---|
| `gws gmail +send --to X --subject Y --body Z` | `--to`, `--subject`, `--body` | Resolve (outbound to external network) |
| `gws gmail +reply --message-id X --body Y` | `--message-id`, `--body` | Resolve |
| `gws gmail +triage --query Q` | `--query` | Resolve (sent to Gmail search API) |
| `gws calendar +agenda` | no user-data args | N/A |
| `gws drive files list --params '{...}'` | `--params` | Resolve |

## E2E test plan

### Fixture files needed

1. **`exec-gws-triage.json`** - gmail +triage output with BEGIN_SENSITIVE markers on `from` (display name) and `subject`
2. **`exec-gws-message-get.json`** - gmail users messages get (format=metadata) with BEGIN_SENSITIVE markers on `snippet`, Subject header, From display name
3. **`exec-gws-agenda.json`** - calendar +agenda output with BEGIN_SENSITIVE markers on `summary` and `location`
4. **`exec-gws-drive-list.json`** - drive files list output with BEGIN_SENSITIVE markers on file `name` and owner `displayName`

### Test cases

**UT-43: gws gmail triage + summarize**
- Prompt: "Check my unread emails and write a summary to {REPORT}"
- Exercises: gmail +triage inbound data spec, untrusted subjects flowing to report
- Assertions: subject fields symbolized, ids/dates pass through raw, report has resolved content

**UT-44: gws gmail read message**
- Prompt: "List my recent emails, read the first one, summarize it to {REPORT}"
- Exercises: messages list (all TRUSTED) then messages get (snippet UNTRUSTED)
- Assertions: snippet symbolized, message IDs pass through raw

**UT-45: gws calendar agenda summary**
- Prompt: "Show my schedule for this week and write a summary to {REPORT}"
- Exercises: calendar +agenda inbound data spec, untrusted summaries flowing to report
- Assertions: event summaries/locations symbolized, times pass through raw

**UT-46: gws drive file listing**
- Prompt: "List my recent Drive files and write a summary to {REPORT}"
- Exercises: drive files list inbound data spec, untrusted file names flowing to report
- Assertions: file names symbolized, ids/mimeTypes pass through raw

### EXEC_FIXTURES regex patterns

```typescript
"gws gmail \\+triage":          "exec-gws-triage.json",
"gws gmail users messages get": "exec-gws-message-get.json",
"gws calendar \\+agenda":       "exec-gws-agenda.json",
"gws drive files list":         "exec-gws-drive-list.json",
```

Note: existing patterns `"gws gmail users messages list"` and `"gws gmail \\+read"` in test-runners.ts need updating. `+read` doesn't exist in gws. The `messages list` pattern is fine. `+read` should be removed or replaced with `users messages get`.

## Open questions

1. **Per-header dispatch for gmail messages get**: The `payload.headers` array mixes trusted (Date, To) and untrusted (Subject, From display name) values. Options:
   - (a) Treat entire `payload` as UNTRUSTED (conservative, loses metadata access)
   - (b) Custom handler that inspects header names (complex, not supported by current SchemaNode)
   - (c) Phase 1: only support `+triage` helper which flattens headers into top-level fields

2. **Shared calendar trust model**: On personal calendars, all events are self-created (TRUSTED). On shared/public calendars, other users can create events (summary/location become UNTRUSTED). Current approach: conservatively mark summary/location as UNTRUSTED for all calendars.

3. **Existing UT-24 and fixtures**: UT-24 uses `gws gmail users messages list` and `gws gmail +read`. Since `+read` doesn't exist, UT-24 needs updating. The `email-list.json` and `email-body.html` fixtures should be kept for backward compat but the UT-24 test should be reworked.
