# mandu-arbiter (Python)

A stdlib-only Python client for the Mandu arbiter: one JSON object per
line over the arbiter's Unix socket (`arbiter/ipc/protocol.ts`), matched by
request id. Like the TypeScript client, a call that does not answer in time
raises `ArbiterTimeout`: callers must fail closed on it.

```python
from mandu_arbiter import ArbiterClient

with ArbiterClient() as c:                # MANDU_ARBITER_SOCK, or pass the path
    c.hello()                             # identity and axes
    c.symbolize("WebFetch", page_text, origin="https://example.com/")
    c.why_path("/home/me/.pgpass")        # the law's view of a file
    c.desymbolization_decision("$MDU:...", "api.example.com")
    c.request("anyOp", arg=1)             # every other op
```

Tests: `cd clients/python && python3 -m unittest discover -s tests` (a fake
arbiter for the protocol and the fail-closed timeout; a real arbiter from
this checkout for the typed helpers, skipped without Node).
