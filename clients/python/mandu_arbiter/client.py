"""The arbiter's NDJSON-over-Unix-socket protocol, in Python (stdlib only).

Framing (arbiter/ipc/client.ts): each request is ``{"id": n, "op": ..., **args}``
plus a newline; each response is ``{"id": n, "ok": true, "result": ...}`` or
``{"id": n, "ok": false, "error": "..."}``. One connection, requests answered
in any order and matched by id. Not thread-safe: use one client per thread.
"""
from __future__ import annotations

import json
import os
import socket
import time
from typing import Any, Dict, List, Optional


DEFAULT_TIMEOUT_S = 5.0


class ArbiterError(Exception):
    """The arbiter answered ok:false, or the connection failed."""


class ArbiterTimeout(ArbiterError):
    """No answer within the deadline. Callers must fail closed on this."""


class ArbiterClient:
    """A connection to one arbiter socket.

    >>> with ArbiterClient("/run/user/1000/mandu/current/arbiter.sock") as c:
    ...     c.ping()
    """

    def __init__(self, socket_path: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT_S) -> None:
        path = socket_path or os.environ.get("MANDU_ARBITER_SOCK")
        if not path:
            raise ArbiterError("no arbiter socket: pass socket_path or set MANDU_ARBITER_SOCK")
        self.socket_path = path
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._buf = b""
        self._next_id = 1
        self._stash: Dict[int, Dict[str, Any]] = {}

    # ── connection ──────────────────────────────────────────────────────────
    def connect(self) -> "ArbiterClient":
        if self._sock is None:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            try:
                s.connect(self.socket_path)
            except OSError as e:
                s.close()
                raise ArbiterError(f"arbiter unreachable at {self.socket_path}: {e}") from e
            self._sock = s
        return self

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
                self._buf = b""

    def __enter__(self) -> "ArbiterClient":
        return self.connect()

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ── the one primitive ───────────────────────────────────────────────────
    def request(self, op: str, timeout: Optional[float] = None, **args: Any) -> Any:
        """Send one op and return its ``result``. Raises ArbiterError on
        ``ok:false`` and ArbiterTimeout when no answer arrives in time."""
        self.connect()
        assert self._sock is not None
        rid = self._next_id
        self._next_id += 1
        payload = json.dumps({"id": rid, "op": op, **args}, separators=(",", ":")) + "\n"
        deadline = time.monotonic() + (timeout if timeout is not None else self.timeout)
        try:
            self._sock.sendall(payload.encode("utf-8"))
        except OSError as e:
            self.close()
            raise ArbiterError(f"arbiter {op}: send failed ({e})") from e
        while rid not in self._stash:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ArbiterTimeout(f"arbiter {op} timed out: fail closed")
            self._read_one(remaining, op)
        msg = self._stash.pop(rid)
        if not msg.get("ok"):
            raise ArbiterError(f"arbiter {op}: {msg.get('error', 'error')}")
        return msg.get("result")

    def _read_one(self, remaining: float, op: str) -> None:
        assert self._sock is not None
        while b"\n" not in self._buf:
            self._sock.settimeout(remaining)
            try:
                chunk = self._sock.recv(65536)
            except socket.timeout as e:
                raise ArbiterTimeout(f"arbiter {op} timed out: fail closed") from e
            except OSError as e:
                self.close()
                raise ArbiterError(f"arbiter {op}: receive failed ({e})") from e
            if not chunk:
                self.close()
                raise ArbiterError(f"arbiter {op}: connection closed")
            self._buf += chunk
        line, _, self._buf = self._buf.partition(b"\n")
        if not line.strip():
            return
        msg = json.loads(line)
        if isinstance(msg, dict) and isinstance(msg.get("id"), int):
            self._stash[msg["id"]] = msg

    # ── typed helpers (the ops an eval or a tool most often needs) ──────────
    def ping(self) -> Any:
        return self.request("ping")

    def hello(self) -> Dict[str, Any]:
        """Identity and axes of the arbiter (confidentiality / integrity)."""
        return self.request("hello")

    def symbolize(self, tool: str, value: str, **extra: Any) -> Any:
        """Classify + symbolize one tool output field (untrusted → a $MDU: symbol)."""
        return self.request("symbolize", tool=tool, value=value, **extra)

    def desymbolization_decision(self, symbol: str, destination: Optional[str] = None, boundary: str = "network") -> Dict[str, Any]:
        """Would the egress gate release this symbol at ``destination``?"""
        req: Dict[str, Any] = {"symbol": symbol, "boundary": boundary}
        if destination:
            req["destination"] = destination
        return self.request("desymbolizationDecision", request=req)

    def why_path(self, path: str, home: Optional[str] = None) -> Dict[str, Any]:
        """``mandu why <path>``: level, deciding rule, readers, bindings."""
        return self.request("whyPath", path=path, **({"home": home} if home else {}))

    def why_host(self, host: str) -> Dict[str, Any]:
        """``mandu why <host>``: bound secrets and the release decisions."""
        return self.request("whyHost", host=host)

    def emit(self, event: Dict[str, Any]) -> Any:
        """Append one observability event (best effort for callers)."""
        return self.request("emit", event=event)

    def events(self, session_id: str, since_seq: int = 0) -> List[Dict[str, Any]]:
        return self.request("events", sessionId=session_id, sinceSeq=since_seq)["events"]

    def verify_events(self, session_id: str) -> Dict[str, Any]:
        """A session log's hash chain: ``{"ok": ..., "brokenAt": seq?, "head": ...}``."""
        return self.request("verifyEvents", sessionId=session_id)
