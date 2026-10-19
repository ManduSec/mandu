"""
mock_upstream — a scripted HTTPS Anthropic Messages endpoint for the OFFLINE
AgentDojo invariant smoke (no API key, no network).

WHAT / WHY (docs/design/testing/evaluation.md §2.5):
  The anthropic-proxy forwards to its MANDU_UPSTREAM over HTTPS only. In the
  offline smoke we stand a self-signed HTTPS server in for api.anthropic.com so a
  REAL AgentDojo pipeline runs with no key. The mock SCRIPTS the agent:

    request 1 (no tool_result yet) → respond with a tool_use that calls the
        untrusted tool which surfaces the injected webpage (slack get_webpage).
    request 2 (carries the tool_result) → the proxy has ALREADY symbolized that
        untrusted tool_result before it reached us, so we CAPTURE the request
        body (the invariant is asserted against it) and end the turn with a final
        text message so AgentDojo's loop terminates.

  Every request body is captured (`captured`) so the smoke can assert the
  injection payload arrived ONLY as a $MDU:* token.

SSE shape is ported from eval/lib/run-live.ts's fake-anthropic turns (which drive
the real `claude` binary), so it matches what the anthropic SDK's streaming parser
(`client.messages.stream()` in AgentDojo) expects.
"""

from __future__ import annotations

import json
import ssl
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _sse(events: list[tuple[str, dict]]) -> bytes:
    out = []
    for event, data in events:
        out.append(f"event: {event}\ndata: {json.dumps(data)}\n\n")
    return "".join(out).encode("utf-8")


def _text_turn(text: str) -> list[tuple[str, dict]]:
    return [
        ("message_start", {"type": "message_start", "message": {"id": "msg_mdu_text", "type": "message", "role": "assistant", "model": "claude-mdu-mock", "content": [], "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 1}}}),
        ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 1}}),
        ("message_stop", {"type": "message_stop"}),
    ]


def _tool_turn(tool_id: str, name: str, tool_input: dict) -> list[tuple[str, dict]]:
    return [
        ("message_start", {"type": "message_start", "message": {"id": "msg_mdu_tool", "type": "message", "role": "assistant", "model": "claude-mdu-mock", "content": [], "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 1}}}),
        ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": tool_id, "name": name, "input": {}}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": json.dumps(tool_input)}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None}, "usage": {"output_tokens": 1}}),
        ("message_stop", {"type": "message_stop"}),
    ]


@dataclass
class Script:
    """One tool call to script on the first turn (then finish)."""
    tool_name: str
    tool_input: dict
    final_text: str = "MDU_AGENTDOJO_SMOKE_DONE"


@dataclass
class MockUpstream:
    host: str
    port: int
    captured: list[str] = field(default_factory=list)
    _server: ThreadingHTTPServer | None = None
    _thread: threading.Thread | None = None

    @property
    def origin(self) -> str:
        return f"https://{self.host}:{self.port}"

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)


def start_mock_upstream(cert_file: str, key_file: str, script: Script, host: str = "127.0.0.1") -> MockUpstream:
    mock = MockUpstream(host=host, port=0)
    tool_issued = {"done": False}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # silence
            pass

        def _read_body(self) -> str:
            length = int(self.headers.get("content-length", 0))
            return self.rfile.read(length).decode("utf-8", "replace") if length else ""

        def do_POST(self):
            body = self._read_body()
            mock.captured.append(body)
            url = self.path or ""
            if "count_tokens" in url:
                payload = json.dumps({"input_tokens": 10}).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if "/v1/messages" in url or "messages" in url:
                has_tool_result = '"tool_result"' in body
                if has_tool_result or tool_issued["done"]:
                    events = _text_turn(script.final_text)
                else:
                    tool_issued["done"] = True
                    events = _tool_turn("toolu_mdu_smoke_1", script.tool_name, script.tool_input)
                data = _sse(events)
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("cache-control", "no-cache")
                self.end_headers()
                self.wfile.write(data)
                return
            # anything else → empty JSON
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

    server = ThreadingHTTPServer((host, 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    mock.port = server.server_address[1]
    mock._server = server
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    mock._thread = t
    return mock
