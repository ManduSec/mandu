"""
stack — boot/teardown of the REAL Mandu defense stack (arbiter + anthropic-proxy)
for the AgentDojo eval, plus a self-signed cert minter for the offline mock.

Mirrors the boot pattern in eval/lib/run-live.ts (bootStack): spawn the arbiter
daemon on a temp unix socket, spawn the anthropic-proxy pointed at an upstream
(the mock in smoke mode, api.anthropic.com in real mode), and hand back the proxy
base URL for AgentDojo's ANTHROPIC_BASE_URL. The arbiter loads the AgentDojo trust
spec via MANDU_INBOUND_SPEC (docs/design/testing/evaluation.md §2.4-5).
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ARBITER_DIR = os.path.join(REPO_ROOT, "arbiter")
ARBITER_TSX = os.path.join(ARBITER_DIR, "node_modules", ".bin", "tsx")
ARBITER_MAIN = os.path.join(ARBITER_DIR, "ipc", "server-main.ts")
PROXY_DIR = os.path.join(REPO_ROOT, "interceptors", "anthropic-proxy")
PROXY_TSX = os.path.join(PROXY_DIR, "node_modules", ".bin", "tsx")
PROXY_MAIN = os.path.join(PROXY_DIR, "src", "server-main.ts")


class DepsMissing(RuntimeError):
    """The Node stack isn't installed — the caller SKIPs cleanly (exit 0)."""


def deps_available() -> str | None:
    """Return a skip-reason string if a required dependency is absent, else None."""
    if not os.path.exists(ARBITER_TSX):
        return "arbiter tsx missing — run 'cd arbiter && npm install'"
    if not os.path.exists(PROXY_TSX):
        return "anthropic-proxy tsx missing — run 'cd interceptors/anthropic-proxy && npm install'"
    if not _which("openssl"):
        return "openssl not on PATH (needed to mint the mock upstream's TLS cert)"
    return None


def _which(name: str) -> str | None:
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def free_port(host: str = "127.0.0.1") -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_for_socket(path: str, tries: int = 100) -> bool:
    for _ in range(tries):
        if os.path.exists(path):
            return True
        time.sleep(0.1)
    return False


def _wait_for_port(host: str, port: int, tries: int = 100) -> bool:
    for _ in range(tries):
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def mint_self_signed_cert(tmp: str) -> tuple[str, str]:
    """Mint a throwaway self-signed cert/key into tmp; return (cert, key) paths."""
    cert = os.path.join(tmp, "mock-cert.pem")
    key = os.path.join(tmp, "mock-key.pem")
    r = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
         "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=mandu-agentdojo-mock"],
        capture_output=True, text=True, timeout=30,
    )
    if r.returncode != 0:
        raise RuntimeError(f"openssl could not mint a cert: {r.stderr or r.stdout}")
    return cert, key


@dataclass
class Stack:
    proxy_base_url: str
    arbiter_sock: str
    _procs: list[subprocess.Popen]

    def dispose(self) -> None:
        for p in self._procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in self._procs:
            try:
                p.wait(timeout=5)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass


@contextmanager
def defense_stack(tmp: str, upstream_origin: str, inbound_spec: str, fake_upstream: bool):
    """
    Boot arbiter + anthropic-proxy; yield a Stack. `upstream_origin` is where the
    proxy forwards (the mock in smoke mode, https://api.anthropic.com in real
    mode). `inbound_spec` selects the arbiter's trust ruleset (agentdojo /
    fail-closed / claude-code). `fake_upstream` makes the proxy accept the mock's
    self-signed cert (NODE_TLS_REJECT_UNAUTHORIZED=0).
    """
    skip = deps_available()
    if skip is not None:
        raise DepsMissing(skip)

    procs: list[subprocess.Popen] = []
    arbiter_sock = os.path.join(tmp, "arbiter.sock")
    # A throwaway Mandu home: the arbiter's symbol DB and events live in it.
    mandu_home = os.path.join(tmp, "mandu-home")
    os.makedirs(mandu_home, exist_ok=True)

    try:
        arbiter_env = {
            **os.environ,
            "MANDU_ARBITER_SOCK": arbiter_sock,
            "MANDU_HOME": mandu_home,
            # A pinned arbiter registers an instance dir: keep it in this tmp tree.
            "MANDU_RUNTIME_DIR": os.path.join(tmp, "mandu-runtime"),
            "MANDU_INBOUND_SPEC": inbound_spec,
        }
        procs.append(subprocess.Popen(
            [ARBITER_TSX, ARBITER_MAIN, arbiter_sock],
            env=arbiter_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        ))
        if not _wait_for_socket(arbiter_sock):
            raise RuntimeError("arbiter daemon failed to start (no socket)")

        proxy_port = free_port()
        proxy_env = {
            **os.environ,
            "MANDU_ARBITER_SOCK": arbiter_sock,
            "MANDU_HOME": mandu_home,
            "MANDU_UPSTREAM": upstream_origin,
            "MANDU_PROXY_PORT": str(proxy_port),
            "MANDU_PROXY_HOST": "127.0.0.1",
        }
        if fake_upstream:
            proxy_env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
        procs.append(subprocess.Popen(
            [PROXY_TSX, PROXY_MAIN],
            env=proxy_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        ))
        if not _wait_for_port("127.0.0.1", proxy_port):
            raise RuntimeError(f"anthropic-proxy failed to start on 127.0.0.1:{proxy_port}")

        yield Stack(
            proxy_base_url=f"http://127.0.0.1:{proxy_port}",
            arbiter_sock=arbiter_sock,
            _procs=procs,
        )
    finally:
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in procs:
            try:
                p.wait(timeout=5)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
