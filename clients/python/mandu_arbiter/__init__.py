"""mandu_arbiter: a Python client for the Mandu arbiter (comparisons.md §3.12).

The arbiter speaks one JSON object per line over a Unix socket
(arbiter/ipc/protocol.ts). This client mirrors the TypeScript ArbiterClient's
contract where it matters for security: a call that does not answer in time
RAISES (fail closed), it never returns a default.
"""
from .client import ArbiterClient, ArbiterError, ArbiterTimeout

__all__ = ["ArbiterClient", "ArbiterError", "ArbiterTimeout"]
__version__ = "0.1.0"
