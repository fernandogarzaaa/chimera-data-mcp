"""Client-safe error contract for MCP tool responses."""

from __future__ import annotations


class ClientSafeError(ValueError):
    """A deliberate, human-written error whose message is safe to show MCP clients.

    Raise for validation/policy rejections (mutation attempts, unsafe code).
    Unexpected exceptions must never have their raw messages sent to clients:
    they are logged server-side and replaced with a generic message, since a
    message can embed server filesystem paths just as a traceback can.
    """
