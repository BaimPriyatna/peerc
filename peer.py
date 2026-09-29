"""peer.py — backward-compatible shim over core.transport.manager (Phase 38).

ConnectionManager and its supporting names now live in
core/transport/manager.py. This module only re-exports them so legacy
`from peer import ConnectionManager` call sites keep working; the objects
are identical (`peer.ConnectionManager is core.transport.manager.ConnectionManager`).

It carries no logic and no import-time side effects. New code should import
from core.transport.manager directly.
"""

from core.transport.manager import (
    CONNECT_TIMEOUT,
    MAX_CONNECTIONS,
    ConnectionLimitError,
    ConnectionManager,
    OnMessage,
)

__all__ = [
    "CONNECT_TIMEOUT",
    "MAX_CONNECTIONS",
    "ConnectionLimitError",
    "ConnectionManager",
    "OnMessage",
]
