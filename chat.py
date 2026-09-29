"""chat.py — backward-compatible shim over core.messaging.session (Phase 38).

ChatSession and its supporting names now live in core/messaging/session.py.
This module only re-exports them so legacy `import chat` call sites keep
working; the objects are identical
(`chat.ChatSession is core.messaging.session.ChatSession`).

It carries no logic and no import-time side effects. New code should import
from core.messaging.session directly.

Caveat for callers that rebind module attributes: assigning to a name on this
shim (e.g. `chat.ACK_TIMEOUT = 0.5`) does not reach core.messaging.session,
which is where ChatSession actually reads it. Set it on the canonical module.
"""

from core.messaging.session import (
    ACK_TIMEOUT,
    ChatSession,
    OnChatReceived,
    OnStatusChange,
    SentMessageState,
)

__all__ = [
    "ACK_TIMEOUT",
    "ChatSession",
    "OnChatReceived",
    "OnStatusChange",
    "SentMessageState",
]
