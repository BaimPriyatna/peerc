"""core.messaging — chat session logic (Phase 38).

    session.py  ChatSession: chat sending, delivery acknowledgment state, and
                ack timeouts, layered on a ConnectionManager

Import from core.messaging.session directly. The root-level chat.py is a
backward-compatible shim that re-exports its public names.
"""
