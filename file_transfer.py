"""file_transfer.py — backward-compatible shim over core.transfer.session (Phase 38).

FileTransferSession and its supporting names now live in
core/transfer/session.py. This module only re-exports them so legacy
`import file_transfer` call sites keep working; the objects are identical
(`file_transfer.FileTransferSession is core.transfer.session.FileTransferSession`).

It carries no logic and no import-time side effects. New code should import
from core.transfer.session directly.

Caveat for callers that rebind module attributes: assigning to a name on this
shim does not reach core.transfer.session, which is where the session reads
it. Patch the canonical module instead.

`_ERROR_REPORT_CAP` is private; it is re-exported only because an existing
test reads it, and goes away with the test migration.
"""

from core.protocol import ErrorCode
from core.transfer.session import (
    CHUNK_SIZE,
    FileTransferSession,
    IncomingTransfer,
    OnComplete,
    OnOfferReceived,
    OnProgress,
    OutgoingTransfer,
    PathTraversalError,
    _ERROR_REPORT_CAP,
)

__all__ = [
    "CHUNK_SIZE",
    "ErrorCode",
    "FileTransferSession",
    "IncomingTransfer",
    "OnComplete",
    "OnOfferReceived",
    "OnProgress",
    "OutgoingTransfer",
    "PathTraversalError",
]
