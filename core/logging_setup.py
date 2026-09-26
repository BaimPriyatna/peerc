"""core/logging_setup.py — Phase 28.1: Operational logging foundation.

Resolves the "Remaining work" cell of RELIABILITY_DESIGN.md §2: one
application-wide diagnostic logging policy, configured from a single
startup point, with a redacting filter that never trusts every call site
to remember what is safe to record.

This is diagnostics only. It must never:
  - alter security decisions (core.security.events remains the sole
    security-event path; this module does not compete with it);
  - become a second audit store; or
  - render ordinary logs inside the Textual UI (the root ``peerc`` logger
    does not propagate to the library root logger / stderr).

Named loggers rooted at ``peerc`` (module authors use
``logging.getLogger("peerc.<area>")``, e.g. ``peerc.transport``,
``peerc.protocol``, ``peerc.transfer``, ``peerc.vault``, ``peerc.ui``,
``peerc.security``, ``peerc.discovery``) all flow through the single
handler configured here via normal logger-hierarchy propagation — no
per-module handler setup needed.
"""

import logging
import logging.handlers
import os
from pathlib import Path
from typing import Optional

# Structured fields callers may attach via ``extra={...}`` — these are the
# only fields RELIABILITY_DESIGN.md §2.2 lists as safe to record.
ALLOWED_EXTRA_FIELDS = frozenset(
    {
        "device_id_prefix",
        "addr_key",
        "transfer_id",
        "operation",
        "error_code",
        "group_id",
        "peer_id_prefix",
        "event_type",
    }
)

# Field names that must never reach a log record. The filter actively
# strips these rather than trusting every call site to remember —
# chat/file content, key material, passphrases, recovery codes, link
# PINs, decrypted endpoint links, and vault plaintext are all forbidden
# by §2.2, regardless of which module tried to log them.
FORBIDDEN_EXTRA_FIELDS = frozenset(
    {
        "chat_content",
        "message_text",
        "file_content",
        "passphrase",
        "public_key",
        "private_key",
        "session_key",
        "dek",
        "recovery_code",
        "link_pin",
        "pin",
        "endpoint_link",
        "vault_plaintext",
        "plaintext",
        "raw_key",
        "secret",
    }
)

_REDACTED = "[REDACTED]"

# Same dotfolder convention as core/trust/store.py's DEFAULT_DB_PATH and
# core/vault/keyfile.py's DEFAULT_VAULT_DIR — a fixed ~/.peerc, not
# platformdirs/XDG.
DEFAULT_LOG_PATH = os.path.expanduser("~/.peerc/diagnostics.log")

MAX_BYTES = 5 * 1024 * 1024  # 5 MB per file
BACKUP_COUNT = 3  # plus the active file: bounded by size AND count

_ROOT_LOGGER_NAME = "peerc"
_configured_path: Optional[Path] = None


class _RedactingFilter(logging.Filter):
    """Strips forbidden structured fields from every record that reaches
    the root ``peerc`` logger, regardless of which child logger emitted
    it. Installed once at the root so no module needs to opt in."""

    def filter(self, record: logging.LogRecord) -> bool:
        for field_name in FORBIDDEN_EXTRA_FIELDS:
            if hasattr(record, field_name):
                setattr(record, field_name, _REDACTED)
        return True


def default_log_path() -> Path:
    return Path(DEFAULT_LOG_PATH)


def configure_logging(
    *,
    diagnostic_mode: bool = False,
    debug: bool = False,
    log_path: Optional[Path] = None,
) -> Path:
    """Single startup configuration point for the ``peerc`` logger tree.

    Policy (RELIABILITY_DESIGN.md §2.2):
      - Default (``diagnostic_mode=False``, ``debug=False``): ``WARNING``
        and above, written to a rotating local diagnostic file. This is
        the normal interactive-run policy.
      - ``diagnostic_mode=True``: a user-selected diagnostic mode,
        ``INFO`` and above.
      - ``debug=True``: opt-in for a single run, ``DEBUG`` and above. The
        caller is responsible for visibly marking the UI as running in
        diagnostic mode; this function only sets the level and writes one
        marker line to the log itself.

    Idempotent: calling this again (e.g. toggling diagnostic mode
    mid-run) replaces the previously-installed handler rather than
    stacking duplicates or leaking file handles.

    Returns the resolved log file path.
    """
    global _configured_path

    path = Path(log_path) if log_path is not None else default_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger(_ROOT_LOGGER_NAME)

    # Replace only handlers this function previously installed — never
    # touch a handler some other part of the process attached directly
    # (e.g. a test's own capture handler).
    for existing in list(root.handlers):
        if getattr(existing, "_peerc_managed", False):
            root.removeHandler(existing)
            existing.close()

    handler = logging.handlers.RotatingFileHandler(
        path, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8"
    )
    handler._peerc_managed = True  # type: ignore[attr-defined]
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-8s %(name)s %(message)s")
    )
    root.addHandler(handler)

    if not any(isinstance(f, _RedactingFilter) for f in root.filters):
        root.addFilter(_RedactingFilter())

    if debug:
        level = logging.DEBUG
    elif diagnostic_mode:
        level = logging.INFO
    else:
        level = logging.WARNING
    root.setLevel(level)

    # Diagnostics stay out of the Textual UI and out of the default
    # library root logger — this handler is the only sink.
    root.propagate = False

    if debug:
        root.warning("peerc logging: DEBUG diagnostic mode is ON for this run")
    elif diagnostic_mode:
        root.info("peerc logging: diagnostic mode (INFO) is ON for this run")

    _configured_path = path
    return path


def is_configured() -> bool:
    return _configured_path is not None


def current_log_path() -> Optional[Path]:
    return _configured_path
