"""tests/test_logging_setup.py — Phase 28.1: Operational logging foundation.

Tests covering:
- Rotating file handler is created at the configured path
- Default policy is WARNING+ (INFO/DEBUG suppressed)
- diagnostic_mode=True raises the level to INFO
- debug=True raises the level to DEBUG and writes a visible marker line
- Forbidden structured fields (passphrase, private_key, ...) are redacted
  from any record that carries them, even via `extra=`
- Allowed structured fields pass through unredacted
- Idempotent re-configuration replaces rather than stacks handlers
- root `peerc` logger does not propagate to the library root logger
- discovery.py's logger is rooted under `peerc` (part of the tree)
"""

import logging
import logging.handlers

import pytest

from core.logging_setup import (
    FORBIDDEN_EXTRA_FIELDS,
    configure_logging,
    current_log_path,
    is_configured,
)


@pytest.fixture(autouse=True)
def _reset_peerc_logger():
    """Each test gets a clean `peerc` root logger: no leftover managed
    handlers/filters from a previous test, and state restored after."""
    root = logging.getLogger("peerc")
    saved_handlers = list(root.handlers)
    saved_filters = list(root.filters)
    saved_level = root.level
    saved_propagate = root.propagate

    for h in list(root.handlers):
        if getattr(h, "_peerc_managed", False):
            root.removeHandler(h)
            h.close()

    yield

    for h in list(root.handlers):
        if getattr(h, "_peerc_managed", False):
            root.removeHandler(h)
            h.close()
    root.handlers = saved_handlers
    root.filters = saved_filters
    root.level = saved_level
    root.propagate = saved_propagate

    import core.logging_setup as mod
    mod._configured_path = None


def _read_log(path) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def test_creates_rotating_file_at_configured_path(tmp_path):
    log_path = tmp_path / "diag.log"
    resolved = configure_logging(log_path=log_path)

    assert resolved == log_path
    assert log_path.parent.exists()
    assert is_configured()
    assert current_log_path() == log_path

    root = logging.getLogger("peerc")
    managed = [h for h in root.handlers if getattr(h, "_peerc_managed", False)]
    assert len(managed) == 1
    assert isinstance(managed[0], logging.handlers.RotatingFileHandler)


def test_default_level_is_warning(tmp_path):
    log_path = tmp_path / "diag.log"
    configure_logging(log_path=log_path)

    logger = logging.getLogger("peerc.transport")
    logger.info("info message should not appear")
    logger.warning("warning message should appear")
    for h in logging.getLogger("peerc").handlers:
        h.flush()

    content = _read_log(log_path)
    assert "warning message should appear" in content
    assert "info message should not appear" not in content


def test_diagnostic_mode_raises_to_info(tmp_path):
    log_path = tmp_path / "diag.log"
    configure_logging(diagnostic_mode=True, log_path=log_path)

    logger = logging.getLogger("peerc.transfer")
    logger.info("info message should now appear")
    logger.debug("debug message should still be suppressed")
    for h in logging.getLogger("peerc").handlers:
        h.flush()

    content = _read_log(log_path)
    assert "info message should now appear" in content
    assert "debug message should still be suppressed" not in content
    # Visible marker for the diagnostic mode itself
    assert "diagnostic mode (INFO) is ON" in content


def test_debug_mode_raises_to_debug_with_marker(tmp_path):
    log_path = tmp_path / "diag.log"
    configure_logging(debug=True, log_path=log_path)

    logger = logging.getLogger("peerc.vault")
    logger.debug("debug message should appear now")
    for h in logging.getLogger("peerc").handlers:
        h.flush()

    content = _read_log(log_path)
    assert "debug message should appear now" in content
    assert "DEBUG diagnostic mode is ON" in content


def test_forbidden_extra_fields_redacted(tmp_path):
    log_path = tmp_path / "diag.log"
    configure_logging(diagnostic_mode=True, log_path=log_path)

    logger = logging.getLogger("peerc.ui")
    logger.info(
        "device connected",
        extra={"passphrase": "super-secret-value", "device_id_prefix": "abcd1234"},
    )
    for h in logging.getLogger("peerc").handlers:
        h.flush()

    content = _read_log(log_path)
    assert "super-secret-value" not in content

    # Confirm the filter actually redacts every forbidden field name, not
    # just the one exercised above.
    root = logging.getLogger("peerc")
    record = logging.LogRecord(
        name="peerc.transfer", level=logging.INFO, pathname=__file__, lineno=1,
        msg="test", args=(), exc_info=None,
    )
    for field_name in FORBIDDEN_EXTRA_FIELDS:
        setattr(record, field_name, "sensitive-value")
    for f in root.filters:
        f.filter(record)
    for field_name in FORBIDDEN_EXTRA_FIELDS:
        assert getattr(record, field_name) == "[REDACTED]"


def test_allowed_extra_fields_pass_through(tmp_path):
    log_path = tmp_path / "diag.log"
    configure_logging(diagnostic_mode=True, log_path=log_path)

    root = logging.getLogger("peerc")
    record = logging.LogRecord(
        name="peerc.transfer", level=logging.INFO, pathname=__file__, lineno=1,
        msg="test", args=(), exc_info=None,
    )
    record.transfer_id = "xfer-123"
    record.error_code = "TRANSFER_NOT_FOUND"
    for f in root.filters:
        f.filter(record)
    assert record.transfer_id == "xfer-123"
    assert record.error_code == "TRANSFER_NOT_FOUND"


def test_idempotent_reconfiguration_does_not_stack_handlers(tmp_path):
    log_path = tmp_path / "diag.log"
    configure_logging(log_path=log_path)
    configure_logging(diagnostic_mode=True, log_path=log_path)
    configure_logging(debug=True, log_path=log_path)

    root = logging.getLogger("peerc")
    managed = [h for h in root.handlers if getattr(h, "_peerc_managed", False)]
    assert len(managed) == 1
    assert root.level == logging.DEBUG

    redacting_filters = [
        f for f in root.filters
        if f.__class__.__name__ == "_RedactingFilter"
    ]
    assert len(redacting_filters) == 1


def test_root_logger_does_not_propagate(tmp_path):
    log_path = tmp_path / "diag.log"
    configure_logging(log_path=log_path)

    root = logging.getLogger("peerc")
    assert root.propagate is False


def test_discovery_logger_is_rooted_under_peerc():
    import discovery
    assert discovery._log.name == "peerc.discovery"
