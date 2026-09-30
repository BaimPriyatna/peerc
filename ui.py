"""ui.py — backward-compatible shim over the app package (Phase 38).

The terminal UI now lives in app/:

    app/ui/app.py                 ChatApp
    app/ui/modals/*.py            identity/trust, vault, transfer, and link modals
    app/ui/widgets/rich_log.py    SelectableRichLog and the clipboard helper
    app/config.py                 UI port and presentation/orchestration timeouts
    app/main.py                   main(), the console-script entry point

This module only re-exports the legacy public UI API so `import ui` /
`from ui import ChatApp, main` keep working; the objects are identical to the
canonical ones. It carries no logic and no import-time side effects; the
`__main__` guard only preserves the documented `python3 ui.py` launch. New
code should import from app.* directly.

Caveat for callers that rebind module attributes: assigning to a name on this
shim does not reach the canonical modules that read it.

`_group_security_events` and `_parse_endpoint_line` are private; they are
re-exported only because existing tests import them, and go away with the
test migration.
"""

from app.config import (
    AUTO_LOCK_POLL_SECONDS,
    IP_CHANGE_CHECK_INTERVAL,
    RELAY_CANDIDATE_WINDOW,
    RELAY_DIRECT_TIMEOUT,
    RELAY_RESPONSE_TIMEOUT,
    UI_TCP_PORT,
)
from app.main import main
from app.ui.app import ChatApp
from app.ui.modals.identity import (
    NameSetupModal,
    SecurityEventsModal,
    TrustCenterModal,
    TrustConfirmModal,
    TrustDeviceDetailModal,
    TrustPromptModal,
    _group_security_events,
    validate_display_name,
)
from app.ui.modals.link import (
    LinkAddModal,
    LinkGenerateModal,
    LinkMenuModal,
    LinkResultModal,
    _parse_endpoint_line,
)
from app.ui.modals.transfer import FileOfferModal
from app.ui.modals.vault import (
    CriticalActionKeyModal,
    VaultCreateModal,
    VaultRecoveryCodeModal,
    VaultUnlockModal,
)
from app.ui.widgets.rich_log import (
    SelectableRichLog,
    apply_selection_to_strip,
    copy_to_system_clipboard,
)

__all__ = [
    "AUTO_LOCK_POLL_SECONDS",
    "ChatApp",
    "CriticalActionKeyModal",
    "FileOfferModal",
    "IP_CHANGE_CHECK_INTERVAL",
    "LinkAddModal",
    "LinkGenerateModal",
    "LinkMenuModal",
    "LinkResultModal",
    "NameSetupModal",
    "RELAY_CANDIDATE_WINDOW",
    "RELAY_DIRECT_TIMEOUT",
    "RELAY_RESPONSE_TIMEOUT",
    "SecurityEventsModal",
    "SelectableRichLog",
    "TrustCenterModal",
    "TrustConfirmModal",
    "TrustDeviceDetailModal",
    "TrustPromptModal",
    "UI_TCP_PORT",
    "VaultCreateModal",
    "VaultRecoveryCodeModal",
    "VaultUnlockModal",
    "apply_selection_to_strip",
    "copy_to_system_clipboard",
    "main",
    "validate_display_name",
]

if __name__ == "__main__":
    main()
