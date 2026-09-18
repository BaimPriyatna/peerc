"""
ui.py — terminal UI tying discovery, chat, and file_transfer together.

Layout:
    +------------------+------------------------------+
    | Peers (online)   |  Chat log (active peer)       |
    |                  |                               |
    +------------------+------------------------------+
    | > input box (type text, or /send <path>, /help)  |
    +--------------------------------------------------+

Commands typed into the input box:
    /help                           show available commands and shortcuts
    /connect <ip>[:port]            connect directly to peer (hotspot / AP isolation fix)
    /peers                          list all discovered peers and status
    /msg <peer-name-or-id-prefix>   switch active chat target
    /send <filepath>                offer a file to the active peer
    /name <new-name>                change display name and re-announce
    /copy [last|all]                copy chat to system clipboard
    /clear                          clear chat log
    /info or /me                    show local identity and network details
    /lock                           lock the vault now (re-prompt for passphrase)
    /autolock [minutes]             show or set idle auto-lock timeout (default 5)
    /criticalkey [status|set|change|clear]
                                    manage optional extra key for Export
    /quit or /exit                  quit peerc

Cursor & Mouse:
    - Click and drag text in the chat log to select/block text.
    - Press Ctrl+C or Ctrl+Shift+C to copy selected text to clipboard.
    - Ctrl+Q quits immediately.
    - Click any peer in the sidebar list to switch conversation target.
"""

import asyncio
import base64
import os
import secrets
import shutil
import subprocess
import time
from typing import Optional
import uuid

from rich.markup import escape as rich_escape
from rich.style import Style
from textual import events, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.selection import Selection
from textual.strip import Strip
from textual.widgets import Button, Footer, Header, Input, Label, ListItem, ListView, RichLog

import chat
from core.security.events import SecuritySeverity
from core.events import (
    EventBus,
    NetworkMessageReceived,
    SecurityWarning,
    TrustRequired,
    bridge_security_events,
)
import core.identity as identity
import discovery
from core.device_info import detect_device_model
import file_transfer
import protocol
from core.trust.store import DEFAULT_DB_PATH as TRUST_DB_LEGACY_PATH
from core.trust.store import TrustStore
from core.group import (
    AdminStatus,
    DEFAULT_CAPABILITY_TTL,
    ExportCapability,
    ExportRequest,
    Group,
    GroupPolicy,
    GroupStore,
    MembershipCertificate,
    MembershipStatus,
    PolicyEnforcer,
    create_export_request,
    create_group,
    issue_export_capability,
    issue_membership_certificate,
    verify_export_capability,
    verify_export_request,
    verify_group_audit_event,
)
from core.group.protocol import (
    GroupJoinRequest,
    GroupJoinResponse,
    GroupLeaveRequest,
    GroupLeaveResponse,
    MembershipRevocation,
    create_join_request,
    create_join_response,
    create_leave_request,
    create_leave_response,
    create_membership_revocation,
    verify_join_request,
    verify_join_response,
    verify_leave_request,
    verify_leave_response,
    verify_membership_revocation,
)
from core.identity.device_identity import compute_device_id
from core.vault import (
    DEFAULT_AUTO_LOCK_SECONDS,
    RecoveryCodeError,
    VaultDatabase,
    VaultExistsError,
    VaultPersistence,
    VaultSession,
    WeakPassphraseError,
    WrongSecretError,
    create_vault,
    load_vault_keyfile,
    migrate_plaintext_trust_db,
    save_vault_keyfile,
    unlock_with_passphrase,
    unlock_with_recovery_code,
    vault_exists,
)
from peer import ConnectionManager

UI_TCP_PORT = 5656
AUTO_LOCK_POLL_SECONDS = 1.0


def apply_selection_to_strip(strip: Strip, start: int, end: int, style: Style) -> Strip:
    """Apply a visual highlight style to a span within a Textual Strip."""
    cell_len = strip.cell_length
    if cell_len == 0:
        return strip
    if end == -1 or end > cell_len:
        end = cell_len
    start = max(0, min(start, cell_len))
    end = max(0, min(end, cell_len))
    if start >= end:
        return strip

    cuts = []
    if start > 0:
        cuts.append(start)
    cuts.append(end)
    if end < cell_len:
        cuts.append(cell_len)

    parts = list(strip.divide(cuts))
    styled_parts = []
    idx = 0
    if start > 0:
        styled_parts.append(parts[idx])
        idx += 1
    styled_parts.append(parts[idx].apply_style(style))
    idx += 1
    if end < cell_len:
        styled_parts.append(parts[idx])
    return Strip.join(styled_parts)


class SelectableRichLog(RichLog):
    """RichLog with native mouse text selection and cursor offset tracking."""

    ALLOW_SELECT = True

    def get_selection(self, selection: Selection) -> tuple[str, str] | None:
        """Extract plain text lines under the user's mouse selection."""
        text = "\n".join(strip.text.rstrip() for strip in self.lines)
        return selection.extract(text), "\n"

    def render_line(self, y: int) -> Strip:
        """Render line with selection highlighting and character offset metadata."""
        scroll_x, scroll_y = self.scroll_offset
        line_idx = scroll_y + y
        width = self.scrollable_content_region.width

        if line_idx >= len(self.lines):
            return Strip.blank(width, self.rich_style)

        base_strip = self.lines[line_idx]

        selection = self.text_selection
        if selection is not None:
            span = selection.get_span(line_idx)
            if span is not None:
                start, end = span
                try:
                    sel_style = self.screen.get_component_rich_style("screen--selection")
                except Exception:
                    sel_style = None
                if not sel_style or (not sel_style.bgcolor and not sel_style.reverse):
                    sel_style = Style(reverse=True)
                base_strip = apply_selection_to_strip(base_strip, start, end, sel_style)

        line = base_strip.crop_extend(scroll_x, scroll_x + width, self.rich_style)
        line = line.apply_offsets(scroll_x, line_idx)
        return line.apply_style(self.rich_style)


def copy_to_system_clipboard(text: str) -> None:
    """Copy text to system clipboard using Wayland or X11 tools if available."""
    if shutil.which("wl-copy"):
        try:
            proc = subprocess.Popen(["wl-copy"], stdin=subprocess.PIPE)
            proc.communicate(input=text.encode("utf-8"), timeout=0.5)
            return
        except Exception:
            pass
    if shutil.which("xclip"):
        try:
            proc = subprocess.Popen(["xclip", "-selection", "clipboard"], stdin=subprocess.PIPE)
            proc.communicate(input=text.encode("utf-8"), timeout=0.5)
            return
        except Exception:
            pass
    if shutil.which("xsel"):
        try:
            proc = subprocess.Popen(["xsel", "-b", "-i"], stdin=subprocess.PIPE)
            proc.communicate(input=text.encode("utf-8"), timeout=0.5)
            return
        except Exception:
            pass


def validate_display_name(name: str) -> tuple[bool, str]:
    """Shared by NameSetupModal (first run) and the /name command
    (BUG-020: no control characters/newlines, max 32 chars — nickname
    used to be accepted verbatim and broadcast to every peer on the LAN
    as-is)."""
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in name):
        return False, "Name cannot contain control characters or newlines."
    if len(name) > 32:
        return False, "Name too long (max 32 characters)."
    return True, ""


class NameSetupModal(ModalScreen[str]):
    """First-run only: pick a display name before the app proceeds.

    Not security-relevant (same as /name later) — just avoids everyone's
    very first session silently showing up as "peer" to other peers.
    Leaving it blank keeps the "peer" default, same as never running
    /name at all. Validation mirrors the /name command's rules
    (BUG-020: no control characters/newlines, max 32 chars).
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="vault-dialog"):
            yield Label("👋 Welcome to peerc")
            yield Label("What name should other peers see you as? (you can change this later with /name)")
            yield Label("", id="name-error")
            yield Input(placeholder="peer", id="display-name")
            yield Button("Continue", id="continue-name", variant="success")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "continue-name":
            self._submit()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._submit()

    def _submit(self) -> None:
        value = self.query_one("#display-name", Input).value.strip()
        error_label = self.query_one("#name-error", Label)
        if not value:
            self.dismiss("")  # keep the "peer" default
            return
        ok, error = validate_display_name(value)
        if not ok:
            error_label.update(error)
            return
        self.dismiss(value)


class VaultCreateModal(ModalScreen[str]):
    """First-run only: choose a passphrase for the local vault. Validates
    locally (match + minimum length) before ever dismissing — no need
    for the caller to loop on this one, unlike VaultUnlockModal below."""

    def __init__(self):
        super().__init__()
        self.error = ""

    def compose(self) -> ComposeResult:
        with Vertical(id="vault-dialog"):
            yield Label("🔐 Create your peerc vault")
            yield Label(
                "Choose a passphrase to protect your messages and files stored "
                "locally on this device (at least 8 characters)."
            )
            yield Label("", id="vault-error")
            yield Input(placeholder="Passphrase", password=True, id="pw1")
            yield Input(placeholder="Confirm passphrase", password=True, id="pw2")
            yield Button("Create Vault", id="create", variant="success")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "create":
            self._submit()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._submit()

    def _submit(self) -> None:
        pw1 = self.query_one("#pw1", Input).value
        pw2 = self.query_one("#pw2", Input).value
        error_label = self.query_one("#vault-error", Label)
        if pw1 != pw2:
            error_label.update("Passphrases don't match.")
            return
        if len(pw1) < 8:
            error_label.update("Passphrase must be at least 8 characters.")
            return
        self.dismiss(pw1)


class VaultRecoveryCodeModal(ModalScreen[bool]):
    """Shown exactly once, right after vault creation. The recovery code
    is never shown again after this — losing both the passphrase and
    this code means the vault's contents are unrecoverable."""

    def __init__(self, recovery_code: str):
        super().__init__()
        self.recovery_code = recovery_code

    def compose(self) -> ComposeResult:
        with Vertical(id="vault-dialog"):
            yield Label("⚠️  Save your recovery code")
            yield Label(
                "This is the only way back into your vault if you forget your "
                "passphrase. It will not be shown again — write it down somewhere safe."
            )
            yield Label(self.recovery_code, id="recovery-code-text")
            yield Button("I've saved it — Continue", id="continue", variant="warning")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "continue":
            self.dismiss(True)


class VaultUnlockModal(ModalScreen[tuple[str, str]]):
    """Every run after the first: unlock with the passphrase, or fall
    back to the recovery code. Just collects (mode, value) and dismisses
    immediately — actually trying the unlock (and looping back here with
    an error on failure) is the caller's job, since that requires the
    keyfile this modal doesn't have."""

    def __init__(self, error: str = ""):
        super().__init__()
        self.error = error
        self.mode = "passphrase"

    def compose(self) -> ComposeResult:
        with Vertical(id="vault-dialog"):
            yield Label("🔒 Unlock your peerc vault")
            yield Label(self.error, id="vault-error")
            yield Input(placeholder="Passphrase", password=True, id="vault-input")
            with Horizontal():
                yield Button("Unlock", id="unlock", variant="success")
                yield Button("Use recovery code instead", id="toggle-mode")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "toggle-mode":
            self.mode = "recovery" if self.mode == "passphrase" else "passphrase"
            input_widget = self.query_one("#vault-input", Input)
            input_widget.password = self.mode == "passphrase"
            input_widget.placeholder = (
                "Passphrase" if self.mode == "passphrase" else "Recovery code (e.g. XXXXX-XXXXX-...)"
            )
            event.button.label = (
                "Use passphrase instead" if self.mode == "recovery" else "Use recovery code instead"
            )
            return
        if event.button.id == "unlock":
            self.dismiss((self.mode, self.query_one("#vault-input", Input).value))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss((self.mode, event.value))


class CriticalActionKeyModal(ModalScreen[Optional[tuple[str, ...]]]):
    """Collect the optional Export critical-action key without keeping it
    in app state. The caller immediately hands it to VaultSession."""

    def __init__(self, mode: str, error: str = ""):
        super().__init__()
        if mode not in {"set", "change", "clear", "export"}:
            raise ValueError("unknown critical-action modal mode")
        self.mode = mode
        self.error = error

    def compose(self) -> ComposeResult:
        title = {
            "set": "Set Export critical-action key",
            "change": "Change Export critical-action key",
            "clear": "Clear Export critical-action key",
            "export": "Authorize Export",
        }[self.mode]
        with Vertical(id="vault-dialog"):
            yield Label(title)
            yield Label(self._body_text())
            yield Label(self.error, id="vault-error")
            if self.mode == "change":
                yield Input(placeholder="Current critical-action key", password=True, id="critical-old")
                yield Input(placeholder="New critical-action key", password=True, id="critical-new")
                yield Input(placeholder="Confirm new key", password=True, id="critical-confirm")
            elif self.mode == "set":
                yield Input(placeholder="Critical-action key", password=True, id="critical-new")
                yield Input(placeholder="Confirm key", password=True, id="critical-confirm")
            else:
                yield Input(placeholder="Critical-action key", password=True, id="critical-current")
            with Horizontal():
                yield Button(self._submit_label(), id="critical-submit", variant=self._submit_variant())
                yield Button("Cancel", id="critical-cancel")

    def _body_text(self) -> str:
        if self.mode == "export":
            return "Export requires the extra key configured for this vault."
        if self.mode == "clear":
            return "Enter the current key once to remove the extra Export gate."
        return "This optional key is required in addition to the unlocked session for Export."

    def _submit_label(self) -> str:
        return {
            "set": "Set Key",
            "change": "Change Key",
            "clear": "Clear Key",
            "export": "Authorize",
        }[self.mode]

    def _submit_variant(self) -> str:
        return "error" if self.mode == "clear" else "success"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "critical-cancel":
            self.dismiss(None)
            return
        if event.button.id == "critical-submit":
            self._submit()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._submit()

    def _submit(self) -> None:
        error_label = self.query_one("#vault-error", Label)
        if self.mode == "change":
            old = self.query_one("#critical-old", Input).value
            new = self.query_one("#critical-new", Input).value
            confirm = self.query_one("#critical-confirm", Input).value
            if new != confirm:
                error_label.update("New keys don't match.")
                return
            self.dismiss((old, new))
            return
        if self.mode == "set":
            new = self.query_one("#critical-new", Input).value
            confirm = self.query_one("#critical-confirm", Input).value
            if new != confirm:
                error_label.update("Keys don't match.")
                return
            self.dismiss((new,))
            return
        current = self.query_one("#critical-current", Input).value
        self.dismiss((current,))


class FileOfferModal(ModalScreen[bool]):
    """Blocking prompt shown when a peer offers to send us a file."""

    def __init__(self, sender_name: str, filename: str, size: int):
        super().__init__()
        self.sender_name = sender_name
        self.filename = filename
        self.size = size

    def compose(self) -> ComposeResult:
        size_kb = self.size / 1024
        with Vertical(id="offer-dialog"):
            yield Label(f"{self.sender_name} wants to send you a file:")
            yield Label(f"  {self.filename}  ({size_kb:.1f} KB)")
            with Horizontal():
                yield Button("Accept", id="accept", variant="success")
                yield Button("Reject", id="reject", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "accept")


class ChatApp(App):
    CSS = """
    #main { height: 1fr; }
    #peer-list { width: 30; border: solid $accent; }
    #chat-log { border: solid $accent; }
    #offer-dialog {
        align: center middle;
        background: $panel;
        border: thick $accent;
        padding: 1 2;
        width: 60;
        height: auto;
    }
    #vault-dialog {
        align: center middle;
        background: $panel;
        border: thick $accent;
        padding: 1 2;
        width: 70;
        height: auto;
    }
    #vault-dialog Input { margin-top: 1; }
    #vault-dialog Button { margin-top: 1; }
    #vault-error { color: $error; }
    #recovery-code-text {
        margin: 1 0;
        padding: 1;
        border: solid $warning;
        text-align: center;
        text-style: bold;
    }
    Screen > .screen--selection {
        background: $primary;
        color: $text;
    }
    """
    BINDINGS = [
        ("ctrl+c", "copy_or_quit", "Copy / Quit"),
        ("ctrl+shift+c", "copy_selection", "Copy"),
        ("ctrl+q", "quit", "Quit"),
        ("ctrl+k", "clear_chat", "Clear"),
        ("ctrl+l", "lock_vault", "Lock"),
    ]

    def __init__(self):
        super().__init__()
        self.peer_id: str = ""
        self.display_name: str = ""
        self.device_model: str = ""
        self.public_key_bytes: bytes = b""
        self.my_identity = None  # DeviceKeypair, set in on_mount (BUG-004)
        self.trust_store: Optional[TrustStore] = None
        self.group_store: Optional[GroupStore] = None
        self.vault_db = None  # VaultDatabase, set in on_mount (Phase 39.2)
        self.vault_persistence = None  # VaultPersistence, set in on_mount (Phase 39.2)
        self.vault_session = None  # VaultSession, set in on_mount (Phase 39.3)
        self._relocking = False  # True while the mid-session unlock modal is up
        self.registry: Optional[discovery.PeerRegistry] = None
        self.event_bus: Optional[EventBus] = None
        self._unhook_security_events = None
        self.manager: Optional[ConnectionManager] = None
        self.chat_session: Optional[chat.ChatSession] = None
        self.file_session: Optional[file_transfer.FileTransferSession] = None
        self.active_peer_id: Optional[str] = None
        self._last_received_msg: str = ""
        
        # Phase 39.5: secure storage paths
        self.secure_storage_dir = os.path.expanduser("~/.peerc/secure")
        self.downloads_dir = "downloads"

        # Phase 42.4: Group Authority join/leave pending requests
        self._pending_join_requests: dict[str, tuple[str, GroupJoinRequest]] = {}
        self._pending_leave_requests: dict[str, tuple[str, GroupLeaveRequest]] = {}

        # Phase 43: Group-Gated Export Authorization
        self.policy_enforcer: Optional[PolicyEnforcer] = None
        self._pending_export_requests: dict[str, tuple[str, ExportRequest]] = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main"):
            yield ListView(id="peer-list")
            yield SelectableRichLog(id="chat-log", wrap=True, markup=True)
        yield Input(placeholder="Type a message, or /help for commands", id="input-box")
        yield Footer()

    async def on_mount(self) -> None:
        # push_screen_wait() (used for the vault-unlock modals below)
        # must run inside a Textual worker, not directly in on_mount —
        # _setup() below is @work-decorated for exactly that reason.
        self._setup()

    @work
    async def _setup(self) -> None:
        # BUG-004 (v1.15.1): one identity load now covers everything —
        # peer_id/display_name (as before), the raw public key (Phase
        # 5.1, for discovery's self-consistency check), and the full
        # DeviceKeypair (new) that ConnectionManager needs to perform a
        # real authenticated handshake on every connection.
        dev_identity = identity.load_or_create_identity()
        self.peer_id = dev_identity.device_id
        self.display_name = dev_identity.name
        self.public_key_bytes = dev_identity.keypair.public_key_bytes()
        self.my_identity = dev_identity.keypair
        self.device_model = detect_device_model()

        if dev_identity.is_new:
            chosen_name = await self._maybe_setup_name()
            if chosen_name:
                self.display_name = chosen_name
                discovery.save_identity(self.peer_id, chosen_name)

        self.title = f"peerc — {self.display_name} (id: {self.peer_id[:8]})"

        self.registry = discovery.PeerRegistry(
            on_peer_new=self._on_peer_new, on_peer_lost=self._on_peer_lost,
        )
        self.event_bus = EventBus()
        self._unhook_security_events = bridge_security_events(self.event_bus)

        # Phase 39.2: unlock (or first-time create) the encrypted vault
        # before anything that needs to read/write persisted state.
        dek = await self._unlock_vault()
        self.vault_db = VaultDatabase.unlock(dek)
        migrated = migrate_plaintext_trust_db(self.vault_db, TRUST_DB_LEGACY_PATH)
        if migrated:
            log = self.query_one("#chat-log", SelectableRichLog)
            log.write(f"[dim]Migrated {migrated} trusted device(s) into the encrypted vault.[/dim]")
        await self.vault_db.start_auto_flush()

        # Phase 39.3: session/auto-lock wraps the live vault — idle
        # timeout, hard lock, file-action re-auth policy.
        self.vault_session = VaultSession()
        self.vault_session.unlock(dek, self.vault_db)

        # BUG-004 (v1.15.1) / Phase 39.2: TrustStore now shares the
        # vault's own connection — its trusted_devices/identity_transitions
        # rows live inside the encrypted vault file, not a separate
        # plaintext trust.db (which migrate_plaintext_trust_db() above
        # just retired if one existed).
        self.trust_store = TrustStore(conn=self.vault_db.conn)

        # Phase 42.1: group/membership rows share the same vault
        # connection, same reasoning as TrustStore above.
        self.group_store = GroupStore(conn=self.vault_db.conn)

        # Phase 42.2: wire group_store into trust_store for External Trust Restriction (§6)
        self.trust_store.set_group_store(self.group_store)

        # Phase 43: PolicyEnforcer for group-gated export authorization
        self.policy_enforcer = PolicyEnforcer(self.group_store)

        self.manager = ConnectionManager(
            listen_port=UI_TCP_PORT,
            my_identity=self.my_identity,
            my_name=self.display_name,
            event_bus=self.event_bus,
            trust_store=self.trust_store,
        )
        self.chat_session = chat.ChatSession(
            self.manager,
            event_bus=self.event_bus,
            on_chat_received=self._on_chat_received,
            on_status_change=self._on_status_change,
        )
        self.file_session = file_transfer.FileTransferSession(
            self.manager,
            downloads_dir="downloads",
            event_bus=self.event_bus,
            on_offer_received=self._on_offer_received,
            on_progress=self._on_transfer_progress,
            on_complete=self._on_transfer_complete,
        )

        # Phase 39.2: subscribes itself to ChatReceived/ChatMessageSent/
        # ChatMessageStatusChanged/TransferCompleted and writes rows into
        # the vault — this is what "absorbs Phase 27" for real.
        self.vault_persistence = VaultPersistence(self.vault_db, self.event_bus)

        # Wire event bus subscribers
        self.event_bus.subscribe(NetworkMessageReceived, self._on_network_message_handshake)
        self.event_bus.subscribe(SecurityWarning, self._on_security_warning)
        self.event_bus.subscribe(TrustRequired, self._on_trust_required)

        await self.manager.start_server()
        self._discovery = discovery.Discovery(
            self.peer_id, self.display_name, UI_TCP_PORT, self.registry,
            public_key=self.public_key_bytes, model=self.device_model,
        )
        asyncio.create_task(self._discovery.run())
        asyncio.create_task(self._prune_ui_loop())
        asyncio.create_task(self._auto_lock_loop())

        log = self.query_one("#chat-log", SelectableRichLog)
        log.write(f"[bold cyan]Started as {self.display_name} · {self.device_model} (id: {self.peer_id[:8]})[/bold cyan]")
        log.write("Waiting for peers... use [bold yellow]/help[/bold yellow] for commands.")
        timeout_m = self.vault_session.auto_lock_seconds / 60.0
        if self.vault_session.auto_lock_seconds == 0:
            log.write("[dim]Auto-lock disabled. /lock to lock manually; /autolock <minutes> to enable.[/dim]")
        else:
            log.write(
                f"[dim]Auto-lock after {timeout_m:g} min idle "
                f"(sudo-style). /lock now, or /autolock to change.[/dim]"
            )
        log.write("[dim]Tip: Drag mouse over text to block/select. Press Ctrl+C or Ctrl+Shift+C to copy. Press Ctrl+Q to quit.[/dim]")

    async def _maybe_setup_name(self) -> str:
        """First-run only (dev_identity.is_new) — factored out on its own
        so tests can bypass it the same way they bypass _unlock_vault
        (a fresh isolated identity in a test is_new=True every run, and
        this shows a modal that a headless pilot.pause() never answers)."""
        return await self.push_screen_wait(NameSetupModal())

    async def _unlock_vault(self) -> bytes:
        """Phase 39.2: first-run vault creation, or unlock on every run
        after that. Returns the DEK. Blocks the rest of on_mount via the
        modal screens above — nothing that needs persisted state should
        run before this resolves."""
        if not vault_exists():
            passphrase = await self.push_screen_wait(VaultCreateModal())
            try:
                keyfile, recovery_code = create_vault(passphrase, device_name=self.display_name)
            except VaultExistsError:
                # Lost a race with another peerc instance creating it
                # first — fall through to the normal unlock path below.
                keyfile = load_vault_keyfile()
                return await self._unlock_vault_loop(keyfile)
            await self.push_screen_wait(VaultRecoveryCodeModal(recovery_code))
            return unlock_with_passphrase(keyfile, passphrase)

        keyfile = load_vault_keyfile()
        return await self._unlock_vault_loop(keyfile)

    async def _unlock_vault_loop(self, keyfile) -> bytes:
        error = ""
        while True:
            mode, value = await self.push_screen_wait(VaultUnlockModal(error=error))
            try:
                if mode == "passphrase":
                    return unlock_with_passphrase(keyfile, value)
                return unlock_with_recovery_code(keyfile, value)
            except WrongSecretError:
                error = "Incorrect passphrase or recovery code — try again."
            except RecoveryCodeError:
                error = "That doesn't look like a valid recovery code — try again."

    def on_unmount(self) -> None:
        # Phase 39.2/39.3: flush and destroy the plaintext working copy
        # on exit — leaving it around defeats the point of the whole
        # unlock/lock lifecycle. Prefer session.lock() so the DEK is
        # wiped too; fall back to vault_db.lock() if session never started.
        if self.vault_session is not None and self.vault_session.is_unlocked:
            if self.vault_persistence is not None:
                self.vault_persistence.reattach(None)
            if self.trust_store is not None:
                self.trust_store.adopt_conn(None)
            if self.group_store is not None:
                self.group_store.adopt_conn(None)
            self.vault_session.lock()
            self.vault_db = None
        elif self.vault_db is not None:
            self.vault_db.lock()
            self.vault_db = None

    def _touch_session(self) -> None:
        """Phase 39.3: any real user activity resets the idle timer."""
        if self.vault_session is not None:
            self.vault_session.touch()

    def _critical_key_status_text(self) -> str:
        if self.vault_session is None:
            return "unknown"
        keyfile = load_vault_keyfile()
        return (
            "enabled"
            if self.vault_session.critical_action_key_configured(keyfile)
            else "not set"
        )

    async def _prompt_for_export_authorization(self) -> bool:
        """Phase 39.4 UI hook for Phase 39.5's actual Export command."""
        if self.vault_session is None or not self.vault_session.is_unlocked:
            raise RuntimeError("vault must be unlocked before Export authorization")
        keyfile = load_vault_keyfile()
        if not self.vault_session.critical_action_key_configured(keyfile):
            return True
        result = await self.push_screen_wait(CriticalActionKeyModal("export"))
        if result is None:
            return False
        return self.vault_session.authorize_export(keyfile, result[0])

    async def _handle_critical_key_command(self, arg: str) -> None:
        if self.vault_session is None or not self.vault_session.is_unlocked:
            self._log("[red]Vault is locked — unlock first.[/red]")
            return

        action = (arg or "status").lower()
        keyfile = load_vault_keyfile()
        configured = self.vault_session.critical_action_key_configured(keyfile)

        if action in ("status", "show"):
            state = "enabled" if configured else "not set"
            self._log(f"[cyan]Export critical-action key: {state}.[/cyan]")
            return

        if action == "set":
            if configured:
                self._log("[yellow]Critical-action key is already set. Use /criticalkey change or clear.[/yellow]")
                return
            result = await self.push_screen_wait(CriticalActionKeyModal("set"))
            if result is None:
                self._log("[dim]Critical-action key setup cancelled.[/dim]")
                return
            try:
                self.vault_session.set_critical_action_key(keyfile, result[0])
                save_vault_keyfile(keyfile)
                self._log("[green]Export critical-action key enabled.[/green]")
            except WeakPassphraseError as e:
                self._log(f"[red]{e}[/red]")
            return

        if action == "change":
            if not configured:
                self._log("[yellow]No critical-action key is set. Use /criticalkey set first.[/yellow]")
                return
            result = await self.push_screen_wait(CriticalActionKeyModal("change"))
            if result is None:
                self._log("[dim]Critical-action key change cancelled.[/dim]")
                return
            try:
                old_secret, new_secret = result
                self.vault_session.change_critical_action_key(keyfile, old_secret, new_secret)
                save_vault_keyfile(keyfile)
                self._log("[green]Export critical-action key changed.[/green]")
            except WeakPassphraseError as e:
                self._log(f"[red]{e}[/red]")
            except WrongSecretError:
                self._log("[red]Incorrect current critical-action key.[/red]")
            return

        if action == "clear":
            if not configured:
                self._log("[cyan]No critical-action key is set.[/cyan]")
                return
            result = await self.push_screen_wait(CriticalActionKeyModal("clear"))
            if result is None:
                self._log("[dim]Critical-action key clear cancelled.[/dim]")
                return
            try:
                self.vault_session.clear_critical_action_key(keyfile, result[0])
                save_vault_keyfile(keyfile)
                self._log("[green]Export critical-action key cleared.[/green]")
            except WrongSecretError:
                self._log("[red]Incorrect critical-action key.[/red]")
            return

        self._log("[yellow]Usage: /criticalkey [status|set|change|clear][/yellow]")

    # ---- Phase 39.5: file action command handlers ----------------------

    async def _handle_list_files(self) -> None:
        """List all secure files in secure storage."""
        if self.vault_session is None or not self.vault_session.is_unlocked:
            self._log("[red]Vault is locked — unlock first.[/red]")
            return
        
        from core.vault import list_secure_files
        
        try:
            files = list_secure_files(self.secure_storage_dir)
            if not files:
                self._log("[yellow]No secure files yet. Use /secure <path> to add files.[/yellow]")
                return
            
            self._log("[bold yellow]╔═══════════════ Secure Files ════════════════╗[/bold yellow]")
            for meta in files[:20]:  # limit to 20 most recent
                size_mb = meta.size / (1024 * 1024)
                short_id = meta.secure_id[:12]
                self._log(
                    f"  [bold cyan]{short_id}[/bold cyan] → {meta.original_filename} "
                    f"({size_mb:.2f} MB)"
                )
            if len(files) > 20:
                self._log(f"  [dim]... and {len(files) - 20} more[/dim]")
            self._log("[bold yellow]╚═════════════════════════════════════════════╝[/bold yellow]")
            self._log("[dim]Use /open <id>, /export <id>, or /delete <id>[/dim]")
        except Exception as e:
            self._log(f"[red]Error listing files: {e}[/red]")

    async def _handle_open_file(self, file_id: str) -> None:
        """Open a secure file (view-only, never execute)."""
        if not file_id:
            self._log("[yellow]Usage: /open <file_id> (use /files to list)[/yellow]")
            return
        
        if self.vault_session is None or not self.vault_session.is_unlocked:
            self._log("[red]Vault is locked — unlock first.[/red]")
            return
        
        # Check if re-auth is required
        if self.vault_session.requires_reauth("open"):
            self._log("[yellow]Passphrase required for Open action.[/yellow]")
            result = await self.push_screen_wait(VaultUnlockModal())
            if result is None:
                self._log("[red]Open cancelled.[/red]")
                return
            passphrase_provided = result[0]
            keyfile = load_vault_keyfile()
            if not self.vault_session.verify_passphrase(keyfile, passphrase_provided):
                self._log("[red]Wrong passphrase — Open cancelled.[/red]")
                return
        
        from core.vault import (
            open_secure_file,
            check_executable_for_open,
            ExecutableBlockedError,
        )
        
        # Find matching secure_id (allow prefix match)
        from core.vault import list_secure_files
        files = list_secure_files(self.secure_storage_dir)
        match = next((f for f in files if f.secure_id.startswith(file_id)), None)
        if match is None:
            self._log(f"[red]No secure file found with ID starting with '{file_id}'[/red]")
            return
        
        try:
            # Open with executable detection
            temp_path, metadata = open_secure_file(
                secure_id=match.secure_id,
                secure_storage_dir=self.secure_storage_dir,
                session=self.vault_session,
                executable_checker=check_executable_for_open,
            )
            
            self._log(f"[green]✓ Opened {metadata.original_filename} in default viewer[/green]")
            self._log(f"[dim]Temp location: {temp_path}[/dim]")
            self._log("[yellow]⚠ Remember: this file will be auto-deleted on app close.[/yellow]")
            
            # Try to open with default system viewer
            import subprocess
            import platform
            
            system = platform.system()
            if system == "Windows":
                os.startfile(temp_path)
            elif system == "Darwin":  # macOS
                subprocess.Popen(["open", temp_path])
            else:  # Linux
                subprocess.Popen(["xdg-open", temp_path])
                
        except ExecutableBlockedError as e:
            # The detected-type info is now embedded in the exception
            # message itself (file_actions.open_secure_file deletes the
            # temp file before this handler runs, so it can't be
            # inspected here — see file_actions.py for details).
            self._log(f"[red]✗ Open blocked: {e}[/red]")
            self._log("[yellow]Use /export if you need this file outside secure storage.[/yellow]")
        except Exception as e:
            self._log(f"[red]Error opening file: {e}[/red]")

    async def _handle_export_file(self, file_id: str) -> None:
        """Export a secure file to permanent plaintext location."""
        if not file_id:
            self._log("[yellow]Usage: /export <file_id> [destination][/yellow]")
            return
        
        if self.vault_session is None or not self.vault_session.is_unlocked:
            self._log("[red]Vault is locked — unlock first.[/red]")
            return
        
        # Export ALWAYS requires authorization via critical-action key flow
        self._log("[yellow]⚠ Export will create a permanent plaintext copy.[/yellow]")
        authorized = await self._prompt_for_export_authorization()
        if not authorized:
            self._log("[red]Export cancelled — authorization failed.[/red]")
            return
        
        from core.vault import export_secure_file, list_secure_files
        
        # Find matching secure_id
        files = list_secure_files(self.secure_storage_dir)
        match = next((f for f in files if f.secure_id.startswith(file_id)), None)
        if match is None:
            self._log(f"[red]No secure file found with ID starting with '{file_id}'[/red]")
            return
        
        # Destination: downloads_dir by default
        destination = os.path.join(self.downloads_dir, match.original_filename)
        os.makedirs(self.downloads_dir, exist_ok=True)
        
        # Handle existing file
        if os.path.exists(destination):
            base, ext = os.path.splitext(match.original_filename)
            counter = 1
            while os.path.exists(destination):
                destination = os.path.join(self.downloads_dir, f"{base} ({counter}){ext}")
                counter += 1
        
        try:
            keyfile = load_vault_keyfile()
            metadata = export_secure_file(
                secure_id=match.secure_id,
                secure_storage_dir=self.secure_storage_dir,
                destination_path=destination,
                session=self.vault_session,
                keyfile=keyfile,
                critical_secret=None,  # already authorized above
                policy_enforcer=self.policy_enforcer or (PolicyEnforcer(self.group_store) if self.group_store else None),
                device_id=self.peer_id,
            )
            
            self._log(f"[green]✓ Exported {metadata.original_filename} → {destination}[/green]")
            self._log("[yellow]⚠ This plaintext copy is no longer protected by vault encryption.[/yellow]")
        except Exception as e:
            self._log(f"[red]Error exporting file: {e}[/red]")

    async def _handle_move_to_secure(self, filepath: str) -> None:
        """Move an existing local file into secure storage."""
        if not filepath:
            self._log("[yellow]Usage: /secure <filepath>[/yellow]")
            return
        
        if not os.path.exists(filepath):
            self._log(f"[red]File not found: {filepath}[/red]")
            return
        
        if self.vault_session is None or not self.vault_session.is_unlocked:
            self._log("[red]Vault is locked — unlock first.[/red]")
            return
        
        # Check if re-auth is required
        if self.vault_session.requires_reauth("move_to_secure"):
            self._log("[yellow]Passphrase required for Move to Secure Storage.[/yellow]")
            result = await self.push_screen_wait(VaultUnlockModal())
            if result is None:
                self._log("[red]Move to Secure cancelled.[/red]")
                return
            passphrase_provided = result[0]
            keyfile = load_vault_keyfile()
            if not self.vault_session.verify_passphrase(keyfile, passphrase_provided):
                self._log("[red]Wrong passphrase — Move to Secure cancelled.[/red]")
                return
        
        from core.vault import move_to_secure_storage
        from core.transfer.hashing import sha256_file
        
        try:
            # Calculate checksum for verification
            checksum = sha256_file(filepath)
            
            # Encrypt and move to secure storage
            metadata = move_to_secure_storage(
                plaintext_path=filepath,
                secure_storage_dir=self.secure_storage_dir,
                session=self.vault_session,
                checksum=checksum,
                delete_source=False,  # keep original by default
            )
            
            short_id = metadata.secure_id[:12]
            self._log(f"[green]✓ Moved {metadata.original_filename} to secure storage[/green]")
            self._log(f"[dim]Secure ID: {short_id}...[/dim]")
            self._log("[yellow]Original file kept. Delete manually if needed.[/yellow]")
        except Exception as e:
            self._log(f"[red]Error moving to secure storage: {e}[/red]")

    async def _handle_delete_file(self, file_id: str) -> None:
        """Delete a secure file permanently."""
        if not file_id:
            self._log("[yellow]Usage: /delete <file_id> (use /files to list)[/yellow]")
            return
        
        if self.vault_session is None or not self.vault_session.is_unlocked:
            self._log("[red]Vault is locked — unlock first.[/red]")
            return
        
        # Check if re-auth is required
        if self.vault_session.requires_reauth("delete"):
            self._log("[yellow]Passphrase required for Delete action.[/yellow]")
            result = await self.push_screen_wait(VaultUnlockModal())
            if result is None:
                self._log("[red]Delete cancelled.[/red]")
                return
            passphrase_provided = result[0]
            keyfile = load_vault_keyfile()
            if not self.vault_session.verify_passphrase(keyfile, passphrase_provided):
                self._log("[red]Wrong passphrase — Delete cancelled.[/red]")
                return
        
        from core.vault import delete_secure_file_action, list_secure_files
        
        # Find matching secure_id
        files = list_secure_files(self.secure_storage_dir)
        match = next((f for f in files if f.secure_id.startswith(file_id)), None)
        if match is None:
            self._log(f"[red]No secure file found with ID starting with '{file_id}'[/red]")
            return
        
        # Confirmation
        self._log(f"[yellow]⚠ Really delete {match.original_filename}? This cannot be undone![/yellow]")
        self._log("[yellow]Type 'yes' to confirm:[/yellow]")
        
        # TODO: Proper confirmation modal would be better, but for now use a simple approach
        # For MVP, just proceed with deletion (user already had to re-auth)
        
        try:
            metadata = delete_secure_file_action(
                secure_id=match.secure_id,
                secure_storage_dir=self.secure_storage_dir,
                session=self.vault_session,
            )
            
            self._log(f"[green]✓ Deleted {metadata.original_filename} from secure storage[/green]")
        except Exception as e:
            self._log(f"[red]Error deleting file: {e}[/red]")

    # ---- End Phase 39.5 file actions -----------------------------------

    # ---- Phase 42: Group Authority command handlers & network callbacks ----

    async def _handle_group_command(self, arg: str) -> None:
        """Dispatcher for /group and /groups commands."""
        if self.group_store is None:
            self._log("[red]Vault is locked — unlock first to access Group Authority.[/red]")
            return

        parts = arg.strip().split(maxsplit=2)
        subcmd = parts[0].lower() if parts else "list"
        rest = parts[1] if len(parts) > 1 else ""
        extra = parts[2] if len(parts) > 2 else ""

        if subcmd in ("list", "ls") or not arg.strip():
            await self._handle_group_list()
        elif subcmd == "create":
            await self._handle_group_create(rest, extra if extra else None)
        elif subcmd == "info":
            await self._handle_group_info(rest)
        elif subcmd == "members":
            await self._handle_group_members(rest)
        elif subcmd == "admins":
            await self._handle_group_admins(rest)
        elif subcmd == "join":
            await self._handle_group_join(rest, extra)
        elif subcmd == "leave":
            await self._handle_group_leave(rest, extra)
        elif subcmd == "approve":
            await self._handle_group_approve(rest, extra)
        elif subcmd == "reject":
            await self._handle_group_reject(rest, extra)
        elif subcmd == "approve-leave":
            await self._handle_group_approve_leave(rest, extra)
        elif subcmd == "reject-leave":
            await self._handle_group_reject_leave(rest, extra)
        elif subcmd == "revoke":
            await self._handle_group_revoke(rest, extra)
        elif subcmd == "addadmin":
            await self._handle_group_add_admin(rest, extra)
        elif subcmd == "policy":
            await self._handle_group_policy(rest, extra)
        elif subcmd == "audit":
            await self._handle_group_audit(rest, extra)
        elif subcmd in ("authorize-export", "auth-export"):
            await self._handle_group_authorize_export(rest, extra)
        elif subcmd == "req-export":
            await self._handle_group_req_export(rest, extra)
        elif subcmd in ("caps", "capabilities"):
            await self._handle_group_caps(rest, extra)
        else:
            self._log(f"[yellow]Unknown group subcommand: '{subcmd}'. Type /help for usage.[/yellow]")

    async def _handle_group_list(self) -> None:
        groups = self.group_store.list_groups()
        if not groups:
            self._log("[yellow]No groups found. Use /group create <name> to create one.[/yellow]")
            return
        self._log("[bold yellow]╔═════════════════════ Groups ═════════════════════╗[/bold yellow]")
        for g in groups:
            is_admin = self.group_store.is_admin(g.group_id, self.peer_id)
            role_str = "[bold green]Admin[/bold green]" if is_admin else "Member"
            status = self.group_store.get_membership_status(g.group_id, self.peer_id)
            status_str = f" [{status.value}]" if status else " [not joined]"
            self._log(f"  • [bold]{g.name}[/bold] (id: [cyan]{g.group_id}[/cyan]) — {role_str}{status_str}")
        self._log("[bold yellow]╚═══════════════════════════════════════════════════╝[/bold yellow]")
        self._log("[dim]Use /group info <id>, /group members <id>, or /group admins <id>[/dim]")

    async def _handle_group_audit(self, group_id: str, extra: str = "") -> None:
        if not group_id:
            groups = self.group_store.list_groups()
            if len(groups) == 1:
                group_id = groups[0].group_id
            else:
                self._log("[yellow]Usage: /group audit <group_id> [limit][/yellow]")
                return

        group = self.group_store.get_group(group_id)
        if group is None:
            self._log(f"[red]Group '{group_id}' not found.[/red]")
            return

        try:
            limit = int(extra) if extra.strip().isdigit() else 20
        except Exception:
            limit = 20

        active_admins = self.group_store.get_active_admin_public_keys(group_id)
        events = self.group_store.list_audit_events(group_id, limit=limit)

        self._log(f"[bold yellow]╔════════════ Group Audit Log: {group.name} ({len(events)}) ════════════╗[/bold yellow]")
        if not events:
            self._log("  [dim]No audit events recorded yet.[/dim]")
        for ev in events:
            t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ev.timestamp))
            if ev.signature:
                if verify_group_audit_event(ev, active_admins):
                    ver_badge = "[green]✓ signed[/green]"
                else:
                    ver_badge = "[red]✗ invalid-sig[/red]"
            else:
                ver_badge = "[dim]unsigned[/dim]"

            sev_color = (
                "green" if ev.severity == SecuritySeverity.INFO
                else ("yellow" if ev.severity == SecuritySeverity.WARNING else "red")
            )
            actor = f" by {ev.signer_device_id[:8]}" if ev.signer_device_id else ""
            self._log(
                f"  [{sev_color}][{ev.severity.value}][/{sev_color}] [dim]{t_str}[/dim] "
                f"[bold]{ev.event_type}[/bold]: {ev.description}{actor} ({ver_badge})"
            )
        self._log("[bold yellow]╚══════════════════════════════════════════════════════════╝[/bold yellow]")

    async def _handle_group_create(self, name: str, group_id: Optional[str] = None) -> None:
        if not name:
            self._log("[yellow]Usage: /group create <name> [group_id][/yellow]")
            return
        if self.my_identity is None:
            self._log("[red]Identity not initialized.[/red]")
            return

        gid = group_id.strip() if group_id else uuid.uuid4().hex[:8]
        group = create_group(admin_keypair=self.my_identity, name=name, group_id=gid)
        try:
            self.group_store.create_group(group)
            cert = issue_membership_certificate(
                self.my_identity,
                device_id=self.peer_id,
                device_public_key=self.public_key_bytes,
                group_id=gid,
                role="admin",
                permissions=["chat", "file", "export", "admin"],
            )
            self.group_store.record_membership(cert)
            self._log(f"[green]✓ Group [bold]{name}[/bold] created! ID: [cyan]{gid}[/cyan] (you are Admin)[/green]")
        except Exception as e:
            self._log(f"[red]Failed to create group: {e}[/red]")

    async def _handle_group_info(self, group_id: str) -> None:
        if not group_id:
            groups = self.group_store.list_groups()
            if len(groups) == 1:
                group_id = groups[0].group_id
            else:
                self._log("[yellow]Usage: /group info <group_id>[/yellow]")
                return

        group = self.group_store.get_group(group_id)
        if group is None:
            self._log(f"[red]Group '{group_id}' not found.[/red]")
            return

        admins = self.group_store.list_admins(group_id)
        members = self.group_store.list_memberships(group_id)
        policy = self.group_store.get_policy(group_id)
        is_admin = self.group_store.is_admin(group_id, self.peer_id)

        self._log(f"[bold yellow]╔════════════ Group Details: {group.name} ({group.group_id}) ════════════╗[/bold yellow]")
        self._log(f"  [bold]Group ID:[/bold]     [cyan]{group.group_id}[/cyan]")
        self._log(f"  [bold]Founder:[/bold]      {group.admin_device_id[:8]}...")
        self._log(f"  [bold]Your Role:[/bold]    {'[bold green]Admin[/bold green]' if is_admin else 'Member'}")
        self._log(f"  [bold]Admins ({len(admins)}):[/bold]   {', '.join(a.device_id[:8] for a in admins if a.status == AdminStatus.ACTIVE)}")
        self._log(f"  [bold]Members:[/bold]      {len(members)} total")
        if policy is None:
            self._log("  [bold]Policy:[/bold]       default (all allowed)")
        else:
            self._log(
                f"  [bold]Policy:[/bold]       ext_trust={policy.allow_external_trust}, "
                f"export={policy.allow_export}, leave_req_admin={policy.leave_requires_admin}"
            )
        self._log("[bold yellow]╚═══════════════════════════════════════════════════╝[/bold yellow]")

    async def _handle_group_members(self, group_id: str) -> None:
        if not group_id:
            groups = self.group_store.list_groups()
            if len(groups) == 1:
                group_id = groups[0].group_id
            else:
                self._log("[yellow]Usage: /group members <group_id>[/yellow]")
                return

        group = self.group_store.get_group(group_id)
        if group is None:
            self._log(f"[red]Group '{group_id}' not found.[/red]")
            return

        members = self.group_store.list_memberships(group_id)
        self._log(f"[bold yellow]╔════════════ Members: {group.name} ({len(members)}) ════════════╗[/bold yellow]")
        if not members:
            self._log("  [dim]No members recorded yet.[/dim]")
        for m in members:
            status_color = "green" if m.status == MembershipStatus.ACTIVE.value else "red"
            is_you = " [bold cyan](YOU)[/bold cyan]" if m.device_id == self.peer_id else ""
            perms = ",".join(m.permissions) if m.permissions else "none"
            self._log(
                f"  • [bold]{m.device_id[:8]}[/bold]{is_you} | "
                f"Role: [cyan]{m.role}[/cyan] | "
                f"Status: [{status_color}]{m.status}[/{status_color}] | "
                f"Perms: {perms}"
            )
        self._log("[bold yellow]╚═══════════════════════════════════════════════════╝[/bold yellow]")

    async def _handle_group_admins(self, group_id: str) -> None:
        if not group_id:
            groups = self.group_store.list_groups()
            if len(groups) == 1:
                group_id = groups[0].group_id
            else:
                self._log("[yellow]Usage: /group admins <group_id>[/yellow]")
                return

        group = self.group_store.get_group(group_id)
        if group is None:
            self._log(f"[red]Group '{group_id}' not found.[/red]")
            return

        admins = self.group_store.list_admins(group_id)
        self._log(f"[bold yellow]╔════════════ Admins: {group.name} ({len(admins)}) ════════════╗[/bold yellow]")
        for a in admins:
            status_color = "green" if a.status == AdminStatus.ACTIVE else "red"
            is_you = " [bold cyan](YOU)[/bold cyan]" if a.device_id == self.peer_id else ""
            self._log(
                f"  • [bold]{a.device_id[:8]}[/bold]{is_you} | "
                f"Status: [{status_color}]{a.status.value}[/{status_color}]"
            )
        self._log("[bold yellow]╚═══════════════════════════════════════════════════╝[/bold yellow]")

    async def _handle_group_join(self, group_id: str, peer_arg: str = "") -> None:
        if not group_id:
            self._log("[yellow]Usage: /group join <group_id> [peer_name_or_id][/yellow]")
            return
        if self.my_identity is None:
            self._log("[red]Identity not initialized.[/red]")
            return

        target_peer = None
        if peer_arg:
            target_peer = next(
                (p for p in self.registry.list_peers()
                 if peer_arg.lower() in p.name.lower() or p.peer_id.startswith(peer_arg)),
                None,
            )
            if target_peer is None:
                self._log(f"[red]No peer matching '{peer_arg}' found.[/red]")
                return
        elif self.active_peer_id:
            target_peer = self.registry.get(self.active_peer_id)

        if target_peer is None:
            self._log("[red]No target peer specified or active. Use /group join <group_id> <peer>[/red]")
            return

        addr_key = f"{target_peer.ip}:{target_peer.tcp_port}"
        connected = await self._ensure_connected(addr_key)
        if not connected:
            self._log(f"[red]Could not connect to {target_peer.name} ({addr_key})[/red]")
            return

        req = create_join_request(
            self.my_identity,
            group_id=group_id,
            requested_role="member",
            requested_permissions=["chat", "file"],
            reason="Join request from peerc UI",
        )
        wire = protocol.make_group_join_request(
            request_id=req.request_id,
            group_id=req.group_id,
            device_id=req.device_id,
            device_public_key=req.device_public_key,
            requested_role=req.requested_role,
            requested_permissions=req.requested_permissions,
            signature=req.signature,
            reason=req.reason,
            timestamp=req.timestamp,
        )
        try:
            await self.manager.send(addr_key, wire)
            self._log(f"[cyan]Sent join request for group '{group_id}' to {target_peer.name} ({target_peer.peer_id[:8]}).[/cyan]")
        except Exception as e:
            self._log(f"[red]Failed to send join request: {e}[/red]")

    async def _handle_group_approve(self, group_id: str, extra: str) -> None:
        if not group_id or not extra:
            self._log("[yellow]Usage: /group approve <group_id> <device_id> [role][/yellow]")
            return
        if self.my_identity is None:
            self._log("[red]Identity not initialized.[/red]")
            return

        parts = extra.split(maxsplit=1)
        device_id = parts[0]
        role = parts[1] if len(parts) > 1 else None

        pending_entry = None
        match_key = None
        for k, (ak, r) in self._pending_join_requests.items():
            if r.group_id == group_id and (r.device_id.startswith(device_id) or r.request_id.startswith(device_id)):
                pending_entry = (ak, r)
                match_key = k
                break

        if pending_entry is not None:
            addr_key, req = pending_entry
            pub_bytes = base64.b64decode(req.device_public_key)
            target_device_id = req.device_id
            target_role = role or req.requested_role or "member"
            perms = req.requested_permissions or ["chat", "file"]
        else:
            peer = self.registry.get(device_id) or next(
                (p for p in self.registry.list_peers() if p.peer_id.startswith(device_id) or p.name.lower() == device_id.lower()),
                None,
            )
            if peer is None or not peer.public_key:
                self._log(f"[red]No pending join request or peer with public key found for '{device_id}'.[/red]")
                return
            addr_key = f"{peer.ip}:{peer.tcp_port}"
            pub_bytes = peer.public_key
            target_device_id = peer.peer_id
            target_role = role or "member"
            perms = ["chat", "file"]
            req = None

        cert = issue_membership_certificate(
            self.my_identity,
            device_id=target_device_id,
            device_public_key=pub_bytes,
            group_id=group_id,
            role=target_role,
            permissions=perms,
        )
        try:
            self.group_store.record_membership(cert)
        except Exception as e:
            self._log(f"[red]Failed to record membership: {e}[/red]")
            return

        if req is not None:
            res = create_join_response(
                self.my_identity,
                req,
                approved=True,
                certificate=cert,
                reason="Approved by administrator",
            )
            wire = protocol.make_group_join_response(
                request_id=res.request_id,
                group_id=res.group_id,
                device_id=res.device_id,
                approved=res.approved,
                admin_device_id=res.admin_device_id,
                signature=res.signature,
                certificate=cert.to_dict(),
                reason=res.reason,
                timestamp=res.timestamp,
            )
            try:
                await self.manager.send(addr_key, wire)
            except Exception as e:
                self._log(f"[yellow]Membership recorded, but failed to send wire response: {e}[/yellow]")
            if match_key:
                self._pending_join_requests.pop(match_key, None)

        self._log(f"[green]✓ Approved membership for {target_device_id[:8]} in group '{group_id}' (role: {target_role}).[/green]")

    async def _handle_group_reject(self, group_id: str, extra: str) -> None:
        if not group_id or not extra:
            self._log("[yellow]Usage: /group reject <group_id> <device_id> [reason][/yellow]")
            return
        if self.my_identity is None:
            self._log("[red]Identity not initialized.[/red]")
            return

        parts = extra.split(maxsplit=1)
        device_id = parts[0]
        reason = parts[1] if len(parts) > 1 else "Rejected by administrator"

        match_key = None
        pending_entry = None
        for k, (ak, r) in self._pending_join_requests.items():
            if r.group_id == group_id and (r.device_id.startswith(device_id) or r.request_id.startswith(device_id)):
                pending_entry = (ak, r)
                match_key = k
                break

        if pending_entry is None:
            self._log(f"[red]No pending join request found for '{device_id}' in group '{group_id}'.[/red]")
            return

        addr_key, req = pending_entry
        res = create_join_response(
            self.my_identity,
            req,
            approved=False,
            reason=reason,
        )
        wire = protocol.make_group_join_response(
            request_id=res.request_id,
            group_id=res.group_id,
            device_id=res.device_id,
            approved=res.approved,
            admin_device_id=res.admin_device_id,
            signature=res.signature,
            reason=res.reason,
            timestamp=res.timestamp,
        )
        try:
            await self.manager.send(addr_key, wire)
        except Exception as e:
            self._log(f"[yellow]Failed to send wire rejection: {e}[/yellow]")

        if match_key:
            self._pending_join_requests.pop(match_key, None)
        self._log(f"[yellow]Rejected join request for {req.device_id[:8]} in group '{group_id}'.[/yellow]")

    async def _handle_group_leave(self, group_id: str, reason: str = "") -> None:
        if not group_id:
            self._log("[yellow]Usage: /group leave <group_id> [reason][/yellow]")
            return
        if self.my_identity is None:
            self._log("[red]Identity not initialized.[/red]")
            return

        cert = self.group_store.get_membership(group_id, self.peer_id)
        if cert is None:
            self._log(f"[red]You are not a member of group '{group_id}'.[/red]")
            return

        policy = self.group_store.get_policy(group_id)
        req = create_leave_request(self.my_identity, group_id=group_id, reason=reason or "Leaving group")

        if policy and policy.leave_requires_admin:
            admins = self.group_store.list_admins(group_id)
            target_admin = next((a for a in admins if a.status == AdminStatus.ACTIVE and a.device_id != self.peer_id), None)
            if target_admin is None:
                self._log("[red]No active administrator found for this group to approve leave.[/red]")
                return

            peer = self.registry.get(target_admin.device_id)
            if peer is None:
                self._log(f"[yellow]Leave requires admin approval, but admin {target_admin.device_id[:8]} is offline.[/yellow]")
                return
            addr_key = f"{peer.ip}:{peer.tcp_port}"
            connected = await self._ensure_connected(addr_key)
            if not connected:
                self._log(f"[red]Could not connect to admin at {addr_key}[/red]")
                return

            wire = protocol.make_group_leave_request(
                request_id=req.request_id,
                group_id=req.group_id,
                device_id=req.device_id,
                signature=req.signature,
                reason=req.reason,
                timestamp=req.timestamp,
            )
            try:
                await self.manager.send(addr_key, wire)
                self._log(f"[yellow]Leave request submitted for group '{group_id}'. Waiting for administrator approval.[/yellow]")
            except Exception as e:
                self._log(f"[red]Failed to send leave request: {e}[/red]")
        else:
            try:
                self.group_store.process_leave_request(req)
                self._log(f"[green]✓ You have left group '{group_id}'.[/green]")
            except Exception as e:
                self._log(f"[red]Failed to process leave: {e}[/red]")

    async def _handle_group_approve_leave(self, group_id: str, extra: str) -> None:
        if not group_id or not extra:
            self._log("[yellow]Usage: /group approve-leave <group_id> <device_id>[/yellow]")
            return
        if self.my_identity is None:
            self._log("[red]Identity not initialized.[/red]")
            return

        device_id = extra.strip().split()[0]
        match_key = None
        pending_entry = None
        for k, (ak, r) in self._pending_leave_requests.items():
            if r.group_id == group_id and (r.device_id.startswith(device_id) or r.request_id.startswith(device_id)):
                pending_entry = (ak, r)
                match_key = k
                break

        if pending_entry is None:
            self._log(f"[red]No pending leave request found for '{device_id}' in group '{group_id}'.[/red]")
            return

        addr_key, req = pending_entry
        revoc = create_membership_revocation(
            self.my_identity,
            group_id=group_id,
            device_id=req.device_id,
            reason=req.reason or "Leave approved by admin",
        )
        res = create_leave_response(
            self.my_identity,
            req,
            approved=True,
            revocation=revoc,
            reason="Leave approved by administrator",
        )
        try:
            self.group_store.process_leave_response(res)
        except Exception as e:
            self._log(f"[red]Failed to process leave locally: {e}[/red]")
            return

        wire = protocol.make_group_leave_response(
            request_id=res.request_id,
            group_id=res.group_id,
            device_id=res.device_id,
            approved=res.approved,
            admin_device_id=res.admin_device_id,
            signature=res.signature,
            revocation=revoc.to_dict(),
            reason=res.reason,
            timestamp=res.timestamp,
        )
        try:
            await self.manager.send(addr_key, wire)
        except Exception as e:
            self._log(f"[yellow]Leave processed locally, but failed to send wire response: {e}[/yellow]")

        if match_key:
            self._pending_leave_requests.pop(match_key, None)
        self._log(f"[green]✓ Approved leave for {req.device_id[:8]} from group '{group_id}'.[/green]")

    async def _handle_group_reject_leave(self, group_id: str, extra: str) -> None:
        if not group_id or not extra:
            self._log("[yellow]Usage: /group reject-leave <group_id> <device_id> [reason][/yellow]")
            return
        if self.my_identity is None:
            self._log("[red]Identity not initialized.[/red]")
            return

        parts = extra.strip().split(maxsplit=1)
        device_id = parts[0]
        reason = parts[1] if len(parts) > 1 else "Leave rejected by administrator"

        match_key = None
        pending_entry = None
        for k, (ak, r) in self._pending_leave_requests.items():
            if r.group_id == group_id and (r.device_id.startswith(device_id) or r.request_id.startswith(device_id)):
                pending_entry = (ak, r)
                match_key = k
                break

        if pending_entry is None:
            self._log(f"[red]No pending leave request found for '{device_id}' in group '{group_id}'.[/red]")
            return

        addr_key, req = pending_entry
        res = create_leave_response(
            self.my_identity,
            req,
            approved=False,
            reason=reason,
        )
        wire = protocol.make_group_leave_response(
            request_id=res.request_id,
            group_id=res.group_id,
            device_id=res.device_id,
            approved=res.approved,
            admin_device_id=res.admin_device_id,
            signature=res.signature,
            reason=res.reason,
            timestamp=res.timestamp,
        )
        try:
            await self.manager.send(addr_key, wire)
        except Exception as e:
            self._log(f"[yellow]Failed to send wire rejection: {e}[/yellow]")

        if match_key:
            self._pending_leave_requests.pop(match_key, None)
        self._log(f"[yellow]Rejected leave request for {req.device_id[:8]} from group '{group_id}'.[/yellow]")

    async def _handle_group_revoke(self, group_id: str, extra: str) -> None:
        if not group_id or not extra:
            self._log("[yellow]Usage: /group revoke <group_id> <device_id> [reason][/yellow]")
            return
        if self.my_identity is None:
            self._log("[red]Identity not initialized.[/red]")
            return

        parts = extra.strip().split(maxsplit=1)
        device_id = parts[0]
        reason = parts[1] if len(parts) > 1 else "Revoked by administrator"

        if not self.group_store.is_admin(group_id, self.peer_id):
            self._log(f"[red]You are not an administrator of group '{group_id}'.[/red]")
            return

        cert = self.group_store.get_membership(group_id, device_id)
        if cert is None:
            all_m = self.group_store.list_memberships(group_id)
            match_m = next((m for m in all_m if m.device_id.startswith(device_id)), None)
            if match_m:
                cert = match_m
                device_id = match_m.device_id

        if cert is None:
            self._log(f"[red]No membership found for device '{device_id}' in group '{group_id}'.[/red]")
            return

        revoc = create_membership_revocation(
            self.my_identity,
            group_id=group_id,
            device_id=device_id,
            reason=reason,
        )
        try:
            self.group_store.record_revocation(revoc)
            self._log(f"[green]✓ Revoked membership for {device_id[:8]} in group '{group_id}'.[/green]")
        except Exception as e:
            self._log(f"[red]Failed to revoke membership: {e}[/red]")
            return

        wire = protocol.make_group_membership_revoke(
            revocation_id=revoc.revocation_id,
            group_id=revoc.group_id,
            device_id=revoc.device_id,
            revoked_by=revoc.revoked_by,
            signature=revoc.signature,
            reason=revoc.reason,
            timestamp=revoc.timestamp,
        )
        peer = self.registry.get(device_id)
        if peer:
            addr_key = f"{peer.ip}:{peer.tcp_port}"
            if self.manager.is_connected(addr_key):
                try:
                    await self.manager.send(addr_key, wire)
                except Exception:
                    pass

    async def _handle_group_add_admin(self, group_id: str, extra: str) -> None:
        if not group_id or not extra:
            self._log("[yellow]Usage: /group addadmin <group_id> <device_id>[/yellow]")
            return

        device_id = extra.strip().split()[0]
        if not self.group_store.is_admin(group_id, self.peer_id):
            self._log(f"[red]You are not an administrator of group '{group_id}'.[/red]")
            return

        cert = self.group_store.get_membership(group_id, device_id)
        pub_key = None
        if cert:
            pub_key = base64.b64decode(cert.device_public_key)
            device_id = cert.device_id
        else:
            all_m = self.group_store.list_memberships(group_id)
            match_m = next((m for m in all_m if m.device_id.startswith(device_id)), None)
            if match_m:
                pub_key = base64.b64decode(match_m.device_public_key)
                device_id = match_m.device_id
            else:
                peer = self.registry.get(device_id) or next(
                    (p for p in self.registry.list_peers() if p.peer_id.startswith(device_id)), None
                )
                if peer and peer.public_key:
                    pub_key = peer.public_key
                    device_id = peer.peer_id

        if pub_key is None:
            self._log(f"[red]Could not find public key for device '{device_id}'.[/red]")
            return

        try:
            self.group_store.add_admin(group_id, device_id, pub_key, added_by=self.peer_id)
            self._log(f"[green]✓ Device {device_id[:8]} is now an administrator of group '{group_id}'.[/green]")
        except Exception as e:
            self._log(f"[red]Failed to add admin: {e}[/red]")

    async def _handle_group_policy(self, group_id: str, extra: str) -> None:
        if not group_id:
            groups = self.group_store.list_groups()
            if len(groups) == 1:
                group_id = groups[0].group_id
            else:
                self._log("[yellow]Usage: /group policy <group_id> [key=value ...][/yellow]")
                return

        group = self.group_store.get_group(group_id)
        if group is None:
            self._log(f"[red]Group '{group_id}' not found.[/red]")
            return

        policy = self.group_store.get_policy(group_id)
        if not extra.strip():
            self._log(f"[bold yellow]╔════════════ Group Policy: {group.name} ════════════╗[/bold yellow]")
            if policy is None:
                self._log("  [dim]Default policy active (all actions allowed):[/dim]")
                self._log("  • allow_external_trust:  [green]True[/green]")
                self._log("  • allow_export:          [green]True[/green]")
                self._log("  • leave_requires_admin:  [cyan]False[/cyan]")
                self._log("  • allow_inter_group:     [green]True[/green]")
            else:
                ext_col = "green" if policy.allow_external_trust else "red"
                exp_col = "green" if policy.allow_export else "red"
                lra_col = "yellow" if policy.leave_requires_admin else "cyan"
                aig_col = "green" if policy.allow_inter_group else "red"
                self._log(f"  • allow_external_trust:  [{ext_col}]{policy.allow_external_trust}[/{ext_col}]")
                self._log(f"  • allow_export:          [{exp_col}]{policy.allow_export}[/{exp_col}]")
                self._log(f"  • leave_requires_admin:  [{lra_col}]{policy.leave_requires_admin}[/{lra_col}]")
                self._log(f"  • allow_inter_group:     [{aig_col}]{policy.allow_inter_group}[/{aig_col}]")
                if policy.admin_device_id:
                    self._log(f"  • Set by admin:          {policy.admin_device_id[:8]}...")
            self._log("[bold yellow]╚═════════════════════════════════════════════════════╝[/bold yellow]")
            self._log("[dim]To change: /group policy <id> allow_external_trust=false leave_requires_admin=true[/dim]")
            return

        if not self.group_store.is_admin(group_id, self.peer_id):
            self._log(f"[red]You must be an administrator of group '{group_id}' to modify policy.[/red]")
            return

        current = policy or GroupPolicy(group_id=group_id, admin_device_id=self.peer_id)
        for pair in extra.split():
            if "=" not in pair:
                continue
            k, v = pair.split("=", 1)
            k = k.lower().strip()
            val_bool = v.lower().strip() in ("1", "true", "yes", "on")
            if k == "allow_external_trust":
                current.allow_external_trust = val_bool
            elif k == "allow_export":
                current.allow_export = val_bool
            elif k == "leave_requires_admin":
                current.leave_requires_admin = val_bool
            elif k == "allow_inter_group":
                current.allow_inter_group = val_bool
            else:
                self._log(f"[yellow]Unknown policy field: {k}[/yellow]")

        current.admin_device_id = self.peer_id
        current.updated_at = time.time()
        try:
            self.group_store.set_policy(current)
            self._log(f"[green]✓ Updated policy for group '{group_id}'.[/green]")
        except Exception as e:
            self._log(f"[red]Failed to set policy: {e}[/red]")

    async def _handle_group_authorize_export(self, group_id: str, extra: str) -> None:
        if not group_id or not extra.strip():
            self._log("[yellow]Usage: /group authorize-export <group_id> <device_id> [file_id] [ttl_seconds][/yellow]")
            return

        if not self.group_store.is_admin(group_id, self.peer_id):
            self._log(f"[red]You must be an administrator of group '{group_id}' to authorize export.[/red]")
            return

        parts = extra.strip().split()
        device_arg = parts[0]
        file_arg = parts[1] if len(parts) > 1 else "*"
        ttl_arg = float(parts[2]) if len(parts) > 2 and parts[2].isdigit() else DEFAULT_CAPABILITY_TTL

        # Check if there's a matching pending request
        pending_entry = None
        match_key = None
        for k, (ak, r) in self._pending_export_requests.items():
            if r.group_id == group_id and (r.device_id.startswith(device_arg) or r.request_id.startswith(device_arg)):
                pending_entry = (ak, r)
                match_key = k
                break

        if pending_entry is not None:
            addr_key, req = pending_entry
            target_device_id = req.device_id
            target_file_id = req.file_id
            cap = issue_export_capability(self.my_identity, self.peer_id, req, ttl=ttl_arg)
        else:
            cert = self.group_store.get_membership(group_id, device_arg)
            if cert:
                target_device_id = cert.device_id
                pub_b64 = cert.device_public_key
            else:
                peer = self.registry.get(device_arg) or next(
                    (p for p in self.registry.list_peers() if p.peer_id.startswith(device_arg)),
                    None,
                )
                if peer and peer.public_key:
                    target_device_id = peer.peer_id
                    pub_b64 = base64.b64encode(peer.public_key).decode("ascii")
                else:
                    self._log(f"[red]Could not resolve device '{device_arg}' in group '{group_id}'.[/red]")
                    return

            target_file_id = file_arg
            dummy_req = ExportRequest(
                request_id=secrets.token_hex(16),
                device_id=target_device_id,
                device_public_key=pub_b64,
                group_id=group_id,
                file_id=target_file_id,
            )
            cap = issue_export_capability(self.my_identity, self.peer_id, dummy_req, ttl=ttl_arg)
            peer_obj = self.registry.get(target_device_id)
            addr_key = f"{peer_obj.ip}:{peer_obj.tcp_port}" if peer_obj else None

        try:
            self.group_store.store_capability(cap)
        except Exception as e:
            self._log(f"[red]Failed to store capability: {e}[/red]")
            return

        if match_key:
            self._pending_export_requests.pop(match_key, None)

        if addr_key and self.manager:
            wire = protocol.make_group_export_capability(
                capability_id=cap.capability_id,
                request_id=cap.request_id,
                group_id=cap.group_id,
                device_id=cap.device_id,
                file_id=cap.file_id,
                action=cap.action,
                issued_at=cap.issued_at,
                expires_at=cap.expires_at,
                nonce=cap.nonce,
                admin_device_id=cap.admin_device_id,
                signature=cap.signature,
            )
            try:
                await self.manager.send(addr_key, wire)
            except Exception as e:
                self._log(f"[yellow]Capability stored, but failed to send to peer: {e}[/yellow]")

        self._log(
            f"[green]✓ Authorized export of file '{target_file_id}' for {target_device_id[:8]} "
            f"in group '{group_id}' (valid for {int(ttl_arg)}s).[/green]"
        )

    async def _handle_group_req_export(self, group_id: str, extra: str) -> None:
        if not group_id or not extra.strip():
            self._log("[yellow]Usage: /group req-export <group_id> <file_id> [reason][/yellow]")
            return

        cert = self.group_store.get_membership(group_id, self.peer_id)
        if cert is None and not self.group_store.is_admin(group_id, self.peer_id):
            self._log(f"[red]You are not a member of group '{group_id}'.[/red]")
            return

        parts = extra.strip().split(maxsplit=1)
        file_id = parts[0]
        reason = parts[1] if len(parts) > 1 else None

        pub_b64 = base64.b64encode(self.public_key_bytes).decode("ascii")
        req = create_export_request(
            self.my_identity,
            device_id=self.peer_id,
            device_public_key_b64=pub_b64,
            group_id=group_id,
            file_id=file_id,
            reason=reason,
        )

        wire = protocol.make_group_export_request(
            request_id=req.request_id,
            group_id=req.group_id,
            device_id=req.device_id,
            device_public_key=req.device_public_key,
            file_id=req.file_id,
            signature=req.signature,
            action=req.action,
            reason=req.reason,
            timestamp=req.timestamp,
        )

        admins = self.group_store.list_admins(group_id, status=AdminStatus.ACTIVE)
        sent_any = False
        if self.manager:
            for adm in admins:
                if adm.device_id == self.peer_id:
                    continue
                peer = self.registry.get(adm.device_id)
                if peer:
                    try:
                        await self.manager.send(f"{peer.ip}:{peer.tcp_port}", wire)
                        sent_any = True
                    except Exception:
                        pass

        if sent_any:
            self._log(f"[green]✓ Sent export request for file '{file_id}' to active admin(s) in group '{group_id}'.[/green]")
        else:
            self._log(f"[yellow]Export request created (ID: {req.request_id[:8]}), but no connected group admins were found online.[/yellow]")

    async def _handle_group_caps(self, group_id: str, extra: str) -> None:
        if not group_id:
            groups = self.group_store.list_groups()
            if len(groups) == 1:
                group_id = groups[0].group_id
            else:
                self._log("[yellow]Usage: /group caps <group_id> [device_id][/yellow]")
                return

        group = self.group_store.get_group(group_id)
        if group is None:
            self._log(f"[red]Group '{group_id}' not found.[/red]")
            return

        target_dev = extra.strip() or None
        caps = self.group_store.list_capabilities(group_id, device_id=target_dev)
        self._log(f"[bold yellow]╔════════════ Active Export Capabilities: {group.name} ({len(caps)}) ════════════╗[/bold yellow]")
        if not caps:
            self._log("  [dim]No unexpired, unused export capabilities found.[/dim]")
        for c in caps:
            rem = max(0, int(c.expires_at - time.time()))
            admin_str = f"by {c.admin_device_id[:8]}" if c.admin_device_id else "admin"
            self._log(
                f"  • [bold cyan]{c.capability_id[:12]}[/bold cyan] → file: [bold]{c.file_id}[/bold] "
                f"| device: {c.device_id[:8]} ({admin_str}) [green]{rem}s left[/green]"
            )
        self._log("[bold yellow]╚══════════════════════════════════════════════════════════════════╝[/bold yellow]")

    async def _on_group_join_request(self, addr_key: str, message: dict) -> None:
        if self.group_store is None or self.my_identity is None:
            return
        try:
            req = GroupJoinRequest.from_dict(message)
        except Exception as e:
            self._log(f"[dim]Ignored invalid group_join_request: {e}[/dim]")
            return
        if not verify_join_request(req):
            self._log(f"[red][bold]SECURITY:[/bold] Invalid signature on join request from {req.device_id[:8]}[/red]")
            return

        if not self.group_store.is_admin(req.group_id, self.peer_id):
            return

        key = f"{req.group_id}:{req.device_id}"
        self._pending_join_requests[key] = (addr_key, req)

        group = self.group_store.get_group(req.group_id)
        group_name = group.name if group else req.group_id
        peer = self.registry.get(req.device_id)
        sender_name = peer.name if peer else req.device_id[:8]

        self._log(f"[bold yellow]╔════════════ Group Join Request: {req.device_id[:8]} ════════════╗[/bold yellow]")
        self._log(f"  [bold]From:[/bold]   {sender_name} ({req.device_id[:8]})")
        self._log(f"  [bold]Group:[/bold]  {group_name} ({req.group_id})")
        self._log(f"  [bold]Role:[/bold]   {req.requested_role}")
        if req.reason:
            self._log(f"  [bold]Reason:[/bold] {rich_escape(req.reason)}")
        self._log(
            f"  [bold]Action:[/bold] [bold cyan]/group approve {req.group_id} {req.device_id[:8]}[/bold cyan] "
            f"or [bold cyan]/group reject {req.group_id} {req.device_id[:8]}[/bold cyan]"
        )
        self._log("[bold yellow]╚════════════════════════════════════════════╝[/bold yellow]")

    async def _on_group_join_response(self, addr_key: str, message: dict) -> None:
        if self.group_store is None:
            return
        try:
            res = GroupJoinResponse.from_dict(message)
        except Exception as e:
            self._log(f"[dim]Ignored invalid group_join_response: {e}[/dim]")
            return

        if not res.approved:
            self._log(f"[red]✗ Join request for group '{res.group_id}' rejected: {res.reason or 'No reason provided'}[/red]")
            return

        group = self.group_store.get_group(res.group_id)
        if group is None:
            admin_pub = None
            peer = self.registry.get(res.admin_device_id)
            if peer and peer.public_key:
                admin_pub = peer.public_key
            else:
                p_by_addr = next((p for p in self.registry.list_peers() if f"{p.ip}:{p.tcp_port}" == addr_key), None)
                if p_by_addr and p_by_addr.public_key and compute_device_id(p_by_addr.public_key) == res.admin_device_id:
                    admin_pub = p_by_addr.public_key
            if admin_pub:
                pub_b64 = base64.b64encode(admin_pub).decode("ascii")
                self.group_store.create_group(Group(
                    group_id=res.group_id,
                    name=res.group_id,
                    admin_device_id=res.admin_device_id,
                    admin_public_key=pub_b64,
                    created_at=time.time(),
                ))

        try:
            self.group_store.process_join_response(res)
            self._log(f"[green]✓ Joined group [bold]{res.group_id}[/bold]! Membership certificate verified and recorded.[/green]")
        except Exception as e:
            self._log(f"[red]Failed to process join response: {e}[/red]")

    async def _on_group_leave_request(self, addr_key: str, message: dict) -> None:
        if self.group_store is None or self.my_identity is None:
            return
        try:
            req = GroupLeaveRequest.from_dict(message)
        except Exception as e:
            self._log(f"[dim]Ignored invalid group_leave_request: {e}[/dim]")
            return

        if not self.group_store.is_admin(req.group_id, self.peer_id):
            return

        cert = self.group_store.get_membership(req.group_id, req.device_id)
        if cert:
            if not verify_leave_request(req, base64.b64decode(cert.device_public_key)):
                self._log(f"[red][bold]SECURITY:[/bold] Invalid signature on leave request from {req.device_id[:8]}[/red]")
                return

        key = f"{req.group_id}:{req.device_id}"
        self._pending_leave_requests[key] = (addr_key, req)

        group = self.group_store.get_group(req.group_id)
        group_name = group.name if group else req.group_id
        peer = self.registry.get(req.device_id)
        sender_name = peer.name if peer else req.device_id[:8]

        self._log("[bold yellow]╔════════════ Group Leave Request ════════════╗[/bold yellow]")
        self._log(f"  [bold]From:[/bold]   {sender_name} ({req.device_id[:8]})")
        self._log(f"  [bold]Group:[/bold]  {group_name} ({req.group_id})")
        if req.reason:
            self._log(f"  [bold]Reason:[/bold] {rich_escape(req.reason)}")
        self._log(
            f"  [bold]Action:[/bold] [bold cyan]/group approve-leave {req.group_id} {req.device_id[:8]}[/bold cyan] "
            f"or [bold cyan]/group reject-leave {req.group_id} {req.device_id[:8]}[/bold cyan]"
        )
        self._log("[bold yellow]╚═════════════════════════════════════════════╝[/bold yellow]")

    async def _on_group_leave_response(self, addr_key: str, message: dict) -> None:
        if self.group_store is None:
            return
        try:
            res = GroupLeaveResponse.from_dict(message)
        except Exception as e:
            self._log(f"[dim]Ignored invalid group_leave_response: {e}[/dim]")
            return

        if not res.approved:
            self._log(f"[red]✗ Leave request for group '{res.group_id}' rejected: {res.reason or 'No reason provided'}[/red]")
            return

        try:
            self.group_store.process_leave_response(res)
            self._log(f"[green]✓ Leave approved for group '{res.group_id}'. Membership revoked.[/green]")
        except Exception as e:
            self._log(f"[red]Failed to apply leave response: {e}[/red]")

    async def _on_group_membership_revoke(self, addr_key: str, message: dict) -> None:
        if self.group_store is None:
            return
        try:
            revoc = MembershipRevocation.from_dict(message)
        except Exception as e:
            self._log(f"[dim]Ignored invalid group_membership_revoke: {e}[/dim]")
            return

        try:
            self.group_store.record_revocation(revoc)
            self._log(
                f"[bold red]SECURITY NOTICE:[/bold red] Membership in group '{revoc.group_id}' "
                f"was revoked by admin ({revoc.revoked_by[:8]}). Reason: {revoc.reason or 'None'}"
            )
        except Exception as e:
            self._log(f"[red]Failed to record revocation: {e}[/red]")

    async def _on_group_export_request(self, addr_key: str, message: dict) -> None:
        if self.group_store is None or self.my_identity is None:
            return
        try:
            req = ExportRequest.from_dict(message)
        except Exception as e:
            self._log(f"[dim]Ignored invalid group_export_request: {e}[/dim]")
            return
        if not verify_export_request(req):
            self._log(f"[red][bold]SECURITY:[/bold] Invalid signature on export request from {req.device_id[:8]}[/red]")
            return

        if not self.group_store.is_admin(req.group_id, self.peer_id):
            return

        key = f"{req.group_id}:{req.device_id}:{req.file_id}"
        self._pending_export_requests[key] = (addr_key, req)

        group = self.group_store.get_group(req.group_id)
        group_name = group.name if group else req.group_id
        peer = self.registry.get(req.device_id)
        sender_name = peer.name if peer else req.device_id[:8]

        self._log(f"[bold yellow]╔════════════ Group Export Request: {req.device_id[:8]} ════════════╗[/bold yellow]")
        self._log(f"  [bold]From:[/bold]   {sender_name} ({req.device_id[:8]})")
        self._log(f"  [bold]Group:[/bold]  {group_name} ({req.group_id})")
        self._log(f"  [bold]File:[/bold]   {req.file_id}")
        if req.reason:
            self._log(f"  [bold]Reason:[/bold] {rich_escape(req.reason)}")
        self._log(
            f"  [bold]Action:[/bold] [bold cyan]/group authorize-export {req.group_id} {req.device_id[:8]} {req.file_id}[/bold cyan]"
        )
        self._log("[bold yellow]╚══════════════════════════════════════════════════════════╝[/bold yellow]")

    async def _on_group_export_capability(self, addr_key: str, message: dict) -> None:
        if self.group_store is None:
            return
        try:
            cap = ExportCapability.from_dict(message)
        except Exception as e:
            self._log(f"[dim]Ignored invalid group_export_capability: {e}[/dim]")
            return

        try:
            self.group_store.store_capability(cap)
            rem = max(0, int(cap.expires_at - time.time()))
            self._log(
                f"[green]✓ Received Export Authorization for file [bold]{cap.file_id}[/bold] "
                f"in group '{cap.group_id}' (expires in {rem}s).[/green]"
            )
        except Exception as e:
            self._log(f"[red]Failed to store received export capability: {e}[/red]")


    def _perform_hard_lock(self) -> None:
        """Detach dependents, wipe DEK, flush+destroy the working copy.
        Does not show the unlock modal — caller handles that."""
        if self.vault_persistence is not None:
            self.vault_persistence.reattach(None)
        if self.trust_store is not None:
            self.trust_store.adopt_conn(None)
        if self.group_store is not None:
            self.group_store.adopt_conn(None)
        self.policy_enforcer = None
        if self.vault_session is not None and self.vault_session.is_unlocked:
            self.vault_session.lock()
        self.vault_db = None

    @work
    async def action_lock_vault(self) -> None:
        """Ctrl+L / /lock — lock now and re-prompt."""
        await self._lock_and_reprompt(reason="locked manually")

    @work
    async def _reunlock_work(self) -> None:
        """Worker entry for the unlock modal (push_screen_wait must run
        inside a Textual worker, not a bare asyncio task or input handler)."""
        await self._reunlock_vault()

    async def _lock_and_reprompt(self, reason: str = "locked") -> None:
        if self._relocking:
            return
        if self.vault_session is None or not self.vault_session.is_unlocked:
            # Already locked — just make sure the unlock modal is up.
            await self._reunlock_vault()
            return
        self._perform_hard_lock()
        self._log(f"[yellow]Vault {reason}. Enter passphrase to continue.[/yellow]")
        await self._reunlock_vault()

    async def _reunlock_vault(self) -> None:
        """Show the unlock modal and rewire TrustStore / persistence
        onto a freshly unlocked VaultDatabase."""
        if self._relocking:
            return
        self._relocking = True
        try:
            keyfile = load_vault_keyfile()
            dek = await self._unlock_vault_loop(keyfile)
            self.vault_db = VaultDatabase.unlock(dek)
            await self.vault_db.start_auto_flush()
            if self.vault_session is None:
                self.vault_session = VaultSession()
            self.vault_session.unlock(dek, self.vault_db)
            if self.trust_store is not None:
                self.trust_store.adopt_conn(self.vault_db.conn)
            if self.group_store is not None:
                self.group_store.adopt_conn(self.vault_db.conn)
                self.policy_enforcer = PolicyEnforcer(self.group_store)
            if self.trust_store is not None and self.group_store is not None:
                self.trust_store.set_group_store(self.group_store)
            if self.vault_persistence is not None:
                self.vault_persistence.reattach(self.vault_db)
            self._log("[green]Vault unlocked.[/green]")
        finally:
            self._relocking = False

    async def _auto_lock_loop(self) -> None:
        """Phase 39.3: poll idle expiry roughly once a second."""
        while True:
            await asyncio.sleep(AUTO_LOCK_POLL_SECONDS)
            if self._relocking:
                continue
            if self.vault_session is None or not self.vault_session.is_unlocked:
                continue
            if self.vault_session.idle_expired():
                # Hard-lock synchronously so the next poll doesn't
                # re-fire; the @work helper only owns the unlock modal.
                self._perform_hard_lock()
                self._log(
                    "[yellow]Vault auto-locked after idle timeout. "
                    "Enter passphrase to continue.[/yellow]"
                )
                self._reunlock_work()

    def _session_is_unlocked(self) -> bool:
        return bool(self.vault_session is not None and self.vault_session.is_unlocked)

    def copy_to_clipboard(self, text: str) -> None:
        """Copy text to clipboard using terminal escape sequences and system tools."""
        super().copy_to_clipboard(text)
        copy_to_system_clipboard(text)

    def action_copy_selection(self) -> None:
        """Explicit copy action for Ctrl+Shift+C."""
        selected = self.screen.get_selected_text()
        if selected:
            self.copy_to_clipboard(selected)
            preview = selected.strip()[:32] + ("..." if len(selected.strip()) > 32 else "")
            self.notify(f"Copied: {preview}", title="Clipboard", timeout=2)
        else:
            self.notify("No text selected to copy", title="Clipboard", timeout=1.5)

    def action_copy_or_quit(self) -> None:
        """Ctrl+C handler: copies selection if text is blocked, otherwise exits."""
        selected = self.screen.get_selected_text()
        if selected:
            self.copy_to_clipboard(selected)
            preview = selected.strip()[:32] + ("..." if len(selected.strip()) > 32 else "")
            self.notify(f"Copied: {preview}", title="Clipboard", timeout=2)
        else:
            self.exit()

    def action_clear_chat(self) -> None:
        self.query_one("#chat-log", SelectableRichLog).clear()
        self._log("[dim]Chat log cleared.[/dim]")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Switch active conversation when clicking a peer in the left sidebar."""
        self._touch_session()
        if event.item and event.item.name:
            self.active_peer_id = event.item.name
            peer = self.registry.get(event.item.name)
            target_name = peer.name if peer else event.item.name
            self._log(f"[cyan]Active peer -> {target_name}[/cyan]")
            self._refresh_peer_list()

    async def _on_network_message_handshake(self, evt: NetworkMessageReceived) -> None:
        msg_type = evt.message.get("type")
        addr_key = evt.addr_key
        ip = addr_key.rsplit(":", 1)[0]
        if msg_type == "hello":
            peer_id = evt.message.get("peer_id", "")
            sender_name = evt.message.get("sender_name", ip)
            tcp_port = evt.message.get("tcp_port", UI_TCP_PORT)
            if peer_id and peer_id != self.peer_id and self._verify_self_reported_id(addr_key, peer_id):
                self.registry.upsert(peer_id, sender_name, ip, tcp_port)
                self._refresh_peer_list()
                if self.active_peer_id is None:
                    self.active_peer_id = peer_id
                ack = protocol.make_hello_ack(self.peer_id, self.display_name, UI_TCP_PORT)
                await self.manager.send(addr_key, ack)
        elif msg_type == "hello_ack":
            peer_id = evt.message.get("peer_id", "")
            sender_name = evt.message.get("sender_name", ip)
            tcp_port = evt.message.get("tcp_port", UI_TCP_PORT)
            if peer_id and peer_id != self.peer_id and self._verify_self_reported_id(addr_key, peer_id):
                self.registry.upsert(peer_id, sender_name, ip, tcp_port)
                self._refresh_peer_list()
                if self.active_peer_id is None:
                    self.active_peer_id = peer_id
        elif msg_type == "group_join_request":
            await self._on_group_join_request(addr_key, evt.message)
        elif msg_type == "group_join_response":
            await self._on_group_join_response(addr_key, evt.message)
        elif msg_type == "group_leave_request":
            await self._on_group_leave_request(addr_key, evt.message)
        elif msg_type == "group_leave_response":
            await self._on_group_leave_response(addr_key, evt.message)
        elif msg_type == "group_membership_revoke":
            await self._on_group_membership_revoke(addr_key, evt.message)
        elif msg_type == "group_export_request":
            await self._on_group_export_request(addr_key, evt.message)
        elif msg_type == "group_export_capability":
            await self._on_group_export_capability(addr_key, evt.message)

    def _verify_self_reported_id(self, addr_key: str, claimed_peer_id: str) -> bool:
        """BUG-005: hello/hello_ack/chat messages carry a self-reported
        peer_id — before BUG-004, nothing proved the sender actually owned
        that identity, so a peer could claim to be anyone and get written
        straight into the registry. Now that every connection completed
        an authenticated handshake (Phase 6), cross-check the claim
        against the transport's own verified peer_device_id and refuse to
        register anything that doesn't match, rather than trusting the
        application-level message on its own."""
        authenticated_id = self.manager.get_peer_device_id(addr_key)
        if authenticated_id is None:
            return False  # no active session for this addr_key at all
        if claimed_peer_id != authenticated_id:
            self._log(
                f"[red][bold]SECURITY:[/bold] {addr_key} claimed peer_id "
                f"{claimed_peer_id[:8]}... but its authenticated handshake identity "
                f"is {authenticated_id[:8]}... — ignoring[/red]"
            )
            return False
        return True

    def _on_security_warning(self, evt: SecurityWarning) -> None:
        peer_info = f" (peer {evt.peer_id[:8]})" if evt.peer_id else ""
        color = "red" if evt.severity in ("HIGH", "CRITICAL") else "yellow"
        self._log(f"[{color}][bold]SECURITY {evt.severity}:[/bold] {evt.event_type}{peer_info}[/{color}]")

    def _on_trust_required(self, evt: TrustRequired) -> None:
        # BUG-004: the connection is already allowed to proceed (handshake.py
        # itself returns PENDING rather than rejecting) — this is a
        # notification, not a gate. A real approve/reject flow is Phase
        # 36/37, tracked separately in docs/ROADMAP.md; for now the user
        # just sees that a new, not-yet-trusted device connected.
        self._log(
            f"[yellow]New device seen for the first time: [bold]{evt.peer_name}[/bold] "
            f"({evt.peer_id[:8]}) — not yet trusted.[/yellow]"
        )

    async def _prune_ui_loop(self) -> None:
        while True:
            await asyncio.sleep(2.0)
            self._refresh_peer_list()

    def _refresh_peer_list(self) -> None:
        peer_list = self.query_one("#peer-list", ListView)
        peer_list.clear()
        peers = self.registry.list_peers()
        for peer in peers:
            is_active = (peer.peer_id == self.active_peer_id)
            marker = "[bold cyan]►[/bold cyan] " if is_active else "  "
            label = f"{marker}[bold]{peer.name}[/bold]\n  [dim]{peer.ip}:{peer.tcp_port}[/dim]"
            peer_list.append(ListItem(Label(label), name=peer.peer_id))

    def _on_peer_new(self, peer: discovery.Peer) -> None:
        self._log(f"[green]+ {peer.name} came online ({peer.ip})[/green]")
        self._refresh_peer_list()
        if self.active_peer_id is None:
            self.active_peer_id = peer.peer_id

    def _on_peer_lost(self, peer: discovery.Peer) -> None:
        self._log(f"[red]- {peer.name} went offline[/red]")
        self._refresh_peer_list()

    def _log(self, text: str) -> None:
        try:
            self.query_one("#chat-log", SelectableRichLog).write(text)
        except Exception:
            pass

    def _active_addr_key(self) -> Optional[str]:
        if self.active_peer_id is None:
            return None
        peer = self.registry.get(self.active_peer_id)
        if peer is None:
            return None
        return f"{peer.ip}:{peer.tcp_port}"

    async def _ensure_connected(self, addr_key: str) -> bool:
        if not self.manager.is_connected(addr_key):
            try:
                ip, port_str = addr_key.rsplit(":", 1)
                await self.manager.connect_to(ip, int(port_str))
                return True
            except Exception as e:
                self._log(f"[red]Connection error to {addr_key}: {e}[/red]")
                return False
        return True

    # ---- chat callbacks ----

    async def _on_chat_received(self, addr_key: str, message: dict) -> None:
        sender_id = message.get("sender_id", "")
        sender_name = message.get("sender_name", "peer")
        text = message.get("text", "")
        self._last_received_msg = text
        ip = addr_key.rsplit(":", 1)[0]
        if sender_id and sender_id != self.peer_id and self._verify_self_reported_id(addr_key, sender_id):
            self.registry.upsert(sender_id, sender_name, ip, UI_TCP_PORT)
            self._refresh_peer_list()
            if self.active_peer_id is None:
                self.active_peer_id = sender_id

        self._log(f"[bold green]<{rich_escape(sender_name)}>[/bold green] {rich_escape(text)}")

    def _on_status_change(self, message_id: str, status: str) -> None:
        mark = "delivered \u2713\u2713" if status == "delivered" else "failed \u2717"
        self._log(f"[dim]  ({mark})[/dim]")

    # ---- file transfer callbacks ----

    async def _on_offer_received(self, transfer_id: str, filename: str, size: int, sender_name: str) -> bool:
        self._log(f"[yellow]File offer from {rich_escape(sender_name)}: {rich_escape(filename)} ({size/1024:.1f} KB)[/yellow]")
        accepted = await self.push_screen_wait(FileOfferModal(sender_name, filename, size))
        self._log(f"[yellow]  -> {'accepted' if accepted else 'rejected'}[/yellow]")
        return bool(accepted)

    def _on_transfer_progress(self, transfer_id: str, done: int, total: int) -> None:
        pct = (done / total * 100) if total else 0
        self._log(f"[dim]  transfer {transfer_id[:8]}: {pct:.0f}%[/dim]")

    def _on_transfer_complete(self, transfer_id: str, success: bool, filepath: Optional[str]) -> None:
        if success:
            self._log(f"[green]File received: {filepath}[/green]")
        else:
            self._log(f"[red]File transfer {transfer_id[:8]} failed or was rejected[/red]")

    # ---- input handling ----

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        event.input.value = ""
        if not text:
            return

        # Phase 39.3: chat/commands need an unlocked session. Re-unlock
        # goes through a @work helper because push_screen_wait must run
        # inside a Textual worker (same reason _setup is @work).
        if not self._session_is_unlocked():
            if not self._relocking:
                self._reunlock_work()
            self._log("[yellow]Vault is locked — unlock to continue, then retry.[/yellow]")
            return
        self._touch_session()

        if text.startswith("/"):
            await self._handle_command(text)
            return

        addr_key = self._active_addr_key()
        if addr_key is None:
            self._log("[red]No active peer. Use /msg <name> or /connect <ip> to select one.[/red]")
            return

        connected = await self._ensure_connected(addr_key)
        if not connected:
            return

        await self.chat_session.send_chat(addr_key, self.peer_id, self.display_name, text)
        self._log(f"[bold cyan]<you>[/bold cyan] {text}")

    async def _handle_command(self, text: str) -> None:
        parts = text.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if cmd in ("/help", "/h"):
            self._log("[bold yellow]╔═══════════════════════ Commands ═══════════════════════╗[/bold yellow]")
            self._log(" [bold cyan]/connect <ip>[:port][/bold cyan]  Connect to peer IP (hotspot / AP fix)")
            self._log(" [bold cyan]/peers[/bold cyan]                List all discovered peers & status")
            self._log(" [bold cyan]/msg <name|id>[/bold cyan]        Switch active chat recipient")
            self._log(" [bold cyan]/send <filepath>[/bold cyan]      Offer a file to active peer")
            self._log(" [bold cyan]/name <new-name>[/bold cyan]      Change display name and re-announce")
            self._log(" [bold cyan]/copy [all|last][/bold cyan]      Copy chat log or last message")
            self._log(" [bold cyan]/clear[/bold cyan]                Clear chat log screen")
            self._log(" [bold cyan]/info[/bold cyan] or [bold cyan]/me[/bold cyan]           Show self identity & network details")
            self._log("[dim cyan]───────────────────── Vault & Security ──────────────────[/dim cyan]")
            self._log(" [bold cyan]/lock[/bold cyan]                 Lock vault now (Ctrl+L); re-prompt for passphrase")
            self._log(" [bold cyan]/autolock [minutes][/bold cyan]  Show/set idle auto-lock (default 5; 0 = off)")
            self._log(" [bold cyan]/criticalkey [action][/bold cyan] Manage optional Export extra key")
            self._log("[dim cyan]───────────────────── File Actions ──────────────────────[/dim cyan]")
            self._log(" [bold cyan]/files[/bold cyan]                List secure files")
            self._log(" [bold cyan]/open <file_id>[/bold cyan]       Open secure file (view-only)")
            self._log(" [bold cyan]/export <file_id>[/bold cyan]     Export secure file to plaintext")
            self._log(" [bold cyan]/secure <filepath>[/bold cyan]    Move local file to secure storage")
            self._log(" [bold cyan]/delete <file_id>[/bold cyan]     Delete secure file permanently")
            self._log("[dim cyan]───────────────────── Group Authority ───────────────────[/dim cyan]")
            self._log(" [bold cyan]/groups[/bold cyan]                 List all managed groups & memberships")
            self._log(" [bold cyan]/group create <name>[/bold cyan]   Create a new group (you become admin)")
            self._log(" [bold cyan]/group info [id][/bold cyan]       Show details and policy of a group")
            self._log(" [bold cyan]/group members [id][/bold cyan]    List members of a group")
            self._log(" [bold cyan]/group admins [id][/bold cyan]     List administrators of a group")
            self._log(" [bold cyan]/group join <id> [peer][/bold cyan] Send join request to active/named peer")
            self._log(" [bold cyan]/group leave <id>[/bold cyan]       Leave group or request leave")
            self._log(" [bold cyan]/group approve <id> <dev>[/bold cyan] (Admin) Approve pending join request")
            self._log(" [bold cyan]/group reject <id> <dev>[/bold cyan]  (Admin) Reject pending join request")
            self._log(" [bold cyan]/group revoke <id> <dev>[/bold cyan]  (Admin) Revoke member access")
            self._log(" [bold cyan]/group addadmin <id> <dev>[/bold cyan] (Admin) Add an administrator")
            self._log(" [bold cyan]/group policy <id> [k=v][/bold cyan] View or set group policy")
            self._log(" [bold cyan]/group audit <id> [limit][/bold cyan] (Admin) View signed audit log")
            self._log(" [bold cyan]/group req-export <id> <fid>[/bold cyan] Request admin authorization to export file")
            self._log(" [bold cyan]/group authorize-export <id> <dev>[/bold cyan] (Admin) Authorize device file export")
            self._log(" [bold cyan]/group caps [id][/bold cyan]         List active export capabilities")
            self._log("[dim cyan]────────────────────────────────────────────────────────[/dim cyan]")
            self._log(" [bold cyan]/quit[/bold cyan] or [bold cyan]/exit[/bold cyan]          Exit application")
            self._log("[bold yellow]╚═══════════════════════ Shortcuts ══════════════════════╝[/bold yellow]")
            self._log(" [dim]• Block text with mouse cursor, then press Ctrl+C or Ctrl+Shift+C to copy[/dim]")
            self._log(" [dim]• Click any peer in the sidebar to switch conversation[/dim]")
            self._log(" [dim]• Ctrl+C : Copy selected text (or quit if nothing selected)[/dim]")
            self._log(" [dim]• Ctrl+Shift+C : Copy selected text to clipboard[/dim]")
            self._log(" [dim]• Ctrl+L : Lock vault now[/dim]")
            self._log(" [dim]• Ctrl+Q : Quit peerc immediately[/dim]")
            self._log(" [dim]• Ctrl+K : Clear chat history[/dim]")

        elif cmd in ("/connect", "/add"):
            if not arg:
                self._log("[yellow]Usage: /connect <ip> or /connect <ip>:<port> (IPv6: /connect [::1]:5656)[/yellow]")
                return
            port = UI_TCP_PORT
            ip = arg
            # BUG-025: bare "colon in string means IPv4:port" breaks on any
            # IPv6 address (which is full of colons). Support the standard
            # "[addr]:port" bracket notation, and otherwise only treat a
            # single trailing ":port" as a port split — never split a raw
            # (unbracketed) IPv6 literal like fe80::1234.
            if arg.startswith("["):
                closing = arg.find("]")
                if closing != -1:
                    ip = arg[1:closing]
                    rest = arg[closing + 1:]
                    if rest.startswith(":") and rest[1:].isdigit():
                        port = int(rest[1:])
            elif arg.count(":") == 1:
                # Exactly one colon: unambiguous "ipv4:port" (IPv6 addresses
                # always have 2+ colons, so this never misfires on those).
                ip_part, port_str = arg.rsplit(":", 1)
                if port_str.isdigit():
                    ip = ip_part
                    port = int(port_str)
            # arg.count(":") >= 2 and no brackets -> treat as a bare IPv6
            # address with no port, matching the /connect [IPv6]:port fix
            # recommended in the bug report.

            self._log(f"[cyan]Connecting to {ip}:{port}...[/cyan]")
            # 1. Send immediate UDP discovery probe
            self._discovery.probe_peer(ip)

            # 2. Establish TCP connection
            try:
                addr_key = await self.manager.connect_to(ip, port)
                # 3. Send hello handshake
                hello = protocol.make_hello(self.peer_id, self.display_name, UI_TCP_PORT)
                await self.manager.send(addr_key, hello)

                # 4. Upsert temporary peer entry if not already present
                existing = next((p for p in self.registry.list_peers() if p.ip == ip), None)
                if not existing:
                    manual_id = f"peer-{ip}"
                    self.registry.upsert(manual_id, f"Peer ({ip})", ip, port)
                    self.active_peer_id = manual_id
                else:
                    self.active_peer_id = existing.peer_id

                self._refresh_peer_list()
                self._log(f"[green]✓ Connected to {ip}:{port}! Active peer set.[/green]")
            except Exception as e:
                self._log(f"[red]Failed to connect to {ip}:{port}: {e}[/red]")

        elif cmd == "/peers":
            peers = self.registry.list_peers()
            if not peers:
                self._log("[yellow]No peers currently detected. Use /connect <ip> to connect directly.[/yellow]")
            else:
                self._log("[bold yellow]Discovered peers:[/bold yellow]")
                for p in peers:
                    active = " [bold cyan](ACTIVE)[/bold cyan]" if p.peer_id == self.active_peer_id else ""
                    device = f" · {rich_escape(p.model)}" if p.model else ""
                    self._log(f"  • [bold]{p.name}[/bold]{device} (id: {p.peer_id[:8]}) at {p.ip}:{p.tcp_port}{active}")

        elif cmd == "/msg":
            if not arg:
                self._log("[yellow]Usage: /msg <name-or-id-prefix>[/yellow]")
                return
            match = next(
                (p for p in self.registry.list_peers()
                 if arg.lower() in p.name.lower() or p.peer_id.startswith(arg)),
                None,
            )
            if match:
                self.active_peer_id = match.peer_id
                self._log(f"[cyan]Active peer -> {match.name}[/cyan]")
                self._refresh_peer_list()
            else:
                self._log(f"[red]No peer matching '{arg}'[/red]")

        elif cmd == "/send":
            if not arg or not os.path.isfile(arg):
                self._log(f"[red]File not found: {arg}[/red]")
                return
            addr_key = self._active_addr_key()
            if addr_key is None:
                self._log("[red]No active peer. Use /msg <name> or /connect <ip> first.[/red]")
                return
            connected = await self._ensure_connected(addr_key)
            if not connected:
                return
            transfer_id = await self.file_session.offer_file(addr_key, arg)
            if transfer_id is None:
                self._log(f"[red]Could not offer {os.path.basename(arg)}: not connected[/red]")
                return
            self._log(f"[cyan]Offered {os.path.basename(arg)} ({transfer_id[:8]})[/cyan]")

        elif cmd == "/name":
            if not arg:
                self._log(f"[yellow]Current name: {rich_escape(self.display_name)}. Usage: /name <new_name>[/yellow]")
                return

            ok, error = validate_display_name(arg)
            if not ok:
                self._log(f"[red]{error}[/red]")
                return

            old_name = self.display_name
            self.display_name = arg
            self.title = f"peerc — {self.display_name} (id: {self.peer_id[:8]})"
            self._discovery.name = arg
            discovery.save_identity(self.peer_id, arg)
            self._discovery.broadcast_now()
            self._log(f"[green]Name changed from '{rich_escape(old_name)}' to '{rich_escape(arg)}'[/green]")

        elif cmd == "/copy":
            log_widget = self.query_one("#chat-log", SelectableRichLog)
            if arg == "all":
                all_text = "\n".join(strip.text.rstrip() for strip in log_widget.lines)
                if all_text:
                    self.copy_to_clipboard(all_text)
                    self._log("[green]Copied all chat history to clipboard![/green]")
                    self.notify("All chat history copied!", title="Clipboard")
                else:
                    self._log("[yellow]Chat log is empty.[/yellow]")
            else:
                if self._last_received_msg:
                    self.copy_to_clipboard(self._last_received_msg)
                    self._log(f"[green]Copied last message: '{self._last_received_msg}'[/green]")
                    self.notify(f"Copied: {self._last_received_msg[:20]}", title="Clipboard")
                else:
                    # Try copying last line of log
                    if log_widget.lines:
                        last_line = log_widget.lines[-1].text.strip()
                        self.copy_to_clipboard(last_line)
                        self._log(f"[green]Copied: '{last_line}'[/green]")
                        self.notify("Copied last line!", title="Clipboard")
                    else:
                        self._log("[yellow]No message to copy.[/yellow]")

        elif cmd in ("/clear", "/cls"):
            self.action_clear_chat()

        elif cmd in ("/info", "/me"):
            net = discovery.get_network_info()
            ips_str = ", ".join(net.get("local_ips", [])) or "unknown"
            targets_str = ", ".join(net.get("targets", []))
            self._log("[bold yellow]╔════════════════════ Self Info ════════════════════╗[/bold yellow]")
            self._log(f"  [bold]Name:[/bold]       {self.display_name}")
            self._log(f"  [bold]Device:[/bold]     {self.device_model}")
            self._log(f"  [bold]Peer ID:[/bold]    {self.peer_id}")
            self._log(f"  [bold]TCP Port:[/bold]   {UI_TCP_PORT}")
            self._log(f"  [bold]UDP Port:[/bold]   {discovery.BROADCAST_PORT}")
            self._log(f"  [bold]Local IPs:[/bold]  {ips_str}")
            self._log(f"  [bold]Broadcasts:[/bold] {targets_str}")
            active_peer = self.registry.get(self.active_peer_id) if self.active_peer_id else None
            active_str = f"{active_peer.name} ({active_peer.ip})" if active_peer else "None"
            self._log(f"  [bold]Active Peer:[/bold]{active_str}")
            if self.vault_session is not None:
                if self.vault_session.auto_lock_seconds == 0:
                    lock_str = "disabled"
                else:
                    mins = self.vault_session.auto_lock_seconds / 60.0
                    remaining = self.vault_session.seconds_until_lock()
                    rem_str = f", {remaining:.0f}s left" if remaining is not None else ""
                    lock_str = f"{mins:g} min idle{rem_str}"
                self._log(f"  [bold]Auto-lock:[/bold]  {lock_str}")
                self._log(
                    f"  [bold]Vault:[/bold]      "
                    f"{'unlocked' if self.vault_session.is_unlocked else 'locked'}"
                )
                self._log(
                    f"  [bold]Export key:[/bold] "
                    f"{self._critical_key_status_text()}"
                )
            self._log("[bold yellow]╚═══════════════════════════════════════════════════╝[/bold yellow]")

        elif cmd == "/lock":
            self.action_lock_vault()

        elif cmd == "/autolock":
            if self.vault_session is None or not self.vault_session.is_unlocked:
                self._log("[red]Vault is locked — unlock first.[/red]")
                return
            if not arg:
                secs = self.vault_session.auto_lock_seconds
                if secs == 0:
                    self._log("[cyan]Auto-lock is disabled (0). /autolock <minutes> to enable.[/cyan]")
                else:
                    self._log(
                        f"[cyan]Auto-lock after {secs / 60.0:g} minutes idle "
                        f"({secs:g}s). Default is {DEFAULT_AUTO_LOCK_SECONDS / 60.0:g}.[/cyan]"
                    )
                return
            try:
                minutes = float(arg)
            except ValueError:
                self._log("[yellow]Usage: /autolock [minutes]  (0 disables auto-lock)[/yellow]")
                return
            if minutes < 0:
                self._log("[yellow]Minutes must be >= 0.[/yellow]")
                return
            self.vault_session.set_auto_lock_seconds(minutes * 60.0)
            if minutes == 0:
                self._log("[green]Auto-lock disabled. /lock still works.[/green]")
            else:
                self._log(f"[green]Auto-lock set to {minutes:g} minute(s) idle.[/green]")

        elif cmd == "/criticalkey":
            await self._handle_critical_key_command(arg)

        elif cmd == "/files":
            await self._handle_list_files()

        elif cmd == "/open":
            await self._handle_open_file(arg)

        elif cmd == "/export":
            await self._handle_export_file(arg)

        elif cmd == "/secure":
            await self._handle_move_to_secure(arg)

        elif cmd == "/delete":
            await self._handle_delete_file(arg)

        elif cmd in ("/groups", "/group"):
            await self._handle_group_command(arg)

        elif cmd in ("/quit", "/exit", "/q"):
            self.exit()

        else:
            self._log(f"[red]Unknown command: {cmd}. Type /help for command list.[/red]")


def main() -> None:
    """CLI entrypoint for peerc."""
    ChatApp().run()


if __name__ == "__main__":
    main()
