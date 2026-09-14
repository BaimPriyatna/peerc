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
    /nick <new-name>                change display name and re-announce
    /copy [last|all]                copy chat to system clipboard
    /clear                          clear chat log
    /info or /me                    show local identity and network details
    /quit or /exit                  quit peerc

Cursor & Mouse:
    - Click and drag text in the chat log to select/block text.
    - Press Ctrl+C or Ctrl+Shift+C to copy selected text to clipboard.
    - Ctrl+Q quits immediately.
    - Click any peer in the sidebar list to switch conversation target.
"""

import asyncio
import os
import shutil
import subprocess
from typing import Optional

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
from core.events import (
    EventBus,
    NetworkMessageReceived,
    SecurityWarning,
    TrustRequired,
    bridge_security_events,
)
import core.identity as identity
import discovery
import file_transfer
import protocol
from core.trust.store import DEFAULT_DB_PATH as TRUST_DB_LEGACY_PATH
from core.trust.store import TrustStore
from core.vault import (
    RecoveryCodeError,
    VaultDatabase,
    VaultExistsError,
    VaultPersistence,
    WrongSecretError,
    create_vault,
    load_vault_keyfile,
    migrate_plaintext_trust_db,
    unlock_with_passphrase,
    unlock_with_recovery_code,
    vault_exists,
)
from peer import ConnectionManager

UI_TCP_PORT = 5656


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
    ]

    def __init__(self):
        super().__init__()
        self.peer_id: str = ""
        self.display_name: str = ""
        self.public_key_bytes: bytes = b""
        self.my_identity = None  # DeviceKeypair, set in on_mount (BUG-004)
        self.trust_store: Optional[TrustStore] = None
        self.vault_db = None  # VaultDatabase, set in on_mount (Phase 39.2)
        self.vault_persistence = None  # VaultPersistence, set in on_mount (Phase 39.2)
        self.registry: Optional[discovery.PeerRegistry] = None
        self.event_bus: Optional[EventBus] = None
        self._unhook_security_events = None
        self.manager: Optional[ConnectionManager] = None
        self.chat_session: Optional[chat.ChatSession] = None
        self.file_session: Optional[file_transfer.FileTransferSession] = None
        self.active_peer_id: Optional[str] = None
        self._last_received_msg: str = ""

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
        self.title = f"peerc — {self.display_name} ({self.peer_id[:8]})"

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

        # BUG-004 (v1.15.1) / Phase 39.2: TrustStore now shares the
        # vault's own connection — its trusted_devices/identity_transitions
        # rows live inside the encrypted vault file, not a separate
        # plaintext trust.db (which migrate_plaintext_trust_db() above
        # just retired if one existed).
        self.trust_store = TrustStore(conn=self.vault_db.conn)

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
            public_key=self.public_key_bytes,
        )
        asyncio.create_task(self._discovery.run())
        asyncio.create_task(self._prune_ui_loop())

        log = self.query_one("#chat-log", SelectableRichLog)
        log.write(f"[bold cyan]Started as {self.display_name} ({self.peer_id[:8]})[/bold cyan]")
        log.write("Waiting for peers... use [bold yellow]/help[/bold yellow] for commands.")
        log.write("[dim]Tip: Drag mouse over text to block/select. Press Ctrl+C or Ctrl+Shift+C to copy. Press Ctrl+Q to quit.[/dim]")

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
        # Phase 39.2: flush and destroy the plaintext working copy on
        # exit — leaving it around defeats the point of the whole
        # unlock/lock lifecycle.
        if self.vault_db is not None:
            self.vault_db.lock()

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
            self._log(" [bold cyan]/nick <new-name>[/bold cyan]      Change display name and re-announce")
            self._log(" [bold cyan]/copy [all|last][/bold cyan]      Copy chat log or last message")
            self._log(" [bold cyan]/clear[/bold cyan]                Clear chat log screen")
            self._log(" [bold cyan]/info[/bold cyan] or [bold cyan]/me[/bold cyan]           Show self identity & network details")
            self._log(" [bold cyan]/quit[/bold cyan] or [bold cyan]/exit[/bold cyan]          Exit application")
            self._log("[bold yellow]╚═══════════════════════ Shortcuts ══════════════════════╝[/bold yellow]")
            self._log(" [dim]• Block text with mouse cursor, then press Ctrl+C or Ctrl+Shift+C to copy[/dim]")
            self._log(" [dim]• Click any peer in the sidebar to switch conversation[/dim]")
            self._log(" [dim]• Ctrl+C : Copy selected text (or quit if nothing selected)[/dim]")
            self._log(" [dim]• Ctrl+Shift+C : Copy selected text to clipboard[/dim]")
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
                    self._log(f"  • [bold]{p.name}[/bold] ({p.peer_id[:8]}) at {p.ip}:{p.tcp_port}{active}")

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

        elif cmd == "/nick":
            if not arg:
                self._log(f"[yellow]Current nickname: {rich_escape(self.display_name)}. Usage: /nick <new_name>[/yellow]")
                return

            # BUG-020: nickname was previously accepted verbatim — no length
            # cap, no control-character/newline check — before being stored
            # and broadcast to every peer on the LAN.
            if any(ord(c) < 0x20 or ord(c) == 0x7f for c in arg):
                self._log("[red]Nickname cannot contain control characters or newlines.[/red]")
                return
            if len(arg) > 32:
                self._log("[red]Nickname too long (max 32 characters).[/red]")
                return

            old_name = self.display_name
            self.display_name = arg
            self.title = f"peerc — {self.display_name} ({self.peer_id[:8]})"
            self._discovery.name = arg
            discovery.save_identity(self.peer_id, arg)
            self._discovery.broadcast_now()
            self._log(f"[green]Nickname changed from '{rich_escape(old_name)}' to '{rich_escape(arg)}'[/green]")

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
            self._log(f"  [bold]Peer ID:[/bold]    {self.peer_id}")
            self._log(f"  [bold]TCP Port:[/bold]   {UI_TCP_PORT}")
            self._log(f"  [bold]UDP Port:[/bold]   {discovery.BROADCAST_PORT}")
            self._log(f"  [bold]Local IPs:[/bold]  {ips_str}")
            self._log(f"  [bold]Broadcasts:[/bold] {targets_str}")
            active_peer = self.registry.get(self.active_peer_id) if self.active_peer_id else None
            active_str = f"{active_peer.name} ({active_peer.ip})" if active_peer else "None"
            self._log(f"  [bold]Active Peer:[/bold]{active_str}")
            self._log("[bold yellow]╚═══════════════════════════════════════════════════╝[/bold yellow]")

        elif cmd in ("/quit", "/exit", "/q"):
            self.exit()

        else:
            self._log(f"[red]Unknown command: {cmd}. Type /help for command list.[/red]")


def main() -> None:
    """CLI entrypoint for peerc."""
    ChatApp().run()


if __name__ == "__main__":
    main()