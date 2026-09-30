"""app/ui/modals/identity.py — identity, trust, and security-event modals (Phase 38).

Name setup, the Trust Center and its confirm / prompt / device-detail
screens, and the grouped security-event viewer, with their display helpers.
"""

from typing import TYPE_CHECKING, Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, ListItem, ListView

from core.security.events import SecurityEvent, SecuritySeverity
from core.events import TrustRequired
from core.trust.device import TrustedDevice, TrustStatus
from core.identity.fingerprint import format_fingerprint, short_fingerprint

if TYPE_CHECKING:
    from app.ui.app import ChatApp


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


def _format_relative_time(ts: float) -> str:
    """Human-readable relative timestamp — 'just now', '3 min ago', etc."""
    import time as _time
    delta = _time.time() - ts
    if delta < 60:
        return "just now"
    if delta < 3600:
        m = int(delta / 60)
        return f"{m} min ago"
    if delta < 86400:
        h = int(delta / 3600)
        return f"{h}h ago"
    d = int(delta / 86400)
    return f"{d}d ago"


def _format_severity_label(severity: "SecuritySeverity | str") -> str:
    """Phase 37.2: text severity labels (no emoji) for the Events view."""
    name = severity.value if isinstance(severity, SecuritySeverity) else str(severity)
    if name == "INFO":
        return "[dim]INFO[/]"
    if name == "WARNING":
        return "[yellow]WARN[/]"
    if name == "HIGH":
        return "[red]HIGH[/]"
    if name == "CRITICAL":
        return "[bold red]CRIT[/]"
    return name


def _group_security_events(events: list[SecurityEvent]) -> list[SecurityEvent]:
    """Group by (event_type, device_id), keeping the latest timestamp per group."""
    best: dict[tuple[str, str], SecurityEvent] = {}
    for ev in events:
        key = (ev.event_type, ev.device_id or "")
        prev = best.get(key)
        if prev is None or ev.timestamp >= prev.timestamp:
            best[key] = ev
    return sorted(best.values(), key=lambda e: e.timestamp, reverse=True)


class TrustCenterModal(ModalScreen[None]):
    """Phase 36.1: Read-only Trust Center — lists all known devices with
    status filters (All / Pending / Trusted / Revoked).  A device row can
    be clicked to open TrustDeviceDetailModal for the full fingerprint and
    metadata.  Actions (Trust/Reject/Revoke) are added in Phase 36.2
    (1.20.1); this sub-step is deliberately read-only.

    Vault-locked guard: if trust_store is None when this modal is
    composing, it shows a 'Vault is locked' message and a Close button.
    """

    # Internal filter: None = all, or a TrustStatus
    def __init__(self, filter_status: "Optional[TrustStatus]" = None) -> None:
        super().__init__()
        self._filter = filter_status
        self._devices: list[TrustedDevice] = []

    def compose(self) -> ComposeResult:
        title = "Trust Center — "
        if self._filter is None:
            title += "All Devices"
        else:
            title += self._filter.value.capitalize() + " Devices"
        with Vertical(id="trust-center-dialog"):
            yield Label(f"[bold]{title}[/bold]")
            with Horizontal(id="trust-center-filter"):
                yield Button("All", id="tc-filter-all", variant="primary" if self._filter is None else "default")
                yield Button("⏳ Pending", id="tc-filter-pending",
                             variant="warning" if self._filter == TrustStatus.PENDING else "default")
                yield Button("✓ Trusted", id="tc-filter-trusted",
                             variant="success" if self._filter == TrustStatus.TRUSTED else "default")
                yield Button("✗ Revoked", id="tc-filter-revoked",
                             variant="error" if self._filter == TrustStatus.REVOKED else "default")
            yield ListView(id="trust-center-list")
            yield Label("", id="trust-center-empty")
            yield Button("Close", id="tc-close")

    def on_mount(self) -> None:
        self._load_devices()

    def _load_devices(self) -> None:
        app: ChatApp = self.app  # type: ignore[assignment]
        list_view = self.query_one("#trust-center-list", ListView)
        empty_label = self.query_one("#trust-center-empty", Label)
        list_view.clear()

        if app.trust_store is None:
            empty_label.update("[red]Vault is locked — unlock to view devices.[/red]")
            return

        try:
            self._devices = app.trust_store.list_all(status=self._filter)
        except Exception:
            empty_label.update("[red]Could not read trust store.[/red]")
            return

        if not self._devices:
            filter_name = (self._filter.value.lower() + " ") if self._filter else ""
            empty_label.update(f"[dim]No {filter_name}devices.[/dim]")
            return

        empty_label.update("")
        for dev in self._devices:
            if dev.status == TrustStatus.PENDING:
                icon = "[yellow]⏳[/yellow]"
            elif dev.status == TrustStatus.TRUSTED:
                icon = "[green]✓[/green]"
            else:
                icon = "[red]✗[/red]"
            last = _format_relative_time(dev.last_seen)
            label = (
                f"{icon} [bold]{dev.name}[/bold]  "
                f"[dim]{dev.device_id[:8]}[/dim]  "
                f"[dim]{dev.status.value}[/dim]  "
                f"[dim]last seen {last}[/dim]"
            )
            list_view.append(ListItem(Label(label), name=dev.device_id))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        if btn == "tc-close":
            self.dismiss()
            return
        if btn == "tc-filter-all":
            self._filter = None
        elif btn == "tc-filter-pending":
            self._filter = TrustStatus.PENDING
        elif btn == "tc-filter-trusted":
            self._filter = TrustStatus.TRUSTED
        elif btn == "tc-filter-revoked":
            self._filter = TrustStatus.REVOKED
        # Refresh filter buttons styling by re-composing is complex;
        # instead just reload the list; user sees the result immediately.
        self._load_devices()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Open device detail when a row is clicked/selected."""
        device_id = event.item.name
        if device_id is None:
            return
        app: ChatApp = self.app  # type: ignore[assignment]
        if app.trust_store is None:
            return
        dev = app.trust_store.get(device_id)
        if dev is None:
            return
        self.app.push_screen(TrustDeviceDetailModal(dev))


class TrustConfirmModal(ModalScreen["Optional[str]"]):
    """Phase 36.2: Confirmation gate before a trust decision writes to the
    store. Dismisses with a reason string (empty string OK — 'no reason
    given') on confirm, or None on cancel.

    action:
      - "trust"  — approve a PENDING device; no reason field, just a
        restated name/fingerprint to confirm against.
      - "revoke" / "reject" — same underlying local-revoke action
        (revoke_device()), different verb depending on the device's
        current state; shows an optional free-text reason Input,
        pre-filled empty per the design doc.
    """

    def __init__(self, device: TrustedDevice, action: str, initial_reason: str = "") -> None:
        super().__init__()
        self._device = device
        self._action = action
        self._initial_reason = initial_reason

    def compose(self) -> ComposeResult:
        dev = self._device
        with Vertical(id="trust-confirm-dialog"):
            if self._action == "trust":
                yield Label("[bold]Trust this device?[/bold]")
                yield Label(f"Name: {dev.name}")
                yield Label(f"Fingerprint: {format_fingerprint(dev.device_id)}")
                with Horizontal(id="trust-confirm-actions"):
                    yield Button("Trust", id="tcm-confirm", variant="success")
                    yield Button("Cancel", id="tcm-cancel")
            else:
                verb = "Revoke" if self._action == "revoke" else "Reject"
                yield Label(f"[bold]{verb} this device?[/bold]")
                yield Label(
                    "This change is local. Future handshakes from this "
                    "device will be rejected."
                )
                yield Label("Reason (optional):")
                yield Input(value=self._initial_reason, placeholder="reason", id="tcm-reason")
                with Horizontal(id="trust-confirm-actions"):
                    yield Button("Confirm", id="tcm-confirm", variant="error")
                    yield Button("Cancel", id="tcm-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "tcm-cancel":
            self.dismiss(None)
        elif event.button.id == "tcm-confirm":
            if self._action == "trust":
                self.dismiss("")
            else:
                reason = self.query_one("#tcm-reason", Input).value.strip()
                self.dismiss(reason)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if self._action != "trust":
            self.dismiss(event.value.strip())


class TrustDeviceDetailModal(ModalScreen[None]):
    """Phase 36.1/36.2: Detail view for a single trusted/pending/revoked
    device. Shows full device_id, public-key fingerprint (derived from
    device_id as SHA256 of pubkey), first/last seen, status, and revocation
    metadata. A 'Copy Fingerprint' control lets the user copy it for an
    out-of-band comparison.

    Phase 36.2 adds the decision controls themselves: a PENDING device
    gets Trust/Reject buttons, a TRUSTED device gets Revoke, and a
    REVOKED device stays view-only (Close). Each action opens
    TrustConfirmModal before writing to the store, then refreshes this
    view in place against the updated record.
    """

    def __init__(self, device: TrustedDevice) -> None:
        super().__init__()
        self._device = device

    def compose(self) -> ComposeResult:
        with Vertical(id="trust-detail-dialog"):
            yield from self._render_body()

    def _render_body(self) -> ComposeResult:
        dev = self._device
        full_fp = format_fingerprint(dev.device_id)

        if dev.status == TrustStatus.PENDING:
            status_label = "[yellow]⏳ PENDING[/yellow] — awaiting your approval"
        elif dev.status == TrustStatus.TRUSTED:
            status_label = "[green]✓ TRUSTED[/green] — identity verified and approved"
        else:
            status_label = "[red]✗ REVOKED[/red] — future handshakes rejected"

        yield Label(f"[bold]Device: {dev.name}[/bold]")
        yield Label(f"Status: {status_label}")
        yield Label(f"Device ID:  [dim]{dev.device_id}[/dim]")
        yield Label("Fingerprint (for out-of-band comparison):")
        yield Label(full_fp, id="trust-detail-fingerprint")
        yield Label(
            f"First seen: {_format_relative_time(dev.first_seen)}  "
            f"| Last seen: {_format_relative_time(dev.last_seen)}"
        )
        if dev.status == TrustStatus.REVOKED and dev.revoked_by:
            yield Label(
                f"Revoked by: {dev.revoked_by}"
                + (f"  Reason: {dev.revoke_reason}" if dev.revoke_reason else "")
            )
        yield from self._render_rotation_section()
        with Horizontal(id="trust-detail-actions"):
            yield Button("Copy Fingerprint", id="td-copy-fp")
            if dev.status == TrustStatus.PENDING:
                yield Button("Trust", id="td-trust", variant="success")
                yield Button("Reject", id="td-reject", variant="error")
            elif dev.status == TrustStatus.TRUSTED:
                yield Button("Revoke", id="td-revoke", variant="error")
            yield Button("Close", id="td-close")

    def _render_rotation_section(self) -> ComposeResult:
        """Phase 37.2: read-only rotation chain (omit if no history)."""
        app = getattr(self, "app", None)
        store = getattr(app, "trust_store", None) if app is not None else None
        if store is None:
            return
        try:
            chain = store.get_rotation_chain(self._device.device_id)
        except Exception:
            return
        if len(chain) <= 1:
            return

        statuses = {nid: store.get(nid) for nid in chain}
        tainted = any(
            d is not None and d.status == TrustStatus.REVOKED
            for d in statuses.values()
        )
        parts: list[str] = []
        for nid in chain:
            short = nid[:8]
            node = statuses.get(nid)
            if node is not None and node.status == TrustStatus.REVOKED:
                parts.append(f"[red]{short}[/red]")
            else:
                parts.append(f"[dim]{short}[/dim]")
        yield Label("Rotation history:", id="td-rotation-label")
        yield Label(" → ".join(parts), id="td-rotation-chain")
        if tainted:
            yield Label(
                "[red]Chain tainted — revoked ancestor present[/red]",
                id="td-rotation-taint",
            )

    async def _refresh(self, app: "ChatApp") -> None:
        """Re-fetch the device from the store and re-render this view in
        place. If the vault locked mid-flow or the device somehow
        vanished, just close rather than show a stale/broken view."""
        if app.trust_store is None:
            self.dismiss()
            return
        updated = app.trust_store.get(self._device.device_id)
        if updated is None:
            self.dismiss()
            return
        self._device = updated
        container = self.query_one("#trust-detail-dialog", Vertical)
        await container.remove_children()
        await container.mount_all(list(self._render_body()))

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        if btn == "td-close":
            self.dismiss()
            return
        if btn == "td-copy-fp":
            full_fp = format_fingerprint(self._device.device_id)
            self.app.copy_to_clipboard(full_fp)
            self.notify("Fingerprint copied to clipboard.", title="Copied")
            return

        app: ChatApp = self.app  # type: ignore[assignment]
        if btn == "td-trust":
            result = await app.push_screen_wait(TrustConfirmModal(self._device, "trust"))
            if result is None:
                return
            await app._do_trust_approve(self._device.device_id)
            await self._refresh(app)
        elif btn == "td-reject":
            result = await app.push_screen_wait(TrustConfirmModal(self._device, "reject"))
            if result is None:
                return
            await app._do_trust_revoke(self._device.device_id, result or None)
            await self._refresh(app)
        elif btn == "td-revoke":
            result = await app.push_screen_wait(TrustConfirmModal(self._device, "revoke"))
            if result is None:
                return
            await app._do_trust_revoke(self._device.device_id, result or None)
            await self._refresh(app)


class TrustPromptModal(ModalScreen[None]):
    """Phase 37.1: Event-driven pending prompt for unverified devices.

    Displays device name, short peer ID, abbreviated fingerprint,
    full fingerprint reveal/copy controls, and observed connection route
    (untrusted reachability info). Provides Trust, Reject, and Later actions.
    """

    def __init__(self, evt: TrustRequired) -> None:
        super().__init__()
        self.evt = evt
        self._revealed = False

    def compose(self) -> ComposeResult:
        peer_id = self.evt.peer_id
        short_id = peer_id[:8] if peer_id else "unknown"
        try:
            short_fp = short_fingerprint(peer_id) if peer_id else ""
            full_fp = format_fingerprint(peer_id) if peer_id else ""
        except Exception:
            short_fp = peer_id[:16] if peer_id else ""
            full_fp = peer_id
        route = self.evt.addr_key if self.evt.addr_key else "unknown"

        with Vertical(id="trust-prompt-dialog"):
            yield Label("[bold]Trust Required: New Device Seen[/bold]", id="tpm-title")
            yield Label(f"Device Name: [bold]{self.evt.peer_name}[/bold]", id="tpm-name")
            yield Label(f"Device ID: [dim]{short_id}[/dim]", id="tpm-id")
            yield Label(f"Fingerprint: {short_fp}", id="tpm-short-fp")
            yield Label(full_fp, id="tpm-full-fp")
            with Horizontal(id="tpm-fp-actions"):
                yield Button("Reveal Full Fingerprint", id="tpm-reveal-fp")
                yield Button("Copy Fingerprint", id="tpm-copy-fp")
            yield Label(
                f"Observed connection route: {route}\n"
                "[dim italic](untrusted reachability info, not for identity verification)[/dim italic]",
                id="tpm-route",
            )
            with Horizontal(id="trust-prompt-actions"):
                yield Button("Trust", id="tpm-trust", classes="trust", variant="success")
                yield Button("Reject", id="tpm-reject", classes="reject", variant="error")
                yield Button("Later", id="tpm-later", classes="later")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        if btn == "tpm-copy-fp":
            try:
                full_fp = format_fingerprint(self.evt.peer_id)
            except Exception:
                full_fp = self.evt.peer_id
            if hasattr(self.app, "copy_to_clipboard"):
                self.app.copy_to_clipboard(full_fp)
            self.notify("Fingerprint copied to clipboard.", title="Copied")
            return
        if btn == "tpm-reveal-fp":
            self._revealed = not self._revealed
            fp_label = self.query_one("#tpm-full-fp", Label)
            fp_label.styles.display = "block" if self._revealed else "none"
            event.button.label = "Hide Full Fingerprint" if self._revealed else "Reveal Full Fingerprint"
            return

        app = self.app
        if btn in ("tpm-trust", "trust"):
            if hasattr(app, "_do_trust_approve"):
                await app._do_trust_approve(self.evt.peer_id)
            self.dismiss()
        elif btn in ("tpm-reject", "reject"):
            if hasattr(app, "_do_trust_revoke"):
                await app._do_trust_revoke(self.evt.peer_id, reason=None)
            self.dismiss()
        elif btn in ("tpm-later", "later"):
            self.dismiss()


class SecurityEventsModal(ModalScreen[None]):
    """Phase 37.2: Read-only Security Events view.

    Groups buffered SecurityEvent entries by (event_type, device_id),
    keeps the latest timestamp per group, and links known device_ids to
    TrustDeviceDetailModal. Informational only — no approve/reject actions.
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="security-events-dialog"):
            yield Label("[bold]Security Events[/bold]", id="se-title")
            yield Label(
                "[dim]Grouped by type + device (latest only). Read-only.[/dim]",
                id="se-subtitle",
            )
            yield ListView(id="security-events-list")
            yield Label("", id="security-events-empty")
            yield Button("Close", id="se-close")

    def on_mount(self) -> None:
        self._load_events()

    def _load_events(self) -> None:
        app: ChatApp = self.app  # type: ignore[assignment]
        list_view = self.query_one("#security-events-list", ListView)
        empty_label = self.query_one("#security-events-empty", Label)
        list_view.clear()

        raw = getattr(app, "_security_event_log", None) or []
        grouped = _group_security_events(list(raw))
        if not grouped:
            empty_label.update("[dim]No security events recorded yet.[/dim]")
            return

        empty_label.update("")
        for ev in grouped:
            sev = _format_severity_label(ev.severity)
            device = (ev.device_id[:8] if ev.device_id else "—")
            when = _format_relative_time(ev.timestamp)
            label = (
                f"{sev}  [bold]{ev.event_type}[/bold]  "
                f"[dim]{device}[/dim]  [dim]{when}[/dim]"
            )
            list_view.append(ListItem(Label(label), name=ev.device_id or ""))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "se-close":
            self.dismiss()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        device_id = event.item.name
        if not device_id:
            return
        app: ChatApp = self.app  # type: ignore[assignment]
        if app.trust_store is None:
            return
        dev = app.trust_store.get(device_id)
        if dev is None:
            self.notify("Device not in trust store.", title="Security Events")
            return
        self.app.push_screen(TrustDeviceDetailModal(dev))


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
