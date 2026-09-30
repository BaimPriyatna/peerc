"""app/ui/modals/link.py — connection-link modals and endpoint-line parsing (Phase 38).
"""

import secrets
import socket
from typing import Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, TextArea

from core.connectivity.locator import (
    KIND_DIRECT_V4,
    KIND_DIRECT_V6,
    KIND_RENDEZVOUS,
    Endpoint,
    LocatorError,
)
from app.config import UI_TCP_PORT


def _parse_endpoint_line(line: str, device_id: str) -> Endpoint:
    """Parse one "host:port" line from LinkGenerateModal's TextArea into
    an Endpoint, inferring kind the same way /connect already parses its
    argument (BUG-025's bracket-notation handling for IPv6): "[addr]:port"
    or "[addr]" for IPv6, "host:port" (single colon) for IPv4/hostname,
    a bare host with 2+ colons and no brackets for IPv6 with the default
    port, and a bare host with no colon at all for IPv4/hostname with
    the default port. Raises ValueError with a human-readable reason on
    anything that doesn't parse.
    """
    line = line.strip()
    if not line:
        raise ValueError("empty line")

    host, port = line, UI_TCP_PORT
    if line.startswith("["):
        closing = line.find("]")
        if closing == -1:
            raise ValueError("unterminated '[' in IPv6 address")
        host = line[1:closing]
        rest = line[closing + 1:]
        if rest.startswith(":"):
            if not rest[1:].isdigit():
                raise ValueError(f"invalid port {rest[1:]!r}")
            port = int(rest[1:])
    elif line.count(":") == 1:
        host_part, port_str = line.rsplit(":", 1)
        if port_str.isdigit():
            host, port = host_part, int(port_str)
        # else: a single colon but non-numeric suffix — treat the whole
        # thing as a bare (unlikely) hostname with the default port.
    # line.count(":") >= 2 with no brackets: bare IPv6, default port —
    # host/port already default to (line, UI_TCP_PORT) above.

    try:
        socket.inet_pton(socket.AF_INET, host)
        kind = KIND_DIRECT_V4
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, host)
            kind = KIND_DIRECT_V6
        except OSError:
            kind = KIND_RENDEZVOUS  # not a literal IP — treat as a hostname

    try:
        return Endpoint(device_id=device_id, kind=kind, host=host, port=port)
    except LocatorError as e:
        raise ValueError(str(e)) from e


class LinkMenuModal(ModalScreen[str]):
    """Phase 44.3 UI: entry point for Add-by-Link, reachable via the
    /link command or the Ctrl+G binding — both land here first. Returns
    "generate", "add", or "" (cancel)."""

    def compose(self) -> ComposeResult:
        with Vertical(id="vault-dialog"):
            yield Label("🔗 Add-by-Link")
            yield Label("Add a peer over the Internet without waiting for them to be on the same network.")
            yield Button("Generate a link (share with a friend)", id="generate", variant="success")
            yield Button("Add via a link (paste one you received)", id="add", variant="primary")
            yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id if event.button.id != "cancel" else "")


class LinkGenerateModal(ModalScreen[Optional[tuple]]):
    """Collect endpoints (pre-filled from detected local addresses,
    editable) and a PIN, then hand back (endpoints_text, pin) for the
    caller to actually build the link with create_link() — this modal
    doesn't touch identity/crypto itself, it's just the click+input
    surface. Returns None on cancel."""

    def __init__(self, detected_lines: list):
        super().__init__()
        self.detected_lines = detected_lines

    def compose(self) -> ComposeResult:
        with Vertical(id="link-generate-dialog"):
            yield Label("🔗 Generate an Add-by-Link")
            yield Label(
                "Endpoints, one per line (host:port). Detected local address is "
                "pre-filled — edit, add your public IP if you've port-forwarded, "
                "or remove lines you don't want to share."
            )
            yield TextArea("\n".join(self.detected_lines), id="link-endpoints")
            yield Label("6-digit PIN — send this through a DIFFERENT channel than the link itself")
            with Horizontal():
                yield Input(placeholder="e.g. 482913", id="link-pin", max_length=6)
                yield Button("Random PIN", id="random-pin")
            yield Label("", id="link-gen-error")
            yield Button("Generate Link", id="generate", variant="success")
            yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "random-pin":
            self.query_one("#link-pin", Input).value = f"{secrets.randbelow(1_000_000):06d}"
        elif event.button.id == "generate":
            self._submit()
        elif event.button.id == "cancel":
            self.dismiss(None)

    def _submit(self) -> None:
        endpoints_text = self.query_one("#link-endpoints", TextArea).text
        pin = self.query_one("#link-pin", Input).value.strip()
        error_label = self.query_one("#link-gen-error", Label)
        if not any(line.strip() for line in endpoints_text.splitlines()):
            error_label.update("At least one endpoint is required.")
            return
        if not (len(pin) == 6 and pin.isdigit()):
            error_label.update("PIN must be exactly 6 digits.")
            return
        self.dismiss((endpoints_text, pin))


class LinkResultModal(ModalScreen[None]):
    """Shows a freshly-generated link + its PIN, with a one-click copy
    for the link text. Purely informational — always dismisses with
    None."""

    def __init__(self, link: str, pin: str):
        super().__init__()
        self.link = link
        self.pin = pin

    def compose(self) -> ComposeResult:
        with Vertical(id="link-generate-dialog"):
            yield Label("✅ Link generated")
            yield Label(
                "Send the link and the PIN through two SEPARATE trusted channels "
                "(e.g. link by email, PIN by text or call) — anyone who has both "
                "can prove they're you."
            )
            yield Input(value=self.link, id="link-result-text")
            yield Label(f"PIN: {self.pin}")
            yield Button("Copy Link", id="copy", variant="success")
            yield Button("Close", id="close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "copy":
            self.app.copy_to_clipboard(self.link)
        else:
            self.dismiss(None)


class LinkAddModal(ModalScreen[Optional[tuple]]):
    """Collect a pasted link + its PIN. Returns (link_text, pin) or None
    on cancel — decoding/connecting happens in the caller, same
    click+input-only split as LinkGenerateModal."""

    def compose(self) -> ComposeResult:
        with Vertical(id="vault-dialog"):
            yield Label("🔗 Add a peer via link")
            yield Input(placeholder="Paste the PEERC1:... link here", id="link-input")
            yield Input(placeholder="6-digit PIN", id="link-pin-input", max_length=6)
            yield Label("", id="link-add-error")
            yield Button("Decode & Connect", id="decode", variant="success")
            yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "decode":
            self._submit()
        else:
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._submit()

    def _submit(self) -> None:
        link_text = self.query_one("#link-input", Input).value.strip()
        pin = self.query_one("#link-pin-input", Input).value.strip()
        error_label = self.query_one("#link-add-error", Label)
        if not link_text:
            error_label.update("Paste a link first.")
            return
        if not (len(pin) == 6 and pin.isdigit()):
            error_label.update("PIN must be exactly 6 digits.")
            return
        self.dismiss((link_text, pin))
