"""app/ui/modals/transfer.py — file-transfer modals (Phase 38).
"""

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label


class FileOfferModal(ModalScreen[bool]):
    """Blocking prompt shown when a peer offers to send us a file."""

    def __init__(self, sender_name: str, filename: str, size: int):
        super().__init__()
        self.sender_name = sender_name
        self.filename = filename
        self.file_size = size

    def compose(self) -> ComposeResult:
        size_kb = self.file_size / 1024
        with Vertical(id="offer-dialog"):
            yield Label(f"{self.sender_name} wants to send you a file:")
            yield Label(f"  {self.filename}  ({size_kb:.1f} KB)")
            with Horizontal():
                yield Button("Accept", id="accept", variant="success")
                yield Button("Reject", id="reject", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "accept")
