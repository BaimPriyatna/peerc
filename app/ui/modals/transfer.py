"""app/ui/modals/transfer.py — file-transfer modals (Phase 38, 47.6).
"""

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label


class FileOfferModal(ModalScreen[bool]):
    """Blocking prompt shown when a peer offers to send us a file.
    
    Phase 47.6: supports resume — if resume_offset > 0, shows "Resume from X%"
    and the accept button reads "Resume".
    """

    def __init__(self, sender_name: str, filename: str, size: int, resume_offset: int = 0):
        super().__init__()
        self.sender_name = sender_name
        self.filename = filename
        self.file_size = size
        self.resume_offset = resume_offset

    def compose(self) -> ComposeResult:
        size_kb = self.file_size / 1024
        with Vertical(id="offer-dialog"):
            yield Label(f"{self.sender_name} wants to send you a file:")
            yield Label(f"  {self.filename}  ({size_kb:.1f} KB)")
            
            # Phase 47.6: show resume info if resuming
            if self.resume_offset > 0:
                resume_pct = (self.resume_offset / self.file_size * 100) if self.file_size > 0 else 0
                done_kb = self.resume_offset / 1024
                yield Label(f"  Resume from {resume_pct:.0f}% ({done_kb:.1f} of {size_kb:.1f} KB)")
            
            with Horizontal():
                # Phase 47.6: button text changes to "Resume" when resuming
                accept_label = "Resume" if self.resume_offset > 0 else "Accept"
                yield Button(accept_label, id="accept", variant="success")
                yield Button("Reject", id="reject", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "accept")
