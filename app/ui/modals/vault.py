"""app/ui/modals/vault.py — vault and critical-action-key modals (Phase 38).
"""

from typing import Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label


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
