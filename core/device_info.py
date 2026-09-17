"""core/device_info.py — best-effort "what kind of device is this" string.

Deliberately NOT persisted anywhere (not in identity.json, not in the
vault) — see §37 "Self-Reported Display Metadata" in
docs/SECURITY_MODEL.md: if it were saved once at identity creation,
restoring/importing that identity onto a different physical device
would keep showing the old device's model forever. Instead this is
recomputed fresh every time the app starts, from whatever machine it's
actually running on right now — self-reported, informational only,
never a trust input (same rule as the display name).
"""

import os
import platform


def detect_device_model() -> str:
    """Best-effort human-readable device/platform description.

    True hardware model detection (e.g. "Pixel 7", "MacBook Air M2") isn't
    reliably available cross-platform without extra OS-specific
    permissions/libraries, so this settles for OS + a couple of common
    special cases (WSL, Termux) that are cheap to detect and useful to
    show — good enough for a human to eyeball during manual verification,
    which is the only thing this string is for.
    """
    system = platform.system()

    if system == "Darwin":
        mac_version = platform.mac_ver()[0]
        return f"macOS {mac_version}".strip() if mac_version else "macOS"

    if system == "Linux":
        if _is_termux():
            return "Android (Termux)"
        if _is_wsl():
            return f"WSL Linux ({platform.machine()})"
        return f"Linux ({platform.machine()})"

    if system == "Windows":
        release = platform.release()
        return f"Windows {release}".strip() if release else "Windows"

    return system or "Unknown device"


def _is_wsl() -> bool:
    try:
        with open("/proc/version", "r") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def _is_termux() -> bool:
    return "com.termux" in os.environ.get("PREFIX", "")
