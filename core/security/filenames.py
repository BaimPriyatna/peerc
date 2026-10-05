"""core/security/filenames.py — one rule for turning a peer-supplied name into a safe file name.

A file name that arrives over the network (a `file_offer`, or the original
name stored with a vault entry) is attacker-controlled text. This module
reduces it to a single, harmless path component so that joining it onto a
directory can never leave that directory, never creates a hidden NTFS stream,
and never names a Windows device.

    sanitize_filename("..\\\\..\\\\Startup\\\\evil.exe")  ->  "evil.exe"
    sanitize_filename("report.pdf:hidden")             ->  "report.pdf_hidden"   (Windows rules)
    sanitize_filename("NUL.txt")                       ->  "_NUL.txt"            (Windows rules)

Directory components are stripped for **both** separators on every platform
(a Windows path is just a name on Linux, and vice versa). The Windows-specific
rules (reserved device names, characters illegal on NTFS, trailing dots and
spaces) apply when running on Windows, or when `windows=True` is passed.
"""

import os
from typing import Optional

MAX_FILENAME_BYTES = 255                 # the limit of most filesystems, in UTF-8 bytes
_MAX_EXTENSION_BYTES = 16                # an extension longer than this is not worth preserving

_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)
_WINDOWS_ILLEGAL = '<>:"|?*'


class UnsafeFilenameError(ValueError):
    """Nothing usable is left of the supplied name."""


def _truncate(name: str, max_bytes: int) -> str:
    if len(name.encode("utf-8")) <= max_bytes:
        return name
    stem, ext = os.path.splitext(name)
    if len(ext.encode("utf-8")) > _MAX_EXTENSION_BYTES:
        stem, ext = name, ""
    budget = max_bytes - len(ext.encode("utf-8"))
    stem = stem.encode("utf-8")[:budget].decode("utf-8", "ignore")
    return (stem or "file") + ext


def sanitize_filename(
    name: object,
    *,
    fallback: Optional[str] = None,
    windows: Optional[bool] = None,
    max_bytes: int = MAX_FILENAME_BYTES,
) -> str:
    """Reduce `name` to one safe path component.

    If nothing usable remains (not a string, empty, ".", ".."), return
    `fallback` when one is given, otherwise raise UnsafeFilenameError.
    """
    if windows is None:
        windows = os.name == "nt"

    def unusable() -> str:
        if fallback is not None:
            return fallback
        raise UnsafeFilenameError(f"unsafe filename: {name!r}")

    if not isinstance(name, str):
        return unusable()

    leaf = name.replace("\\", "/").split("/")[-1]                   # last component, either separator
    leaf = "".join(ch for ch in leaf if ch >= " " and ch != "\x7f")  # no control characters, NUL included
    leaf = leaf.strip()
    if windows:
        leaf = "".join("_" if ch in _WINDOWS_ILLEGAL else ch for ch in leaf)
        leaf = leaf.rstrip(". ")
    if leaf in ("", ".", ".."):
        return unusable()
    if windows and leaf.split(".", 1)[0].upper() in _WINDOWS_RESERVED:
        leaf = "_" + leaf
    return _truncate(leaf, max_bytes)
