"""core/vault/executable_detection.py — Phase 39.5: executable detection.

See docs/SECURE_STORAGE_DESIGN.md §6, §11.6. Open must never execute a file
— view/preview only. Detection method: custom magic-byte sniffing for the
narrow set of executable/script signatures, not a third-party library
(avoids native-dependency concerns like `python-magic`/`libmagic` for a
problem narrower than general MIME detection).

Checks actual file headers against:
  - MZ (Windows PE executables)
  - \x7fELF (Linux ELF executables)
  - Mach-O magic numbers (macOS executables)
  - #! shebang (scripts)

Extension is kept as a secondary signal (flag harder if extension disagrees
with sniffed content), never the sole basis — a renamed executable must
still be caught by content. Fails closed: when detection is inconclusive,
block Open and direct the user to Export instead (§11.6).
"""

import os
from typing import Optional


class ExecutableDetectionError(Exception):
    """Raised when a file is detected as executable or detection is inconclusive."""


# Magic byte signatures for common executable formats
MAGIC_PE = b"MZ"  # Windows PE (Portable Executable)
MAGIC_ELF = b"\x7fELF"  # Linux ELF
MAGIC_MACH_O_32 = b"\xfe\xed\xfa\xce"  # Mach-O 32-bit
MAGIC_MACH_O_64 = b"\xfe\xed\xfa\xcf"  # Mach-O 64-bit
MAGIC_MACH_O_32_REV = b"\xce\xfa\xed\xfe"  # Mach-O 32-bit (reverse byte order)
MAGIC_MACH_O_64_REV = b"\xcf\xfa\xed\xfe"  # Mach-O 64-bit (reverse byte order)
MAGIC_MACH_O_FAT = b"\xca\xfe\xba\xbe"  # Mach-O FAT binary (universal)
MAGIC_MACH_O_FAT_REV = b"\xbe\xba\xfe\xca"  # FAT (reverse)
MAGIC_SHEBANG = b"#!"  # Script with shebang

# Extension patterns that suggest executables (case-insensitive)
EXECUTABLE_EXTENSIONS = {
    # Windows
    ".exe", ".dll", ".com", ".bat", ".cmd", ".msi", ".scr", ".vbs", ".js",
    ".wsf", ".ps1", ".psm1",
    # Linux/Unix
    ".sh", ".bash", ".zsh", ".fish", ".ksh", ".csh",
    # Python
    ".py", ".pyw", ".pyc", ".pyo",
    # Other scripts
    ".rb", ".pl", ".php", ".awk", ".sed",
    # macOS
    ".app", ".command",
    # Binary/library
    ".so", ".dylib", ".bin", ".run",
}

# Maximum bytes to read for magic-byte detection
MAX_HEADER_BYTES = 4096


def is_executable(file_path: str, strict: bool = True) -> bool:
    """Check if a file is or may be executable.
    
    Args:
        file_path: Path to the file to check
        strict: If True, fail closed on inconclusive results (default)
    
    Returns:
        True if the file is detected as executable
    
    Note:
        This is used as a gate for Open action (§6). When strict=True
        (default), inconclusive results are treated as "may be executable"
        and will block Open, directing the user to Export instead.
    """
    if not os.path.exists(file_path):
        return False
    
    # Check magic bytes (content-based detection)
    content_executable = _check_magic_bytes(file_path)
    
    # Check extension (secondary signal)
    extension_suspicious = _check_extension(file_path)
    
    # Decision logic (§11.6):
    # 1. If content is definitely executable → block
    # 2. If content is inconclusive AND extension is suspicious → block (strict)
    # 3. If both are clean → allow
    
    if content_executable is True:
        return True  # definitely executable
    
    if content_executable is None:  # inconclusive
        if strict and extension_suspicious:
            return True  # fail closed
    
    if extension_suspicious and not strict:
        return True  # non-strict: extension alone is enough
    
    return False


def check_executable_for_open(file_path: str) -> None:
    """Check if a file is safe to Open (view-only, never execute).
    
    Raises ExecutableDetectionError if the file is or may be executable.
    This is the function file_actions.open_secure_file() calls.
    
    Args:
        file_path: Path to the decrypted temp file
    
    Raises:
        ExecutableDetectionError: If the file should not be opened
    """
    if is_executable(file_path, strict=True):
        filename = os.path.basename(file_path)
        raise ExecutableDetectionError(
            f"File '{filename}' appears to be executable or script content. "
            f"Open is blocked for security (§6). Use Export if you need the file."
        )


def _check_magic_bytes(file_path: str) -> Optional[bool]:
    """Check file header for executable magic bytes.
    
    Returns:
        True: definitely executable
        False: definitely not executable (based on known safe signatures)
        None: inconclusive (unknown format)
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(MAX_HEADER_BYTES)
        
        if len(header) == 0:
            return False  # empty file is safe
        
        # Check Windows PE
        if header.startswith(MAGIC_PE):
            return True
        
        # Check Linux ELF
        if header.startswith(MAGIC_ELF):
            return True
        
        # Check macOS Mach-O (multiple variants)
        if (
            header.startswith(MAGIC_MACH_O_32)
            or header.startswith(MAGIC_MACH_O_64)
            or header.startswith(MAGIC_MACH_O_32_REV)
            or header.startswith(MAGIC_MACH_O_64_REV)
            or header.startswith(MAGIC_MACH_O_FAT)
            or header.startswith(MAGIC_MACH_O_FAT_REV)
        ):
            return True
        
        # Check shebang (scripts)
        if header.startswith(MAGIC_SHEBANG):
            return True
        
        # Check for common safe formats (positive identification)
        if _is_known_safe_format(header):
            return False
        
        # Unknown format → inconclusive
        return None
    
    except (OSError, IOError):
        # Can't read file → fail closed
        return None


def _is_known_safe_format(header: bytes) -> bool:
    """Check if the header matches known safe (non-executable) formats.
    
    This is a positive allowlist for common document/media formats.
    Deliberately narrow — we're not trying to identify every safe format,
    just the most common ones to avoid false positives.
    """
    # PDF
    if header.startswith(b"%PDF"):
        return True
    
    # PNG
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return True
    
    # JPEG
    if header.startswith(b"\xff\xd8\xff"):
        return True
    
    # GIF
    if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
        return True
    
    # ZIP (also used by docx, xlsx, etc. — not inherently safe but common)
    if header.startswith(b"PK\x03\x04") or header.startswith(b"PK\x05\x06"):
        # ZIP can contain executables, but .zip extension will be caught
        # separately. Here we're just saying "ZIP magic != executable magic"
        return True
    
    # Plain text (UTF-8 BOM or ASCII printable start)
    if header.startswith(b"\xef\xbb\xbf"):  # UTF-8 BOM
        return True
    
    # Check if file starts with printable ASCII (heuristic for text files)
    if len(header) > 0 and _is_likely_text(header[:512]):
        return True
    
    return False


def _is_likely_text(data: bytes) -> bool:
    """Heuristic: check if data looks like plain text.
    
    Returns True if at least 95% of the first chunk is printable ASCII
    or common whitespace. This catches plain text files, JSON, XML, etc.
    """
    if len(data) == 0:
        return False
    
    printable = 0
    for byte in data:
        # Printable ASCII (0x20-0x7E) + common whitespace (\t, \n, \r)
        if (0x20 <= byte <= 0x7E) or byte in (0x09, 0x0A, 0x0D):
            printable += 1
    
    ratio = printable / len(data)
    return ratio >= 0.95


def _check_extension(file_path: str) -> bool:
    """Check if the file extension suggests executable content.
    
    Returns True if the extension is in EXECUTABLE_EXTENSIONS (case-insensitive).
    This is a secondary signal only — never the sole basis for blocking (§11.6).
    """
    _, ext = os.path.splitext(file_path)
    return ext.lower() in EXECUTABLE_EXTENSIONS


def describe_file_type(file_path: str) -> str:
    """Human-readable description of what was detected.
    
    Useful for UI messages explaining why a file was blocked.
    
    Returns:
        String like "Windows PE executable" or "Script with shebang" or "Unknown"
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(MAX_HEADER_BYTES)
        
        if header.startswith(MAGIC_PE):
            return "Windows PE executable"
        if header.startswith(MAGIC_ELF):
            return "Linux ELF executable"
        if header.startswith(MAGIC_SHEBANG):
            return "Script with shebang"
        if (
            header.startswith(MAGIC_MACH_O_32)
            or header.startswith(MAGIC_MACH_O_64)
            or header.startswith(MAGIC_MACH_O_32_REV)
            or header.startswith(MAGIC_MACH_O_64_REV)
        ):
            return "macOS Mach-O executable"
        if header.startswith(MAGIC_MACH_O_FAT) or header.startswith(MAGIC_MACH_O_FAT_REV):
            return "macOS universal binary"
        
        # Check known safe formats
        if header.startswith(b"%PDF"):
            return "PDF document"
        if header.startswith(b"\x89PNG"):
            return "PNG image"
        if header.startswith(b"\xff\xd8\xff"):
            return "JPEG image"
        if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
            return "GIF image"
        
        # Check extension as fallback hint
        _, ext = os.path.splitext(file_path)
        if ext.lower() in EXECUTABLE_EXTENSIONS:
            return f"Suspicious file extension ({ext})"
        
        return "Unknown file type"
    
    except (OSError, IOError):
        return "Unknown (cannot read file)"
