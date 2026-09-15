"""tests/test_executable_detection.py — Phase 39.5: executable detection tests.

Covers:
  1. Windows PE executables (MZ header) detected.
  2. Linux ELF executables (\x7fELF header) detected.
  3. macOS Mach-O executables (multiple magic bytes) detected.
  4. Script files with shebang (#!) detected.
  5. Known safe formats (PDF, PNG, JPEG, GIF) allowed.
  6. Plain text files allowed.
  7. Executable extensions (.exe, .sh, .py) flagged.
  8. Extension mismatch (executable content with .txt extension) caught.
  9. Fail-closed on ambiguous/unknown files in strict mode.
 10. check_executable_for_open raises ExecutableDetectionError on executables.
 11. describe_file_type returns human-readable descriptions.
"""

import os

import pytest

from core.vault.executable_detection import (
    ExecutableDetectionError,
    check_executable_for_open,
    describe_file_type,
    is_executable,
)


def test_windows_pe_executable_detected(tmp_path):
    """Windows PE executable (MZ header) must be detected."""
    exe_file = tmp_path / "program.exe"
    exe_file.write_bytes(b"MZ" + b"\x00" * 100)
    
    assert is_executable(str(exe_file), strict=True)
    assert describe_file_type(str(exe_file)) == "Windows PE executable"


def test_linux_elf_executable_detected(tmp_path):
    """Linux ELF executable (\x7fELF header) must be detected."""
    elf_file = tmp_path / "program"
    elf_file.write_bytes(b"\x7fELF" + b"\x00" * 100)
    
    assert is_executable(str(elf_file), strict=True)
    assert describe_file_type(str(elf_file)) == "Linux ELF executable"


def test_macos_mach_o_32bit_detected(tmp_path):
    """macOS Mach-O 32-bit executable must be detected."""
    macho_file = tmp_path / "program"
    macho_file.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
    
    assert is_executable(str(macho_file), strict=True)
    assert describe_file_type(str(macho_file)) == "macOS Mach-O executable"


def test_macos_mach_o_64bit_detected(tmp_path):
    """macOS Mach-O 64-bit executable must be detected."""
    macho_file = tmp_path / "program"
    macho_file.write_bytes(b"\xfe\xed\xfa\xcf" + b"\x00" * 100)
    
    assert is_executable(str(macho_file), strict=True)
    assert describe_file_type(str(macho_file)) == "macOS Mach-O executable"


def test_macos_fat_binary_detected(tmp_path):
    """macOS FAT universal binary must be detected."""
    fat_file = tmp_path / "program"
    fat_file.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 100)
    
    assert is_executable(str(fat_file), strict=True)
    assert describe_file_type(str(fat_file)) == "macOS universal binary"


def test_script_with_shebang_detected(tmp_path):
    """Script file with shebang (#!) must be detected."""
    script_file = tmp_path / "script.sh"
    script_file.write_text("#!/bin/bash\necho hello")
    
    assert is_executable(str(script_file), strict=True)
    assert describe_file_type(str(script_file)) == "Script with shebang"


def test_pdf_file_allowed(tmp_path):
    """PDF files (known safe format) must be allowed."""
    pdf_file = tmp_path / "document.pdf"
    pdf_file.write_bytes(b"%PDF-1.4\n" + b"content")
    
    assert not is_executable(str(pdf_file), strict=True)
    assert describe_file_type(str(pdf_file)) == "PDF document"


def test_png_image_allowed(tmp_path):
    """PNG images (known safe format) must be allowed."""
    png_file = tmp_path / "image.png"
    png_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    
    assert not is_executable(str(png_file), strict=True)
    assert describe_file_type(str(png_file)) == "PNG image"


def test_jpeg_image_allowed(tmp_path):
    """JPEG images (known safe format) must be allowed."""
    jpeg_file = tmp_path / "photo.jpg"
    jpeg_file.write_bytes(b"\xff\xd8\xff" + b"\x00" * 100)
    
    assert not is_executable(str(jpeg_file), strict=True)
    assert describe_file_type(str(jpeg_file)) == "JPEG image"


def test_gif_image_allowed(tmp_path):
    """GIF images (known safe format) must be allowed."""
    gif_file = tmp_path / "animation.gif"
    gif_file.write_bytes(b"GIF89a" + b"\x00" * 100)
    
    assert not is_executable(str(gif_file), strict=True)
    assert describe_file_type(str(gif_file)) == "GIF image"


def test_plain_text_file_allowed(tmp_path):
    """Plain text files must be allowed."""
    text_file = tmp_path / "readme.txt"
    text_file.write_text("This is a plain text file with no executable content.")
    
    assert not is_executable(str(text_file), strict=True)


def test_executable_extension_flagged(tmp_path):
    """Files with executable extensions must be flagged."""
    # .exe extension
    exe_file = tmp_path / "program.exe"
    exe_file.write_text("not actually executable content")
    assert is_executable(str(exe_file), strict=True)
    
    # .sh extension
    sh_file = tmp_path / "script.sh"
    sh_file.write_text("not a script")
    assert is_executable(str(sh_file), strict=True)
    
    # .py extension
    py_file = tmp_path / "module.py"
    py_file.write_text("not python code")
    assert is_executable(str(py_file), strict=True)


def test_extension_mismatch_caught(tmp_path):
    """Executable content with misleading extension must be caught."""
    fake_txt = tmp_path / "innocent.txt"
    fake_txt.write_bytes(b"MZ" + b"\x00" * 100)  # PE executable
    
    # Content says executable, extension says text
    assert is_executable(str(fake_txt), strict=True)
    assert describe_file_type(str(fake_txt)) == "Windows PE executable"


def test_fail_closed_on_unknown_file_strict_mode(tmp_path):
    """Unknown file types must be blocked in strict mode."""
    unknown_file = tmp_path / "mystery.dat"
    unknown_file.write_bytes(b"\xab\xcd\xef\x01\x02\x03" + b"\x00" * 100)
    
    # Strict mode: fail closed (block unknown)
    assert is_executable(str(unknown_file), strict=True)


def test_non_strict_mode_allows_unknown_safe_extension(tmp_path):
    """Non-strict mode allows unknown content with safe extension."""
    data_file = tmp_path / "data.json"
    data_file.write_bytes(b"\xab\xcd\xef\x01\x02\x03")  # unknown magic
    
    # Non-strict mode with safe extension → allow
    assert not is_executable(str(data_file), strict=False)


def test_check_executable_for_open_raises_on_executable(tmp_path):
    """check_executable_for_open must raise ExecutableDetectionError on executables."""
    exe_file = tmp_path / "malware.exe"
    exe_file.write_bytes(b"MZ" + b"\x00" * 100)
    
    with pytest.raises(ExecutableDetectionError, match="appears to be executable"):
        check_executable_for_open(str(exe_file))


def test_check_executable_for_open_allows_safe_files(tmp_path):
    """check_executable_for_open must allow known safe files."""
    pdf_file = tmp_path / "report.pdf"
    pdf_file.write_bytes(b"%PDF-1.4\n" + b"content")
    
    # Should not raise
    check_executable_for_open(str(pdf_file))


def test_empty_file_allowed(tmp_path):
    """Empty files must be allowed (safe by definition)."""
    empty_file = tmp_path / "empty.dat"
    empty_file.write_bytes(b"")
    
    assert not is_executable(str(empty_file), strict=True)


def test_zip_file_not_flagged_as_executable(tmp_path):
    """ZIP files (PK magic) must not be flagged as executable by content."""
    zip_file = tmp_path / "archive.zip"
    zip_file.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    
    # ZIP magic itself is safe (though .zip extension is also safe)
    assert not is_executable(str(zip_file), strict=True)


def test_describe_file_type_unknown(tmp_path):
    """describe_file_type on unknown file returns 'Unknown file type'."""
    unknown = tmp_path / "mystery.bin"
    unknown.write_bytes(b"\xaa\xbb\xcc\xdd")
    
    desc = describe_file_type(str(unknown))
    assert desc == "Unknown file type"


def test_describe_file_type_suspicious_extension(tmp_path):
    """describe_file_type flags suspicious extensions."""
    suspicious = tmp_path / "script.py"
    suspicious.write_text("not python")
    
    desc = describe_file_type(str(suspicious))
    assert "Suspicious file extension" in desc or "Script" in desc or desc != "Unknown file type"


def test_renamed_elf_still_detected(tmp_path):
    """Renamed ELF executable (no extension) must still be caught."""
    renamed_exe = tmp_path / "innocuous_file"
    renamed_exe.write_bytes(b"\x7fELF" + b"\x00" * 100)
    
    # No .exe extension, but content is ELF
    assert is_executable(str(renamed_exe), strict=True)
    assert describe_file_type(str(renamed_exe)) == "Linux ELF executable"


def test_script_without_shebang_but_py_extension(tmp_path):
    """Python file without shebang but with .py extension must be flagged."""
    py_file = tmp_path / "module.py"
    py_file.write_text("print('hello')")  # no shebang
    
    # Extension alone should flag it
    assert is_executable(str(py_file), strict=True)


def test_text_file_with_high_ascii_ratio_allowed(tmp_path):
    """Text file with mostly printable ASCII must be allowed."""
    text_file = tmp_path / "data.txt"
    text_file.write_text("A" * 1000 + "\n" + "B" * 1000)  # 95%+ printable
    
    assert not is_executable(str(text_file), strict=True)


def test_binary_blob_with_safe_extension_strict_mode(tmp_path):
    """Binary blob with .dat extension in strict mode: fail closed."""
    binary_file = tmp_path / "random.dat"
    binary_file.write_bytes(bytes(range(256)))  # mix of everything
    
    # Strict mode + unknown content + safe extension = still fail closed
    # (because we can't positively identify it as safe)
    result = is_executable(str(binary_file), strict=True)
    # This should be True (fail closed) because it's not in the safe allowlist
    assert result  # Unknown content → blocked in strict mode


def test_multiple_magic_bytes_mach_o_variants(tmp_path):
    """All Mach-O magic byte variants must be detected."""
    variants = [
        (b"\xfe\xed\xfa\xce", "macOS Mach-O executable"),
        (b"\xfe\xed\xfa\xcf", "macOS Mach-O executable"),
        (b"\xce\xfa\xed\xfe", "macOS Mach-O executable"),
        (b"\xcf\xfa\xed\xfe", "macOS Mach-O executable"),
        (b"\xca\xfe\xba\xbe", "macOS universal binary"),
        (b"\xbe\xba\xfe\xca", "macOS universal binary"),
    ]
    
    for magic, expected_desc in variants:
        variant_file = tmp_path / f"test_{magic.hex()}"
        variant_file.write_bytes(magic + b"\x00" * 100)
        
        assert is_executable(str(variant_file), strict=True)
        desc = describe_file_type(str(variant_file))
        assert expected_desc in desc
